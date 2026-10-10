//! Regression test: a risc0 Groth16 proof of a REAL program completes on a 16 GB card, twice on one
//! worker.
//!
//! Before the fix in the `hemilabs/risc0` fork this failed on the RTX 5080 even at po2 20 — the
//! smallest segment in use — for a 46M-cycle sha256-chain, in two ways:
//!
//! * on a FRESH worker the STARK left ~10.5 GB of freed buffers cached in risc0's thread-local
//!   `BUFFER_POOL` (capped at 16 GB, so unbounded on this card), and the Groth16 wrap — which allocates
//!   through sppark, outside that pool — ran out at 15.8 of 16.3 GB;
//! * after ONE wrap, the Groth16 prover's SRS cache stayed resident (~7.25 GB idle) for the life of the
//!   process, and the next STARK peaked within 469 MiB of the card's capacity, failing outright in some
//!   program orders.
//!
//! The fix is two releases: `hal::cuda::clear_buffer_pool`, which risc0-zkvm now calls around the wrap,
//! and `risc0_groth16::prove::release_srs`, which the zkminer worker calls after each proof on a card
//! under 20 GiB (`release_groth16_cache_if_tight`). Measured after both on 2026-10-07: 9.57 GiB released
//! before each wrap, the idle worker down to 2,452 MiB, the second proof peaking at 12,436 MiB, both
//! proofs completing in ~41 s.
//!
//! The 5080's ceiling is still po2 20. At 21 and 22 the FIRST STARK segment of a fresh worker asks for a
//! single buffer the card cannot hold (3.46 GB with 12.8 GB in use; 14.16 GB), unrelated to the wrap.
//! Production does not ask for more: without a usable calibration `resolve_po2` defers to risc0's
//! default, po2 20. Set `ZKMINER_TEST_PO2` to probe other sizes.
//!
//! `#[ignore]`d — real GPU proofs. Run with:
//!   ZKMINER_TEST_RISC0_SLOT=risc0:cuda:0 cargo test -p zkminer-prover --test risc0_groth16_vram \
//!     -- --ignored --test-threads=1 --nocapture

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use zkminer_prover::dispatcher::WorkerPool;

fn worker_vram_mib(pid: u32) -> Option<u64> {
    let out = std::process::Command::new("nvidia-smi")
        .args([
            "--query-compute-apps=pid,used_gpu_memory",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        let mut f = l.split(',');
        let p: u32 = f.next()?.trim().parse().ok()?;
        let m: u64 = f.next()?.trim().parse().ok()?;
        (p == pid).then_some(m)
    })
}

#[test]
#[ignore = "real GPU proofs"]
fn a_real_risc0_groth16_proof_completes_on_this_card() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .try_init();
    let elf_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../target/riscv-guest/zkminer-prove-risc0/sha256-chain/riscv32im-risc0-zkvm-elf/\
         release/sha256-chain.bin",
    );
    let Ok(elf) = std::fs::read(&elf_path) else {
        eprintln!("SKIP: {} not found", elf_path.display());
        return;
    };
    let key = std::env::var("ZKMINER_TEST_RISC0_SLOT").unwrap_or_else(|_| "risc0:cuda:0".into());
    let po2: u8 = std::env::var("ZKMINER_TEST_PO2")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);

    let mut pool = WorkerPool::new(HashMap::new(), vec![], Some(Duration::from_secs(900)));
    let connected = pool.discover_and_spawn();
    if !connected.contains(&key) {
        eprintln!("SKIP: {key} not among {connected:?}");
        pool.shutdown_all();
        return;
    }
    // The same input as the benchmark's sha256-chain: 46,137,344 cycles.
    let input = 10_000u32.to_le_bytes();

    let mut outcomes = Vec::new();
    for round in 1..=2 {
        let pid = pool.worker_pid(&key).unwrap_or(0);
        eprintln!(
            "round {round}: worker pid {pid} holds {:?} MiB before proving",
            worker_vram_mib(pid)
        );
        let started = Instant::now();
        let r = pool.prove(
            &key,
            &elf,
            &input,
            Some(po2),
            Some(Duration::from_secs(900)),
            None,
        );
        let pid_after = pool.worker_pid(&key).unwrap_or(0);
        match &r {
            Ok(p) => eprintln!(
                "round {round}: PROVED at po2={po2} in {:.1}s (seal {} bytes); worker pid {pid_after} \
                 now holds {:?} MiB",
                started.elapsed().as_secs_f64(),
                p.seal.len(),
                worker_vram_mib(pid_after)
            ),
            Err(e) => eprintln!(
                "round {round}: FAILED at po2={po2} after {:.1}s: {e:#}",
                started.elapsed().as_secs_f64()
            ),
        }
        outcomes.push(r.is_ok());
        // Let the dispatcher's view settle before reading the worker again.
        std::thread::sleep(Duration::from_secs(2));
    }
    pool.shutdown_all();
    assert!(
        outcomes.iter().all(|ok| *ok),
        "{key}: {outcomes:?} — a 46M-cycle Groth16 proof must complete on this card, and again on the \
         same worker; see the module doc"
    );
}
