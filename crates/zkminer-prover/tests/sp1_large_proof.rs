//! A LARGE SP1 Groth16 proof, for exercising the GPU prover under real shard counts.
//!
//! `sp1_proof_test` proves fibonacci(100) — 5,466 cycles, one shard, and ~45s of its ~51s is the fixed
//! Groth16 wrap. That is a fine smoke test and a poor stress test: it barely touches the sharding,
//! sumcheck and FRI paths where the Blackwell out-of-bounds bugs lived. This one scales the work until
//! those paths run thousands of times.
//!
//! `#[ignore]`d deliberately. A full-size GPU proof has twice hard-frozen this machine when it ran as a
//! side effect of a broader `cargo test`, so it must be asked for by name.
//!
//! ```text
//! ZKMINER_SP1_INPUT=4000000 ZKMINER_TEST_SP1_SLOT=sp1:cuda:0 \
//!   cargo test --release -p zkminer-prover --test sp1_large_proof -- --ignored --nocapture
//! ```
//!
//! * `ZKMINER_SP1_GUEST`     guest name under `guests/sp1/` (default `sha256-chain`)
//! * `ZKMINER_SP1_INPUT`     the guest's `u32` input — iterations for `sha256-chain` (default 1_000_000)
//! * `ZKMINER_TEST_SP1_SLOT` which slot to prove on, e.g. `sp1:cuda:1`
//! * `ZKMINER_SP1_TIMEOUT_S` proof timeout in seconds (default 2400)

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use zkminer_prover::dispatcher::WorkerPool;

fn guest_elf(name: &str) -> Option<Vec<u8>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "guests/sp1/{name}/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/{name}-sp1-guest"
    ));
    if p.exists() {
        std::fs::read(&p).ok()
    } else {
        eprintln!("guest ELF not found: {}", p.display());
        None
    }
}

#[test]
#[ignore = "full-size GPU proof: minutes long, and heavy enough to have frozen this box when run implicitly"]
fn sp1_large_groth16_proof() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();

    let guest = std::env::var("ZKMINER_SP1_GUEST").unwrap_or_else(|_| "sha256-chain".to_string());
    let input_n: u32 = std::env::var("ZKMINER_SP1_INPUT")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(1_000_000);
    let timeout_s: u64 = std::env::var("ZKMINER_SP1_TIMEOUT_S")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(2400);

    let Some(elf) = guest_elf(&guest) else {
        eprintln!("SKIP: no ELF for {guest}");
        return;
    };
    eprintln!("guest {guest}: {} bytes ELF, input {input_n}", elf.len());

    let mut pool = WorkerPool::new(HashMap::new(), vec![], Some(Duration::from_secs(timeout_s)));
    let connected = pool.discover_and_spawn();
    eprintln!("connected: {connected:?}");

    let want = std::env::var("ZKMINER_TEST_SP1_SLOT").ok();
    let key = match &want {
        Some(w) => connected.iter().find(|k| *k == w).cloned(),
        None => connected.iter().find(|k| k.starts_with("sp1:")).cloned(),
    };
    let Some(key) = key else {
        eprintln!("SKIP: no matching SP1 slot in {connected:?}");
        pool.shutdown_all();
        return;
    };

    eprintln!("proving on {key} (timeout {timeout_s}s)");
    let start = Instant::now();
    let result = pool.prove(
        &key,
        &elf,
        &input_n.to_le_bytes(),
        None,
        Some(Duration::from_secs(timeout_s)),
        None,
    );
    let elapsed = start.elapsed();

    match result {
        Ok(proof) => {
            eprintln!(
                "LARGE PROOF PASS on {key}: {} cycles in {:.1}s ({:.0} cycles/s), seal {} bytes",
                proof.cycles,
                elapsed.as_secs_f64(),
                proof.cycles as f64 / elapsed.as_secs_f64(),
                proof.seal.len()
            );
            assert!(!proof.seal.is_empty(), "seal must not be empty");
            assert!(!proof.journal.is_empty(), "journal must not be empty");
            // Same on-chain shape the small proof produces; a compact Groth16 seal, not bincode.
            assert!(
                proof.seal.len() < 500,
                "seal {} bytes is not a compact Groth16 proof",
                proof.seal.len()
            );
            pool.shutdown_all();
        }
        Err(e) => {
            pool.shutdown_all();
            panic!(
                "LARGE PROOF FAILED on {key} after {:.1}s: {e:#}",
                elapsed.as_secs_f64()
            );
        }
    }
}
