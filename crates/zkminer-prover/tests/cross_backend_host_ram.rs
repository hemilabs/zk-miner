//! Regression test: an idle worker of one backend gives its HOST RAM back for another backend's proof
//! on a different card.
//!
//! `sp1-gpu-server` stays resident between proofs, deliberately, so the next SP1 proof is cheap:
//! measured on 2026-10-07 at 23.3 GB of host RAM while idle. On this 28 GB box that left no room for a
//! risc0 proof on EITHER card — `can_admit`'s live headroom was gone — and nothing gave it back until
//! the SP1 worker was recycled for some other reason. The claim gate therefore refused every risc0 job
//! for as long as SP1 sat warm, and a risc0 proof dispatched anyway was refused at admission.
//!
//! The fix counts an idle worker of another backend as reclaimable at the claim gate, and recycles it
//! at dispatch (`make_host_room`) before refusing. This test warms SP1 on one card, checks that the
//! old rule would refuse risc0 there and then — so a pass cannot be vacuous — and then requires the
//! claim gate to admit risc0, a risc0 proof on the OTHER card to succeed, and SP1's idle worker to have
//! been recycled for it.
//!
//! `#[ignore]`d — real GPU proofs, and it needs the host short of RAM in the way described: an SP1
//! worker resident at more than about `MemTotal - 9 GiB`. `ZKMINER_TEST_SP1_CARD` (default 0) and
//! `ZKMINER_TEST_RISC0_CARD` (default 1) pick the cards. `ZKMINER_TEST_PROVERS_DIR` adds a directory
//! searched for the worker binaries before `~/.zkminer/provers`, which must hold builds that speak
//! this tree's protocol version. Run with:
//!   ZKMINER_TEST_PROVERS_DIR=/path ZKMINER_SP1_SERVER_INSTALL=0 cargo test --release \
//!     -p zkminer-prover --test cross_backend_host_ram -- --ignored --test-threads=1 --nocapture

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use zkminer_prover::dispatcher::WorkerPool;
use zkminer_prover::memory;

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

#[test]
#[ignore = "real GPU proofs"]
fn an_idle_sp1_worker_gives_its_host_ram_to_risc0_on_another_card() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let risc0_elf = root.join(
        "target/riscv-guest/zkminer-prove-risc0/fibonacci/riscv32im-risc0-zkvm-elf/release/\
         fibonacci.bin",
    );
    let sp1_elf = root.join(
        "crates/zkminer-prover/guests/sp1/fibonacci/target/elf-compilation/\
         riscv64im-succinct-zkvm-elf/release/fibonacci-sp1-guest",
    );
    let (Ok(risc0_elf), Ok(sp1_elf)) = (std::fs::read(&risc0_elf), std::fs::read(&sp1_elf)) else {
        eprintln!("SKIP: build the risc0 and SP1 fibonacci guests first");
        return;
    };

    let card = |var: &str, default: &str| std::env::var(var).unwrap_or_else(|_| default.into());
    let sp1 = format!("sp1:cuda:{}", card("ZKMINER_TEST_SP1_CARD", "0"));
    let risc0 = format!("risc0:cuda:{}", card("ZKMINER_TEST_RISC0_CARD", "1"));
    let dirs: Vec<PathBuf> = std::env::var_os("ZKMINER_TEST_PROVERS_DIR")
        .map(PathBuf::from)
        .into_iter()
        .collect();
    let mut pool = WorkerPool::new(HashMap::new(), dirs, Some(Duration::from_secs(900)));
    let connected = pool.discover_and_spawn();
    if !connected.contains(&risc0) || !connected.contains(&sp1) {
        eprintln!("SKIP: need both {risc0} and {sp1} (connected: {connected:?})");
        pool.shutdown_all();
        return;
    }

    let input = 100u32.to_le_bytes();
    let budget = Some(Duration::from_secs(600));
    let prove = |key: &str, elf: &[u8]| {
        let t = Instant::now();
        let r = pool.prove(key, elf, &input, None, budget, None);
        eprintln!(
            "RESULT {key}: {} in {:.1}s",
            match &r {
                Ok(p) => format!("PROVED, seal {} bytes", p.seal.len()),
                Err(e) => format!("FAILED {e:#}"),
            },
            t.elapsed().as_secs_f64()
        );
        r
    };

    // SP1 first, leaving its worker resident and idle.
    let warm = prove(&sp1, &sp1_elf);
    let sp1_pid = pool.worker_pid(&sp1).unwrap_or(0);
    let sp1_holds = pool.current_host_bytes_for_slot(&sp1).unwrap_or(0);
    let available = memory::mem_available_bytes().unwrap_or(0);
    let total = memory::mem_total_bytes().unwrap_or(0);
    let want = pool.expected_host_peak("risc0");
    let old_rule = memory::can_admit(
        want,
        0,
        pool.reserved_host_memory(),
        available,
        total,
        memory::DEFAULT_HOST_RESERVE_BYTES,
    );
    let claimable = pool.backend_fits_for_claim(want, "risc0", 0, 2);
    eprintln!(
        "RESULT idle {sp1} worker (pid {sp1_pid}) holds {:.1} GiB; {:.1} of {:.1} GiB available; a \
         risc0 proof wants {:.1} GiB: old rule {}, claim gate now {}",
        sp1_holds as f64 / GIB,
        available as f64 / GIB,
        total as f64 / GIB,
        want as f64 / GIB,
        if old_rule { "admits" } else { "refuses" },
        if claimable { "admits" } else { "refuses" },
    );

    // risc0 on the other card must make room in host RAM.
    let proof = prove(&risc0, &risc0_elf);
    let sp1_after = pool.worker_pid(&sp1).unwrap_or(0);
    eprintln!(
        "RESULT {sp1} worker after the risc0 proof: {}",
        if sp1_after == sp1_pid {
            format!("kept (pid {sp1_after})")
        } else {
            format!("recycled (pid {sp1_pid} -> {sp1_after})")
        }
    );

    // And SP1 must come back for its own next job.
    let again = prove(&sp1, &sp1_elf);
    pool.shutdown_all();

    warm.expect("the first SP1 proof must succeed on an otherwise idle host");
    assert!(
        !old_rule,
        "risc0 fitted beside the idle SP1 worker ({:.1} GiB held, {:.1} GiB available) without \
         recycling it: this run did not exercise making room in host RAM",
        sp1_holds as f64 / GIB,
        available as f64 / GIB,
    );
    assert!(
        claimable,
        "the claim gate refused risc0 although the memory it lacked was held only by an idle SP1 \
         worker that dispatch would recycle"
    );
    let proof = proof.unwrap_or_else(|e| {
        panic!(
            "risc0 could not prove on {risc0} beside an idle SP1 worker on another card: {e:#}. \
             That worker must be recycled to give its host RAM back."
        )
    });
    assert!(!proof.seal.is_empty());
    assert_ne!(
        sp1_after, sp1_pid,
        "risc0 proved but the idle SP1 worker was never recycled"
    );
    again.unwrap_or_else(|e| {
        panic!("SP1 must respawn and prove again after its worker was recycled: {e:#}")
    });
}
