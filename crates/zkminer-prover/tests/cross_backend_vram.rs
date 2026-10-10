//! Regression test: two backends on ONE card make room for each other.
//!
//! risc0 and SP1 share a per-card guard, so they never prove at the same time — but the guard says
//! nothing about what an IDLE worker keeps. Measured on 2026-10-07 after a `fibonacci` proof: an idle
//! risc0 worker holds 1,806 MiB of the RTX 5080 and 7,134 MiB of the RTX 4090 (which keeps its Groth16
//! SRS cache resident); an idle SP1 worker holds 15,124 MiB of the 5080 and 15,302 MiB of the 4090,
//! still 30 s after its proof. The VRAM gate credited every process of ours as free, so it read the
//! 5080 beside an idle risc0 worker as 16,301 MiB available, admitted SP1's 15,604 MiB tier, and the
//! proof ran out of device memory and was killed by the 600 s watchdog: "Worker sp1 process died
//! (EOF)". In the other direction, a risc0 worker respawned 0.7 s after the SP1 worker was recycled
//! by hand still died on its first 8 MiB allocation, because the memory was not back yet.
//!
//! The fix reads the card per slot, recycles the other backend's idle worker when it stands in the way,
//! and waits for its memory to actually come back. This test runs the production interleaving on one
//! card — risc0, then SP1, then risc0 again — and requires all three to prove, the first switch to have
//! recycled the idle risc0 worker, and the second to have recycled the idle SP1 worker whenever that
//! still held at least 1 GiB of its own — so a run where nothing needed recycling cannot pass
//! vacuously.
//!
//! Assumes nothing else on the card: on the 5080 SP1's smallest tier leaves only 276 MiB to spare
//! (15,880 MiB allocatable against 15,604), so a desktop session fails the SP1 step for reasons that
//! have nothing to do with this fix. The 4090 step assumes a host budget that allows the 268M tier
//! (at least 21⅓ GiB, two thirds of the 32 GiB reference), which is what makes its idle risc0 worker
//! stand in the way.
//!
//! `#[ignore]`d — real GPU proofs. `ZKMINER_TEST_CARD` picks the card (default 0); both backends must
//! have a slot on it. Run with:
//!   ZKMINER_TEST_CARD=0 cargo test --release -p zkminer-prover --test cross_backend_vram \
//!     -- --ignored --test-threads=1 --nocapture

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use zkminer_prover::dispatcher::WorkerPool;

fn compute_app_mib(pid: u32) -> Option<u64> {
    let out = std::process::Command::new("nvidia-smi")
        .args([
            "--query-compute-apps=pid,used_gpu_memory",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        let (p, m) = l.split_once(',')?;
        (p.trim().parse::<u32>().ok()? == pid)
            .then(|| m.trim().parse().ok())
            .flatten()
    })
}

#[test]
#[ignore = "real GPU proofs"]
fn risc0_and_sp1_alternate_on_one_card() {
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

    let card = std::env::var("ZKMINER_TEST_CARD").unwrap_or_else(|_| "0".into());
    let (risc0, sp1) = (format!("risc0:cuda:{card}"), format!("sp1:cuda:{card}"));
    let mut pool = WorkerPool::new(HashMap::new(), vec![], Some(Duration::from_secs(900)));
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

    // risc0 first, leaving its worker idle on the card.
    let first = prove(&risc0, &risc0_elf);
    let risc0_pid = pool.worker_pid(&risc0).unwrap_or(0);
    eprintln!(
        "RESULT idle {risc0} worker (pid {risc0_pid}) holds {:?} MiB",
        compute_app_mib(risc0_pid)
    );
    let before_sp1 = pool.vram_budget_for_slot(&sp1);
    eprintln!("RESULT {sp1} before admission: {before_sp1:?}");

    // SP1 must make room.
    let second = prove(&sp1, &sp1_elf);
    let risc0_after = pool.worker_pid(&risc0).unwrap_or(0);
    eprintln!(
        "RESULT {risc0} worker after the SP1 admission: {}",
        if risc0_after == risc0_pid {
            format!("kept (pid {risc0_after})")
        } else {
            format!("recycled (pid {risc0_pid} -> {risc0_after})")
        }
    );

    // The reverse direction. Does the idle SP1 worker give its arena back by itself? Watched for
    // 30 s and reported; the fix must not depend on the answer.
    // SP1's OWN holding: what the card has in use less what SP1's slot sees as held elsewhere. Not
    // risc0's view, which would count a desktop session as SP1's.
    let sp1_holds = || {
        pool.vram_budget_for_slot(&sp1)
            .map_or(0, |b| b.used.saturating_sub(b.held_elsewhere))
    };
    let t = Instant::now();
    let held_by_sp1 = loop {
        let held = sp1_holds();
        if held < 1 << 30 || t.elapsed() >= Duration::from_secs(30) {
            break held;
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    eprintln!(
        "RESULT idle {sp1} worker, {:.0}s after its proof, holds {} MiB of the card",
        t.elapsed().as_secs_f64(),
        held_by_sp1 >> 20
    );
    let sp1_pid = pool.worker_pid(&sp1).unwrap_or(0);

    // risc0 must make room in turn, and its recycled worker must come back.
    let third = prove(&risc0, &risc0_elf);
    let sp1_after = pool.worker_pid(&sp1).unwrap_or(0);
    eprintln!(
        "RESULT {sp1} worker after the risc0 admission: {}",
        if sp1_after == sp1_pid {
            format!("kept (pid {sp1_after})")
        } else {
            format!("recycled (pid {sp1_pid} -> {sp1_after})")
        }
    );
    pool.shutdown_all();

    first.expect("the first risc0 proof must succeed on an otherwise idle card");
    let proof = second.unwrap_or_else(|e| {
        panic!(
            "SP1 could not prove on {sp1} after risc0 had proved there: {e:#}. The other backend's \
             idle worker must be recycled when it stands between SP1 and its tier."
        )
    });
    assert!(!proof.seal.is_empty());
    // Non-vacuity. On both cards here the idle risc0 worker leaves less than SP1's tier needs
    // (5080: 14,072 MiB against 15,604; 4090: 16,973 against 18,278 — see the header for what that
    // assumes), so a pass without a recycle means this run did not exercise the fix.
    assert_ne!(
        risc0_after, risc0_pid,
        "SP1 proved but the idle risc0 worker was never recycled: this run did not exercise making \
         room for SP1"
    );
    third.unwrap_or_else(|e| {
        panic!(
            "risc0 could not prove on {risc0} after SP1 had proved there: {e:#}. The recycled risc0 \
             worker must come back, and the idle SP1 worker's arena must be given back first."
        )
    });
    if held_by_sp1 >= 1 << 30 {
        assert_ne!(
            sp1_after, sp1_pid,
            "risc0 proved beside {} MiB of an idle SP1 worker without recycling it: this run did not \
             exercise making room for risc0",
            held_by_sp1 >> 20
        );
    }
}
