//! Does a slot inside its own respawn-backoff window burn a caller's attempt, or get
//! waited out?
//!
//! soak20 lost every job it failed to this: all four died on
//! `proving failed after 3 attempt(s): Backoff: waiting ~4.5s before respawning`, and
//! for 0x92e7686c attempt 3 fired **155 microseconds** after attempt 2. The 3-attempt
//! budget was consumed by a 5-second timer the failure handler had armed 0.7s earlier,
//! because no dispatch predicate knew about the window and the single-key shortcut went
//! straight into `ensure_alive` -> `respawn` -> instant bail.
//!
//! Needs a real CUDA worker. Run with:
//!   ZKMINER_GPU_NAME_FILTER=4090 cargo test --release -p zkminer-prover \
//!     --test backoff_dispatch -- --ignored --nocapture --test-threads=1

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zkminer_prover::dispatcher::WorkerPool;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn find_risc0_elf(guest: &str) -> Option<Vec<u8>> {
    let p = workspace_root().join(format!(
        "target/riscv-guest/zkminer-prover/{guest}/riscv32im-risc0-zkvm-elf/release/{guest}.bin"
    ));
    if p.exists() {
        return std::fs::read(&p).ok();
    }
    let alt = p.with_extension("");
    if alt.exists() {
        std::fs::read(&alt).ok()
    } else {
        None
    }
}

fn input(vals: &[u32]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// Kill the worker behind `key` so the NEXT prove observes EOF and arms the backoff.
fn sigkill_worker(pool: &WorkerPool, key: &str) -> Option<u32> {
    let pid = pool.worker_pid(key)?;
    if pid != 0 {
        #[cfg(unix)]
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
    Some(pid)
}

#[test]
#[ignore = "needs a real CUDA worker; run explicitly"]
fn a_backoff_blocked_single_slot_is_waited_out_not_failed_instantly() {
    let elf = match find_risc0_elf("fibonacci") {
        Some(e) if !e.is_empty() => e,
        _ => panic!("REQUIRED: fibonacci risc0 ELF not built"),
    };

    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(900)));
    let connected = pool.discover_and_spawn();
    let keys: Vec<_> = connected
        .iter()
        .filter(|k| k.starts_with("risc0:cuda"))
        .cloned()
        .collect();
    assert_eq!(
        keys.len(),
        1,
        "this test needs EXACTLY one cuda slot so the single-key shortcut is exercised; \
         set ZKMINER_GPU_NAME_FILTER. got: {keys:?}"
    );
    let key = keys[0].clone();
    eprintln!("slot under test: {key}");

    // 1. Start a LONG proof, then SIGKILL the worker mid-proof. That path runs the
    //    failure handler (`mark_slot_failed`), which is what arms the backoff window --
    //    exactly as the OOM did in soak20. Killing the worker BEFORE a prove does not
    //    work: `ensure_alive` just respawns it cleanly, since `last_failure` is None.
    let pool = std::sync::Arc::new(pool);
    let big = input(&[40_000_000]);
    let elf_c = elf.clone();
    let pool_c = pool.clone();
    let prove1 = std::thread::spawn(move || {
        let mut used = None;
        let r = pool_c.prove_min_vram(
            "risc0",
            &elf_c,
            &big,
            None,
            Some(Duration::from_secs(600)),
            None,
            None,
            &[],
            &[],
            &mut used,
            None,
            None,
        );
        r.map(|_| ()).map_err(|e| format!("{e:#}"))
    });

    // Let it get properly into the proof, then kill.
    std::thread::sleep(Duration::from_secs(8));
    let pid = sigkill_worker(&pool, &key).expect("worker pid");
    eprintln!("SIGKILLed worker pid {pid} mid-proof");

    let first = prove1.join().expect("prove thread");
    eprintln!("prove #1: {first:?}");
    assert!(
        first.is_err(),
        "killing the worker mid-proof should have failed this attempt (and armed the backoff)"
    );

    // 2. Immediately retry. This is the soak20 moment. The slot is dead and inside its
    //    5s window, and it is the ONLY key.
    let t0 = Instant::now();
    let mut used2 = None;
    let second = pool.prove_min_vram(
        "risc0",
        &elf,
        &input(&[1000]),
        None,
        Some(Duration::from_secs(300)),
        None,
        None,
        &[],
        &[],
        &mut used2,
        None,
        None,
    );
    let elapsed = t0.elapsed();
    eprintln!("prove #2 returned after {elapsed:?}: ok={}", second.is_ok());

    // The regression: returning in microseconds with a Backoff error.
    if let Err(e) = &second {
        let msg = format!("{e:#}");
        assert!(
            !msg.contains("Backoff: waiting"),
            "prove #2 returned a respawn-backoff error after {elapsed:?} — this is the \
             soak20 job-loss shape: the caller's attempt was spent on a timer, not on a \
             GPU. err: {msg}"
        );
        panic!("prove #2 failed for another reason after {elapsed:?}: {msg}");
    }

    assert!(
        elapsed >= Duration::from_secs(1),
        "prove #2 succeeded in {elapsed:?} — too fast to have waited out a backoff window, \
         so this run did not actually exercise the path"
    );
    eprintln!(
        "PASS: the backoff window was waited out ({elapsed:?}) and the proof then ran, \
         instead of the attempt being burned in microseconds"
    );
    pool.shutdown_all();
}
