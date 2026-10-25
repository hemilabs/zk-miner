//! Integration tests for the worker lifecycle: timeout → kill → EOF → cleanup → respawn.
//!
//! Uses a mock worker binary (`mock-worker`) that speaks the IPC protocol and
//! can be configured via env vars passed through spawn_env:
//! - `MOCK_HANG_ON`: hang on "benchmark", "prove", or "both"
//! - `MOCK_CRASH_ON`: exit(1) on "benchmark", "prove", or "both"
//!
//! Run with: `cargo test -p zkminer-prover --features testing --test worker_lifecycle`
#![cfg(all(unix, feature = "testing"))]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use zkminer_prover::dispatcher::WorkerPool;

fn mock_worker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock-worker"))
}

fn mock_env(hang_on: &str, crash_on: &str) -> HashMap<String, String> {
    let mut env = HashMap::new();
    if !hang_on.is_empty() {
        env.insert("MOCK_HANG_ON".to_string(), hang_on.to_string());
    }
    if !crash_on.is_empty() {
        env.insert("MOCK_CRASH_ON".to_string(), crash_on.to_string());
    }
    env.insert("MOCK_BACKEND".to_string(), "mock".to_string());
    env
}

// ---- Benchmark timeout tests ----

#[test]
fn benchmark_timeout_kills_and_cleans_up() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(2)));

    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("benchmark", ""),
    )
    .expect("failed to spawn mock worker");

    let initial_pid = pool.test_pid("mock:generic").unwrap();
    assert!(initial_pid > 0, "initial PID should be nonzero");
    assert_eq!(pool.test_has_handle("mock:generic"), Some(true));
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));

    // benchmark() catches per-slot errors internally and returns Ok(vec![])
    let result = pool.benchmark("mock");
    assert!(result.is_ok());

    // After timeout kill: handle cleared, PID zeroed, failures NOT incremented
    assert_eq!(pool.test_has_handle("mock:generic"), Some(false));
    assert_eq!(pool.test_pid("mock:generic"), Some(0));
    assert_eq!(
        pool.test_consecutive_failures("mock:generic"),
        Some(0),
        "intentional kill should not increment consecutive_failures"
    );
}

#[test]
fn benchmark_timeout_then_ensure_alive_respawns() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(2)));

    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("benchmark", ""),
    )
    .expect("failed to spawn mock worker");

    let initial_pid = pool.test_pid("mock:generic").unwrap();

    // Trigger timeout kill
    let _ = pool.benchmark("mock");
    assert_eq!(pool.test_has_handle("mock:generic"), Some(false));

    // Update spawn_env so the respawned worker doesn't hang
    pool.test_set_spawn_env("mock:generic", mock_env("", ""));

    // Next benchmark call hits ensure_alive → finds handle=None → respawn()
    // using the updated spawn_env. The respawned worker responds normally.
    let result = pool.benchmark("mock");
    assert!(result.is_ok());

    // Verify respawn happened: new PID, handle alive, failures reset
    assert_eq!(pool.test_has_handle("mock:generic"), Some(true));
    let new_pid = pool.test_pid("mock:generic").unwrap();
    assert!(new_pid > 0, "respawned worker should have a nonzero PID");
    assert_ne!(
        new_pid, initial_pid,
        "respawn should produce a different PID"
    );
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));
}

// ---- Prove timeout tests ----

#[test]
fn prove_timeout_kills_and_cleans_up() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);

    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("prove", ""),
    )
    .expect("failed to spawn mock worker");

    let initial_pid = pool.test_pid("mock:generic").unwrap();
    assert!(initial_pid > 0);

    let result = pool.prove("mock", &[], &[], None, Some(Duration::from_secs(2)), None);
    assert!(result.is_err(), "prove should fail after timeout kill");

    assert_eq!(pool.test_has_handle("mock:generic"), Some(false));
    assert_eq!(pool.test_pid("mock:generic"), Some(0));
    assert_eq!(
        pool.test_consecutive_failures("mock:generic"),
        Some(0),
        "intentional kill should not increment consecutive_failures"
    );
}

#[test]
fn prove_timeout_then_ensure_alive_respawns() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);

    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("prove", ""),
    )
    .expect("failed to spawn mock worker");

    let initial_pid = pool.test_pid("mock:generic").unwrap();

    // Trigger timeout kill
    let _ = pool.prove("mock", &[], &[], None, Some(Duration::from_secs(2)), None);

    // Update spawn_env so respawn doesn't hang
    pool.test_set_spawn_env("mock:generic", mock_env("", ""));

    // Next prove call triggers ensure_alive → respawn with updated env
    let result = pool.prove("mock", &[], &[], None, Some(Duration::from_secs(5)), None);
    assert!(result.is_ok(), "prove should succeed after respawn");

    let output = result.unwrap();
    assert_eq!(output.cycles, 1000);

    let new_pid = pool.test_pid("mock:generic").unwrap();
    assert!(new_pid > 0);
    assert_ne!(
        new_pid, initial_pid,
        "respawn should produce a different PID"
    );
}

// ---- Worker crash tests (spontaneous death, not timeout) ----

#[test]
fn benchmark_crash_increments_consecutive_failures() {
    let mut pool = WorkerPool::new(
        HashMap::new(),
        Vec::new(),
        Some(Duration::from_secs(10)), // generous timeout — crash happens instantly
    );

    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("", "benchmark"), // crash (exit 1) on benchmark
    )
    .expect("failed to spawn mock worker");

    let _ = pool.benchmark("mock");

    // Crash is NOT an intentional kill — consecutive_failures SHOULD increment
    assert_eq!(pool.test_has_handle("mock:generic"), Some(false));
    assert_eq!(pool.test_pid("mock:generic"), Some(0));
    assert_eq!(
        pool.test_consecutive_failures("mock:generic"),
        Some(1),
        "crash should increment consecutive_failures"
    );
}

#[test]
fn prove_crash_increments_consecutive_failures() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);

    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("", "prove"), // crash on prove
    )
    .expect("failed to spawn mock worker");

    let result = pool.prove("mock", &[], &[], None, Some(Duration::from_secs(10)), None);
    assert!(result.is_err());

    assert_eq!(pool.test_has_handle("mock:generic"), Some(false));
    assert_eq!(pool.test_pid("mock:generic"), Some(0));
    assert_eq!(
        pool.test_consecutive_failures("mock:generic"),
        Some(1),
        "crash should increment consecutive_failures"
    );
}

#[test]
fn crash_then_ensure_alive_respawns_successfully() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);

    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("", "prove"), // crash on prove
    )
    .expect("failed to spawn mock worker");

    let initial_pid = pool.test_pid("mock:generic").unwrap();

    // First prove crashes
    let _ = pool.prove("mock", &[], &[], None, Some(Duration::from_secs(10)), None);
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(1));

    // Update spawn_env so respawned worker doesn't crash, and reset the
    // backoff counter so respawn proceeds immediately (backoff logic is
    // already tested in unit tests — here we test the respawn mechanics).
    pool.test_set_spawn_env("mock:generic", mock_env("", ""));
    pool.test_reset_failures("mock:generic");

    // Next prove triggers ensure_alive → respawn with clean env
    let result = pool.prove("mock", &[], &[], None, Some(Duration::from_secs(5)), None);
    assert!(result.is_ok(), "prove should succeed after crash + respawn");

    let output = result.unwrap();
    assert_eq!(output.cycles, 1000);

    let new_pid = pool.test_pid("mock:generic").unwrap();
    assert_ne!(new_pid, initial_pid);
    // Successful respawn resets consecutive_failures to 0
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));
}

// ---- Normal operation (no timeout, no crash) ----

#[test]
fn normal_benchmark_completes_without_timeout() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(10)));

    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");

    let result = pool.benchmark("mock");
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());

    assert_eq!(pool.test_has_handle("mock:generic"), Some(true));
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));
}

#[test]
fn normal_prove_completes_without_timeout() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);

    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");

    let result = pool.prove("mock", &[], &[], None, Some(Duration::from_secs(10)), None);
    assert!(result.is_ok());

    let output = result.unwrap();
    assert_eq!(output.cycles, 1000);
    assert!(output.journal.is_empty());
    assert!(output.seal.is_empty());

    assert_eq!(pool.test_has_handle("mock:generic"), Some(true));
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));
}

// ---- Making room on a card ----

/// Recycling a sibling to make room on its card, against real worker processes: an idle one is shut
/// down and left ready to respawn — pid retracted, no failure counted — and one whose slot is held is
/// left alone, promptly.
#[test]
fn an_idle_sibling_is_recycled_and_a_busy_one_is_left_alone() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker(
        "mock:busy",
        "mock",
        mock_worker_path(),
        mock_env("prove", ""),
    )
    .expect("failed to spawn mock worker");
    pool.insert_test_worker("mock:idle", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    let busy_pid = pool.test_pid("mock:busy").unwrap();
    let idle_pid = pool.test_pid("mock:idle").unwrap();
    assert!(busy_pid > 0 && idle_pid > 0);

    // A hung proof holds `mock:busy`'s slot for its whole duration.
    let pool = Arc::new(pool);
    let prover = {
        let pool = pool.clone();
        std::thread::spawn(move || {
            pool.prove(
                "mock:busy",
                &[],
                &[],
                None,
                Some(Duration::from_secs(4)),
                None,
            )
        })
    };
    // Wait until the proof actually holds the slot, rather than sleeping and hoping it does.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !pool.test_slot_is_held("mock:busy") {
        assert!(
            Instant::now() < deadline,
            "the hung proof never took its slot"
        );
        assert!(!prover.is_finished(), "the hung proof finished early");
        std::thread::sleep(Duration::from_millis(20));
    }

    let started = Instant::now();
    let recycled = pool.test_evict_idle_siblings("sp1:cuda:0", &["mock:busy".to_string()]);
    assert!(recycled.is_empty(), "a sibling in use must not be recycled");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "giving up on a held sibling took {:?}",
        started.elapsed()
    );
    assert_eq!(pool.test_pid("mock:busy"), Some(busy_pid));

    let recycled = pool.test_evict_idle_siblings("sp1:cuda:0", &["mock:idle".to_string()]);
    assert_eq!(recycled, vec!["mock:idle".to_string()]);
    assert_eq!(pool.test_has_handle("mock:idle"), Some(false));
    assert_eq!(
        pool.test_pid("mock:idle"),
        Some(0),
        "pid must be retracted with the worker"
    );
    assert_eq!(
        pool.test_consecutive_failures("mock:idle"),
        Some(0),
        "making room is not a failure; the slot must respawn on its next job without backoff"
    );

    let _ = prover.join();
    // And it does come back.
    let out = pool
        .prove(
            "mock:idle",
            &[],
            &[],
            None,
            Some(Duration::from_secs(10)),
            None,
        )
        .expect("a recycled sibling must respawn on its next dispatch");
    assert!(out.seal.is_empty());
    assert_eq!(pool.test_has_handle("mock:idle"), Some(true));
    assert_ne!(pool.test_pid("mock:idle"), Some(idle_pid));
}

/// A slot whose worker was recycled to make room is skipped for cycle measurement, not failed on: the
/// measurement runs on the next live worker.
#[test]
fn cycle_measurement_skips_a_recycled_slot() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    for key in ["mock:a", "mock:b"] {
        pool.insert_test_worker(key, "mock", mock_worker_path(), mock_env("", ""))
            .expect("failed to spawn mock worker");
    }
    // Recycle each in turn, so whichever one the measurement reaches first is the one gone.
    for gone in ["mock:a", "mock:b"] {
        let _ = pool.test_evict_idle_siblings("sp1:cuda:0", &[gone.to_string()]);
        assert_eq!(pool.test_has_handle(gone), Some(false));
        assert!(
            pool.has_idle_worker("mock"),
            "the other worker is idle and live"
        );
        let (cycles, _journal_len, _peak) = pool
            .execute_cycles("mock", &[], &[], Some(Duration::from_secs(10)), None)
            .expect("measurement must move on to the live worker");
        assert_eq!(cycles, 1000);
        // Bring it back for the next round.
        pool.prove(gone, &[], &[], None, Some(Duration::from_secs(10)), None)
            .expect("respawn");
    }
}

/// Once the pool is CLOSING — the process is exiting — nothing is spawned again: a respawn then would
/// outlive the miner. A dispatch to a slot whose worker was recycled must fail, not bring it back.
#[test]
fn a_closed_pool_never_respawns() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:a", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    pool.close();
    assert_eq!(pool.test_has_handle("mock:a"), Some(false));
    let err = pool
        .prove("mock:a", &[], &[], None, Some(Duration::from_secs(5)), None)
        .expect_err("a closed pool must not respawn a worker");
    assert!(
        format!("{err:#}").contains("shutting down"),
        "must say why: {err:#}"
    );
    assert_eq!(pool.test_has_handle("mock:a"), Some(false));
    assert_eq!(pool.test_pid("mock:a"), Some(0));
}

// ---- Warm-up ----

/// A backend's one-time setup answers, and is reported back.
#[test]
fn warmup_reports_what_was_done() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    let summary = pool.warm_up("mock", Duration::from_secs(10)).unwrap();
    assert_eq!(summary, "nothing to warm up");
    assert!(pool.backend_warmed("mock"));
    assert!(pool
        .warm_up("nonexistent", Duration::from_secs(10))
        .is_err());
}

/// A warm-up that hangs (a download that stalls) is killed at its deadline, like a benchmark: the
/// slot is cleared for a respawn and the kill is not counted as a crash.
#[test]
fn a_hung_warmup_is_killed_at_its_deadline() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("warmup", ""),
    )
    .expect("failed to spawn mock worker");
    let started = std::time::Instant::now();
    assert!(pool.warm_up("mock", Duration::from_secs(2)).is_err());
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(pool.test_has_handle("mock:generic"), Some(false));
    assert_eq!(pool.test_pid("mock:generic"), Some(0));
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));
}

/// A worker that dies during its warm-up is an error, counted as a failure.
#[test]
fn a_warmup_crash_is_an_error() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("", "warmup"),
    )
    .expect("failed to spawn mock worker");
    assert!(pool.warm_up("mock", Duration::from_secs(10)).is_err());
    assert_eq!(pool.test_has_handle("mock:generic"), Some(false));
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(1));
}

/// RESIDUAL A — prove-preempts-measure, end to end.
///
/// A pre-claim cycle measurement is held in flight (the mock worker hangs on Execute), so it is
/// registered as preemptible and holds its slot. A committed proof then PREEMPTS it: the dispatcher
/// SIGKILLs the measure worker. The measurement thread must observe the kill, reclassify it as the
/// TYPED transient `MeasurePreempted` (not a wall-clock timeout, not a crash), deregister, and leave
/// the slot DEAD but not FAILED (its health must not be dinged — the kill was intentional and the
/// measurement was healthy). This exercises the real cross-thread SIGKILL + recv-fail path, which is
/// the part that could not be covered by the pure-logic planner tests.
#[test]
fn a_committed_proof_preempts_an_inflight_measurement_end_to_end() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    // On the (non-measure-pool) PROVE slot, so the measurement reserves NO host RAM — the test is
    // then independent of how much RAM the box happens to have free. Hang on Execute so it stays in
    // flight until it is killed.
    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("execute", ""),
    )
    .expect("failed to spawn mock worker");

    let pool = Arc::new(pool);
    let measurer = {
        let pool = Arc::clone(&pool);
        std::thread::spawn(move || {
            // A generous watchdog budget that we never reach — the preemption kills it first.
            pool.execute_cycles("mock", &[], &[], Some(Duration::from_secs(120)), None)
        })
    };

    // Wait until the measurement is actually in flight (registered). Bounded so the test fails loudly
    // rather than hanging if registration regresses.
    let mut waited = Duration::ZERO;
    while pool.test_inflight_measure_count() == 0 {
        std::thread::sleep(Duration::from_millis(20));
        waited += Duration::from_millis(20);
        assert!(
            waited < Duration::from_secs(10),
            "measurement never registered as in-flight"
        );
    }
    assert_eq!(pool.test_inflight_measure_count(), 1);
    // Non-blocking: the measurement HOLDS the slot lock across its recv, so `test_has_handle`
    // (which takes that lock) would block until the measurement returns — use the try_lock probe.
    assert!(
        pool.test_slot_is_held("mock:generic"),
        "the hanging measurement holds its slot"
    );

    // Preempt it, exactly as a committed proof short on resources would.
    pool.test_preempt_all_inflight_measures();

    // The measurement thread unwinds with the TYPED transient.
    let result = measurer.join().expect("measurer thread panicked");
    let err = result.expect_err("a preempted measurement must return an error, not a cycle count");
    assert!(
        err.downcast_ref::<zkminer_prover_protocol::types::MeasurePreempted>()
            .is_some(),
        "a preempted measurement must return the typed MeasurePreempted (got: {err:#})"
    );

    // Deregistered, slot DEAD (handle gone, pid zeroed) but NOT failed (health untouched).
    assert_eq!(
        pool.test_inflight_measure_count(),
        0,
        "the registration must be cleared on return"
    );
    assert_eq!(pool.test_has_handle("mock:generic"), Some(false));
    assert_eq!(pool.test_pid("mock:generic"), Some(0));
    assert_eq!(
        pool.test_consecutive_failures("mock:generic"),
        Some(0),
        "preemption is an intentional kill — it must NOT count against slot health"
    );
}

/// A measurement that completes NORMALLY deregisters itself and leaves its slot healthy — the
/// preemptible window is exactly the in-flight duration, nothing lingers in the registry.
#[test]
fn a_normal_measurement_leaves_no_inflight_registration() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");

    let (cycles, _journal, _peak) = pool
        .execute_cycles("mock", &[], &[], Some(Duration::from_secs(10)), None)
        .expect("measurement should succeed");
    assert_eq!(cycles, 1000);
    assert_eq!(
        pool.test_inflight_measure_count(),
        0,
        "a finished measurement must not stay registered as preemptible"
    );
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));
}
