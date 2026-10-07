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
use std::time::Duration;

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
