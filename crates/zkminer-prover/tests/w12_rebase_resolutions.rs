//! W12-RETEST: focused tests for the three #39/#43 conflict resolutions of the W12 rebase
//! (docs/metal-port-notes/W12-REBASE.md): the per-step benchmark watchdog on a Metal slot, the
//! one-time setup on any slot (first_slot_that_succeeds) with Metal slots, and the mock worker's
//! MOCK_BENCHMARK_SECS sleep before its MOCK_FAIL_ON / MOCK_BENCH_ROWS answer.
//!
//! Run with: `cargo test -p zkminer-prover --features testing --test w12_rebase_resolutions`
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use zkminer_prover::dispatcher::WorkerPool;

fn mock_worker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock-worker"))
}

/// A mock risc0 worker the handshake accepts (this build's risc0 major.minor).
fn risc0_env(extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = HashMap::new();
    env.insert("MOCK_BACKEND".into(), "risc0".into());
    env.insert(
        "MOCK_SDK_VERSION".into(),
        format!(
            "risc0-zkvm {}.0",
            zkminer_prover_protocol::RISC0_ZKVM_MAJOR_MINOR
        ),
    );
    for (k, v) in extra {
        env.insert((*k).into(), (*v).into());
    }
    env
}

fn metal_slot(pool: &mut WorkerPool, key: &str, env: HashMap<String, String>) {
    pool.insert_test_worker(key, "risc0", mock_worker_path(), env)
        .expect("mock risc0 worker");
    pool.test_set_gpu_tag(key, "metal");
}

/// Resolution 1 (dispatcher `benchmark`): a Metal slot's benchmark runs on #43's per-step clock
/// with the beta's Metal deadline. A suite whose steps each take 2 s, 3 steps or more, outlasts the
/// configured 3 s: it must finish with every row, the worker alive and not counted as failed.
#[test]
fn a_metal_slots_benchmark_outlasting_the_configured_deadline_finishes() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(3)));
    metal_slot(
        &mut pool,
        "risc0:metal:0",
        risc0_env(&[("MOCK_BENCHMARK_SECS", "2"), ("MOCK_BENCH_ROWS", "all")]),
    );
    let pid = pool.test_pid("risc0:metal:0").unwrap();
    let started = Instant::now();
    let rows = pool.benchmark("risc0").expect("benchmark");
    assert!(
        started.elapsed() >= Duration::from_secs(4),
        "every step should have run: {:?}",
        started.elapsed()
    );
    assert!(!rows.is_empty(), "the rows of the suite");
    assert_eq!(pool.test_has_handle("risc0:metal:0"), Some(true), "killed");
    assert_eq!(pool.test_pid("risc0:metal:0"), Some(pid));
    assert_eq!(pool.test_consecutive_failures("risc0:metal:0"), Some(0));
    assert_eq!(pool.test_intentional_kill("risc0:metal:0"), Some(false));
}

/// Resolution 1 (dispatcher `benchmark_streaming`): the same through the streaming entry point
/// `zkminer benchmark` uses: a complete result for the Metal slot, no failure.
#[test]
fn a_metal_slots_streaming_benchmark_outlasting_the_configured_deadline_finishes() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(3)));
    metal_slot(
        &mut pool,
        "risc0:metal:0",
        risc0_env(&[("MOCK_BENCHMARK_SECS", "2"), ("MOCK_BENCH_ROWS", "all")]),
    );
    let pid = pool.test_pid("risc0:metal:0").unwrap();
    let started = Instant::now();
    let run = pool.benchmark_all_streaming(&|_| {});
    assert!(started.elapsed() >= Duration::from_secs(4), "{:?}", started.elapsed());
    // The mock's made-up suite may be judged incomplete (no real score), but never cut off.
    for f in &run.failures {
        let e = f.error.to_lowercase();
        assert!(
            !e.contains("timed out") && !e.contains("timeout") && !e.contains("killed"),
            "{f:?}"
        );
    }
    let slot = run
        .results
        .iter()
        .find(|r| r.slot_key == "risc0:metal:0")
        .unwrap_or_else(|| panic!("{:?} / {:?}", run.results, run.failures));
    assert!(!slot.entries.is_empty());
    // benchmark_all_streaming respawns every GPU worker after the suite (by design, a fresh worker
    // for proving), so the pid changes; the slot must be up again, not dead or backing off.
    assert_eq!(pool.test_has_handle("risc0:metal:0"), Some(true), "not respawned");
    assert_ne!(pool.test_pid("risc0:metal:0"), Some(pid), "not recycled after the suite");
    assert_eq!(pool.test_consecutive_failures("risc0:metal:0"), Some(0));
}

/// Resolution 2 (#39's first_slot_that_succeeds beside the Metal recycle functions): with two
/// Metal slots, a first one whose warm-up fails hands the one-time setup to the second.
#[test]
fn a_metal_slot_that_fails_its_warmup_hands_the_setup_to_the_next_metal_slot() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    metal_slot(
        &mut pool,
        "risc0:metal:0",
        risc0_env(&[("MOCK_FAIL_ON", "warmup")]),
    );
    metal_slot(&mut pool, "risc0:metal:1", risc0_env(&[]));
    let summary = pool
        .warm_up("risc0", Duration::from_secs(20))
        .expect("risc0:metal:1 runs the setup after risc0:metal:0 fails it");
    assert!(!summary.is_empty());
    assert!(pool.backend_warmed("risc0"));
    assert_eq!(pool.test_consecutive_failures("risc0:metal:1"), Some(0));
    // The failing slot's worker answered an Error and stays up (W10-BENCH's MOCK_FAIL_ON).
    assert_eq!(pool.test_has_handle("risc0:metal:0"), Some(true));
}

/// Resolution 2: with both Metal slots failing, the error is the last one's, with the first's in
/// its context, and the backend stays unwarmed.
#[test]
fn every_metal_slot_failing_its_warmup_reports_each() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    for k in ["risc0:metal:0", "risc0:metal:1"] {
        metal_slot(
            &mut pool,
            k,
            risc0_env(&[("MOCK_FAIL_ON", "warmup"), ("MOCK_FAIL_MESSAGE", k)]),
        );
    }
    let err = pool
        .warm_up("risc0", Duration::from_secs(20))
        .expect_err("no slot can run the setup");
    let text = format!("{err:#}");
    assert!(text.contains("risc0:metal:0") && text.contains("risc0:metal:1"), "{text}");
    assert!(!pool.backend_warmed("risc0"));
}

/// Resolution 3 (mock worker: #43's sleep, then W10-BENCH's answer): with MOCK_FAIL_ON=benchmark and
/// MOCK_BENCHMARK_SECS=1 the failure comes after the delay, as an answer (the worker is not killed
/// or counted as crashed), and the benchmark reports it.
#[test]
fn the_mock_sleeps_then_answers_its_forced_benchmark_failure() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(10)));
    metal_slot(
        &mut pool,
        "risc0:metal:0",
        risc0_env(&[
            ("MOCK_BENCHMARK_SECS", "1"),
            ("MOCK_FAIL_ON", "benchmark"),
            ("MOCK_FAIL_MESSAGE", "w12 forced failure"),
        ]),
    );
    let pid = pool.test_pid("risc0:metal:0").unwrap();
    let started = Instant::now();
    let run = pool.benchmark_all_streaming(&|_| {});
    let took = started.elapsed();
    // The warm-up step's failure is only a warning; the suite's request fails: >= 2 delayed answers.
    assert!(took >= Duration::from_secs(2), "{took:?}");
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert_eq!(run.failures.len(), 1, "{:?}", run.failures);
    assert!(
        run.failures[0].error.contains("w12 forced failure"),
        "{:?}",
        run.failures[0]
    );
    let e = run.failures[0].error.to_lowercase();
    assert!(!e.contains("timed out") && !e.contains("killed"), "{e}");
    // An answered failure is not a crash: the slot is up again after the suite's GPU recycle.
    assert_eq!(pool.test_has_handle("risc0:metal:0"), Some(true));
    assert_ne!(pool.test_pid("risc0:metal:0"), Some(0));
    let _ = pid;
}

/// Resolution 3: MOCK_BENCH_ROWS=all with MOCK_BENCHMARK_SECS still answers rows, after the delay.
#[test]
fn the_mock_sleeps_then_answers_its_rows() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(10)));
    metal_slot(
        &mut pool,
        "risc0:metal:0",
        risc0_env(&[("MOCK_BENCHMARK_SECS", "1"), ("MOCK_BENCH_ROWS", "all")]),
    );
    let started = Instant::now();
    let rows = pool.benchmark("risc0").expect("benchmark");
    assert!(started.elapsed() >= Duration::from_secs(2), "{:?}", started.elapsed());
    assert!(!rows.is_empty());
}
