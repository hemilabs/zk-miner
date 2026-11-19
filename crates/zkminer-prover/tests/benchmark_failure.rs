//! W10-BENCH: the suite-level benchmark entry points with a worker whose warm-up fails.
//!
//! The process-wide worker pool (`engine::init_worker_pool`) can be set once per process, so these
//! checks live in their own test binary and in one test. Before W10-BENCH, `run_benchmark` fell back to
//! the SIMULATED suite here (impossible c/s figures, printed by `zkminer benchmark` with exit 0).
//!
//! Run with: `cargo test -p zkminer-prover --features testing --test benchmark_failure`
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use zkminer_prover::benchmark;
use zkminer_prover::dispatcher::WorkerPool;

#[test]
fn a_failed_worker_gives_a_failed_suite_never_a_simulated_one() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(30)));
    let env: HashMap<String, String> = [
        ("MOCK_BACKEND", "risc0".to_string()),
        (
            "MOCK_SDK_VERSION",
            format!(
                "risc0-zkvm {}.0",
                zkminer_prover_protocol::RISC0_ZKVM_MAJOR_MINOR
            ),
        ),
        ("MOCK_FAIL_ON", "warmup".to_string()),
        (
            "MOCK_FAIL_MESSAGE",
            "warm-up failed: compute pipeline for stepAccumA: Compilation failed".to_string(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    pool.insert_test_worker(
        "risc0:metal:0",
        "risc0",
        PathBuf::from(env!("CARGO_BIN_EXE_mock-worker")),
        env,
    )
    .expect("mock risc0 worker");
    pool.test_set_gpu_tag("risc0:metal:0", "metal");
    zkminer_prover::engine::init_worker_pool(pool);

    let dir = std::env::temp_dir().join(format!("w10-bench-{}", std::process::id()));
    let cache = dir.join("benchmarks.json");

    for (name, suite) in [
        ("run_benchmark", benchmark::run_benchmark()),
        (
            "run_benchmark_gpu_only",
            benchmark::run_benchmark_gpu_only(),
        ),
        (
            "run_benchmark_gpu_only_streaming",
            benchmark::run_benchmark_gpu_only_streaming(&|_| {}),
        ),
    ] {
        assert!(suite.failed(), "{name}: not reported as failed");
        assert!(
            !suite.is_simulated(),
            "{name}: fell back to simulated results"
        );
        assert!(
            suite
                .results
                .iter()
                .all(|r| r.prover_backend != "simulated"),
            "{name}: {:?}",
            suite.results
        );
        assert!(suite.results.is_empty(), "{name}: {:?}", suite.results);
        assert_eq!(suite.zkops, 0.0, "{name}");
        assert_eq!(suite.failures.len(), 1, "{name}: {:?}", suite.failures);
        assert_eq!(suite.failures[0].slot_key, "risc0:metal:0");
        let lines = benchmark::describe_failures(&suite.failures);
        assert!(lines[0].contains("stepAccumA"), "{name}: {lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("macos-smoke.sh")),
            "{name}: no advice for a Metal worker: {lines:?}"
        );
        // Never cached, so `zkminer run` never prices from it.
        assert!(suite.not_cacheable().is_some(), "{name}");
        let err = benchmark::save_benchmark_to_for_test(&cache, &suite).unwrap_err();
        assert!(err.contains("failed on risc0:metal:0"), "{name}: {err}");
        assert!(!cache.exists(), "{name}: a failed suite was written");
    }
    let _ = std::fs::remove_dir_all(&dir);
    if let Some(pool) = zkminer_prover::engine::worker_pool() {
        pool.close();
    }
}
