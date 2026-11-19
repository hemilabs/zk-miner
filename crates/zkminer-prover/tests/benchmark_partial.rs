//! W10-BENCH round 1: the suite-level entry points with a worker whose suite comes back short, and
//! with a declined sibling beside a working card. One test per binary: the process-wide worker pool
//! (`engine::init_worker_pool`) can be set once per process, so the two cases share one pool here:
//! a metal slot that drops programs, plus a declined SP1 slot.
//!
//! Run with: `cargo test -p zkminer-prover --features testing --test benchmark_partial`
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use zkminer_prover::benchmark;
use zkminer_prover::dispatcher::WorkerPool;

#[test]
fn a_short_suite_is_a_failed_uncached_suite_and_a_declined_sibling_is_only_reported() {
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
        ("MOCK_BENCH_ROWS", "all".to_string()),
        (
            "MOCK_BENCH_DROP",
            "sha256-chain,ecdsa-verify,bigint-mul,chacha-mix,zkop-mix".to_string(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let mock = PathBuf::from(env!("CARGO_BIN_EXE_mock-worker"));
    pool.insert_test_worker("risc0:metal:0", "risc0", mock.clone(), env)
        .expect("mock risc0 worker");
    pool.test_set_gpu_tag("risc0:metal:0", "metal");
    pool.insert_test_down_worker(
        "sp1:cuda:0",
        "sp1",
        "cuda",
        mock,
        Some("sp1 unavailable: libcudart.so.12 not found"),
    );
    zkminer_prover::engine::init_worker_pool(pool);

    let dir = std::env::temp_dir().join(format!("w10-bench-partial-{}", std::process::id()));
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
        // The memory-merkle row proved and is kept, to be shown as incomplete.
        assert!(
            suite
                .results
                .iter()
                .any(|r| r.program_name == "memory-merkle"),
            "{name}: {:?}",
            suite.results
        );
        assert!(suite.failed(), "{name}: a short suite was not a failure");
        assert_eq!(suite.failures.len(), 1, "{name}: {:?}", suite.failures);
        assert_eq!(suite.failures[0].slot_key, "risc0:metal:0");
        assert!(
            suite.failures[0].error.contains("zkop-mix"),
            "{name}: {}",
            suite.failures[0].error
        );
        // The declined SP1 slot is reported, not failed.
        assert_eq!(suite.not_benchmarked.len(), 1, "{name}");
        assert_eq!(suite.not_benchmarked[0].slot_key, "sp1:cuda:0");
        let lines = benchmark::describe_not_benchmarked(&suite.not_benchmarked);
        assert!(lines[0].contains("libcudart"), "{name}: {lines:?}");
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
