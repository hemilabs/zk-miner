//! W10-BENCH round 1: a working card beside a worker that DECLINED at startup. The working card's
//! suite is a clean, cacheable run (before round 1 the declined sibling failed the whole run, so
//! nothing was ever saved and the miner priced from the synthetic fallback). Own binary: the
//! process-wide worker pool can be set once per process.
//!
//! Run with: `cargo test -p zkminer-prover --features testing --test benchmark_declined_sibling`
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use zkminer_prover::benchmark;
use zkminer_prover::dispatcher::WorkerPool;

#[test]
fn a_working_card_beside_a_declined_one_is_measured_and_cacheable() {
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

    let dir = std::env::temp_dir().join(format!("w10-bench-declined-{}", std::process::id()));
    let cache = dir.join("benchmarks.json");

    for (name, suite) in [
        (
            "run_benchmark_gpu_only",
            benchmark::run_benchmark_gpu_only(),
        ),
        (
            "run_benchmark_gpu_only_streaming",
            benchmark::run_benchmark_gpu_only_streaming(&|_| {}),
        ),
    ] {
        assert!(!suite.failed(), "{name}: {:?}", suite.failures);
        assert!(
            !suite.device_benchmarks.is_empty(),
            "{name}: no device rows"
        );
        assert_eq!(suite.not_benchmarked.len(), 1, "{name}");
        assert_eq!(suite.not_cacheable(), None, "{name}");
        benchmark::save_benchmark_to_for_test(&cache, &suite)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            cache.exists(),
            "{name}: the working card's rows were not saved"
        );
        let _ = std::fs::remove_file(&cache);
    }
    let _ = std::fs::remove_dir_all(&dir);
    if let Some(pool) = zkminer_prover::engine::worker_pool() {
        pool.close();
    }
}
