//! A calibration sweeps up to the segment size that no longer fits the card. The risc0 worker answers
//! that size ResourceExhausted (it catches its HAL's failed allocation): the slot is charged no
//! failure, its worker is replaced for a clean GPU state, and the next size calibrates at once, with
//! no respawn backoff to wait out. The card is given as readings (`test_set_cards`): nothing here
//! reads a GPU.
//!
//! Run with: `cargo test -p zkminer-prover --features testing --test calibration_oom`
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::path::PathBuf;

use zkminer_prover::dispatcher::{TestCard, WorkerPool};

const KEY: &str = "risc0:cuda:0";

fn mock_worker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock-worker"))
}

#[test]
fn a_calibration_size_that_does_not_fit_replaces_the_worker_and_charges_no_failure() {
    let env: HashMap<String, String> =
        [("MOCK_BACKEND", "risc0"), ("MOCK_CALIBRATION_OOM_AT", "22")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker(KEY, "risc0", mock_worker_path(), env)
        .expect("spawn the mock worker");
    // An idle 24 GB card, read from here rather than from this host's GPUs.
    pool.test_set_card_identity(
        KEY,
        "cuda",
        Some("0000:02:00.0"),
        Some("NVIDIA GeForce RTX 4090"),
        Some(24_564 << 20),
    );
    pool.test_set_cards(
        KEY,
        vec![Some(TestCard {
            total_mib: 24_564,
            reserved_mib: 455,
            ..Default::default()
        })],
    );
    let first = pool.worker_pid(KEY).expect("a live worker");

    let e = pool
        .calibrate_slot_po2(KEY, 22)
        .expect_err("22 does not fit");
    assert!(format!("{e:#}").contains("allocation failed"), "{e:#}");
    // Typed, so the calibration sweep knows the size does not fit and does not retry it.
    let typed = e
        .downcast_ref::<zkminer_prover_protocol::types::WorkerProofError>()
        .expect("a typed answer");
    assert!(typed.is_gpu_oom(), "{typed}");
    assert_eq!(
        pool.test_consecutive_failures(KEY),
        Some(0),
        "not the worker's fault"
    );
    assert_eq!(
        pool.test_has_handle(KEY),
        Some(false),
        "replaced for a clean GPU state"
    );

    let sample = pool.calibrate_slot_po2(KEY, 21).expect("21 fits, at once");
    assert_eq!(sample.po2, 21);
    let second = pool.worker_pid(KEY).expect("a fresh worker");
    assert_ne!(second, first);
    assert_eq!(pool.test_consecutive_failures(KEY), Some(0));
}
