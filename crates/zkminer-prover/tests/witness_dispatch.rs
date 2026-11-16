//! A witness proof through the pool (`WorkerPool::prove_witness_min_vram`), against the mock worker:
//! the bundle reaches the worker in the frame, a proof comes back as a proof, and a run that did not
//! reproduce its bundle comes back as a typed `JournalDiverged`, not an error, with the slot healthy.
//!
//! Run with: `cargo test -p zkminer-prover --features testing --test witness_dispatch`
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use zkminer_prover::dispatcher::{WitnessProveOutcome, WorkerPool};
use zkminer_prover_protocol::{WitnessProve, GUEST_EXIT_HALTED};

fn mock_worker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock-worker"))
}

fn pool(extra: &[(&str, &str)]) -> WorkerPool {
    let mut env: HashMap<String, String> = extra
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    env.insert("MOCK_BACKEND".to_string(), "mock".to_string());
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), env)
        .expect("spawn the mock worker");
    pool
}

fn witness() -> WitnessProve {
    WitnessProve {
        input_path: "/retention/job/v1/w.bin".to_string(),
        prefix: vec![1; 64],
        input_sha256: [2; 32],
        w_len: 4096,
        expect_journal_sha256: [3; 32],
        segment_dir: "/segments/mock-0".to_string(),
    }
}

fn prove(pool: &WorkerPool, used: &mut Option<String>) -> anyhow::Result<WitnessProveOutcome> {
    pool.prove_witness_min_vram(
        "mock",
        b"elf",
        &witness(),
        Some(19),
        Some(Duration::from_secs(10)),
        None,
        None,
        &[],
        &[],
        used,
        None,
        None,
        Some([4; 32]),
        None,
        0,
    )
}

#[test]
fn a_diverged_witness_run_is_a_typed_outcome_and_the_slot_stays_healthy() {
    let pool = pool(&[("MOCK_WITNESS_DIVERGE", "1")]);
    let mut used = None;
    match prove(&pool, &mut used).expect("a divergence is not an error") {
        WitnessProveOutcome::JournalDiverged(d) => {
            assert_eq!(d.slot_key, "mock:generic");
            // The mock commits the bundle's path and reports its length as cycles: the bundle arrived.
            assert_eq!(d.journal, witness().input_path.as_bytes());
            assert_eq!(d.journal_len as usize, witness().input_path.len());
            assert_eq!(d.journal_sha256, [!3u8; 32]);
            assert_eq!(
                (d.exit_kind, d.exit_code, d.cycles),
                (GUEST_EXIT_HALTED, 0, 4096)
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(used.as_deref(), Some("mock:generic"));
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));
    assert_eq!(
        pool.test_has_handle("mock:generic"),
        Some(true),
        "the worker was not replaced"
    );

    // The same pool still proves inline jobs.
    let out = pool
        .prove(
            "mock",
            b"elf",
            b"input",
            Some(20),
            Some(Duration::from_secs(10)),
            None,
        )
        .expect("an inline proof");
    assert_eq!(out.cycles, 1020);
}

#[test]
fn a_witness_proof_comes_back_as_a_proof() {
    let pool = pool(&[]);
    let mut used = None;
    match prove(&pool, &mut used).unwrap() {
        WitnessProveOutcome::Proved(p) => assert_eq!(p.cycles, 1019, "at the po2 asked for"),
        other => panic!("{other:?}"),
    }
}
