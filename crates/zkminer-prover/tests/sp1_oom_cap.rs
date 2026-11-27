//! The SP1 shard-size cap, the 12 GB card sizes and the protocol handshake, end to end through
//! `WorkerPool` and the mock worker: a proof that runs out of GPU memory, its retry on the same
//! card one shard size smaller, the record once it proves there, a risc0 benchmark and calibration
//! at a 12 GB card's own size. The card is given to the pool as readings (`test_set_cards`), so
//! nothing here reads a GPU, and the cap record is a temporary file, never `~/.zkminer`'s.
//!
//! Run with: `cargo test -p zkminer-prover --features testing --test sp1_oom_cap`
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use zkminer_prover::dispatcher::{TestCard, WorkerPool};
use zkminer_prover::sp1_shard_caps::Store;
use zkminer_prover_protocol::types::{self as t, ErrorKind, WorkerProofError};

const MIB: u64 = 1024 * 1024;
/// An RTX 4070: 12,282 MiB, 272 of it reserved by the driver.
const TOTAL_MIB: u64 = 12_282;
const RESERVED_MIB: u64 = 272;
const BUS: &str = "0000:03:00.0";
const NAME: &str = "NVIDIA GeForce RTX 4070";
const SP1_KEY: &str = "sp1:cuda:0";
/// The smaller of a 12 GB card's two measured SP1 shard sizes.
const SMALLER: u64 = 134_217_728;

fn mock_worker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock-worker"))
}

/// The dispatcher reads these from its own environment when it predicts an SP1 worker's size, as
/// the worker it spawns would: set in the shell, they would change what these tests check.
fn require_default_sizing() {
    for v in [
        t::SP1_ELEMENT_THRESHOLD_ENV,
        t::SP1_ELEMENT_THRESHOLD_CAP_ENV,
        t::HOST_MEM_BUDGET_ENV,
        t::SP1_NO_AUTOTUNE_ENV,
        "SP1_GPU_DROP_LDES",
        "SP1_GPU_RECOMPUTE_FIRST_LAYER",
        zkminer_prover::discovery::MIN_AVAILABLE_VRAM_MB_ENV,
    ] {
        assert!(
            std::env::var_os(v).is_none(),
            "{v} is set in this environment; unset it to run these tests (it changes how the \
             dispatcher sizes SP1)"
        );
    }
}

/// A temporary directory, removed when dropped. On Windows the mock worker runs at Low integrity,
/// as every worker does, so the directory is labelled for it to write its record in.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("zkminer-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(windows)]
        zkminer_prover::windows_sandbox::label_low_writable_for_tests(&dir).unwrap();
        Self(dir)
    }

    fn record(&self) -> Vec<String> {
        std::fs::read_to_string(self.0.join("record"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn caps(&self) -> PathBuf {
        self.0.join(zkminer_prover::sp1_shard_caps::FILE_NAME)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The 4070 with `foreign_mib` held by another program.
fn card(foreign_mib: u64) -> TestCard {
    TestCard {
        total_mib: TOTAL_MIB,
        reserved_mib: RESERVED_MIB,
        foreign_mib,
        ..Default::default()
    }
}

/// An SP1 slot on an idle 4070, its worker the mock with `knobs`, sized for the card: 268M, the
/// larger of its two sizes. Caps are kept in `dir`.
fn sp1_pool(dir: &TempDir, knobs: &[(&str, &str)]) -> WorkerPool {
    require_default_sizing();
    let available = (TOTAL_MIB - RESERVED_MIB) * MIB;
    assert_eq!(
        t::sp1_config_for_available_vram(
            t::Sp1Gpu::Cuda,
            Some(TOTAL_MIB * MIB),
            available,
            None,
            None
        )
        .map(|c| c.threshold),
        Some(268_435_456),
        "the card's larger size"
    );
    let mut env: HashMap<String, String> = knobs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    env.insert("MOCK_BACKEND".into(), "sp1".into());
    env.insert(
        "MOCK_RECORD_TO".into(),
        dir.0.join("record").display().to_string(),
    );
    env.insert(
        t::CUDA_VRAM_AVAILABLE_BYTES_ENV.into(),
        available.to_string(),
    );
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.use_sp1_shard_caps(dir.caps());
    pool.insert_test_worker(SP1_KEY, "sp1", mock_worker_path(), env)
        .expect("spawn the mock worker");
    pool.test_set_card_identity(
        SP1_KEY,
        "cuda",
        Some(BUS),
        Some(NAME),
        Some(TOTAL_MIB * MIB),
    );
    pool.test_set_cards(SP1_KEY, vec![Some(card(0))]);
    pool
}

fn prove(pool: &WorkerPool, elf: &[u8]) -> anyhow::Result<()> {
    pool.prove("sp1", elf, &[], None, Some(Duration::from_secs(30)), None)
        .map(|_| ())
}

fn worker_error_kind(e: &anyhow::Error) -> ErrorKind {
    e.downcast_ref::<WorkerProofError>()
        .unwrap_or_else(|| panic!("not a worker's proof error: {e:#}"))
        .kind
        .clone()
}

fn recorded_cap(dir: &TempDir) -> Option<u64> {
    Store::load(dir.caps())
        .cap_for(BUS, NAME, TOTAL_MIB * MIB)
        .map(|c| c.max_element_threshold)
}

/// A program that fits only at the smaller size: its out-of-memory lowers the card without counting
/// as a failure, the retry belongs on this card and runs there at once at the smaller size, and once
/// it proves the cap is recorded for later runs.
#[test]
fn an_sp1_out_of_memory_is_retried_on_its_card_one_size_smaller_and_recorded_once_it_proves() {
    let dir = TempDir::new("sp1-oom-cap");
    let pool = sp1_pool(
        &dir,
        &[("MOCK_OOM_UNLESS_CAP_AT_MOST", &SMALLER.to_string())],
    );

    let e = prove(&pool, b"heavy").expect_err("runs out at 268M");
    assert!(matches!(
        worker_error_kind(&e),
        ErrorKind::ResourceExhausted
    ));
    assert_eq!(
        pool.test_consecutive_failures(SP1_KEY),
        Some(0),
        "no failure"
    );
    assert_eq!(
        pool.spawn_env_value(SP1_KEY, t::SP1_ELEMENT_THRESHOLD_CAP_ENV)
            .as_deref(),
        Some("134217728")
    );
    assert_eq!(
        pool.take_sp1_retry_card(SP1_KEY),
        Some(WorkerPool::gpu_device_id("cuda", "0"))
    );
    assert_eq!(recorded_cap(&dir), None, "not before it proves");

    // The retry: no respawn backoff, a worker at the smaller size, and it proves.
    prove(&pool, b"heavy").expect("proves at 134M");
    assert_eq!(dir.record(), ["prove cap=none", "prove cap=134217728"]);
    assert_eq!(recorded_cap(&dir), Some(SMALLER));
    assert_eq!(pool.test_consecutive_failures(SP1_KEY), Some(0));
}

/// Another program's memory grew while the proof ran: the card is lowered for the run, but the
/// retry is not pinned to it (that memory is likely still there) and nothing is recorded.
#[test]
fn an_sp1_out_of_memory_another_programs_growth_caused_is_neither_pinned_nor_recorded() {
    let dir = TempDir::new("sp1-oom-growth");
    let pool = Arc::new(sp1_pool(
        &dir,
        &[
            ("MOCK_OOM_UNLESS_CAP_AT_MOST", &SMALLER.to_string()),
            ("MOCK_PROVE_DELAY_SECS", "2"),
        ],
    ));
    let grows = {
        let pool = Arc::clone(&pool);
        std::thread::spawn(move || {
            // While the proof runs, after its admission read none of another program's.
            std::thread::sleep(Duration::from_millis(1_000));
            pool.test_set_cards(SP1_KEY, vec![Some(card(600))]);
        })
    };
    let e = prove(&pool, b"squeezed").expect_err("runs out");
    grows.join().unwrap();
    assert!(matches!(
        worker_error_kind(&e),
        ErrorKind::ResourceExhausted
    ));
    assert_eq!(pool.test_consecutive_failures(SP1_KEY), Some(0));
    assert_eq!(
        pool.spawn_env_value(SP1_KEY, t::SP1_ELEMENT_THRESHOLD_CAP_ENV)
            .as_deref(),
        Some("134217728"),
        "lowered for the run"
    );
    assert_eq!(pool.take_sp1_retry_card(SP1_KEY), None, "not pinned");
    prove(&pool, b"squeezed").expect("proves at 134M");
    assert_eq!(recorded_cap(&dir), None, "never recorded");
    assert!(!dir.caps().exists());
}

/// A program that runs out at the smaller size too: the lowering did not help, so it is undone and
/// the second out-of-memory counts as a failure.
#[test]
fn an_sp1_out_of_memory_at_the_smaller_size_too_undoes_the_lowering() {
    let dir = TempDir::new("sp1-oom-undo");
    let pool = sp1_pool(&dir, &[("MOCK_PROVE_ERROR_KIND", "resource_exhausted")]);
    prove(&pool, b"too heavy").expect_err("runs out at 268M");
    assert_eq!(pool.test_consecutive_failures(SP1_KEY), Some(0));
    assert!(pool.take_sp1_retry_card(SP1_KEY).is_some());
    prove(&pool, b"too heavy").expect_err("runs out at 134M too");
    assert_eq!(dir.record(), ["prove cap=none", "prove cap=134217728"]);
    assert_eq!(pool.test_consecutive_failures(SP1_KEY), Some(1));
    assert_eq!(
        pool.spawn_env_value(SP1_KEY, t::SP1_ELEMENT_THRESHOLD_CAP_ENV),
        None,
        "undone"
    );
    assert_eq!(pool.take_sp1_retry_card(SP1_KEY), None);
    assert_eq!(recorded_cap(&dir), None);
}

/// A failure that is not an out-of-memory has nothing to do with the size: no lowering, and the
/// worker, which answered, is kept.
#[test]
fn an_sp1_proof_failure_lowers_nothing() {
    let dir = TempDir::new("sp1-fail");
    let pool = sp1_pool(&dir, &[("MOCK_PROVE_ERROR_KIND", "proof_failed")]);
    let e = prove(&pool, b"broken").expect_err("fails");
    assert!(matches!(worker_error_kind(&e), ErrorKind::ProofFailed));
    assert_eq!(pool.test_consecutive_failures(SP1_KEY), Some(0));
    assert_eq!(pool.test_has_handle(SP1_KEY), Some(true));
    assert_eq!(
        pool.spawn_env_value(SP1_KEY, t::SP1_ELEMENT_THRESHOLD_CAP_ENV),
        None
    );
    assert_eq!(pool.take_sp1_retry_card(SP1_KEY), None);

    // A second in a row restarts the worker, and so its GPU server, which may be what can no
    // longer prove; still not counted as a failure.
    prove(&pool, b"broken").expect_err("fails again");
    assert_eq!(pool.test_has_handle(SP1_KEY), Some(false), "restarted");
    assert_eq!(pool.test_consecutive_failures(SP1_KEY), Some(0));
    // The next proof starts a fresh worker, and the count over.
    prove(&pool, b"broken").expect_err("fails on the fresh worker");
    assert_eq!(pool.test_has_handle(SP1_KEY), Some(true));
}

/// A job's own input or program failing says nothing about the server: never a restart.
#[test]
fn an_sp1_job_rejected_for_its_input_never_restarts_the_worker() {
    let dir = TempDir::new("sp1-invalid");
    let pool = sp1_pool(&dir, &[("MOCK_PROVE_ERROR_KIND", "invalid_input")]);
    for _ in 0..3 {
        let e = prove(&pool, b"bad input").expect_err("rejected");
        assert!(matches!(worker_error_kind(&e), ErrorKind::InvalidInput));
        assert_eq!(pool.test_has_handle(SP1_KEY), Some(true));
    }
}

/// A worker from before this protocol (one that would ignore the card cap and miss sp1-gpu's own
/// out-of-memory wordings) is refused at the handshake.
#[test]
fn a_worker_of_an_older_protocol_is_refused() {
    let older = (zkminer_prover_protocol::PROTOCOL_VERSION - 1).to_string();
    let env = HashMap::from([
        ("MOCK_BACKEND".to_string(), "sp1".to_string()),
        ("MOCK_PROTOCOL_VERSION".to_string(), older),
    ]);
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    let e = pool
        .insert_test_worker(SP1_KEY, "sp1", mock_worker_path(), env)
        .expect_err("an older worker");
    assert!(
        format!("{e:#}").contains("Protocol version mismatch"),
        "{e:#}"
    );
    const _: () = assert!(zkminer_prover_protocol::PROTOCOL_VERSION >= 14);
}

/// An SP1 benchmark that runs out of GPU memory at the card's size is measured again at once one
/// shard size smaller, and that size is recorded once the benchmark completes there: the rate the
/// miner saves is one the card can run at, not a rate measured at a size it overflows.
#[test]
fn an_sp1_benchmark_that_runs_out_of_memory_is_measured_again_smaller_and_recorded() {
    let dir = TempDir::new("sp1-bench-oom");
    let pool = sp1_pool(
        &dir,
        &[("MOCK_OOM_UNLESS_CAP_AT_MOST", &SMALLER.to_string())],
    );
    pool.benchmark("sp1").expect("benchmarked");
    assert_eq!(
        pool.spawn_env_value(SP1_KEY, t::SP1_ELEMENT_THRESHOLD_CAP_ENV)
            .as_deref(),
        Some("134217728")
    );
    assert_eq!(
        recorded_cap(&dir),
        Some(SMALLER),
        "recorded once it completed"
    );
    assert_eq!(pool.test_consecutive_failures(SP1_KEY), Some(0));
    // Two runs: the warm-up and the suite at the card's size, then both again at the smaller one.
    assert_eq!(dir.record().len(), 4, "{:?}", dir.record());
}

/// One that runs out at the smallest size too gets no row: the lowering is undone, nothing is
/// recorded, and the card is not given a rate it cannot run at.
#[test]
fn an_sp1_benchmark_out_of_memory_at_every_size_gives_no_row() {
    let dir = TempDir::new("sp1-bench-oom-all");
    let pool = sp1_pool(&dir, &[("MOCK_OOM_UNLESS_CAP_AT_MOST", "1")]);
    let rows = pool.benchmark("sp1").expect("the pool answers");
    assert!(rows.is_empty());
    assert_eq!(
        pool.spawn_env_value(SP1_KEY, t::SP1_ELEMENT_THRESHOLD_CAP_ENV),
        None,
        "undone"
    );
    assert_eq!(recorded_cap(&dir), None);
    assert!(!dir.caps().exists());
}

/// A risc0 slot on `vram_mib` of CUDA card, its worker the mock, with `card` as its reading.
fn risc0_pool(dir: &TempDir, vram_mib: u64, reading: TestCard) -> WorkerPool {
    let key = "risc0:cuda:0";
    let env = HashMap::from([
        ("MOCK_BACKEND".to_string(), "risc0".to_string()),
        (
            "MOCK_RECORD_TO".to_string(),
            dir.0.join("record").display().to_string(),
        ),
    ]);
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker(key, "risc0", mock_worker_path(), env)
        .expect("spawn the mock worker");
    pool.test_set_card_identity(key, "cuda", Some(BUS), Some(NAME), Some(vram_mib * MIB));
    pool.test_set_cards(key, vec![Some(reading)]);
    pool
}

/// A risc0 card is benchmarked at its own job size, on every request of its suite: 19 on a 12 GB
/// card, 20 on a larger one. An SP1 slot is sent none.
#[test]
fn a_risc0_card_is_benchmarked_at_its_own_job_size() {
    for (vram_mib, po2) in [(TOTAL_MIB, 19u8), (24_564, 20)] {
        let dir = TempDir::new(&format!("risc0-bench-{vram_mib}"));
        let reading = TestCard {
            total_mib: vram_mib,
            ..card(0)
        };
        let pool = risc0_pool(&dir, vram_mib, reading);
        let _ = pool.benchmark("risc0");
        let record = dir.record();
        assert!(!record.is_empty(), "the suite was sent");
        for line in &record {
            assert_eq!(line, &format!("benchmark po2=Some({po2})"), "{record:?}");
        }
    }
    let dir = TempDir::new("sp1-bench");
    let pool = sp1_pool(&dir, &[]);
    let _ = pool.benchmark("sp1");
    let record = dir.record();
    assert!(!record.is_empty());
    assert!(
        record.iter().all(|l| l == "benchmark po2=None"),
        "{record:?}"
    );
}

/// Calibration sizes its run against what physically fits: the Windows shared-card margin is
/// sizing's, not calibration's (its own 10% is its headroom).
#[test]
fn calibration_sizes_against_what_physically_fits() {
    use zkminer_prover::benchmark::find_optimal_gpu_po2;
    let dir = TempDir::new("risc0-calibrate");
    let margin_mib = 1_024;
    let with_margin_mib = 9_500;
    let fits = |mib: u64| find_optimal_gpu_po2(mib * MIB, "risc0", "cuda").0;
    assert_eq!(fits(with_margin_mib), 19);
    assert_eq!(
        fits(with_margin_mib - margin_mib),
        18,
        "the margin decides it"
    );
    let reading = TestCard {
        growth_margin_mib: margin_mib,
        ..card(TOTAL_MIB - RESERVED_MIB - with_margin_mib)
    };
    let pool = risc0_pool(&dir, TOTAL_MIB, reading);
    let sample = pool
        .calibrate_slot_po2("risc0:cuda:0", 20)
        .expect("the mock calibrates");
    assert_eq!(sample.po2, 19);
}
