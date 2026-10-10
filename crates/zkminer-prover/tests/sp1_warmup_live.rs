//! SP1's warm-up against the real worker and the real circuit artifacts: a download cut short
//! leaves nothing that passes for an install, and the next warm-up completes it.
//!
//! This is what a first proof on a fresh host used to do inside its watchdog, through the SDK's own
//! installer, which creates the directory first and trusts any directory it finds: a download cut
//! short left a torn install that failed every later proof.
//!
//! Downloads the ~6.2 GB artifact tarball (twice: once cut short) into a scratch directory, never
//! into `~/.sp1`. Needs the release build of `zkminer-prove-sp1` (or `ZKMINER_SP1_WORKER`), and
//! network access. Run with:
//!   cargo test -p zkminer-prover --features testing --test sp1_warmup_live -- --ignored --nocapture

#![cfg(all(unix, feature = "testing"))]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use zkminer_prover::dispatcher::WorkerPool;

fn worker_binary() -> PathBuf {
    std::env::var_os("ZKMINER_SP1_WORKER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/zkminer-prove-sp1")
        })
}

#[test]
#[ignore = "downloads ~12 GB"]
fn a_download_cut_short_is_redone_and_never_trusted() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
    let worker = worker_binary();
    assert!(
        worker.is_file(),
        "build zkminer-prove-sp1 first: {}",
        worker.display()
    );

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/sp1-warmup-live-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let circuits = root.join("groth16");
    let version_dir = circuits.join("v6.0.0");
    let mut env = HashMap::new();
    env.insert(
        "SP1_GROTH16_CIRCUIT_PATH".to_string(),
        circuits.display().to_string(),
    );
    // The real server must not be replaced by anything during this test.
    env.insert("ZKMINER_SP1_SERVER_INSTALL".to_string(), "0".to_string());

    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("sp1:generic", "sp1", worker.clone(), env)
        .expect("failed to start the SP1 worker");

    // Cut short by the watchdog, as a first proof's 90 s budget would cut it.
    let cut = pool.warm_up("sp1", Duration::from_secs(20));
    assert!(cut.is_err(), "the download should not finish in 20 s");
    assert!(!pool.backend_warmed("sp1"));
    assert!(
        !version_dir.exists(),
        "a download cut short must publish nothing at {}",
        version_dir.display()
    );

    // The next warm-up (on a respawned worker) sweeps the debris and completes the install.
    let summary = pool
        .warm_up("sp1", Duration::from_secs(60 * 60))
        .expect("warm-up failed");
    eprintln!("warm-up: {summary}");
    assert!(summary.contains("downloaded"), "{summary}");
    assert!(pool.backend_warmed("sp1"));
    for name in [
        "groth16_circuit.bin",
        "groth16_pk.bin",
        "groth16_vk.bin",
        "constraints.json",
    ] {
        let len = std::fs::metadata(version_dir.join(name))
            .map(|m| m.len())
            .unwrap_or(0);
        assert!(len > 0, "{name} is missing or empty");
    }
    let debris: Vec<String> = std::fs::read_dir(&circuits)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("staging"))
        .collect();
    assert!(debris.is_empty(), "staging left behind: {debris:?}");

    // And once installed, it is found rather than fetched again.
    let again = pool
        .warm_up("sp1", Duration::from_secs(120))
        .expect("second warm-up failed");
    assert!(again.contains("already installed"), "{again}");

    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&root);
}
