//! W10-BENCH: `zkminer benchmark` end to end, with the mock worker standing in for a prover.
//!
//! In the macOS 26 VM the Metal worker's warm-up failed, and `zkminer benchmark` then printed a table
//! of SIMULATED results (3,009,039,154 c/s, a zkOP/s score) and exited 0. Here a worker that fails
//! must give a failure (no table, the worker and its error named, what to try, a non-zero exit), and
//! only a machine with no worker at all may see the simulated table, labelled as such.
//!
//! Needs the mock worker (crates/zkminer-prover/src/bin/mock_worker.rs):
//!
//! ```sh
//! cargo build -p zkminer-prover --features testing --bin mock-worker
//! cargo test -p zkminer-cli --test benchmark_cli
//! ```
//!
//! `ZKMINER_TEST_MOCK_WORKER` overrides the mock's path (default `target/debug/mock-worker`). Each
//! test runs the CLI with its own `HOME`, so nothing of the user's `~/.zkminer` is read or written, and
//! from its own directory: discovery also searches the CLI's own directory, and cargo's
//! `target/debug` can hold a real worker (zkminer-prove-risc0-metal), which must not be started.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The mock worker, or `None` (with a message) when it is not built: `cargo test -p zkminer-cli`
/// does not build it (it is another package's binary, behind its `testing` feature), so a test that
/// needs one skips rather than fails.
fn mock_worker() -> Option<PathBuf> {
    let path = std::env::var("ZKMINER_TEST_MOCK_WORKER")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root().join("target/debug/mock-worker"));
    if path.is_file() {
        return Some(path);
    }
    eprintln!(
        "SKIPPED: no mock worker at {}: build it (cargo build -p zkminer-prover --features testing \
         --bin mock-worker) or set ZKMINER_TEST_MOCK_WORKER",
        path.display()
    );
    None
}

/// A fresh `HOME` with `~/.zkminer/provers/<worker>` linked to the mock, or no worker at all. `None`
/// when a worker is wanted and the mock is not built (the test is skipped).
fn sandbox(tag: &str, worker: Option<&str>) -> Option<PathBuf> {
    let mock = match worker {
        Some(_) => Some(mock_worker()?),
        None => None,
    };
    let home = std::env::temp_dir().join(format!(
        "zkminer-bench-cli-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let provers = home.join(".zkminer/provers");
    std::fs::create_dir_all(&provers).unwrap();
    if let (Some(name), Some(mock)) = (worker, mock) {
        std::os::unix::fs::symlink(mock, provers.join(name)).unwrap();
    }
    let bin = home.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let cli = bin.join("zkminer");
    let built = Path::new(env!("CARGO_BIN_EXE_zkminer"));
    if std::fs::hard_link(built, &cli).is_err() {
        std::fs::copy(built, &cli).unwrap();
    }
    Some(home)
}

fn zkminer_benchmark(home: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(home.join("bin/zkminer"));
    cmd.arg("benchmark")
        .args(args)
        .env("HOME", home)
        .env_remove("ZKMINER_TEST_FORCE_FAIL")
        .env("MOCK_BACKEND", "risc0")
        .env(
            "MOCK_SDK_VERSION",
            format!(
                "risc0-zkvm {}.0",
                zkminer_prover_protocol::RISC0_ZKVM_MAJOR_MINOR
            ),
        );
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run zkminer benchmark")
}

const STEP_ACCUM: &str =
    "warm-up failed: loading the rv32im metallib: compute pipeline for stepAccumA: Compilation failed";

fn assert_failed_without_a_table(out: &Output, worker: &str, advice: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a failed benchmark exited 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    for absent in ["Program", "simulated", "SIMULATED", "zkOP/s", "c/s"] {
        assert!(
            !stdout.contains(absent),
            "a failed benchmark printed {absent:?}:\n{stdout}"
        );
    }
    assert!(stderr.contains("BENCHMARK FAILED"), "{stderr}");
    assert!(
        stderr.contains(&format!("{worker}: warm-up of {worker} failed")),
        "{stderr}"
    );
    assert!(stderr.contains("stepAccumA"), "{stderr}");
    assert!(stderr.contains(advice), "no advice {advice:?}:\n{stderr}");
}

/// The VM's failure, on a Metal worker: a warm-up that answers with an error.
#[cfg(target_os = "macos")]
#[test]
fn a_metal_warm_up_failure_fails_the_benchmark() {
    let Some(home) = sandbox("metal", Some("zkminer-prove-risc0-metal")) else {
        return;
    };
    let env = [
        ("MOCK_FAIL_ON", "warmup"),
        ("MOCK_FAIL_MESSAGE", STEP_ACCUM),
    ];
    let out = zkminer_benchmark(&home, &[], &env);
    assert_failed_without_a_table(&out, "risc0:metal:0", "tools/macos-smoke.sh");

    // --calibrate saves nothing either, and --json prints nothing on stdout.
    let out = zkminer_benchmark(&home, &["--calibrate"], &env);
    assert_failed_without_a_table(&out, "risc0:metal:0", "tools/macos-smoke.sh");
    let out = zkminer_benchmark(&home, &["--json"], &env);
    assert!(!out.status.success());
    assert!(
        out.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!home.join(".zkminer/benchmarks.json").exists());
    let _ = std::fs::remove_dir_all(&home);
}

/// The same with a CPU (generic) risc0 worker: a failure, with the generic advice.
#[test]
fn a_cpu_worker_failure_fails_the_benchmark() {
    let Some(home) = sandbox("cpu", Some("zkminer-prove-risc0")) else {
        return;
    };
    let env = [
        ("MOCK_FAIL_ON", "warmup"),
        ("MOCK_FAIL_MESSAGE", STEP_ACCUM),
    ];
    let out = zkminer_benchmark(&home, &["--calibrate"], &env);
    assert_failed_without_a_table(&out, "risc0:generic", "--benchmark");
    assert!(!home.join(".zkminer/benchmarks.json").exists());
    let _ = std::fs::remove_dir_all(&home);
}

/// No worker at all: the only case that is simulated. Every line says so, there is no score, and
/// nothing is saved, even with --calibrate.
#[test]
fn with_no_worker_every_line_says_simulated() {
    let home = sandbox("none", None).expect("no worker needed");
    let out = zkminer_benchmark(&home, &["--calibrate"], &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    let table: Vec<&str> = stdout
        .lines()
        .skip_while(|l| !l.starts_with("SIMULATED BENCHMARK"))
        .filter(|l| !l.trim().is_empty() && !l.starts_with('─'))
        .collect();
    assert!(table.len() >= 5, "no simulated table:\n{stdout}");
    for line in &table {
        assert!(
            line.contains("SIMULATED"),
            "unlabelled line {line:?}:\n{stdout}"
        );
    }
    assert!(
        !stdout.contains("MzkOP/s"),
        "a score from a simulated run:\n{stdout}"
    );
    assert!(!home.join(".zkminer/benchmarks.json").exists());
    let _ = std::fs::remove_dir_all(&home);
}

/// W10-BENCH round 1: a Metal worker whose suite comes back short (four programs and the zkOP/s score
/// did not prove) fails the benchmark: the rows that proved are shown as incomplete, the exit is
/// non-zero, and --calibrate saves nothing. Before round 1 this printed a normal table with exit 0
/// and saved it.
#[cfg(target_os = "macos")]
#[test]
fn a_short_metal_suite_fails_the_benchmark_and_saves_nothing() {
    let Some(home) = sandbox("short", Some("zkminer-prove-risc0-metal")) else {
        return;
    };
    let env = [
        ("MOCK_BENCH_ROWS", "all"),
        (
            "MOCK_BENCH_DROP",
            "sha256-chain,ecdsa-verify,bigint-mul,chacha-mix,zkop-mix",
        ),
    ];
    let out = zkminer_benchmark(&home, &["--calibrate"], &env);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a short suite exited 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("BENCHMARK FAILED"), "{stderr}");
    assert!(stderr.contains("incomplete"), "{stderr}");
    for program in ["sha256-chain", "chacha-mix", "zkop-mix"] {
        assert!(stderr.contains(program), "{program} not named:\n{stderr}");
    }
    assert!(
        stdout.contains("memory-merkle"),
        "the proved row is not shown:\n{stdout}"
    );
    assert!(!home.join(".zkminer/benchmarks.json").exists());
    let _ = std::fs::remove_dir_all(&home);
}

/// The control for the test above: the same mock with every program proved is a normal benchmark,
/// exit 0, with a table and no failure.
#[cfg(target_os = "macos")]
#[test]
fn a_complete_metal_suite_is_a_normal_benchmark() {
    let Some(home) = sandbox("complete", Some("zkminer-prove-risc0-metal")) else {
        return;
    };
    let out = zkminer_benchmark(&home, &[], &[("MOCK_BENCH_ROWS", "all")]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(!stderr.contains("BENCHMARK FAILED"), "{stderr}");
    assert!(
        stdout.contains("memory-merkle") && stdout.contains("MzkOP/s"),
        "{stdout}"
    );
    assert!(!stdout.contains("SIMULATED"), "{stdout}");
    let _ = std::fs::remove_dir_all(&home);
}
