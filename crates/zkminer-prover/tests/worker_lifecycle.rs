//! Integration tests for the worker lifecycle: timeout → kill → EOF → cleanup → respawn.
//!
//! Uses a mock worker binary (`mock-worker`) that speaks the IPC protocol and
//! can be configured via env vars passed through spawn_env:
//! - `MOCK_HANG_ON`: hang on "benchmark", "prove", or "both"
//! - `MOCK_CRASH_ON`: exit(1) on "benchmark", "prove", or "both"
//!
//! Run with: `cargo test -p zkminer-prover --features testing --test worker_lifecycle`
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

// ---- risc0 version skew (P31-19) ----

/// The host prefixes its own risc0's Groth16 seal selector to every risc0 proof, so a worker built on
/// another risc0 (a stale 3.0 worker in ~/.zkminer/provers under a 3.1 host) or on another protocol
/// version must fail the handshake: never advertised, so no job is claimed for it.
#[test]
fn a_worker_on_another_risc0_or_protocol_is_refused_at_the_handshake() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(5)));
    let skewed = |sdk: &str, proto: Option<u32>| {
        let mut env = mock_env("", "");
        env.insert("MOCK_BACKEND".to_string(), "risc0".to_string());
        env.insert("MOCK_SDK_VERSION".to_string(), sdk.to_string());
        if let Some(p) = proto {
            env.insert("MOCK_PROTOCOL_VERSION".to_string(), p.to_string());
        }
        env
    };
    let this = format!(
        "risc0-zkvm {}.0",
        zkminer_prover_protocol::RISC0_ZKVM_MAJOR_MINOR
    );
    let err = pool
        .insert_test_worker(
            "risc0:a",
            "risc0",
            mock_worker_path(),
            skewed("risc0-zkvm 3.0.6", None),
        )
        .expect_err("a risc0 3.0 worker must be refused");
    assert!(format!("{err:#}").contains("risc0-zkvm 3.0.6"), "{err:#}");
    let old = zkminer_prover_protocol::PROTOCOL_VERSION - 1;
    let err = pool
        .insert_test_worker(
            "risc0:b",
            "risc0",
            mock_worker_path(),
            skewed(&this, Some(old)),
        )
        .expect_err("a previous-protocol worker must be refused");
    assert!(
        format!("{err:#}").contains("Protocol version mismatch"),
        "{err:#}"
    );
    pool.insert_test_worker("risc0:c", "risc0", mock_worker_path(), skewed(&this, None))
        .expect("this build's risc0 on this protocol is accepted");
}

// ---- Handshake ----

/// A worker built for another protocol version (an old one left in `~/.zkminer/provers`, which is
/// searched first) is a DECLINE, not a transient spawn failure: otherwise its slot stays "healthy",
/// is respawned on every dispatch, and the miner claims jobs only a stale worker would take.
#[test]
fn a_worker_of_another_protocol_version_declines() {
    let mut env = mock_env("", "");
    env.insert(
        "MOCK_PROTOCOL_VERSION".to_string(),
        (zkminer_prover_protocol::PROTOCOL_VERSION - 1).to_string(),
    );
    let err = match zkminer_prover::worker::WorkerHandle::spawn("mock", &mock_worker_path(), &env) {
        Ok(_) => panic!("a worker of another protocol version was accepted"),
        Err(e) => format!("{e:#}"),
    };
    assert!(
        err.contains(zkminer_prover_protocol::types::WORKER_DECLINED),
        "not a decline: {err}"
    );
    assert!(err.contains("Protocol version mismatch"), "{err}");
    // This build's version is accepted.
    zkminer_prover::worker::WorkerHandle::spawn("mock", &mock_worker_path(), &mock_env("", ""))
        .expect("a worker of this protocol version");
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

/// `benchmark_timeout` bounds each step of a benchmark, not the whole run: a worker whose warm-up and
/// suite each take 2 s (4 s in all) outlives a 3 s timeout, as an Arc A770's risc0 benchmark (over
/// 30 minutes, no step past about 10) outlives the default 1800 s.
#[test]
fn a_benchmark_longer_than_its_timeout_survives_when_each_step_fits() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(3)));
    let mut env = mock_env("", "");
    env.insert("MOCK_BENCHMARK_SECS".to_string(), "2".to_string());
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), env)
        .expect("failed to spawn mock worker");
    let pid = pool.test_pid("mock:generic").unwrap();

    let started = std::time::Instant::now();
    assert!(pool.benchmark("mock").is_ok());
    assert!(
        started.elapsed() >= Duration::from_secs(4),
        "the benchmark should have taken both steps: {:?}",
        started.elapsed()
    );
    assert_eq!(
        pool.test_has_handle("mock:generic"),
        Some(true),
        "the worker was killed"
    );
    assert_eq!(pool.test_pid("mock:generic"), Some(pid));
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));
}

// ---- Intel warm-ups ----

/// The pids that warmed up, one line per `Warmup` the mock answered (`MOCK_WARMUP_LOG`).
fn warmups(log: &std::path::Path) -> usize {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .count()
}

fn risc0_env(log: &std::path::Path, hang_on: &str) -> HashMap<String, String> {
    let mut env = mock_env(hang_on, "");
    env.insert("MOCK_BACKEND".to_string(), "risc0".to_string());
    env.insert("MOCK_WARMUP_LOG".to_string(), log.display().to_string());
    env
}

/// On Windows the mock worker runs at Low integrity, as every worker does, so the log's directory is
/// labelled for it to write in.
fn warmup_log(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zkminer-warmup-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(windows)]
    zkminer_prover::windows_sandbox::label_low_writable_for_tests(&dir).unwrap();
    dir.join("warmups")
}

/// An Intel card's kernels are compiled for it on its first proof, so each is warmed up before it
/// proves. The startup warm-up warms every Intel card and records each: it used to warm only the
/// first slot and record only the backend, so every Intel card warmed up again inside its first
/// claimed proof (on a start that ran no benchmark).
#[test]
fn the_startup_warm_up_warms_each_intel_card_once() {
    let log = warmup_log("each-card");
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    for key in ["risc0:intel:0", "risc0:intel:1"] {
        pool.insert_test_worker(key, "risc0", mock_worker_path(), risc0_env(&log, ""))
            .expect("failed to spawn mock worker");
    }
    pool.warm_up("risc0", Duration::from_secs(60))
        .expect("warm up");
    assert_eq!(warmups(&log), 2, "one warm-up per Intel card");
    for _ in 0..4 {
        pool.prove("risc0", &[], &[], None, Some(Duration::from_secs(10)), None)
            .expect("a warmed card proves");
    }
    assert_eq!(warmups(&log), 2, "a claimed proof warmed a card up again");
    let _ = std::fs::remove_dir_all(log.parent().unwrap());
}

/// An Intel card whose startup warm-up failed warms up before its first proof, inside the job's
/// deadline, not inside `WARMUP_TIMEOUT` (an hour): a warm-up that hangs is cut where the proof could
/// no longer start (15 s before the deadline), and the job fails with a deadline error.
#[test]
fn an_intel_warm_up_inside_a_claimed_proof_stops_at_its_deadline() {
    let log = warmup_log("deadline");
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker(
        "risc0:cuda:0",
        "risc0",
        mock_worker_path(),
        risc0_env(&log, ""),
    )
    .expect("failed to spawn mock worker");
    pool.insert_test_worker(
        "risc0:intel:0",
        "risc0",
        mock_worker_path(),
        risc0_env(&log, "warmup"),
    )
    .expect("failed to spawn mock worker");
    // The backend warms on the CUDA slot; the Intel card's warm-up hangs and is cut at 3 s.
    pool.warm_up("risc0", Duration::from_secs(3))
        .expect("the backend warms up");
    let before = warmups(&log);

    let eligible = ["gpu-intel0".to_string()];
    let started = std::time::Instant::now();
    let err = pool
        .prove_min_vram(
            "risc0",
            &[],
            &[],
            None,
            Some(Duration::from_secs(600)),
            None,
            None,
            &[],
            &[],
            &mut None,
            Some(started + Duration::from_secs(25)),
            None,
            None,
            zkminer_prover::dispatcher::JobCards {
                eligible: &eligible,
                order: &eligible,
            },
            0,
        )
        .expect_err("a card that cannot warm up cannot prove");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the warm-up outlived the job: {:?}",
        started.elapsed()
    );
    assert_eq!(
        warmups(&log),
        before + 1,
        "the card warmed up inside the proof"
    );
    assert!(
        err.downcast_ref::<zkminer_prover_protocol::types::ProofDeadlineReached>()
            .is_some()
            || format!("{err:#}").contains("deadline"),
        "{err:#}"
    );
    let _ = std::fs::remove_dir_all(log.parent().unwrap());
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

/// What the dispatcher makes of an SP1 worker that lost its `sp1-gpu-server` and exited: a new worker,
/// whose next proof succeeds, and a slot not retired however often it happens, as that can be one
/// job's doing and the job is what the retry budget is for. Exit code 75 is told apart only for a host
/// OOM, which `a_lost_server_after_a_host_oom_is_a_memory_shortage` covers.
#[test]
fn a_worker_that_lost_its_server_is_replaced_and_the_next_proof_succeeds() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    let mut env = mock_env("", "prove");
    env.insert(
        "MOCK_CRASH_CODE".to_string(),
        zkminer_prover_protocol::types::WORKER_EXIT_SERVER_LOST.to_string(),
    );
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), env.clone())
        .expect("failed to spawn mock worker");

    for round in 0..3 {
        let result = pool.prove("mock", &[], &[], None, Some(Duration::from_secs(30)), None);
        let e = result.expect_err("this worker exits on every proof");
        assert!(
            e.downcast_ref::<zkminer_prover::worker::WorkerDied>()
                .is_some(),
            "round {round}: {e:#}"
        );
        // Never sent to a dead worker again: the handle is gone, and the PID with it.
        assert_eq!(pool.test_has_handle("mock:generic"), Some(false));
        assert_eq!(pool.test_pid("mock:generic"), Some(0));
        // One failure: the respawn that follows clears it, so repeats cannot retire the slot.
        assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(1));
    }

    pool.test_set_spawn_env("mock:generic", mock_env("", ""));
    let output = pool
        .prove("mock", &[], &[], None, Some(Duration::from_secs(30)), None)
        .expect("the replacement proves");
    assert_eq!(output.cycles, 1000);
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));
}

/// What a preempted SP1 measurement staged goes with it. SIGKILL skips the executor's own cleanup, and
/// the room is about to be given to the proof, so left there the two add up to a full tmpfs and a
/// SIGBUS.
// `/dev/shm` is Linux's.
#[cfg(target_os = "linux")]
#[test]
// Linux only: there is no `/dev/shm` tmpfs on macOS (POSIX shm is not a directory there), SP1's native
// executor does not stage that way off Linux, and `worker::unlink_group_sp1_shm` is compiled only for
// Linux. On macOS the mock cannot stage, so the test failed with "the mock never staged" (M6).
#[cfg(target_os = "linux")]
fn preempting_an_sp1_measurement_unlinks_what_it_staged() {
    let shm_name = format!("sp1_mocktest{}_t", std::process::id());
    let shm_file = format!("/dev/shm/{shm_name}");
    let mut env = mock_env("execute", "");
    env.insert("MOCK_BACKEND".to_string(), "sp1".to_string());
    env.insert("MOCK_HOLD_SHM".to_string(), shm_name);
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("sp1:measure:0", "sp1", mock_worker_path(), env)
        .expect("failed to spawn mock worker");
    let pool = Arc::new(pool);
    let measurer = {
        let pool = Arc::clone(&pool);
        std::thread::spawn(move || {
            pool.execute_cycles("sp1", &[], &[], Some(Duration::from_secs(120)), None, None)
        })
    };
    // The mock names the file only once it is mapped, which is how the kill will find it.
    let started = Instant::now();
    while !std::path::Path::new(&shm_file).exists() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the mock never staged"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    pool.test_preempt_all_inflight_measures();
    let err = measurer.join().unwrap().expect_err("it was preempted");
    assert!(
        err.downcast_ref::<zkminer_prover_protocol::types::MeasurePreempted>()
            .is_some(),
        "{err:#}"
    );
    let leaked = std::path::Path::new(&shm_file).exists();
    let _ = std::fs::remove_file(&shm_file);
    assert!(
        !leaked,
        "preempting a measurement must not leave what it staged in /dev/shm"
    );
}

/// The same preemption with a real SP1 worker and guest, for what they really stage. SP1's executor
/// shares the guest's memory and trace ring with its runner through memfds, not `/dev/shm` files
/// (see `zkminer-prove-sp1`'s confinement), so what it stages is read from the host's shared memory
/// (`Shmem` in `/proc/meminfo`, which counts memfd pages) and must come back once it is preempted.
///
///   ZKMINER_TEST_SP1_WORKER=<zkminer-prove-sp1> cargo test -p zkminer-prover --features testing \\
///     --test worker_lifecycle -- --ignored --test-threads=1 preempting_a_real_sp1_measurement
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs a real zkminer-prove-sp1, and no other SP1 execution on this host"]
fn preempting_a_real_sp1_measurement_frees_what_it_staged() {
    /// The host's shared memory in use: tmpfs, SysV and memfd pages.
    fn shmem() -> u64 {
        let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap();
        let kib: u64 = meminfo
            .lines()
            .find_map(|l| l.strip_prefix("Shmem:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
            .expect("Shmem in /proc/meminfo");
        kib * 1024
    }
    let worker =
        PathBuf::from(std::env::var("ZKMINER_TEST_SP1_WORKER").expect("the worker to run"));
    let dir = std::env::temp_dir().join(format!("zkminer-preempt-shm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf_path = dir.join("guest.elf");
    let exported = std::process::Command::new(&worker)
        .args(["--export-guest", "sha256-chain"])
        .arg(&elf_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(exported.success());
    let elf = std::fs::read(&elf_path).unwrap();
    let before_staging = shmem();
    let staged = || shmem().saturating_sub(before_staging);

    let mut env = HashMap::new();
    env.insert(
        zkminer_prover_protocol::types::SP1_MEASURE_ONLY_ENV.to_string(),
        "1".to_string(),
    );
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("sp1:measure:0", "sp1", worker, env)
        .expect("failed to spawn the SP1 worker");
    let pool = Arc::new(pool);
    let measurer = {
        let pool = Arc::clone(&pool);
        let input = 2_000_000u32.to_le_bytes().to_vec();
        std::thread::spawn(move || {
            pool.execute_cycles(
                "sp1",
                &elf,
                &input,
                Some(Duration::from_secs(300)),
                None,
                None,
            )
        })
    };
    let started = Instant::now();
    while staged() < 500 * 1024 * 1024 {
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "it never staged ({} bytes of shared memory)",
            staged()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let peak = staged();
    pool.test_preempt_all_inflight_measures();
    let err = measurer.join().unwrap().expect_err("it was preempted");
    assert!(
        err.downcast_ref::<zkminer_prover_protocol::types::MeasurePreempted>()
            .is_some(),
        "{err:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    // The pages themselves come back, not just the names: the runner that mapped them is gone.
    let started = Instant::now();
    while staged() > 64 * 1024 * 1024 {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{peak} bytes staged, {} still in use after the preemption",
            staged()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A host OOM kills the largest process, which for SP1 is the server and not the worker, and the
/// worker then exits on its own account. That must still read as a memory shortage, or a healthy card
/// is excluded for what the host did. Needs a real OOM kill, so a worker adopted into a memory-capped
/// scope, whose limit the mock lowers before it allocates, and so a systemd user manager:
///
///   cargo test -p zkminer-prover --features testing --test worker_lifecycle -- --ignored \\
///     a_lost_server_after_a_host_oom_is_a_memory_shortage
#[test]
#[ignore = "needs a systemd user manager to cap the worker's memory"]
fn a_lost_server_after_a_host_oom_is_a_memory_shortage() {
    let code = zkminer_prover_protocol::types::WORKER_EXIT_SERVER_LOST;
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    let mut env = mock_env("", "prove");
    env.insert("MOCK_CRASH_CODE".to_string(), code.to_string());
    env.insert("MOCK_SERVER_OOM".to_string(), "1".to_string());
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), env)
        .expect("failed to spawn mock worker");

    let e = pool
        .prove("mock", &[], &[], None, Some(Duration::from_secs(120)), None)
        .expect_err("this worker exits on the proof");
    let shortage = e
        .downcast_ref::<zkminer_prover_protocol::types::HostMemoryShortage>()
        .unwrap_or_else(|| panic!("not read as a host OOM: {e:#}"));
    assert!(shortage.attempted);
    assert_eq!(
        pool.test_consecutive_failures("mock:generic"),
        Some(0),
        "a host OOM is not charged to the slot"
    );
}

// ---- Windows: a failure for want of host memory is not the card's ----

/// A worker that exits with `STATUS_COMMITMENT_LIMIT` died because the host's commit ran out, not
/// because its card failed: a memory shortage that costs the attempt and is not charged to the slot.
#[cfg(windows)]
#[test]
fn a_worker_that_died_out_of_commit_is_a_host_memory_shortage() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    let mut env = mock_env("", "prove");
    env.insert(
        "MOCK_CRASH_CODE".to_string(),
        (0xC000_012Du32 as i32).to_string(),
    );
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), env)
        .expect("failed to spawn mock worker");

    let e = pool
        .prove("mock", &[], &[], None, Some(Duration::from_secs(30)), None)
        .expect_err("this worker exits on the proof");
    let shortage = e
        .downcast_ref::<zkminer_prover_protocol::types::HostMemoryShortage>()
        .unwrap_or_else(|| panic!("not read as a host shortage: {e:#}"));
    assert!(shortage.attempted);
    assert_eq!(
        pool.test_consecutive_failures("mock:generic"),
        Some(0),
        "a host shortage is not charged to the slot"
    );
}

/// The same death with another code, and the host not short, is the worker's own failure.
#[cfg(windows)]
#[test]
fn a_worker_that_crashed_otherwise_is_its_own_failure() {
    let roomy = zkminer_prover::memory::mem_available_bytes().unwrap_or(0)
        > 2 * zkminer_prover::memory::HOST_SHORT_LOW_WATER_BYTES;
    if !roomy {
        eprintln!("skipped: this host is short of memory now, which is the other case");
        return;
    }
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    let mut env = mock_env("", "prove");
    env.insert(
        "MOCK_CRASH_CODE".to_string(),
        (0xC000_0005u32 as i32).to_string(),
    );
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), env)
        .expect("failed to spawn mock worker");

    let e = pool
        .prove("mock", &[], &[], None, Some(Duration::from_secs(30)), None)
        .expect_err("this worker exits on the proof");
    assert!(e
        .downcast_ref::<zkminer_prover_protocol::types::HostMemoryShortage>()
        .is_none());
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(1));
    // Its exit code is in the error.
    assert!(format!("{e:#}").contains("0xC0000005"), "{e:#}");
}

/// A worker reporting that it ran out of memory while the host had plenty ran out on its CARD: that
/// stays the typed GPU out-of-memory.
#[cfg(windows)]
#[test]
fn an_out_of_memory_with_room_on_the_host_is_the_cards() {
    let roomy = zkminer_prover::memory::mem_available_bytes().unwrap_or(0)
        > 2 * zkminer_prover::memory::HOST_SHORT_LOW_WATER_BYTES;
    if !roomy {
        eprintln!("skipped: this host is short of memory now, which is the other case");
        return;
    }
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    let mut env = mock_env("", "");
    env.insert(
        "MOCK_PROVE_ERROR_KIND".to_string(),
        "resource_exhausted".to_string(),
    );
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), env)
        .expect("failed to spawn mock worker");

    let e = pool
        .prove("mock", &[], &[], None, Some(Duration::from_secs(30)), None)
        .expect_err("this worker reports an out-of-memory");
    assert!(e
        .downcast_ref::<zkminer_prover_protocol::types::HostMemoryShortage>()
        .is_none());
    let worker = e
        .downcast_ref::<zkminer_prover_protocol::types::WorkerProofError>()
        .unwrap_or_else(|| panic!("not the worker's typed error: {e:#}"));
    assert!(worker.is_gpu_oom());
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

// ---- Making room on a card ----

/// Recycling a sibling to make room on its card, against real worker processes: an idle one is shut
/// down and left ready to respawn — pid retracted, no failure counted — and one whose slot is held is
/// left alone, promptly.
#[test]
fn an_idle_sibling_is_recycled_and_a_busy_one_is_left_alone() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker(
        "mock:busy",
        "mock",
        mock_worker_path(),
        mock_env("prove", ""),
    )
    .expect("failed to spawn mock worker");
    pool.insert_test_worker("mock:idle", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    let busy_pid = pool.test_pid("mock:busy").unwrap();
    let idle_pid = pool.test_pid("mock:idle").unwrap();
    assert!(busy_pid > 0 && idle_pid > 0);

    // A hung proof holds `mock:busy`'s slot for its whole duration.
    let pool = Arc::new(pool);
    let prover = {
        let pool = pool.clone();
        std::thread::spawn(move || {
            pool.prove(
                "mock:busy",
                &[],
                &[],
                None,
                Some(Duration::from_secs(4)),
                None,
            )
        })
    };
    // Wait until the proof actually holds the slot, rather than sleeping and hoping it does.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !pool.test_slot_is_held("mock:busy") {
        assert!(
            Instant::now() < deadline,
            "the hung proof never took its slot"
        );
        assert!(!prover.is_finished(), "the hung proof finished early");
        std::thread::sleep(Duration::from_millis(20));
    }

    let started = Instant::now();
    let recycled = pool.test_evict_idle_siblings("sp1:cuda:0", &["mock:busy".to_string()]);
    assert!(recycled.is_empty(), "a sibling in use must not be recycled");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "giving up on a held sibling took {:?}",
        started.elapsed()
    );
    assert_eq!(pool.test_pid("mock:busy"), Some(busy_pid));

    let recycled = pool.test_evict_idle_siblings("sp1:cuda:0", &["mock:idle".to_string()]);
    assert_eq!(recycled, vec!["mock:idle".to_string()]);
    assert_eq!(pool.test_has_handle("mock:idle"), Some(false));
    assert_eq!(
        pool.test_pid("mock:idle"),
        Some(0),
        "pid must be retracted with the worker"
    );
    assert_eq!(
        pool.test_consecutive_failures("mock:idle"),
        Some(0),
        "making room is not a failure; the slot must respawn on its next job without backoff"
    );

    let _ = prover.join();
    // And it does come back.
    let out = pool
        .prove(
            "mock:idle",
            &[],
            &[],
            None,
            Some(Duration::from_secs(10)),
            None,
        )
        .expect("a recycled sibling must respawn on its next dispatch");
    assert!(out.seal.is_empty());
    assert_eq!(pool.test_has_handle("mock:idle"), Some(true));
    assert_ne!(pool.test_pid("mock:idle"), Some(idle_pid));
}

/// A slot whose worker was recycled to make room is skipped for cycle measurement, not failed on: the
/// measurement runs on the next live worker.
#[test]
fn cycle_measurement_skips_a_recycled_slot() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    for key in ["mock:a", "mock:b"] {
        pool.insert_test_worker(key, "mock", mock_worker_path(), mock_env("", ""))
            .expect("failed to spawn mock worker");
    }
    // Recycle each in turn, so whichever one the measurement reaches first is the one gone.
    for gone in ["mock:a", "mock:b"] {
        let _ = pool.test_evict_idle_siblings("sp1:cuda:0", &[gone.to_string()]);
        assert_eq!(pool.test_has_handle(gone), Some(false));
        assert!(
            pool.has_idle_worker("mock"),
            "the other worker is idle and live"
        );
        let m = pool
            .execute_cycles("mock", &[], &[], Some(Duration::from_secs(10)), None, None)
            .expect("measurement must move on to the live worker");
        assert_eq!(m.cycles, 1000);
        // Bring it back for the next round.
        pool.prove(gone, &[], &[], None, Some(Duration::from_secs(10)), None)
            .expect("respawn");
    }
}

/// Once the pool is CLOSING — the process is exiting — nothing is spawned again: a respawn then would
/// outlive the miner. A dispatch to a slot whose worker was recycled must fail, not bring it back.
#[test]
fn a_closed_pool_never_respawns() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:a", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    pool.close();
    assert_eq!(pool.test_has_handle("mock:a"), Some(false));
    let err = pool
        .prove("mock:a", &[], &[], None, Some(Duration::from_secs(5)), None)
        .expect_err("a closed pool must not respawn a worker");
    assert!(
        format!("{err:#}").contains("shutting down"),
        "must say why: {err:#}"
    );
    assert_eq!(pool.test_has_handle("mock:a"), Some(false));
    assert_eq!(pool.test_pid("mock:a"), Some(0));
}

// ---- Warm-up ----

/// A backend's one-time setup answers, and is reported back.
#[test]
fn warmup_reports_what_was_done() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    let summary = pool.warm_up("mock", Duration::from_secs(10)).unwrap();
    assert_eq!(summary, "nothing to warm up");
    assert!(pool.backend_warmed("mock"));
    assert!(pool
        .warm_up("nonexistent", Duration::from_secs(10))
        .is_err());
}

/// A worker that has run a guest has no network, so a warm-up (which may download) never runs on
/// one: the slot gets a fresh worker for it, without counting a failure. A worker that has only
/// shaken hands keeps its process.
#[test]
fn a_warmup_after_a_guest_runs_on_a_fresh_worker() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    let first = pool.test_pid("mock:generic").unwrap();
    assert_ne!(first, 0);
    pool.warm_up("mock", Duration::from_secs(10)).unwrap();
    assert_eq!(
        pool.test_pid("mock:generic"),
        Some(first),
        "nothing ran before it: same worker"
    );

    // A measurement on the prove slot (a backend with no measure pool) runs the job's guest there.
    let m = pool
        .execute_cycles("mock", &[], &[], Some(Duration::from_secs(10)), None, None)
        .unwrap();
    assert_eq!(m.cycles, 1000);
    assert_eq!(pool.test_pid("mock:generic"), Some(first));
    let summary = pool.warm_up("mock", Duration::from_secs(10)).unwrap();
    assert_eq!(summary, "nothing to warm up");
    let fresh = pool.test_pid("mock:generic").unwrap();
    assert!(fresh != 0 && fresh != first, "{first} -> {fresh}");
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));
    // And the fresh one, warmed, serves the next job.
    pool.prove(
        "mock:generic",
        &[],
        &[],
        None,
        Some(Duration::from_secs(10)),
        None,
    )
    .unwrap();
    assert_eq!(pool.test_pid("mock:generic"), Some(fresh));
}

/// A warm-up that hangs (a download that stalls) is killed at its deadline, like a benchmark: the
/// slot is cleared for a respawn and the kill is not counted as a crash.
#[test]
fn a_hung_warmup_is_killed_at_its_deadline() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("warmup", ""),
    )
    .expect("failed to spawn mock worker");
    let started = std::time::Instant::now();
    assert!(pool.warm_up("mock", Duration::from_secs(2)).is_err());
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(pool.test_has_handle("mock:generic"), Some(false));
    assert_eq!(pool.test_pid("mock:generic"), Some(0));
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));
}

/// The one-time setup is the host's, so a slot that fails it does not stop the backend: the next
/// slot runs it.
#[test]
fn a_failed_warmup_moves_on_to_the_next_slot() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:a", "mock", mock_worker_path(), mock_env("", "warmup"))
        .expect("failed to spawn mock worker");
    pool.insert_test_worker("mock:b", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    let summary = pool
        .warm_up("mock", Duration::from_secs(10))
        .expect("mock:b runs the setup after mock:a fails it");
    assert_eq!(summary, "nothing to warm up");
    assert!(pool.backend_warmed("mock"));
    assert_eq!(pool.test_consecutive_failures("mock:a"), Some(1));
    assert_eq!(pool.test_consecutive_failures("mock:b"), Some(0));
}

/// A worker that dies during its warm-up is an error, counted as a failure.
#[test]
fn a_warmup_crash_is_an_error() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("", "warmup"),
    )
    .expect("failed to spawn mock worker");
    assert!(pool.warm_up("mock", Duration::from_secs(10)).is_err());
    assert_eq!(pool.test_has_handle("mock:generic"), Some(false));
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(1));
}

/// RESIDUAL A — prove-preempts-measure, end to end.
///
/// A pre-claim cycle measurement is held in flight (the mock worker hangs on Execute), so it is
/// registered as preemptible and holds its slot. A committed proof then PREEMPTS it: the dispatcher
/// SIGKILLs the measure worker. The measurement thread must observe the kill, reclassify it as the
/// TYPED transient `MeasurePreempted` (not a wall-clock timeout, not a crash), deregister, and leave
/// the slot DEAD but not FAILED (its health must not be dinged — the kill was intentional and the
/// measurement was healthy). This exercises the real cross-thread SIGKILL + recv-fail path, which is
/// the part that could not be covered by the pure-logic planner tests.
#[test]
fn a_committed_proof_preempts_an_inflight_measurement_end_to_end() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    // On the (non-measure-pool) PROVE slot, so the measurement reserves NO host RAM — the test is
    // then independent of how much RAM the box happens to have free. Hang on Execute so it stays in
    // flight until it is killed.
    pool.insert_test_worker(
        "mock:generic",
        "mock",
        mock_worker_path(),
        mock_env("execute", ""),
    )
    .expect("failed to spawn mock worker");

    let pool = Arc::new(pool);
    let measurer = {
        let pool = Arc::clone(&pool);
        std::thread::spawn(move || {
            // A generous watchdog budget that we never reach — the preemption kills it first.
            pool.execute_cycles("mock", &[], &[], Some(Duration::from_secs(120)), None, None)
        })
    };

    // Wait until the measurement is actually in flight (registered). Bounded so the test fails loudly
    // rather than hanging if registration regresses.
    let mut waited = Duration::ZERO;
    while pool.test_inflight_measure_count() == 0 {
        std::thread::sleep(Duration::from_millis(20));
        waited += Duration::from_millis(20);
        assert!(
            waited < Duration::from_secs(10),
            "measurement never registered as in-flight"
        );
    }
    assert_eq!(pool.test_inflight_measure_count(), 1);
    // Non-blocking: the measurement HOLDS the slot lock across its recv, so `test_has_handle`
    // (which takes that lock) would block until the measurement returns — use the try_lock probe.
    assert!(
        pool.test_slot_is_held("mock:generic"),
        "the hanging measurement holds its slot"
    );

    // Preempt it, exactly as a committed proof short on resources would.
    pool.test_preempt_all_inflight_measures();

    // The measurement thread unwinds with the TYPED transient.
    let result = measurer.join().expect("measurer thread panicked");
    let err = result.expect_err("a preempted measurement must return an error, not a cycle count");
    assert!(
        err.downcast_ref::<zkminer_prover_protocol::types::MeasurePreempted>()
            .is_some(),
        "a preempted measurement must return the typed MeasurePreempted (got: {err:#})"
    );

    // Deregistered, slot DEAD (handle gone, pid zeroed) but NOT failed (health untouched).
    assert_eq!(
        pool.test_inflight_measure_count(),
        0,
        "the registration must be cleared on return"
    );
    assert_eq!(pool.test_has_handle("mock:generic"), Some(false));
    assert_eq!(pool.test_pid("mock:generic"), Some(0));
    assert_eq!(
        pool.test_consecutive_failures("mock:generic"),
        Some(0),
        "preemption is an intentional kill — it must NOT count against slot health"
    );
}

/// The segment size a job is measured at, and the size its slot proves it at, reach the worker.
#[test]
fn the_segment_size_reaches_the_worker() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    let m = pool
        .execute_cycles(
            "mock",
            &[],
            &[],
            Some(Duration::from_secs(10)),
            None,
            Some(18),
        )
        .expect("measurement should succeed");
    assert_eq!(m.cycles, 1018);
    // A job's size on its slot wins over the caller's `po2`.
    let size_on = |k: &str| {
        if k == "mock:generic" {
            vec![19]
        } else {
            Vec::new()
        }
    };
    let mut used = None;
    let out = pool
        .prove_min_vram(
            "mock",
            &[],
            &[],
            Some(20),
            Some(Duration::from_secs(10)),
            None,
            None,
            &[],
            &[],
            &mut used,
            None,
            Some(&size_on),
            None,
            zkminer_prover::dispatcher::JobCards::default(),
            0,
        )
        .expect("proof should succeed");
    assert_eq!((out.cycles, used.as_deref()), (1019, Some("mock:generic")));
}

/// A measurement that completes NORMALLY deregisters itself and leaves its slot healthy — the
/// preemptible window is exactly the in-flight duration, nothing lingers in the registry.
#[test]
fn a_normal_measurement_leaves_no_inflight_registration() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");

    let m = pool
        .execute_cycles("mock", &[], &[], Some(Duration::from_secs(10)), None, None)
        .expect("measurement should succeed");
    assert_eq!(m.cycles, 1000);
    // The mock commits nothing: an empty journal, reported whole.
    assert_eq!(m.journal.as_deref(), Some(&[][..]));
    assert_eq!(
        pool.test_inflight_measure_count(),
        0,
        "a finished measurement must not stay registered as preemptible"
    );
    assert_eq!(pool.test_consecutive_failures("mock:generic"), Some(0));
}

// ---- M9: the Metal recycle policy ----

/// A worker is recycled after 20 proofs, but a Metal one is kept (its warm state is worth keeping,
/// and its idle footprint does not grow; M9 note): 25 proofs on each, one pid for the Metal slot.
#[test]
fn a_metal_worker_outlives_the_20_proof_recycle() {
    if std::env::var_os("ZKMINER_RECYCLE_AFTER_PROOFS").is_some()
        || std::env::var_os("ZKMINER_METAL_RECYCLE_AFTER_PROOFS").is_some()
    {
        return;
    }
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    let mut metal = WorkerPool::new(HashMap::new(), Vec::new(), None);
    metal
        .insert_test_worker("mock:metal", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    metal.test_set_gpu_tag("mock:metal", "metal");
    let (generic_pid, metal_pid) = (pool.test_pid("mock:generic"), metal.test_pid("mock:metal"));
    for i in 0..25 {
        pool.prove("mock", &[], &[], None, Some(Duration::from_secs(10)), None)
            .unwrap_or_else(|e| panic!("generic proof {i}: {e:#}"));
        metal
            .prove("mock", &[], &[], None, Some(Duration::from_secs(10)), None)
            .unwrap_or_else(|e| panic!("metal proof {i}: {e:#}"));
    }
    assert_ne!(
        pool.test_pid("mock:generic"),
        generic_pid,
        "recycled after 20 proofs"
    );
    assert_eq!(
        metal.test_pid("mock:metal"),
        metal_pid,
        "kept past 20 proofs"
    );
    assert_eq!(metal.test_consecutive_failures("mock:metal"), Some(0));
}

// ---- W7-M10: the owner-active tier and the respawn right after a proof ----

const GIB: u64 = 1 << 30;

/// A Metal slot (mock worker) with a 16 GB Mac's figure, 8 GiB.
fn metal_16gb_pool() -> WorkerPool {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:metal", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    pool.test_set_gpu_tag("mock:metal", "metal");
    pool.test_set_vram("mock:metal", 8 * GIB);
    pool
}

fn prove_at(pool: &WorkerPool, po2: Option<u8>) -> u64 {
    pool.prove("mock", &[], &[], po2, Some(Duration::from_secs(10)), None)
        .unwrap_or_else(|e| panic!("proof at {po2:?}: {e:#}"))
        .cycles
}

/// Whether this process has no explicit Metal budget: one (gpu-run's default) caps every figure the
/// worker sees, so the 4 and 8 GiB tiers are the same worker and nothing respawns. The gate runs
/// these with `gpu-run --light --no-budget` (the mock worker uses no GPU).
fn no_budget(test: &str) -> bool {
    let none = zkminer_prover::metal_sizing::env_working_set_budget().is_none();
    if !none {
        eprintln!("{test}: skipped under RISC0_METAL_MAX_WORKING_SET_BYTES (run with --no-budget)");
    }
    none
}

fn respawn_early_on() -> bool {
    !std::env::var_os("ZKMINER_METAL_RESPAWN_EARLY").is_some_and(|v| v == "0")
}

/// Unenforced (the default), the tier follows the owner at each job's start, never changes a job's
/// po2, is recorded per job, and never respawns the worker: a worker at the idle figure proves a job
/// the active tier admits exactly as one at the active figure would (`metal_sizing::same_for_job`),
/// so a respawn would only cost a cold worker. A count recycle while the owner is active keeps the
/// idle figure (a worker moved to 4 GiB would refuse the next po2 19 job).
#[test]
fn a_metal_job_proves_at_the_owner_tier_its_po2_fits() {
    use zkminer_prover::metal_sizing::OwnerForce;
    let pool = metal_16gb_pool();
    pool.test_force_enforce(Some(false));
    let pid0 = pool.test_pid("mock:metal");
    pool.test_force_owner(Some(OwnerForce::Active));
    // A job measured at 19 (before the owner came back) keeps 19 and the idle tier.
    assert_eq!(prove_at(&pool, Some(19)), 1019);
    assert_eq!(pool.metal_tier_jobs(), (1, 0));
    // A job measured at 18 while the owner is active: the active tier, on the same worker.
    assert_eq!(prove_at(&pool, Some(18)), 1018);
    assert_eq!(pool.metal_tier_jobs(), (1, 1));
    // The owner leaves: a po2 18 job is an idle-tier job, still the same worker.
    pool.test_force_owner(Some(OwnerForce::Idle));
    assert_eq!(prove_at(&pool, Some(18)), 1018);
    assert_eq!(pool.metal_tier_jobs(), (2, 1));
    // A benchmark-style proof (no po2) always runs at the idle tier.
    pool.test_force_owner(Some(OwnerForce::Active));
    assert_eq!(prove_at(&pool, None), 1000);
    assert_eq!(pool.metal_tier_jobs(), (3, 1));
    assert_eq!(pool.test_pid("mock:metal"), pid0, "no tier respawn unenforced");
    assert_eq!(pool.test_spawn_vram("mock:metal"), Some(8 * GIB));
    // A count recycle while the owner is active respawns at the figure the worker had.
    pool.test_set_recycle_after("mock:metal", 1);
    prove_at(&pool, Some(18));
    prove_at(&pool, Some(19));
    assert_ne!(pool.test_pid("mock:metal"), pid0);
    assert_eq!(pool.test_spawn_vram("mock:metal"), Some(8 * GIB));
    assert_eq!(pool.metal_tier_jobs(), (4, 2));
    assert_eq!(pool.test_consecutive_failures("mock:metal"), Some(0));
}

/// W7-M10 review finding: when the owner comes back with jobs measured at the idle po2 queued, the
/// worker is not moved to the active tier in the idle gap after each of them (and back before the
/// next): at most one respawn for the whole queue, and it happens at the first job the active tier
/// can hold. With enforcement on, where the tier's figure is the worker's budget.
#[test]
fn queued_idle_po2_jobs_after_the_owner_returns_respawn_the_worker_at_most_once() {
    if !no_budget("queued_idle_po2_jobs_after_the_owner_returns_respawn_the_worker_at_most_once") {
        return;
    }
    use zkminer_prover::metal_sizing::OwnerForce;
    let pool = metal_16gb_pool();
    pool.test_force_enforce(Some(true));
    pool.test_force_owner(Some(OwnerForce::Active));
    let pid0 = pool.test_pid("mock:metal");
    for _ in 0..3 {
        assert_eq!(prove_at(&pool, Some(19)), 1019);
        assert_eq!(pool.test_spawn_vram("mock:metal"), Some(8 * GIB));
    }
    assert_eq!(pool.metal_tier_jobs(), (3, 0));
    assert_eq!(
        pool.test_pid("mock:metal"),
        pid0,
        "no respawn for idle-po2 jobs"
    );
    // The first job measured at the active po2: one respawn, before it, at 4 GiB.
    assert_eq!(prove_at(&pool, Some(18)), 1018);
    let pid1 = pool.test_pid("mock:metal");
    assert_ne!(pid1, pid0);
    assert_eq!(pool.test_spawn_vram("mock:metal"), Some(4 * GIB));
    for _ in 0..2 {
        assert_eq!(prove_at(&pool, Some(18)), 1018);
    }
    assert_eq!(pool.test_pid("mock:metal"), pid1, "already at its tier");
    assert_eq!(pool.metal_tier_jobs(), (3, 3));
    // The owner leaves: the next po2 18 job runs on the worker as it is (active tier, no respawn
    // before it); right after it the worker goes back to idle in the idle gap, so the po2 19 jobs
    // claimed from now find it there.
    pool.test_force_owner(Some(OwnerForce::Idle));
    assert_eq!(prove_at(&pool, Some(18)), 1018);
    assert_eq!(pool.metal_tier_jobs(), (3, 4));
    if respawn_early_on() {
        let pid2 = pool.test_pid("mock:metal");
        assert_ne!(pid2, pid1, "back to idle right after the proof");
        assert_eq!(pool.test_spawn_vram("mock:metal"), Some(8 * GIB));
        assert_eq!(prove_at(&pool, Some(19)), 1019);
        assert_eq!(pool.test_pid("mock:metal"), pid2);
    } else {
        // Without the early respawn, the po2 19 job's start makes it (the worker would refuse).
        assert_eq!(prove_at(&pool, Some(19)), 1019);
        assert_ne!(pool.test_pid("mock:metal"), pid1);
        assert_eq!(pool.test_spawn_vram("mock:metal"), Some(8 * GIB));
    }
    assert_eq!(pool.metal_tier_jobs(), (4, 4));
    assert_eq!(pool.test_consecutive_failures("mock:metal"), Some(0));
}

/// W7-M10 review finding: on a 36 GB Mac the active tier (20 GiB) keeps po2 20 and the Groth16 key
/// decision of the idle one (28 GiB), so with enforcement off an owner switching back and forth
/// never respawns the worker.
#[test]
fn a_36_gb_macs_owner_switches_never_respawn_the_worker() {
    use zkminer_prover::metal_sizing::OwnerForce;
    let mut pool = metal_16gb_pool();
    pool.test_set_vram("mock:metal", 28 * GIB);
    pool.test_force_enforce(Some(false));
    let pid = pool.test_pid("mock:metal");
    for (i, force) in [
        OwnerForce::Active,
        OwnerForce::Idle,
        OwnerForce::Active,
        OwnerForce::Active,
        OwnerForce::Idle,
        OwnerForce::Active,
    ]
    .into_iter()
    .enumerate()
    {
        pool.test_force_owner(Some(force));
        assert_eq!(prove_at(&pool, Some(20)), 1020, "proof {i}");
        assert_eq!(pool.test_pid("mock:metal"), pid, "proof {i}");
    }
    assert_eq!(pool.test_spawn_vram("mock:metal"), Some(28 * GIB));
    assert_eq!(pool.metal_tier_jobs(), (2, 4));
}

/// A benchmark prices the Mac at its idle tier: a worker left at the active tier (enforcement on)
/// is respawned at the idle figure first.
#[test]
fn a_metal_benchmark_runs_at_the_idle_tier() {
    if !no_budget("a_metal_benchmark_runs_at_the_idle_tier") {
        return;
    }
    use zkminer_prover::metal_sizing::OwnerForce;
    let pool = metal_16gb_pool();
    pool.test_force_enforce(Some(true));
    pool.test_force_owner(Some(OwnerForce::Active));
    // Owner active, a job at 18: active tier (respawned before the proof).
    assert_eq!(prove_at(&pool, Some(18)), 1018);
    assert_eq!(pool.test_spawn_vram("mock:metal"), Some(4 * GIB));
    let pid = pool.test_pid("mock:metal");
    pool.benchmark("mock").expect("benchmark");
    assert_eq!(pool.test_spawn_vram("mock:metal"), Some(8 * GIB));
    assert_ne!(
        pool.test_pid("mock:metal"),
        pid,
        "respawned at the idle tier for the benchmark"
    );
}

/// A worker due for its count-based recycle is respawned right after the proof that made it due,
/// not before the next one.
#[test]
fn a_due_metal_worker_is_respawned_right_after_its_proof() {
    if !respawn_early_on() {
        return;
    }
    let pool = metal_16gb_pool();
    pool.test_force_owner(Some(zkminer_prover::metal_sizing::OwnerForce::Idle));
    pool.test_set_recycle_after("mock:metal", 2);
    let pid0 = pool.test_pid("mock:metal");
    prove_at(&pool, Some(19));
    assert_eq!(pool.test_pid("mock:metal"), pid0);
    prove_at(&pool, Some(19));
    let pid1 = pool.test_pid("mock:metal");
    assert_ne!(pid1, pid0, "respawned as the second proof ended");
    assert_eq!(pool.test_has_handle("mock:metal"), Some(true));
    // The new worker proves the next job without another respawn before it.
    prove_at(&pool, Some(19));
    assert_eq!(pool.test_pid("mock:metal"), pid1);
    prove_at(&pool, Some(19));
    assert_ne!(pool.test_pid("mock:metal"), pid1);
    assert_eq!(pool.metal_tier_jobs(), (4, 0));
    assert_eq!(pool.test_consecutive_failures("mock:metal"), Some(0));
}

/// A slot that is not an enumerated Apple GPU (no figure) is untouched by the tier.
#[test]
fn a_metal_slot_without_a_figure_ignores_the_owner_tier() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:metal", "mock", mock_worker_path(), mock_env("", ""))
        .expect("failed to spawn mock worker");
    pool.test_set_gpu_tag("mock:metal", "metal");
    pool.test_force_owner(Some(zkminer_prover::metal_sizing::OwnerForce::Active));
    let pid = pool.test_pid("mock:metal");
    for _ in 0..3 {
        assert_eq!(prove_at(&pool, Some(18)), 1018);
    }
    assert_eq!(pool.test_pid("mock:metal"), pid);
    assert_eq!(pool.metal_tier_jobs(), (0, 0));
}

/// W7-M10 A/B harness (real Metal worker, ignored): proofs through the miner's own pool (the
/// process-wide one, so the respawn right after a proof and its background growth check run as in
/// the miner), each worker recycled after every proof (`ZKMINER_M10_RECYCLE`, default 1), with
/// `ZKMINER_M10_GAP_MS` (default 3000) between proofs. Prints each proof's wall time as the caller
/// sees it (respawn included) and the worker pid. Arms: `ZKMINER_METAL_RESPAWN_EARLY=0` or unset.
///
///   ZKMINER_M10_WORKER=<zkminer-prove-risc0-metal> cargo test --release -p zkminer-prover \
///     --features testing --test worker_lifecycle -- --ignored --nocapture m10_recycled_first_prove
#[test]
#[ignore = "proves on the Apple GPU with ZKMINER_M10_WORKER; run alone under gpu-run"]
fn m10_recycled_first_prove() {
    let Ok(worker) = std::env::var("ZKMINER_M10_WORKER") else {
        eprintln!("ZKMINER_M10_WORKER is not set");
        return;
    };
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
    let num = |k: &str, d: u64| -> u64 {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let dir = std::env::temp_dir().join(format!("m10-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let guest = dir.join("fibonacci.elf");
    let out = std::process::Command::new(&worker)
        .arg("--export-guest")
        .arg("fibonacci")
        .arg(&guest)
        .output()
        .unwrap();
    assert!(out.status.success());
    let elf = std::fs::read(&guest).unwrap();
    let iters = num("ZKMINER_M10_FIB_ITERS", 400_000) as u32;
    let key = "risc0:metal";
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker(key, "risc0", worker.into(), HashMap::new())
        .expect("spawn the Metal worker");
    pool.test_set_gpu_tag(key, "metal");
    pool.test_set_recycle_after(key, num("ZKMINER_M10_RECYCLE", 1) as u32);
    // An Apple GPU figure (e.g. a 16 GB Mac's 8 GiB) turns the owner tier on for this slot; the
    // tier then follows ZKMINER_OWNER_ACTIVE (or the owner's real activity).
    let vram = num("ZKMINER_M10_VRAM", 0);
    if vram > 0 {
        pool.test_set_vram(key, vram);
    }
    let po2 = std::env::var("ZKMINER_M10_PO2")
        .ok()
        .and_then(|v| v.parse::<u8>().ok());
    zkminer_prover::engine::init_worker_pool(pool);
    let pool = zkminer_prover::engine::worker_pool().unwrap();
    let gap = Duration::from_millis(num("ZKMINER_M10_GAP_MS", 3000));
    let proofs = num("ZKMINER_M10_PROOFS", 3);
    for i in 1..=proofs {
        if i > 1 {
            std::thread::sleep(gap);
        }
        let pid_before = pool.test_pid(key).unwrap_or(0);
        let t = Instant::now();
        let p = pool
            .prove(
                "risc0",
                &elf,
                &iters.to_le_bytes(),
                po2,
                Some(Duration::from_secs(300)),
                None,
            )
            .unwrap_or_else(|e| panic!("proof {i}: {e:#}"));
        let wall = t.elapsed().as_secs_f64();
        eprintln!(
            "M10 tiers after proof {i}: (idle, active) = {:?}, spawn figure {:?}",
            pool.metal_tier_jobs(),
            pool.test_spawn_vram(key)
        );
        assert!(!p.seal.is_empty());
        eprintln!(
            "M10 proof {i}: {wall:.3} s wall, worker {:.3} s, pid {pid_before} -> {}",
            p.duration.as_secs_f64(),
            pool.test_pid(key).unwrap_or(0)
        );
    }
    std::thread::sleep(Duration::from_millis(500));
    pool.close();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- W10-BENCH: a failed benchmark is reported, never silently dropped ----

/// A Metal-tagged risc0 worker whose warm-up answers with an error, as a Mac whose GPU pipelines do
/// not build does (the macOS 26 VM: "compute pipeline for stepAccumA: Compilation failed").
fn failing_metal_pool(fail_on: &str) -> WorkerPool {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(30)));
    let mut env = mock_env("", "");
    env.insert("MOCK_BACKEND".to_string(), "risc0".to_string());
    env.insert(
        "MOCK_SDK_VERSION".to_string(),
        format!(
            "risc0-zkvm {}.0",
            zkminer_prover_protocol::RISC0_ZKVM_MAJOR_MINOR
        ),
    );
    env.insert("MOCK_FAIL_ON".to_string(), fail_on.to_string());
    env.insert(
        "MOCK_FAIL_MESSAGE".to_string(),
        "warm-up failed: compute pipeline for stepAccumA: Compilation failed".to_string(),
    );
    pool.insert_test_worker("risc0:metal:0", "risc0", mock_worker_path(), env)
        .expect("mock risc0 worker");
    pool.test_set_gpu_tag("risc0:metal:0", "metal");
    pool
}

#[test]
fn a_failed_warm_up_is_reported_as_the_slots_failure() {
    let pool = failing_metal_pool("warmup");
    assert!(pool.has_any_worker());
    let run = pool.benchmark_all_with_device_info();
    assert!(run.results.is_empty(), "{:?}", run.results);
    assert_eq!(run.failures.len(), 1, "{:?}", run.failures);
    let f = &run.failures[0];
    assert_eq!(f.slot_key, "risc0:metal:0");
    assert_eq!(f.gpu_tag, "metal");
    assert!(
        f.error.contains("warm-up of risc0:metal:0 failed") && f.error.contains("stepAccumA"),
        "{}",
        f.error
    );

    // The streaming path (the TUI's and the miner's) reports it the same way, and its progress events
    // mark the slot finished without success.
    let finished = std::sync::Mutex::new(Vec::new());
    let run = pool.benchmark_all_streaming(&|event| {
        if let zkminer_prover::dispatcher::BenchmarkProgressKind::Finished { succeeded } =
            event.kind
        {
            finished.lock().unwrap().push(succeeded);
        }
    });
    assert!(run.results.is_empty());
    assert_eq!(run.failures.len(), 1, "{:?}", run.failures);
    assert!(run.failures[0].error.contains("stepAccumA"));
    assert_eq!(*finished.lock().unwrap(), vec![false]);
}

/// A worker that answers its benchmark with an error, and one that answers with no rows (it proved
/// none of the programs), are failures too.
#[test]
fn a_benchmark_error_or_an_empty_answer_is_the_slots_failure() {
    let pool = failing_metal_pool("benchmark");
    let run = pool.benchmark_all_with_device_info();
    assert!(run.results.is_empty());
    assert_eq!(run.failures.len(), 1, "{:?}", run.failures);
    assert!(
        run.failures[0].error.contains("stepAccumA"),
        "{}",
        run.failures[0].error
    );

    // The plain mock answers every Benchmark with zero rows.
    let pool = failing_metal_pool("");
    let run = pool.benchmark_all_with_device_info();
    assert!(run.results.is_empty());
    assert_eq!(run.failures.len(), 1, "{:?}", run.failures);
    assert_eq!(
        run.failures[0].error,
        zkminer_prover::dispatcher::NO_BENCHMARK_ROWS
    );
}

#[test]
fn an_empty_pool_has_no_worker() {
    let pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(5)));
    assert!(!pool.has_any_worker());
    let run = pool.benchmark_all_with_device_info();
    assert!(run.results.is_empty() && run.failures.is_empty());
}

// ---- W10-BENCH round 1: declined siblings and short suites ----

/// A Metal-tagged risc0 mock that answers every program with a row, except those in `drop`.
fn measuring_metal_pool(drop: &str) -> WorkerPool {
    let mut env = mock_env("", "");
    env.insert("MOCK_BACKEND".to_string(), "risc0".to_string());
    env.insert(
        "MOCK_SDK_VERSION".to_string(),
        format!(
            "risc0-zkvm {}.0",
            zkminer_prover_protocol::RISC0_ZKVM_MAJOR_MINOR
        ),
    );
    env.insert("MOCK_BENCH_ROWS".to_string(), "all".to_string());
    env.insert("MOCK_BENCH_DROP".to_string(), drop.to_string());
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(30)));
    pool.insert_test_worker("risc0:metal:0", "risc0", mock_worker_path(), env)
        .expect("mock risc0 worker");
    pool.test_set_gpu_tag("risc0:metal:0", "metal");
    pool
}

/// Both entry points, so each check covers `zkminer benchmark` and the TUI/miner's streaming path.
fn both_runs(pool: &WorkerPool) -> Vec<(&'static str, zkminer_prover::dispatcher::BenchmarkRun)> {
    vec![
        ("with_device_info", pool.benchmark_all_with_device_info()),
        ("streaming", pool.benchmark_all_streaming(&|_| {})),
    ]
}

/// The control: a worker on which every program and the score proved gives a clean run.
#[test]
fn a_complete_suite_is_a_clean_run() {
    let pool = measuring_metal_pool("");
    for (name, run) in both_runs(&pool) {
        assert!(run.failures.is_empty(), "{name}: {:?}", run.failures);
        assert!(run.not_benchmarked.is_empty(), "{name}");
        assert_eq!(run.results.len(), 1, "{name}");
        assert!(
            zkminer_prover::dispatcher::missing_benchmark_rows("risc0", &run.results[0].entries)
                .is_empty(),
            "{name}: {:?}",
            run.results[0].entries
        );
    }
    pool.close();
}

/// A worker leaves out a program that did not prove and verify, and the dispatcher leaves out a
/// score that failed. Either makes the slot's benchmark a failure that names what is missing; the
/// rows that did prove are kept, to be shown (reviewer's repro: only memory-merkle came back, and
/// `zkminer benchmark` printed a normal table, exit 0, and saved it under --calibrate).
#[test]
fn a_short_suite_is_the_slots_failure() {
    for (drop, named) in [
        (
            "sha256-chain,ecdsa-verify,bigint-mul,chacha-mix,zkop-mix",
            vec![
                "sha256-chain",
                "ecdsa-verify",
                "bigint-mul",
                "chacha-mix",
                "zkop-mix",
            ],
        ),
        ("memory-merkle", vec!["memory-merkle"]),
        ("zkop-mix", vec!["zkop-mix"]),
    ] {
        let pool = measuring_metal_pool(drop);
        let finished = std::sync::Mutex::new(Vec::new());
        let streamed = pool.benchmark_all_streaming(&|event| {
            if let zkminer_prover::dispatcher::BenchmarkProgressKind::Finished { succeeded } =
                event.kind
            {
                finished.lock().unwrap().push(succeeded);
            }
        });
        assert_eq!(*finished.lock().unwrap(), vec![false], "{drop}");
        for (name, run) in [
            ("with_device_info", pool.benchmark_all_with_device_info()),
            ("streaming", streamed),
        ] {
            assert_eq!(
                run.results.len(),
                1,
                "{drop}/{name}: the proved rows are kept"
            );
            assert_eq!(run.failures.len(), 1, "{drop}/{name}: {:?}", run.failures);
            let error = &run.failures[0].error;
            assert!(
                error.contains(zkminer_prover::dispatcher::INCOMPLETE_BENCHMARK),
                "{drop}/{name}: {error}"
            );
            for program in &named {
                assert!(
                    error.contains(program),
                    "{drop}/{name}: {program} not named: {error}"
                );
            }
        }
        pool.close();
    }
}

/// A worker that DECLINED at startup (`sp1 unavailable: libcudart.so.12 not found`) beside a working
/// card, and a second card of the SAME backend whose worker could not be started: the working card's
/// benchmark is a clean run, and the two are reported as not benchmarked. Before round 1 they failed
/// the whole run, so `zkminer benchmark --calibrate` exited 1 and the TUI never saved the working
/// card's rows.
#[test]
fn a_declined_or_unstartable_sibling_does_not_fail_a_working_card() {
    let mut pool = measuring_metal_pool("");
    pool.insert_test_down_worker(
        "sp1:cuda:0",
        "sp1",
        "cuda",
        mock_worker_path(),
        Some("sp1 unavailable: libcudart.so.12 not found"),
    );
    pool.insert_test_down_worker(
        "risc0:cuda:1",
        "risc0",
        "cuda",
        PathBuf::from("/nonexistent/zkminer-prove-risc0-cuda"),
        None,
    );
    for (name, run) in both_runs(&pool) {
        assert!(run.failures.is_empty(), "{name}: {:?}", run.failures);
        assert_eq!(run.results.len(), 1, "{name}");
        assert_eq!(run.results[0].slot_key, "risc0:metal:0");
        let mut down: Vec<&str> = run
            .not_benchmarked
            .iter()
            .map(|f| f.slot_key.as_str())
            .collect();
        down.sort();
        assert_eq!(down, ["risc0:cuda:1", "sp1:cuda:0"], "{name}");
        let declined = run
            .not_benchmarked
            .iter()
            .find(|f| f.slot_key == "sp1:cuda:0")
            .unwrap();
        assert!(declined.error.contains("libcudart"), "{}", declined.error);
    }
    // A declined slot is not a benchmark target either, so a start with saved results for every
    // other card does not re-run the benchmark for a row that cannot come.
    let targets: Vec<(String, String)> = pool.benchmark_targets();
    assert!(targets.iter().all(|(_, b)| b != "sp1"), "{targets:?}");
    assert!(
        targets.iter().any(|(_, b)| b == "risc0"),
        "a slot that may still start stays a target: {targets:?}"
    );
    pool.close();
}

/// W10-BENCH round 2 (reviewer's probe 1): the risc0 GPU worker could not start (a crash or a
/// backoff, not a decline), and the host also has a CPU `generic` risc0 worker. The GPU slot's error
/// is the run's failure: the CPU worker never stands in for it (before, the CPU worker was
/// benchmarked instead and the run was clean: exit 0, cached under --calibrate, used for pricing).
#[test]
fn a_down_gpu_slot_is_not_covered_by_a_cpu_worker() {
    for gpu in ["risc0:metal:0", "risc0:cuda:0"] {
        let mut env = mock_env("", "");
        env.insert("MOCK_BACKEND".to_string(), "risc0".to_string());
        env.insert(
            "MOCK_SDK_VERSION".to_string(),
            format!(
                "risc0-zkvm {}.0",
                zkminer_prover_protocol::RISC0_ZKVM_MAJOR_MINOR
            ),
        );
        env.insert("MOCK_BENCH_ROWS".to_string(), "all".to_string());
        let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(30)));
        pool.insert_test_worker("risc0:generic", "risc0", mock_worker_path(), env)
            .expect("mock risc0 cpu worker");
        pool.insert_test_down_worker(
            gpu,
            "risc0",
            gpu.split(':').nth(1).unwrap(),
            mock_worker_path(),
            None,
        );
        for (name, run) in both_runs(&pool) {
            assert!(
                run.failures.iter().any(|f| f.slot_key == gpu),
                "{gpu}/{name}: the down GPU slot must fail the run: {:?}",
                run.failures
            );
            assert!(
                run.not_benchmarked.iter().all(|f| f.slot_key != gpu),
                "{gpu}/{name}: {:?}",
                run.not_benchmarked
            );
            assert!(
                run.results.iter().all(|r| r.slot_key != "risc0:generic"),
                "{gpu}/{name}: the CPU worker is not benchmarked in the GPU's place"
            );
        }
        pool.close();
    }
}

/// W10-BENCH round 2 (reviewer's probe 2): the OpenVM worker cannot prove; its `Benchmark` answer
/// times a stand-in workload under the name "openvm". Those rows are never measurements: not in
/// `results` (so not shown, cached or priced), and a slot that only has them did not measure. With
/// the only real prover (risc0 cuda) down, the run fails; beside a working card, OpenVM is reported
/// as not benchmarked (SIMULATED) and the card's run is clean.
#[test]
fn openvm_stub_rows_are_never_measurements() {
    let openvm_env = || {
        let mut env = mock_env("", "");
        env.insert("MOCK_BACKEND".to_string(), "openvm".to_string());
        env.insert("MOCK_BENCH_ROWS".to_string(), "all".to_string());
        env
    };
    // The only real prover is down.
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(30)));
    pool.insert_test_worker("openvm:generic", "openvm", mock_worker_path(), openvm_env())
        .expect("mock openvm worker");
    pool.insert_test_down_worker(
        "risc0:cuda:0",
        "risc0",
        "cuda",
        PathBuf::from("/nonexistent/zkminer-prove-risc0-cuda"),
        None,
    );
    for (name, run) in both_runs(&pool) {
        assert!(run.results.is_empty(), "{name}: {:?}", run.results);
        assert!(
            run.failures.iter().any(|f| f.slot_key == "risc0:cuda:0"),
            "{name}: {:?}",
            run.failures
        );
        let openvm = run
            .failures
            .iter()
            .find(|f| f.slot_key == "openvm:generic")
            .unwrap_or_else(|| panic!("{name}: {:?}", run.failures));
        assert!(
            openvm
                .error
                .contains(zkminer_prover::dispatcher::SIMULATED_BENCHMARK),
            "{name}: {}",
            openvm.error
        );
    }
    pool.close();

    // Beside a working card: a clean run with the stub reported, never measured.
    let mut pool = measuring_metal_pool("");
    pool.insert_test_worker("openvm:generic", "openvm", mock_worker_path(), openvm_env())
        .expect("mock openvm worker");
    pool.insert_test_down_worker(
        "openvm:cuda:1",
        "openvm",
        "cuda",
        PathBuf::from("/nonexistent/zkminer-prove-openvm"),
        None,
    );
    let queued = std::sync::Mutex::new(Vec::new());
    let streamed = pool.benchmark_all_streaming(&|event| {
        if matches!(
            event.kind,
            zkminer_prover::dispatcher::BenchmarkProgressKind::Queued
        ) {
            queued.lock().unwrap().push(event.slot_key);
        }
    });
    assert_eq!(*queued.lock().unwrap(), ["risc0:metal:0"]);
    for (name, run) in [
        ("with_device_info", pool.benchmark_all_with_device_info()),
        ("streaming", streamed),
    ] {
        assert!(run.failures.is_empty(), "{name}: {:?}", run.failures);
        assert_eq!(run.results.len(), 1, "{name}");
        assert_eq!(run.results[0].slot_key, "risc0:metal:0");
        let mut skipped: Vec<&str> = run
            .not_benchmarked
            .iter()
            .map(|f| f.slot_key.as_str())
            .collect();
        skipped.sort();
        // openvm:generic is skipped silently, as every CPU worker beside a GPU one of its backend.
        assert_eq!(skipped, ["openvm:cuda:1"], "{name}");
    }
    // Never a startup-benchmark target: its row can never be saved.
    assert!(
        pool.benchmark_targets().iter().all(|(_, b)| b != "openvm"),
        "{:?}",
        pool.benchmark_targets()
    );
    pool.close();
}

/// W10-BENCH round 2: a worker of ANOTHER backend that could not be started does not get a pass
/// because a card measured: only a GPU of its own backend covers for it.
#[test]
fn a_down_slot_of_another_backend_fails_the_run() {
    let mut pool = measuring_metal_pool("");
    pool.insert_test_down_worker(
        "sp1:cuda:0",
        "sp1",
        "cuda",
        PathBuf::from("/nonexistent/zkminer-prove-sp1"),
        None,
    );
    for (name, run) in both_runs(&pool) {
        assert_eq!(run.results.len(), 1, "{name}");
        assert!(
            run.not_benchmarked.is_empty(),
            "{name}: {:?}",
            run.not_benchmarked
        );
        assert_eq!(run.failures.len(), 1, "{name}: {:?}", run.failures);
        assert_eq!(run.failures[0].slot_key, "sp1:cuda:0", "{name}");
    }
    pool.close();
}

/// With nothing measured, the slots that could not be benchmarked are the run's failures, with their
/// reasons: a lone worker that declined or never started fails the benchmark.
#[test]
fn only_down_slots_fail_the_run() {
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), Some(Duration::from_secs(5)));
    pool.insert_test_down_worker(
        "risc0:metal:0",
        "risc0",
        "metal",
        mock_worker_path(),
        Some("risc0 unavailable: no Metal device"),
    );
    for (name, run) in both_runs(&pool) {
        assert!(run.results.is_empty(), "{name}");
        assert!(run.not_benchmarked.is_empty(), "{name}");
        assert_eq!(run.failures.len(), 1, "{name}: {:?}", run.failures);
        assert!(run.failures[0].error.contains("no Metal device"), "{name}");
    }
    pool.close();
}

// ---- Declines expire ----

/// A worker that exits `WORKER_EXIT_DECLINED` on its first guest (its executor canary failed) has its
/// slot declined, out of use for ten minutes. Once that wait is over the slot is tried with a fresh
/// worker, which passes its handshake and is offered again; a worker that still cannot run a guest
/// declines again, for twice as long; and one that can proves.
#[test]
fn a_declined_slot_is_retried_with_a_fresh_worker() {
    use zkminer_prover_protocol::types::{WorkerDeclined, WORKER_EXIT_DECLINED};
    let min = |m: u64| Duration::from_secs(m * 60);
    let declining = || {
        let mut env = mock_env("", "prove");
        env.insert(
            "MOCK_CRASH_CODE".to_string(),
            WORKER_EXIT_DECLINED.to_string(),
        );
        env
    };
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker("mock:generic", "mock", mock_worker_path(), declining())
        .expect("failed to spawn mock worker");
    let prove = |pool: &WorkerPool| {
        pool.prove(
            "mock",
            b"elf",
            b"input",
            None,
            Some(Duration::from_secs(30)),
            None,
        )
    };

    let err = prove(&pool).expect_err("a declining worker proves nothing");
    assert!(err.downcast_ref::<WorkerDeclined>().is_some(), "{err:#}");
    let (_, wait) = pool.test_decline("mock:generic").expect("declined");
    assert_eq!(wait, min(10));
    assert!(!pool.is_backend_healthy("mock"));
    assert_eq!(pool.retry_due_declines(), 0, "not before its wait is over");
    assert!(prove(&pool).is_err(), "a declined slot takes no proof");

    pool.test_expire_decline("mock:generic");
    assert_eq!(pool.retry_due_declines(), 1);
    assert!(pool.test_decline("mock:generic").is_none(), "offered again");
    assert_eq!(pool.test_has_handle("mock:generic"), Some(true));
    assert!(pool.is_backend_healthy("mock"));

    let err = prove(&pool).expect_err("its worker still cannot run a guest");
    assert!(err.downcast_ref::<WorkerDeclined>().is_some(), "{err:#}");
    let (_, wait) = pool.test_decline("mock:generic").expect("declined again");
    assert_eq!(wait, min(20));

    pool.test_set_spawn_env("mock:generic", mock_env("", ""));
    pool.test_expire_decline("mock:generic");
    assert_eq!(pool.retry_due_declines(), 1);
    prove(&pool).expect("a worker that can run a guest proves");
    assert!(pool.test_decline("mock:generic").is_none());
}
