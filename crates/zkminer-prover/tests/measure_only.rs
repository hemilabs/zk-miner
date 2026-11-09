//! A measure-only pool (`WorkerPool::measure_only`), as `zkminer simulate` builds it: measure workers
//! only, `derive_program_id` on them, and `execute_cycles` beside it.
//!
//! The mock worker plays both backends through wrapper scripts (the handshake checks the backend a
//! worker names), and answers `ProgramId` with keccak256 of the ELF.
//!
//! Run with: `cargo test -p zkminer-prover --features testing --test measure_only`
#![cfg(all(unix, target_os = "linux", feature = "testing"))]

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use alloy_primitives::keccak256;
use zkminer_prover::dispatcher::WorkerPool;
use zkminer_prover_protocol::types::MeasureWallClockTimeout;

fn mock_worker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock-worker"))
}

/// A wrapper that runs the mock worker as `backend`, with `extra` env, through `exec` (the dispatcher
/// relies on the pid and process group surviving it).
fn wrapper(dir: &Path, backend: &str, extra: &[(&str, &str)]) -> PathBuf {
    let mut env = format!("MOCK_BACKEND={backend}");
    for (k, v) in extra {
        env.push_str(&format!(" {k}={v}"));
    }
    let path = dir.join(format!("{backend}-{}", extra.len()));
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nexec env {env} {}\n",
            mock_worker_path().display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "zkminer-measure-only-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn measure_only_pool(binaries: HashMap<String, PathBuf>) -> (WorkerPool, Vec<String>) {
    let mut pool = WorkerPool::new(binaries, Vec::new(), None);
    pool.only_backends(["risc0", "sp1"]);
    pool.measure_only();
    let connected = pool.discover_and_spawn();
    (pool, connected)
}

#[test]
fn a_measure_only_pool_starts_measure_workers_and_no_prover() {
    let dir = temp_dir("spawn");
    let binaries = HashMap::from([
        ("risc0".to_string(), wrapper(&dir, "risc0", &[])),
        ("sp1".to_string(), wrapper(&dir, "sp1", &[])),
    ]);
    let (pool, connected) = measure_only_pool(binaries);
    assert!(connected.is_empty(), "no prove worker: {connected:?}");
    assert!(pool.worker_info("risc0").is_none());
    assert!(pool.worker_info("sp1").is_none());
    assert_eq!(pool.measure_worker_count("risc0"), Some(2));
    assert_eq!(pool.measure_workers_live("risc0"), 2);
    // SP1's pool needs a /dev/shm big enough for its executor; this host's is, CI's may not be.
    if pool.measure_worker_count("sp1").is_some_and(|n| n > 0) {
        assert!(pool.measure_workers_live("sp1") > 0);
    }

    let elf = b"\x7fELF not a real one".to_vec();
    let d = pool
        .derive_program_id("risc0", &elf, Some(Duration::from_secs(30)))
        .expect("the mock derives");
    assert_eq!(d.program_id, keccak256(&elf).0);
    // The measurement path works beside it, on the same pool.
    let m = pool
        .execute_cycles(
            "risc0",
            &elf,
            &[1, 2, 3],
            Some(Duration::from_secs(30)),
            None,
            Some(20),
        )
        .expect("the mock measures");
    assert_eq!(m.cycles, 1020, "1,000 plus the segment size asked for");
    assert_eq!(
        m.host_entropy_reads,
        Some(0),
        "the worker's count of host-entropy reads comes through"
    );
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_uncounted_host_entropy_read_stays_unknown() {
    let dir = temp_dir("entropy");
    for (value, want) in [("3", Some(3)), ("unknown", None)] {
        let binaries = HashMap::from([(
            "risc0".to_string(),
            wrapper(&dir, "risc0", &[("MOCK_HOST_ENTROPY_READS", value)]),
        )]);
        let (pool, _) = measure_only_pool(binaries);
        let m = pool
            .execute_cycles(
                "risc0",
                b"elf",
                &[],
                Some(Duration::from_secs(30)),
                None,
                None,
            )
            .expect("the mock measures");
        assert_eq!(m.host_entropy_reads, want, "{value}: never read as 0");
        pool.shutdown_all();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_pool_without_measure_only_still_starts_its_prover() {
    let dir = temp_dir("prove");
    let binaries = HashMap::from([("risc0".to_string(), wrapper(&dir, "risc0", &[]))]);
    let mut pool = WorkerPool::new(binaries, Vec::new(), None);
    pool.only_backends(["risc0"]);
    let connected = pool.discover_and_spawn();
    assert_eq!(connected.len(), 1, "the prove worker: {connected:?}");
    assert_eq!(pool.measure_workers_live("risc0"), 2);
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_refused_elf_is_an_error_not_an_id() {
    let dir = temp_dir("refuse");
    let binaries = HashMap::from([(
        "risc0".to_string(),
        wrapper(&dir, "risc0", &[("MOCK_PROGRAM_ID_FAIL", "1")]),
    )]);
    let (pool, _) = measure_only_pool(binaries);
    let err = pool
        .derive_program_id("risc0", b"junk", Some(Duration::from_secs(30)))
        .expect_err("refused");
    assert!(
        err.downcast_ref::<zkminer_prover_protocol::types::ProgramIdRefused>()
            .is_some(),
        "the worker's verdict on the bytes is typed: {err:#}"
    );
    // The worker answered; it was not killed or scored against.
    assert_eq!(pool.measure_workers_live("risc0"), 2);
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_worker_that_dies_deriving_is_not_a_refusal() {
    let dir = temp_dir("crash");
    let binaries = HashMap::from([(
        "risc0".to_string(),
        wrapper(&dir, "risc0", &[("MOCK_CRASH_ON", "program_id")]),
    )]);
    let (pool, _) = measure_only_pool(binaries);
    let err = pool
        .derive_program_id("risc0", b"anything", Some(Duration::from_secs(30)))
        .expect_err("it died");
    assert!(
        err.downcast_ref::<zkminer_prover_protocol::types::ProgramIdRefused>()
            .is_none(),
        "a death is not the worker's refusal: {err:#}"
    );
    // Typed, so `zkminer simulate` can remember the program rather than derive it again per job.
    assert!(
        err.downcast_ref::<zkminer_prover_protocol::types::MeasureWorkerDied>()
            .is_some(),
        "{err:#}"
    );
    // The dead slot is cleared and scored, so the next request revives it.
    let states: Vec<_> = (0..2)
        .map(|i| pool.test_measure_slot_state("risc0", i).unwrap())
        .collect();
    assert_eq!(
        states.iter().filter(|(live, _, _)| !live).count(),
        1,
        "{states:?}"
    );
    assert_eq!(
        states.iter().filter(|(_, _, f)| *f == 1).count(),
        1,
        "{states:?}"
    );
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_derivation_past_its_bound_is_a_typed_timeout_and_frees_the_slot() {
    let dir = temp_dir("hang");
    let binaries = HashMap::from([(
        "risc0".to_string(),
        wrapper(&dir, "risc0", &[("MOCK_HANG_ON", "program_id")]),
    )]);
    let (pool, _) = measure_only_pool(binaries);
    let err = pool
        .derive_program_id("risc0", b"slow", Some(Duration::from_secs(2)))
        .expect_err("it hangs");
    assert!(
        err.downcast_ref::<MeasureWallClockTimeout>().is_some(),
        "typed, so a caller can tell it from a guest's error text: {err:#}"
    );
    // The killed slot is cleared, not left pointing at a dead worker, and not scored as a crash.
    let states: Vec<_> = (0..2)
        .map(|i| pool.test_measure_slot_state("risc0", i).unwrap())
        .collect();
    assert_eq!(
        states.iter().filter(|(live, _, _)| !live).count(),
        1,
        "{states:?}"
    );
    assert!(
        states.iter().all(|(_, _, failures)| *failures == 0),
        "{states:?}"
    );
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Block until `pid` has exited (a zombie or gone): its pipes are closed from then on.
fn wait_exited(pid: u32) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| {
                s.rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().next().map(str::to_string))
            });
        if matches!(state.as_deref(), None | Some("Z") | Some("X")) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pid {pid} did not exit"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_worker_found_dead_when_a_request_is_sent_is_typed_gone() {
    use zkminer_prover_protocol::types::MeasureWorkerGone;
    let dir = temp_dir("gone");
    let binaries = HashMap::from([("risc0".to_string(), wrapper(&dir, "risc0", &[]))]);
    let (pool, _) = measure_only_pool(binaries);
    // Both measure workers die while idle (an OOM kill between requests, say).
    for i in 0..2 {
        let (live, pid, _) = pool.test_measure_slot_state("risc0", i).unwrap();
        assert!(live && pid > 0);
        let killed = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .unwrap();
        assert!(killed.success());
        wait_exited(pid);
    }
    let err = pool
        .derive_program_id("risc0", b"elf", Some(Duration::from_secs(30)))
        .expect_err("its worker is gone");
    assert!(
        err.downcast_ref::<MeasureWorkerGone>().is_some(),
        "typed, so a caller can tell nothing ran: {err:#}"
    );
    let err = pool
        .execute_cycles(
            "risc0",
            b"elf",
            &[1],
            Some(Duration::from_secs(30)),
            None,
            Some(20),
        )
        .expect_err("its worker is gone too");
    assert!(
        err.downcast_ref::<MeasureWorkerGone>().is_some(),
        "the same on the execute path: {err:#}"
    );
    // Both slots were cleared, not scored, and the next request revives one.
    for i in 0..2 {
        let (live, _, failures) = pool.test_measure_slot_state("risc0", i).unwrap();
        assert!(!live, "slot {i} cleared");
        assert_eq!(failures, 0, "slot {i} not scored against");
    }
    let d = pool
        .derive_program_id("risc0", b"elf", Some(Duration::from_secs(30)))
        .expect("a revived worker derives");
    assert_eq!(d.program_id, keccak256(b"elf").0);
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

/// SP1's measure worker is set up (its CPU prover built) outside any request's bound, once per
/// spawn, on the worker the next request will use; a worker that died idle is respawned and set up
/// again before a request finds it gone.
#[test]
fn the_next_sp1_measure_worker_is_set_up_once_per_spawn() {
    let dir = temp_dir("warm");
    let binaries = HashMap::from([
        ("sp1".to_string(), wrapper(&dir, "sp1", &[])),
        ("risc0".to_string(), wrapper(&dir, "risc0", &[])),
    ]);
    let (pool, _) = measure_only_pool(binaries);
    // risc0 has no such setup: ready while a worker runs.
    assert!(pool.warm_measure_worker("risc0", Duration::from_secs(5)));
    if !pool.measure_worker_count("sp1").is_some_and(|n| n > 0) {
        // This host's /dev/shm is too small for an SP1 measure pool (see the first test).
        pool.shutdown_all();
        return;
    }
    assert!(pool.warm_measure_worker("sp1", Duration::from_secs(30)));
    let (_, pid, _) = pool.test_measure_slot_state("sp1", 0).unwrap();
    assert!(pool.warm_measure_worker("sp1", Duration::from_secs(30)), "still set up");
    assert_eq!(pool.test_measure_slot_state("sp1", 0).unwrap().1, pid, "the same worker");
    // It dies idle: respawned and set up before any request.
    let killed = std::process::Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    wait_exited(pid);
    assert!(pool.warm_measure_worker("sp1", Duration::from_secs(30)));
    let (live, new_pid, _) = pool.test_measure_slot_state("sp1", 0).unwrap();
    assert!(live && new_pid != pid, "a new worker in the same slot");
    // And the request after it runs on it.
    pool.derive_program_id("sp1", b"elf", Some(Duration::from_secs(30)))
        .expect("a set-up worker derives");
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_set_up_past_its_bound_is_killed_and_reports_not_ready() {
    let dir = temp_dir("warm-hang");
    let binaries = HashMap::from([(
        "sp1".to_string(),
        wrapper(&dir, "sp1", &[("MOCK_HANG_ON", "warmup")]),
    )]);
    let (pool, _) = measure_only_pool(binaries);
    if !pool.measure_worker_count("sp1").is_some_and(|n| n > 0) {
        pool.shutdown_all();
        return;
    }
    let started = std::time::Instant::now();
    assert!(!pool.warm_measure_worker("sp1", Duration::from_secs(2)));
    assert!(started.elapsed() < Duration::from_secs(20), "bounded");
    let (live, _, failures) = pool.test_measure_slot_state("sp1", 0).unwrap();
    assert!(!live, "the watchdog killed it");
    assert_eq!(failures, 0, "its own bound's kill is not scored against the slot");
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_worker_that_dies_during_a_request_is_not_gone() {
    // The death is the request's (it may be the guest's doing): untyped, and the slot is scored.
    let dir = temp_dir("dies-during");
    let binaries = HashMap::from([(
        "risc0".to_string(),
        wrapper(&dir, "risc0", &[("MOCK_CRASH_ON", "execute")]),
    )]);
    let (pool, _) = measure_only_pool(binaries);
    let err = pool
        .execute_cycles(
            "risc0",
            b"elf",
            &[1],
            Some(Duration::from_secs(30)),
            None,
            Some(20),
        )
        .expect_err("it died");
    assert!(
        err.downcast_ref::<zkminer_prover_protocol::types::MeasureWorkerGone>()
            .is_none(),
        "{err:#}"
    );
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_measure_worker_means_none_live() {
    let pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    assert_eq!(pool.measure_workers_live("risc0"), 0);
    assert!(pool
        .derive_program_id("risc0", b"x", Some(Duration::from_secs(1)))
        .is_err());
}

// ─── Real workers (opt-in) ───────────────────────────────────────────────────
//
// `ZKMINER_TEST_RISC0_WORKER` (e.g. target/release/zkminer-prove-risc0-cpu) and `ZKMINER_TEST_SP1_WORKER`
// (target/release/zkminer-prove-sp1): the program id each derives for its fibonacci guest must be the one
// `--export-guest` prints — the `programId` a job for that guest carries.

/// `--export-guest <name>` from `worker`: the guest's bytes and the program id it prints.
fn export(worker: &Path, name: &str, dir: &Path) -> (Vec<u8>, [u8; 32]) {
    let path = dir.join(format!("{name}.elf"));
    let out = std::process::Command::new(worker)
        .args(["--export-guest", name])
        .arg(&path)
        .output()
        .expect("run --export-guest");
    assert!(
        out.status.success(),
        "--export-guest: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let hex = printed.strip_prefix("0x").unwrap_or(&printed);
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    (
        std::fs::read(&path).unwrap(),
        bytes.try_into().expect("32 bytes"),
    )
}

fn real_pool(backend: &str, worker: PathBuf) -> WorkerPool {
    let (pool, connected) = measure_only_pool(HashMap::from([(backend.to_string(), worker)]));
    assert!(connected.is_empty());
    assert!(
        pool.measure_workers_live(backend) > 0,
        "the {backend} measure worker did not start"
    );
    pool
}

#[test]
#[ignore = "needs ZKMINER_TEST_RISC0_WORKER"]
fn the_risc0_worker_derives_its_guests_image_id_and_measures_it() {
    let worker = PathBuf::from(
        std::env::var("ZKMINER_TEST_RISC0_WORKER").expect("ZKMINER_TEST_RISC0_WORKER"),
    );
    let dir = temp_dir("risc0-real");
    // The risc0 worker exports its fibonacci guest only.
    let (fib, fib_id) = export(&worker, "fibonacci", &dir);
    // As `zkminer simulate` runs it under the indexer's unit: a HOME it cannot write (so no key file
    // can be read or made there) and a `sys_rand` key for this run only, passed as not ephemeral. The
    // worker must still return the journal, or every binding reads `unchecked`.
    let home = dir.join("read-only-home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::env::set_var("HOME", &home);
    zkminer_prover::worker::set_risc0_sys_rand_key([0x5a; 32], false);
    let pool = real_pool("risc0", worker);
    let d = pool
        .derive_program_id("risc0", &fib, Some(Duration::from_secs(60)))
        .expect("derive");
    assert_eq!(
        d.program_id, fib_id,
        "the image id the worker derives is the job's programId"
    );
    // Not an ELF: the worker's typed refusal, and it stays up.
    let err = pool
        .derive_program_id(
            "risc0",
            b"\x7fELF but not really",
            Some(Duration::from_secs(60)),
        )
        .expect_err("refused");
    assert!(
        err.downcast_ref::<zkminer_prover_protocol::types::ProgramIdRefused>()
            .is_some(),
        "{err:#}"
    );
    assert!(pool.measure_workers_live("risc0") > 0);
    // And the measurement beside it: one segment, a power of two at po2 20.
    let m = pool
        .execute_cycles(
            "risc0",
            &fib,
            &10u32.to_le_bytes(),
            Some(Duration::from_secs(120)),
            Some(fib_id),
            Some(20),
        )
        .expect("execute");
    assert!(m.cycles.is_power_of_two(), "{} cycles", m.cycles);
    assert_eq!(
        m.journal.as_deref(),
        Some(&55u64.to_le_bytes()[..]),
        "fibonacci(10) = 55, returned under the per-run key"
    );
    // It reads no host entropy past its runtime's own draw; and this build's count works (else None).
    assert_eq!(m.host_entropy_reads, Some(0));
    assert!(
        !home.join(".zkminer").exists(),
        "nothing was created under HOME"
    );
    pool.shutdown_all();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "needs ZKMINER_TEST_SP1_WORKER (SP1 setup on the CPU: minutes)"]
fn the_sp1_worker_derives_its_guests_vkey_on_the_cpu() {
    let worker =
        PathBuf::from(std::env::var("ZKMINER_TEST_SP1_WORKER").expect("ZKMINER_TEST_SP1_WORKER"));
    let dir = temp_dir("sp1-real");
    let (fib, fib_vkey) = export(&worker, "fibonacci", &dir);
    let pool = real_pool("sp1", worker);
    let d = pool
        .derive_program_id("sp1", &fib, Some(Duration::from_secs(1800)))
        .expect("derive the vkey");
    assert_eq!(
        d.program_id, fib_vkey,
        "the vkey hash the worker derives is the job's programId"
    );
    let m = pool
        .execute_cycles(
            "sp1",
            &fib,
            &10u32.to_le_bytes(),
            Some(Duration::from_secs(600)),
            None,
            None,
        )
        .expect("execute");
    assert!(m.cycles > 0);
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}
