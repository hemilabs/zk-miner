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

/// What the `sys-rand-echo` guest must commit under the public rule: everything from public data.
fn echo_journal_by_the_rule(image_id: &[u8; 32], input: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let seed: [u8; 32] = Sha256::new()
        .chain_update(zkminer_prover_protocol::sys_rand::SYS_RAND_DOMAIN)
        .chain_update(image_id)
        .chain_update(Sha256::digest(input))
        .finalize()
        .into();
    let block = |i: u64| {
        Sha256::new()
            .chain_update(b"risc0-zkvm/sys_rand/v1")
            .chain_update(seed)
            .chain_update(i.to_le_bytes())
            .finalize()
    };
    let stream: Vec<u8> = (0..2).flat_map(|i| block(i).to_vec()).collect();
    // The guest's runtime takes the first 16 bytes before `main`.
    stream[16..48].to_vec()
}

/// A guest that commits its `sys_rand` bytes: the journal is exactly what the public rule predicts,
/// in separate worker processes and at different segment sizes. This is what a change to the seed
/// function, the input it hashes, the image id's byte order or the fork's stream would break.
#[test]
#[ignore = "needs ZKMINER_TEST_RISC0_WORKER"]
fn the_risc0_worker_seeds_a_guest_by_the_public_rule_in_every_process() {
    let worker = PathBuf::from(
        std::env::var("ZKMINER_TEST_RISC0_WORKER").expect("ZKMINER_TEST_RISC0_WORKER"),
    );
    let dir = temp_dir("sys-rand-rule");
    let (echo, echo_id) = export(&worker, "sys-rand-echo", &dir);
    let input = b"zkminer".to_vec();
    let want = echo_journal_by_the_rule(&echo_id, &input);
    for po2 in [18u8, 20] {
        let pool = real_pool("risc0", worker.clone());
        let m = pool
            .execute_cycles(
                "risc0",
                &echo,
                &input,
                Some(Duration::from_secs(120)),
                Some(echo_id),
                Some(po2),
            )
            .expect("execute");
        assert_eq!(
            m.journal.as_deref(),
            Some(&want[..]),
            "the bytes the rule predicts, at po2 {po2}"
        );
        assert_eq!(m.host_entropy_reads, Some(1), "its one draw is counted");
        pool.shutdown_all();
    }
    // Another input is another seed.
    let pool = real_pool("risc0", worker);
    let other = pool
        .execute_cycles(
            "risc0",
            &echo,
            b"zkminer!",
            Some(Duration::from_secs(120)),
            Some(echo_id),
            Some(20),
        )
        .expect("execute");
    assert_ne!(other.journal.as_deref(), Some(&want[..]));
    assert_eq!(
        other.journal.as_deref(),
        Some(&echo_journal_by_the_rule(&echo_id, b"zkminer!")[..])
    );
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

/// `same_path` against the real worker: a plain guest runs the same at every size, in the guest's own
/// cycles, though its padded count moves; one that reads the size does not.
#[test]
#[ignore = "needs ZKMINER_TEST_RISC0_WORKER"]
fn the_risc0_worker_shows_which_guests_steer_on_the_segment_size() {
    let worker = PathBuf::from(
        std::env::var("ZKMINER_TEST_RISC0_WORKER").expect("ZKMINER_TEST_RISC0_WORKER"),
    );
    let dir = temp_dir("segment-size");
    let (fib, fib_id) = export(&worker, "fibonacci", &dir);
    let (steer, steer_id) = export(&worker, "segment-size-steer", &dir);
    let pool = real_pool("risc0", worker);
    let at = |elf: &[u8], id: [u8; 32], input: &[u8], po2: u8| {
        pool.execute_cycles("risc0", elf, input, Some(Duration::from_secs(300)), Some(id), Some(po2))
            .expect("execute")
    };
    let input = 10u32.to_le_bytes();
    let base = at(&fib, fib_id, &input, 20);
    assert!(base.user_cycles.is_some_and(|c| c > 0));
    assert_eq!(base.keccak_cycles, Some(0));
    for po2 in [16u8, 18, 22] {
        assert!(base.same_path(&at(&fib, fib_id, &input, po2)), "fibonacci at po2 {po2}");
    }
    let at20 = at(&steer, steer_id, &[], 20);
    let at19 = at(&steer, steer_id, &[], 19);
    assert_eq!(at20.journal, at19.journal, "one journal, so the journal alone cannot tell");
    assert_eq!(at20.host_entropy_reads, Some(0), "and it reads no randomness");
    assert!(!at20.same_path(&at19), "its own cycles differ");
    assert!(at20.cycles > at19.cycles * 4, "{} against {}", at20.cycles, at19.cycles);
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The keccak proof size is a host setting a guest can see, so a simulation fixes it: every measure
/// worker gets the SDK's default whatever this host's environment says.
#[test]
fn a_measure_only_pool_pins_the_keccak_size_a_guest_can_see() {
    use zkminer_prover_protocol::sys_rand::{RISC0_CANONICAL_KECCAK_PO2, RISC0_KECCAK_PO2_ENV};
    let dir = temp_dir("keccak-pin");
    let log = dir.join("env.log");
    let path = dir.join("risc0-logs-env");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nenv >> {}\nexec env MOCK_BACKEND=risc0 {}\n",
            log.display(),
            mock_worker_path().display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::env::set_var(RISC0_KECCAK_PO2_ENV, "15");
    let (pool, _) = measure_only_pool(HashMap::from([("risc0".to_string(), path)]));
    std::env::remove_var(RISC0_KECCAK_PO2_ENV);
    assert!(pool.measure_workers_live("risc0") > 0);
    let seen = std::fs::read_to_string(&log).unwrap();
    let want = format!("{RISC0_KECCAK_PO2_ENV}={RISC0_CANONICAL_KECCAK_PO2}");
    assert!(seen.lines().any(|l| l == want), "pinned: {seen}");
    assert!(
        !seen.lines().any(|l| l == format!("{RISC0_KECCAK_PO2_ENV}=15")),
        "not the host's"
    );
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
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
    // As `zkminer simulate` runs it under the indexer's unit: a HOME it cannot write. The worker must
    // still return the journal, or every binding reads `unchecked`.
    let home = dir.join("read-only-home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::env::set_var("HOME", &home);
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
        "fibonacci(10) = 55"
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

/// The pids that set up, one line per `Warmup` the mock answered (`MOCK_WARMUP_LOG`).
fn warmups(log: &Path) -> Vec<u32> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().parse().unwrap())
        .collect()
}

/// `measure_only_pool`, with `bound` on a request's measure-worker setup.
fn measure_only_pool_bounded(binaries: HashMap<String, PathBuf>, bound: Duration) -> WorkerPool {
    let mut pool = WorkerPool::new(binaries, Vec::new(), None);
    pool.only_backends(["sp1"]);
    pool.measure_only();
    pool.measure_setup_bound(Some(bound));
    pool.discover_and_spawn();
    pool
}

/// SP1's measure worker pays a one-time setup on first use (its CPU prover; minutes on a host with
/// one free core). A request sets its worker up FIRST, under the setup bound, so the request's own
/// bound covers only the request: here a 4 s setup and a 2 s bound, which timed every first
/// measurement out when the setup ran inside it. Once per spawn: a respawned worker is set up again
/// by the request that revives it.
#[test]
fn a_request_sets_its_sp1_measure_worker_up_outside_its_own_bound() {
    let dir = temp_dir("lazy-setup");
    let log = dir.join("warmups");
    let log_s = log.display().to_string();
    let binaries = HashMap::from([(
        "sp1".to_string(),
        wrapper(
            &dir,
            "sp1",
            &[("MOCK_SETUP_SECS", "4"), ("MOCK_WARMUP_LOG", &log_s)],
        ),
    )]);
    let pool = measure_only_pool_bounded(binaries, Duration::from_secs(60));
    if !pool.measure_worker_count("sp1").is_some_and(|n| n > 0) {
        // This host's /dev/shm is too small for an SP1 measure pool (see the first test).
        pool.shutdown_all();
        return;
    }
    let bound = Some(Duration::from_secs(2));
    let execute = || pool.execute_cycles("sp1", b"elf", &[], bound, None, None);

    execute().expect("the setup is not inside the request's bound");
    assert_eq!(warmups(&log).len(), 1, "set up once");
    execute().expect("a set-up worker measures");
    assert_eq!(warmups(&log).len(), 1, "and not again for the same worker");
    pool.derive_program_id("sp1", b"elf", bound)
        .expect("a derivation runs on the same set-up worker");
    assert_eq!(warmups(&log).len(), 1);

    // Every worker dies idle. The requests that find one gone say so (typed, nothing ran) until one
    // revives a worker, which it sets up before measuring, again outside its bound.
    let first = warmups(&log)[0];
    for i in 0..pool.measure_worker_count("sp1").unwrap() {
        let (live, pid, _) = pool.test_measure_slot_state("sp1", i).unwrap();
        if live && pid != 0 {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status();
            wait_exited(pid);
        }
    }
    let mut measured = false;
    for _ in 0..10 {
        match execute() {
            Ok(_) => {
                measured = true;
                break;
            }
            Err(e) => {
                assert!(
                    e.downcast_ref::<zkminer_prover_protocol::types::MeasureWorkerGone>()
                        .is_some()
                        || e.downcast_ref::<zkminer_prover_protocol::types::MeasureSlotsBusy>()
                            .is_some(),
                    "only a typed 'nothing ran': {e:#}"
                );
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    assert!(measured, "a revived worker measures");
    let set_up = warmups(&log);
    assert_eq!(set_up.len(), 2, "the revived worker was set up: {set_up:?}");
    assert_ne!(set_up[1], first, "by its own process");
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A derivation sets a cold worker up first, outside its own bound, as an execution does.
#[test]
fn a_derivation_sets_its_sp1_measure_worker_up_outside_its_own_bound() {
    let dir = temp_dir("lazy-setup-derive");
    let binaries = HashMap::from([(
        "sp1".to_string(),
        wrapper(&dir, "sp1", &[("MOCK_SETUP_SECS", "4")]),
    )]);
    let pool = measure_only_pool_bounded(binaries, Duration::from_secs(60));
    if !pool.measure_worker_count("sp1").is_some_and(|n| n > 0) {
        pool.shutdown_all();
        return;
    }
    let d = pool
        .derive_program_id("sp1", b"elf", Some(Duration::from_secs(2)))
        .expect("the setup is not inside the derivation's bound");
    assert_eq!(d.program_id, keccak256(b"elf").0);
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A setup past its bound is killed and fails the request as the typed transient
/// `MeasureSetupFailed`: no guest ran, so it is neither a wall-clock timeout (which strikes the
/// job) nor scored against the slot.
#[test]
fn a_setup_past_its_bound_fails_the_request_as_a_typed_transient() {
    let dir = temp_dir("setup-hang");
    let binaries = HashMap::from([(
        "sp1".to_string(),
        wrapper(&dir, "sp1", &[("MOCK_HANG_ON", "warmup")]),
    )]);
    let pool = measure_only_pool_bounded(binaries, Duration::from_secs(2));
    if !pool.measure_worker_count("sp1").is_some_and(|n| n > 0) {
        pool.shutdown_all();
        return;
    }
    let started = std::time::Instant::now();
    let e = pool
        .execute_cycles(
            "sp1",
            b"elf",
            &[],
            Some(Duration::from_secs(60)),
            None,
            None,
        )
        .expect_err("the setup never finishes");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "bounded by the setup bound"
    );
    assert!(
        e.downcast_ref::<zkminer_prover_protocol::types::MeasureSetupFailed>()
            .is_some(),
        "typed: {e:#}"
    );
    assert!(
        e.downcast_ref::<MeasureWallClockTimeout>().is_none(),
        "{e:#}"
    );
    let (live, _, failures) = pool.test_measure_slot_state("sp1", 0).unwrap();
    assert!(!live, "the setup's watchdog killed it");
    assert_eq!(
        failures, 0,
        "its own bound's kill is not scored against the slot"
    );
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A claimed proof may preempt a measurement while its worker is still being set up: the request is
/// the typed `MeasurePreempted` (no strike), and the kill is not scored against the slot.
#[test]
fn a_setup_preempted_by_a_claimed_proof_is_a_preemption() {
    let dir = temp_dir("setup-preempt");
    let log = dir.join("warmups");
    let log_s = log.display().to_string();
    let binaries = HashMap::from([(
        "sp1".to_string(),
        wrapper(
            &dir,
            "sp1",
            &[("MOCK_HANG_ON", "warmup"), ("MOCK_WARMUP_LOG", &log_s)],
        ),
    )]);
    let pool = std::sync::Arc::new(measure_only_pool_bounded(binaries, Duration::from_secs(60)));
    if !pool.measure_worker_count("sp1").is_some_and(|n| n > 0) {
        pool.shutdown_all();
        return;
    }
    let measurer = {
        let pool = std::sync::Arc::clone(&pool);
        std::thread::spawn(move || {
            pool.execute_cycles(
                "sp1",
                b"elf",
                &[],
                Some(Duration::from_secs(60)),
                None,
                None,
            )
        })
    };
    // The mock logs the Warmup before it hangs in it.
    let started = std::time::Instant::now();
    while warmups(&log).is_empty() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the setup never started"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    pool.test_preempt_all_inflight_measures();
    let e = measurer.join().unwrap().expect_err("it was preempted");
    assert!(
        e.downcast_ref::<zkminer_prover_protocol::types::MeasurePreempted>()
            .is_some(),
        "{e:#}"
    );
    let (live, _, failures) = pool.test_measure_slot_state("sp1", 0).unwrap();
    assert!(!live, "the preemption killed it");
    assert_eq!(failures, 0, "a preemption is not scored against the slot");
    pool.shutdown_all();
    let _ = std::fs::remove_dir_all(&dir);
}
