//! The CPU worker's one-shot witness execute (`--witness-execute`) under the real sandbox, launched
//! as the miner launches it (`zkminer_prover::witness_exec::run_witness_execute`: a job cgroup, fds
//! 0-3, an empty environment), on the real fibonacci guest (`--export-guest`).
//!
//! Needs a delegated cgroup:
//!
//! ```text
//! systemd-run --user --scope -q -p Delegate=yes -- \
//!     env ZKMINER_SANDBOX_TESTS_REQUIRED=1 CARGO_TARGET_DIR=... \
//!     cargo test -p zkminer-prove-risc0 --features cpu --test witness_execute
//! ```
//!
//! Elsewhere it prints `SKIPPED` to stderr and returns (or fails, with ZKMINER_SANDBOX_TESTS_REQUIRED).
#![cfg(all(target_os = "linux", feature = "cpu"))]

use std::fs::File;
use std::io::Write;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zkminer_prover::witness_exec::{run_witness_execute, CgroupSpec, WitnessExecError};
use zkminer_prover_protocol::{
    sys_rand::risc0_seed, write_message, WitnessExecuteFailure, WitnessExecuteRequest,
    GUEST_EXIT_HALTED, WITNESS_EXECUTE_ARG,
};
use zkminer_witness_sandbox::{
    delegated_root, landlock_abi, prepare_command, Cgroup, SandboxError, MIN_LANDLOCK_ABI,
};

const WORKER: &str = env!("CARGO_BIN_EXE_zkminer-prove-risc0-cpu");

/// What every run here gets unless a test says otherwise. Two tasks (the main thread and the
/// executor's segment thread) and 256 MiB are what the execute measured to need (see
/// `the_execute_runs_in_two_tasks_and_little_memory`); these leave room.
const PIDS_MAX: u32 = 4;
const MEMORY_MAX: u64 = 512 << 20;
const TIMEOUT: Duration = Duration::from_secs(120);

fn skip(test: &str, reason: &str) {
    if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
        panic!("{test}: sandbox unavailable: {reason}");
    }
    let _ = writeln!(std::io::stderr(), "SKIPPED {test}: {reason}");
}

fn delegated(test: &str) -> Option<PathBuf> {
    let abi = landlock_abi();
    if abi < MIN_LANDLOCK_ABI {
        skip(test, &format!("Landlock ABI {abi} < {MIN_LANDLOCK_ABI}"));
        return None;
    }
    match delegated_root() {
        Ok(root) => Some(root),
        Err(e @ SandboxError::NotDelegated { .. }) => {
            skip(test, &e.to_string());
            None
        }
        Err(e) => panic!("{test}: delegated_root: {e}"),
    }
}

/// The worker's fibonacci guest and its image id, as `--export-guest` writes and prints them.
fn fibonacci() -> &'static (Vec<u8>, [u8; 32]) {
    static GUEST: OnceLock<(Vec<u8>, [u8; 32])> = OnceLock::new();
    GUEST.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fibonacci.elf");
        let out = Command::new(WORKER)
            .args(["--export-guest", "fibonacci"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let printed = String::from_utf8(out.stdout).unwrap();
        let hex = printed.trim().trim_start_matches("0x");
        let id: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let elf = std::fs::read(&path).unwrap();
        assert!(!elf.is_empty(), "the worker was built without its guests");
        (elf, id.try_into().unwrap())
    })
}

fn fib(n: u32) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        (a, b) = (b, a.wrapping_add(b));
    }
    a
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// `W` in a file opened read-only, and the request for it.
fn job(
    dir: &Path,
    w: &[u8],
    prefix: &[u8],
    po2s: &[u8],
    seed: [u8; 32],
) -> (File, WitnessExecuteRequest) {
    let path = w_path(dir, w);
    std::fs::write(&path, w).unwrap();
    let req = WitnessExecuteRequest {
        elf: fibonacci().0.clone(),
        prefix: prefix.to_vec(),
        w_len: w.len() as u64,
        input_sha256: sha256(&[prefix, w].concat()),
        sys_rand_seed: seed,
        po2s: po2s.to_vec(),
        keccak_po2: 17,
        max_cycles: None,
    };
    (File::open(&path).unwrap(), req)
}

/// Where [`job`] keeps `w`: named by its hash, so two jobs in one directory never share a file.
fn w_path(dir: &Path, w: &[u8]) -> PathBuf {
    let hex: String = sha256(w).iter().map(|b| format!("{b:02x}")).collect();
    dir.join(format!("w-{hex}.bin"))
}

fn spec(name: &str) -> CgroupSpec {
    CgroupSpec {
        name: format!("wexec-{name}-{}", std::process::id()),
        memory_max: MEMORY_MAX,
        pids_max: PIDS_MAX,
        cpu_max: None,
        cpu_weight: 50,
    }
}

fn run(
    root: &Path,
    name: &str,
    w: &File,
    req: &WitnessExecuteRequest,
) -> Result<zkminer_prover_protocol::WitnessExecuteResponse, WitnessExecError> {
    run_witness_execute(Path::new(WORKER), root, spec(name), req, w.as_fd(), TIMEOUT)
}

fn exit_failure(e: &WitnessExecError) -> Option<WitnessExecuteFailure> {
    match e {
        WitnessExecError::Exit { failure, .. } => *failure,
        _ => None,
    }
}

/// Cycles and the journal at each po2; the journal is the same at every one; the image id is the
/// guest's; and a job with the journal prefix reads the prefix first.
#[test]
fn executes_at_every_po2_under_the_sandbox() {
    let test = "executes_at_every_po2_under_the_sandbox";
    let Some(root) = delegated(test) else { return };
    let dir = tempfile::tempdir().unwrap();
    // ~400k cycles: several segments at po2 16, one at 20.
    let n = 40_000u32;
    let (w, req) = job(dir.path(), &n.to_le_bytes(), &[], &[16, 18, 20], [1; 32]);
    let resp = run(&root, "po2s", &w, &req)
        .unwrap_or_else(|e| panic!("{e}\n{}", e.log_tail().unwrap_or("")));
    assert_eq!(resp.image_id, fibonacci().1, "the guest's image id");
    assert_eq!(resp.results.len(), 3);
    let journal = fib(n).to_le_bytes();
    for (r, po2) in resp.results.iter().zip([16, 18, 20]) {
        assert_eq!(r.po2, po2);
        assert_eq!((r.exit_kind, r.exit_code), (GUEST_EXIT_HALTED, 0));
        assert_eq!(r.journal, journal, "po2 {po2}");
        assert_eq!((r.journal_len, r.journal_sha256), (8, sha256(&journal)));
        assert!(r.segment_bytes > 0 && r.peak_host_bytes > 0, "{r:?}");
        eprintln!(
            "po2 {po2}: {} cycles, {} segment bytes, peak RSS {} MiB",
            r.cycles,
            r.segment_bytes,
            r.peak_host_bytes >> 20
        );
    }
    // Segments are padded to powers of two: smaller ones pad more, and cost more segment bytes.
    let [a, b, c] = [0, 1, 2].map(|i| resp.results[i].cycles);
    assert!(a > 1 << 16, "several segments at 16: {a}");
    assert!(
        c.is_power_of_two() && c <= 1 << 20,
        "one segment at 20: {c}"
    );
    assert!(b >= c / 2, "{b} {c}");
    assert!(resp.results[0].segment_bytes > resp.results[2].segment_bytes);

    // The 64-byte prefix comes first: fibonacci reads its n from the prefix's first word.
    let mut prefix = [0u8; 64];
    prefix[..4].copy_from_slice(&12u32.to_le_bytes());
    let (w, req) = job(
        dir.path(),
        b"W after the prefix",
        &prefix,
        &[16, 22],
        [1; 32],
    );
    let resp = run(&root, "prefix", &w, &req).unwrap();
    assert!(resp
        .results
        .iter()
        .all(|r| r.journal == 144u64.to_le_bytes()));
}

/// An input that is not the request's is refused with its typed exit code, before any execution.
#[test]
fn a_wrong_input_is_refused() {
    let test = "a_wrong_input_is_refused";
    let Some(root) = delegated(test) else { return };
    let dir = tempfile::tempdir().unwrap();
    let (w, mut req) = job(dir.path(), &10u32.to_le_bytes(), &[], &[20], [1; 32]);
    req.input_sha256[0] ^= 1;
    let e = run(&root, "hash", &w, &req).unwrap_err();
    assert_eq!(
        exit_failure(&e),
        Some(WitnessExecuteFailure::InputMismatch),
        "{e}"
    );
    req.input_sha256[0] ^= 1;
    req.w_len += 1;
    let e = run(&root, "len", &w, &req).unwrap_err();
    assert_eq!(
        exit_failure(&e),
        Some(WitnessExecuteFailure::InputMismatch),
        "{e}"
    );
    req.w_len -= 1;
    // The prefix is part of what is hashed.
    req.prefix = vec![0; 64];
    let e = run(&root, "prefix", &w, &req).unwrap_err();
    assert_eq!(
        exit_failure(&e),
        Some(WitnessExecuteFailure::InputMismatch),
        "{e}"
    );
}

/// The seed is the request's, and the guest's journal does not depend on it when it reads no
/// randomness. The miner derives it from the bundle's input hash, as a prove worker would from W.
#[test]
fn the_seed_is_the_requests() {
    let test = "the_seed_is_the_requests";
    let Some(root) = delegated(test) else { return };
    let dir = tempfile::tempdir().unwrap();
    let w = 1000u32.to_le_bytes();
    let seed_a = risc0_seed(&[1; 32], &fibonacci().1, &sha256(&w));
    let seed_b = risc0_seed(&[2; 32], &fibonacci().1, &sha256(&w));
    assert_ne!(seed_a, seed_b);
    let (f, req_a) = job(dir.path(), &w, &[], &[16, 20], seed_a);
    let a = run(&root, "seed-a", &f, &req_a).unwrap();
    let req_b = WitnessExecuteRequest {
        sys_rand_seed: seed_b,
        ..req_a.clone()
    };
    let b = run(&root, "seed-b", &f, &req_b).unwrap();
    for (x, y) in a.results.iter().zip(&b.results) {
        assert_eq!(
            (&x.journal, x.journal_sha256, x.cycles),
            (&y.journal, y.journal_sha256, y.cycles)
        );
    }
    assert_eq!(a.results[0].journal, fib(1000).to_le_bytes());
}

/// The typed failures: an ELF risc0 refuses, a cycle cap, a writable W, a malformed request.
#[test]
fn failures_are_typed_by_exit_code() {
    let test = "failures_are_typed_by_exit_code";
    let Some(root) = delegated(test) else { return };
    let dir = tempfile::tempdir().unwrap();
    let (w, req) = job(dir.path(), &40_000u32.to_le_bytes(), &[], &[16], [1; 32]);

    let bad_elf = WitnessExecuteRequest {
        elf: b"\x7fELF but no program".to_vec(),
        ..req.clone()
    };
    let e = run(&root, "elf", &w, &bad_elf).unwrap_err();
    assert_eq!(
        exit_failure(&e),
        Some(WitnessExecuteFailure::InvalidElf),
        "{e}"
    );

    let capped = WitnessExecuteRequest {
        max_cycles: Some(1 << 17),
        ..req.clone()
    };
    let e = run(&root, "cap", &w, &capped).unwrap_err();
    assert_eq!(
        exit_failure(&e),
        Some(WitnessExecuteFailure::CycleLimit),
        "{e}"
    );

    let bad_po2 = WitnessExecuteRequest {
        po2s: vec![15],
        ..req.clone()
    };
    let e = run(&root, "po2", &w, &bad_po2).unwrap_err();
    assert_eq!(
        exit_failure(&e),
        Some(WitnessExecuteFailure::BadRequest),
        "{e}"
    );

    // W must not be writable (a file opened read-write, unsealed).
    let writable = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(w_path(dir.path(), &40_000u32.to_le_bytes()))
        .unwrap();
    let e = run(&root, "rw", &writable, &req).unwrap_err();
    assert_eq!(
        exit_failure(&e),
        Some(WitnessExecuteFailure::BadRequest),
        "{e}"
    );

    // A sealed memfd is accepted.
    let memfd = sealed_memfd(&40_000u32.to_le_bytes());
    let resp = run(&root, "memfd", &memfd, &req).unwrap();
    assert_eq!(resp.results[0].journal, fib(40_000).to_le_bytes());
}

fn sealed_memfd(bytes: &[u8]) -> File {
    use std::os::fd::FromRawFd;
    // SAFETY: memfd_create with a static name; the fd is owned by the File.
    let fd =
        unsafe { libc::memfd_create(c"w".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    assert!(fd >= 0);
    let mut f = unsafe { File::from_raw_fd(fd) };
    f.write_all(bytes).unwrap();
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: fcntl on an open fd.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
    f
}

/// The launcher's other outcomes, from the real worker: the timeout kills the cgroup, and a
/// `memory.max` the input cannot fit in is an OOM kill.
#[test]
fn a_timeout_and_an_oom_are_their_own_errors() {
    let test = "a_timeout_and_an_oom_are_their_own_errors";
    let Some(root) = delegated(test) else { return };
    let dir = tempfile::tempdir().unwrap();
    // Billions of cycles: far past a one-second budget.
    let (w, req) = job(dir.path(), &u32::MAX.to_le_bytes(), &[], &[20], [1; 32]);
    let started = Instant::now();
    let e = run_witness_execute(
        Path::new(WORKER),
        &root,
        spec("timeout"),
        &req,
        w.as_fd(),
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(matches!(e, WitnessExecError::Timeout { .. }), "{e}");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "killed promptly"
    );

    // 64 MiB of W into a 32 MiB cgroup.
    let big = vec![7u8; 64 << 20];
    let (w, req) = job(dir.path(), &big, &[], &[20], [1; 32]);
    let small = CgroupSpec {
        memory_max: 32 << 20,
        ..spec("oom")
    };
    let e =
        run_witness_execute(Path::new(WORKER), &root, small, &req, w.as_fd(), TIMEOUT).unwrap_err();
    assert!(matches!(e, WitnessExecError::OomKilled { .. }), "{e}");
}

/// Two tasks — the main thread and the executor's segment thread — and a small cgroup are enough
/// for a multi-segment execution at every job po2.
#[test]
fn the_execute_runs_in_two_tasks_and_little_memory() {
    let test = "the_execute_runs_in_two_tasks_and_little_memory";
    let Some(root) = delegated(test) else { return };
    let dir = tempfile::tempdir().unwrap();
    let (w, req) = job(
        dir.path(),
        &40_000u32.to_le_bytes(),
        &[],
        &[16, 17, 18, 19, 20, 21, 22],
        [1; 32],
    );
    let tight = CgroupSpec {
        pids_max: 2,
        memory_max: 256 << 20,
        ..spec("tight")
    };
    let resp = run_witness_execute(Path::new(WORKER), &root, tight, &req, w.as_fd(), TIMEOUT)
        .unwrap_or_else(|e| panic!("{e}\n{}", e.log_tail().unwrap_or("")));
    assert_eq!(resp.results.len(), 7);
    let peak = resp
        .results
        .iter()
        .map(|r| r.peak_host_bytes)
        .max()
        .unwrap();
    eprintln!(
        "7 po2s in pids.max 2 / memory.max 256 MiB: peak RSS {} MiB",
        peak >> 20
    );
    // One task is not enough: the executor cuts segments on a thread of its own.
    let one = CgroupSpec {
        pids_max: 1,
        ..spec("one-task")
    };
    let e =
        run_witness_execute(Path::new(WORKER), &root, one, &req, w.as_fd(), TIMEOUT).unwrap_err();
    eprintln!("pids.max 1: {e}");
    assert_eq!(
        exit_failure(&e),
        Some(WitnessExecuteFailure::Panicked),
        "{e}"
    );
}

/// The worker restricted itself, seen from outside while it runs: seccomp in filter mode, no new
/// privileges, an environment nobody can read, and its threads; and it never touches HOME, even
/// when it has one (the launcher gives it none).
#[test]
fn the_running_worker_is_restricted_and_never_touches_home() {
    let test = "the_running_worker_is_restricted_and_never_touches_home";
    let Some(root) = delegated(test) else { return };
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let (w, req) = job(dir.path(), &u32::MAX.to_le_bytes(), &[], &[20], [1; 32]);
    let cg = Cgroup::create(&root, &spec("inspect")).unwrap();
    let mut cmd = Command::new(WORKER);
    cmd.arg(WITNESS_EXECUTE_ARG)
        .env_clear()
        // Everything a worker that wanted the key would need to find one.
        .env("HOME", home.path())
        .env("RUST_LOG", "debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    prepare_command(&mut cmd, &cg, &[(w.as_fd(), 3)]).unwrap();
    let mut child = cmd.spawn().unwrap();
    drop(cmd);
    let pid = child.id();
    write_message(child.stdin.as_mut().unwrap(), &req).unwrap();
    drop(child.stdin.take());

    // Wait until it is executing (two threads), then look.
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        if field(&s, "Threads:").is_some_and(|t| t == "2") || Instant::now() > deadline {
            break s;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(field(&status, "Seccomp:").as_deref(), Some("2"), "{status}");
    assert_eq!(field(&status, "NoNewPrivs:").as_deref(), Some("1"));
    assert_eq!(field(&status, "Threads:").as_deref(), Some("2"));
    assert!(
        std::fs::read(format!("/proc/{pid}/environ")).is_err(),
        "environ readable"
    );
    let current: u64 = std::fs::read_to_string(cg.path().join("memory.current"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let pids: u64 = std::fs::read_to_string(cg.path().join("pids.current"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    eprintln!(
        "while executing: {pids} tasks, memory.current {} MiB",
        current >> 20
    );

    cg.kill().unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.code().is_none(), "killed: {:?}", out.status);
    cg.remove().unwrap();
    let log = String::from_utf8_lossy(&out.stderr);
    assert!(
        !log.contains("sys_rand key"),
        "it went looking for the key:\n{log}"
    );
    assert_eq!(
        std::fs::read_dir(home.path()).unwrap().count(),
        0,
        "HOME untouched"
    );
}

fn field(status: &str, name: &str) -> Option<String> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
}
