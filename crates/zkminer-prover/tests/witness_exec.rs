//! The witness execute launcher's contract and its error classes, against stand-in workers (shell
//! scripts) in a real job cgroup: what the child is given (fds 0-3, an empty environment, its own
//! cgroup), and a timeout, a typed exit, a signal and malformed output as distinct errors. The real
//! worker's runs, an OOM kill included, are in zkminer-prove-risc0's `tests/witness_execute.rs`.
//!
//! Needs a delegated cgroup:
//!
//! ```text
//! systemd-run --user --scope -q -p Delegate=yes -- \
//!     env ZKMINER_SANDBOX_TESTS_REQUIRED=1 cargo test -p zkminer-prover --test witness_exec
//! ```
#![cfg(target_os = "linux")]

use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use zkminer_prover::witness_exec::{
    run_witness_execute, witness_execute_build, CgroupSpec, WitnessExecError,
};
use zkminer_prover_protocol::{WitnessExecuteFailure, WitnessExecuteRequest};
use zkminer_witness_sandbox::{delegated_root, SandboxError};

fn skip(test: &str, reason: &str) {
    if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
        panic!("{test}: sandbox unavailable: {reason}");
    }
    let _ = writeln!(std::io::stderr(), "SKIPPED {test}: {reason}");
}

fn delegated(test: &str) -> Option<PathBuf> {
    match delegated_root() {
        Ok(root) => Some(root),
        Err(e @ SandboxError::NotDelegated { .. }) => {
            skip(test, &e.to_string());
            None
        }
        Err(e) => panic!("{test}: delegated_root: {e}"),
    }
}

/// A stand-in worker: `body` as a `/bin/sh` script (no PATH: absolute paths only).
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn request() -> WitnessExecuteRequest {
    WitnessExecuteRequest {
        elf: vec![0x7f; 100_000],
        prefix: vec![],
        w_len: 5,
        input_sha256: [0; 32],
        sys_rand_seed: [0; 32],
        po2s: vec![20],
        keccak_po2: 17,
        max_cycles: None,
    }
}

fn spec(name: &str) -> CgroupSpec {
    CgroupSpec {
        name: format!("wexec-launcher-{name}-{}", std::process::id()),
        memory_max: 64 << 20,
        pids_max: 16,
        cpu_max: None,
        cpu_weight: 50,
    }
}

fn run(root: &Path, binary: &Path, name: &str, timeout: Duration) -> (WitnessExecError, Duration) {
    let dir = tempfile::tempdir().unwrap();
    let w_path = dir.path().join("w.bin");
    std::fs::write(&w_path, b"hello").unwrap();
    let w = std::fs::File::open(&w_path).unwrap();
    let started = Instant::now();
    let err = run_witness_execute(binary, root, spec(name), &request(), w.as_fd(), timeout)
        .expect_err("a stand-in never answers");
    (err, started.elapsed())
}

#[test]
fn the_child_gets_fds_0_to_3_an_empty_environment_and_its_own_cgroup() {
    let test = "the_child_gets_fds_0_to_3_an_empty_environment_and_its_own_cgroup";
    let Some(root) = delegated(test) else { return };
    let dir = tempfile::tempdir().unwrap();
    // Reports what it was given on stderr (the log), and last becomes `ls`, which lists the fds it
    // inherited (the shell keeps its own, the script's among them, at 10 and up) plus its own
    // directory fd, the lowest free one. It writes nothing to stdout.
    let worker = script(
        dir.path(),
        "report",
        "echo \"args:$*\" >&2\n\
         echo env-begin >&2; /usr/bin/env >&2; echo env-end >&2\n\
         /bin/cat /proc/$$/cgroup >&2\n\
         echo \"w:$(/bin/cat <&3)\" >&2\n\
         echo fds-begin >&2\n\
         exec /bin/ls /proc/self/fd >&2",
    );
    std::env::set_var("ZKMINER_LAUNCHER_TEST_SECRET", "must-not-leak");
    let (err, _) = run(&root, &worker, "report", Duration::from_secs(30));
    let WitnessExecError::MalformedOutput { log_tail, .. } = &err else {
        panic!("{err}")
    };
    assert!(log_tail.contains("args:--witness-execute"), "{log_tail}");
    // Exactly 0-3, and `ls`'s own fd 4: none of the launcher's other descriptors.
    let mut fds: Vec<u32> = log_tail
        .lines()
        .skip_while(|l| *l != "fds-begin")
        .skip(1)
        .map_while(|l| l.parse().ok())
        .collect();
    fds.sort_unstable();
    assert_eq!(fds, [0, 1, 2, 3, 4], "{log_tail}");
    let env: Vec<&str> = log_tail
        .lines()
        .skip_while(|l| *l != "env-begin")
        .skip(1)
        .take_while(|l| *l != "env-end")
        .collect();
    assert!(
        env.iter().all(|l| l.starts_with("PWD=")),
        "only what the shell sets itself: {env:?}"
    );
    assert!(!log_tail.contains("must-not-leak"));
    assert!(
        log_tail.contains(&format!("wexec-launcher-report-{}", std::process::id())),
        "{log_tail}"
    );
    assert!(log_tail.contains("w:hello"), "W at fd 3: {log_tail}");
    // The cgroup is gone after the run.
    assert!(!root.join(spec("report").name).exists());
}

/// The build handshake runs the worker with `--witness-execute --build`, an empty environment and no
/// fd 3, in its own cgroup, and takes nothing but one well-formed build frame from it.
#[test]
fn the_build_handshake_asks_with_its_own_argument_and_takes_only_a_frame() {
    let test = "the_build_handshake_asks_with_its_own_argument_and_takes_only_a_frame";
    let Some(root) = delegated(test) else { return };
    let dir = tempfile::tempdir().unwrap();
    // Exit 0 (no frame) only when asked exactly so, with nothing at fd 3 and no environment (but the
    // PWD the shell sets itself).
    let worker = script(
        dir.path(),
        "asked",
        "[ \"$1\" = --witness-execute ] && [ \"$2\" = --build ] && [ ! -e /proc/self/fd/3 ] \
         && [ -z \"$(/usr/bin/env | /bin/grep -v '^PWD=')\" ] || exit 3\nexit 0",
    );
    let err = witness_execute_build(&worker, &root, spec("build-asked"), Duration::from_secs(30))
        .expect_err("a stand-in sends no frame");
    assert!(
        matches!(err, WitnessExecError::MalformedOutput { .. }),
        "{err}"
    );
    assert!(!root.join(spec("build-asked").name).exists());
    // An old worker, which would read a request instead: its typed refusal, not a build.
    let worker = script(dir.path(), "old", "exit 80");
    let err = witness_execute_build(&worker, &root, spec("build-old"), Duration::from_secs(30))
        .expect_err("refused");
    assert!(matches!(err, WitnessExecError::Exit { code: 80, .. }), "{err}");
    let worker = script(dir.path(), "garbage-build", "printf 'not a frame'");
    let err = witness_execute_build(&worker, &root, spec("build-garbage"), Duration::from_secs(30))
        .expect_err("garbage");
    assert!(
        matches!(err, WitnessExecError::MalformedOutput { .. }),
        "{err}"
    );
}

#[test]
fn a_timeout_kills_the_whole_cgroup_promptly() {
    let test = "a_timeout_kills_the_whole_cgroup_promptly";
    let Some(root) = delegated(test) else { return };
    let dir = tempfile::tempdir().unwrap();
    let worker = script(dir.path(), "sleeper", "/bin/sleep 60 & exec /bin/sleep 60");
    let (err, took) = run(&root, &worker, "timeout", Duration::from_secs(1));
    assert!(matches!(err, WitnessExecError::Timeout { .. }), "{err}");
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert!(
        !root.join(spec("timeout").name).exists(),
        "the cgroup, and its background sleep, are gone"
    );
}

#[test]
fn a_signal_an_exit_and_malformed_output_are_their_own_errors() {
    let test = "a_signal_an_exit_and_malformed_output_are_their_own_errors";
    let Some(root) = delegated(test) else { return };
    let dir = tempfile::tempdir().unwrap();
    let worker = script(dir.path(), "killed", "kill -TERM $$");
    let (err, _) = run(&root, &worker, "signal", Duration::from_secs(30));
    assert!(
        matches!(err, WitnessExecError::Signaled { signal: 15, .. }),
        "{err}"
    );

    let worker = script(dir.path(), "garbage", "printf 'not a frame'");
    let (err, _) = run(&root, &worker, "garbage", Duration::from_secs(30));
    assert!(
        matches!(err, WitnessExecError::MalformedOutput { .. }),
        "{err}"
    );

    let worker = script(dir.path(), "silent", "exit 0");
    let (err, _) = run(&root, &worker, "silent", Duration::from_secs(30));
    assert!(
        matches!(err, WitnessExecError::MalformedOutput { .. }),
        "{err}"
    );

    // A typed failure, and an exit code that is none of the worker's.
    let worker = script(dir.path(), "typed", "exit 84");
    let (err, _) = run(&root, &worker, "typed", Duration::from_secs(30));
    assert!(
        matches!(
            err,
            WitnessExecError::Exit {
                code: 84,
                failure: Some(WitnessExecuteFailure::Unprovable),
                ..
            }
        ),
        "{err}"
    );
    let worker = script(dir.path(), "other", "exit 3");
    let (err, _) = run(&root, &worker, "other", Duration::from_secs(30));
    assert!(
        matches!(
            err,
            WitnessExecError::Exit {
                code: 3,
                failure: None,
                ..
            }
        ),
        "{err}"
    );
}
