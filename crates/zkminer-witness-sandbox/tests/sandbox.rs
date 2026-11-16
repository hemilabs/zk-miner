//! End-to-end tests of the rootless sandbox: they spawn the probe binary.
//!
//! The tests that need cgroups must run inside a delegated cgroup, e.g.
//!
//! ```text
//! systemd-run --user --scope -q -p Delegate=yes -- \
//!     cargo test -p zkminer-witness-sandbox -- --test-threads=1
//! ```
//!
//! Elsewhere they print `SKIPPED <test>: <reason>` to stderr (uncaptured) and return; set
//! `ZKMINER_SANDBOX_TESTS_REQUIRED=1` to make them fail instead, and
//! `ZKMINER_SANDBOX_TESTS_VERBOSE=1` to print every check.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zkminer_witness_sandbox::{
    delegated_root, landlock_abi, prepare_command, self_test, self_test_profile, Cgroup,
    CgroupSpec, Profile, SandboxError, SandboxMode, SelfTestReport, MIN_LANDLOCK_ABI,
};

const PROBE: &str = env!("CARGO_BIN_EXE_zkminer-witness-sandbox-probe");

/// Written straight to fd 2: libtest captures `eprintln!`, not the raw handle.
fn say(msg: &str) {
    let _ = writeln!(std::io::stderr(), "{msg}");
}

/// Skips (or, with ZKMINER_SANDBOX_TESTS_REQUIRED set, fails) `test` when the host cannot run it.
fn skip(test: &str, reason: &str) {
    if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
        panic!("{test}: sandbox unavailable: {reason}");
    }
    say(&format!("SKIPPED {test}: {reason}"));
}

fn landlock_ok(test: &str) -> bool {
    let abi = landlock_abi();
    if abi < MIN_LANDLOCK_ABI {
        skip(test, &format!("Landlock ABI {abi} < {MIN_LANDLOCK_ABI}"));
        return false;
    }
    true
}

/// The delegated root, or `None` after printing SKIPPED.
fn delegated(test: &str) -> Option<PathBuf> {
    if !landlock_ok(test) {
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

fn secret() -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(b"zkminer sandbox test secret, not a real one\n")
        .unwrap();
    f
}

fn assert_passed(test: &str, report: &SelfTestReport) {
    let failures: Vec<_> = report.failures().collect();
    if !failures.is_empty() || std::env::var_os("ZKMINER_SANDBOX_TESTS_VERBOSE").is_some() {
        for c in &report.checks {
            say(&format!(
                "  {} {} {}",
                if c.passed { "PASS" } else { "FAIL" },
                c.name,
                c.detail
            ));
        }
    }
    assert!(
        report.passed(),
        "{test}: {} failed checks: {failures:#?}",
        failures.len()
    );
    say(&format!("{test}: {} checks passed", report.checks.len()));
}

fn names(report: &SelfTestReport) -> Vec<&str> {
    report.checks.iter().map(|c| c.name.as_str()).collect()
}

#[test]
fn builder_runner_self_test() {
    let test = "builder_runner_self_test";
    if delegated(test).is_none() {
        return;
    }
    let s = secret();
    let report = self_test_profile(
        SandboxMode::Rootless,
        &Profile::BuilderRunner,
        Path::new(PROBE),
        s.path(),
    );
    assert_passed(test, &report);
    let n = names(&report);
    for c in [
        "builder_runner/status_seccomp",
        "builder_runner/status_no_new_privs",
        "builder_runner/in_job_cgroup",
        "builder_runner/read_secret",
        "builder_runner/socket_inet",
        "builder_runner/kill_parent",
        "builder_runner/oom_kill",
        "builder_runner/pids_max",
        "builder_runner/probe_output",
    ] {
        assert!(n.contains(&c), "missing {c}");
    }
}

#[test]
fn execute_worker_self_test() {
    let test = "execute_worker_self_test";
    if delegated(test).is_none() {
        return;
    }
    let s = secret();
    let report = self_test_profile(
        SandboxMode::Rootless,
        &Profile::ExecuteWorker,
        Path::new(PROBE),
        s.path(),
    );
    assert_passed(test, &report);
    assert!(names(&report).contains(&"execute_worker/seccomp_denylist"));
}

#[test]
fn broker_self_test() {
    let test = "broker_self_test";
    if delegated(test).is_none() {
        return;
    }
    let s = secret();
    let dir = tempfile::tempdir().unwrap();
    let endpoints = dir.path().join("endpoints.toml");
    std::fs::write(&endpoints, "[evm-rpc]\n").unwrap();
    let spool = dir.path().join("spool");
    std::fs::create_dir(&spool).unwrap();
    let profile = Profile::Broker {
        readable: vec![endpoints],
        writable: vec![spool],
        tcp_connect_ports: vec![443],
    };
    let report = self_test_profile(SandboxMode::Rootless, &profile, Path::new(PROBE), s.path());
    assert_passed(test, &report);
    let n = names(&report);
    for c in [
        "broker/socket_inet_allowed",
        "broker/tcp_connect_allowed_port",
        "broker/tcp_connect_denied_port",
        "broker/socket_unix",
        "broker/abstract_unix_connect",
        "broker/read_readable",
        "broker/write_writable",
        "broker/read_secret",
    ] {
        assert!(n.contains(&c), "missing {c}");
    }
}

#[test]
fn full_self_test() {
    let test = "full_self_test";
    if delegated(test).is_none() {
        return;
    }
    let s = secret();
    let report = self_test(SandboxMode::Rootless, Path::new(PROBE), s.path());
    assert_passed(test, &report);
    for p in ["builder_runner/", "execute_worker/", "broker/"] {
        assert!(
            report.checks.iter().any(|c| c.name.starts_with(p)),
            "no {p} checks"
        );
    }
}

#[test]
fn system_mode_is_not_implemented() {
    let s = secret();
    let report = self_test(SandboxMode::System, Path::new(PROBE), s.path());
    assert!(!report.passed());
    assert_eq!(names(&report), vec!["system_mode"]);
}

/// Negative control: the same checks, with `restrict_self` skipped, must fail. Otherwise a passing
/// self-test would prove nothing. Needs no cgroup.
#[test]
fn checks_fail_without_the_sandbox() {
    if !landlock_ok("checks_fail_without_the_sandbox") {
        return;
    }
    let s = secret();
    let out = Command::new(PROBE)
        .args([
            "checks",
            "--profile",
            "builder_runner",
            "--unrestricted",
            "1",
            "--listen-port",
            "9",
            "--abstract",
            "zkminer-test-nonexistent",
            "--secret",
        ])
        .arg(s.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("\nDONE "), "{text}");
    // Not properties of restrict_self (inherited_fds), or kernel-dependent (x32 may be absent).
    let exempt = ["inherited_fds", "x32_syscall"];
    let mut checked = 0;
    for line in text.lines().filter_map(|l| l.strip_prefix("CHECK ")) {
        let mut it = line.splitn(3, ' ');
        let (name, verdict) = (it.next().unwrap(), it.next().unwrap());
        if exempt.contains(&name) {
            continue;
        }
        assert_eq!(verdict, "FAIL", "{name} passes without any sandbox: {line}");
        checked += 1;
    }
    assert!(checked >= 25, "only {checked} checks: {text}");
}

#[test]
fn restrict_self_refuses_a_multithreaded_process() {
    if !landlock_ok("restrict_self_refuses_a_multithreaded_process") {
        return;
    }
    let out = Command::new(PROBE)
        .args(["threaded", "--profile", "builder_runner"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("THREADED restrict_self must run before the process starts threads"),
        "{text}"
    );
}

#[test]
fn delegated_root_is_idempotent() {
    let test = "delegated_root_is_idempotent";
    let Some(first) = delegated(test) else { return };
    assert_eq!(delegated_root().unwrap(), first);
    assert!(first.ends_with("sandboxes"));
    // This process now lives in the sibling `supervisor` cgroup.
    let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
    assert!(own.trim_end().ends_with("/supervisor"), "{own}");
    let parent = first.parent().unwrap();
    assert!(std::fs::read_to_string(parent.join("cgroup.procs"))
        .unwrap()
        .trim()
        .is_empty());
    let ctl = std::fs::read_to_string(first.join("cgroup.subtree_control")).unwrap();
    for c in ["cpu", "memory", "pids"] {
        assert!(ctl.split_whitespace().any(|x| x == c), "{ctl}");
    }
}

#[test]
fn cgroup_names_and_duplicates() {
    let test = "cgroup_names_and_duplicates";
    let Some(root) = delegated(test) else { return };
    let spec = |name: &str| CgroupSpec {
        name: name.into(),
        memory_max: 64 << 20,
        pids_max: 8,
        cpu_max: Some((50_000, 100_000)),
        cpu_weight: 10,
    };
    for bad in ["../escape", "a/b", ".", "..", ""] {
        assert!(
            matches!(
                Cgroup::create(&root, &spec(bad)),
                Err(SandboxError::InvalidArgument(_))
            ),
            "{bad:?}"
        );
    }
    let name = format!("test-dup-{}", std::process::id());
    let cg = Cgroup::create(&root, &spec(&name)).unwrap();
    assert!(
        Cgroup::create(&root, &spec(&name)).is_err(),
        "a second cgroup with the same name"
    );
    assert_eq!(
        std::fs::read_to_string(cg.path().join("memory.swap.max"))
            .unwrap()
            .trim(),
        "0"
    );
    assert!(!cg.oom_killed());
    let path = cg.path().to_path_buf();
    drop(cg); // Drop removes it too.
    assert!(!path.exists());
}

fn identity(fd: RawFd) -> (u64, u64) {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    assert_eq!(unsafe { libc::fstat(fd, st.as_mut_ptr()) }, 0);
    let st = unsafe { st.assume_init() };
    (st.st_dev, st.st_ino)
}

/// A pipe's read end at exactly `fd` (which must be free), close-on-exec.
fn pipe_at(fd: RawFd) -> (OwnedFd, OwnedFd) {
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) },
        -1,
        "fd {fd} already in use"
    );
    let (r, w) = std::io::pipe().unwrap();
    let r: OwnedFd = r.into();
    assert_eq!(
        unsafe { libc::dup3(r.as_raw_fd(), fd, libc::O_CLOEXEC) },
        fd
    );
    (unsafe { OwnedFd::from_raw_fd(fd) }, w.into())
}

/// The hook end to end with real fds: a swap (600 <-> 601), a move to 3, an inheritable fd that
/// must not leak, the job cgroup joined before exec, and `remove` killing a live child.
#[test]
fn prepare_command_places_fds_and_joins_cgroup() {
    let test = "prepare_command_places_fds_and_joins_cgroup";
    let Some(root) = delegated(test) else { return };
    let spec = CgroupSpec {
        name: format!("test-fds-{}", std::process::id()),
        memory_max: 128 << 20,
        pids_max: 8,
        cpu_max: None,
        cpu_weight: 10,
    };
    let cg = Cgroup::create(&root, &spec).unwrap();

    let (a, _aw) = pipe_at(600);
    let (b, _bw) = pipe_at(601);
    let (c, _cw) = std::io::pipe().unwrap();
    let c: OwnedFd = c.into();
    // Inheritable (no CLOEXEC), like an fd some library leaked.
    let mut leak = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(leak.as_mut_ptr(), 0) }, 0);
    let leak = unsafe { (OwnedFd::from_raw_fd(leak[0]), OwnedFd::from_raw_fd(leak[1])) };

    let want = [
        (601, identity(a.as_raw_fd())),
        (600, identity(b.as_raw_fd())),
        (3, identity(c.as_raw_fd())),
    ];
    let mut cmd = Command::new(PROBE);
    cmd.args(["fds", "--profile", "builder_runner"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    prepare_command(
        &mut cmd,
        &cg,
        &[(a.as_fd(), 601), (b.as_fd(), 600), (c.as_fd(), 3)],
    )
    .unwrap();
    let mut child = cmd.spawn().unwrap();
    drop(cmd);

    let mut fds = Vec::new();
    let mut cgroup_line = String::new();
    for line in BufReader::new(child.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        if line == "DONE" {
            break;
        }
        if let Some(rest) = line.strip_prefix("FD ") {
            let v: Vec<u64> = rest.split(' ').map(|x| x.parse().unwrap()).collect();
            fds.push((v[0] as RawFd, (v[1], v[2])));
        } else if let Some(rest) = line.strip_prefix("CGROUP ") {
            cgroup_line = rest.to_string();
        }
    }
    let numbers: Vec<RawFd> = fds.iter().map(|(n, _)| *n).collect();
    assert_eq!(numbers, vec![0, 1, 2, 3, 600, 601], "{fds:?}");
    for (n, id) in want {
        assert!(fds.contains(&(n, id)), "fd {n} should be {id:?}: {fds:?}");
    }
    assert!(
        cgroup_line.ends_with(&format!("/sandboxes/{}", spec.name)),
        "{cgroup_line}"
    );
    drop(leak);

    // The probe now blocks on stdin; remove() must kill it.
    assert!(cg.populated().unwrap());
    cg.remove().unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
}

#[test]
fn prepare_command_rejects_bad_targets() {
    let test = "prepare_command_rejects_bad_targets";
    let Some(root) = delegated(test) else { return };
    let spec = CgroupSpec {
        name: format!("test-badfd-{}", std::process::id()),
        memory_max: 64 << 20,
        pids_max: 4,
        cpu_max: None,
        cpu_weight: 10,
    };
    let cg = Cgroup::create(&root, &spec).unwrap();
    let (r, _w) = std::io::pipe().unwrap();
    let mut cmd = Command::new(PROBE);
    for target in [0, 2, 1024] {
        assert!(matches!(
            prepare_command(&mut cmd, &cg, &[(r.as_fd(), target)]),
            Err(SandboxError::InvalidArgument(_))
        ));
    }
    assert!(prepare_command(&mut cmd, &cg, &[(r.as_fd(), 3), (r.as_fd(), 3)]).is_err());
    cg.remove().unwrap();
}
