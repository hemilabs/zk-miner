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
use std::os::linux::net::SocketAddrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zkminer_witness_sandbox::probe::{
    expected_checks, ProbeArgs, ProfileKind, POSITIVE_CHECKS, UNSANDBOXED_EXEMPT,
};
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
        "builder_runner/sysv_shmget",
        "builder_runner/sysv_msgget",
        "builder_runner/sysv_semget",
        "builder_runner/fchmod_inherited",
        "builder_runner/fchown_inherited",
        "builder_runner/fsetxattr_inherited",
        "builder_runner/fremovexattr_inherited",
        "builder_runner/flock_inherited",
        "builder_runner/fcntl_setlease_inherited",
        "builder_runner/fcntl_notify_dir",
        "builder_runner/file_getattr_inherited",
        "builder_runner/file_setattr_inherited",
        "builder_runner/ioctl_setflags_inherited",
        "builder_runner/prctl_set_dumpable",
        "builder_runner/prctl_set_ptracer",
        "builder_runner/ptrace_attach_child",
        "builder_runner/process_vm_readv_child",
        "builder_runner/inherited_file_unchanged",
    ] {
        assert!(n.contains(&c), "missing {c}");
    }
    // Review r1 broker F3 (PoC `meta`), inverted: nothing about the host is readable without
    // opening a file, and the runner starts in `/`.
    for c in METADATA {
        assert!(
            n.contains(&format!("builder_runner/{c}").as_str()),
            "missing {c}"
        );
    }
}

/// The host-metadata checks every runner and worker self-test reports (and passes).
const METADATA: &[&str] = &[
    "cwd_root",
    "uname",
    "sysinfo",
    "readlinkat_proc_self_exe",
    "faccessat_root",
    "faccessat2_root",
    "statfs_root",
    "fstatfs_inherited",
    "getxattr_root",
    "listxattr_root",
    "fgetxattr_inherited",
    "statx_enosys",
    "listmount",
    "statmount",
    "lsm_list_modules",
    "lsm_get_self_attr",
    "chdir",
    "fchdir",
];

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
    let n = names(&report);
    assert!(n.contains(&"execute_worker/seccomp_denylist"));
    for c in METADATA {
        assert!(
            n.contains(&format!("execute_worker/{c}").as_str()),
            "missing {c}"
        );
    }
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
    };
    let report = self_test_profile(SandboxMode::Rootless, &profile, Path::new(PROBE), s.path());
    assert_passed(test, &report);
    let n = names(&report);
    for c in [
        "broker/socket_inet",
        "broker/socket_inet6",
        "broker/tcp_connect_loopback",
        "broker/connect_syscall",
        "broker/listen_syscall",
        "broker/accept_syscall",
        "broker/reconnect_inherited_tcp",
        "broker/fastopen_inherited_tcp",
        "broker/seal_socket_creation",
        "broker/listeners_untouched",
        "broker/getsid_parent",
        "broker/socket_unix",
        "broker/abstract_unix_connect",
        "broker/read_readable",
        "broker/write_writable",
        "broker/read_secret",
        "broker/socket_inet_tcp",
        "broker/socket_udp",
        "broker/socket_mptcp",
        "broker/socket_icmp",
        "broker/socket_raw",
        "broker/socketpair_unix_stream_allowed",
        "broker/socketpair_unix_dgram",
        "broker/socketpair_unix_seqpacket",
        "broker/sysv_shmget",
        "broker/fchmod_inherited",
        "broker/prctl_set_dumpable",
        "broker/inherited_file_unchanged",
    ] {
        assert!(n.contains(&c), "missing {c}");
    }
    // The broker keeps them (it reads its spool).
    for c in METADATA {
        assert!(!n.contains(&format!("broker/{c}").as_str()), "{c}");
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

/// Owned SysV objects of this uid, from `/proc/sysvipc/{shm,msg,sem}` (the negative control's
/// probe creates and removes one of each).
fn sysv_objects() -> usize {
    let uid = unsafe { libc::geteuid() }.to_string();
    ["shm", "msg", "sem"]
        .iter()
        .map(|t| {
            let text = std::fs::read_to_string(format!("/proc/sysvipc/{t}")).unwrap_or_default();
            let header: Vec<&str> = text
                .lines()
                .next()
                .unwrap_or("")
                .split_whitespace()
                .collect();
            let col = header
                .iter()
                .position(|h| *h == "cuid")
                .expect("cuid column");
            text.lines()
                .skip(1)
                .filter(|l| l.split_whitespace().nth(col) == Some(uid.as_str()))
                .count()
        })
        .sum()
}

/// Negative control: the same checks, with `restrict_self` skipped, must fail — for every profile.
/// Otherwise a passing self-test would prove nothing. Every check runs its real logic here (no
/// argument is missing, nothing is skipped but `restrict_self` itself): checks of operations the
/// profile allows must pass, the few in `UNSANDBOXED_EXEMPT` (which an unprivileged process cannot
/// tell from the sandbox) are only reported. Needs no cgroup.
#[test]
fn checks_fail_without_the_sandbox() {
    if !landlock_ok("checks_fail_without_the_sandbox") {
        return;
    }
    for kind in [
        ProfileKind::BuilderRunner,
        ProfileKind::ExecuteWorker,
        ProfileKind::Broker,
    ] {
        negative_control(kind);
    }
}

fn negative_control(kind: ProfileKind) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    let label = kind.label();
    let s = secret();
    let dir = tempfile::tempdir().unwrap();
    // Everything the checks reach for exists and answers, so a check fails because the operation
    // worked, not because its target was missing.
    let listen = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let deny = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let abstract_name = format!("zkminer-negative-{}-{label}", std::process::id());
    let addr =
        std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes()).unwrap();
    let _unix = std::os::unix::net::UnixListener::bind_addr(&addr).unwrap();
    let meta_path = dir.path().join("w");
    std::fs::write(&meta_path, b"inherited\n").unwrap();
    std::fs::set_permissions(&meta_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let meta = std::fs::File::open(&meta_path).unwrap();

    let mut a = ProbeArgs::new(kind);
    a.unrestricted = true;
    a.secret = Some(s.path().to_path_buf());
    a.listen_port = Some(listen.local_addr().unwrap().port());
    a.deny_port = Some(deny.local_addr().unwrap().port());
    a.abstract_name = Some(abstract_name);
    a.meta_fd = Some(5);
    a.expect_fds = vec![0, 1, 2, 5];
    a.tag = format!("negative-{}-{label}", std::process::id());
    if kind == ProfileKind::Broker {
        let endpoints = dir.path().join("endpoints.toml");
        std::fs::write(&endpoints, "# test\n").unwrap();
        let spool = dir.path().join("spool");
        std::fs::create_dir(&spool).unwrap();
        a.readable = vec![endpoints];
        a.writable = vec![spool];
    }
    let sysv_before = sysv_objects();
    let mut cmd = Command::new(PROBE);
    cmd.args(a.to_args("checks"))
        .env_clear()
        .stdin(Stdio::null());
    let raw = meta.as_raw_fd();
    // SAFETY: dup2/fcntl only, between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if raw == 5 {
                if libc::fcntl(5, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(raw, 5) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("\nDONE "), "{label}: {text}");

    let mut seen = Vec::new();
    let mut failed_as_expected = 0;
    for line in text.lines().filter_map(|l| l.strip_prefix("CHECK ")) {
        let mut it = line.splitn(3, ' ');
        let (name, verdict, detail) = (
            it.next().unwrap(),
            it.next().unwrap(),
            it.next().unwrap_or(""),
        );
        seen.push(name.to_string());
        assert!(
            !detail.contains("missing --"),
            "{label}/{name} did not run: {line}"
        );
        assert!(
            name == "restrict_self" || !detail.starts_with("skipped"),
            "{label}/{name} was skipped: {line}"
        );
        if let Some((_, why)) = UNSANDBOXED_EXEMPT.iter().find(|(n, _)| *n == name) {
            say(&format!(
                "  {label}/{name} {verdict} (exempt: {why}): {detail}"
            ));
            continue;
        }
        if POSITIVE_CHECKS.contains(&name) {
            assert_eq!(
                verdict, "PASS",
                "{label}/{name}: an allowed operation fails without any sandbox: {line}"
            );
        } else {
            assert_eq!(
                verdict, "FAIL",
                "{label}/{name} passes without any sandbox: {line}"
            );
            failed_as_expected += 1;
        }
    }
    for c in expected_checks(kind) {
        assert!(
            seen.iter().any(|s| s == c),
            "{label}: {c} not printed: {text}"
        );
    }
    let want = expected_checks(kind).len()
        - POSITIVE_CHECKS
            .iter()
            .filter(|c| expected_checks(kind).contains(c))
            .count()
        - UNSANDBOXED_EXEMPT
            .iter()
            .filter(|(c, _)| expected_checks(kind).contains(c))
            .count();
    assert_eq!(failed_as_expected, want, "{label}: {text}");
    // What the unrestricted probe did to the parent's things, it undid.
    let m = std::fs::metadata(&meta_path).unwrap();
    assert_eq!(
        m.mode() & 0o7777,
        0o640,
        "{label}: the inherited file's mode changed"
    );
    assert_eq!(
        sysv_objects(),
        sysv_before,
        "{label}: SysV objects left behind"
    );
    say(&format!("checks_fail_without_the_sandbox: {label}: {failed_as_expected} denial checks fail unsandboxed"));
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
        .stdout(Stdio::piped())
        .env("ZKMINER_PROBE_BEFORE", "1");
    prepare_command(
        &mut cmd,
        &cg,
        &[(a.as_fd(), 601), (b.as_fd(), 600), (c.as_fd(), 3)],
    )
    .unwrap();
    cmd.env("ZKMINER_PROBE_AFTER", "2");
    // The test process's own environment (PATH, HOME, CARGO_*, ...) must not reach the child.
    assert!(std::env::vars_os().count() > 0);
    let mut child = cmd.spawn().unwrap();
    drop(cmd);

    let mut fds = Vec::new();
    let mut env = Vec::new();
    let mut cgroup_line = String::new();
    for line in BufReader::new(child.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        if line == "DONE" {
            break;
        }
        if let Some(rest) = line.strip_prefix("ENV ") {
            env.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("FD ") {
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
    // Only what was set on the Command, before or after prepare_command.
    env.sort();
    assert_eq!(env, vec!["ZKMINER_PROBE_AFTER", "ZKMINER_PROBE_BEFORE"]);
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

/// Review L2: with fd 0, 1 or 2 closed in the parent, opening `cgroup.procs` returns that number,
/// and std puts the child's stdin/stdout/stderr there before the hook writes "0" to it: the child
/// stayed in the miner's cgroup, uncapped (the "0" went to /dev/null or the stdout pipe).
/// `prepare_command` must keep the fd above 2. The parent's stdio is restored right after
/// `prepare_command` (nothing may print meanwhile), which with the old code also replaced the
/// procs fd itself, so the old code fails this test either way.
///
/// It closes this process's stdio for a moment, so any fd another test opens meanwhile lands on
/// 0-2 and is clobbered when stdio comes back (which made `prepare_command_places_fds_and_joins_cgroup`
/// fail with EBADF, and this test's own `dup`, now and then). So its body runs in a child test
/// process of its own, alone.
#[test]
fn prepare_command_survives_closed_stdio() {
    const CHILD: &str = "ZKMINER_SANDBOX_TEST_STDIO_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return closed_stdio_body();
    }
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "prepare_command_survives_closed_stdio",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    assert!(text.contains("1 passed"), "{text}");
    for line in text.lines().filter(|l| l.contains("SKIPPED")) {
        say(line);
    }
}

fn closed_stdio_body() {
    let test = "prepare_command_survives_closed_stdio";
    let Some(root) = delegated(test) else { return };
    for closed in [&[0][..], &[1], &[2], &[0, 1, 2]] {
        let tag: String = closed.iter().map(|f| f.to_string()).collect();
        let spec = CgroupSpec {
            name: format!("test-stdio-{}-{tag}", std::process::id()),
            memory_max: 64 << 20,
            pids_max: 8,
            cpu_max: None,
            cpu_weight: 10,
        };
        let cg = Cgroup::create(&root, &spec).unwrap();
        let mut cmd = Command::new(PROBE);
        cmd.args(["fds", "--profile", "builder_runner"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // SAFETY: dup/close/dup2 of this process's stdio, restored before anything else runs.
        let saved: Vec<(RawFd, RawFd)> = closed
            .iter()
            .map(|&fd| (fd, unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 100) }))
            .collect();
        for &(fd, copy) in &saved {
            assert!(copy >= 100);
            unsafe { libc::close(fd) };
        }
        let prepared = prepare_command(&mut cmd, &cg, &[]);
        for &(fd, copy) in &saved {
            unsafe {
                libc::dup2(copy, fd);
                libc::close(copy);
            }
        }
        prepared.unwrap();
        let out = cmd.output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "stdio {closed:?} closed: {:?} {text}",
            out.status
        );
        let cgroup_line = text
            .lines()
            .find_map(|l| l.strip_prefix("CGROUP "))
            .unwrap_or("");
        assert!(
            cgroup_line.ends_with(&format!("/sandboxes/{}", spec.name)),
            "stdio {closed:?} closed while preparing: the child ran in {cgroup_line:?}"
        );
        assert!(
            text.starts_with("FD 0 "),
            "stdio {closed:?}: stray bytes on stdout: {text:?}"
        );
        cg.remove().unwrap();
    }
}

/// Review L5: a user scope *without* `Delegate=yes` is owned by this uid as well (the user manager
/// runs as the user), so ownership proves nothing; `delegated_root` must ask systemd, refuse, and
/// change nothing.
#[test]
fn delegated_root_refuses_a_scope_without_delegate() {
    let test = "delegated_root_refuses_a_scope_without_delegate";
    if delegated(test).is_none() {
        return;
    }
    let out = match Command::new("systemd-run")
        .args(["--user", "--scope", "-q", "--"])
        .arg(PROBE)
        .args(["delegation", "--profile", "builder_runner"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            skip(
                test,
                &format!(
                    "systemd-run --user --scope: {:?} {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr)
                ),
            );
            return;
        }
        Err(e) => {
            skip(test, &format!("systemd-run: {e}"));
            return;
        }
    };
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("DELEGATION not_delegated"), "{text}");
    assert!(
        text.contains("Delegate=\"no\""),
        "refused by systemd's answer: {text}"
    );
    assert!(
        text.contains("SUPERVISOR false"),
        "a refusal changed the cgroup: {text}"
    );
}
