//! The confinement of the processes that run requester guests outside the sandbox profiles, live:
//! the probe binary confines itself as an inline worker does (`confined`), or runs a child under the
//! supervisor as an SP1 worker runs `sp1-gpu-server` (`supervised`), and reports every check.
//!
//! Among them the ways out a guest that escaped its executor in such a worker would try: the
//! session bus (`systemd --user` StartTransientUnit), the Docker socket, systemd-resolved, writes to
//! the home directory (autostart, user units, `environment.d`, `.bashrc`, the provers, the miner's
//! config), signals (by every syscall that sends one) and `/proc` access to the miner (the probe's
//! parent stands in for it), and the kernel surface the filters take away: namespaces (`unshare`,
//! `setns`, `clone` with a `CLONE_NEW*` flag; `clone3` is unimplemented), mounts and the new mount
//! API, `userfaultfd`, `perf_event_open` and file handles, and the host-control calls (modules,
//! `kexec`, `reboot`, the clock, swap, accounting, quotas, the kernel log, port I/O; `personality`
//! only queried); threads and `posix_spawn` still work.
//! Metadata writes (mode, owner, extended attributes, times; by path and through an fd) are
//! refused, but for the supervised server's runner, which its supervisor makes executable; links,
//! renames, removals, directories, symlinks and truncation outside the writable path are refused
//! by Landlock.
//!
//! Needs Landlock ABI >= 6 (else SKIPPED, or a failure with `ZKMINER_SANDBOX_TESTS_REQUIRED=1`); no
//! cgroup, no GPU.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zkminer_witness_sandbox::{landlock_abi, MIN_LANDLOCK_ABI};

const PROBE: &str = env!("CARGO_BIN_EXE_zkminer-witness-sandbox-probe");

fn say(msg: &str) {
    let _ = writeln!(std::io::stderr(), "{msg}");
}

fn landlock_ok(test: &str) -> bool {
    let abi = landlock_abi();
    if abi >= MIN_LANDLOCK_ABI {
        return true;
    }
    if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
        panic!("{test}: Landlock ABI {abi} < {MIN_LANDLOCK_ABI}");
    }
    say(&format!(
        "SKIPPED {test}: Landlock ABI {abi} < {MIN_LANDLOCK_ABI}"
    ));
    false
}

/// A home directory with what an escaped guest would go for.
fn fake_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    for d in [
        ".config/autostart",
        ".config/systemd/user",
        ".config/environment.d",
        ".zkminer/provers",
        ".ssh",
    ] {
        std::fs::create_dir_all(h.join(d)).unwrap();
    }
    for (f, body) in [
        (".bashrc", "# the operator's\n"),
        (".zkminer/provers/zkminer-prove-risc0-cuda", "#!/bin/sh\n"),
        (".zkminer/config.toml", "[chain]\n"),
        (".zkminer/keystore.json", "{\"not\":\"a real key\"}\n"),
        (".ssh/id_ed25519", "not a real key\n"),
    ] {
        std::fs::write(h.join(f), body).unwrap();
    }
    home
}

/// Lines a child prints on stdout, up to and including the first that starts with `until`.
fn read_until(out: &mut impl BufRead, until: &str, log: &mut String) -> bool {
    let mut line = String::new();
    loop {
        line.clear();
        if out.read_line(&mut line).unwrap_or(0) == 0 {
            return false;
        }
        log.push_str(&line);
        if line.starts_with(until) {
            return true;
        }
    }
}

fn failures(log: &str) -> Vec<&str> {
    log.lines()
        .filter(|l| l.starts_with("CHECK ") && l.contains(" FAIL "))
        .collect()
}

fn checked(log: &str, name: &str) -> bool {
    log.lines()
        .any(|l| l.starts_with(&format!("CHECK {name} ok")))
}

/// The namespace, mount and kernel-surface checks both probes run (`kernel_surface_checks`).
const KERNEL_SURFACE: &[&str] = &[
    "unshare_none",
    "unshare_newuser",
    "unshare_newnet",
    "setns",
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "move_mount",
    "open_tree",
    "open_tree_attr",
    "mount_setattr",
    "userfaultfd",
    "perf_event_open",
    "name_to_handle_at",
    "open_by_handle_at",
    "clone_newns",
    "clone_newcgroup",
    "clone_newuts",
    "clone_newipc",
    "clone_newuser",
    "clone_newpid",
    "clone_newnet",
    "clone_newtime",
    "clone3_enosys",
    "thread_after_confinement",
];

/// The host-control calls both probes make (`host_control_checks`), each refused, and
/// `personality`, which may be queried and not changed.
fn host_control_checks() -> Vec<&'static str> {
    let mut v = vec![
        "init_module",
        "finit_module",
        "delete_module",
        "kexec_load",
        "kexec_file_load",
        "reboot",
        "clock_settime",
        "clock_adjtime",
        "settimeofday",
        "adjtimex",
        "swapon",
        "swapoff",
        "acct",
        "quotactl",
        "quotactl_fd",
        "syslog",
        "sethostname",
        "setdomainname",
        "personality_query",
        "personality_change",
    ];
    if cfg!(target_arch = "x86_64") {
        v.extend(["iopl", "ioperm"]);
    }
    v
}

/// Metadata writes (`metadata_checks`), each refused, on a file both probes may write; and the
/// namespace changes outside the writable path that Landlock refuses (`namespace_checks`).
fn metadata_and_namespace_checks() -> Vec<String> {
    let mut v: Vec<&str> = vec![
        "fchmodat",
        "fchmodat2",
        "fchownat",
        "setxattr",
        "lsetxattr",
        "setxattrat",
        "removexattr",
        "lremovexattr",
        "removexattrat",
        "utimensat_path",
        "ioctl_setflags",
        "ioctl_fssetxattr",
        "ioctl_enable_verity",
        "fchmod",
        "fchown",
        "fsetxattr",
        "fremovexattr",
        "futimens",
        "chmod_key",
    ];
    if cfg!(target_arch = "x86_64") {
        v.extend(["chmod", "chown", "lchown", "utime", "utimes", "futimesat"]);
    }
    let mut names: Vec<String> = v.iter().map(|n| format!("meta_{n}")).collect();
    names.push("metadata_unchanged".into());
    for n in [
        "link_into_home",
        "link_out_of_home",
        "symlink_into_home",
        "rename_into_home",
        "rename_out_of_home",
        "unlink_home",
        "rmdir_home",
        "mkdir_home",
        "truncate_home",
    ] {
        names.push(format!("ns_{n}"));
    }
    names
}

/// Signals by every syscall but `kill` (`signal_checks`), and limits, priorities and scheduling
/// (`process_control_checks`), aimed at `who`; leaving the session or process group.
fn signal_checks(who: &str) -> Vec<String> {
    let mut v: Vec<String> = [
        "tgkill",
        "rt_sigqueueinfo",
        "rt_tgsigqueueinfo",
        "pidfd_send_signal",
        "prlimit64",
        "setpriority",
        "ioprio_set",
        "sched_setaffinity",
        "sched_setscheduler",
        "sched_setparam",
        "sched_setattr",
    ]
    .iter()
    .map(|s| format!("{s}_{who}"))
    .collect();
    v.extend(["setsid", "setpgid", "setpriority_self"].map(String::from));
    v
}

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn confined(
    sockets: &str,
    leak: Option<&str>,
    own_server: bool,
) -> (String, Option<i32>, tempfile::TempDir, Option<String>) {
    let home = fake_home();
    let write = tempfile::tempdir().unwrap();
    let sock_dir = tempfile::tempdir().unwrap();
    let listener_path = sock_dir.path().join("l.sock");
    let listener = UnixListener::bind(&listener_path).unwrap();
    let dgram_path = sock_dir.path().join("dgram.sock");
    let dgram = std::os::unix::net::UnixDatagram::bind(&dgram_path).unwrap();
    let mut cmd = Command::new(PROBE);
    cmd.args(["confined", "--sockets", sockets, "--home"])
        .arg(home.path())
        .arg("--write")
        .arg(write.path())
        .args(["--exec", "/usr/bin/env", "--listener"])
        .arg(&listener_path)
        // A pipe or /dev/null, as a worker's stdin is: the harness's own may be a socket, which the
        // confinement would refuse to keep.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(l) = leak {
        cmd.args(["--leak", l]);
    }
    if own_server {
        cmd.arg("--own-server").arg("--dgram").arg(&dgram_path);
    }
    let mut child = Killed(cmd.spawn().unwrap());
    // The `keep` probe connects before it confines itself, and writes once confined.
    let kept = (sockets == "keep" && leak.is_none() && !own_server).then(|| {
        let (mut conn, _) = listener.accept().unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf)
            .map(|_| String::from_utf8_lossy(&buf).into_owned())
            .unwrap_or_default()
    });
    let mut out = BufReader::new(child.0.stdout.take().unwrap());
    let mut log = String::new();
    let done = read_until(&mut out, "CONFINED CHECKS DONE", &mut log);
    if done {
        // The miner (here, the test) can still signal its worker.
        unsafe { libc::kill(child.0.id() as i32, libc::SIGUSR1) };
        let _ = out.read_to_string(&mut log);
    }
    let code = child.0.wait().unwrap().code();
    // Whatever the probe sent at it, nothing reached the test's datagram socket.
    dgram.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 16];
    assert!(
        dgram.recv(&mut buf).is_err(),
        "a datagram reached the test's socket:\n{log}"
    );
    (log, code, home, kept)
}

#[test]
fn a_confined_worker_reaches_no_socket_no_home_and_not_the_miner() {
    if !landlock_ok("a_confined_worker_reaches_no_socket_no_home_and_not_the_miner") {
        return;
    }
    let (log, code, home, _) = confined("none", None, false);
    say(&log);
    assert!(failures(&log).is_empty(), "{:#?}", failures(&log));
    assert!(log.contains("GOT SIGUSR1"), "{log}");
    assert_eq!(code, Some(0), "{log}");
    for name in [
        "capabilities_dropped",
        "confine",
        "pivot_session_bus",
        "pivot_docker",
        "pivot_resolved_varlink",
        "new_connection_to_listener",
        "socket_unix_stream",
        "socket_unix_dgram",
        "socket_inet",
        "write_config_autostart",
        "write_config_systemd_unit",
        "write_environment_d",
        "append_bashrc",
        "overwrite_prover",
        "write_miner_config",
        "read_key",
        "read_ssh_key",
        "write_tmp",
        "write_dev_shm",
        "write_own_dir",
        "signal_parent_0",
        "signal_parent_term",
        "proc_parent_environ",
        "proc_parent_mem",
        "proc_parent_cmdline",
        "proc_parent_status",
        "proc_init_cmdline",
        "read_proc_self_status",
        "read_proc_thread-self_stat",
        "read_proc_cpuinfo",
        "ptrace_parent",
        "old_thread_socket",
        "old_thread_home_write",
        "exec_unnamed",
        "exec_named",
        "spawn_after_confinement",
    ] {
        assert!(checked(&log, name), "{name} not checked:\n{log}");
    }
    for name in KERNEL_SURFACE.iter().copied().chain(host_control_checks()) {
        assert!(checked(&log, name), "{name} not checked:\n{log}");
    }
    for name in signal_checks("parent") {
        assert!(checked(&log, &name), "{name} not checked:\n{log}");
    }
    for name in metadata_and_namespace_checks() {
        assert!(checked(&log, &name), "{name} not checked:\n{log}");
    }
    assert!(checked(&log, "runner_chmod_refused"), "{log}");
    // Nothing was written where it was refused.
    assert!(!home.path().join(".config/autostart/zk.desktop").exists());
    assert!(!home.path().join(".config/thread-was-here").exists());
    assert_eq!(
        std::fs::read_to_string(home.path().join(".bashrc")).unwrap(),
        "# the operator's\n"
    );
    assert!(home.path().join(".config/systemd/user").is_dir());
    assert!(!home.path().join(".config/new-dir").exists());
    assert!(!home.path().join(".config/moved").exists());
    // The pivots this host has were really reachable before: the refusals are the confinement's.
    for l in log.lines().filter(|l| l.starts_with("NOTE before_")) {
        say(l);
    }
}

#[test]
fn a_proving_sp1_worker_keeps_only_its_own_connection() {
    if !landlock_ok("a_proving_sp1_worker_keeps_only_its_own_connection") {
        return;
    }
    // The probe's listener connection: its peer is this test, the probe's parent, which is not a
    // process the probe started. So the confinement must refuse to keep it.
    let (log, code, _home, _) = confined("keep", None, false);
    say(&log);
    assert!(
        log.lines()
            .any(|l| l.starts_with("CHECK confine FAIL") && l.contains("still open")),
        "a connection to a process it did not start is not one to keep:\n{log}"
    );
    assert_eq!(code, Some(1));
}

#[test]
fn a_proving_sp1_worker_keeps_its_connection_to_the_server_it_started() {
    if !landlock_ok("a_proving_sp1_worker_keeps_its_connection_to_the_server_it_started") {
        return;
    }
    let (log, code, _home, _) = confined("keep", None, true);
    say(&log);
    assert!(failures(&log).is_empty(), "{:#?}", failures(&log));
    for name in [
        "confine",
        "kept_connection_usable",
        "own_server_got_it",
        "seqpacket_pair_reaches_only_its_peer",
        "new_connection_to_listener",
        "pivot_session_bus",
        "pivot_docker",
        "socket_unix_stream",
        "write_config_autostart",
        "signal_parent_0",
    ] {
        assert!(checked(&log, name), "{name} not checked:\n{log}");
    }
    assert!(log.contains("OWN SERVER GOT kept"), "{log}");
    assert_eq!(code, Some(0), "{log}");
}

#[test]
fn a_network_socket_left_open_fails_the_confinement() {
    if !landlock_ok("a_network_socket_left_open_fails_the_confinement") {
        return;
    }
    for leak in ["inet", "unix-dgram"] {
        let (log, code, _home, _) = confined("none", Some(leak), false);
        assert!(
            log.lines()
                .any(|l| l.starts_with("CHECK confine FAIL") && l.contains("still open")),
            "{leak}:\n{log}"
        );
        assert_eq!(code, Some(1), "{leak}");
    }
}

fn supervised(
    linger: bool,
) -> (
    Child,
    PathBuf,
    tempfile::TempDir,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    supervised_with(linger, false)
}

fn supervised_with(
    linger: bool,
    affinity: bool,
) -> (
    Child,
    PathBuf,
    tempfile::TempDir,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let home = fake_home();
    let write = tempfile::tempdir().unwrap();
    // Private, as the worker's temporary directory is (the supervisor makes runner files
    // executable only in such a directory).
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(write.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let sock_dir = tempfile::tempdir().unwrap();
    let socket = sock_dir.path().join("server.sock");
    let mut cmd = if linger {
        // Started by a shell that is then killed: the supervisor's starter, as the worker is.
        let mut c = Command::new("/bin/sh");
        c.arg("-c")
            .arg("\"$0\" supervised \"$1\" \"$2\" \"$3\"; echo STARTER-DONE")
            .arg(PROBE)
            .env("ZKMINER_PROBE_LINGER", "1");
        c
    } else {
        let mut c = Command::new(PROBE);
        c.arg("supervised");
        c
    };
    cmd.arg(&socket).arg(home.path()).arg(write.path());
    if affinity {
        cmd.arg("affinity");
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    (cmd.spawn().unwrap(), socket, home, write, sock_dir)
}

fn field(log: &str, key: &str) -> Option<i32> {
    log.lines()
        .find_map(|l| l.strip_prefix(key))
        .and_then(|v| v.trim().parse().ok())
}

#[test]
fn a_supervised_server_listens_until_its_first_connection_and_never_after() {
    if !landlock_ok("a_supervised_server_listens_until_its_first_connection_and_never_after") {
        return;
    }
    let (child, socket, home, _write, _dir) = supervised(false);
    let mut child = Killed(child);
    let mut out = BufReader::new(child.0.stdout.take().unwrap());
    let mut log = String::new();
    assert!(read_until(&mut out, "LISTENING", &mut log), "{log}");
    let mut conn = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut answer = String::new();
    conn.read_to_string(&mut answer).unwrap();
    let _ = out.read_to_string(&mut log);
    let code = child.0.wait().unwrap().code();
    say(&log);
    assert!(answer.ends_with("DONE\n"), "{answer}");
    assert!(failures(&log).is_empty(), "{:#?}\n{log}", failures(&log));
    for name in [
        "pre_accept_seqpacket_socket",
        "pre_accept_inet_refused",
        "pre_accept_dgram_refused",
        "listen",
        "post_accept_socket_unix_stream",
        "post_accept_socket_unix_seqpacket",
        "post_accept_socket_inet",
        "post_accept_listen",
        "post_accept_bind_abstract",
        "post_accept_connect",
        "stream_pair_allowed",
        "dgram_pair_refused",
        "own_listener_refused",
        "signal_supervisor",
        "proc_supervisor_environ",
        "write_config_autostart",
        "write_tmp",
        "stdin_is_dev_null",
        "spawn_own_helper",
        "thread_affinity_own_thread_refused",
    ] {
        assert!(checked(&log, name), "{name} not checked:\n{log}");
    }
    for name in KERNEL_SURFACE.iter().copied().chain(host_control_checks()) {
        assert!(checked(&log, name), "{name} not checked:\n{log}");
    }
    for name in signal_checks("supervisor") {
        assert!(checked(&log, &name), "{name} not checked:\n{log}");
    }
    for name in metadata_and_namespace_checks() {
        assert!(checked(&log, &name), "{name} not checked:\n{log}");
    }
    for name in [
        "runner_made_executable_by_supervisor",
        "other_file_not_made_executable",
        "runner_other_mode_refused",
    ] {
        assert!(checked(&log, name), "{name} not checked:\n{log}");
    }
    for pivot in ["session_bus", "docker", "resolved_varlink"] {
        if log.contains(&format!("pre_accept_connect_{pivot}")) {
            assert!(
                checked(&log, &format!("pre_accept_connect_{pivot}")),
                "{log}"
            );
        }
    }
    assert_eq!(code, Some(0), "{log}");
    assert!(!home.path().join(".config/autostart/zk.desktop").exists());
}

/// The HIP server's confinement (`allow_thread_affinity`) reaches the supervised server's filter:
/// a CPU set for one of its own new threads is allowed, and every other process control is still
/// refused.
#[test]
fn a_supervised_server_allowed_thread_affinity_may_place_its_threads() {
    if !landlock_ok("a_supervised_server_allowed_thread_affinity_may_place_its_threads") {
        return;
    }
    let (child, socket, _home, _write, _dir) = supervised_with(false, true);
    let mut child = Killed(child);
    let mut out = BufReader::new(child.0.stdout.take().unwrap());
    let mut log = String::new();
    assert!(read_until(&mut out, "LISTENING", &mut log), "{log}");
    let mut conn = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut answer = String::new();
    conn.read_to_string(&mut answer).unwrap();
    let _ = out.read_to_string(&mut log);
    let code = child.0.wait().unwrap().code();
    say(&log);
    assert!(answer.ends_with("DONE\n"), "{answer}");
    assert!(failures(&log).is_empty(), "{:#?}\n{log}", failures(&log));
    assert!(
        checked(&log, "thread_affinity_own_thread_allowed"),
        "not checked:\n{log}"
    );
    for name in signal_checks("supervisor") {
        if name != "sched_setaffinity_supervisor" {
            assert!(checked(&log, &name), "{name} not checked:\n{log}");
        }
    }
    assert_eq!(code, Some(0), "{log}");
}

fn alive(pid: i32) -> bool {
    // A zombie no longer runs anything.
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|s| {
            !s.rsplit_once(')')
                .is_some_and(|(_, r)| r.trim_start().starts_with('Z'))
        })
        .unwrap_or(false)
}

#[test]
fn a_supervised_server_ends_with_the_process_that_started_its_supervisor() {
    if !landlock_ok("a_supervised_server_ends_with_the_process_that_started_its_supervisor") {
        return;
    }
    let (child, socket, _home, _write, _dir) = supervised(true);
    let mut starter = Killed(child);
    let mut out = BufReader::new(starter.0.stdout.take().unwrap());
    let mut log = String::new();
    assert!(read_until(&mut out, "LISTENING", &mut log), "{log}");
    let supervisor = field(&log, "SUPERVISOR ").unwrap();
    let server = field(&log, "SERVER ").unwrap();
    let mut conn = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    let mut answer = String::new();
    conn.read_to_string(&mut answer).unwrap();
    assert!(answer.ends_with("DONE\n"), "{answer}");
    assert!(alive(server) && alive(supervisor));
    // The starter (the worker, in production) dies without a word.
    starter.0.kill().unwrap();
    starter.0.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while (alive(server) || alive(supervisor)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!alive(server), "the server outlived its starter");
    assert!(!alive(supervisor), "the supervisor outlived its starter");
    let _ = Path::new(&socket);
}
