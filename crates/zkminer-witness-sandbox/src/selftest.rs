//! Parent side of the self-test (plan §10.3): spawns the probe in each sandbox and checks the
//! resulting properties from both sides.

use std::io::Read;
use std::net::TcpListener;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::cgroup::{cgroup2_mount, parse_keyed};
use crate::probe::{expected_checks, ProbeArgs, ProfileKind};
use crate::{
    delegated_root, prepare_command, Cgroup, CgroupSpec, Check, Profile, SandboxMode,
    SelfTestReport,
};

const MIB: u64 = 1 << 20;
/// The probe's fd layout: a ready pipe and a go pipe, like the runner's fixed fds, and a read-only
/// fd of a file the parent owns (like the execute worker's W file).
const READY_FD: i32 = 3;
const GO_FD: i32 = 4;
const META_FD: i32 = 5;
/// The inherited file's mode, which must survive the probe.
const META_MODE: u32 = 0o640;
const META_XATTR: &str = "user.zkminer-probe";
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);
const READY_TIMEOUT: Duration = Duration::from_secs(20);

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique(purpose: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("selftest-{}-{n}-{purpose}", std::process::id())
}

struct Recorder {
    label: &'static str,
    checks: Vec<Check>,
}

impl Recorder {
    fn check(&mut self, name: &str, passed: bool, detail: impl Into<String>) {
        self.checks.push(Check {
            name: format!("{}/{name}", self.label),
            passed,
            detail: detail.into(),
        });
    }
}

fn system_mode_unavailable(mode: SandboxMode) -> SelfTestReport {
    SelfTestReport {
        mode,
        checks: vec![Check {
            name: "system_mode".into(),
            passed: false,
            detail: "the system sandbox mode (namespaces, a separate uid, an nftables floor) needs root \
                     (`zkminer witness setup`) and is not implemented on this host; use \
                     sandbox_mode = \"rootless\""
                .into(),
        }],
    }
}

/// Runs the self-test (plan §10.3) for every profile: the builder runner, the execute worker, and
/// a broker profile with a private read-only endpoints file and spool directory (created in the
/// system temp dir and removed afterwards). See [`self_test_profile`] for what is checked.
///
/// `probe_binary` is the `zkminer-witness-sandbox-probe` binary; `secret_path` is an existing file
/// this process can read and no sandbox may (in production `~/.zkminer/config.toml`). The miner
/// must be in a delegated cgroup ([`delegated_root`]); otherwise the report fails with a
/// `cgroup_delegated` check. [`SandboxMode::System`] yields a single failed `system_mode` check.
pub fn self_test(mode: SandboxMode, probe_binary: &Path, secret_path: &Path) -> SelfTestReport {
    if mode == SandboxMode::System {
        return system_mode_unavailable(mode);
    }
    let mut checks = Vec::new();
    for kind in [ProfileKind::BuilderRunner, ProfileKind::ExecuteWorker] {
        let profile = ProbeArgs::new(kind).profile();
        checks.extend(self_test_profile(mode, &profile, probe_binary, secret_path).checks);
    }
    match BrokerFixture::new() {
        Ok(fx) => {
            let profile = Profile::Broker {
                readable: vec![fx.endpoints.clone()],
                writable: vec![fx.spool.clone()],
                tcp_connect_ports: vec![],
            };
            checks.extend(self_test_profile(mode, &profile, probe_binary, secret_path).checks);
        }
        Err(e) => checks.push(Check {
            name: "broker/fixture".into(),
            passed: false,
            detail: format!("creating the broker's test endpoints file and spool: {e}"),
        }),
    }
    SelfTestReport { mode, checks }
}

/// A private directory holding a broker endpoints file and spool, removed on drop.
struct BrokerFixture {
    dir: PathBuf,
    endpoints: PathBuf,
    spool: PathBuf,
}

impl BrokerFixture {
    fn new() -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::env::temp_dir().join(unique("broker"));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let fx = BrokerFixture {
            endpoints: dir.join("endpoints.toml"),
            spool: dir.join("spool"),
            dir,
        };
        std::fs::write(&fx.endpoints, "# zkminer sandbox self-test\n")?;
        std::fs::create_dir(&fx.spool)?;
        Ok(fx)
    }
}

impl Drop for BrokerFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A private directory with one file (mode [`META_MODE`]) the probe inherits read-only at
/// [`META_FD`], removed on drop.
struct MetaFixture {
    dir: PathBuf,
    file: PathBuf,
    fd: OwnedFd,
}

impl MetaFixture {
    fn new() -> std::io::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let dir = std::env::temp_dir().join(unique("inherited"));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let file = dir.join("w");
        std::fs::write(
            &file,
            b"zkminer sandbox self-test: an inherited read-only file\n",
        )?;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(META_MODE))?;
        let fd = std::fs::File::open(&file)?.into();
        Ok(MetaFixture { dir, file, fd })
    }

    /// What changed about the file since it was created, if anything: mode, owner, the probe's
    /// xattr.
    fn changes(&self) -> Vec<String> {
        use std::os::unix::fs::MetadataExt;
        let mut bad = Vec::new();
        match std::fs::metadata(&self.file) {
            Ok(m) => {
                if m.mode() & 0o7777 != META_MODE {
                    bad.push(format!("mode {:o}, was {META_MODE:o}", m.mode() & 0o7777));
                }
                // SAFETY: geteuid cannot fail.
                if m.uid() != unsafe { libc::geteuid() } {
                    bad.push(format!("owner uid {}", m.uid()));
                }
            }
            Err(e) => bad.push(e.to_string()),
        }
        let path =
            std::ffi::CString::new(self.file.as_os_str().as_encoded_bytes()).unwrap_or_default();
        let name = std::ffi::CString::new(META_XATTR).unwrap_or_default();
        let mut buf = [0u8; 16];
        // SAFETY: valid NUL-terminated strings and a buffer of the length passed.
        let n = unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n >= 0 {
            bad.push(format!("xattr {META_XATTR} set"));
        }
        bad
    }
}

impl Drop for MetaFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Runs the self-test for one profile, in three fresh cgroups under [`delegated_root`]:
///
/// 1. **checks**: the probe applies `profile` with [`crate::restrict_self`] and tries the
///    forbidden operations (one check each, see the probe); meanwhile the parent verifies from
///    outside that `/proc/<pid>/status` shows `Seccomp: 2` and `NoNewPrivs: 1`, that the probe sits
///    in its job cgroup (joined before exec), that its `/proc/<pid>/environ` is unreadable even to
///    its parent (`PR_SET_DUMPABLE(0)`), and that the cgroup limits read back as written. The
///    parent hands the probe its fds 3, 4 and 5 (a read-only fd of a file it owns, whose mode,
///    owner and xattrs must be unchanged afterwards) through [`prepare_command`] and holds an
///    inheritable (non-`CLOEXEC`) pipe the probe must not receive;
/// 2. **oom**: under a 64 MiB `memory.max` the probe touches 512 MiB and must be OOM-killed
///    (`SIGKILL`, `memory.events` `oom_kill`), not swap (`memory.swap.max=0`);
/// 3. **pids**: under `pids.max=16` the probe must fail to `fork` (seccomp) and then start threads
///    until `pids.max` refuses with `EAGAIN` (`pids.events` `max`).
///
/// Each cgroup must then be removable (`cgroup.kill`, empty, `rmdir`). For a broker profile the
/// probe also connects to a loopback port the parent listens on that is added to
/// `tcp_connect_ports` (must succeed) and to another listening port that is not (must fail with
/// Landlock's `EACCES`), and reads/writes its `readable`/`writable` paths. Note that in rootless
/// mode nothing below the port level is checked: there is no kernel egress floor for addresses.
pub fn self_test_profile(
    mode: SandboxMode,
    profile: &Profile,
    probe_binary: &Path,
    secret_path: &Path,
) -> SelfTestReport {
    if mode == SandboxMode::System {
        return system_mode_unavailable(mode);
    }
    let kind = ProfileKind::of(profile);
    let mut r = Recorder {
        label: kind.label(),
        checks: Vec::new(),
    };
    let root = match delegated_root() {
        Ok(root) => {
            r.check("cgroup_delegated", true, root.display().to_string());
            root
        }
        Err(e) => {
            r.check("cgroup_delegated", false, e.to_string());
            return SelfTestReport {
                mode,
                checks: r.checks,
            };
        }
    };
    // The denial checks are only meaningful if the parent itself can read the secret.
    match std::fs::read(secret_path) {
        Ok(_) => r.check(
            "secret_readable_by_parent",
            true,
            secret_path.display().to_string(),
        ),
        Err(e) => r.check(
            "secret_readable_by_parent",
            false,
            format!("{}: {e}", secret_path.display()),
        ),
    }
    let mut base = ProbeArgs::new(kind);
    if let Profile::Broker {
        readable,
        writable,
        tcp_connect_ports,
    } = profile
    {
        base.readable = readable.clone();
        base.writable = writable.clone();
        base.ports = tcp_connect_ports.clone();
    }
    base.secret = Some(secret_path.to_path_buf());

    checks_run(&mut r, &base, probe_binary, &root);
    oom_run(&mut r, &base, probe_binary, &root);
    pids_run(&mut r, &base, probe_binary, &root);
    SelfTestReport {
        mode,
        checks: r.checks,
    }
}

fn create_cgroup(r: &mut Recorder, root: &Path, spec: &CgroupSpec, check: &str) -> Option<Cgroup> {
    match Cgroup::create(root, spec) {
        Ok(cg) => Some(cg),
        Err(e) => {
            r.check(check, false, format!("creating cgroup {}: {e}", spec.name));
            None
        }
    }
}

fn remove_cgroup(r: &mut Recorder, cg: Cgroup, check: &str) {
    let path = cg.path().display().to_string();
    match cg.remove() {
        Ok(()) => r.check(check, true, format!("killed, emptied and removed {path}")),
        Err(e) => r.check(check, false, e.to_string()),
    }
}

/// Reads the limits back from the cgroup files.
fn verify_limits(cg: &Cgroup, spec: &CgroupSpec) -> (bool, String) {
    let read = |f: &str| {
        std::fs::read_to_string(cg.path().join(f))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    let cpu_max = match spec.cpu_max {
        Some((q, p)) => format!("{q} {p}"),
        None => "max 100000".to_string(),
    };
    let swap = read("memory.swap.max");
    let want = [
        ("memory.max", spec.memory_max.to_string()),
        ("pids.max", spec.pids_max.to_string()),
        ("cpu.max", cpu_max),
        ("cpu.weight", spec.cpu_weight.to_string()),
        ("memory.oom.group", "1".to_string()),
    ];
    let mut bad: Vec<String> = want
        .iter()
        .filter(|(f, v)| read(f) != *v)
        .map(|(f, v)| format!("{f}={:?} want {v:?}", read(f)))
        .collect();
    if swap != "0" && cg.path().join("memory.swap.max").exists() {
        bad.push(format!("memory.swap.max={swap:?} want \"0\""));
    }
    if bad.is_empty() {
        (
            true,
            format!(
                "memory.max {} swap.max {swap} pids.max {} cpu.max {:?} cpu.weight {}",
                spec.memory_max, spec.pids_max, spec.cpu_max, spec.cpu_weight
            ),
        )
    } else {
        (false, bad.join(", "))
    }
}

fn reader<R: Read + Send + 'static>(mut r: R) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = r.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    })
}

/// Spawned probe with its output readers.
struct Running {
    child: Child,
    stdout: JoinHandle<String>,
    stderr: JoinHandle<String>,
}

impl Running {
    fn spawn(mut cmd: Command) -> std::io::Result<Self> {
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = reader(child.stdout.take().expect("piped stdout"));
        let stderr = reader(child.stderr.take().expect("piped stderr"));
        Ok(Running {
            child,
            stdout,
            stderr,
        })
    }

    /// Waits up to `timeout`, then kills the cgroup.
    fn finish(mut self, cg: &Cgroup, timeout: Duration) -> (Option<ExitStatus>, String, String) {
        let deadline = Instant::now() + timeout;
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Ok(None) => {
                    // Timed out: reported as no status.
                    let _ = cg.kill();
                    let _ = self.child.wait();
                    break None;
                }
                Err(_) => break None,
            }
        };
        // A process left in the cgroup could keep the pipes open.
        if status.is_some() {
            let _ = cg.kill();
        }
        let out = self.stdout.join().unwrap_or_default();
        let err = self.stderr.join().unwrap_or_default();
        (status, out, err)
    }
}

fn probe_command(probe: &Path, args: &ProbeArgs, command: &str) -> Command {
    let mut cmd = Command::new(probe);
    cmd.args(args.to_args(command)).env_clear();
    cmd
}

fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(':').map(str::trim))
}

/// Polls `fd` for one byte.
fn read_byte(fd: &OwnedFd, timeout: Duration) -> Option<u8> {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: one valid pollfd.
    if unsafe { libc::poll(&mut pfd, 1, ms) } <= 0 {
        return None;
    }
    let mut b = [0u8; 1];
    // SAFETY: reads at most one byte into `b`.
    (unsafe { libc::read(fd.as_raw_fd(), b.as_mut_ptr().cast(), 1) } == 1).then_some(b[0])
}

/// A pipe whose ends are both inheritable (no `CLOEXEC`), standing in for an fd the miner leaks.
fn inheritable_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: pipe2 writes two fds into `fds`.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both fds were just created and are owned here.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn checks_run(r: &mut Recorder, base: &ProbeArgs, probe: &Path, root: &Path) {
    let spec = CgroupSpec {
        name: unique(&format!("{}-checks", r.label)),
        memory_max: 512 * MIB,
        pids_max: 32,
        cpu_max: Some((200_000, 100_000)),
        cpu_weight: 20,
    };
    let Some(cg) = create_cgroup(r, root, &spec, "cgroup_create") else {
        return;
    };
    r.check("cgroup_create", true, cg.path().display().to_string());
    let (ok, d) = verify_limits(&cg, &spec);
    r.check("cgroup_limits", ok, d);

    match checks_probe(r, base, probe, &cg) {
        Ok(()) => {}
        Err(e) => r.check("probe_setup", false, e),
    }
    remove_cgroup(r, cg, "cgroup_remove");
}

fn checks_probe(
    r: &mut Recorder,
    base: &ProbeArgs,
    probe: &Path,
    cg: &Cgroup,
) -> Result<(), String> {
    let s = |e: std::io::Error| e.to_string();
    let is_broker = base.kind == ProfileKind::Broker;

    // Loopback listeners: one allowed (for the broker), one not.
    let listen = TcpListener::bind("127.0.0.1:0").map_err(s)?;
    let listen_port = listen.local_addr().map_err(s)?.port();
    let mut deny = TcpListener::bind("127.0.0.1:0").map_err(s)?;
    while base.ports.contains(&deny.local_addr().map_err(s)?.port()) {
        deny = TcpListener::bind("127.0.0.1:0").map_err(s)?;
    }
    let deny_port = deny.local_addr().map_err(s)?.port();

    // An abstract Unix socket the parent listens on, reachable from outside the sandbox.
    let abstract_name = unique("abstract");
    let addr = SocketAddr::from_abstract_name(abstract_name.as_bytes()).map_err(s)?;
    let unix = UnixListener::bind_addr(&addr).map_err(s)?;
    let control = UnixStream::connect_addr(&addr);
    r.check(
        "abstract_socket_reachable_unsandboxed",
        control.is_ok(),
        format!(
            "parent connect to @{abstract_name}: {:?}",
            control.as_ref().map(|_| ())
        ),
    );
    drop(control);

    let (ready_r, ready_w) = std::io::pipe().map_err(s)?;
    let (go_r, go_w) = std::io::pipe().map_err(s)?;
    let (ready_r, ready_w, go_r, go_w): (OwnedFd, OwnedFd, OwnedFd, OwnedFd) =
        (ready_r.into(), ready_w.into(), go_r.into(), go_w.into());
    let leak = inheritable_pipe().map_err(s)?;
    let meta = MetaFixture::new().map_err(|e| format!("creating the inherited file: {e}"))?;

    let mut args = base.clone();
    args.listen_port = Some(listen_port);
    args.deny_port = Some(deny_port);
    if is_broker {
        args.ports.push(listen_port);
    }
    args.abstract_name = Some(abstract_name);
    args.meta_fd = Some(META_FD);
    args.expect_fds = vec![0, 1, 2, READY_FD, GO_FD, META_FD];
    args.ready_fd = Some(READY_FD);
    args.go_fd = Some(GO_FD);
    args.tag = unique("t");

    let mut cmd = probe_command(probe, &args, "checks");
    prepare_command(
        &mut cmd,
        cg,
        &[
            (ready_w.as_fd(), READY_FD),
            (go_r.as_fd(), GO_FD),
            (meta.fd.as_fd(), META_FD),
        ],
    )
    .map_err(|e| e.to_string())?;
    let running = Running::spawn(cmd);
    // The child holds its copies now; the parent's must go so EOFs propagate.
    drop((ready_w, go_r, leak));
    let running = match running {
        Ok(p) => {
            r.check("probe_spawn", true, format!("pid {}", p.child.id()));
            p
        }
        Err(e) => {
            r.check("probe_spawn", false, format!("{}: {e}", probe.display()));
            return Ok(());
        }
    };
    let pid = running.child.id();

    let ready = read_byte(&ready_r, READY_TIMEOUT) == Some(b'R');
    r.check(
        "probe_ready",
        ready,
        if ready {
            "restricted and waiting"
        } else {
            "no ready byte (see probe output)"
        },
    );
    if ready {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let seccomp = status_field(&status, "Seccomp");
        let filters = status_field(&status, "Seccomp_filters");
        r.check(
            "status_seccomp",
            seccomp == Some("2"),
            format!("/proc/{pid}/status Seccomp: {seccomp:?}, Seccomp_filters: {filters:?}"),
        );
        let nnp = status_field(&status, "NoNewPrivs");
        r.check(
            "status_no_new_privs",
            nnp == Some("1"),
            format!("/proc/{pid}/status NoNewPrivs: {nnp:?}"),
        );

        let want = cgroup2_mount().ok().and_then(|m| {
            cg.path()
                .strip_prefix(m)
                .ok()
                .map(|rel| format!("0::/{}", rel.display()))
        });
        let got = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
        let got = got
            .lines()
            .find(|l| l.starts_with("0::"))
            .unwrap_or("")
            .to_string();
        r.check(
            "in_job_cgroup",
            want.as_deref() == Some(got.as_str()),
            format!("{got} (want {want:?})"),
        );

        let environ = std::fs::read(format!("/proc/{pid}/environ"));
        r.check(
            "environ_unreadable",
            environ.is_err(),
            match environ {
                Ok(_) => {
                    "parent could read /proc/<pid>/environ: the probe is still dumpable".to_string()
                }
                Err(e) => format!("parent read of /proc/{pid}/environ: {e} (PR_SET_DUMPABLE 0)"),
            },
        );
    }
    drop(go_w);

    let (status, out, err) = running.finish(cg, PROBE_TIMEOUT);
    r.check(
        "probe_exit",
        status.is_some_and(|s| s.success()),
        match status {
            Some(s) => format!("{s}"),
            None => format!("no exit within {PROBE_TIMEOUT:?}; cgroup killed"),
        },
    );
    drop((listen, deny, unix));
    let changes = meta.changes();
    r.check(
        "inherited_file_unchanged",
        changes.is_empty(),
        if changes.is_empty() {
            format!("mode {META_MODE:o}, owner and xattrs as before")
        } else {
            changes.join(", ")
        },
    );

    let mut seen = Vec::new();
    let mut done = None;
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("CHECK ") {
            let mut parts = rest.splitn(3, ' ');
            let (Some(name), Some(verdict)) = (parts.next(), parts.next()) else {
                continue;
            };
            let detail = parts.next().unwrap_or("").to_string();
            r.check(name, verdict == "PASS", detail);
            seen.push(name.to_string());
        } else if let Some(n) = line.strip_prefix("DONE ") {
            done = n.trim().parse::<usize>().ok();
        }
    }
    let missing: Vec<&str> = expected_checks(base.kind)
        .into_iter()
        .filter(|c| !seen.iter().any(|s| s == c))
        .collect();
    let complete = missing.is_empty() && done == Some(seen.len());
    let mut detail = format!("{} checks, DONE {:?}", seen.len(), done);
    if !missing.is_empty() {
        detail += &format!(", missing {missing:?}");
    }
    if !complete && !err.trim().is_empty() {
        detail += &format!(", stderr: {}", err.trim().replace('\n', " | "));
    }
    r.check("probe_output", complete, detail);
    Ok(())
}

fn oom_run(r: &mut Recorder, base: &ProbeArgs, probe: &Path, root: &Path) {
    let spec = CgroupSpec {
        name: unique(&format!("{}-oom", r.label)),
        memory_max: 64 * MIB,
        pids_max: 16,
        cpu_max: None,
        cpu_weight: 20,
    };
    let Some(cg) = create_cgroup(r, root, &spec, "oom_kill") else {
        return;
    };
    let mut args = base.clone();
    args.bytes = 512 * MIB;
    let mut cmd = probe_command(probe, &args, "oom");
    let outcome = prepare_command(&mut cmd, &cg, &[])
        .map_err(|e| e.to_string())
        .and_then(|()| Running::spawn(cmd).map_err(|e| e.to_string()));
    match outcome {
        Ok(running) => {
            let (status, out, _) = running.finish(&cg, PROBE_TIMEOUT);
            let restricted = out.contains("RESTRICTED");
            let survived = out.contains("SURVIVED");
            let sigkill = status.and_then(|s| s.signal()) == Some(libc::SIGKILL);
            let oom = cg.oom_killed();
            let peak = cg.memory_peak();
            r.check(
                "oom_kill",
                restricted && sigkill && oom && !survived,
                format!(
                    "restricted {restricted}, status {status:?}, memory.events oom kill {oom}, survived {survived}, \
                     memory.peak {peak:?} (memory.max {})",
                    spec.memory_max
                ),
            );
        }
        Err(e) => r.check("oom_kill", false, e),
    }
    remove_cgroup(r, cg, "oom_cgroup_remove");
}

fn pids_run(r: &mut Recorder, base: &ProbeArgs, probe: &Path, root: &Path) {
    let spec = CgroupSpec {
        name: unique(&format!("{}-pids", r.label)),
        memory_max: 256 * MIB,
        pids_max: 16,
        cpu_max: None,
        cpu_weight: 20,
    };
    let Some(cg) = create_cgroup(r, root, &spec, "pids_max") else {
        return;
    };
    let mut args = base.clone();
    args.max_tasks = 1024;
    let mut cmd = probe_command(probe, &args, "pids");
    let outcome = prepare_command(&mut cmd, &cg, &[])
        .map_err(|e| e.to_string())
        .and_then(|()| Running::spawn(cmd).map_err(|e| e.to_string()));
    match outcome {
        Ok(running) => {
            let (status, out, _) = running.finish(&cg, PROBE_TIMEOUT);
            let line = out
                .lines()
                .find_map(|l| l.strip_prefix("PIDS "))
                .unwrap_or("");
            let field = |k: &str| {
                line.split_whitespace()
                    .find_map(|kv| kv.strip_prefix(k)?.strip_prefix('=')?.parse::<i64>().ok())
            };
            let (fork_errno, threads, errno) =
                (field("fork_errno"), field("threads"), field("errno"));
            let events_max = std::fs::read_to_string(cg.path().join("pids.events"))
                .ok()
                .and_then(|t| parse_keyed(&t, "max"));
            r.check(
                "no_new_processes",
                fork_errno == Some(libc::EPERM as i64),
                format!("fork() in the sandbox: errno {fork_errno:?} (want EPERM)"),
            );
            let capped = status.is_some_and(|s| s.success())
                && threads.is_some_and(|t| t < spec.pids_max as i64)
                && errno == Some(libc::EAGAIN as i64)
                && events_max.is_some_and(|m| m > 0);
            r.check(
                "pids_max",
                capped,
                format!(
                    "{threads:?} threads + main before EAGAIN (errno {errno:?}), pids.max {}, pids.events max {events_max:?}, status {status:?}",
                    spec.pids_max
                ),
            );
        }
        Err(e) => r.check("pids_max", false, e),
    }
    remove_cgroup(r, cg, "pids_cgroup_remove");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_mode_is_reported_unavailable() {
        let report = self_test(
            SandboxMode::System,
            Path::new("/nonexistent"),
            Path::new("/nonexistent"),
        );
        assert!(!report.passed());
        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.checks[0].name, "system_mode");
        assert!(report.checks[0].detail.contains("not implemented"));
    }

    #[test]
    fn status_fields() {
        let status = "Name:\tprobe\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t2\n";
        assert_eq!(status_field(status, "Seccomp"), Some("2"));
        assert_eq!(status_field(status, "Seccomp_filters"), Some("2"));
        assert_eq!(status_field(status, "NoNewPrivs"), Some("1"));
        assert_eq!(status_field(status, "Missing"), None);
    }

    #[test]
    fn empty_report_does_not_pass() {
        assert!(!SelfTestReport {
            mode: SandboxMode::Rootless,
            checks: vec![]
        }
        .passed());
    }
}
