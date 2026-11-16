//! The self-test probe: the child side of [`crate::self_test`], run by the
//! `zkminer-witness-sandbox-probe` binary (or by any sandboxed binary that calls [`main`] for a
//! `--self-test` flag). It applies a profile with [`crate::restrict_self`], then tries forbidden
//! operations and prints one line per check:
//!
//! ```text
//! CHECK <name> PASS|FAIL <detail>
//! DONE <number of CHECK lines>
//! ```
//!
//! Arguments are trusted (they come from the miner). Not a stable interface.

use std::ffi::{CString, OsStr, OsString};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::restrict::{current_state, denied_syscalls};
use crate::{restrict_self, Profile, MIN_LANDLOCK_ABI};

/// The probe binary's file name.
pub const PROBE_BINARY: &str = "zkminer-witness-sandbox-probe";

/// A [`Profile`] without its parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileKind {
    BuilderRunner,
    ExecuteWorker,
    Broker,
}

impl ProfileKind {
    pub fn of(profile: &Profile) -> Self {
        match profile {
            Profile::BuilderRunner => ProfileKind::BuilderRunner,
            Profile::ExecuteWorker => ProfileKind::ExecuteWorker,
            Profile::Broker { .. } => ProfileKind::Broker,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ProfileKind::BuilderRunner => "builder_runner",
            ProfileKind::ExecuteWorker => "execute_worker",
            ProfileKind::Broker => "broker",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [
            ProfileKind::BuilderRunner,
            ProfileKind::ExecuteWorker,
            ProfileKind::Broker,
        ]
        .into_iter()
        .find(|k| k.label() == s)
    }
}

/// Checks every `checks` run prints, for every profile.
const COMMON_CHECKS: &[&str] = &[
    "restrict_self",
    "report",
    "inherited_fds",
    "prctl_state",
    "read_secret",
    "proc_self_status",
    "open_nvidiactl",
    "open_dri_render",
    "write_tmp",
    "write_dev_shm",
    "landlock_mkdir_tmp",
    "chmod_secret",
    "fchmod_inherited",
    "fchown_inherited",
    "fsetxattr_inherited",
    "fremovexattr_inherited",
    "flock_inherited",
    "fcntl_setlease_inherited",
    "fcntl_notify_dir",
    "file_getattr_inherited",
    "file_setattr_inherited",
    "ioctl_setflags_inherited",
    "sysv_shmget",
    "sysv_msgget",
    "sysv_semget",
    "socket_unix",
    "socket_netlink",
    "abstract_unix_connect",
    "kill_parent",
    "ptrace_attach_child",
    "process_vm_readv_child",
    "setpriority_parent",
    "sched_setaffinity_parent",
    "prlimit_parent",
    "fork",
    "clone3",
    #[cfg(target_arch = "x86_64")]
    "x32_syscall",
    "pdeathsig_locked",
    "prctl_set_dumpable",
    "prctl_set_ptracer",
    "ioctl_tiocsti",
    "seccomp_denylist",
    "execve",
];

const NO_NETWORK_CHECKS: &[&str] = &["socket_inet", "socket_inet6", "tcp_connect_loopback"];

const BROKER_CHECKS: &[&str] = &[
    "socket_inet_allowed",
    "socket_inet6_allowed",
    "socket_inet_tcp_allowed",
    "socket_udp",
    "socket_mptcp",
    "socket_icmp",
    "socket_raw",
    "socketpair_unix_stream_allowed",
    "socketpair_unix_dgram",
    "socketpair_unix_seqpacket",
    "tcp_connect_allowed_port",
    "tcp_connect_denied_port",
    "tcp_bind",
    "read_readable",
    "readable_not_writable",
    "write_writable",
];

/// Checks that something the profile *allows* still works: they pass without the sandbox too.
pub const POSITIVE_CHECKS: &[&str] = &[
    "socket_inet_allowed",
    "socket_inet6_allowed",
    "socket_inet_tcp_allowed",
    "socketpair_unix_stream_allowed",
    "tcp_connect_allowed_port",
    "read_readable",
    "write_writable",
];

/// Checks that cannot tell the sandbox from an unprivileged process without it, with the reason;
/// every other check fails in an `--unrestricted` run (the negative control).
pub const UNSANDBOXED_EXEMPT: &[(&str, &str)] = &[
    (
        "inherited_fds",
        "a property of prepare_command, which the negative control does not use",
    ),
    (
        "socket_raw",
        "without CAP_NET_RAW the kernel refuses a raw socket with EPERM too; the seccomp rule \
         itself is proven by restrict.rs's BPF interpreter test",
    ),
];

/// Every check a `checks` run must print for `kind`.
pub fn expected_checks(kind: ProfileKind) -> Vec<&'static str> {
    let mut v = COMMON_CHECKS.to_vec();
    v.extend_from_slice(match kind {
        ProfileKind::Broker => BROKER_CHECKS,
        _ => NO_NETWORK_CHECKS,
    });
    v
}

/// The probe's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeArgs {
    pub kind: ProfileKind,
    pub readable: Vec<PathBuf>,
    pub writable: Vec<PathBuf>,
    pub ports: Vec<u16>,
    /// A file the probe must not read.
    pub secret: Option<PathBuf>,
    /// A loopback TCP port the parent listens on (in `ports` for the broker).
    pub listen_port: Option<u16>,
    /// Broker: a loopback TCP port the parent listens on that is not in `ports`.
    pub deny_port: Option<u16>,
    /// An abstract Unix socket name the parent listens on.
    pub abstract_name: Option<String>,
    /// An inherited read-only fd of a regular file the parent owns, for the metadata checks
    /// (`fchmod`, `fsetxattr`, `flock`, leases, ...). The parent checks afterwards that the file
    /// did not change.
    pub meta_fd: Option<RawFd>,
    /// The fds the probe must have, and only those, at startup.
    pub expect_fds: Vec<RawFd>,
    /// Written one byte (`R`) once restricted.
    pub ready_fd: Option<RawFd>,
    /// Read until EOF before running the checks.
    pub go_fd: Option<RawFd>,
    /// `oom`: bytes to allocate and touch.
    pub bytes: u64,
    /// `pids`: most threads to try.
    pub max_tasks: u32,
    /// Makes file names unique.
    pub tag: String,
    /// Test only (a negative control): `checks` without [`restrict_self`], skipping the checks
    /// that would act on the parent or replace the process. Every other check must then fail.
    pub unrestricted: bool,
}

impl ProbeArgs {
    pub fn new(kind: ProfileKind) -> Self {
        ProbeArgs {
            kind,
            readable: Vec::new(),
            writable: Vec::new(),
            ports: Vec::new(),
            secret: None,
            listen_port: None,
            deny_port: None,
            abstract_name: None,
            meta_fd: None,
            expect_fds: vec![0, 1, 2],
            ready_fd: None,
            go_fd: None,
            bytes: 0,
            max_tasks: 4096,
            tag: std::process::id().to_string(),
            unrestricted: false,
        }
    }

    /// The profile these arguments describe.
    pub fn profile(&self) -> Profile {
        match self.kind {
            ProfileKind::BuilderRunner => Profile::BuilderRunner,
            ProfileKind::ExecuteWorker => Profile::ExecuteWorker,
            ProfileKind::Broker => Profile::Broker {
                readable: self.readable.clone(),
                writable: self.writable.clone(),
                tcp_connect_ports: self.ports.clone(),
            },
        }
    }

    /// `command` (`checks`, `oom`, `pids`, `fds` or `threaded`) followed by the flags.
    pub fn to_args(&self, command: &str) -> Vec<OsString> {
        let mut a: Vec<OsString> =
            vec![command.into(), "--profile".into(), self.kind.label().into()];
        let mut flag = |k: &str, v: OsString| {
            a.push(k.into());
            a.push(v);
        };
        for p in &self.readable {
            flag("--readable", p.into());
        }
        for p in &self.writable {
            flag("--writable", p.into());
        }
        for p in &self.ports {
            flag("--port", p.to_string().into());
        }
        if let Some(p) = &self.secret {
            flag("--secret", p.into());
        }
        if let Some(p) = self.listen_port {
            flag("--listen-port", p.to_string().into());
        }
        if let Some(p) = self.deny_port {
            flag("--deny-port", p.to_string().into());
        }
        if let Some(n) = &self.abstract_name {
            flag("--abstract", n.into());
        }
        if let Some(f) = self.meta_fd {
            flag("--meta-fd", f.to_string().into());
        }
        let fds: Vec<String> = self.expect_fds.iter().map(|f| f.to_string()).collect();
        flag("--expect-fds", fds.join(",").into());
        if let Some(f) = self.ready_fd {
            flag("--ready-fd", f.to_string().into());
        }
        if let Some(f) = self.go_fd {
            flag("--go-fd", f.to_string().into());
        }
        flag("--bytes", self.bytes.to_string().into());
        flag("--max-tasks", self.max_tasks.to_string().into());
        flag("--tag", self.tag.clone().into());
        if self.unrestricted {
            flag("--unrestricted", "1".into());
        }
        a
    }

    /// Parses what [`ProbeArgs::to_args`] produced (without the command).
    pub fn parse(args: &[OsString]) -> Result<Self, String> {
        fn num<T: std::str::FromStr>(k: &str, v: &OsStr) -> Result<T, String> {
            v.to_str()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("{k}: bad value {v:?}"))
        }
        let mut it = args.iter();
        let mut kind = None;
        let mut a = ProbeArgs::new(ProfileKind::BuilderRunner);
        while let Some(k) = it.next() {
            let k = k.to_str().ok_or("non-UTF-8 flag")?;
            let v = it.next().ok_or_else(|| format!("{k} needs a value"))?;
            match k {
                "--profile" => {
                    kind = Some(
                        v.to_str()
                            .and_then(ProfileKind::parse)
                            .ok_or_else(|| format!("bad profile {v:?}"))?,
                    )
                }
                "--readable" => a.readable.push(v.into()),
                "--writable" => a.writable.push(v.into()),
                "--port" => a.ports.push(num(k, v)?),
                "--secret" => a.secret = Some(v.into()),
                "--listen-port" => a.listen_port = Some(num(k, v)?),
                "--deny-port" => a.deny_port = Some(num(k, v)?),
                "--abstract" => {
                    a.abstract_name = Some(v.to_str().ok_or("bad --abstract")?.to_string())
                }
                "--meta-fd" => a.meta_fd = Some(num(k, v)?),
                "--expect-fds" => {
                    let s = v.to_str().ok_or("bad --expect-fds")?;
                    a.expect_fds = s
                        .split(',')
                        .filter(|x| !x.is_empty())
                        .map(|x| x.parse().map_err(|_| format!("bad fd {x:?}")))
                        .collect::<Result<_, _>>()?;
                }
                "--ready-fd" => a.ready_fd = Some(num(k, v)?),
                "--go-fd" => a.go_fd = Some(num(k, v)?),
                "--bytes" => a.bytes = num(k, v)?,
                "--max-tasks" => a.max_tasks = num(k, v)?,
                "--tag" => a.tag = v.to_str().ok_or("bad --tag")?.to_string(),
                "--unrestricted" => a.unrestricted = v == "1",
                _ => return Err(format!("unknown flag {k}")),
            }
        }
        a.kind = kind.ok_or("--profile is required")?;
        Ok(a)
    }
}

/// Entry point of the probe binary: `<checks|oom|pids|fds|threaded> --profile <..> [flags]`.
/// Returns the exit code.
pub fn main() -> i32 {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some(command) = args.first().and_then(|c| c.to_str()) else {
        eprintln!("usage: {PROBE_BINARY} <checks|oom|pids|fds|threaded> --profile <builder_runner|execute_worker|broker> [flags]");
        return 64;
    };
    let parsed = match ProbeArgs::parse(&args[1..]) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{PROBE_BINARY}: {e}");
            return 64;
        }
    };
    match command {
        "checks" => run_checks(&parsed),
        "oom" => run_oom(&parsed),
        "pids" => run_pids(&parsed),
        "fds" => run_fds(),
        "threaded" => run_threaded(&parsed),
        _ => {
            eprintln!("{PROBE_BINARY}: unknown command {command}");
            64
        }
    }
}

// ---------------------------------------------------------------------------------------------
// helpers

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn errname(e: i32) -> String {
    let n = match e {
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::ENOENT => "ENOENT",
        libc::ENOSYS => "ENOSYS",
        libc::EAGAIN => "EAGAIN",
        libc::EBADF => "EBADF",
        libc::EINVAL => "EINVAL",
        libc::EFAULT => "EFAULT",
        libc::ESRCH => "ESRCH",
        libc::ECONNREFUSED => "ECONNREFUSED",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::ENOTTY => "ENOTTY",
        libc::EIO => "EIO",
        libc::EEXIST => "EEXIST",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::ENODATA => "ENODATA",
        libc::ENOTDIR => "ENOTDIR",
        libc::ENOPROTOOPT => "ENOPROTOOPT",
        libc::EPROTONOSUPPORT => "EPROTONOSUPPORT",
        libc::ESOCKTNOSUPPORT => "ESOCKTNOSUPPORT",
        libc::EISCONN => "EISCONN",
        _ => return format!("errno {e}"),
    };
    n.to_string()
}

fn cstr(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).unwrap_or_default()
}

/// Pass iff the raw syscall result is an error with an errno in `want`.
fn denied(ret: libc::c_long, err: i32, want: &[i32]) -> (bool, String) {
    if ret >= 0 {
        (false, format!("succeeded (returned {ret})"))
    } else {
        (want.contains(&err), errname(err))
    }
}

/// Pass iff `r` failed with an errno in `want`.
fn denied_io<T>(r: io::Result<T>, want: &[i32]) -> (bool, String) {
    match r {
        Ok(_) => (false, "succeeded".to_string()),
        Err(e) => {
            let n = e.raw_os_error().unwrap_or(0);
            (want.contains(&n), errname(n))
        }
    }
}

/// Runs a raw syscall-like call and captures errno right after it.
fn sys(f: impl FnOnce() -> libc::c_long) -> (libc::c_long, i32) {
    let r = f();
    (r, if r < 0 { errno() } else { 0 })
}

/// The fds open now, excluding the one used to list them.
fn open_fds() -> Vec<RawFd> {
    let mut listed: Vec<RawFd> = match std::fs::read_dir("/proc/self/fd") {
        Ok(rd) => rd
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .collect(),
        Err(_) => return vec![-1],
    };
    // The directory's own fd is closed again by now.
    // SAFETY: F_GETFD on an int only queries.
    listed.retain(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
    listed.sort_unstable();
    listed
}

fn close(fd: RawFd) {
    if fd >= 0 {
        // SAFETY: closes an fd this probe opened.
        unsafe { libc::close(fd) };
    }
}

fn new_socket(domain: libc::c_int, ty: libc::c_int) -> (libc::c_long, i32) {
    // SAFETY: socket takes integers.
    sys(|| unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC, 0) } as libc::c_long)
}

fn loopback(port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
        },
        sin_zero: [0; 8],
    }
}

fn abstract_addr(name: &str) -> (libc::sockaddr_un, libc::socklen_t) {
    // SAFETY: sockaddr_un is plain data; all-zero is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = name.as_bytes();
    let n = bytes.len().min(addr.sun_path.len() - 1);
    for (dst, src) in addr.sun_path[1..=n].iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + 1 + n;
    (addr, len as libc::socklen_t)
}

#[derive(Default)]
struct Out {
    count: usize,
}

impl Out {
    fn check(&mut self, name: &str, passed: bool, detail: impl AsRef<str>) {
        let detail = detail.as_ref().replace(['\n', '\r'], " ");
        println!(
            "CHECK {name} {} {detail}",
            if passed { "PASS" } else { "FAIL" }
        );
        self.count += 1;
    }

    fn result(&mut self, name: &str, (passed, detail): (bool, String)) {
        self.check(name, passed, detail);
    }

    fn done(&self) {
        println!("DONE {}", self.count);
        let _ = io::stdout().flush();
    }
}

// ---------------------------------------------------------------------------------------------
// checks

/// Read by `process_vm_readv_child` from the tracee's copy of this process's memory.
static TRACEE_MARK: [u8; 8] = *b"zkminer!";

/// A child forked before the sandbox, the target of the ptrace and `process_vm_readv` checks: the
/// most permissive target there is (Yama's `ptrace_scope` 1 lets a process trace its own
/// descendants, and the child predates the probe's Landlock domain), so without the sandbox those
/// checks fail instead of passing on Yama's say-so. It holds none of the probe's fds and dies with
/// it (`PR_SET_PDEATHSIG`; the self-test also kills the cgroup).
fn spawn_tracee() -> Result<libc::pid_t, i32> {
    // SAFETY: getpid cannot fail.
    let parent = unsafe { libc::getpid() };
    let _ = io::stdout().flush();
    // SAFETY: the child only makes async-signal-safe syscalls and never returns.
    match unsafe { libc::fork() } {
        -1 => Err(errno()),
        0 => unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            if libc::getppid() != parent {
                libc::_exit(0);
            }
            libc::syscall(libc::SYS_close_range, 0u32, u32::MAX, 0u32);
            loop {
                libc::pause();
            }
        },
        pid => Ok(pid),
    }
}

/// The missing-argument detail, the same everywhere (the negative control looks for it).
fn missing(flag: &str) -> String {
    format!("missing {flag}")
}

fn run_checks(a: &ProbeArgs) -> i32 {
    // Before restricting: what we inherited, and sockets to try connecting with afterwards (a
    // sandboxed process cannot create them, but must not be able to use them either), a directory
    // fd for the dnotify check, and the tracee.
    let fds_at_start = open_fds();
    let (unix_sock, _) = new_socket(libc::AF_UNIX, libc::SOCK_STREAM);
    let (inet_sock, _) = new_socket(libc::AF_INET, libc::SOCK_STREAM);
    let (unix_sock, inet_sock) = (unix_sock as RawFd, inet_sock as RawFd);
    // SAFETY: a constant path.
    let root_dir = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    let tracee = spawn_tracee();

    let profile = a.profile();
    let mut out = Out::default();
    let restricted = if a.unrestricted {
        out.check(
            "restrict_self",
            false,
            "skipped (--unrestricted negative control)",
        );
        Ok(current_state(crate::landlock_abi()))
    } else {
        restrict_self(&profile)
    };
    let report = match restricted {
        Ok(r) => {
            if !a.unrestricted {
                out.check("restrict_self", true, "ok");
            }
            r
        }
        Err(e) => {
            out.check("restrict_self", false, e.to_string());
            out.done();
            return 2;
        }
    };
    out.check(
        "report",
        report.landlock_abi >= MIN_LANDLOCK_ABI
            && report.seccomp
            && report.no_new_privs
            && report.dumpable_cleared
            && report.core_dumps_disabled,
        format!("{report:?}"),
    );

    // Let the parent inspect /proc/<pid> while we are restricted and idle.
    if let Some(fd) = a.ready_fd {
        // SAFETY: writes one byte from a static buffer.
        unsafe { libc::write(fd, b"R".as_ptr().cast(), 1) };
    }
    if let Some(fd) = a.go_fd {
        // SAFETY: the parent mapped this fd; we own it from here on.
        let mut go = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let mut sink = Vec::new();
        let _ = go.read_to_end(&mut sink);
    }

    let mut expected = a.expect_fds.clone();
    expected.sort_unstable();
    out.check(
        "inherited_fds",
        fds_at_start == expected,
        format!("open at start {fds_at_start:?}, expected {expected:?}"),
    );

    let state = current_state(report.landlock_abi);
    out.check(
        "prctl_state",
        state.seccomp && state.no_new_privs && state.dumpable_cleared && state.core_dumps_disabled,
        format!(
            "PR_GET_SECCOMP==2 {}, NO_NEW_PRIVS {}, !DUMPABLE {}, RLIMIT_CORE=0 {}",
            state.seccomp, state.no_new_privs, state.dumpable_cleared, state.core_dumps_disabled
        ),
    );

    let fs_denied = [libc::EPERM, libc::EACCES];
    match &a.secret {
        Some(secret) => out.result("read_secret", denied_io(std::fs::read(secret), &fs_denied)),
        None => out.check("read_secret", false, missing("--secret")),
    }
    out.result(
        "proc_self_status",
        denied_io(std::fs::read("/proc/self/status"), &fs_denied),
    );
    for (name, dev) in [
        ("open_nvidiactl", "/dev/nvidiactl"),
        ("open_dri_render", "/dev/dri/renderD128"),
    ] {
        if a.unrestricted {
            // Never touch a GPU node outside the sandbox: the same open of a harmless device
            // shows the check failing when nothing denies it.
            let r = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null");
            let (ok, d) = denied_io(r, &fs_denied);
            out.check(
                name,
                ok,
                format!("{d} (/dev/null standing in for {dev} outside the sandbox)"),
            );
        } else if Path::new(dev).exists() {
            let r = std::fs::OpenOptions::new().read(true).write(true).open(dev);
            out.result(name, denied_io(r, &fs_denied));
        } else {
            out.check(name, true, format!("{dev} absent on this host"));
        }
    }
    for (name, dir) in [("write_tmp", "/tmp"), ("write_dev_shm", "/dev/shm")] {
        let p = PathBuf::from(format!("{dir}/zkminer-probe-{}", a.tag));
        let r = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p);
        if r.is_ok() {
            let _ = std::fs::remove_file(&p);
        }
        out.result(name, denied_io(r, &fs_denied));
    }
    {
        // mkdir is not in the seccomp denylist: EACCES here is Landlock's answer alone.
        let p = PathBuf::from(format!("/tmp/zkminer-probe-{}.d", a.tag));
        let r = std::fs::create_dir(&p);
        if r.is_ok() {
            let _ = std::fs::remove_dir(&p);
        }
        let (ok, d) = denied_io(r, &[libc::EACCES]);
        out.check("landlock_mkdir_tmp", ok, format!("{d} (Landlock layer)"));
    }
    match &a.secret {
        Some(secret) => {
            // Re-apply the current mode, so even a missing filter changes nothing.
            let mode = std::fs::metadata(secret)
                .map(|m| m.mode() & 0o7777)
                .unwrap_or(0o600);
            let c = cstr(secret);
            // SAFETY: `c` is a valid path.
            let (r, e) = sys(|| unsafe { libc::chmod(c.as_ptr(), mode) } as libc::c_long);
            out.result("chmod_secret", denied(r, e, &[libc::EPERM]));
        }
        None => out.check("chmod_secret", false, missing("--secret")),
    }
    inherited_fd_checks(a, root_dir, &mut out);
    sysv_checks(&mut out);

    let is_broker = a.kind == ProfileKind::Broker;
    let (r, e) = new_socket(libc::AF_UNIX, libc::SOCK_STREAM);
    close(r as RawFd);
    out.result("socket_unix", denied(r, e, &[libc::EPERM]));
    let (r, e) = new_socket(libc::AF_NETLINK, libc::SOCK_RAW);
    close(r as RawFd);
    out.result("socket_netlink", denied(r, e, &[libc::EPERM]));

    match (&a.abstract_name, unix_sock >= 0) {
        (Some(name), true) => {
            let (addr, len) = abstract_addr(name);
            // SAFETY: `addr` is a valid sockaddr_un of `len` bytes.
            let (r, e) = sys(|| unsafe {
                libc::connect(unix_sock, (&addr as *const libc::sockaddr_un).cast(), len)
            } as libc::c_long);
            let (ok, d) = denied(r, e, &[libc::EPERM]);
            let layer = if is_broker {
                "Landlock abstract-socket scope"
            } else {
                "seccomp"
            };
            out.check("abstract_unix_connect", ok, format!("{d} ({layer})"));
        }
        (None, _) => out.check("abstract_unix_connect", false, missing("--abstract")),
        (_, false) => out.check(
            "abstract_unix_connect",
            false,
            "could not create a socket before restricting",
        ),
    }

    // SAFETY: getppid cannot fail.
    let ppid = unsafe { libc::getppid() };
    {
        // SAFETY: signal 0 only checks permission.
        let (r, e) = sys(|| unsafe { libc::kill(ppid, 0) } as libc::c_long);
        let (ok, d) = denied(r, e, &[libc::EPERM]);
        out.check("kill_parent", ok, format!("{d} (Landlock signal scope)"));
    }
    tracee_checks(tracee, &mut out);
    {
        // Re-apply the parent's current values, so even a missing filter changes nothing.
        // SAFETY: integer arguments.
        let nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, ppid as libc::id_t) };
        // SAFETY: integer arguments.
        let (r, e) =
            sys(
                || unsafe { libc::setpriority(libc::PRIO_PROCESS, ppid as libc::id_t, nice) }
                    as libc::c_long,
            );
        out.result("setpriority_parent", denied(r, e, &[libc::EPERM]));

        // SAFETY: cpu_set_t is plain data.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::cpu_set_t>();
        // SAFETY: `set` is a valid cpu_set_t of `size` bytes.
        if unsafe { libc::sched_getaffinity(ppid, size, &mut set) } == 0 {
            // SAFETY: as above.
            let (r, e) =
                sys(|| unsafe { libc::sched_setaffinity(ppid, size, &set) } as libc::c_long);
            out.result("sched_setaffinity_parent", denied(r, e, &[libc::EPERM]));
        } else {
            let d = format!("sched_getaffinity failed: {}", errname(errno()));
            out.check("sched_setaffinity_parent", false, d);
        }

        let mut old = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: a get-only prlimit into `old`.
        let (r, e) =
            sys(
                || unsafe { libc::prlimit(ppid, libc::RLIMIT_NOFILE, std::ptr::null(), &mut old) }
                    as libc::c_long,
            );
        out.result("prlimit_parent", denied(r, e, &[libc::EPERM]));
    }
    {
        let _ = io::stdout().flush();
        // SAFETY: the child (if any) exits immediately without touching shared state.
        let (r, e) = sys(|| unsafe { libc::fork() } as libc::c_long);
        if r == 0 {
            // SAFETY: async-signal-safe exit in the child.
            unsafe { libc::_exit(0) };
        }
        if r > 0 {
            let mut st = 0;
            // SAFETY: reaps the child we forked.
            unsafe { libc::waitpid(r as libc::pid_t, &mut st, 0) };
        }
        out.result("fork", denied(r, e, &[libc::EPERM]));
    }
    {
        // SAFETY: a NULL clone_args with size 0 is rejected before anything happens.
        let (r, e) =
            sys(|| unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize) });
        out.result("clone3", denied(r, e, &[libc::ENOSYS]));
    }
    #[cfg(target_arch = "x86_64")]
    {
        // The x32 alias of getpid: the filter's EPERM, never the kernel's ENOSYS (a kernel without
        // CONFIG_X86_X32_ABI says ENOSYS whether or not the filter is there).
        // SAFETY: getpid takes no arguments.
        let (r, e) = sys(|| unsafe { libc::syscall(0x4000_0000 | libc::SYS_getpid) });
        out.result("x32_syscall", denied(r, e, &[libc::EPERM]));
    }
    {
        // SAFETY: re-arming the same parent-death signal; harmless even if allowed.
        let (r, e) = sys(
            || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) }
                as libc::c_long,
        );
        out.result("pdeathsig_locked", denied(r, e, &[libc::EPERM]));
    }
    {
        // SAFETY: getter/setter prctls with integer arguments; the old value is put back if the
        // set ever succeeded.
        let before = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        let (r, e) =
            sys(|| unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } as libc::c_long);
        if r == 0 && before >= 0 {
            // SAFETY: as above.
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, before, 0, 0, 0) };
        }
        out.result("prctl_set_dumpable", denied(r, e, &[libc::EPERM]));
        // 0 clears any ptracer: harmless even if allowed.
        // SAFETY: integer arguments.
        let (r, e) = sys(
            || unsafe { libc::prctl(crate::restrict::PR_SET_PTRACER, 0, 0, 0, 0) } as libc::c_long,
        );
        out.result("prctl_set_ptracer", denied(r, e, &[libc::EPERM]));
    }
    {
        let c: libc::c_char = b'x' as libc::c_char;
        // SAFETY: fd -1 makes even an unfiltered call fail with EBADF.
        let (r, e) = sys(|| unsafe { libc::ioctl(-1, libc::TIOCSTI, &c) } as libc::c_long);
        out.result("ioctl_tiocsti", denied(r, e, &[libc::EPERM]));
    }
    {
        let mut tried = 0;
        let mut wrong = Vec::new();
        for s in denied_syscalls(&profile)
            .into_iter()
            .filter(|s| s.probe_with_bogus_args)
        {
            tried += 1;
            let m = -1 as libc::c_long;
            // SAFETY: all-ones arguments make every listed syscall fail harmlessly (bad fd, bad
            // pointer, bad flags or missing capability) even if it were not filtered.
            let (r, e) = sys(|| unsafe { libc::syscall(s.nr, m, m, m, m, m, m) });
            if r >= 0 || e != libc::EPERM {
                wrong.push(format!(
                    "{}={}",
                    s.name,
                    if r >= 0 {
                        format!("ok({r})")
                    } else {
                        errname(e)
                    }
                ));
            }
        }
        let detail = if wrong.is_empty() {
            format!("all {tried} denied syscalls return EPERM")
        } else {
            format!("not EPERM: {}", wrong.join(","))
        };
        out.check("seccomp_denylist", wrong.is_empty() && tried > 0, detail);
    }

    if is_broker {
        broker_checks(a, &mut out);
    } else {
        no_network_checks(a, inet_sock, &mut out);
    }
    close(unix_sock);
    close(inet_sock);
    close(root_dir);

    // Last: if exec worked, this process is gone and DONE never prints.
    let _ = io::stdout().flush();
    // Outside the sandbox, a path that does not exist exercises the same check without replacing
    // the process (ENOENT, not the filter's EPERM).
    let target = if a.unrestricted {
        "/nonexistent/zkminer-probe-exec"
    } else {
        "/bin/true"
    };
    let path = CString::new(target).unwrap_or_default();
    let argv = [path.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<libc::c_char>()];
    // SAFETY: NULL-terminated argv/envp of valid C strings.
    let (r, e) = sys(
        || unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) } as libc::c_long,
    );
    let (ok, d) = denied(r, e, &[libc::EPERM]);
    out.check("execve", ok, format!("{d} ({target})"));

    out.done();
    0
}

/// ptrace and `process_vm_readv` against the pre-sandbox child.
fn tracee_checks(tracee: Result<libc::pid_t, i32>, out: &mut Out) {
    let pid = match tracee {
        Ok(pid) => pid,
        Err(e) => {
            let d = format!(
                "could not fork the tracee before restricting: {}",
                errname(e)
            );
            out.check("ptrace_attach_child", false, d.clone());
            out.check("process_vm_readv_child", false, d);
            return;
        }
    };
    // SAFETY: integer arguments; a successful attach is waited for and detached again.
    let (r, e) = sys(|| unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0usize, 0usize) });
    if r >= 0 {
        let mut st = 0;
        // SAFETY: waits for the attach stop of our own child, then detaches.
        unsafe {
            libc::waitpid(pid, &mut st, libc::__WALL);
            libc::ptrace(libc::PTRACE_DETACH, pid, 0usize, 0usize);
        }
    }
    let (ok, d) = denied(r, e, &[libc::EPERM]);
    out.check(
        "ptrace_attach_child",
        ok,
        format!("{d} (PTRACE_ATTACH to own child {pid})"),
    );

    let mut buf = [0u8; 8];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: TRACEE_MARK.as_ptr() as *mut libc::c_void,
        iov_len: TRACEE_MARK.len(),
    };
    // SAFETY: `local` points at `buf`; the remote address is only read by the kernel.
    let (r, e) =
        sys(|| unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) } as libc::c_long);
    let (ok, d) = denied(r, e, &[libc::EPERM]);
    let got = if r > 0 {
        format!(", read {:?}", String::from_utf8_lossy(&buf))
    } else {
        String::new()
    };
    out.check(
        "process_vm_readv_child",
        ok,
        format!("{d} (own child {pid}{got})"),
    );
}

/// Metadata writes, locks, leases and notifications through an fd the sandbox inherited (the W
/// file, a memfd), which Landlock does not see: it checks rights when a path is opened.
fn inherited_fd_checks(a: &ProbeArgs, root_dir: RawFd, out: &mut Out) {
    const NAMES: [&str; 9] = [
        "fchmod_inherited",
        "fchown_inherited",
        "fsetxattr_inherited",
        "fremovexattr_inherited",
        "flock_inherited",
        "fcntl_setlease_inherited",
        "file_getattr_inherited",
        "file_setattr_inherited",
        "ioctl_setflags_inherited",
    ];
    let eperm = [libc::EPERM];
    match a.meta_fd {
        None => {
            for n in NAMES {
                out.check(n, false, missing("--meta-fd"));
            }
        }
        Some(fd) => {
            let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: fstat writes into `st`.
            let mode = if unsafe { libc::fstat(fd, st.as_mut_ptr()) } == 0 {
                // SAFETY: fstat succeeded.
                unsafe { st.assume_init() }.st_mode & 0o7777
            } else {
                0o600
            };
            // Each call re-applies what is there (mode, owner -1/-1, flags) or is undone at once,
            // so even a missing filter leaves the parent's file as it was.
            // SAFETY (all calls below): integer arguments, or pointers to valid local buffers and
            // NUL-terminated constants.
            let (r, e) = sys(|| unsafe { libc::fchmod(fd, mode) } as libc::c_long);
            out.result("fchmod_inherited", denied(r, e, &eperm));
            let (r, e) = sys(|| unsafe { libc::fchown(fd, u32::MAX, u32::MAX) } as libc::c_long);
            out.result("fchown_inherited", denied(r, e, &eperm));
            let name = c"user.zkminer-probe";
            let (r, e) =
                sys(
                    || unsafe { libc::fsetxattr(fd, name.as_ptr(), b"1".as_ptr().cast(), 1, 0) }
                        as libc::c_long,
                );
            if r == 0 {
                unsafe { libc::fremovexattr(fd, name.as_ptr()) };
            }
            out.result("fsetxattr_inherited", denied(r, e, &eperm));
            let (r, e) =
                sys(
                    || unsafe { libc::fremovexattr(fd, c"user.zkminer-probe-absent".as_ptr()) }
                        as libc::c_long,
                );
            out.result("fremovexattr_inherited", denied(r, e, &eperm));
            let (r, e) =
                sys(|| unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) } as libc::c_long);
            if r == 0 {
                unsafe { libc::flock(fd, libc::LOCK_UN) };
            }
            out.result("flock_inherited", denied(r, e, &eperm));
            let (r, e) =
                sys(|| unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_RDLCK) } as libc::c_long);
            if r == 0 {
                unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_UNLCK) };
            }
            out.result("fcntl_setlease_inherited", denied(r, e, &eperm));
            // struct file_attr (FILE_ATTR_SIZE_VER0): fa_xflags u64, then four u32s.
            let mut attr = [0u64; 3];
            let size = std::mem::size_of_val(&attr);
            let (r, e) = sys(|| unsafe {
                libc::syscall(
                    468,
                    fd,
                    c"".as_ptr(),
                    attr.as_mut_ptr(),
                    size,
                    libc::AT_EMPTY_PATH,
                )
            });
            out.result("file_getattr_inherited", denied(r, e, &eperm));
            let (r, e) = sys(|| unsafe {
                libc::syscall(
                    469,
                    fd,
                    c"".as_ptr(),
                    attr.as_mut_ptr(),
                    size,
                    libc::AT_EMPTY_PATH,
                )
            });
            out.result("file_setattr_inherited", denied(r, e, &eperm));
            let mut flags: libc::c_long = 0;
            unsafe { libc::ioctl(fd, 0x8008_6601, &mut flags) }; // FS_IOC_GETFLAGS
            let (r, e) =
                sys(
                    || unsafe { libc::ioctl(fd, crate::restrict::FS_IOC_SETFLAGS as _, &flags) }
                        as libc::c_long,
                );
            out.result("ioctl_setflags_inherited", denied(r, e, &eperm));
        }
    }
    if root_dir < 0 {
        out.check(
            "fcntl_notify_dir",
            false,
            "could not open / before restricting",
        );
    } else {
        // DN_DELETE on /: the rarest event, and the notification is removed at once if it was set.
        // SAFETY: integer arguments.
        let (r, e) = sys(|| unsafe {
            libc::fcntl(root_dir, libc::F_NOTIFY, 0x8 /* DN_DELETE */)
        } as libc::c_long);
        if r == 0 {
            unsafe { libc::fcntl(root_dir, libc::F_NOTIFY, 0) };
        }
        let (ok, d) = denied(r, e, &eperm);
        out.check(
            "fcntl_notify_dir",
            ok,
            format!("{d} (F_NOTIFY on a directory fd held from before)"),
        );
    }
}

/// SysV IPC: a private segment, queue and semaphore set. Anything created (no sandbox) is removed
/// again at once.
fn sysv_checks(out: &mut Out) {
    let eperm = [libc::EPERM];
    let flags = libc::IPC_CREAT | 0o600;
    // SAFETY (all): integer arguments; IPC_RMID with a NULL buffer.
    let (r, e) = sys(|| unsafe { libc::shmget(libc::IPC_PRIVATE, 4096, flags) } as libc::c_long);
    if r >= 0 {
        unsafe { libc::shmctl(r as i32, libc::IPC_RMID, std::ptr::null_mut()) };
    }
    out.result("sysv_shmget", denied(r, e, &eperm));
    let (r, e) = sys(|| unsafe { libc::msgget(libc::IPC_PRIVATE, flags) } as libc::c_long);
    if r >= 0 {
        unsafe { libc::msgctl(r as i32, libc::IPC_RMID, std::ptr::null_mut()) };
    }
    out.result("sysv_msgget", denied(r, e, &eperm));
    let (r, e) = sys(|| unsafe { libc::semget(libc::IPC_PRIVATE, 1, flags) } as libc::c_long);
    if r >= 0 {
        unsafe { libc::semctl(r as i32, 0, libc::IPC_RMID) };
    }
    out.result("sysv_semget", denied(r, e, &eperm));
}

fn no_network_checks(a: &ProbeArgs, inet_sock: RawFd, out: &mut Out) {
    for (name, domain) in [
        ("socket_inet", libc::AF_INET),
        ("socket_inet6", libc::AF_INET6),
    ] {
        let (r, e) = new_socket(domain, libc::SOCK_STREAM);
        close(r as RawFd);
        out.result(name, denied(r, e, &[libc::EPERM]));
    }
    match (a.listen_port, inet_sock >= 0) {
        (Some(port), true) => {
            let addr = loopback(port);
            // SAFETY: `addr` is a valid sockaddr_in.
            let (r, e) = sys(|| unsafe {
                libc::connect(
                    inet_sock,
                    (&addr as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            } as libc::c_long);
            let (ok, d) = denied(r, e, &[libc::EPERM, libc::EACCES]);
            out.check(
                "tcp_connect_loopback",
                ok,
                format!("{d} to 127.0.0.1:{port} (a listening port)"),
            );
        }
        (None, _) => out.check("tcp_connect_loopback", false, missing("--listen-port")),
        (_, false) => out.check(
            "tcp_connect_loopback",
            false,
            "could not create a socket before restricting",
        ),
    }
}

/// How a socket the broker must not have was tried.
enum Reach {
    /// `connect` to 127.0.0.1:port.
    Connect(u16),
    /// `sendto` 127.0.0.1:port.
    SendTo(u16, &'static [u8]),
}

/// Pass iff `socket(domain, ty, proto)` fails with `EPERM`. If it is created (no sandbox), it is
/// pointed at a port not in `tcp_connect_ports` and the detail says whether that got through.
fn denied_socket(
    domain: libc::c_int,
    ty: libc::c_int,
    proto: libc::c_int,
    reach: Option<Reach>,
) -> (bool, String) {
    // SAFETY: socket takes integers.
    let (fd, e) =
        sys(|| unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC, proto) } as libc::c_long);
    if fd < 0 {
        return denied(fd, e, &[libc::EPERM]);
    }
    let fd = fd as RawFd;
    let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let detail =
        match reach {
            None => "created".to_string(),
            Some(Reach::Connect(port)) => {
                let addr = loopback(port);
                // SAFETY: `addr` is a valid sockaddr_in of `len` bytes.
                let (r, e) = sys(|| unsafe {
                    libc::connect(fd, (&addr as *const libc::sockaddr_in).cast(), len)
                } as libc::c_long);
                format!(
                    "created; connect to 127.0.0.1:{port}: {}",
                    if r == 0 {
                        "connected".into()
                    } else {
                        errname(e)
                    }
                )
            }
            Some(Reach::SendTo(port, payload)) => {
                let addr = loopback(port);
                // SAFETY: `payload` and `addr` are valid for the lengths passed.
                let (r, e) = sys(|| unsafe {
                    libc::sendto(
                        fd,
                        payload.as_ptr().cast(),
                        payload.len(),
                        0,
                        (&addr as *const libc::sockaddr_in).cast(),
                        len,
                    )
                } as libc::c_long);
                format!(
                    "created; sendto 127.0.0.1:{port}: {}",
                    if r >= 0 {
                        format!("{r} bytes sent")
                    } else {
                        errname(e)
                    }
                )
            }
        };
    close(fd);
    (false, detail)
}

/// Pass iff `socketpair(AF_UNIX, ty)` fails with `EPERM`.
fn denied_pair(ty: libc::c_int) -> (bool, String) {
    let mut sv = [-1 as RawFd; 2];
    // SAFETY: socketpair writes two fds into `sv`.
    let (r, e) = sys(|| unsafe {
        libc::socketpair(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr())
    } as libc::c_long);
    if r == 0 {
        close(sv[0]);
        close(sv[1]);
    }
    denied(r, e, &[libc::EPERM])
}

fn broker_checks(a: &ProbeArgs, out: &mut Out) {
    let (r, e) = new_socket(libc::AF_INET, libc::SOCK_STREAM);
    close(r as RawFd);
    out.check(
        "socket_inet_allowed",
        r >= 0,
        if r >= 0 { "ok".into() } else { errname(e) },
    );
    let (r, e) = new_socket(libc::AF_INET6, libc::SOCK_STREAM);
    close(r as RawFd);
    // A kernel without IPv6 says EAFNOSUPPORT: still not the filter.
    out.check(
        "socket_inet6_allowed",
        r >= 0 || e != libc::EPERM,
        if r >= 0 { "ok".into() } else { errname(e) },
    );
    {
        // How hyper (socket2) asks: protocol IPPROTO_TCP, with SOCK_NONBLOCK | SOCK_CLOEXEC.
        // SAFETY: socket takes integers.
        let (r, e) = sys(|| unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::IPPROTO_TCP,
            )
        } as libc::c_long);
        close(r as RawFd);
        out.check(
            "socket_inet_tcp_allowed",
            r >= 0,
            if r >= 0 { "ok".into() } else { errname(e) },
        );
    }
    // Landlock restricts TCP only: every other socket the broker could make reaches any port.
    let deny = a.deny_port;
    let need = |out: &mut Out, name: &str| out.check(name, false, missing("--deny-port"));
    match deny {
        Some(port) => {
            let (ok, d) = denied_socket(
                libc::AF_INET,
                libc::SOCK_DGRAM,
                0,
                Some(Reach::SendTo(port, b"zkminer-probe-udp")),
            );
            out.check("socket_udp", ok, d);
            let (ok, d) = denied_socket(
                libc::AF_INET,
                libc::SOCK_STREAM,
                libc::IPPROTO_MPTCP,
                Some(Reach::Connect(port)),
            );
            out.check("socket_mptcp", ok, d);
        }
        None => {
            need(out, "socket_udp");
            need(out, "socket_mptcp");
        }
    }
    // An ICMP echo request (type 8) to 127.0.0.1; ping sockets have no port.
    const ECHO: &[u8] = &[8, 0, 0, 0, 0, 0, 0, 1, b'z', b'k'];
    let (ok, d) = denied_socket(
        libc::AF_INET,
        libc::SOCK_DGRAM,
        libc::IPPROTO_ICMP,
        Some(Reach::SendTo(0, ECHO)),
    );
    out.check("socket_icmp", ok, d);
    let (ok, d) = denied_socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP, None);
    out.check("socket_raw", ok, d);

    {
        let mut sv = [-1 as RawFd; 2];
        // SAFETY: socketpair writes two fds into `sv`.
        let (r, e) = sys(|| unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                sv.as_mut_ptr(),
            )
        } as libc::c_long);
        close(sv[0]);
        close(sv[1]);
        out.check(
            "socketpair_unix_stream_allowed",
            r == 0,
            if r == 0 {
                "ok (tokio's signal driver)".into()
            } else {
                errname(e)
            },
        );
    }
    out.result("socketpair_unix_dgram", denied_pair(libc::SOCK_DGRAM));
    out.result(
        "socketpair_unix_seqpacket",
        denied_pair(libc::SOCK_SEQPACKET),
    );

    match a.listen_port {
        Some(port) => {
            let r = TcpStream::connect(("127.0.0.1", port));
            let d = match &r {
                Ok(_) => format!("connected to allowed 127.0.0.1:{port}"),
                Err(e) => format!("{e} to allowed 127.0.0.1:{port}"),
            };
            out.check("tcp_connect_allowed_port", r.is_ok(), d);
        }
        None => out.check("tcp_connect_allowed_port", false, missing("--listen-port")),
    }
    match a.deny_port {
        Some(port) => {
            let (ok, d) = denied_io(TcpStream::connect(("127.0.0.1", port)), &[libc::EACCES]);
            out.check(
                "tcp_connect_denied_port",
                ok,
                format!(
                    "{d} to listening 127.0.0.1:{port} not in tcp_connect_ports (Landlock layer)"
                ),
            );
        }
        None => out.check("tcp_connect_denied_port", false, missing("--deny-port")),
    }
    out.result(
        "tcp_bind",
        denied_io(
            TcpListener::bind("127.0.0.1:0"),
            &[libc::EPERM, libc::EACCES],
        ),
    );

    let mut problems = Vec::new();
    for p in &a.readable {
        let r = if p.is_dir() {
            std::fs::read_dir(p).map(|_| ())
        } else {
            std::fs::read(p).map(|_| ())
        };
        if let Err(e) = r {
            problems.push(format!("{}: {e}", p.display()));
        }
    }
    out.check(
        "read_readable",
        problems.is_empty() && !a.readable.is_empty(),
        if a.readable.is_empty() {
            missing("--readable")
        } else if problems.is_empty() {
            format!("{} paths readable", a.readable.len())
        } else {
            problems.join("; ")
        },
    );

    let mut problems = Vec::new();
    for p in &a.readable {
        let target = if p.is_dir() {
            p.join(format!("zkminer-probe-{}", a.tag))
        } else {
            p.clone()
        };
        let r = std::fs::OpenOptions::new()
            .write(true)
            .create(p.is_dir())
            .truncate(false)
            .open(&target);
        if r.is_ok() && p.is_dir() {
            let _ = std::fs::remove_file(&target);
        }
        let (ok, d) = denied_io(r, &[libc::EACCES]);
        if !ok {
            problems.push(format!("{}: {d}", target.display()));
        }
    }
    out.check(
        "readable_not_writable",
        problems.is_empty() && !a.readable.is_empty(),
        if a.readable.is_empty() {
            missing("--readable")
        } else if problems.is_empty() {
            "EACCES".to_string()
        } else {
            problems.join("; ")
        },
    );

    let mut problems = Vec::new();
    for dir in &a.writable {
        let f = dir.join(format!("zkminer-probe-{}", a.tag));
        let g = dir.join(format!("zkminer-probe-{}.renamed", a.tag));
        let r = std::fs::write(&f, b"spool")
            .and_then(|_| std::fs::rename(&f, &g))
            .and_then(|_| std::fs::read(&g))
            .and_then(|b| {
                if b == b"spool" {
                    Ok(())
                } else {
                    Err(io::Error::other("content mismatch"))
                }
            })
            .and_then(|_| std::fs::remove_file(&g));
        if let Err(e) = r {
            problems.push(format!("{}: {e}", dir.display()));
        }
    }
    out.check(
        "write_writable",
        problems.is_empty() && !a.writable.is_empty(),
        if a.writable.is_empty() {
            missing("--writable")
        } else if problems.is_empty() {
            format!("{} spool dirs writable", a.writable.len())
        } else {
            problems.join("; ")
        },
    );
}

// ---------------------------------------------------------------------------------------------
// cgroup modes

/// Allocates and touches `bytes` (past `memory.max`): the parent expects an OOM kill.
fn run_oom(a: &ProbeArgs) -> i32 {
    if let Err(e) = restrict_self(&a.profile()) {
        println!("ERROR {e}");
        return 2;
    }
    println!("RESTRICTED");
    let _ = io::stdout().flush();
    let mut v: Vec<u8> = Vec::new();
    // Grow in 1 MiB steps, touching every byte, so the charge rises gradually.
    let step = 1 << 20;
    while (v.len() as u64) < a.bytes {
        v.resize(v.len() + step, 1);
    }
    std::hint::black_box(&v);
    println!("SURVIVED {}", v.len());
    0
}

/// Tries to fork, then starts threads until `pids.max` stops it (threads are tasks too).
fn run_pids(a: &ProbeArgs) -> i32 {
    if let Err(e) = restrict_self(&a.profile()) {
        println!("ERROR {e}");
        return 2;
    }
    let _ = io::stdout().flush();
    // SAFETY: the child (if any) exits immediately.
    let pid = unsafe { libc::fork() };
    let fork_errno = match pid {
        -1 => errno(),
        0 => unsafe { libc::_exit(0) },
        p => {
            let mut st = 0;
            // SAFETY: reaps the child we forked.
            unsafe { libc::waitpid(p, &mut st, 0) };
            0
        }
    };
    let mut threads = 0u32;
    let mut err = 0;
    while threads < a.max_tasks {
        match std::thread::Builder::new()
            .stack_size(64 << 10)
            .spawn(|| loop {
                std::thread::park();
            }) {
            Ok(_) => threads += 1,
            Err(e) => {
                err = e.raw_os_error().unwrap_or(-1);
                break;
            }
        }
    }
    println!("PIDS fork_errno={fork_errno} threads={threads} errno={err}");
    let _ = io::stdout().flush();
    0
}

// ---------------------------------------------------------------------------------------------
// test helpers

/// Unrestricted: prints `FD <n> <st_dev> <st_ino>` for every open fd, `ENV <name>` for every
/// environment variable and `CGROUP <path>`, then reads stdin to EOF (a parent that keeps stdin
/// open keeps the probe alive).
fn run_fds() -> i32 {
    for fd in open_fds() {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat writes into `st`.
        if unsafe { libc::fstat(fd, st.as_mut_ptr()) } == 0 {
            // SAFETY: fstat succeeded.
            let st = unsafe { st.assume_init() };
            println!("FD {fd} {} {}", st.st_dev, st.st_ino);
        }
    }
    for (k, _) in std::env::vars_os() {
        println!("ENV {}", k.to_string_lossy());
    }
    let cg = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    println!(
        "CGROUP {}",
        crate::cgroup::parse_proc_cgroup(&cg).unwrap_or("")
    );
    println!("DONE");
    let _ = io::stdout().flush();
    let mut sink = Vec::new();
    let _ = io::stdin().read_to_end(&mut sink);
    0
}

/// Starts a thread, then calls [`restrict_self`]: prints `THREADED <error>` (or `THREADED ok`,
/// which would be a bug).
fn run_threaded(a: &ProbeArgs) -> i32 {
    let _t = std::thread::spawn(|| loop {
        std::thread::park();
    });
    match restrict_self(&a.profile()) {
        Ok(_) => println!("THREADED ok"),
        Err(e) => println!("THREADED {e}"),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_round_trip() {
        let mut a = ProbeArgs::new(ProfileKind::Broker);
        a.readable = vec!["/a b/endpoints".into()];
        a.writable = vec!["/spool".into()];
        a.ports = vec![443, 8545];
        a.secret = Some("/tmp/secret".into());
        a.listen_port = Some(4000);
        a.deny_port = Some(4001);
        a.abstract_name = Some("zk-1".into());
        a.meta_fd = Some(5);
        a.expect_fds = vec![0, 1, 2, 3, 4, 5];
        a.ready_fd = Some(3);
        a.go_fd = Some(4);
        a.bytes = 1 << 29;
        a.max_tasks = 64;
        a.tag = "t1".into();
        a.unrestricted = true;
        let args = a.to_args("checks");
        assert_eq!(args[0], "checks");
        assert_eq!(ProbeArgs::parse(&args[1..]).unwrap(), a);
    }

    #[test]
    fn args_errors() {
        assert!(ProbeArgs::parse(&[]).is_err());
        assert!(ProbeArgs::parse(&["--profile".into(), "nope".into()]).is_err());
        assert!(ProbeArgs::parse(&["--profile".into()]).is_err());
        assert!(ProbeArgs::parse(&[
            "--profile".into(),
            "broker".into(),
            "--bogus".into(),
            "1".into()
        ])
        .is_err());
    }

    #[test]
    fn expected_check_sets() {
        let runner = expected_checks(ProfileKind::BuilderRunner);
        let broker = expected_checks(ProfileKind::Broker);
        assert!(runner.contains(&"socket_inet") && !runner.contains(&"socket_inet_allowed"));
        assert!(broker.contains(&"tcp_connect_denied_port") && !broker.contains(&"socket_inet"));
        let mut all = broker.clone();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), broker.len());
    }

    #[test]
    fn abstract_address_layout() {
        let (addr, len) = abstract_addr("zk");
        assert_eq!(addr.sun_path[0], 0);
        assert_eq!(addr.sun_path[1], b'z' as libc::c_char);
        assert_eq!(len as usize, std::mem::size_of::<libc::sa_family_t>() + 3);
    }
}
