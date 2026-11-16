//! Live checks of [`crate::confine`] and [`crate::supervise`], run by the probe binary
//! (`zkminer-witness-sandbox-probe confined ...` / `supervised ...`) for `tests/confine.rs`: a
//! confinement can only be observed in a process of its own, and the supervisor forks, which needs a
//! single-threaded process (a test harness is not one).
//!
//! Every check prints one line, `CHECK <name> ok <detail>` or `CHECK <name> FAIL <detail>`; what
//! is only observed prints `NOTE <name> <detail>`.

use std::ffi::{CString, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::confine::{confine_all_threads, Confinement, Rights, Sockets};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn check(name: &str, ok: bool, detail: impl std::fmt::Display) {
    println!("CHECK {name} {} {detail}", if ok { "ok" } else { "FAIL" });
    let _ = std::io::stdout().flush();
}

fn note(name: &str, detail: impl std::fmt::Display) {
    println!("NOTE {name} {detail}");
    let _ = std::io::stdout().flush();
}

fn cpath(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).expect("no NUL in a test path")
}

/// The host's Unix sockets a guest that escaped its executor would pivot through: the session bus
/// (systemd --user's StartTransientUnit), the Docker daemon (root-equivalent, host networking),
/// systemd-resolved (the host's resolvers), the system bus, the user's systemd manager.
pub fn pivot_sockets() -> Vec<(&'static str, PathBuf)> {
    // SAFETY: getuid has no arguments.
    let uid = unsafe { libc::getuid() };
    vec![
        ("session_bus", PathBuf::from(format!("/run/user/{uid}/bus"))),
        ("docker", PathBuf::from("/run/docker.sock")),
        ("docker_var", PathBuf::from("/var/run/docker.sock")),
        (
            "resolved_varlink",
            PathBuf::from("/run/systemd/resolve/io.systemd.Resolve"),
        ),
        ("system_bus", PathBuf::from("/run/dbus/system_bus_socket")),
        (
            "systemd_user_private",
            PathBuf::from(format!("/run/user/{uid}/systemd/private")),
        ),
    ]
}

/// `connect` to the Unix stream socket at `path`: Ok, or the errno of the step that failed.
fn unix_connect(path: &Path) -> Result<libc::c_int, (&'static str, i32)> {
    // SAFETY: plain socket call.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(("socket", errno()));
    }
    let rc = connect_fd(fd, path);
    if rc != 0 {
        // SAFETY: closing the fd just opened.
        unsafe { libc::close(fd) };
        return Err(("connect", rc));
    }
    Ok(fd)
}

/// `connect(fd, path)`: 0 or the errno.
fn connect_fd(fd: libc::c_int, path: &Path) -> i32 {
    // SAFETY: a zeroed sockaddr_un filled with a path shorter than sun_path.
    unsafe {
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_bytes();
        if bytes.len() >= addr.sun_path.len() {
            return libc::ENAMETOOLONG;
        }
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
        if libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), len as u32) == 0 {
            0
        } else {
            errno()
        }
    }
}

/// `open(path, flags)`: Ok(()) or the errno.
fn try_open(path: &Path, flags: libc::c_int) -> Result<(), i32> {
    let c = cpath(path);
    // SAFETY: a NUL-terminated path; the fd is closed.
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: closing the fd just opened.
    unsafe { libc::close(fd) };
    Ok(())
}

/// Runs `path` (no arguments) and waits: its exit status, or the errno `execve` failed with in the
/// child (reported as exit code 100 + errno), or the fork's errno.
fn run(path: &Path) -> Result<(i32, String), i32> {
    let c = cpath(path);
    let argv = [c.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    // SAFETY: fork; the child only calls async-signal-safe functions.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(errno());
    }
    if pid == 0 {
        unsafe {
            libc::execve(c.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(100 + *libc::__errno_location());
        }
    }
    let mut st = 0;
    // SAFETY: waiting for the child just forked.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    let code = if libc::WIFEXITED(st) {
        libc::WEXITSTATUS(st)
    } else {
        -libc::WTERMSIG(st)
    };
    Ok((code, String::new()))
}

static GOT_SIGUSR1: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigusr1(_: libc::c_int) {
    GOT_SIGUSR1.store(true, Ordering::SeqCst);
}

struct ConfinedArgs {
    home: PathBuf,
    write: PathBuf,
    exec: Option<PathBuf>,
    sockets: Sockets,
    /// A Unix listener of the test's, connected to before the confinement (`keep`) and after.
    listener: Option<PathBuf>,
    /// A socket to leave open before the confinement (`inet`, `unix-dgram`), which must fail it.
    leak: Option<String>,
    /// Keep a connection to a server this process starts itself, as an SP1 worker does.
    own_server: bool,
    /// A datagram socket of the test's: what a datagram pair could reach with `sendto`, and a
    /// seqpacket pair (allowed where pairs are kept) cannot.
    dgram: Option<PathBuf>,
}

fn parse_confined(args: &[OsString]) -> Result<ConfinedArgs, String> {
    let mut a = ConfinedArgs {
        home: PathBuf::new(),
        write: PathBuf::new(),
        exec: None,
        sockets: Sockets::None,
        listener: None,
        leak: None,
        own_server: false,
        dgram: None,
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))
        };
        match flag.to_str() {
            Some("--home") => a.home = value()?.into(),
            Some("--write") => a.write = value()?.into(),
            Some("--exec") => a.exec = Some(value()?.into()),
            Some("--listener") => a.listener = Some(value()?.into()),
            Some("--leak") => a.leak = Some(value()?.to_string_lossy().into_owned()),
            Some("--own-server") => a.own_server = true,
            Some("--dgram") => a.dgram = Some(value()?.into()),
            Some("--sockets") => {
                a.sockets = match value()?.to_str() {
                    Some("none") => Sockets::None,
                    Some("keep") => Sockets::KeepConnected,
                    other => return Err(format!("unknown sockets policy {other:?}")),
                }
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    if a.home.as_os_str().is_empty() || a.write.as_os_str().is_empty() {
        return Err("--home and --write are required".into());
    }
    Ok(a)
}

/// `confined`: confine this process as an inline worker, then try every way out.
pub fn run_confined(args: &[OsString]) -> i32 {
    let a = match parse_confined(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("confined: {e}");
            return 64;
        }
    };
    // SAFETY: installing a handler that only stores to an atomic.
    unsafe { libc::signal(libc::SIGUSR1, on_sigusr1 as *const () as usize) };

    // A thread from before the confinement, which tries its way out when told to.
    let (go_tx, go_rx) = std::sync::mpsc::channel::<PathBuf>();
    let (res_tx, res_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Ok(home) = go_rx.recv() else {
            return;
        };
        // SAFETY: plain socket call.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let inet = if fd < 0 { errno() } else { 0 };
        let write = try_open(
            &home.join(".config/thread-was-here"),
            libc::O_WRONLY | libc::O_CREAT,
        );
        res_tx.send((inet, write)).unwrap();
    });

    // Before: which pivots are there to be refused.
    let pivots = pivot_sockets();
    for (name, path) in &pivots {
        match unix_connect(path) {
            Ok(fd) => {
                // SAFETY: closing the fd just opened.
                unsafe { libc::close(fd) };
                note(&format!("before_{name}"), "connect ok");
            }
            Err((step, e)) => note(&format!("before_{name}"), format!("{step} errno {e}")),
        }
    }
    let own_server = a.write.join("own.sock");
    if a.own_server {
        let listener = std::os::unix::net::UnixListener::bind(&own_server).unwrap();
        // SAFETY: fork; the child serves one connection and exits.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            use std::io::Read;
            let code = match listener.accept() {
                Ok((mut conn, _)) => {
                    let mut buf = [0u8; 5];
                    if conn.read_exact(&mut buf).is_ok() && &buf == b"kept\n" {
                        println!("OWN SERVER GOT kept");
                        0
                    } else {
                        1
                    }
                }
                Err(_) => 1,
            };
            let _ = std::io::stdout().flush();
            // SAFETY: leaving the child.
            unsafe { libc::_exit(code) };
        }
        drop(listener);
    }
    let kept_target = if a.own_server {
        Some(own_server.clone())
    } else {
        a.listener.clone()
    };
    let kept = match (&kept_target, a.sockets) {
        (Some(l), Sockets::KeepConnected) => match unix_connect(l) {
            Ok(fd) => Some(fd),
            Err((step, e)) => {
                check("keep_connect_before", false, format!("{step} errno {e}"));
                return 1;
            }
        },
        _ => None,
    };

    if let Some(leak) = &a.leak {
        let (domain, kind) = match leak.as_str() {
            "inet" => (libc::AF_INET, libc::SOCK_DGRAM),
            _ => (libc::AF_UNIX, libc::SOCK_DGRAM),
        };
        // SAFETY: plain socket call; the fd is left open on purpose.
        let fd = unsafe { libc::socket(domain, kind, 0) };
        note("leaked", format!("{leak} fd {fd}"));
    }
    let mut c = Confinement::with_system(a.sockets);
    c.allow(&a.write, Rights::WRITE);
    if let Some(exec) = &a.exec {
        c.allow(exec, Rights::EXEC);
    }
    match confine_all_threads(&c) {
        Ok(report) => check("confine", true, report),
        Err(e) => {
            check("confine", false, e);
            return 1;
        }
    }

    for (name, path) in &pivots {
        let r = unix_connect(path);
        check(
            &format!("pivot_{name}"),
            matches!(r, Err((_, libc::EPERM))),
            match r {
                Ok(fd) => {
                    // SAFETY: closing the fd just opened.
                    unsafe { libc::close(fd) };
                    "CONNECTED".to_string()
                }
                Err((step, e)) => format!("{step} errno {e}"),
            },
        );
    }
    if let Some(l) = &a.listener {
        let r = unix_connect(l);
        check(
            "new_connection_to_listener",
            matches!(r, Err((_, libc::EPERM))),
            format!("{r:?}"),
        );
    }
    if let (Sockets::KeepConnected, Some(dgram)) = (a.sockets, &a.dgram) {
        seqpacket_pair_reaches_nothing(dgram);
    }
    if let Some(fd) = kept {
        // SAFETY: writing to the connection kept from before.
        let n = unsafe { libc::write(fd, b"kept\n".as_ptr().cast(), 5) };
        check("kept_connection_usable", n == 5, format!("write -> {n}"));
        if a.own_server {
            let mut st = 0;
            // SAFETY: waiting for the own server child.
            unsafe { libc::wait(&mut st) };
            check(
                "own_server_got_it",
                libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
                format!("status {st:#x}"),
            );
        }
        // connect on an existing (unconnected) socket is refused too: nothing to make one with.
    }
    for (name, domain, kind) in [
        ("unix_stream", libc::AF_UNIX, libc::SOCK_STREAM),
        ("unix_dgram", libc::AF_UNIX, libc::SOCK_DGRAM),
        ("unix_seqpacket", libc::AF_UNIX, libc::SOCK_SEQPACKET),
        ("inet", libc::AF_INET, libc::SOCK_STREAM),
        ("inet6_udp", libc::AF_INET6, libc::SOCK_DGRAM),
        ("netlink", libc::AF_NETLINK, libc::SOCK_RAW),
    ] {
        // SAFETY: plain socket call.
        let fd = unsafe { libc::socket(domain, kind, 0) };
        let e = errno();
        check(
            &format!("socket_{name}"),
            fd < 0 && e == libc::EPERM,
            format!("fd {fd} errno {e}"),
        );
    }

    // The home directory: nothing to read or write but what is named.
    let home = &a.home;
    for (name, path, flags) in [
        (
            "write_config_autostart",
            home.join(".config/autostart/zk.desktop"),
            libc::O_WRONLY | libc::O_CREAT,
        ),
        (
            "write_config_systemd_unit",
            home.join(".config/systemd/user/zk.service"),
            libc::O_WRONLY | libc::O_CREAT,
        ),
        (
            "write_environment_d",
            home.join(".config/environment.d/zk.conf"),
            libc::O_WRONLY | libc::O_CREAT,
        ),
        (
            "append_bashrc",
            home.join(".bashrc"),
            libc::O_WRONLY | libc::O_APPEND,
        ),
        (
            "overwrite_prover",
            home.join(".zkminer/provers/zkminer-prove-risc0-cuda"),
            libc::O_WRONLY | libc::O_TRUNC,
        ),
        (
            "write_miner_config",
            home.join(".zkminer/config.toml"),
            libc::O_WRONLY | libc::O_TRUNC,
        ),
        (
            "read_key",
            home.join(".zkminer/keystore.json"),
            libc::O_RDONLY,
        ),
        ("read_ssh_key", home.join(".ssh/id_ed25519"), libc::O_RDONLY),
        (
            "write_tmp",
            PathBuf::from("/tmp/zkminer-confine-probe-must-not-exist"),
            libc::O_WRONLY | libc::O_CREAT,
        ),
        (
            "write_dev_shm",
            PathBuf::from("/dev/shm/zkminer-confine-probe-must-not-exist"),
            libc::O_WRONLY | libc::O_CREAT,
        ),
    ] {
        let r = try_open(&path, flags);
        check(
            name,
            r == Err(libc::EACCES),
            format!("{} -> {r:?}", path.display()),
        );
    }
    let own = a.write.join("allowed");
    let r = try_open(&own, libc::O_WRONLY | libc::O_CREAT);
    check("write_own_dir", r.is_ok(), format!("{r:?}"));
    let fifo = cpath(&a.write.join("fifo"));
    // SAFETY: a NUL-terminated path.
    let rc = unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) };
    let e = errno();
    check(
        "mkfifo_refused",
        rc != 0 && (e == libc::EPERM || e == libc::EACCES),
        format!("errno {e}"),
    );
    let r = try_open(Path::new("/etc/hostname"), libc::O_RDONLY);
    check(
        "read_system_file",
        r.is_ok() || r == Err(libc::ENOENT),
        format!("{r:?}"),
    );

    // Other processes: the parent (the test, standing in for the miner).
    // SAFETY: getppid; kill with signal 0 and SIGTERM send nothing that is not refused.
    let parent = unsafe { libc::getppid() };
    let rc = unsafe { libc::kill(parent, 0) };
    let e = errno();
    check(
        "signal_parent_0",
        rc != 0 && e == libc::EPERM,
        format!("rc {rc} errno {e}"),
    );
    let rc = unsafe { libc::kill(parent, libc::SIGTERM) };
    let e = errno();
    check(
        "signal_parent_term",
        rc != 0 && e == libc::EPERM,
        format!("rc {rc} errno {e}"),
    );
    for f in ["environ", "mem", "maps"] {
        let r = try_open(Path::new(&format!("/proc/{parent}/{f}")), libc::O_RDONLY);
        check(
            &format!("proc_parent_{f}"),
            r == Err(libc::EACCES),
            format!("{r:?}"),
        );
    }
    // SAFETY: an invalid ptrace request; refused by the filter before the kernel looks.
    let rc = unsafe { libc::ptrace(libc::PTRACE_ATTACH, parent, 0, 0) };
    let e = errno();
    check(
        "ptrace_parent",
        rc != 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    // SAFETY: an io_uring setup with no params; refused by the filter.
    let rc = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1, std::ptr::null_mut::<u8>()) };
    let e = errno();
    check("io_uring", rc < 0 && e == libc::EPERM, format!("errno {e}"));

    // The thread from before.
    go_tx.send(home.clone()).unwrap();
    let (inet, write) = res_rx.recv().unwrap();
    check(
        "old_thread_socket",
        inet == libc::EPERM,
        format!("errno {inet}"),
    );
    check(
        "old_thread_home_write",
        write == Err(libc::EACCES),
        format!("{write:?}"),
    );

    // Programs: only what was named runs, and it inherits all of it.
    let r = run(Path::new("/usr/bin/true"));
    check(
        "exec_unnamed",
        r == Ok((100 + libc::EACCES, String::new())),
        format!("{r:?}"),
    );
    if let Some(exec) = &a.exec {
        let r = run(exec);
        check(
            "exec_named",
            r.as_ref().is_ok_and(|(c, _)| *c == 0),
            format!("{r:?}"),
        );
    }

    println!("CONFINED CHECKS DONE");
    let _ = std::io::stdout().flush();
    // The test signals this process now: the miner can still reach its workers.
    for _ in 0..300 {
        if GOT_SIGUSR1.load(Ordering::SeqCst) {
            println!("GOT SIGUSR1");
            return 0;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    println!("NO SIGUSR1");
    2
}

/// `supervised <socket> <home> <write>`: run this binary's `supervised-child` under the supervisor,
/// as an SP1 worker runs `sp1-gpu-server`.
pub fn run_supervised_parent(args: &[OsString]) -> i32 {
    let [socket, home, write] = args else {
        eprintln!("supervised: <socket> <home> <write>");
        return 64;
    };
    let socket = PathBuf::from(socket);
    let Some(dir) = socket.parent() else {
        return 64;
    };
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("supervised: {e}");
            return 1;
        }
    };
    let mut c = Confinement::with_system(Sockets::Supervised);
    c.allow(dir, Rights::MAKE_SOCK);
    c.allow(write, Rights::WRITE);
    c.allow(&exe, Rights::EXEC);
    println!("SUPERVISOR {}", std::process::id());
    let _ = std::io::stdout().flush();
    match crate::supervise::run_supervised(
        &exe,
        &[
            "supervised-child".into(),
            socket.into_os_string(),
            home.clone(),
        ],
        &c,
    ) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("supervised: {e}");
            1
        }
    }
}

/// `supervised-child <socket> <home>`: the server's part. Listens at `<socket>`, accepts one
/// connection, then tries its way out and reports each check on stdout and on the connection.
pub fn run_supervised_child(args: &[OsString]) -> i32 {
    let [socket, home] = args else {
        return 64;
    };
    let socket = PathBuf::from(socket);
    let home = PathBuf::from(home);
    // SAFETY: getpid has no arguments.
    println!("SERVER {}", unsafe { libc::getpid() });
    // Before the first connection: a CUDA-style seqpacket listener, then its own.
    // SAFETY: plain socket calls.
    let pre = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    check(
        "pre_accept_seqpacket_socket",
        pre >= 0,
        format!("fd {pre} errno {}", errno()),
    );
    let inet = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let e = errno();
    check(
        "pre_accept_inet_refused",
        inet < 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    let dgram = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    let e = errno();
    check(
        "pre_accept_dgram_refused",
        dgram < 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    for (name, path) in pivot_sockets() {
        if !path.exists() {
            continue;
        }
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        let rc = connect_fd(fd, &path);
        check(
            &format!("pre_accept_connect_{name}"),
            rc == libc::EPERM,
            format!("errno {rc}"),
        );
        unsafe { libc::close(fd) };
    }
    let lfd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if lfd < 0 {
        check("listen", false, format!("socket errno {}", errno()));
        return 1;
    }
    // SAFETY: a sockaddr_un filled with a short path.
    let bound = unsafe {
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, b) in socket.as_os_str().as_bytes().iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        libc::bind(
            lfd,
            (&addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as u32,
        ) == 0
            && libc::listen(lfd, 4) == 0
    };
    check("listen", bound, format!("errno {}", errno()));
    if !bound {
        return 1;
    }
    println!("LISTENING");
    let _ = std::io::stdout().flush();
    // SAFETY: accepting on our listener.
    let conn = unsafe {
        libc::accept4(
            lfd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if conn < 0 {
        check("accept", false, format!("errno {}", errno()));
        return 1;
    }
    let mut lines: Vec<String> = Vec::new();
    let mut report = |name: &str, ok: bool, detail: String| {
        check(name, ok, &detail);
        lines.push(format!(
            "CHECK {name} {} {detail}\n",
            if ok { "ok" } else { "FAIL" }
        ));
    };
    // After the first connection: no new socket, bind or listen.
    for (name, domain, kind) in [
        ("unix_stream", libc::AF_UNIX, libc::SOCK_STREAM),
        ("unix_seqpacket", libc::AF_UNIX, libc::SOCK_SEQPACKET),
        ("inet", libc::AF_INET, libc::SOCK_STREAM),
    ] {
        let fd = unsafe { libc::socket(domain, kind, 0) };
        let e = errno();
        report(
            &format!("post_accept_socket_{name}"),
            fd < 0 && e == libc::EPERM,
            format!("fd {fd} errno {e}"),
        );
    }
    // The seqpacket socket from before cannot be bound or made to listen now.
    let rc = unsafe { libc::listen(pre, 4) };
    let e = errno();
    report(
        "post_accept_listen",
        rc != 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    let abstract_bound = unsafe {
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let name = b"\0zkminer-probe-abstract";
        for (i, b) in name.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        libc::bind(
            pre,
            (&addr as *const libc::sockaddr_un).cast(),
            (2 + name.len()) as u32,
        )
    };
    let e = errno();
    report(
        "post_accept_bind_abstract",
        abstract_bound != 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    let rc = connect_fd(pre, &socket);
    report(
        "post_accept_connect",
        rc == libc::EPERM,
        format!("errno {rc}"),
    );
    let mut pair = [-1; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
    report(
        "stream_pair_allowed",
        rc == 0,
        format!("rc {rc} errno {}", errno()),
    );
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, pair.as_mut_ptr()) };
    let e = errno();
    report(
        "dgram_pair_refused",
        rc != 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    // No notifying filter of its own, to answer in the supervisor's place.
    let prog = crate::netdeny::notify_filter();
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1,
            crate::netdeny::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog,
        )
    };
    let e = errno();
    report(
        "own_listener_refused",
        rc < 0 && (e == libc::EPERM || e == libc::EBUSY),
        format!("errno {e}"),
    );
    // The supervisor and the home directory are out of reach.
    let sup = unsafe { libc::getppid() };
    let rc = unsafe { libc::kill(sup, 0) };
    let e = errno();
    report(
        "signal_supervisor",
        rc != 0 && e == libc::EPERM,
        format!("errno {e}"),
    );
    let r = try_open(Path::new(&format!("/proc/{sup}/environ")), libc::O_RDONLY);
    report(
        "proc_supervisor_environ",
        r == Err(libc::EACCES),
        format!("{r:?}"),
    );
    let r = try_open(
        &home.join(".config/autostart/zk.desktop"),
        libc::O_WRONLY | libc::O_CREAT,
    );
    report(
        "write_config_autostart",
        r == Err(libc::EACCES),
        format!("{r:?}"),
    );
    let r = try_open(
        Path::new("/tmp/zkminer-confine-probe-must-not-exist"),
        libc::O_WRONLY | libc::O_CREAT,
    );
    report("write_tmp", r == Err(libc::EACCES), format!("{r:?}"));
    // Starting a helper the way Rust's `Command` does when code runs before `exec` (fork, a
    // seqpacket pair to report a failed exec, the parent-death signal): as sp1-gpu-server starts
    // its Groth16 CPU helper, which is itself.
    {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new("/proc/self/exe");
        cmd.arg("noop").stdin(std::process::Stdio::null());
        // SAFETY: prctl is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let r = cmd.status();
        report(
            "spawn_own_helper",
            r.as_ref().is_ok_and(|s| s.success()),
            format!("{r:?}"),
        );
    }
    let stdin_null = std::fs::read_link("/proc/self/fd/0")
        .map(|p| p == Path::new("/dev/null"))
        .unwrap_or(false);
    report("stdin_is_dev_null", stdin_null, String::new());
    lines.push("DONE\n".into());
    for l in &lines {
        // SAFETY: writing to the accepted connection.
        unsafe { libc::write(conn, l.as_ptr().cast(), l.len()) };
    }
    unsafe { libc::close(conn) };
    println!("SERVER DONE");
    let _ = std::io::stdout().flush();
    // Stay up until killed, if asked to (`ZKMINER_PROBE_LINGER`), for the parent-death test.
    if std::env::var_os("ZKMINER_PROBE_LINGER").is_some() {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    0
}

/// A seqpacket pair (allowed where pairs are kept): `sendto` with the address of the test's datagram
/// socket delivers to the pair's other end; the test checks its socket got nothing.
fn seqpacket_pair_reaches_nothing(dgram_path: &Path) {
    let mut pair = [-1; 2];
    // SAFETY: `pair` has room for the two fds.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    if rc != 0 {
        check(
            "seqpacket_pair_reaches_only_its_peer",
            false,
            format!("socketpair errno {}", errno()),
        );
        return;
    }
    // SAFETY: a sockaddr_un with the datagram socket's path, and a short message.
    let sent = unsafe {
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, b) in dgram_path.as_os_str().as_bytes().iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        libc::sendto(
            pair[0],
            b"leak".as_ptr().cast(),
            4,
            0,
            (&addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as u32,
        )
    };
    let mut buf = [0u8; 16];
    // SAFETY: a non-blocking read of the pair's other end.
    let n = unsafe {
        libc::recv(
            pair[1],
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_DONTWAIT,
        )
    };
    check(
        "seqpacket_pair_reaches_only_its_peer",
        n == 4,
        format!("sendto -> {sent}, the pair's other end got {n}"),
    );
    // SAFETY: the two fds just opened.
    unsafe {
        libc::close(pair[0]);
        libc::close(pair[1]);
    }
}
