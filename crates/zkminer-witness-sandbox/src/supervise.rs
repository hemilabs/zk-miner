//! Running `sp1-gpu-server` confined ([`run_supervised`]).
//!
//! The server runs requester guests (every SP1 proof executes its guest there), so it is confined
//! like the workers ([`crate::confine`]): Landlock, and seccomp without network. It cannot simply
//! take [`Sockets::None`], though: it has to create its listening socket (and the CUDA driver one of
//! its own) after it starts, and the path of that socket, under `/tmp`, is fixed by the SDK. Landlock
//! cannot tell its own socket file from any other below `/tmp`, so a server allowed to `bind` for
//! its whole life could put a listener of its own where another program of the user expects one (a
//! terminal multiplexer's, say) and talk to whoever connects.
//!
//! So the server's socket calls go to a supervisor: this process, which starts it and stays its
//! parent. Its filter ([`Sockets::Supervised`]) refuses `connect` and every socket but a Unix stream
//! or seqpacket one outright, and hands `socket`, `bind`, `listen`, `accept` and `accept4` to the
//! supervisor (a seccomp user notification). The supervisor lets them through until the server
//! accepts its first connection, the first moment a requester's bytes can reach it, and refuses
//! `socket`, `bind` and `listen` from then on. The decision rests on the syscall and on that moment
//! alone, never on an argument the server's memory holds, so no thread of the server can change
//! what was decided by rewriting one. A server cannot install a notifying filter of its own to
//! answer in the supervisor's place: one listener per filter chain (the kernel answers `EBUSY`), and
//! its filter refuses the attempt besides.
//!
//! The supervisor also ends the server when the process that started it (the worker) is gone, and
//! the server ends with the supervisor (`PR_SET_PDEATHSIG`); a server whose supervisor is gone gets
//! `ENOSYS` from every call that would have gone to it.

use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::Path;

use crate::confine::Confinement;
use crate::netdeny::{self, Sockets};
use crate::restrict::{landlock_abi, thread_count, MIN_LANDLOCK_ABI};
use crate::SandboxError;

/// `struct seccomp_data`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

/// `struct seccomp_notif`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

/// `struct seccomp_notif_resp`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

const fn iowr(nr: u64, size: usize) -> u64 {
    // _IOWR('!', nr, size)
    (3 << 30) | ((size as u64) << 16) | ((b'!' as u64) << 8) | nr
}
const SECCOMP_IOCTL_NOTIF_RECV: u64 = iowr(0, std::mem::size_of::<SeccompNotif>());
const SECCOMP_IOCTL_NOTIF_SEND: u64 = iowr(1, std::mem::size_of::<SeccompNotifResp>());
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;

/// The exit code of a supervised child that could not be confined (it never ran the program).
pub const EXIT_NOT_CONFINED: i32 = 125;

/// What the supervisor does with one notified syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// The kernel runs it as the server asked.
    Continue,
    /// It fails with `EPERM`.
    Refuse,
    /// A mode change to `0755` by path: the supervisor makes the executor's runner files in the
    /// runner directory executable itself ([`make_runners_executable`]) and answers for the call.
    /// The kernel never runs the server's call, so the path it named does not matter.
    MakeRunnersExecutable,
}

/// What the supervisor answers to one notified syscall `nr` with arguments `args` (registers, never
/// the server's memory), given whether the server has accepted a connection yet (`armed`, which
/// this updates).
pub(crate) fn decide(nr: i64, args: &[u64; 6], armed: &mut bool) -> Answer {
    if nr == libc::SYS_accept || nr == libc::SYS_accept4 {
        // The first moment requester bytes can arrive: from here on, no new socket.
        *armed = true;
        Answer::Continue
    } else if nr == libc::SYS_socket || nr == libc::SYS_bind || nr == libc::SYS_listen {
        if *armed {
            Answer::Refuse
        } else {
            Answer::Continue
        }
    } else if requested_mode(nr, args) == Some(0o755) {
        Answer::MakeRunnersExecutable
    } else {
        Answer::Refuse
    }
}

/// The mode a mode change by path asks for, from its registers: `chmod(path, mode)`,
/// `fchmodat(dirfd, path, mode)`, `fchmodat2(dirfd, path, mode, 0)`. `None` for anything else
/// (`fchmodat2` with flags included).
fn requested_mode(nr: i64, args: &[u64; 6]) -> Option<u32> {
    #[cfg(target_arch = "x86_64")]
    if nr == libc::SYS_chmod {
        return Some(args[1] as u32);
    }
    if nr == libc::SYS_fchmodat || (nr == libc::SYS_fchmodat2 && args[3] as u32 == 0) {
        return Some(args[2] as u32);
    }
    None
}

/// Whether `name` is a runner file as SP1's executor unpacks it: written as
/// `sp1-native-runner-bin-<64 hex digits>.tmp.<pid>` into the temporary directory, made executable
/// (`chmod 0755`), then renamed to `sp1-native-runner-bin-<64 hex digits>`.
pub(crate) fn is_runner_temp_name(name: &[u8]) -> bool {
    let Some(rest) = name.strip_prefix(b"sp1-native-runner-bin-") else {
        return false;
    };
    if rest.len() < 64 {
        return false;
    }
    let (hex, tail) = rest.split_at(64);
    let Some(pid) = tail.strip_prefix(b".tmp.") else {
        return false;
    };
    hex.iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        && !pid.is_empty()
        && pid.len() <= 10
        && pid.iter().all(u8::is_ascii_digit)
}

/// Makes every runner file ([`is_runner_temp_name`]) in `dir` executable (`0755`), on the server's
/// behalf: only a regular file directly in `dir`, reached without following a link, owned by this
/// user and with no other link to it; `dir` itself must be this user's and closed to others (the
/// private temporary directory). How many such files there are.
pub(crate) fn make_runners_executable(dir: &Path) -> std::io::Result<usize> {
    let dir_c = CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: plain syscalls on a NUL-terminated path and the fds they return, closed below.
    let dirfd = unsafe {
        libc::open(
            dir_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if dirfd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = (|| {
        // SAFETY: geteuid takes no arguments; fstat fills a zeroed buffer.
        let me = unsafe { libc::geteuid() };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(dirfd, &mut st) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if st.st_uid != me || st.st_mode & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{} is not a private directory of this user", dir.display()),
            ));
        }
        let mut found = 0;
        for entry in std::fs::read_dir(format!("/proc/self/fd/{dirfd}"))? {
            let name = entry?.file_name();
            if !is_runner_temp_name(name.as_bytes()) {
                continue;
            }
            let Ok(name_c) = CString::new(name.as_bytes()) else {
                continue;
            };
            // SAFETY: openat relative to the directory fd, with a name holding no `/`.
            let fd = unsafe {
                libc::openat(
                    dirfd,
                    name_c.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK
                        | libc::O_NOCTTY
                        | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                continue;
            }
            // SAFETY: fstat and fchmod on the fd just opened, then closed.
            let mut f: libc::stat = unsafe { std::mem::zeroed() };
            let ok = unsafe { libc::fstat(fd, &mut f) } == 0
                && f.st_mode & libc::S_IFMT == libc::S_IFREG
                && f.st_uid == me
                && f.st_nlink == 1
                && (f.st_mode & 0o7777 == 0o755 || unsafe { libc::fchmod(fd, 0o755) } == 0);
            unsafe { libc::close(fd) };
            if ok {
                found += 1;
            }
        }
        Ok(found)
    })();
    // SAFETY: closing the directory fd opened above.
    unsafe { libc::close(dirfd) };
    result
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn os_err(what: &str) -> SandboxError {
    let e = std::io::Error::last_os_error();
    SandboxError::Io(std::io::Error::new(e.kind(), format!("{what}: {e}")))
}

/// Runs `program` with `args` and this process's environment as a confined, supervised child, and
/// supervises it until it exits (its exit code, or 128 + its signal) or this process's own parent
/// does (then it is killed). `confinement` must have [`Sockets::Supervised`]. The child's stdin is
/// `/dev/null` and it inherits no file descriptor but stdout and stderr.
///
/// The server's mode changes by path (it may not make them itself: see [`crate::netdeny`]) are
/// answered here: a change to `0755` makes the executor's runner files in `runner_dir` executable
/// ([`make_runners_executable`]), and nothing else; every other one fails with `EPERM`, as all do
/// when `runner_dir` is `None`.
///
/// Call it from a single-threaded process (it forks). Fails before starting anything if the
/// confinement cannot be built or a filesystem in reach is not local ([`crate::localfs`]); a child
/// that cannot be confined exits with [`EXIT_NOT_CONFINED`] without running `program`.
pub fn run_supervised(
    program: &Path,
    args: &[OsString],
    confinement: &Confinement,
    runner_dir: Option<&Path>,
) -> Result<i32, SandboxError> {
    if confinement.sockets() != Sockets::Supervised {
        return Err(SandboxError::InvalidArgument(
            "run_supervised needs a Sockets::Supervised confinement".into(),
        ));
    }
    let threads = thread_count()?;
    if threads != 1 {
        return Err(SandboxError::MultiThreaded { threads });
    }
    let abi = landlock_abi();
    if abi < MIN_LANDLOCK_ABI {
        return Err(SandboxError::LandlockUnavailable {
            need: MIN_LANDLOCK_ABI,
            have: abi,
        });
    }

    // No network filesystem within reach of the server (see `crate::localfs`); the child checks
    // again once confined.
    let granted = confinement.granted_paths();
    crate::localfs::check_local_filesystems(&granted)?;
    // Everything that allocates happens before the fork.
    let ruleset = confinement.landlock_ruleset(false)?;
    let filters = netdeny::filters(Sockets::Supervised, &[])?;
    let notify = netdeny::notify_filter();
    let own_filters = netdeny::supervisor_filters()?;
    let cstr = |b: &[u8]| {
        CString::new(b).map_err(|e| SandboxError::InvalidArgument(format!("NUL in argument: {e}")))
    };
    let prog_c = cstr(program.as_os_str().as_bytes())?;
    let mut argv_c = vec![prog_c.clone()];
    for a in args {
        argv_c.push(cstr(a.as_bytes())?);
    }
    let mut envp_c = Vec::new();
    for (k, v) in std::env::vars_os() {
        let mut kv = k.as_bytes().to_vec();
        kv.push(b'=');
        kv.extend_from_slice(v.as_bytes());
        envp_c.push(cstr(&kv)?);
    }
    let argv: Vec<*const libc::c_char> = argv_c
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp: Vec<*const libc::c_char> = envp_c
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let notify_prog = libc::sock_fprog {
        len: notify.len() as u16,
        filter: notify.as_ptr() as *mut libc::sock_filter,
    };

    // SAFETY: plain syscalls.
    let me = unsafe { libc::getpid() };
    let parent = unsafe { libc::getppid() };
    let parent_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, parent, 0) } as RawFd;
    if parent_fd < 0 {
        return Err(os_err("pidfd_open(parent)"));
    }
    if unsafe { libc::getppid() } != parent {
        return Err(SandboxError::InvalidArgument(
            "the process that started the supervisor is gone".into(),
        ));
    }
    let mut sv = [-1; 2];
    // SAFETY: `sv` has room for the two fds.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } != 0
    {
        return Err(os_err("socketpair"));
    }

    // SAFETY: the process is single-threaded (checked), so the child may run any code.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(os_err("fork"));
    }
    if child == 0 {
        // The child: never returns.
        // SAFETY: closing fds this process owns.
        unsafe {
            libc::close(sv[0]);
            libc::close(parent_fd);
        }
        let code = confine_child(me, sv[1], ruleset, &notify_prog, &filters, &granted);
        if code != 0 {
            // SAFETY: _exit is always safe.
            unsafe { libc::_exit(code) };
        }
        // SAFETY: NUL-terminated argv and envp arrays of valid C strings.
        unsafe {
            libc::execve(prog_c.as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
        eprintln!(
            "zkminer: cannot start {}: {}",
            program.display(),
            std::io::Error::last_os_error()
        );
        // SAFETY: _exit is always safe.
        unsafe { libc::_exit(127) };
    }

    // The supervisor.
    // SAFETY: closing the child's end.
    unsafe { libc::close(sv[1]) };
    let notif_fd = recv_fd(sv[0]);
    // SAFETY: closing our end.
    unsafe { libc::close(sv[0]) };
    let Some(notif_fd) = notif_fd else {
        // The child failed before it could hand the listener over: it exits with its reason.
        return Ok(wait_child(child));
    };
    // SAFETY: plain syscall.
    let child_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) } as RawFd;
    if child_fd < 0 {
        // SAFETY: killing our own child.
        unsafe { libc::kill(child, libc::SIGKILL) };
        wait_child(child);
        return Err(os_err("pidfd_open(child)"));
    }
    // The supervisor itself needs no socket either.
    for f in &own_filters {
        if let Err(e) = seccompiler::apply_filter_all_threads(f) {
            // SAFETY: killing our own child.
            unsafe { libc::kill(child, libc::SIGKILL) };
            wait_child(child);
            return Err(SandboxError::Seccomp(e.to_string()));
        }
    }
    Ok(supervise(
        notif_fd, parent_fd, child, child_fd, runner_dir, &granted,
    ))
}

/// The child's side: confine itself, hand the notification listener to the supervisor. 0 on
/// success, else the exit code (the reason is on stderr).
fn confine_child(
    supervisor: libc::pid_t,
    sock: RawFd,
    ruleset: landlock::RulesetCreated,
    notify: &libc::sock_fprog,
    filters: &[seccompiler::BpfProgram],
    granted: &[std::path::PathBuf],
) -> i32 {
    let fail = |what: &str| {
        eprintln!("zkminer: cannot confine sp1-gpu-server: {what}");
        EXIT_NOT_CONFINED
    };
    // SAFETY: plain prctl; then checking the parent is still the supervisor.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != supervisor
        {
            return fail("the supervisor is gone");
        }
    }
    // No stdin (the worker's is the miner's command pipe).
    // SAFETY: opening /dev/null and duplicating it onto fd 0.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if null < 0 || libc::dup2(null, 0) < 0 {
            return fail("cannot point stdin at /dev/null");
        }
        libc::close(null);
    }
    match ruleset.restrict_self() {
        Ok(s) if s.ruleset != landlock::RulesetStatus::NotEnforced && s.no_new_privs => {}
        Ok(s) => return fail(&format!("Landlock not enforced: {s:?}")),
        Err(e) => return fail(&format!("Landlock: {e}")),
    }
    // No inherited fd but stdout, stderr and the one to the supervisor (the ruleset's is closed).
    // SAFETY: closing fds this process owns; close_range takes no pointers.
    unsafe {
        if sock > 3 {
            libc::syscall(libc::SYS_close_range, 3u32, (sock - 1) as u32, 0u32);
        }
        libc::syscall(libc::SYS_close_range, (sock + 1) as u32, u32::MAX, 0u32);
    }
    // The notifying filter first: the denylist below refuses any later one.
    // SAFETY: a valid filter program; NO_NEW_PRIVS is set (by restrict_self).
    let notif_fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            netdeny::SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_ulong,
            notify as *const libc::sock_fprog,
        )
    } as RawFd;
    if notif_fd < 0 {
        return fail(&format!(
            "seccomp listener: {}",
            std::io::Error::last_os_error()
        ));
    }
    for f in filters {
        if let Err(e) = seccompiler::apply_filter(f) {
            return fail(&format!("seccomp: {e}"));
        }
    }
    // Checked, not assumed: filter mode, no new privileges, no network socket, no namespace, no
    // network filesystem in reach.
    // SAFETY: getter prctls and a socket call whose fd is closed.
    unsafe {
        if libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) != 2
            || libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
        {
            return fail("seccomp or no_new_privs not in effect");
        }
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd >= 0 || errno() != libc::EPERM {
            return fail("socket(AF_INET) still succeeds");
        }
    }
    if let Err(what) = netdeny::namespaces_refused() {
        return fail(&what);
    }
    if let Err(e) = crate::localfs::check_local_filesystems(granted) {
        return fail(&e.to_string());
    }
    if !send_fd(sock, notif_fd) {
        return fail("cannot hand the listener to the supervisor");
    }
    // SAFETY: closing fds this process owns. The server must not hold its own listener.
    unsafe {
        libc::close(notif_fd);
        libc::close(sock);
    }
    0
}

/// Sends `fd` over the Unix socket `sock` (`SCM_RIGHTS`).
fn send_fd(sock: RawFd, fd: RawFd) -> bool {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: CMSG_SPACE is a pure computation.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    // SAFETY: a zeroed msghdr pointing at valid buffers that outlive the call.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
        libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) == 1
    }
}

/// Receives one fd sent with [`send_fd`]; `None` if the peer closed without sending one.
fn recv_fd(sock: RawFd) -> Option<RawFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: CMSG_SPACE is a pure computation.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    // SAFETY: a zeroed msghdr pointing at valid buffers that outlive the call.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        loop {
            let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
            if n < 0 && errno() == libc::EINTR {
                continue;
            }
            if n != 1 {
                return None;
            }
            break;
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return None;
        }
        Some(std::ptr::read_unaligned(
            libc::CMSG_DATA(cmsg).cast::<RawFd>(),
        ))
    }
}

/// Waits for `child`: its exit code, or 128 + the signal that ended it.
fn wait_child(child: libc::pid_t) -> i32 {
    let mut status = 0;
    loop {
        // SAFETY: waiting for our own child.
        let rc = unsafe { libc::waitpid(child, &mut status, 0) };
        if rc == child {
            break;
        }
        if rc < 0 && errno() != libc::EINTR {
            return 128 + libc::SIGKILL;
        }
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    }
}

fn syscall_name(nr: i64) -> &'static str {
    match nr {
        n if n == libc::SYS_socket => "socket",
        n if n == libc::SYS_bind => "bind",
        n if n == libc::SYS_listen => "listen",
        n if n == libc::SYS_accept => "accept",
        n if n == libc::SYS_accept4 => "accept4",
        n if n == libc::SYS_fchmodat => "fchmodat",
        n if n == libc::SYS_fchmodat2 => "fchmodat2",
        #[cfg(target_arch = "x86_64")]
        n if n == libc::SYS_chmod => "chmod",
        _ => "a syscall",
    }
}

/// The supervisor's loop: answers the child's notifications until it exits, or kills it when
/// `parent_fd`'s process (whoever started the supervisor) exits.
fn supervise(
    notif_fd: RawFd,
    parent_fd: RawFd,
    child: libc::pid_t,
    child_fd: RawFd,
    runner_dir: Option<&Path>,
    granted: &[std::path::PathBuf],
) -> i32 {
    use std::io::{Read, Seek};
    let mut armed = false;
    let mut refused = 0u64;
    // The mount table, watched for the server: on a change that leaves a filesystem within reach
    // that is not local (`crate::localfs`), the server is killed.
    let Ok(mut table) = std::fs::File::open("/proc/self/mountinfo") else {
        // SAFETY: killing our own child.
        unsafe { libc::kill(child, libc::SIGKILL) };
        return wait_child(child);
    };
    let mut sink = Vec::new();
    let _ = table.read_to_end(&mut sink);
    let mut fds = [
        libc::pollfd {
            fd: notif_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: parent_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: child_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: std::os::unix::io::AsRawFd::as_raw_fd(&table),
            events: libc::POLLPRI,
            revents: 0,
        },
    ];
    loop {
        for f in fds.iter_mut() {
            f.revents = 0;
        }
        // SAFETY: `fds` is a valid array of four pollfds.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 4, -1) };
        if rc < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            // SAFETY: killing our own child.
            unsafe { libc::kill(child, libc::SIGKILL) };
            return wait_child(child);
        }
        if fds[2].revents != 0 {
            return wait_child(child);
        }
        if fds[1].revents != 0 {
            // Whoever started us (the worker) is gone: so is the server.
            // SAFETY: killing our own child.
            unsafe { libc::kill(child, libc::SIGKILL) };
            return wait_child(child);
        }
        if fds[3].revents != 0 {
            // Reading the table again from the start acknowledges the change.
            sink.clear();
            let reread = table.rewind().and_then(|()| table.read_to_end(&mut sink));
            let verdict = reread
                .map_err(SandboxError::from)
                .and_then(|_| crate::localfs::check_local_filesystems(granted));
            if let Err(e) = verdict {
                eprintln!("zkminer: the mount table changed under sp1-gpu-server: {e}; ending it");
                // SAFETY: killing our own child.
                unsafe { libc::kill(child, libc::SIGKILL) };
                return wait_child(child);
            }
        }
        if fds[0].revents & libc::POLLIN != 0 {
            // SAFETY: a zeroed notification buffer of the kernel's size.
            let mut req: SeccompNotif = unsafe { std::mem::zeroed() };
            if unsafe { libc::ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV as _, &mut req) } != 0 {
                // ENOENT: the caller was interrupted or is gone.
                continue;
            }
            let nr = i64::from(req.data.nr);
            let answer = decide(nr, &req.data.args, &mut armed);
            // `error` is the negated errno; `val` the call's result when it is 0.
            let error = match answer {
                Answer::Continue => 0,
                Answer::Refuse => -libc::EPERM,
                Answer::MakeRunnersExecutable => match runner_dir.map(make_runners_executable) {
                    Some(Ok(n)) if n > 0 => 0,
                    Some(Err(e)) => -e.raw_os_error().unwrap_or(libc::EPERM),
                    _ => -libc::EPERM,
                },
            };
            let resp = SeccompNotifResp {
                id: req.id,
                val: 0,
                error,
                flags: if answer == Answer::Continue {
                    SECCOMP_USER_NOTIF_FLAG_CONTINUE
                } else {
                    0
                },
            };
            // SAFETY: a valid response buffer. ENOENT (the caller is gone) needs nothing more.
            unsafe { libc::ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND as _, &resp) };
            if answer == Answer::Refuse {
                refused += 1;
                if refused <= 8 {
                    eprintln!(
                        "zkminer: refused {}() in sp1-gpu-server (pid {}){}",
                        syscall_name(nr),
                        req.pid,
                        if netdeny::mode_changes().iter().any(|(_, m)| *m == nr) {
                            ""
                        } else {
                            ": it has taken its first connection"
                        }
                    );
                }
            }
        } else if fds[0].revents != 0 {
            // POLLHUP: no process is left that the filter applies to; the child's pidfd follows.
            fds[0].events = 0;
            fds[0].fd = -1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ioctl_numbers_are_the_kernels() {
        // <linux/seccomp.h>: SECCOMP_IOWR(0, struct seccomp_notif), SECCOMP_IOWR(1, struct
        // seccomp_notif_resp).
        assert_eq!(std::mem::size_of::<SeccompNotif>(), 80);
        assert_eq!(std::mem::size_of::<SeccompNotifResp>(), 24);
        assert_eq!(SECCOMP_IOCTL_NOTIF_RECV, 0xc050_2100);
        assert_eq!(SECCOMP_IOCTL_NOTIF_SEND, 0xc018_2101);
    }

    #[test]
    fn sockets_until_the_first_connection_never_after() {
        use libc::*;
        let none = [0u64; 6];
        let mut armed = false;
        let go = |nr, armed: &mut bool| decide(nr, &none, armed) == Answer::Continue;
        for nr in [
            SYS_socket, SYS_bind, SYS_listen, SYS_socket, SYS_bind, SYS_listen,
        ] {
            assert!(go(nr, &mut armed), "{nr} before the first accept");
        }
        assert!(go(SYS_accept4, &mut armed));
        assert!(armed);
        for nr in [SYS_socket, SYS_bind, SYS_listen] {
            assert!(!go(nr, &mut armed), "{nr} after the first accept");
        }
        assert!(go(SYS_accept4, &mut armed), "the server keeps accepting");
        assert!(go(SYS_accept, &mut armed));
        assert!(
            !go(SYS_connect, &mut armed),
            "never notified, never allowed"
        );
        let mut fresh = false;
        assert!(!go(SYS_connect, &mut fresh));
        assert!(!go(SYS_execve, &mut fresh));
    }

    #[test]
    fn only_a_0755_mode_change_is_answered_and_never_run_by_the_kernel() {
        use libc::*;
        let mut armed = false;
        let path = 0x7f00_0000_1000u64;
        let mut calls = vec![
            (SYS_fchmodat, [AT_FDCWD as u64, path, 0o755, 0, 0, 0]),
            (SYS_fchmodat2, [AT_FDCWD as u64, path, 0o755, 0, 0, 0]),
        ];
        #[cfg(target_arch = "x86_64")]
        calls.push((SYS_chmod, [path, 0o755, 0, 0, 0, 0]));
        for (nr, args) in &calls {
            for a in [false, true] {
                armed = a;
                assert_eq!(
                    decide(*nr, args, &mut armed),
                    Answer::MakeRunnersExecutable,
                    "{nr}"
                );
            }
        }
        let mut refused = vec![
            (SYS_fchmodat, [AT_FDCWD as u64, path, 0o644, 0, 0, 0]),
            (SYS_fchmodat, [AT_FDCWD as u64, path, 0o4755, 0, 0, 0]),
            (SYS_fchmodat, [AT_FDCWD as u64, path, 0o777, 0, 0, 0]),
            // AT_SYMLINK_NOFOLLOW, or any flag.
            (SYS_fchmodat2, [AT_FDCWD as u64, path, 0o755, 0x100, 0, 0]),
            (SYS_fchmod, [3, 0o755, 0, 0, 0, 0]),
            (SYS_fchownat, [AT_FDCWD as u64, path, 0, 0, 0, 0]),
        ];
        #[cfg(target_arch = "x86_64")]
        refused.push((SYS_chmod, [path, 0o666, 0, 0, 0, 0]));
        for (nr, args) in &refused {
            assert_eq!(
                decide(*nr, args, &mut armed),
                Answer::Refuse,
                "{nr} {args:?}"
            );
        }
    }

    #[test]
    fn runner_names() {
        let hex = "039fc830c760cfbf00882fec49bd88bb05b1891e42c20dd600e8093099efbaac";
        assert!(is_runner_temp_name(
            format!("sp1-native-runner-bin-{hex}.tmp.1522603").as_bytes()
        ));
        for bad in [
            format!("sp1-native-runner-bin-{hex}"),
            format!("sp1-native-runner-bin-{hex}.tmp."),
            format!("sp1-native-runner-bin-{hex}.tmp.12345678901"),
            format!("sp1-native-runner-bin-{hex}.tmp.1/x"),
            format!("sp1-native-runner-bin-{}.tmp.1", hex.to_uppercase()),
            format!("sp1-native-runner-bin-{}.tmp.1", &hex[1..]),
            format!("sp1-native-runner-bin-../{}.tmp.1", &hex[3..]),
            format!("x-sp1-native-runner-bin-{hex}.tmp.1"),
            ".bashrc".to_string(),
        ] {
            assert!(!is_runner_temp_name(bad.as_bytes()), "{bad}");
        }
    }

    #[test]
    fn the_supervisor_makes_runner_files_executable_and_nothing_else() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        // Private, as the worker's temporary directory is.
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().mode() & 0o7777;
        let hex = "88200a963af2d9b0d8c13aeb3ce37072e65c1185dc7bea81a053c38a289e9b5e";
        let runner = d.join(format!("sp1-native-runner-bin-{hex}.tmp.42"));
        let other = d.join("other");
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        for f in [&runner, &other, &victim] {
            std::fs::write(f, b"x").unwrap();
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        // A link named like a runner, to a file elsewhere: never followed.
        std::os::unix::fs::symlink(
            &victim,
            d.join(format!("sp1-native-runner-bin-{hex}.tmp.43")),
        )
        .unwrap();
        // A second name for a file of the directory: not changed through it.
        let twice = d.join("twice");
        std::fs::write(&twice, b"x").unwrap();
        std::fs::set_permissions(&twice, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(
            &twice,
            d.join(format!("sp1-native-runner-bin-{hex}.tmp.44")),
        )
        .unwrap();
        // A directory named like one.
        std::fs::create_dir(d.join(format!("sp1-native-runner-bin-{hex}.tmp.45"))).unwrap();

        assert_eq!(make_runners_executable(d).unwrap(), 1);
        assert_eq!(mode(&runner), 0o755);
        assert_eq!(mode(&other), 0o644);
        assert_eq!(mode(&victim), 0o644);
        assert_eq!(mode(&twice), 0o600);
        // Again: already executable, still one.
        assert_eq!(make_runners_executable(d).unwrap(), 1);
        // A directory open to others is not the private one.
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(make_runners_executable(d).is_err());
        // Nor is a link to one.
        let link = outside.path().join("link");
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(d, &link).unwrap();
        assert!(make_runners_executable(&link).is_err());
    }
}
