//! The seccomp half of the confinement of the processes that run requester guests outside the
//! sandbox profiles: the miner's inline measuring and proving workers and the `sp1-gpu-server` an
//! SP1 worker starts. [`crate::confine`] installs it, together with Landlock.
//!
//! Those processes cannot take a [`crate::Profile`]: the GPU stack needs device files, ioctls,
//! `mmap`, threads and helper processes. What they do not need, once their one-time setup is done,
//! is any socket. So their filter takes every socket away, Unix ones included ([`Sockets`]):
//!
//! - [`Sockets::None`] (the risc0 and OpenVM workers): no `socket` or `socketpair` of any domain,
//!   no `connect`, `bind`, `listen`, `accept` or `accept4`.
//!   The only socket such a process may hold when the filter goes on is a listening Unix socket
//!   (the CUDA driver opens one at `cuInit`); with `accept` gone, nothing can come in through it.
//! - [`Sockets::KeepConnected`] (the SP1 worker): the same, except that a Unix stream or seqpacket
//!   `socketpair` stays allowed (the SDK's tokio runtime makes a stream pair, and Rust's
//!   `Command::spawn` reports a failed `exec` over a seqpacket pair; a connected pair reaches nothing
//!   outside the process), and the process may keep the connected Unix stream sockets it holds to
//!   processes it started itself (a proving worker's connection to its own `sp1-gpu-server`, which
//!   is confined too).
//! - [`Sockets::Supervised`] (`sp1-gpu-server`, see [`crate::supervise`]): Unix stream and seqpacket
//!   sockets, `bind`, `listen` and `accept*` reach a supervisor process, which lets them through
//!   until the server takes its first connection and refuses `socket`, `bind` and `listen` from then
//!   on; `connect` and every other socket are refused outright.
//!
//! Every policy also refuses, with `EPERM`: `io_uring_*` (its operations, socket creation and
//! connects included, bypass seccomp), `bpf`, `ptrace`, `process_vm_readv`, `process_vm_writev` and
//! `pidfd_getfd` (another process of the uid, such as the miner, must not be driven, read, written,
//! or have its sockets copied out), `mknod`/`mknodat`, the kernel keyrings (`add_key`, `keyctl`,
//! `request_key`: the uid's keys are not the worker's), a seccomp filter with a user-notification
//! listener of its own, `TIOCSTI`/`TIOCLINUX` (keystrokes into an inherited terminal), and
//! `PR_SET_PTRACER`; on x86_64, every x32 syscall. A syscall of a foreign ABI (`int 0x80` on
//! x86_64) kills the process.
//!
//! None of these processes needs a namespace or a mount, and where unprivileged user namespaces
//! are allowed, a user namespace is the door to most of the kernel's attack surface (its
//! capabilities reach netfilter, mounts and the rest). So every policy also refuses `unshare`,
//! `setns`, `clone` with any `CLONE_NEW*` flag, `mount`, `umount2`, `pivot_root`, `chroot` and
//! the new mount API (`fsopen`, `fsconfig`, `fsmount`, `fspick`, `move_mount`, `open_tree`,
//! `open_tree_attr`, `mount_setattr`), as well as `userfaultfd`, `perf_event_open` and file
//! handles (`name_to_handle_at`, `open_by_handle_at`). `clone3` fails with `ENOSYS`: its flags
//! live in memory, out of a filter's sight, and libc then falls back to `clone`, whose flags the
//! filter reads (threads, `fork`, `vfork` and `posix_spawn` keep working).
//!
//! The filters are installed with `SECCOMP_FILTER_FLAG_TSYNC` after `NO_NEW_PRIVS`: every thread
//! the process has, and every thread and process it creates afterwards (across `exec` too),
//! carries them.

use std::collections::BTreeMap;
use std::os::unix::io::RawFd;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::restrict::{PR_SET_PTRACER, SOCK_TYPE_MASK, SYS_OPEN_TREE_ATTR};
use crate::SandboxError;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("zkminer-witness-sandbox's network filter covers x86_64 and aarch64 only");

/// What a confined process may still do with sockets. See the [module docs](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sockets {
    /// No socket at all.
    None,
    /// No new socket but Unix stream and seqpacket pairs; Unix stream connections to its own
    /// children, made before, stay usable.
    KeepConnected,
    /// `sp1-gpu-server` under its supervisor ([`crate::supervise`]).
    Supervised,
}

impl std::fmt::Display for Sockets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Sockets::None => "no sockets",
            Sockets::KeepConnected => {
                "no sockets but stream pairs, keeps connections to its own children"
            }
            Sockets::Supervised => "its own listener only (supervised)",
        })
    }
}

/// `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
pub(crate) const SECCOMP_FILTER_FLAG_NEW_LISTENER: u64 = 1 << 3;
/// `SECCOMP_RET_USER_NOTIF`.
pub(crate) const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

/// Syscalls denied whatever their arguments, under every policy.
fn always_denied() -> Vec<(&'static str, i64)> {
    use libc::*;
    let mut v = vec![
        ("io_uring_setup", SYS_io_uring_setup),
        ("io_uring_enter", SYS_io_uring_enter),
        ("io_uring_register", SYS_io_uring_register),
        ("bpf", SYS_bpf),
        ("ptrace", SYS_ptrace),
        ("process_vm_readv", SYS_process_vm_readv),
        ("process_vm_writev", SYS_process_vm_writev),
        ("pidfd_getfd", SYS_pidfd_getfd),
        ("connect", SYS_connect),
        ("mknodat", SYS_mknodat),
        ("add_key", SYS_add_key),
        ("keyctl", SYS_keyctl),
        ("request_key", SYS_request_key),
        // Namespaces and mounts (see the module docs; `clone` is filtered by its flags).
        ("unshare", SYS_unshare),
        ("setns", SYS_setns),
        ("mount", SYS_mount),
        ("umount2", SYS_umount2),
        ("pivot_root", SYS_pivot_root),
        ("chroot", SYS_chroot),
        ("fsopen", SYS_fsopen),
        ("fsconfig", SYS_fsconfig),
        ("fsmount", SYS_fsmount),
        ("fspick", SYS_fspick),
        ("move_mount", SYS_move_mount),
        ("open_tree", SYS_open_tree),
        ("open_tree_attr", SYS_OPEN_TREE_ATTR),
        ("mount_setattr", SYS_mount_setattr),
        // Kernel surface no worker needs.
        ("userfaultfd", SYS_userfaultfd),
        ("perf_event_open", SYS_perf_event_open),
        ("name_to_handle_at", SYS_name_to_handle_at),
        ("open_by_handle_at", SYS_open_by_handle_at),
    ];
    #[cfg(target_arch = "x86_64")]
    v.push(("mknod", SYS_mknod));
    v
}

/// Every `CLONE_NEW*` flag. `clone` reads its low byte as the child's exit signal, so it cannot
/// ask for a time namespace (`CLONE_NEWTIME` is that byte's top bit, which no valid signal sets);
/// the filter refuses the bit all the same.
pub(crate) const CLONE_NEW_FLAGS: [(&str, libc::c_int); 8] = [
    ("CLONE_NEWNS", libc::CLONE_NEWNS),
    ("CLONE_NEWCGROUP", libc::CLONE_NEWCGROUP),
    ("CLONE_NEWUTS", libc::CLONE_NEWUTS),
    ("CLONE_NEWIPC", libc::CLONE_NEWIPC),
    ("CLONE_NEWUSER", libc::CLONE_NEWUSER),
    ("CLONE_NEWPID", libc::CLONE_NEWPID),
    ("CLONE_NEWNET", libc::CLONE_NEWNET),
    ("CLONE_NEWTIME", libc::CLONE_NEWTIME),
];

/// Syscalls that fail with `ENOSYS` under every policy ([`raw_filter`]).
pub(crate) const ENOSYS_SYSCALLS: [(&str, i64); 1] = [("clone3", libc::SYS_clone3)];

/// Further syscalls denied whatever their arguments under `sockets`.
fn denied_for(sockets: Sockets) -> Vec<(&'static str, i64)> {
    use libc::*;
    let mut v = always_denied();
    match sockets {
        Sockets::None => v.extend([
            ("socket", SYS_socket),
            ("socketpair", SYS_socketpair),
            ("bind", SYS_bind),
            ("listen", SYS_listen),
            ("accept", SYS_accept),
            ("accept4", SYS_accept4),
        ]),
        Sockets::KeepConnected => v.extend([
            ("socket", SYS_socket),
            ("bind", SYS_bind),
            ("listen", SYS_listen),
            ("accept", SYS_accept),
            ("accept4", SYS_accept4),
        ]),
        // `bind`, `listen`, `accept*` and the Unix `socket`s go to the supervisor.
        Sockets::Supervised => {}
    }
    v
}

/// The syscalls [`Sockets::None`] denies whatever their arguments, for probes and tests.
pub fn denied_without_sockets() -> Vec<(&'static str, i64)> {
    denied_for(Sockets::None)
}

fn cond(arg: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompCondition, SandboxError> {
    // `Dword`: these arguments are `int`s (or an `unsigned int` of flags), whose upper 32 bits the
    // kernel ignores, and so does this comparison.
    SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, value)
        .map_err(|e| SandboxError::Seccomp(e.to_string()))
}

fn rule(conds: Vec<SeccompCondition>) -> Result<SeccompRule, SandboxError> {
    SeccompRule::new(conds).map_err(|e| SandboxError::Seccomp(e.to_string()))
}

/// Argument-filtered denials under `sockets`: a call matching any of a syscall's rules fails with
/// `EPERM`.
fn conditional_denials(sockets: Sockets) -> Result<Vec<(i64, Vec<SeccompRule>)>, SandboxError> {
    use SeccompCmpOp::{Eq, MaskedEq, Ne};
    let mut v = vec![
        // A seccomp filter of the process's own that notifies a listener: the kernel lets the
        // newest notifier answer for every filter before it, which would let it continue what a
        // supervisor refuses. (A second listener in one filter chain already fails with EBUSY.)
        (
            libc::SYS_seccomp,
            vec![rule(vec![cond(
                1,
                MaskedEq(SECCOMP_FILTER_FLAG_NEW_LISTENER),
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
            )?])?],
        ),
        (
            libc::SYS_ioctl,
            vec![
                // Keystrokes into a terminal the process inherited (a worker run by hand).
                rule(vec![cond(1, Eq, libc::TIOCSTI)?])?,
                rule(vec![cond(1, Eq, libc::TIOCLINUX)?])?,
            ],
        ),
        (
            libc::SYS_prctl,
            vec![rule(vec![cond(0, Eq, PR_SET_PTRACER as u64)?])?],
        ),
        // Threads, `fork`, `vfork` and `posix_spawn`, never a new namespace. The kernel reads
        // only the low 32 bits of the flags, and so do these `Dword` comparisons.
        (
            libc::SYS_clone,
            CLONE_NEW_FLAGS
                .iter()
                .map(|&(_, flag)| rule(vec![cond(0, MaskedEq(flag as u64), flag as u64)?]))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    ];
    match sockets {
        Sockets::None => {}
        Sockets::KeepConnected | Sockets::Supervised => {
            // A connected AF_UNIX stream or seqpacket pair reaches nothing outside the process:
            // tokio's signal driver makes a stream pair, and Rust's `Command::spawn` a seqpacket
            // one (on Linux, for a child that runs code before its `exec`), and `sendmsg` on a
            // seqpacket socket ignores any address it is given. A *datagram* pair would not:
            // `sendto` on either end reaches any pathname datagram socket of the host.
            let mut pair = vec![rule(vec![cond(0, Ne, libc::AF_UNIX as u64)?])?];
            for t in 0..=SOCK_TYPE_MASK {
                if t != libc::SOCK_STREAM as u64 && t != libc::SOCK_SEQPACKET as u64 {
                    pair.push(rule(vec![cond(1, MaskedEq(SOCK_TYPE_MASK), t)?])?);
                }
            }
            v.push((libc::SYS_socketpair, pair));
        }
    }
    if sockets == Sockets::Supervised {
        // Unix stream and seqpacket sockets only (the CUDA driver's own listener is a seqpacket
        // one), and those go to the supervisor too. Without `connect`, neither reaches anything:
        // `sendto` with an address fails on both unless they are connected.
        let mut socket = vec![rule(vec![cond(0, Ne, libc::AF_UNIX as u64)?])?];
        for t in 0..=SOCK_TYPE_MASK {
            if t != libc::SOCK_STREAM as u64 && t != libc::SOCK_SEQPACKET as u64 {
                socket.push(rule(vec![cond(1, MaskedEq(SOCK_TYPE_MASK), t)?])?);
            }
        }
        v.push((libc::SYS_socket, socket));
    }
    Ok(v)
}

fn target_arch() -> Result<TargetArch, SandboxError> {
    std::env::consts::ARCH
        .try_into()
        .map_err(|e: seccompiler::BackendError| SandboxError::Seccomp(e.to_string()))
}

/// The denylist (seccompiler; its architecture check kills the process on a foreign-ABI syscall).
fn denylist(sockets: Sockets) -> Result<BpfProgram, SandboxError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for (_, nr) in denied_for(sockets) {
        // An empty rule list matches whatever the arguments.
        rules.insert(nr, Vec::new());
    }
    for (nr, conds) in conditional_denials(sockets)? {
        if rules.insert(nr, conds).is_some() {
            return Err(SandboxError::Seccomp(format!(
                "syscall {nr} both denied and filtered"
            )));
        }
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch()?,
    )
    .map_err(|e| SandboxError::Seccomp(e.to_string()))?;
    filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| SandboxError::Seccomp(e.to_string()))
}

const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
#[cfg(target_arch = "x86_64")]
const BPF_JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K
const ARCH_OFFSET: u32 = 4;
const NR_OFFSET: u32 = 0;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 62 | 0x8000_0000 | 0x4000_0000;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 183 | 0x8000_0000 | 0x4000_0000;

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> seccompiler::sock_filter {
    seccompiler::sock_filter { code, jt, jf, k }
}

/// A hand-written filter for what the denylist (one action per filter, keyed by 64-bit syscall
/// numbers) cannot express: the [`ENOSYS_SYSCALLS`] (`clone3`) fail with `ENOSYS`, and on x86_64
/// every x32 syscall (`nr >= 0x40000000`, the same architecture to seccomp) fails with `EPERM`. It
/// checks the architecture too, killing on a foreign one.
fn raw_filter() -> BpfProgram {
    let [(_, clone3)] = ENOSYS_SYSCALLS;
    let enosys = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
    // Jump offsets count from the next instruction.
    #[cfg(target_arch = "x86_64")]
    {
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        vec![
            /* 0 */ insn(BPF_LD_W_ABS, 0, 0, ARCH_OFFSET),
            /* 1 */ insn(BPF_JEQ_K, 0, 6, AUDIT_ARCH), // else -> 8 (kill)
            /* 2 */ insn(BPF_LD_W_ABS, 0, 0, NR_OFFSET),
            /* 3 */ insn(BPF_JGE_K, 3, 0, 0x4000_0000), // x32 -> 7 (EPERM)
            /* 4 */ insn(BPF_JEQ_K, 1, 0, clone3 as u32), // -> 6 (ENOSYS)
            /* 5 */ insn(BPF_RET_K, 0, 0, libc::SECCOMP_RET_ALLOW),
            /* 6 */ insn(BPF_RET_K, 0, 0, enosys),
            /* 7 */ insn(BPF_RET_K, 0, 0, eperm),
            /* 8 */ insn(BPF_RET_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        ]
    }
    #[cfg(target_arch = "aarch64")]
    {
        vec![
            /* 0 */ insn(BPF_LD_W_ABS, 0, 0, ARCH_OFFSET),
            /* 1 */ insn(BPF_JEQ_K, 0, 4, AUDIT_ARCH), // else -> 6 (kill)
            /* 2 */ insn(BPF_LD_W_ABS, 0, 0, NR_OFFSET),
            /* 3 */ insn(BPF_JEQ_K, 1, 0, clone3 as u32), // -> 5 (ENOSYS)
            /* 4 */ insn(BPF_RET_K, 0, 0, libc::SECCOMP_RET_ALLOW),
            /* 5 */ insn(BPF_RET_K, 0, 0, enosys),
            /* 6 */ insn(BPF_RET_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        ]
    }
}

/// The syscalls [`Sockets::Supervised`] hands to the supervisor.
pub(crate) fn supervised_syscalls() -> [i64; 5] {
    [
        libc::SYS_socket,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
    ]
}

/// [`Sockets::Supervised`]'s notifying filter: [`supervised_syscalls`] go to the supervisor
/// (`SECCOMP_RET_USER_NOTIF`), everything else is the other filters' business. The denylist's
/// `EPERM` (for `socket` of another domain or type) takes precedence over a notification.
pub(crate) fn notify_filter() -> BpfProgram {
    let nrs = supervised_syscalls();
    let n = nrs.len() as u8;
    // 0 ld arch; 1 arch?; 2 ld nr; 3..3+n nr? -> notify; 3+n allow; 4+n notify; 5+n kill.
    let mut f = vec![
        insn(BPF_LD_W_ABS, 0, 0, ARCH_OFFSET),
        insn(BPF_JEQ_K, 0, 3 + n, AUDIT_ARCH), // else -> kill
        insn(BPF_LD_W_ABS, 0, 0, NR_OFFSET),
    ];
    for (j, nr) in nrs.iter().enumerate() {
        f.push(insn(BPF_JEQ_K, n - j as u8, 0, *nr as u32)); // -> notify
    }
    f.extend([
        insn(BPF_RET_K, 0, 0, libc::SECCOMP_RET_ALLOW),
        insn(BPF_RET_K, 0, 0, SECCOMP_RET_USER_NOTIF),
        insn(BPF_RET_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
    ]);
    f
}

/// The filters for `sockets`, in the order they are installed (the notifying filter of
/// [`Sockets::Supervised`] is not among them: [`crate::supervise`] installs it itself).
pub(crate) fn filters(sockets: Sockets) -> Result<Vec<BpfProgram>, SandboxError> {
    Ok(vec![raw_filter(), denylist(sockets)?])
}

/// Checks, in a process the filters are on, that no namespace can be made: `unshare(0)` (a no-op
/// without the filter) fails with `EPERM`, and `clone3` with `ENOSYS` (without the filter, its
/// empty arguments are `EINVAL`). Neither call can change anything.
pub(crate) fn namespaces_refused() -> Result<(), String> {
    // SAFETY: unshare with no flags, and clone3 with no arguments; both take no pointer the
    // kernel would write through.
    let (rc, e) = unsafe { (libc::unshare(0), std::io::Error::last_os_error()) };
    if rc == 0 || e.raw_os_error() != Some(libc::EPERM) {
        return Err(format!("unshare is not refused ({rc}, {e})"));
    }
    let rc = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize) };
    let e = std::io::Error::last_os_error();
    if rc >= 0 || e.raw_os_error() != Some(libc::ENOSYS) {
        return Err(format!("clone3 does not fail with ENOSYS ({rc}, {e})"));
    }
    Ok(())
}

/// One socket open in this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSocket {
    pub fd: RawFd,
    /// `SO_DOMAIN` (an `AF_*` value); `None` if the socket would not say.
    pub family: Option<i32>,
    /// `SO_TYPE` (`SOCK_STREAM`, ...); `None` if the socket would not say.
    pub kind: Option<i32>,
    /// `SO_ACCEPTCONN`: a listening socket.
    pub listening: bool,
    /// The pid of the connected peer (`SO_PEERCRED`), for a connected Unix socket.
    pub peer: Option<i32>,
    /// The socket's inode, as `/proc/<pid>/fd/<fd>` shows it (`socket:[inode]`).
    pub inode: u64,
}

impl std::fmt::Display for OpenSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let family = match self.family {
            Some(libc::AF_UNIX) => "AF_UNIX".to_string(),
            Some(libc::AF_INET) => "AF_INET".to_string(),
            Some(libc::AF_INET6) => "AF_INET6".to_string(),
            Some(libc::AF_NETLINK) => "AF_NETLINK".to_string(),
            Some(libc::AF_PACKET) => "AF_PACKET".to_string(),
            Some(libc::AF_VSOCK) => "AF_VSOCK".to_string(),
            Some(other) => format!("family {other}"),
            None => "unknown family".to_string(),
        };
        write!(f, "fd {} ({family}", self.fd)?;
        if self.listening {
            write!(f, ", listening")?;
        }
        if let Some(peer) = self.peer {
            write!(f, ", peer pid {peer}")?;
        }
        write!(f, ", socket:[{}])", self.inode)
    }
}

fn int_sockopt(fd: RawFd, opt: libc::c_int) -> Option<i32> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `v` and `len` are valid for the kernel to write an int into.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(v)
}

/// Every socket open in this process, from `/proc/self/fd`, with what each says about itself.
pub fn open_sockets() -> std::io::Result<Vec<OpenSocket>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let Some(fd) = entry?
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
        else {
            continue;
        };
        // SAFETY: `st` is a valid stat buffer; an fd closed meanwhile (the directory's own, say)
        // only fails the call.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            continue;
        }
        let family = int_sockopt(fd, libc::SO_DOMAIN);
        let peer = if family == Some(libc::AF_UNIX) {
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            // SAFETY: `cred` and `len` describe a valid ucred buffer.
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut cred as *mut libc::ucred).cast(),
                    &mut len,
                )
            };
            (rc == 0 && cred.pid > 0).then_some(cred.pid)
        } else {
            None
        };
        found.push(OpenSocket {
            fd,
            family,
            kind: int_sockopt(fd, libc::SO_TYPE),
            listening: int_sockopt(fd, libc::SO_ACCEPTCONN) == Some(1),
            peer,
            inode: st.st_ino,
        });
    }
    Ok(found)
}

/// The parent pid of `pid`, from `/proc/<pid>/stat` (after the last `)`: a `comm` may hold any
/// byte).
fn parent_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1;
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Whether `pid` is this process or one it started (at most a few generations down: the SP1 worker's
/// server runs under a supervisor the worker started).
fn is_self_or_descendant(pid: i32) -> bool {
    // SAFETY: getpid takes no arguments.
    let me = unsafe { libc::getpid() };
    let mut cur = pid;
    for _ in 0..4 {
        if cur == me {
            return true;
        }
        match parent_of(cur) {
            Some(p) if p > 1 => cur = p,
            _ => return false,
        }
    }
    false
}

/// The sockets of `open` that `sockets` does not let a confined process keep, and why.
pub(crate) fn sockets_not_allowed(sockets: Sockets, open: &[OpenSocket]) -> Vec<String> {
    open.iter()
        .filter(|s| {
            let unix = s.family == Some(libc::AF_UNIX);
            // A listening Unix socket is inert once `accept` is gone (the CUDA driver's).
            let inert_listener = unix && s.listening && sockets != Sockets::Supervised;
            let own_connection = sockets == Sockets::KeepConnected
                && unix
                && !s.listening
                && s.kind == Some(libc::SOCK_STREAM)
                && s.peer.is_some_and(is_self_or_descendant);
            !(inert_listener || own_connection)
        })
        .map(ToString::to_string)
        .collect()
}

/// Threads of this process whose `/proc/self/task/<tid>/status` does not say `Seccomp: 2`. A thread
/// that exited while being read is skipped.
pub(crate) fn threads_not_in_filter_mode() -> std::io::Result<Vec<String>> {
    let mut out = Vec::new();
    for task in std::fs::read_dir("/proc/self/task")? {
        let task = task?;
        let Ok(status) = std::fs::read_to_string(task.path().join("status")) else {
            continue;
        };
        let mode = status
            .lines()
            .find_map(|l| l.strip_prefix("Seccomp:"))
            .map(str::trim);
        if mode != Some("2") {
            out.push(task.file_name().to_string_lossy().into_owned());
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    pub(crate) const RET_EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    pub(crate) const RET_KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;
    pub(crate) const RET_NOTIFY: u32 = SECCOMP_RET_USER_NOTIF;

    /// `struct seccomp_data`: nr, arch, instruction pointer, six 64-bit arguments.
    pub(crate) fn seccomp_data(arch: u32, nr: i64, args: [u64; 6]) -> [u8; 64] {
        let mut d = [0u8; 64];
        d[0..4].copy_from_slice(&(nr as u32).to_ne_bytes());
        d[4..8].copy_from_slice(&arch.to_ne_bytes());
        d[8..16].copy_from_slice(&0x7f00_dead_beefu64.to_ne_bytes());
        for (i, a) in args.iter().enumerate() {
            d[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_ne_bytes());
        }
        d
    }

    /// A classic-BPF interpreter for exactly the instructions seccompiler and the hand-written
    /// filters emit; anything else panics, so a seccompiler upgrade that emits more cannot pass
    /// silently.
    pub(crate) fn run_bpf(prog: &[seccompiler::sock_filter], data: &[u8; 64]) -> u32 {
        let (mut a, mut pc) = (0u32, 0usize);
        for _ in 0..=prog.len() {
            let i = &prog[pc];
            pc += 1;
            let jump = |taken: bool| usize::from(if taken { i.jt } else { i.jf });
            match i.code {
                0x20 => {
                    let k = i.k as usize;
                    assert!(k.is_multiple_of(4) && k + 4 <= data.len(), "load at {k}");
                    a = u32::from_ne_bytes(data[k..k + 4].try_into().unwrap());
                }
                0x54 => a &= i.k,
                0x05 => pc += i.k as usize,
                0x15 => pc += jump(a == i.k),
                0x25 => pc += jump(a > i.k),
                0x35 => pc += jump(a >= i.k),
                0x45 => pc += jump(a & i.k != 0),
                0x06 => return i.k,
                c => panic!("unexpected BPF opcode {c:#06x} at {}", pc - 1),
            }
        }
        panic!("BPF program did not return");
    }

    /// The kernel's precedence of seccomp actions: the lowest action value wins, `KILL_PROCESS`
    /// (whose top bit makes it negative as an `i32`) first.
    fn precedence(ret: u32) -> i64 {
        let action = ret & 0xffff_0000;
        if action == libc::SECCOMP_RET_KILL_PROCESS {
            -1
        } else {
            i64::from(action)
        }
    }

    /// Every filter runs and the most restrictive action wins, as in the kernel.
    pub(crate) fn verdict_of(filters: &[BpfProgram], data: &[u8; 64]) -> u32 {
        let mut ret = RET_ALLOW;
        for f in filters.iter().rev() {
            let cur = run_bpf(f, data);
            if precedence(cur) < precedence(ret) {
                ret = cur;
            }
        }
        ret
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) const ARCH: u32 = 62 | 0x8000_0000 | 0x4000_0000;
    #[cfg(target_arch = "aarch64")]
    pub(crate) const ARCH: u32 = 183 | 0x8000_0000 | 0x4000_0000;

    fn all(sockets: Sockets) -> Vec<BpfProgram> {
        let mut f = filters(sockets).unwrap();
        if sockets == Sockets::Supervised {
            f.push(notify_filter());
        }
        f
    }

    fn call(sockets: Sockets, nr: i64, args: [u64; 6]) -> u32 {
        verdict_of(&all(sockets), &seccomp_data(ARCH, nr, args))
    }

    const POLICIES: [Sockets; 3] = [Sockets::None, Sockets::KeepConnected, Sockets::Supervised];

    #[test]
    fn no_socket_at_all_without_sockets() {
        use libc::*;
        for domain in [
            AF_UNIX, AF_INET, AF_INET6, AF_PACKET, AF_NETLINK, AF_VSOCK, AF_UNSPEC, 4095,
        ] {
            for kind in [
                SOCK_STREAM,
                SOCK_DGRAM,
                SOCK_RAW,
                SOCK_SEQPACKET | SOCK_CLOEXEC,
            ] {
                for policy in [Sockets::None, Sockets::KeepConnected] {
                    assert_eq!(
                        call(policy, SYS_socket, [domain as u64, kind as u64, 0, 0, 0, 0]),
                        RET_EPERM,
                        "{policy:?} socket({domain}, {kind})"
                    );
                }
                assert_eq!(
                    call(
                        Sockets::None,
                        SYS_socketpair,
                        [domain as u64, kind as u64, 0, 0, 0, 0]
                    ),
                    RET_EPERM,
                    "socketpair({domain}, {kind})"
                );
            }
        }
        for nr in [SYS_connect, SYS_bind, SYS_listen, SYS_accept, SYS_accept4] {
            for policy in [Sockets::None, Sockets::KeepConnected] {
                for args in [[3, 0, 0, 0, 0, 0], [u64::MAX; 6]] {
                    assert_eq!(call(policy, nr, args), RET_EPERM, "{policy:?} {nr}");
                }
            }
        }
    }

    #[test]
    fn only_unix_stream_and_seqpacket_pairs_where_pairs_are_kept() {
        use libc::*;
        for policy in [Sockets::KeepConnected, Sockets::Supervised] {
            for flags in [0, SOCK_CLOEXEC, SOCK_CLOEXEC | SOCK_NONBLOCK] {
                for kind in [SOCK_STREAM, SOCK_SEQPACKET] {
                    assert_eq!(
                        call(
                            policy,
                            SYS_socketpair,
                            [AF_UNIX as u64, (kind | flags) as u64, 0, 0, 0, 0]
                        ),
                        RET_ALLOW,
                        "{policy:?}"
                    );
                }
            }
            for kind in [SOCK_DGRAM, SOCK_RAW, 4, 0, 15] {
                assert_eq!(
                    call(
                        policy,
                        SYS_socketpair,
                        [AF_UNIX as u64, kind as u64, 0, 0, 0, 0]
                    ),
                    RET_EPERM,
                    "{policy:?} unix pair of type {kind}"
                );
            }
            assert_eq!(
                call(
                    policy,
                    SYS_socketpair,
                    [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0]
                ),
                RET_EPERM
            );
            // The kernel reads the domain as an int: upper bits do not turn AF_INET into AF_UNIX.
            assert_eq!(
                call(
                    policy,
                    SYS_socketpair,
                    [(1 << 32) | AF_INET as u64, 1, 0, 0, 0, 0]
                ),
                RET_EPERM
            );
        }
    }

    #[test]
    fn a_supervised_server_asks_for_unix_stream_and_seqpacket_sockets_and_nothing_else() {
        use libc::*;
        let s = Sockets::Supervised;
        for kind in [
            SOCK_STREAM,
            SOCK_SEQPACKET,
            SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
        ] {
            assert_eq!(
                call(s, SYS_socket, [AF_UNIX as u64, kind as u64, 0, 0, 0, 0]),
                RET_NOTIFY,
                "socket(AF_UNIX, {kind})"
            );
        }
        for kind in [SOCK_DGRAM, SOCK_RAW, SOCK_DGRAM | SOCK_CLOEXEC, 0, 15] {
            assert_eq!(
                call(s, SYS_socket, [AF_UNIX as u64, kind as u64, 0, 0, 0, 0]),
                RET_EPERM,
                "socket(AF_UNIX, {kind})"
            );
        }
        for domain in [AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, AF_VSOCK, 4095] {
            for kind in [SOCK_STREAM, SOCK_SEQPACKET, SOCK_DGRAM] {
                assert_eq!(
                    call(s, SYS_socket, [domain as u64, kind as u64, 0, 0, 0, 0]),
                    RET_EPERM,
                    "socket({domain}, {kind})"
                );
            }
        }
        assert_eq!(
            call(
                s,
                SYS_socket,
                [(1 << 32) | AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0]
            ),
            RET_EPERM
        );
        for nr in [SYS_bind, SYS_listen, SYS_accept, SYS_accept4] {
            assert_eq!(call(s, nr, [3, 0, 0, 0, 0, 0]), RET_NOTIFY, "{nr}");
        }
        assert_eq!(call(s, SYS_connect, [3, 0, 0, 0, 0, 0]), RET_EPERM);
    }

    #[test]
    fn listed_syscalls_are_refused_whatever_their_arguments() {
        for policy in POLICIES {
            for (name, nr) in always_denied() {
                for args in [[0; 6], [u64::MAX; 6], [1, 2, 3, 4, 5, 6]] {
                    assert_eq!(
                        call(policy, nr, args),
                        RET_EPERM,
                        "{policy:?} {name} {args:x?}"
                    );
                }
            }
        }
    }

    #[test]
    fn no_listener_of_its_own_no_keystrokes_no_ptracer() {
        use libc::*;
        for policy in POLICIES {
            // seccomp(SET_MODE_FILTER, flags): NEW_LISTENER in any combination is refused...
            for flags in [8u64, 8 | 1, 8 | 2 | 4, u64::MAX] {
                assert_eq!(call(policy, SYS_seccomp, [1, flags, 0, 0, 0, 0]), RET_EPERM);
            }
            // ...other filters (which can only take more away) are not.
            for flags in [0u64, 1, 2, 4] {
                assert_eq!(call(policy, SYS_seccomp, [1, flags, 0, 0, 0, 0]), RET_ALLOW);
            }
            assert_eq!(call(policy, SYS_ioctl, [0, TIOCSTI, 0, 0, 0, 0]), RET_EPERM);
            assert_eq!(
                call(policy, SYS_ioctl, [2, TIOCLINUX, 0, 0, 0, 0]),
                RET_EPERM
            );
            assert_eq!(
                call(policy, SYS_ioctl, [3, 0x5401, 0, 0, 0, 0]),
                RET_ALLOW,
                "TCGETS"
            );
            assert_eq!(
                call(
                    policy,
                    SYS_prctl,
                    [PR_SET_PTRACER as u64, u64::MAX, 0, 0, 0, 0]
                ),
                RET_EPERM
            );
            assert_eq!(
                call(policy, SYS_prctl, [PR_SET_NAME as u64, 0, 0, 0, 0, 0]),
                RET_ALLOW
            );
        }
    }

    /// What a GPU worker needs stays allowed: the filter is a denylist.
    #[test]
    fn everything_else_is_allowed() {
        use libc::*;
        let mut allowed = vec![
            SYS_sendto,
            SYS_recvfrom,
            SYS_sendmsg,
            SYS_recvmsg,
            SYS_mmap,
            SYS_munmap,
            SYS_clone,
            SYS_execve,
            SYS_openat,
            SYS_read,
            SYS_write,
            SYS_futex,
            SYS_getpid,
            SYS_pidfd_open,
            SYS_kill,
            SYS_statfs,
            SYS_fstatfs,
            SYS_newfstatat,
            SYS_statx,
        ];
        #[cfg(target_arch = "x86_64")]
        allowed.extend([SYS_fork, SYS_vfork, SYS_open]);
        for policy in POLICIES {
            for nr in &allowed {
                assert_eq!(
                    call(policy, *nr, [3, 0x1000, 16, 0, 0, 0]),
                    RET_ALLOW,
                    "{nr}"
                );
            }
        }
    }

    #[test]
    fn no_namespace_no_mount_and_clone3_unimplemented() {
        use libc::*;
        let named: Vec<&str> = always_denied().iter().map(|(n, _)| *n).collect();
        for name in [
            "unshare",
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
        ] {
            assert!(named.contains(&name), "{name} is not denied");
        }
        let enosys = libc::SECCOMP_RET_ERRNO | ENOSYS as u32;
        // pthread_create, fork, vfork/posix_spawn: their clone flags.
        let thread = (CLONE_VM
            | CLONE_FS
            | CLONE_FILES
            | CLONE_SIGHAND
            | CLONE_THREAD
            | CLONE_SYSVSEM
            | CLONE_SETTLS
            | CLONE_PARENT_SETTID
            | CLONE_CHILD_CLEARTID) as u64;
        let fork = (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD) as u64;
        let vfork = (CLONE_VM | CLONE_VFORK | SIGCHLD) as u64;
        for policy in POLICIES {
            for flags in [thread, fork, vfork, SIGCHLD as u64] {
                assert_eq!(
                    call(policy, SYS_clone, [flags, 0, 0, 0, 0, 0]),
                    RET_ALLOW,
                    "{policy:?} clone({flags:#x})"
                );
            }
            for (name, flag) in CLONE_NEW_FLAGS {
                for base in [fork, thread, 0] {
                    for high in [0u64, 0xffff_ffff_0000_0000] {
                        let flags = high | base | flag as u64;
                        assert_eq!(
                            call(policy, SYS_clone, [flags, 0, 0, 0, 0, 0]),
                            RET_EPERM,
                            "{policy:?} clone with {name} ({flags:#x})"
                        );
                    }
                }
            }
            // The upper half of the flags, which the kernel ignores, does not refuse a fork.
            assert_eq!(
                call(
                    policy,
                    SYS_clone,
                    [0xffff_ffff_0000_0000 | fork, 0, 0, 0, 0, 0]
                ),
                RET_ALLOW
            );
            // clone3, whatever its arguments: unimplemented, so libc falls back to clone.
            for args in [[0; 6], [u64::MAX; 6], [0x7f00_0000_1000, 88, 0, 0, 0, 0]] {
                assert_eq!(call(policy, SYS_clone3, args), enosys, "{policy:?}");
            }
            #[cfg(target_arch = "x86_64")]
            assert_eq!(
                call(policy, 0x4000_0000 | SYS_clone3, [0; 6]),
                RET_EPERM,
                "x32 clone3"
            );
        }
    }

    #[test]
    fn foreign_abis_are_killed_and_x32_refused() {
        for policy in POLICIES {
            let filters = all(policy);
            // Another architecture (`int 0x80` on x86_64, AArch32 on aarch64): the process is killed.
            let foreign = 3 | 0x4000_0000;
            assert_eq!(
                verdict_of(&filters, &seccomp_data(foreign, 102, [0; 6])),
                RET_KILL,
                "i386 socketcall"
            );
            #[cfg(target_arch = "x86_64")]
            {
                // x32 aliases of an allowed or a supervised call alike: EPERM, never the 64-bit verdict.
                let x32 = |nr: i64| 0x4000_0000 | nr;
                assert_eq!(call(policy, x32(libc::SYS_getpid), [0; 6]), RET_EPERM);
                assert_eq!(
                    call(
                        policy,
                        x32(libc::SYS_socket),
                        [libc::AF_UNIX as u64, 1, 0, 0, 0, 0]
                    ),
                    RET_EPERM
                );
                assert_eq!(
                    call(policy, x32(libc::SYS_bind), [3, 0, 0, 0, 0, 0]),
                    RET_EPERM
                );
            }
        }
    }

    #[test]
    fn a_listener_is_kept_a_connection_only_to_ones_own() {
        let me = std::process::id() as i32;
        let sock = |family, kind, listening, peer| OpenSocket {
            fd: 9,
            family: Some(family),
            kind: Some(kind),
            listening,
            peer,
            inode: 1,
        };
        let listener = sock(libc::AF_UNIX, libc::SOCK_SEQPACKET, true, None);
        let to_self = sock(libc::AF_UNIX, libc::SOCK_STREAM, false, Some(me));
        // Our parent (the test harness) is no child of ours.
        let parent = unsafe { libc::getppid() };
        let to_parent = sock(libc::AF_UNIX, libc::SOCK_STREAM, false, Some(parent));
        let inet = sock(libc::AF_INET, libc::SOCK_STREAM, false, None);
        let dgram = sock(libc::AF_UNIX, libc::SOCK_DGRAM, false, Some(me));
        assert!(sockets_not_allowed(Sockets::None, std::slice::from_ref(&listener)).is_empty());
        assert_eq!(
            sockets_not_allowed(Sockets::None, std::slice::from_ref(&to_self)).len(),
            1
        );
        assert!(
            sockets_not_allowed(Sockets::KeepConnected, &[listener.clone(), to_self]).is_empty()
        );
        for bad in [to_parent, inet, dgram] {
            for policy in POLICIES {
                assert_eq!(
                    sockets_not_allowed(policy, std::slice::from_ref(&bad)).len(),
                    1,
                    "{policy:?} {bad}"
                );
            }
        }
        assert_eq!(
            sockets_not_allowed(Sockets::Supervised, &[listener]).len(),
            1
        );
    }
}
