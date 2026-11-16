//! No network for a process that runs requester code outside the sandbox profiles
//! ([`deny_network_all_threads`]).
//!
//! The miner's inline proving and measuring workers run requester guests in their own process, and
//! cannot take a [`crate::Profile`]: the GPU stack needs device files, a writable home, ioctls,
//! `mmap`, threads and helper processes. What they do not need, once their one-time setup (downloads
//! of proving keys and circuit artifacts) is done, is the network. So the first time such a worker
//! is about to run a requester's guest, it calls [`deny_network_all_threads`]: defense in depth, so
//! that workers that run requester guests have no network, whatever happens inside them.
//!
//! The filter allows everything except, with `EPERM`:
//! - `socket` and `socketpair` of any domain but `AF_UNIX` (a GPU server or helper the worker talks
//!   to over a Unix socket keeps working; `AF_INET`, `AF_INET6`, `AF_PACKET`, `AF_NETLINK`,
//!   `AF_VSOCK`, ... do not);
//! - `io_uring_setup`, `io_uring_enter`, `io_uring_register` (io_uring operations, socket creation
//!   and connects included, bypass seccomp);
//! - `bpf`;
//! - `ptrace`, `process_vm_readv`, `process_vm_writev` and `pidfd_getfd`: another process of the same
//!   uid (the miner, which holds network connections) must not be driven, read, written, or have its
//!   connected sockets copied out;
//! - on x86_64, every x32 syscall (a denylist keyed by 64-bit numbers would miss their aliases);
//!
//! and kills the process on a syscall of a foreign ABI (e.g. `int 0x80` on x86_64), as the sandbox
//! profiles' filters do. `NO_NEW_PRIVS` is set first, so no setuid program run afterwards regains
//! what the filter takes away. The filter is installed with `SECCOMP_FILTER_FLAG_TSYNC`: it covers
//! every thread the process already has, and every thread and child process it creates afterwards
//! inherits it (across `exec` too).
//!
//! It cannot close what is already open: [`deny_network_all_threads`] therefore fails if the process
//! still holds a network socket ([`open_network_sockets`]), so a connection kept alive by an earlier
//! download is caught rather than handed to the guest.

use std::collections::BTreeMap;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::SandboxError;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("zkminer-witness-sandbox's network filter covers x86_64 and aarch64 only");

/// Set once this process has installed the filter.
static INSTALLED: AtomicBool = AtomicBool::new(false);
/// Serialises installs, so two threads never stack two filters.
static INSTALL: Mutex<()> = Mutex::new(());

/// Syscalls denied whatever their arguments.
const DENIED: [(&str, i64); 8] = [
    ("io_uring_setup", libc::SYS_io_uring_setup),
    ("io_uring_enter", libc::SYS_io_uring_enter),
    ("io_uring_register", libc::SYS_io_uring_register),
    ("bpf", libc::SYS_bpf),
    ("ptrace", libc::SYS_ptrace),
    ("process_vm_readv", libc::SYS_process_vm_readv),
    ("process_vm_writev", libc::SYS_process_vm_writev),
    ("pidfd_getfd", libc::SYS_pidfd_getfd),
];

/// Denies this process, all of its threads and everything it starts from now on any network: see
/// the [module docs](self) for the filter. Idempotent: the filter is installed once per process,
/// and a later call only checks again.
///
/// After installing it checks the result rather than the calls: `PR_GET_SECCOMP == 2`,
/// `PR_GET_NO_NEW_PRIVS == 1`, every thread in `/proc/self/task` in seccomp filter mode, and
/// `socket(AF_INET)` and `socket(AF_INET6)` failing with `EPERM`. Then it fails if a network socket
/// (anything but `AF_UNIX` and `AF_NETLINK`) is still open in the process, which the filter cannot
/// take back; the caller must drop it (or exit) and call again.
///
/// Fails closed: on any error the caller must not run the guest. Once the filter is installed it
/// stays installed, error or not ([`is_active`]).
pub fn deny_network_all_threads() -> Result<(), SandboxError> {
    {
        let _install = INSTALL.lock().unwrap_or_else(|e| e.into_inner());
        if !INSTALLED.load(Ordering::Acquire) {
            // Everything that allocates happens before any filter is applied.
            let filters = filters()?;
            // SAFETY: plain prctl with valid arguments.
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            for filter in &filters {
                seccompiler::apply_filter_all_threads(filter)
                    .map_err(|e| SandboxError::Seccomp(e.to_string()))?;
                // Set as soon as one filter is in: from then on the process has lost something.
                INSTALLED.store(true, Ordering::Release);
            }
        }
    }
    verify()?;
    let open = open_network_sockets()?;
    if !open.is_empty() {
        let list: Vec<String> = open.iter().map(ToString::to_string).collect();
        return Err(SandboxError::Seccomp(format!(
            "the network filter is on, but {} network socket{} opened before it {} still open ({}): \
             a filter stops new sockets, not these",
            open.len(),
            if open.len() == 1 { "" } else { "s" },
            if open.len() == 1 { "is" } else { "are" },
            list.join(", ")
        )));
    }
    Ok(())
}

/// Whether this process has installed the network filter ([`deny_network_all_threads`]), so it can
/// no longer open a network socket. A filter inherited from the parent does not count: only one
/// this process installed.
pub fn is_active() -> bool {
    INSTALLED.load(Ordering::Acquire)
}

/// One socket open in this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSocket {
    pub fd: RawFd,
    /// `SO_DOMAIN` (an `AF_*` value); `None` if the socket would not say.
    pub family: Option<i32>,
    /// The socket's inode, as `/proc/<pid>/fd/<fd>` shows it (`socket:[inode]`).
    pub inode: u64,
}

impl std::fmt::Display for OpenSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let family = match self.family {
            Some(libc::AF_INET) => "AF_INET".to_string(),
            Some(libc::AF_INET6) => "AF_INET6".to_string(),
            Some(libc::AF_PACKET) => "AF_PACKET".to_string(),
            Some(libc::AF_VSOCK) => "AF_VSOCK".to_string(),
            Some(other) => format!("family {other}"),
            None => "unknown family".to_string(),
        };
        write!(f, "fd {} ({family}, socket:[{}])", self.fd, self.inode)
    }
}

/// The sockets open in this process that can reach a network: every socket but `AF_UNIX` (a local
/// endpoint, which the filter allows too) and `AF_NETLINK` (the kernel). From `/proc/self/fd`,
/// asking each socket its domain (`SO_DOMAIN`); one whose domain cannot be read is listed too.
pub fn open_network_sockets() -> std::io::Result<Vec<OpenSocket>> {
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
        let mut domain: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `domain` and `len` are valid for the kernel to write an int into.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                (&mut domain as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        let family = (rc == 0).then_some(domain);
        if !matches!(family, Some(libc::AF_UNIX | libc::AF_NETLINK)) {
            found.push(OpenSocket {
                fd,
                family,
                inode: st.st_ino,
            });
        }
    }
    Ok(found)
}

/// Checks what [`deny_network_all_threads`] promises, not that its calls returned.
fn verify() -> Result<(), SandboxError> {
    let fail = |what: String| Err(SandboxError::Seccomp(format!("network filter: {what}")));
    // SAFETY: getter prctls take no pointers.
    let (mode, nnp) = unsafe {
        (
            libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0),
            libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
        )
    };
    if mode != 2 || nnp != 1 {
        return fail(format!(
            "PR_GET_SECCOMP is {mode}, PR_GET_NO_NEW_PRIVS {nnp}"
        ));
    }
    if let Some(tid) = threads_not_in_filter_mode()?.first() {
        return fail(format!("thread {tid} is not in seccomp filter mode"));
    }
    for (name, domain, kind) in [
        ("AF_INET", libc::AF_INET, libc::SOCK_STREAM),
        ("AF_INET6", libc::AF_INET6, libc::SOCK_DGRAM),
    ] {
        // SAFETY: socket takes no pointers; an fd it returns is closed below.
        let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, 0) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        if fd >= 0 {
            // SAFETY: closing the fd just opened.
            unsafe { libc::close(fd) };
            return fail(format!("socket({name}) still succeeds"));
        }
        if errno != Some(libc::EPERM) {
            return fail(format!("socket({name}) failed with {errno:?}, not EPERM"));
        }
    }
    Ok(())
}

/// Threads of this process whose `/proc/self/task/<tid>/status` does not say `Seccomp: 2`. A thread
/// that exited while being read is skipped.
fn threads_not_in_filter_mode() -> std::io::Result<Vec<String>> {
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

fn cond(arg: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompCondition, SandboxError> {
    // `Dword`: socket's arguments are `int`s, whose upper 32 bits the kernel ignores, and so does
    // this comparison.
    SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, value)
        .map_err(|e| SandboxError::Seccomp(e.to_string()))
}

fn target_arch() -> Result<TargetArch, SandboxError> {
    std::env::consts::ARCH
        .try_into()
        .map_err(|e: seccompiler::BackendError| SandboxError::Seccomp(e.to_string()))
}

/// The denylist (seccompiler; its architecture check kills the process on a foreign-ABI syscall).
fn denylist() -> Result<BpfProgram, SandboxError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for (_, nr) in DENIED {
        // An empty rule list matches whatever the arguments.
        rules.insert(nr, Vec::new());
    }
    for nr in [libc::SYS_socket, libc::SYS_socketpair] {
        let not_unix = SeccompRule::new(vec![cond(0, SeccompCmpOp::Ne, libc::AF_UNIX as u64)?])
            .map_err(|e| SandboxError::Seccomp(e.to_string()))?;
        rules.insert(nr, vec![not_unix]);
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

/// On x86_64, a hand-written filter for what a denylist keyed by 64-bit syscall numbers misses: every
/// x32 syscall (`nr >= 0x40000000`, the same architecture to seccomp) fails with `EPERM`. It checks
/// the architecture too, killing on a foreign one. On aarch64 there is no such alias.
fn x32_filter() -> Option<BpfProgram> {
    #[cfg(target_arch = "x86_64")]
    {
        const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
        const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
        const BPF_JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
        const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K
        const ARCH_OFFSET: u32 = 4;
        const NR_OFFSET: u32 = 0;
        const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;
        let insn = |code, jt, jf, k| seccompiler::sock_filter { code, jt, jf, k };
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        Some(vec![
            /* 0 */ insn(BPF_LD_W_ABS, 0, 0, ARCH_OFFSET),
            /* 1 */ insn(BPF_JEQ_K, 0, 4, AUDIT_ARCH_X86_64), // else -> 6 (kill)
            /* 2 */ insn(BPF_LD_W_ABS, 0, 0, NR_OFFSET),
            /* 3 */ insn(BPF_JGE_K, 1, 0, 0x4000_0000), // x32 -> 5 (EPERM)
            /* 4 */ insn(BPF_RET_K, 0, 0, libc::SECCOMP_RET_ALLOW),
            /* 5 */ insn(BPF_RET_K, 0, 0, eperm),
            /* 6 */ insn(BPF_RET_K, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        ])
    }
    #[cfg(target_arch = "aarch64")]
    {
        None
    }
}

/// The filters [`deny_network_all_threads`] installs, in order.
fn filters() -> Result<Vec<BpfProgram>, SandboxError> {
    let mut v: Vec<BpfProgram> = x32_filter().into_iter().collect();
    v.push(denylist()?);
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const RET_EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    const RET_KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 62 | 0x8000_0000 | 0x4000_0000;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 183 | 0x8000_0000 | 0x4000_0000;

    /// `struct seccomp_data`: nr, arch, instruction pointer, six 64-bit arguments.
    fn seccomp_data(arch: u32, nr: i64, args: [u64; 6]) -> [u8; 64] {
        let mut d = [0u8; 64];
        d[0..4].copy_from_slice(&(nr as u32).to_ne_bytes());
        d[4..8].copy_from_slice(&arch.to_ne_bytes());
        d[8..16].copy_from_slice(&0x7f00_dead_beefu64.to_ne_bytes());
        for (i, a) in args.iter().enumerate() {
            d[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_ne_bytes());
        }
        d
    }

    /// A classic-BPF interpreter for exactly the instructions seccompiler and [`x32_filter`] emit;
    /// anything else panics, so a seccompiler upgrade that emits more cannot pass silently.
    fn run_bpf(prog: &[seccompiler::sock_filter], data: &[u8; 64]) -> u32 {
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
                0x06 => return i.k,
                c => panic!("unexpected BPF opcode {c:#06x} at {}", pc - 1),
            }
        }
        panic!("BPF program did not return");
    }

    /// Every filter runs and the most restrictive action wins, as in the kernel.
    fn verdict(data: &[u8; 64]) -> u32 {
        let mut ret = RET_ALLOW;
        for f in filters().unwrap().iter().rev() {
            let cur = run_bpf(f, data);
            if ((cur & 0xffff_0000) as i32) < ((ret & 0xffff_0000) as i32) {
                ret = cur;
            }
        }
        ret
    }

    fn call(nr: i64, args: [u64; 6]) -> u32 {
        verdict(&seccomp_data(ARCH, nr, args))
    }

    #[test]
    fn sockets_other_than_unix_are_refused() {
        use libc::*;
        for (nr, name) in [(SYS_socket, "socket"), (SYS_socketpair, "socketpair")] {
            for domain in [
                AF_INET,
                AF_INET6,
                AF_PACKET,
                AF_NETLINK,
                AF_VSOCK,
                AF_UNSPEC,
                AF_BLUETOOTH,
                4095,
            ] {
                for kind in [SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET] {
                    assert_eq!(
                        call(nr, [domain as u64, kind as u64, 0, 0, 0, 0]),
                        RET_EPERM,
                        "{name}({domain}, {kind})"
                    );
                }
            }
            for kind in [SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET | SOCK_CLOEXEC] {
                assert_eq!(
                    call(nr, [AF_UNIX as u64, kind as u64, 0, 0, 0, 0]),
                    RET_ALLOW,
                    "{name}(AF_UNIX, {kind})"
                );
            }
            // The kernel reads the domain as an int: upper bits do not turn AF_INET into AF_UNIX
            // or the reverse.
            assert_eq!(
                call(nr, [(1 << 32) | AF_INET as u64, 1, 0, 0, 0, 0]),
                RET_EPERM
            );
            assert_eq!(
                call(nr, [(1 << 32) | AF_UNIX as u64, 1, 0, 0, 0, 0]),
                RET_ALLOW
            );
        }
    }

    #[test]
    fn listed_syscalls_are_refused_whatever_their_arguments() {
        for (name, nr) in DENIED {
            for args in [[0; 6], [u64::MAX; 6], [1, 2, 3, 4, 5, 6]] {
                assert_eq!(call(nr, args), RET_EPERM, "{name} with {args:x?}");
            }
        }
    }

    /// What a GPU worker needs stays allowed: the filter is a denylist.
    #[test]
    fn everything_else_is_allowed() {
        use libc::*;
        let mut allowed = vec![
            SYS_connect,
            SYS_sendto,
            SYS_recvfrom,
            SYS_ioctl,
            SYS_mmap,
            SYS_munmap,
            SYS_clone,
            SYS_clone3,
            SYS_execve,
            SYS_openat,
            SYS_read,
            SYS_write,
            SYS_futex,
            SYS_getpid,
            SYS_pidfd_open,
        ];
        #[cfg(target_arch = "x86_64")]
        allowed.extend([SYS_fork, SYS_vfork, SYS_open]);
        for nr in allowed {
            assert_eq!(
                call(nr, [3, 0x1000, 16, 0, 0, 0]),
                RET_ALLOW,
                "syscall {nr}"
            );
        }
    }

    #[test]
    fn foreign_abis_are_killed_and_x32_refused() {
        // Another architecture (`int 0x80` on x86_64, AArch32 on aarch64): the process is killed.
        let i386 = 3 | 0x4000_0000;
        assert_eq!(
            verdict(&seccomp_data(i386, 102, [0; 6])),
            RET_KILL,
            "i386 socketcall"
        );
        assert_eq!(verdict(&seccomp_data(i386, 20, [0; 6])), RET_KILL);
        #[cfg(target_arch = "x86_64")]
        {
            // x32 aliases of an allowed or a filtered call alike: EPERM, never the 64-bit verdict.
            let x32 = |nr: i64| 0x4000_0000 | nr;
            assert_eq!(call(x32(libc::SYS_getpid), [0; 6]), RET_EPERM);
            assert_eq!(
                call(x32(libc::SYS_socket), [libc::AF_INET as u64, 1, 0, 0, 0, 0]),
                RET_EPERM
            );
            assert_eq!(
                call(x32(libc::SYS_socket), [libc::AF_UNIX as u64, 1, 0, 0, 0, 0]),
                RET_EPERM
            );
        }
    }

    // --- The live filter, in a child process: a test process with the filter on would deny every
    // test after it.

    /// Set in the child that installs the filter.
    const CHILD_ENV: &str = "ZKMINER_NETDENY_TEST_CHILD";
    /// Set in a process that child starts, which only checks what it inherited.
    const PROBE_ENV: &str = "ZKMINER_NETDENY_TEST_PROBE";

    /// Runs one test of this binary, by its exact name, in a new process with `env` set.
    fn run_test_in_child(name: &str, env: &str) -> std::process::Output {
        Command::new(std::env::current_exe().unwrap())
            .args([name, "--exact", "--nocapture", "--test-threads=1"])
            .env(env, "1")
            .output()
            .unwrap()
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// `socket(domain, kind)`: Ok(fd) or Err(errno).
    fn socket(domain: i32, kind: i32) -> Result<RawFd, i32> {
        // SAFETY: no pointers.
        let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, 0) };
        if fd >= 0 {
            Ok(fd)
        } else {
            Err(errno())
        }
    }

    fn close(fd: RawFd) {
        // SAFETY: an fd this test opened.
        unsafe { libc::close(fd) };
    }

    /// `Seccomp:` and `NoNewPrivs:` of a `/proc/<pid>[/task/<tid>]/status`.
    fn seccomp_status(status_path: &str) -> (String, String) {
        let status = std::fs::read_to_string(status_path).unwrap();
        let field = |name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .map(|v| v.trim().to_string())
                .unwrap_or_default()
        };
        (field("Seccomp:"), field("NoNewPrivs:"))
    }

    #[test]
    fn the_live_filter_covers_every_thread_and_child() {
        let out = run_test_in_child("netdeny::tests::live_filter_child", CHILD_ENV);
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{log}");
        assert!(log.contains("LIVE FILTER CHECKS PASSED"), "{log}");
    }

    /// The child side of [`the_live_filter_covers_every_thread_and_child`]; a no-op elsewhere.
    #[test]
    fn live_filter_child() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        use std::sync::mpsc;

        // A thread started BEFORE the filter, which tries sockets when told to, then lives until
        // told to exit (so its /proc entry can still be read).
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (res_tx, res_rx) = mpsc::channel();
        let early = std::thread::spawn(move || {
            // SAFETY: gettid takes no arguments.
            let tid = unsafe { libc::syscall(libc::SYS_gettid) };
            go_rx.recv().unwrap();
            let inet = socket(libc::AF_INET, libc::SOCK_STREAM);
            let unix = socket(libc::AF_UNIX, libc::SOCK_STREAM);
            res_tx.send((tid, inet, unix)).unwrap();
            go_rx.recv().unwrap();
        });

        assert!(!is_active());
        // Without the filter, an inet socket opens (no network needed for that).
        close(socket(libc::AF_INET, libc::SOCK_DGRAM).expect("AF_INET before the filter"));

        // A socket left open from before (a download's connection, say) fails the call...
        let leftover = socket(libc::AF_INET, libc::SOCK_DGRAM).unwrap();
        let mut pair = [-1; 2];
        // SAFETY: `pair` holds the two fds.
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            },
            0
        );
        let open = open_network_sockets().unwrap();
        assert_eq!(open.len(), 1, "{open:?}");
        assert_eq!(
            (open[0].fd, open[0].family),
            (leftover, Some(libc::AF_INET))
        );
        let err = deny_network_all_threads().unwrap_err().to_string();
        assert!(err.contains(&format!("fd {leftover} (AF_INET")), "{err}");
        // ...with the filter on all the same...
        assert!(is_active());
        assert_eq!(socket(libc::AF_INET, libc::SOCK_STREAM), Err(libc::EPERM));
        // ...and passes once it is closed. Calling again installs nothing more.
        close(leftover);
        deny_network_all_threads().unwrap();
        deny_network_all_threads().unwrap();
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let filters_installed = status
            .lines()
            .find_map(|l| l.strip_prefix("Seccomp_filters:"))
            .map(|v| v.trim().to_string());
        if let Some(n) = filters_installed {
            assert_eq!(n, filters().unwrap().len().to_string(), "installed once");
        }
        assert!(
            open_network_sockets().unwrap().is_empty(),
            "the unix pair is no network"
        );
        close(pair[0]);
        close(pair[1]);

        // This thread: no socket of any other domain, AF_UNIX as before.
        for domain in [
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_NETLINK,
            libc::AF_PACKET,
        ] {
            for kind in [libc::SOCK_STREAM, libc::SOCK_DGRAM, libc::SOCK_RAW] {
                assert_eq!(socket(domain, kind), Err(libc::EPERM), "{domain}/{kind}");
            }
        }
        // SAFETY: `pair` holds the two fds; the other calls take no pointers the kernel reads
        // (null and zero lengths).
        unsafe {
            assert_eq!(
                libc::socketpair(libc::AF_INET, libc::SOCK_STREAM, 0, pair.as_mut_ptr()),
                -1
            );
            assert_eq!(errno(), libc::EPERM);
            close(socket(libc::AF_UNIX, libc::SOCK_STREAM).expect("AF_UNIX stream"));
            close(socket(libc::AF_UNIX, libc::SOCK_DGRAM).expect("AF_UNIX datagram"));
            assert_eq!(
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr()
                ),
                0
            );
            close(pair[0]);
            close(pair[1]);
            for (name, nr, args) in [
                ("io_uring_setup", libc::SYS_io_uring_setup, [0i64; 6]),
                (
                    "io_uring_enter",
                    libc::SYS_io_uring_enter,
                    [-1, 0, 0, 0, 0, 0],
                ),
                (
                    "io_uring_register",
                    libc::SYS_io_uring_register,
                    [-1, 0, 0, 0, 0, 0],
                ),
                ("bpf", libc::SYS_bpf, [-1, 0, 0, 0, 0, 0]),
                // An invalid request on pid 0: ESRCH or EIO without the filter.
                ("ptrace", libc::SYS_ptrace, [0xffff, 0, 0, 0, 0, 0]),
                // Reading nothing from ourselves: 0 without the filter.
                (
                    "process_vm_readv",
                    libc::SYS_process_vm_readv,
                    [libc::getpid() as i64, 0, 0, 0, 0, 0],
                ),
                (
                    "process_vm_writev",
                    libc::SYS_process_vm_writev,
                    [libc::getpid() as i64, 0, 0, 0, 0, 0],
                ),
                // EBADF without the filter.
                ("pidfd_getfd", libc::SYS_pidfd_getfd, [-1, 0, 0, 0, 0, 0]),
            ] {
                let r = libc::syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]);
                assert_eq!((r, errno()), (-1, libc::EPERM), "{name}");
            }
        }
        let (seccomp, nnp) = seccomp_status("/proc/self/status");
        assert_eq!((seccomp.as_str(), nnp.as_str()), ("2", "1"));

        // The thread that existed before the filter has it too (TSYNC).
        go_tx.send(()).unwrap();
        let (tid, inet, unix) = res_rx.recv().unwrap();
        assert_eq!(inet, Err(libc::EPERM), "a thread started before the filter");
        close(unix.expect("AF_UNIX in that thread"));
        let (seccomp, _) = seccomp_status(&format!("/proc/self/task/{tid}/status"));
        assert_eq!(seccomp, "2");
        go_tx.send(()).unwrap();
        early.join().unwrap();
        // And one started after.
        let late = std::thread::spawn(|| socket(libc::AF_INET6, libc::SOCK_STREAM))
            .join()
            .unwrap();
        assert_eq!(late, Err(libc::EPERM));

        // A forked child (no exec), which only makes raw calls before `_exit`.
        // SAFETY: the child calls only async-signal-safe functions.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                let code = if fd < 0 && *libc::__errno_location() == libc::EPERM {
                    0
                } else {
                    1
                };
                libc::_exit(code);
            }
        }
        let mut st = 0;
        // SAFETY: waiting for the child just forked.
        assert_eq!(unsafe { libc::waitpid(pid, &mut st, 0) }, pid);
        assert!(
            libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
            "forked child: {st:#x}"
        );

        // Programs started after: they run, and inherit the filter across exec.
        assert!(Command::new("/bin/true").status().unwrap().success());
        let mut sleeper = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let (seccomp, nnp) = seccomp_status(&format!("/proc/{}/status", sleeper.id()));
        let _ = sleeper.kill();
        let _ = sleeper.wait();
        assert_eq!(
            (seccomp.as_str(), nnp.as_str()),
            ("2", "1"),
            "an exec'd child"
        );
        let probe = run_test_in_child("netdeny::tests::inherited_filter_probe", PROBE_ENV);
        assert!(
            probe.status.success(),
            "{}{}",
            String::from_utf8_lossy(&probe.stdout),
            String::from_utf8_lossy(&probe.stderr)
        );
        assert!(String::from_utf8_lossy(&probe.stdout).contains("PROBE: INHERITED"));
        println!("LIVE FILTER CHECKS PASSED");
    }

    /// Started by [`live_filter_child`] after its filter is on; a no-op elsewhere.
    #[test]
    fn inherited_filter_probe() {
        if std::env::var_os(PROBE_ENV).is_none() {
            return;
        }
        // Not installed by this process: inherited across fork and exec.
        assert!(!is_active());
        assert_eq!(socket(libc::AF_INET, libc::SOCK_STREAM), Err(libc::EPERM));
        assert_eq!(socket(libc::AF_INET6, libc::SOCK_DGRAM), Err(libc::EPERM));
        close(socket(libc::AF_UNIX, libc::SOCK_STREAM).expect("AF_UNIX"));
        let (seccomp, nnp) = seccomp_status("/proc/self/status");
        assert_eq!((seccomp.as_str(), nnp.as_str()), ("2", "1"));
        println!("PROBE: INHERITED");
    }
}
