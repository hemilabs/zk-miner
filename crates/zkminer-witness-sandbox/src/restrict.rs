//! Child side: Landlock, seccomp and process attributes ([`restrict_self`]).

use std::collections::BTreeMap;
use std::path::Path;

use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd,
    RestrictSelfAttr, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
    Scope, ABI,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::{Profile, RestrictReport, SandboxError};

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("zkminer-witness-sandbox's seccomp filters cover x86_64 and aarch64 only");

/// The oldest Landlock ABI [`restrict_self`] accepts: ABI 6 (Linux 6.12) is the first with signal
/// and abstract Unix socket scoping; ABI 4 brought TCP bind/connect, ABI 3 truncate.
pub const MIN_LANDLOCK_ABI: i32 = 6;

/// The running kernel's Landlock ABI version, or 0 if Landlock is unavailable.
pub fn landlock_abi() -> i32 {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: a version query takes no pointers the kernel dereferences (attr is NULL, size 0).
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if v < 0 {
        0
    } else {
        v as i32
    }
}

/// Threads of the calling process, counted from `/proc/self/task`.
pub(crate) fn thread_count() -> std::io::Result<usize> {
    let mut n = 0;
    for entry in std::fs::read_dir("/proc/self/task")? {
        entry?;
        n += 1;
    }
    Ok(n)
}

/// Child side: applies `profile` to the calling process, irrevocably.
///
/// Call it first thing in `main` of the sandboxed binary: **before the process starts any thread**
/// (a tokio runtime, a wasmtime engine with parallel compilation, rayon, a logger thread) and before
/// it reads untrusted input. It fails with [`SandboxError::MultiThreaded`] if `/proc/self/task`
/// lists more than one thread. Both layers are also applied with thread synchronisation (seccomp
/// `TSYNC`, Landlock `RESTRICT_SELF_TSYNC` where the kernel has ABI 8), and every thread or process
/// created afterwards inherits them.
///
/// In order:
/// 1. **Landlock** (ABI >= [`MIN_LANDLOCK_ABI`], else [`SandboxError::LandlockUnavailable`]): every
///    filesystem right of ABI 6 is handled (plus newer ones the kernel knows, best effort) with no
///    rules, except read-only rules for [`Profile::Broker`]'s `readable` paths and read-write rules
///    for its `writable` directories; TCP bind and connect are handled with no rule (no profile
///    binds or connects TCP); signals and abstract Unix sockets are scoped to the sandbox.
///    `/proc`, `~/.zkminer`, `/tmp`, `/dev/shm` and GPU device nodes are therefore denied by path.
/// 2. `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE(0)`, `RLIMIT_CORE=0`, and no capabilities (the
///    effective, permitted, inheritable and ambient sets cleared, whoever started the miner).
/// 3. **seccomp** (default allow, denied syscalls fail with `EPERM`): see the module source for the
///    full list. Every profile: no `socket`, `connect`, `bind`, `listen`, `accept*`. Runner and
///    worker also: no `socketpair`, `open*`,
///    `creat`, `exec*`, `ptrace`, `process_vm_*`, namespaces, mounts, `bpf`, `perf_event_open`, keys,
///    `userfaultfd`, `io_uring_*`, module/kexec/clock/swap/reboot/quota/acct/iopl, file handles,
///    `personality`; also no new processes (`fork`, `vfork`, `clone` without `CLONE_THREAD`;
///    `clone3` fails with `ENOSYS` so libc falls back to the filterable `clone`), no SysV IPC
///    (`shm*`, `msg*`, `sem*`: segments and queues outlive the sandbox and its cgroup, and every one
///    of the miner's uid is reachable by key or id), no metadata writes by path (`chmod`, `chown`,
///    `utime*`, `*setxattr`, `*removexattr`, `file_setattr`, which Landlock does not cover) or through
///    an inherited fd (`fchmod`, `fchown`, `fsetxattr`, `fremovexattr`, `flock`, `fcntl`
///    `F_SETLEASE`/`F_NOTIFY`, `ioctl` `FS_IOC_SETFLAGS`/`FS_IOC_FSSETXATTR`), no `file_getattr`, no
///    reaching other processes of the same uid (`setpriority`, `ioprio_set`, `prlimit64`,
///    `sched_set*` on another pid, `migrate_pages`, `move_pages`, `process_madvise`, `pidfd_getfd`;
///    `getsid`/`getpgid` of another pid, which map sessions and process groups),
///    no LSM attribute writes (`lsm_set_self_attr`),
///    no `TIOCSTI`/`TIOCLINUX`, no `PR_SET_PDEATHSIG` (the parent-death signal stays), no
///    `PR_SET_DUMPABLE` (it stays 0) or `PR_SET_PTRACER`, no x32 syscalls. Runner and worker also
///    read no host metadata: no `uname`, `sysinfo`, `readlink*`, `access`/`faccessat*`,
///    `statfs`/`fstatfs`, `*getxattr*`/`*listxattr*`, `chdir`/`fchdir`, the mount table
///    (`listmount`/`statmount`), the LSMs (`lsm_list_modules`, `lsm_get_self_attr`), `ustat` and
///    `sysfs`, and `statx` fails with `ENOSYS` (std and glibc fall back to `fstat`/`newfstatat`,
///    which stay: a path's existence, size, owner and times remain readable without a mount
///    namespace). Runner and worker also set no socket option (`setsockopt`). The broker
///    additionally may `socketpair(AF_UNIX, SOCK_STREAM, ..)` (a connected
///    stream pair reaches nothing; tokio's signal driver needs one; a datagram pair could `sendto`
///    any pathname socket, which Landlock ABI 8 cannot restrict) until it calls
///    [`seal_socket_creation`], and open files (which Landlock confines). It has no `socket` and
///    no `connect`: its TCP connections come from the miner's connector, already connected, and
///    without `connect` it cannot disconnect one (`connect(AF_UNSPEC)`) to aim it elsewhere. Its
///    only socket option is `setsockopt(IPPROTO_TCP, TCP_NODELAY)`; every other level and option
///    fails with `EPERM`, so it cannot re-route a connected socket at the IP layer either (an IPv6
///    routing header, IPv4 source routing, binding it to an interface, a next hop, a mark, a TTL:
///    [`REFUSED_SOCKET_OPTIONS`]). Ancillary data on `sendmsg` cannot do it instead: TCP ignores
///    `IPPROTO_IP`/`IPPROTO_IPV6` control messages, and the one `SOL_SOCKET` message that steers
///    routing (`SO_MARK`) needs `CAP_NET_ADMIN`, which step 2 drops.
/// 4. Verification: `PR_GET_SECCOMP == 2`, `PR_GET_NO_NEW_PRIVS == 1`, `PR_GET_DUMPABLE == 0`,
///    `RLIMIT_CORE == 0`, `capget` all zero.
///
/// Fails closed: any error means some layer may be missing, and the caller must exit without
/// reading untrusted input. The process keeps the fds it already holds (its pipe, socket and
/// memfds); Landlock checks rights when a path is opened, not on existing fds.
pub fn restrict_self(profile: &Profile) -> Result<RestrictReport, SandboxError> {
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

    // Everything that allocates or opens a path happens before any restriction is applied.
    let ruleset = landlock_ruleset(profile)?;
    let filters = seccomp_filters(profile)?;

    set_process_attributes()?;

    let status = ruleset
        .restrict_self()
        .map_err(|e| SandboxError::Landlock(e.to_string()))?;
    if status.ruleset == RulesetStatus::NotEnforced || !status.no_new_privs {
        return Err(SandboxError::Landlock(format!(
            "ruleset not enforced: {status:?}"
        )));
    }

    for filter in &filters {
        seccompiler::apply_filter_all_threads(filter)
            .map_err(|e| SandboxError::Seccomp(e.to_string()))?;
    }

    let report = current_state(abi);
    if !(report.seccomp
        && report.no_new_privs
        && report.dumpable_cleared
        && report.core_dumps_disabled
        && report.capabilities_cleared)
    {
        return Err(SandboxError::Seccomp(format!(
            "restrictions did not take effect: {report:?}"
        )));
    }
    Ok(report)
}

/// The broker's second step, once its runtime has made the one socket pair it needs (tokio's
/// signal driver): a further seccomp filter, on every thread (`TSYNC`), that denies
/// `socketpair` as well (and, again, `socket`, `connect`, `bind`, `listen`, `accept`,
/// `accept4`). After it the process can make no socket of any kind; it keeps the ones it holds.
/// Requires [`restrict_self`] first (`NO_NEW_PRIVS`), and checks the result: `socketpair` must
/// then fail with `EPERM`.
pub fn seal_socket_creation() -> Result<(), SandboxError> {
    // SAFETY: a getter prctl.
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 {
        return Err(SandboxError::Seccomp(
            "seal_socket_creation needs restrict_self first".into(),
        ));
    }
    let filter = sealed_sockets_filter()?;
    seccompiler::apply_filter_all_threads(&filter)
        .map_err(|e| SandboxError::Seccomp(e.to_string()))?;
    let mut sv = [-1 as libc::c_int; 2];
    // SAFETY: socketpair writes two fds into `sv`; they are closed at once if it succeeds.
    let r = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    };
    let e = std::io::Error::last_os_error().raw_os_error();
    if r == 0 {
        // SAFETY: both fds were just created here.
        unsafe {
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
        return Err(SandboxError::Seccomp(
            "socketpair still works after seal_socket_creation".into(),
        ));
    }
    if e != Some(libc::EPERM) {
        return Err(SandboxError::Seccomp(format!(
            "socketpair after seal_socket_creation: {e:?}, not EPERM"
        )));
    }
    Ok(())
}

/// The syscalls [`seal_socket_creation`] denies.
pub(crate) const SEALED_SOCKET_SYSCALLS: &[(&str, i64)] = &[
    ("socket", libc::SYS_socket),
    ("socketpair", libc::SYS_socketpair),
    ("connect", libc::SYS_connect),
    ("bind", libc::SYS_bind),
    ("listen", libc::SYS_listen),
    ("accept", libc::SYS_accept),
    ("accept4", libc::SYS_accept4),
];

pub(crate) fn sealed_sockets_filter() -> Result<BpfProgram, SandboxError> {
    let rules: BTreeMap<i64, Vec<SeccompRule>> = SEALED_SOCKET_SYSCALLS
        .iter()
        .map(|&(_, nr)| (nr, Vec::new()))
        .collect();
    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch()?,
    )
    .map_err(|e| SandboxError::Seccomp(e.to_string()))?
    .try_into()
    .map_err(|e: seccompiler::BackendError| SandboxError::Seccomp(e.to_string()))
}

/// Reads back the process attributes [`restrict_self`] sets.
pub(crate) fn current_state(landlock_abi: i32) -> RestrictReport {
    // SAFETY: getter prctls take no pointers.
    let (seccomp, nnp, dumpable) = unsafe {
        (
            libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0),
            libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
            libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0),
        )
    };
    let mut core = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: `core` is a valid rlimit to write into.
    let core_ok = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) } == 0;
    RestrictReport {
        landlock_abi,
        seccomp: seccomp == 2,
        no_new_privs: nnp == 1,
        dumpable_cleared: dumpable == 0,
        core_dumps_disabled: core_ok && core.rlim_cur == 0 && core.rlim_max == 0,
        capabilities_cleared: capabilities_cleared(),
    }
}

fn set_process_attributes() -> Result<(), SandboxError> {
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain prctl/setrlimit calls with valid arguments.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    drop_capabilities()
}

/// `struct __user_cap_header_struct` / `__user_cap_data_struct` (version 3: two data words).
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}
#[repr(C)]
#[derive(Default, Clone, Copy, PartialEq, Eq)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Clears the effective, permitted and inheritable capability sets (and the ambient set, which
/// cannot outlive the permitted one). A process of an unprivileged uid holds none already; a
/// miner started as root would otherwise hand its sandboxes `CAP_NET_ADMIN` — with which a
/// per-packet `SO_MARK` on `sendmsg`, invisible to a seccomp filter, selects a mark-routed path —
/// `CAP_NET_RAW` and the rest. With `NO_NEW_PRIVS` and no `exec`, none can come back.
fn drop_capabilities() -> Result<(), SandboxError> {
    let mut header = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let none = [CapData::default(); 2];
    // SAFETY: a version-3 header and two data words, as capset(2) requires; lowering capabilities
    // needs no privilege.
    if unsafe { libc::syscall(libc::SYS_capset, &mut header as *mut CapHeader, none.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: an integer prctl.
    unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    Ok(())
}

/// Whether the calling thread holds no capability (effective, permitted, inheritable).
pub(crate) fn capabilities_cleared() -> bool {
    let mut header = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut data = [CapData { effective: !0, permitted: !0, inheritable: !0 }; 2];
    // SAFETY: as in `drop_capabilities`; capget writes two data words.
    let r = unsafe { libc::syscall(libc::SYS_capget, &mut header as *mut CapHeader, data.as_mut_ptr()) };
    r == 0 && data == [CapData::default(); 2]
}

// ---------------------------------------------------------------------------------------------
// Landlock

fn ll<E: std::fmt::Display>(e: E) -> SandboxError {
    SandboxError::Landlock(e.to_string())
}

/// Read-only: list and read, never execute.
fn read_only_access(is_dir: bool) -> BitFlags<AccessFs> {
    if is_dir {
        AccessFs::ReadFile | AccessFs::ReadDir
    } else {
        AccessFs::ReadFile.into()
    }
}

/// Read-write for a spool: regular files and directories only (no devices, fifos, sockets,
/// symlinks, ioctls or execution).
fn read_write_access(is_dir: bool) -> BitFlags<AccessFs> {
    if is_dir {
        AccessFs::ReadFile
            | AccessFs::ReadDir
            | AccessFs::WriteFile
            | AccessFs::Truncate
            | AccessFs::RemoveFile
            | AccessFs::RemoveDir
            | AccessFs::MakeReg
            | AccessFs::MakeDir
            | AccessFs::Refer
    } else {
        AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate
    }
}

/// A rule for `path`, failing if it does not exist (landlock's `path_beneath_rules` helper skips
/// missing paths silently, which would fail open for a typo'd spool and closed for nothing).
fn path_rule(
    path: &Path,
    access: fn(bool) -> BitFlags<AccessFs>,
) -> Result<PathBeneath<PathFd>, SandboxError> {
    let fd = PathFd::new(path).map_err(|e| ll(format!("{}: {e}", path.display())))?;
    let is_dir = std::fs::metadata(path)
        .map_err(|e| ll(format!("{}: {e}", path.display())))?
        .is_dir();
    Ok(PathBeneath::new(fd, access(is_dir)))
}

fn landlock_ruleset(profile: &Profile) -> Result<RulesetCreated, SandboxError> {
    let mut created = Ruleset::default()
        // The ABI 6 baseline is mandatory...
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V6))
        .map_err(ll)?
        .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
        .map_err(ll)?
        .scope(Scope::AbstractUnixSocket | Scope::Signal)
        .map_err(ll)?
        // ...and rights added by later ABIs (e.g. ABI 9's ResolveUnix) are handled where the
        // kernel has them.
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI::V9))
        .map_err(ll)?
        .create()
        .map_err(ll)?
        .set_compatibility(CompatLevel::HardRequirement);

    if let Profile::Broker { readable, writable } = profile {
        for path in readable {
            created = created
                .add_rule(path_rule(path, read_only_access)?)
                .map_err(ll)?;
        }
        for path in writable {
            created = created
                .add_rule(path_rule(path, read_write_access)?)
                .map_err(ll)?;
        }
    }

    // Single-threaded is already required; TSYNC (ABI 8) also covers a thread a library started
    // between the count and this call.
    created
        .set_compatibility(CompatLevel::BestEffort)
        .all_threads(true)
        .map_err(ll)
}

// ---------------------------------------------------------------------------------------------
// seccomp

/// A syscall denied unconditionally (with `EPERM`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Denied {
    pub name: &'static str,
    pub nr: i64,
    /// Whether the probe may call it with all-ones arguments to check the filter: true for every
    /// syscall that, if it were *not* filtered, fails harmlessly on such arguments.
    pub probe_with_bogus_args: bool,
}

const fn d(name: &'static str, nr: i64) -> Denied {
    Denied {
        name,
        nr,
        probe_with_bogus_args: true,
    }
}

// Not in libc 0.2.191; new syscalls share one number on every architecture since Linux 5.1.
const SYS_SETXATTRAT: i64 = 463;
const SYS_GETXATTRAT: i64 = 464;
const SYS_LISTXATTRAT: i64 = 465;
const SYS_REMOVEXATTRAT: i64 = 466;
const SYS_OPEN_TREE_ATTR: i64 = 467;
const SYS_FILE_GETATTR: i64 = 468;
const SYS_FILE_SETATTR: i64 = 469;
const SYS_STATMOUNT: i64 = 457;
const SYS_LISTMOUNT: i64 = 458;
const SYS_LSM_GET_SELF_ATTR: i64 = 459;
const SYS_LSM_SET_SELF_ATTR: i64 = 460;
const SYS_LSM_LIST_MODULES: i64 = 461;

/// `prctl(PR_SET_PTRACER)` (Yama): lets a named process, or any (`PR_SET_PTRACER_ANY`), trace us.
pub(crate) const PR_SET_PTRACER: libc::c_int = 0x5961_6d61;
/// `ioctl` requests that change inode flags (`chattr`) through an fd: `FS_IOC_SETFLAGS` (its
/// argument is a `long` on 64-bit, an `int` in the 32-bit spelling) and `FS_IOC_FSSETXATTR`.
pub(crate) const FS_IOC_SETFLAGS: u64 = 0x4008_6602;
pub(crate) const FS_IOC32_SETFLAGS: u64 = 0x4004_6602;
pub(crate) const FS_IOC_FSSETXATTR: u64 = 0x401c_5820;
/// `type & SOCK_TYPE_MASK` is the socket type; the bits above it are `SOCK_NONBLOCK`/`SOCK_CLOEXEC`.
pub(crate) const SOCK_TYPE_MASK: u64 = 0xf;

/// Syscalls that open files by path; the broker may use them (Landlock confines the paths).
fn path_opens() -> Vec<Denied> {
    let mut v = vec![
        d("openat", libc::SYS_openat),
        d("openat2", libc::SYS_openat2),
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([d("open", libc::SYS_open), d("creat", libc::SYS_creat)]);
    v
}

/// Syscalls that read the host's metadata without opening anything, denied to the runner and the
/// worker (review r1 broker F3): an escaped builder could otherwise learn the host's name and
/// kernel (`uname`), its memory, uptime and process count (`sysinfo`), the targets of symlinks such
/// as `/proc/<pid>/cwd` (`readlink*`), which paths exist and are readable (`access`/`faccessat*`),
/// filesystem types and sizes (`statfs`/`fstatfs`), extended attributes (`*getxattr*`,
/// `*listxattr*`), or walk its working directory (`chdir`/`fchdir`; `prepare_command` starts it in
/// `/`). `statx` fails with `ENOSYS` instead ([`raw_filter`]): Rust's std and glibc then fall back to
/// `fstat`/`newfstatat`, which stay allowed — by path they still tell whether a file exists and
/// its size, owner and times; only a mount namespace would close that.
fn host_metadata() -> Vec<Denied> {
    use libc::*;
    let mut v = vec![
        d("readlinkat", SYS_readlinkat),
        d("faccessat", SYS_faccessat),
        d("faccessat2", SYS_faccessat2),
        d("statfs", SYS_statfs),
        d("fstatfs", SYS_fstatfs),
        d("getxattr", SYS_getxattr),
        d("lgetxattr", SYS_lgetxattr),
        d("fgetxattr", SYS_fgetxattr),
        d("getxattrat", SYS_GETXATTRAT),
        d("listxattr", SYS_listxattr),
        d("llistxattr", SYS_llistxattr),
        d("flistxattr", SYS_flistxattr),
        d("listxattrat", SYS_LISTXATTRAT),
        d("uname", SYS_uname),
        d("sysinfo", SYS_sysinfo),
        d("chdir", SYS_chdir),
        d("fchdir", SYS_fchdir),
        // Review r2 B1: the mount table without opening anything (the source of every mount,
        // NFS and CIFS servers' internal host names included), and the LSMs in force.
        d("statmount", SYS_STATMOUNT),
        d("listmount", SYS_LISTMOUNT),
        d("lsm_get_self_attr", SYS_LSM_GET_SELF_ATTR),
        d("lsm_list_modules", SYS_LSM_LIST_MODULES),
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([
        d("readlink", SYS_readlink),
        d("access", SYS_access),
        // A filesystem's free space by device number, and the kernel's filesystem types.
        d("ustat", SYS_ustat),
        d("sysfs", SYS_sysfs),
    ]);
    v
}

/// Syscalls that fail with `ENOSYS` (in [`raw_filter`]) for `profile`: `clone3` for every profile;
/// `statx` for the runner and the worker (see [`host_metadata`]).
pub(crate) fn enosys_syscalls(profile: &Profile) -> Vec<(&'static str, i64)> {
    let mut v = vec![("clone3", libc::SYS_clone3)];
    if !matches!(profile, Profile::Broker { .. }) {
        v.push(("statx", libc::SYS_statx));
    }
    v
}

/// `socketpair`: denied to the runner and the worker; argument-filtered for the broker (an
/// `AF_UNIX` stream pair for its runtime, until [`seal_socket_creation`]).
fn socketpair() -> Vec<Denied> {
    vec![d("socketpair", libc::SYS_socketpair)]
}

/// `setsockopt`: denied to the runner and the worker (they set no option on anything; a socket
/// that reached one could otherwise be re-routed with it); argument-filtered for the broker
/// (`IPPROTO_TCP`/`TCP_NODELAY` only, see [`conditional_denials`]).
fn socket_options() -> Vec<Denied> {
    vec![d("setsockopt", libc::SYS_setsockopt)]
}

/// A socket option as the self-tests and the escape tests try it: level, name, and a value that
/// would take effect if nothing refused it.
#[derive(Debug, Clone, Copy)]
pub struct SocketOption {
    pub name: &'static str,
    pub level: libc::c_int,
    pub option: libc::c_int,
    pub value: &'static [u8],
}

const fn ne_int(v: i32) -> [u8; 4] {
    v.to_ne_bytes()
}

const ONE: [u8; 4] = ne_int(1);
/// `struct ip_options` source route: NOP, LSRR (length 7, pointer 4) through 127.0.0.1.
const LSRR_VIA_LOOPBACK: [u8; 8] = [1, 0x83, 7, 4, 127, 0, 0, 1];
/// An IPv6 type-2 routing header (8 bytes and one address, `::1`): the kernel sends the
/// segments to the address in the header.
const RTHDR_TYPE2_LOOPBACK: [u8; 24] = [0, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// A `sockaddr_in6` for `::1`, port 0.
const SOCKADDR_IN6_LOOPBACK: [u8; 28] = {
    let mut a = [0u8; 28];
    let fam = (libc::AF_INET6 as u16).to_ne_bytes();
    a[0] = fam[0];
    a[1] = fam[1];
    a[23] = 1;
    a
};

/// Socket options that send a connected socket's packets somewhere other than its peer, out
/// another interface, through another route, under a firewall mark, or past the network's
/// expectations (a TTL, a priority): every sandbox profile refuses each with `EPERM` (the broker
/// sets only `IPPROTO_TCP`/`TCP_NODELAY`, the runner and the worker nothing). Unprivileged on
/// Linux: `IPV6_RTHDR` (type 2), `SO_BINDTODEVICE` on an unbound socket, `IP_UNICAST_IF`,
/// `IPV6_UNICAST_IF`, `IPV6_NEXTHOP`, the TTLs; the others need a capability the sandboxes do not
/// have.
pub const REFUSED_SOCKET_OPTIONS: &[SocketOption] = &[
    SocketOption { name: "IPV6_RTHDR", level: libc::IPPROTO_IPV6, option: libc::IPV6_RTHDR, value: &RTHDR_TYPE2_LOOPBACK },
    SocketOption {
        name: "IPV6_2292RTHDR",
        level: libc::IPPROTO_IPV6,
        option: libc::IPV6_2292RTHDR,
        value: &RTHDR_TYPE2_LOOPBACK,
    },
    SocketOption { name: "IP_OPTIONS", level: libc::IPPROTO_IP, option: libc::IP_OPTIONS, value: &LSRR_VIA_LOOPBACK },
    SocketOption { name: "SO_BINDTODEVICE", level: libc::SOL_SOCKET, option: libc::SO_BINDTODEVICE, value: b"lo\0" },
    SocketOption { name: "SO_BINDTOIFINDEX", level: libc::SOL_SOCKET, option: libc::SO_BINDTOIFINDEX, value: &ONE },
    // The interface index in network byte order.
    SocketOption { name: "IP_UNICAST_IF", level: libc::IPPROTO_IP, option: libc::IP_UNICAST_IF, value: &[0, 0, 0, 1] },
    SocketOption { name: "IPV6_UNICAST_IF", level: libc::IPPROTO_IPV6, option: libc::IPV6_UNICAST_IF, value: &ONE },
    SocketOption {
        name: "IPV6_NEXTHOP",
        level: libc::IPPROTO_IPV6,
        option: libc::IPV6_NEXTHOP,
        value: &SOCKADDR_IN6_LOOPBACK,
    },
    SocketOption { name: "IP_TRANSPARENT", level: libc::IPPROTO_IP, option: libc::IP_TRANSPARENT, value: &ONE },
    SocketOption { name: "SO_MARK", level: libc::SOL_SOCKET, option: libc::SO_MARK, value: &ONE },
    SocketOption { name: "SO_DONTROUTE", level: libc::SOL_SOCKET, option: libc::SO_DONTROUTE, value: &ONE },
    SocketOption { name: "SO_PRIORITY", level: libc::SOL_SOCKET, option: libc::SO_PRIORITY, value: &ONE },
    SocketOption { name: "IP_TTL", level: libc::IPPROTO_IP, option: libc::IP_TTL, value: &ONE },
    SocketOption { name: "IPV6_UNICAST_HOPS", level: libc::IPPROTO_IPV6, option: libc::IPV6_UNICAST_HOPS, value: &ONE },
    SocketOption { name: "TCP_ULP", level: libc::IPPROTO_TCP, option: libc::TCP_ULP, value: b"tls\0" },
    SocketOption { name: "TCP_MAXSEG", level: libc::IPPROTO_TCP, option: libc::TCP_MAXSEG, value: &ne_int(536) },
];

/// The one socket option the broker may set (on the sockets the connector hands it).
pub const BROKER_SOCKET_OPTION: SocketOption =
    SocketOption { name: "TCP_NODELAY", level: libc::IPPROTO_TCP, option: libc::TCP_NODELAY, value: &ONE };

/// `setsockopt(fd, o.level, o.option, o.value)`: `Ok(())` or the errno.
pub fn set_socket_option(fd: std::os::fd::RawFd, o: &SocketOption) -> Result<(), i32> {
    // SAFETY: `o.value` is a valid buffer of its stated length; the kernel only reads it.
    let r = unsafe { libc::setsockopt(fd, o.level, o.option, o.value.as_ptr().cast(), o.value.len() as libc::socklen_t) };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }
}

/// Denied for every profile.
fn always_denied() -> Vec<Denied> {
    use libc::*;
    let mut v = vec![
        // No profile has a network of its own: the broker's TCP connections come from the miner's
        // connector, already connected (review r2 F5).
        d("socket", SYS_socket),
        d("connect", SYS_connect),
        d("bind", SYS_bind),
        d("listen", SYS_listen),
        d("accept", SYS_accept),
        d("accept4", SYS_accept4),
        d("execve", SYS_execve),
        d("execveat", SYS_execveat),
        d("ptrace", SYS_ptrace),
        d("process_vm_readv", SYS_process_vm_readv),
        d("process_vm_writev", SYS_process_vm_writev),
        d("process_madvise", SYS_process_madvise),
        d("pidfd_getfd", SYS_pidfd_getfd),
        d("migrate_pages", SYS_migrate_pages),
        d("move_pages", SYS_move_pages),
        d("unshare", SYS_unshare),
        d("setns", SYS_setns),
        d("mount", SYS_mount),
        d("umount2", SYS_umount2),
        d("pivot_root", SYS_pivot_root),
        d("chroot", SYS_chroot),
        d("fsopen", SYS_fsopen),
        d("fsconfig", SYS_fsconfig),
        d("fsmount", SYS_fsmount),
        d("fspick", SYS_fspick),
        d("move_mount", SYS_move_mount),
        d("open_tree", SYS_open_tree),
        d("open_tree_attr", SYS_OPEN_TREE_ATTR),
        d("mount_setattr", SYS_mount_setattr),
        d("bpf", SYS_bpf),
        d("perf_event_open", SYS_perf_event_open),
        d("keyctl", SYS_keyctl),
        d("add_key", SYS_add_key),
        d("request_key", SYS_request_key),
        d("userfaultfd", SYS_userfaultfd),
        // io_uring operations bypass seccomp entirely.
        d("io_uring_setup", SYS_io_uring_setup),
        d("io_uring_enter", SYS_io_uring_enter),
        d("io_uring_register", SYS_io_uring_register),
        d("kexec_load", SYS_kexec_load),
        d("kexec_file_load", SYS_kexec_file_load),
        d("init_module", SYS_init_module),
        d("finit_module", SYS_finit_module),
        d("delete_module", SYS_delete_module),
        d("name_to_handle_at", SYS_name_to_handle_at),
        d("open_by_handle_at", SYS_open_by_handle_at),
        d("personality", SYS_personality),
        d("quotactl", SYS_quotactl),
        d("quotactl_fd", SYS_quotactl_fd),
        d("swapon", SYS_swapon),
        d("swapoff", SYS_swapoff),
        d("reboot", SYS_reboot),
        d("acct", SYS_acct),
        d("clock_settime", SYS_clock_settime),
        d("clock_adjtime", SYS_clock_adjtime),
        d("settimeofday", SYS_settimeofday),
        d("adjtimex", SYS_adjtimex),
        d("syslog", SYS_syslog),
        d("lsm_set_self_attr", SYS_LSM_SET_SELF_ATTR),
        d("fanotify_init", SYS_fanotify_init),
        d("fanotify_mark", SYS_fanotify_mark),
        d("inotify_add_watch", SYS_inotify_add_watch),
        // Metadata writes by path: Landlock does not cover them, and the sandbox runs as the
        // miner's uid (chmod 0644 on a key file would be an escape).
        d("fchmodat", SYS_fchmodat),
        d("fchmodat2", SYS_fchmodat2),
        d("fchownat", SYS_fchownat),
        d("utimensat", SYS_utimensat),
        d("setxattr", SYS_setxattr),
        d("lsetxattr", SYS_lsetxattr),
        d("removexattr", SYS_removexattr),
        d("lremovexattr", SYS_lremovexattr),
        d("setxattrat", SYS_SETXATTRAT),
        d("removexattrat", SYS_REMOVEXATTRAT),
        d("file_setattr", SYS_FILE_SETATTR),
        d("file_getattr", SYS_FILE_GETATTR),
        // ...and through an inherited fd (the W file, a memfd, a pipe): mode, owner, xattrs, locks.
        d("fchmod", SYS_fchmod),
        d("fchown", SYS_fchown),
        d("fsetxattr", SYS_fsetxattr),
        d("fremovexattr", SYS_fremovexattr),
        d("flock", SYS_flock),
        // SysV IPC: every segment, queue and semaphore set of the miner's uid is reachable by key or
        // id (shmctl(SHM_STAT) enumerates them), and what a sandbox creates outlives it and its
        // cgroup (a segment's pages escape memory.max once the cgroup is gone).
        d("shmget", SYS_shmget),
        d("shmat", SYS_shmat),
        d("shmdt", SYS_shmdt),
        d("shmctl", SYS_shmctl),
        // msgget(-1, -1) would create a queue keyed 0xffffffff if the filter were missing.
        Denied {
            name: "msgget",
            nr: SYS_msgget,
            probe_with_bogus_args: false,
        },
        d("msgsnd", SYS_msgsnd),
        d("msgrcv", SYS_msgrcv),
        d("msgctl", SYS_msgctl),
        d("semget", SYS_semget),
        d("semop", SYS_semop),
        d("semtimedop", SYS_semtimedop),
        d("semctl", SYS_semctl),
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([
        d("iopl", SYS_iopl),
        d("ioperm", SYS_ioperm),
        d("uselib", SYS_uselib),
        d("chmod", SYS_chmod),
        d("chown", SYS_chown),
        d("lchown", SYS_lchown),
        d("utime", SYS_utime),
        d("utimes", SYS_utimes),
        d("futimesat", SYS_futimesat),
        // No new processes; these would really fork if the filter were missing.
        Denied {
            name: "fork",
            nr: SYS_fork,
            probe_with_bogus_args: false,
        },
        Denied {
            name: "vfork",
            nr: SYS_vfork,
            probe_with_bogus_args: false,
        },
    ]);
    v
}

/// Every syscall `profile` denies unconditionally.
pub(crate) fn denied_syscalls(profile: &Profile) -> Vec<Denied> {
    let mut v = always_denied();
    if !matches!(profile, Profile::Broker { .. }) {
        v.extend(path_opens());
        v.extend(socketpair());
        v.extend(socket_options());
        v.extend(host_metadata());
    }
    v
}

fn cond(
    arg: u8,
    len: SeccompCmpArgLen,
    op: SeccompCmpOp,
    value: u64,
) -> Result<SeccompCondition, SandboxError> {
    SeccompCondition::new(arg, len, op, value).map_err(|e| SandboxError::Seccomp(e.to_string()))
}

fn rule(conds: Vec<SeccompCondition>) -> Result<SeccompRule, SandboxError> {
    SeccompRule::new(conds).map_err(|e| SandboxError::Seccomp(e.to_string()))
}

/// `arg != 0` (a pid/who of 0 means the caller itself).
fn other_than_self(arg: u8) -> Result<SeccompRule, SandboxError> {
    rule(vec![cond(
        arg,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Ne,
        0,
    )?])
}

/// Argument-filtered denials: each listed rule that matches makes the call fail with `EPERM`.
fn conditional_denials(profile: &Profile) -> Result<Vec<(i64, Vec<SeccompRule>)>, SandboxError> {
    use SeccompCmpArgLen::{Dword, Qword};
    use SeccompCmpOp::{Eq, MaskedEq, Ne};

    // clone: threads only (CLONE_THREAD set), and never a new namespace.
    let mut clone_rules = vec![rule(vec![cond(
        0,
        Qword,
        MaskedEq(libc::CLONE_THREAD as u64),
        0,
    )?])?];
    for ns in [
        libc::CLONE_NEWNS,
        libc::CLONE_NEWCGROUP,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWNET,
    ] {
        clone_rules.push(rule(vec![cond(0, Qword, MaskedEq(ns as u64), ns as u64)?])?);
    }

    let mut v = vec![
        (libc::SYS_clone, clone_rules),
        // Other processes of the same uid (the miner, the provers) are off limits.
        (libc::SYS_sched_setaffinity, vec![other_than_self(0)?]),
        (libc::SYS_sched_setscheduler, vec![other_than_self(0)?]),
        (libc::SYS_sched_setparam, vec![other_than_self(0)?]),
        (libc::SYS_sched_setattr, vec![other_than_self(0)?]),
        (libc::SYS_prlimit64, vec![other_than_self(0)?]),
        (
            libc::SYS_setpriority,
            vec![
                rule(vec![cond(0, Dword, Ne, libc::PRIO_PROCESS as u64)?])?,
                other_than_self(1)?,
            ],
        ),
        (
            libc::SYS_ioprio_set,
            vec![
                // IOPRIO_WHO_PROCESS
                rule(vec![cond(0, Dword, Ne, 1)?])?,
                other_than_self(1)?,
            ],
        ),
        (
            libc::SYS_prctl,
            vec![
                // The parent-death signal set by `prepare_command` cannot be cleared.
                rule(vec![cond(0, Dword, Eq, libc::PR_SET_PDEATHSIG as u64)?])?,
                // `restrict_self` cleared dumpable: a sandbox may not make itself dumpable again
                // (its memory and /proc/<pid> files would open to every process of the uid)...
                rule(vec![cond(0, Dword, Eq, libc::PR_SET_DUMPABLE as u64)?])?,
                // ...nor name a process of its uid that may then ptrace it past Yama.
                rule(vec![cond(0, Dword, Eq, PR_SET_PTRACER as u64)?])?,
            ],
        ),
        (
            libc::SYS_fcntl,
            vec![
                // A lease or a directory notification on an inherited fd signals the sandbox when
                // the miner opens or changes the file (and a lease stalls the miner's open).
                rule(vec![cond(1, Dword, Eq, libc::F_SETLEASE as u64)?])?,
                rule(vec![cond(1, Dword, Eq, libc::F_NOTIFY as u64)?])?,
            ],
        ),
        (
            libc::SYS_ioctl,
            vec![
                // Terminal injection through an inherited tty.
                rule(vec![cond(1, Dword, Eq, libc::TIOCSTI)?])?,
                rule(vec![cond(1, Dword, Eq, libc::TIOCLINUX)?])?,
                // Inode flags (`chattr`) through an inherited fd: the ioctl spelling of
                // `file_setattr`.
                rule(vec![cond(1, Dword, Eq, FS_IOC_SETFLAGS)?])?,
                rule(vec![cond(1, Dword, Eq, FS_IOC32_SETFLAGS)?])?,
                rule(vec![cond(1, Dword, Eq, FS_IOC_FSSETXATTR)?])?,
            ],
        ),
    ];
    // Sessions and process groups of other processes (review r2 B1): `getsid`/`getpgid` only of
    // the caller itself (0, or its own pid, fixed when the filter is built in that process).
    let me = u64::from(std::process::id());
    for nr in [libc::SYS_getsid, libc::SYS_getpgid] {
        v.push((nr, vec![rule(vec![cond(0, Dword, Ne, 0)?, cond(0, Dword, Ne, me)?])?]));
    }
    if matches!(profile, Profile::Broker { .. }) {
        // All arguments are `int`s: the kernel ignores their upper 32 bits, and so do these
        // `Dword` comparisons. A connected AF_UNIX *stream* pair reaches nothing outside the process; tokio's signal
        // driver creates one when the runtime is built (the workspace enables tokio's `signal`
        // feature). A datagram or seqpacket pair would not: `sendto` on either end reaches any
        // pathname datagram socket of the host, which Landlock ABI 8 has no right for.
        let mut pair_rules = vec![rule(vec![cond(0, Dword, Ne, libc::AF_UNIX as u64)?])?];
        pair_rules.extend(non_stream_types(1)?);
        v.push((libc::SYS_socketpair, pair_rules));
        // A handed socket's peer is fixed by the connector's `connect`, but socket options
        // re-route it at the IP layer without one: an IPv6 type-2 routing header (unprivileged)
        // sends later segments to the address it names, `SO_BINDTODEVICE` picks the interface,
        // `IP_UNICAST_IF`/`IPV6_NEXTHOP` the way out. The broker's only call is
        // `set_nodelay` (net.rs), so every other level and option fails: `level != IPPROTO_TCP`
        // or `optname != TCP_NODELAY` (both `int`s).
        v.push((
            libc::SYS_setsockopt,
            vec![
                rule(vec![cond(1, Dword, Ne, libc::IPPROTO_TCP as u64)?])?,
                rule(vec![cond(2, Dword, Ne, libc::TCP_NODELAY as u64)?])?,
            ],
        ));
    }
    Ok(v)
}

/// One rule per socket type other than `SOCK_STREAM`, matching `arg & SOCK_TYPE_MASK` (seccomp has
/// no masked not-equal).
fn non_stream_types(arg: u8) -> Result<Vec<SeccompRule>, SandboxError> {
    (0..=SOCK_TYPE_MASK)
        .filter(|&t| t != libc::SOCK_STREAM as u64)
        .map(|t| {
            rule(vec![cond(
                arg,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                t,
            )?])
        })
        .collect()
}

fn target_arch() -> Result<TargetArch, SandboxError> {
    std::env::consts::ARCH
        .try_into()
        .map_err(|e: seccompiler::BackendError| SandboxError::Seccomp(e.to_string()))
}

/// The main denylist filter (seccompiler; includes an architecture check that kills the process
/// on a foreign-ABI syscall, e.g. `int 0x80`).
fn denylist_filter(profile: &Profile) -> Result<BpfProgram, SandboxError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for s in denied_syscalls(profile) {
        // An empty rule list matches unconditionally.
        rules.insert(s.nr, Vec::new());
    }
    for (nr, conds) in conditional_denials(profile)? {
        if rules.contains_key(&nr) {
            return Err(SandboxError::Seccomp(format!(
                "syscall {nr} both denied and filtered"
            )));
        }
        rules.insert(nr, conds);
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

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> seccompiler::sock_filter {
    seccompiler::sock_filter { code, jt, jf, k }
}

/// A small hand-written filter for what seccompiler cannot express (one action per filter):
/// - the [`enosys_syscalls`] fail with `ENOSYS`: `clone3` (its flags live in memory, so a filter
///   cannot see `CLONE_NEW*` or the absence of `CLONE_THREAD`; libc then falls back to `clone`,
///   which the denylist filters by flags), and for the runner and the worker `statx` (see
///   [`host_metadata`]; std and glibc fall back to `fstat`/`newfstatat` on `ENOSYS`);
/// - on x86_64, any x32 syscall (`nr >= 0x40000000`) fails with `EPERM`; a denylist keyed by
///   64-bit syscall numbers would otherwise miss the x32 aliases on kernels with
///   `CONFIG_X86_X32_ABI`.
fn raw_filter(profile: &Profile) -> BpfProgram {
    const ARCH_OFFSET: u32 = 4;
    const NR_OFFSET: u32 = 0;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 62 | 0x8000_0000 | 0x4000_0000;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 183 | 0x8000_0000 | 0x4000_0000;
    let allow = libc::SECCOMP_RET_ALLOW;
    let enosys = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
    let kill = libc::SECCOMP_RET_KILL_PROCESS;
    let nrs = enosys_syscalls(profile);
    let n = nrs.len() as u8;

    // Jump offsets count from the next instruction.
    #[cfg(target_arch = "x86_64")]
    {
        // 0 ld arch; 1 arch?; 2 ld nr; 3 x32?; 4..4+n ENOSYS nrs; 4+n allow; 5+n enosys;
        // 6+n eperm; 7+n kill.
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        let mut f = vec![
            insn(BPF_LD_W_ABS, 0, 0, ARCH_OFFSET),
            insn(BPF_JEQ_K, 0, 5 + n, AUDIT_ARCH), // else -> kill
            insn(BPF_LD_W_ABS, 0, 0, NR_OFFSET),
            insn(BPF_JGE_K, 2 + n, 0, 0x4000_0000), // x32 -> EPERM
        ];
        for (j, (_, nr)) in nrs.iter().enumerate() {
            f.push(insn(BPF_JEQ_K, n - j as u8, 0, *nr as u32)); // -> ENOSYS
        }
        f.extend([
            insn(BPF_RET_K, 0, 0, allow),
            insn(BPF_RET_K, 0, 0, enosys),
            insn(BPF_RET_K, 0, 0, eperm),
            insn(BPF_RET_K, 0, 0, kill),
        ]);
        f
    }
    #[cfg(target_arch = "aarch64")]
    {
        // 0 ld arch; 1 arch?; 2 ld nr; 3..3+n ENOSYS nrs; 3+n allow; 4+n enosys; 5+n kill.
        let mut f = vec![
            insn(BPF_LD_W_ABS, 0, 0, ARCH_OFFSET),
            insn(BPF_JEQ_K, 0, 3 + n, AUDIT_ARCH), // else -> kill
            insn(BPF_LD_W_ABS, 0, 0, NR_OFFSET),
        ];
        for (j, (_, nr)) in nrs.iter().enumerate() {
            f.push(insn(BPF_JEQ_K, n - j as u8, 0, *nr as u32)); // -> ENOSYS
        }
        f.extend([
            insn(BPF_RET_K, 0, 0, allow),
            insn(BPF_RET_K, 0, 0, enosys),
            insn(BPF_RET_K, 0, 0, kill),
        ]);
        f
    }
}

/// The filters [`restrict_self`] installs, in order.
pub(crate) fn seccomp_filters(profile: &Profile) -> Result<Vec<BpfProgram>, SandboxError> {
    Ok(vec![raw_filter(profile), denylist_filter(profile)?])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broker() -> Profile {
        Profile::Broker {
            readable: vec![],
            writable: vec![],
        }
    }

    #[test]
    fn filters_compile_for_every_profile() {
        for p in [Profile::BuilderRunner, Profile::ExecuteWorker, broker()] {
            let filters = seccomp_filters(&p).unwrap();
            assert_eq!(filters.len(), 2);
            assert!(filters.iter().all(|f| !f.is_empty() && f.len() < 4096));
        }
    }

    #[test]
    fn broker_keeps_socketpairs_and_opens() {
        let names = |p: &Profile| {
            denied_syscalls(p)
                .iter()
                .map(|s| s.name)
                .collect::<Vec<_>>()
        };
        let runner = names(&Profile::BuilderRunner);
        let b = names(&broker());
        // `socketpair` is argument-filtered for the broker (AF_UNIX stream pairs), and it may open
        // files (Landlock confines them).
        for s in ["socketpair", "openat", "openat2"] {
            assert!(runner.contains(&s), "{s}");
            assert!(!b.contains(&s), "{s}");
        }
        // Review r2 F5: no profile has a socket of its own.
        for s in [
            "socket",
            "connect",
            "bind",
            "listen",
            "accept4",
            "execve",
            "ptrace",
            "io_uring_setup",
        ] {
            assert!(b.contains(&s), "{s}");
        }
        let filtered: Vec<i64> = conditional_denials(&broker())
            .unwrap()
            .into_iter()
            .map(|(nr, _)| nr)
            .collect();
        assert!(!filtered.contains(&libc::SYS_socket));
        assert!(filtered.contains(&libc::SYS_socketpair));
    }

    #[test]
    fn denylist_has_no_duplicates() {
        for p in [Profile::BuilderRunner, Profile::ExecuteWorker, broker()] {
            let mut nrs: Vec<i64> = denied_syscalls(&p).iter().map(|s| s.nr).collect();
            let n = nrs.len();
            nrs.sort_unstable();
            nrs.dedup();
            assert_eq!(n, nrs.len());
        }
    }

    // -----------------------------------------------------------------------------------------
    // The installed filters, interpreted.

    const ERRNO_EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    const ERRNO_ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 62 | 0x8000_0000 | 0x4000_0000;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 183 | 0x8000_0000 | 0x4000_0000;

    /// `struct seccomp_data` for a call: nr, arch, instruction pointer, six 64-bit arguments.
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

    /// A classic-BPF interpreter for exactly the instructions seccompiler and [`raw_filter`] emit;
    /// anything else panics, so a seccompiler upgrade that emits more cannot pass silently.
    fn run_bpf(prog: &[seccompiler::sock_filter], data: &[u8; 64]) -> u32 {
        let (mut a, mut pc) = (0u32, 0usize);
        for _ in 0..=prog.len() {
            let i = &prog[pc];
            pc += 1;
            let jump = |taken: bool| usize::from(if taken { i.jt } else { i.jf });
            match i.code {
                0x20 => {
                    // BPF_LD | BPF_W | BPF_ABS
                    let k = i.k as usize;
                    assert!(k.is_multiple_of(4) && k + 4 <= data.len(), "load at {k}");
                    a = u32::from_ne_bytes(data[k..k + 4].try_into().unwrap());
                }
                0x54 => a &= i.k,             // BPF_ALU | BPF_AND | BPF_K
                0x05 => pc += i.k as usize,   // BPF_JMP | BPF_JA
                0x15 => pc += jump(a == i.k), // BPF_JMP | BPF_JEQ | BPF_K
                0x25 => pc += jump(a > i.k),  // BPF_JMP | BPF_JGT | BPF_K
                0x35 => pc += jump(a >= i.k), // BPF_JMP | BPF_JGE | BPF_K
                0x06 => return i.k,           // BPF_RET | BPF_K
                c => panic!("unexpected BPF opcode {c:#06x} at {}", pc - 1),
            }
        }
        panic!("BPF program did not return (jumps only go forward, so it ran off the end)");
    }

    /// What the kernel does with every filter installed: each runs, and the most restrictive action
    /// wins (`SECCOMP_RET_ACTION_FULL` compared as signed); between equals, the newest filter.
    fn verdict(filters: &[BpfProgram], data: &[u8; 64]) -> u32 {
        let mut ret = ALLOW;
        for f in filters.iter().rev() {
            let cur = run_bpf(f, data);
            if ((cur & 0xffff_0000) as i32) < ((ret & 0xffff_0000) as i32) {
                ret = cur;
            }
        }
        ret
    }

    fn call(filters: &[BpfProgram], nr: i64, args: [u64; 6]) -> u32 {
        verdict(filters, &seccomp_data(ARCH, nr, args))
    }

    /// Argument patterns a denied syscall must be refused for, whatever they are.
    const ARG_PATTERNS: [[u64; 6]; 4] = [
        [0; 6],
        [u64::MAX; 6],
        [1, 2, 3, 4, 5, 6],
        [
            0xffff_ffff_0000_0000,
            0x0000_0000_ffff_ffff,
            0x8000_0000,
            1 << 40,
            7,
            0,
        ],
    ];

    #[test]
    fn every_denied_syscall_yields_eperm() {
        for p in [Profile::BuilderRunner, Profile::ExecuteWorker, broker()] {
            let filters = seccomp_filters(&p).unwrap();
            let denied = denied_syscalls(&p);
            assert!(denied.len() > 90, "{} denied for {p:?}", denied.len());
            for s in &denied {
                for args in ARG_PATTERNS {
                    assert_eq!(
                        call(&filters, s.nr, args),
                        ERRNO_EPERM,
                        "{} ({}) with {args:x?} for {p:?}",
                        s.name,
                        s.nr
                    );
                }
            }
        }
    }

    /// The review's findings, by number, so a denial dropped from the list fails here even though
    /// the test above only walks what the list holds.
    #[test]
    fn review_findings_are_denied_for_every_profile() {
        use libc::*;
        let required: Vec<(&str, i64)> = vec![
            // H1: SysV IPC.
            ("shmget", SYS_shmget),
            ("shmat", SYS_shmat),
            ("shmdt", SYS_shmdt),
            ("shmctl", SYS_shmctl),
            ("msgget", SYS_msgget),
            ("msgsnd", SYS_msgsnd),
            ("msgrcv", SYS_msgrcv),
            ("msgctl", SYS_msgctl),
            ("semget", SYS_semget),
            ("semop", SYS_semop),
            ("semtimedop", SYS_semtimedop),
            ("semctl", SYS_semctl),
            // M3: metadata through an inherited fd.
            ("fchmod", SYS_fchmod),
            ("fchown", SYS_fchown),
            ("fsetxattr", SYS_fsetxattr),
            ("fremovexattr", SYS_fremovexattr),
            ("flock", SYS_flock),
            // L1.
            ("file_getattr", 468),
            ("file_setattr", 469),
        ];
        for p in [Profile::BuilderRunner, Profile::ExecuteWorker, broker()] {
            let filters = seccomp_filters(&p).unwrap();
            for (name, nr) in &required {
                assert!(
                    denied_syscalls(&p).iter().any(|s| s.nr == *nr),
                    "{name} not listed for {p:?}"
                );
                for args in ARG_PATTERNS {
                    assert_eq!(call(&filters, *nr, args), ERRNO_EPERM, "{name} for {p:?}");
                }
            }
        }
    }

    /// Review r1 broker F3: the runner and the worker read no host metadata (uname, sysinfo,
    /// symlink targets, access checks, filesystem stats, xattrs, chdir) and `statx` fails with
    /// ENOSYS so std falls back to `fstat`; the broker keeps them (it reads its spool).
    #[test]
    fn runner_and_worker_read_no_host_metadata() {
        use libc::*;
        let mut metadata: Vec<(&str, i64)> = vec![
            ("readlinkat", SYS_readlinkat),
            ("faccessat", SYS_faccessat),
            ("faccessat2", SYS_faccessat2),
            ("statfs", SYS_statfs),
            ("fstatfs", SYS_fstatfs),
            ("getxattr", SYS_getxattr),
            ("lgetxattr", SYS_lgetxattr),
            ("fgetxattr", SYS_fgetxattr),
            ("getxattrat", 464),
            ("listxattr", SYS_listxattr),
            ("llistxattr", SYS_llistxattr),
            ("flistxattr", SYS_flistxattr),
            ("listxattrat", 465),
            ("uname", SYS_uname),
            ("sysinfo", SYS_sysinfo),
            ("chdir", SYS_chdir),
            ("fchdir", SYS_fchdir),
        ];
        #[cfg(target_arch = "x86_64")]
        metadata.extend([("readlink", SYS_readlink), ("access", SYS_access)]);
        for p in [Profile::BuilderRunner, Profile::ExecuteWorker] {
            let f = seccomp_filters(&p).unwrap();
            for (name, nr) in &metadata {
                assert!(
                    denied_syscalls(&p).iter().any(|s| s.nr == *nr),
                    "{name} not listed for {p:?}"
                );
                for args in ARG_PATTERNS {
                    assert_eq!(call(&f, *nr, args), ERRNO_EPERM, "{name} for {p:?}");
                }
            }
            for args in ARG_PATTERNS {
                assert_eq!(call(&f, SYS_statx, args), ERRNO_ENOSYS, "statx for {p:?}");
                assert_eq!(call(&f, SYS_clone3, args), ERRNO_ENOSYS, "clone3 for {p:?}");
            }
            // What stays: stat by path and by fd, and getcwd (which says `/`).
            assert_eq!(call(&f, SYS_newfstatat, [0; 6]), ALLOW);
            assert_eq!(call(&f, SYS_fstat, [0; 6]), ALLOW);
            assert_eq!(call(&f, SYS_getcwd, [0; 6]), ALLOW);
        }
        let b = seccomp_filters(&broker()).unwrap();
        for (name, nr) in metadata.iter().chain([("statx", SYS_statx)].iter()) {
            assert_eq!(call(&b, *nr, [0; 6]), ALLOW, "{name} for the broker");
        }
        assert_eq!(call(&b, SYS_clone3, [0; 6]), ERRNO_ENOSYS);
    }

    #[test]
    fn argument_filters_for_every_profile() {
        use libc::*;
        let u = |v: c_int| v as u64;
        for p in [Profile::BuilderRunner, Profile::ExecuteWorker, broker()] {
            let f = seccomp_filters(&p).unwrap();
            let cases: Vec<(&str, i64, [u64; 6], u32)> = vec![
                // L4 and the parent-death signal.
                (
                    "PR_SET_PDEATHSIG",
                    SYS_prctl,
                    [u(PR_SET_PDEATHSIG), 9, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "PR_SET_DUMPABLE 1",
                    SYS_prctl,
                    [u(PR_SET_DUMPABLE), 1, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "PR_SET_DUMPABLE 0",
                    SYS_prctl,
                    [u(PR_SET_DUMPABLE), 0, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "PR_SET_PTRACER any",
                    SYS_prctl,
                    [u(PR_SET_PTRACER), u64::MAX, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "PR_SET_PTRACER 0",
                    SYS_prctl,
                    [u(PR_SET_PTRACER), 0, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "PR_GET_DUMPABLE",
                    SYS_prctl,
                    [u(PR_GET_DUMPABLE), 0, 0, 0, 0, 0],
                    ALLOW,
                ),
                (
                    "PR_SET_NAME",
                    SYS_prctl,
                    [u(PR_SET_NAME), 0x1000, 0, 0, 0, 0],
                    ALLOW,
                ),
                // M3: leases and notifications; everything else fcntl does stays.
                (
                    "F_SETLEASE",
                    SYS_fcntl,
                    [5, u(F_SETLEASE), u(F_RDLCK), 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "F_SETLEASE hi bits",
                    SYS_fcntl,
                    [5, (1 << 32) | u(F_SETLEASE), 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "F_NOTIFY",
                    SYS_fcntl,
                    [5, u(F_NOTIFY), 1, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "F_GETLEASE",
                    SYS_fcntl,
                    [5, u(F_GETLEASE), 0, 0, 0, 0],
                    ALLOW,
                ),
                ("F_GETFL", SYS_fcntl, [5, u(F_GETFL), 0, 0, 0, 0], ALLOW),
                (
                    "F_SETFL",
                    SYS_fcntl,
                    [5, u(F_SETFL), u(O_NONBLOCK), 0, 0, 0],
                    ALLOW,
                ),
                (
                    "F_DUPFD_CLOEXEC",
                    SYS_fcntl,
                    [5, u(F_DUPFD_CLOEXEC), 3, 0, 0, 0],
                    ALLOW,
                ),
                (
                    "F_ADD_SEALS",
                    SYS_fcntl,
                    [5, u(F_ADD_SEALS), 1, 0, 0, 0],
                    ALLOW,
                ),
                // ioctl: tty injection and inode flags.
                ("TIOCSTI", SYS_ioctl, [0, TIOCSTI, 0, 0, 0, 0], ERRNO_EPERM),
                (
                    "TIOCLINUX",
                    SYS_ioctl,
                    [0, TIOCLINUX, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "FS_IOC_SETFLAGS",
                    SYS_ioctl,
                    [5, FS_IOC_SETFLAGS, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "FS_IOC32_SETFLAGS",
                    SYS_ioctl,
                    [5, FS_IOC32_SETFLAGS, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "FS_IOC_FSSETXATTR",
                    SYS_ioctl,
                    [5, FS_IOC_FSSETXATTR, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                ("FIONREAD", SYS_ioctl, [5, FIONREAD, 0, 0, 0, 0], ALLOW),
                (
                    "FS_IOC_GETFLAGS",
                    SYS_ioctl,
                    [5, 0x8008_6601, 0, 0, 0, 0],
                    ALLOW,
                ),
                // clone: threads, never processes or namespaces; clone3 falls back.
                ("clone thread", SYS_clone, [0x3d0f00, 0, 0, 0, 0, 0], ALLOW),
                (
                    "clone process",
                    SYS_clone,
                    [u(SIGCHLD), 0, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "clone thread+userns",
                    SYS_clone,
                    [0x3d0f00 | u(CLONE_NEWUSER), 0, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                ("clone3", SYS_clone3, [0; 6], ERRNO_ENOSYS),
                // Other processes of the uid.
                (
                    "sched_setaffinity self",
                    SYS_sched_setaffinity,
                    [0, 8, 0, 0, 0, 0],
                    ALLOW,
                ),
                (
                    "sched_setaffinity other",
                    SYS_sched_setaffinity,
                    [1, 8, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "prlimit64 other",
                    SYS_prlimit64,
                    [1, 0, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "setpriority pgrp",
                    SYS_setpriority,
                    [PRIO_PGRP as u64, 0, 0, 0, 0, 0],
                    ERRNO_EPERM,
                ),
                (
                    "setpriority self",
                    SYS_setpriority,
                    [PRIO_PROCESS as u64, 0, 5, 0, 0, 0],
                    ALLOW,
                ),
                // What every runtime needs.
                ("read", SYS_read, [0, 0, 0, 0, 0, 0], ALLOW),
                ("write", SYS_write, [1, 0, 0, 0, 0, 0], ALLOW),
                ("close", SYS_close, [3, 0, 0, 0, 0, 0], ALLOW),
                ("mmap", SYS_mmap, [0, 4096, 3, 0x22, u64::MAX, 0], ALLOW),
                ("futex", SYS_futex, [0x1000, 0, 0, 0, 0, 0], ALLOW),
                ("getpid", SYS_getpid, [0; 6], ALLOW),
                ("exit_group", SYS_exit_group, [0; 6], ALLOW),
                (
                    "memfd_create",
                    SYS_memfd_create,
                    [0x1000, 3, 0, 0, 0, 0],
                    ALLOW,
                ),
                ("pread64", SYS_pread64, [3, 0x1000, 16, 0, 0, 0], ALLOW),
                ("sendmsg", SYS_sendmsg, [5, 0x1000, 0, 0, 0, 0], ALLOW),
            ];
            for (what, nr, args, want) in cases {
                assert_eq!(call(&f, nr, args), want, "{what} for {p:?}");
            }
        }
    }

    #[test]
    fn broker_sockets_are_unix_stream_pairs_only() {
        use libc::*;
        let u = |v: c_int| v as u64;
        let flags = u(SOCK_NONBLOCK | SOCK_CLOEXEC);
        let b = seccomp_filters(&broker()).unwrap();
        let runner = seccomp_filters(&Profile::BuilderRunner).unwrap();
        let socket_cases: Vec<(&str, [u64; 3], u32)> = vec![
            ("tcp", [u(AF_INET), u(SOCK_STREAM), 0], ERRNO_EPERM),
            ("tcp flags", [u(AF_INET), u(SOCK_STREAM) | flags, 0], ERRNO_EPERM),
            (
                "tcp6 IPPROTO_TCP",
                [u(AF_INET6), u(SOCK_STREAM) | flags, u(IPPROTO_TCP)],
                ERRNO_EPERM,
            ),
            // The kernel takes `int`s: upper bits are not part of the argument.
            (
                "tcp upper bits",
                [(7 << 32) | u(AF_INET), (9 << 32) | u(SOCK_STREAM), 5 << 32],
                ERRNO_EPERM,
            ),
            ("udp", [u(AF_INET), u(SOCK_DGRAM), 0], ERRNO_EPERM),
            (
                "udp6 flags",
                [u(AF_INET6), u(SOCK_DGRAM) | flags, 0],
                ERRNO_EPERM,
            ),
            (
                "udp IPPROTO_UDP",
                [u(AF_INET), u(SOCK_DGRAM), u(IPPROTO_UDP)],
                ERRNO_EPERM,
            ),
            (
                "icmp ping",
                [u(AF_INET), u(SOCK_DGRAM), u(IPPROTO_ICMP)],
                ERRNO_EPERM,
            ),
            (
                "icmpv6 ping",
                [u(AF_INET6), u(SOCK_DGRAM), u(IPPROTO_ICMPV6)],
                ERRNO_EPERM,
            ),
            (
                "raw",
                [u(AF_INET), u(SOCK_RAW), u(IPPROTO_TCP)],
                ERRNO_EPERM,
            ),
            (
                "mptcp",
                [u(AF_INET), u(SOCK_STREAM), u(IPPROTO_MPTCP)],
                ERRNO_EPERM,
            ),
            (
                "mptcp6 flags",
                [u(AF_INET6), u(SOCK_STREAM) | flags, u(IPPROTO_MPTCP)],
                ERRNO_EPERM,
            ),
            (
                "sctp stream",
                [u(AF_INET), u(SOCK_STREAM), u(IPPROTO_SCTP)],
                ERRNO_EPERM,
            ),
            (
                "sctp seqpacket",
                [u(AF_INET), u(SOCK_SEQPACKET), u(IPPROTO_SCTP)],
                ERRNO_EPERM,
            ),
            ("smc", [u(AF_INET), u(SOCK_STREAM), 256], ERRNO_EPERM),
            ("dccp", [u(AF_INET), u(SOCK_DCCP), 0], ERRNO_EPERM),
            ("type 0", [u(AF_INET), 0, 0], ERRNO_EPERM),
            ("type 15", [u(AF_INET), 15, 0], ERRNO_EPERM),
            ("unix", [u(AF_UNIX), u(SOCK_STREAM), 0], ERRNO_EPERM),
            ("netlink", [u(AF_NETLINK), u(SOCK_RAW), 0], ERRNO_EPERM),
            ("packet", [u(AF_PACKET), u(SOCK_RAW), 0], ERRNO_EPERM),
            ("vsock", [u(AF_VSOCK), u(SOCK_STREAM), 0], ERRNO_EPERM),
        ];
        for (what, [a, t, pr], want) in socket_cases {
            assert_eq!(
                call(&b, SYS_socket, [a, t, pr, 0, 0, 0]),
                want,
                "broker socket {what}"
            );
            assert_eq!(
                call(&runner, SYS_socket, [a, t, pr, 0, 0, 0]),
                ERRNO_EPERM,
                "runner socket {what}"
            );
        }
        let pair_cases: Vec<(&str, [u64; 3], u32)> = vec![
            ("unix stream", [u(AF_UNIX), u(SOCK_STREAM), 0], ALLOW),
            (
                "unix stream flags",
                [u(AF_UNIX), u(SOCK_STREAM) | flags, 0],
                ALLOW,
            ),
            ("unix dgram", [u(AF_UNIX), u(SOCK_DGRAM), 0], ERRNO_EPERM),
            (
                "unix dgram flags",
                [u(AF_UNIX), u(SOCK_DGRAM) | flags, 0],
                ERRNO_EPERM,
            ),
            (
                "unix seqpacket",
                [u(AF_UNIX), u(SOCK_SEQPACKET), 0],
                ERRNO_EPERM,
            ),
            ("unix raw", [u(AF_UNIX), u(SOCK_RAW), 0], ERRNO_EPERM),
            ("inet stream", [u(AF_INET), u(SOCK_STREAM), 0], ERRNO_EPERM),
        ];
        for (what, [a, t, pr], want) in pair_cases {
            assert_eq!(
                call(&b, SYS_socketpair, [a, t, pr, 0x1000, 0, 0]),
                want,
                "broker socketpair {what}"
            );
            assert_eq!(
                call(&runner, SYS_socketpair, [a, t, pr, 0x1000, 0, 0]),
                ERRNO_EPERM,
                "runner socketpair {what}"
            );
        }
        // Review r2 F5: no `connect` for anyone (the broker's sockets come connected; without
        // `connect` it cannot disconnect one with AF_UNSPEC and aim it elsewhere), and no server
        // side.
        for nr in [SYS_connect, SYS_bind, SYS_listen, SYS_accept, SYS_accept4] {
            assert_eq!(call(&b, nr, [3, 0x1000, 16, 0, 0, 0]), ERRNO_EPERM, "broker {nr}");
            assert_eq!(call(&runner, nr, [3, 0x1000, 16, 0, 0, 0]), ERRNO_EPERM, "runner {nr}");
        }
    }

    /// The broker sets `IPPROTO_TCP`/`TCP_NODELAY` and nothing else; the runner and the worker set
    /// no socket option at all, before or after the broker's seal.
    #[test]
    fn socket_options_per_profile() {
        use libc::*;
        let u = |v: c_int| v as u64;
        let b = seccomp_filters(&broker()).unwrap();
        let mut sealed = b.clone();
        sealed.push(sealed_sockets_filter().unwrap());
        let nodelay = [5, u(IPPROTO_TCP), u(TCP_NODELAY), 0x1000, 4, 0];
        for f in [&b, &sealed] {
            assert_eq!(call(f, SYS_setsockopt, nodelay), ALLOW);
            // The kernel takes `int`s: bits above them are not part of the level or the name.
            assert_eq!(call(f, SYS_setsockopt, [5, (1 << 32) | u(IPPROTO_TCP), (7 << 32) | u(TCP_NODELAY), 0x1000, 4, 0]), ALLOW);
            for o in REFUSED_SOCKET_OPTIONS {
                assert_eq!(call(f, SYS_setsockopt, [5, u(o.level), u(o.option), 0x1000, 4, 0]), ERRNO_EPERM, "broker {}", o.name);
            }
            // TCP_NODELAY's number at another level, and other TCP options.
            for (level, opt) in [(SOL_SOCKET, TCP_NODELAY), (IPPROTO_IP, TCP_NODELAY), (IPPROTO_IPV6, TCP_NODELAY), (SOL_TCP, TCP_KEEPIDLE), (SOL_TCP, TCP_USER_TIMEOUT), (SOL_TCP, 19 /* TCP_REPAIR */), (SOL_TCP, TCP_FASTOPEN_CONNECT), (SOL_TCP, TCP_MD5SIG), (0, 0), (-1, TCP_NODELAY)] {
                assert_eq!(call(f, SYS_setsockopt, [5, u(level), u(opt), 0x1000, 4, 0]), ERRNO_EPERM, "broker {level}/{opt}");
            }
            // Reading options stays.
            assert_eq!(call(f, SYS_getsockopt, [5, u(SOL_SOCKET), u(SO_TYPE), 0x1000, 0x2000, 0]), ALLOW);
        }
        for p in [Profile::BuilderRunner, Profile::ExecuteWorker] {
            let f = seccomp_filters(&p).unwrap();
            assert!(denied_syscalls(&p).iter().any(|s| s.name == "setsockopt"), "{p:?}");
            assert_eq!(call(&f, SYS_setsockopt, nodelay), ERRNO_EPERM, "{p:?}");
            for o in REFUSED_SOCKET_OPTIONS {
                assert_eq!(call(&f, SYS_setsockopt, [5, u(o.level), u(o.option), 0x1000, 4, 0]), ERRNO_EPERM, "{p:?} {}", o.name);
            }
        }
        // The list covers what the review named, and nothing in it is the broker's option.
        for name in [
            "IPV6_RTHDR",
            "IPV6_2292RTHDR",
            "IP_OPTIONS",
            "SO_BINDTODEVICE",
            "SO_BINDTOIFINDEX",
            "IP_UNICAST_IF",
            "IPV6_UNICAST_IF",
            "IPV6_NEXTHOP",
            "IP_TRANSPARENT",
            "SO_MARK",
        ] {
            assert!(REFUSED_SOCKET_OPTIONS.iter().any(|o| o.name == name), "{name}");
        }
        assert!(!REFUSED_SOCKET_OPTIONS
            .iter()
            .any(|o| o.level == BROKER_SOCKET_OPTION.level && o.option == BROKER_SOCKET_OPTION.option));
    }

    /// After `seal_socket_creation` the broker cannot make even a Unix stream pair.
    #[test]
    fn the_seal_denies_every_socket_call() {
        use libc::*;
        let mut f = seccomp_filters(&broker()).unwrap();
        let pair = [u64::from(AF_UNIX as u32), u64::from(SOCK_STREAM as u32), 0, 0x1000, 0, 0];
        assert_eq!(call(&f, SYS_socketpair, pair), ALLOW);
        f.push(sealed_sockets_filter().unwrap());
        assert_eq!(call(&f, SYS_socketpair, pair), ERRNO_EPERM);
        for &(name, nr) in SEALED_SOCKET_SYSCALLS {
            assert_eq!(call(&f, nr, [3, 0x1000, 16, 0, 0, 0]), ERRNO_EPERM, "{name}");
        }
        assert_eq!(call(&f, SYS_read, [3, 0x1000, 16, 0, 0, 0]), ALLOW);
        assert_eq!(call(&f, SYS_sendmsg, [3, 0x1000, 0, 0, 0, 0]), ALLOW);
    }

    /// Review r2 B1: `getsid`/`getpgid` only of the caller; the mount table, the LSMs, `ustat`
    /// and `sysfs` are host metadata.
    #[test]
    fn other_processes_sessions_and_the_mount_table_are_denied() {
        use libc::*;
        let me = u64::from(std::process::id());
        for p in [Profile::BuilderRunner, Profile::ExecuteWorker, broker()] {
            let f = seccomp_filters(&p).unwrap();
            for nr in [SYS_getsid, SYS_getpgid] {
                assert_eq!(call(&f, nr, [0; 6]), ALLOW, "{p:?} {nr} self (0)");
                assert_eq!(call(&f, nr, [me, 0, 0, 0, 0, 0]), ALLOW, "{p:?} {nr} own pid");
                assert_eq!(call(&f, nr, [1, 0, 0, 0, 0, 0]), ERRNO_EPERM, "{p:?} {nr} init");
                assert_eq!(call(&f, nr, [me + 1, 0, 0, 0, 0, 0]), ERRNO_EPERM, "{p:?} {nr} other");
            }
            assert_eq!(call(&f, SYS_LSM_SET_SELF_ATTR, [0; 6]), ERRNO_EPERM, "{p:?}");
        }
        for p in [Profile::BuilderRunner, Profile::ExecuteWorker] {
            let f = seccomp_filters(&p).unwrap();
            let mut nrs = vec![SYS_STATMOUNT, SYS_LISTMOUNT, SYS_LSM_GET_SELF_ATTR, SYS_LSM_LIST_MODULES];
            #[cfg(target_arch = "x86_64")]
            nrs.extend([SYS_ustat, SYS_sysfs]);
            for nr in nrs {
                assert_eq!(call(&f, nr, [0; 6]), ERRNO_EPERM, "{p:?} {nr}");
            }
        }
    }

    #[test]
    fn foreign_and_x32_calls() {
        for p in [Profile::BuilderRunner, Profile::ExecuteWorker, broker()] {
            let f = seccomp_filters(&p).unwrap();
            // Another architecture (e.g. `int 0x80` on x86_64): the process is killed.
            let i386 = 3 | 0x4000_0000;
            assert_eq!(verdict(&f, &seccomp_data(i386, 20, [0; 6])), KILL, "{p:?}");
            #[cfg(target_arch = "x86_64")]
            {
                // x32 aliases, allowed or denied as 64-bit calls: EPERM, never the 64-bit verdict.
                assert_eq!(
                    call(&f, 0x4000_0000 | libc::SYS_getpid, [0; 6]),
                    ERRNO_EPERM,
                    "{p:?}"
                );
                assert_eq!(
                    call(&f, 0x4000_0000 | libc::SYS_shmget, [0; 6]),
                    ERRNO_EPERM,
                    "{p:?}"
                );
            }
        }
    }

    #[test]
    fn landlock_abi_is_queried() {
        // Not a requirement of the build host, only that the query itself works.
        assert!(landlock_abi() >= 0);
    }
}
