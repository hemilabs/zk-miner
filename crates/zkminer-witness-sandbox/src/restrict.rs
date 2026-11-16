//! Child side: Landlock, seccomp and process attributes ([`restrict_self`]).

use std::collections::BTreeMap;
use std::path::Path;

use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
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
///    for its `writable` directories; TCP bind and connect are handled, with connect rules only for
///    the broker's `tcp_connect_ports`; signals and abstract Unix sockets are scoped to the sandbox.
///    `/proc`, `~/.zkminer`, `/tmp`, `/dev/shm` and GPU device nodes are therefore denied by path.
/// 2. `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE(0)`, `RLIMIT_CORE=0`.
/// 3. **seccomp** (default allow, denied syscalls fail with `EPERM`): see the module source for the
///    full list. Runner and worker: no `socket*`, `connect`, `bind`, `listen`, `accept*`, `open*`,
///    `creat`, `exec*`, `ptrace`, `process_vm_*`, namespaces, mounts, `bpf`, `perf_event_open`, keys,
///    `userfaultfd`, `io_uring_*`, module/kexec/clock/swap/reboot/quota/acct/iopl, file handles,
///    `personality`; also no new processes (`fork`, `vfork`, `clone` without `CLONE_THREAD`;
///    `clone3` fails with `ENOSYS` so libc falls back to the filterable `clone`), no metadata writes
///    by path (`chmod`, `chown`, `utime*`, `*setxattr`, `*removexattr`, which Landlock does not
///    cover), no reaching other processes of the same uid (`setpriority`, `ioprio_set`, `prlimit64`,
///    `sched_set*` on another pid, `migrate_pages`, `move_pages`, `process_madvise`, `pidfd_getfd`),
///    no `TIOCSTI`/`TIOCLINUX`, no `PR_SET_PDEATHSIG` (the parent-death signal stays), no x32
///    syscalls. The broker additionally may `socket(AF_INET | AF_INET6, ..)`, `socketpair(AF_UNIX, ..)`
///    (a connected pair reaches nothing; tokio's signal driver needs one), `connect`, and open
///    files (which Landlock confines).
/// 4. Verification: `PR_GET_SECCOMP == 2`, `PR_GET_NO_NEW_PRIVS == 1`, `PR_GET_DUMPABLE == 0`,
///    `RLIMIT_CORE == 0`.
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
        && report.core_dumps_disabled)
    {
        return Err(SandboxError::Seccomp(format!(
            "restrictions did not take effect: {report:?}"
        )));
    }
    Ok(report)
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
    Ok(())
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

    if let Profile::Broker {
        readable,
        writable,
        tcp_connect_ports,
    } = profile
    {
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
        for port in tcp_connect_ports {
            created = created
                .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
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
const SYS_REMOVEXATTRAT: i64 = 466;
const SYS_OPEN_TREE_ATTR: i64 = 467;

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

/// Socket syscalls the broker needs (`socket` and `socketpair` are argument-filtered for it).
fn client_sockets() -> Vec<Denied> {
    vec![
        d("socket", libc::SYS_socket),
        d("socketpair", libc::SYS_socketpair),
        d("connect", libc::SYS_connect),
    ]
}

/// Denied for every profile.
fn always_denied() -> Vec<Denied> {
    use libc::*;
    let mut v = vec![
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
        v.extend(client_sockets());
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
        // The parent-death signal set by `prepare_command` cannot be cleared.
        (
            libc::SYS_prctl,
            vec![rule(vec![cond(
                0,
                Dword,
                Eq,
                libc::PR_SET_PDEATHSIG as u64,
            )?])?],
        ),
        // Terminal injection through an inherited tty.
        (
            libc::SYS_ioctl,
            vec![
                rule(vec![cond(1, Dword, Eq, libc::TIOCSTI)?])?,
                rule(vec![cond(1, Dword, Eq, libc::TIOCLINUX)?])?,
            ],
        ),
    ];
    if matches!(profile, Profile::Broker { .. }) {
        // The broker may create IPv4/IPv6 sockets only (no AF_UNIX, AF_NETLINK, AF_PACKET,
        // AF_ALG, AF_VSOCK, ...).
        v.push((
            libc::SYS_socket,
            vec![rule(vec![
                cond(0, Dword, Ne, libc::AF_INET as u64)?,
                cond(0, Dword, Ne, libc::AF_INET6 as u64)?,
            ])?],
        ));
        // A connected AF_UNIX pair reaches nothing outside the process; tokio's signal driver
        // creates one when the runtime is built (the workspace enables tokio's `signal` feature).
        v.push((libc::SYS_socketpair, vec![rule(vec![cond(0, Dword, Ne, libc::AF_UNIX as u64)?])?]));
    }
    Ok(v)
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

/// A small hand-written filter for what seccompiler cannot express:
/// - `clone3` fails with `ENOSYS` (its flags live in memory, so a filter cannot see
///   `CLONE_NEW*` or the absence of `CLONE_THREAD`; libc then falls back to `clone`, which the
///   denylist filters by flags);
/// - on x86_64, any x32 syscall (`nr >= 0x40000000`) fails with `EPERM`; a denylist keyed by
///   64-bit syscall numbers would otherwise miss the x32 aliases on kernels with
///   `CONFIG_X86_X32_ABI`.
fn raw_filter() -> BpfProgram {
    const ARCH_OFFSET: u32 = 4;
    const NR_OFFSET: u32 = 0;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 62 | 0x8000_0000 | 0x4000_0000;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 183 | 0x8000_0000 | 0x4000_0000;
    let allow = libc::SECCOMP_RET_ALLOW;
    let enosys = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
    let kill = libc::SECCOMP_RET_KILL_PROCESS;

    #[cfg(target_arch = "x86_64")]
    {
        let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        vec![
            /* 0 */ insn(BPF_LD_W_ABS, 0, 0, ARCH_OFFSET),
            /* 1 */ insn(BPF_JEQ_K, 0, 6, AUDIT_ARCH), // else -> 8 (kill)
            /* 2 */ insn(BPF_LD_W_ABS, 0, 0, NR_OFFSET),
            /* 3 */ insn(BPF_JGE_K, 3, 0, 0x4000_0000), // x32 -> 7 (EPERM)
            /* 4 */ insn(BPF_JEQ_K, 1, 0, libc::SYS_clone3 as u32), // -> 6 (ENOSYS)
            /* 5 */ insn(BPF_RET_K, 0, 0, allow),
            /* 6 */ insn(BPF_RET_K, 0, 0, enosys),
            /* 7 */ insn(BPF_RET_K, 0, 0, eperm),
            /* 8 */ insn(BPF_RET_K, 0, 0, kill),
        ]
    }
    #[cfg(target_arch = "aarch64")]
    {
        vec![
            /* 0 */ insn(BPF_LD_W_ABS, 0, 0, ARCH_OFFSET),
            /* 1 */ insn(BPF_JEQ_K, 0, 4, AUDIT_ARCH), // else -> 6 (kill)
            /* 2 */ insn(BPF_LD_W_ABS, 0, 0, NR_OFFSET),
            /* 3 */ insn(BPF_JEQ_K, 1, 0, libc::SYS_clone3 as u32), // -> 5 (ENOSYS)
            /* 4 */ insn(BPF_RET_K, 0, 0, allow),
            /* 5 */ insn(BPF_RET_K, 0, 0, enosys),
            /* 6 */ insn(BPF_RET_K, 0, 0, kill),
        ]
    }
}

/// The filters [`restrict_self`] installs, in order.
pub(crate) fn seccomp_filters(profile: &Profile) -> Result<Vec<BpfProgram>, SandboxError> {
    Ok(vec![raw_filter(), denylist_filter(profile)?])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broker() -> Profile {
        Profile::Broker {
            readable: vec![],
            writable: vec![],
            tcp_connect_ports: vec![443],
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
    fn broker_keeps_client_sockets_and_opens() {
        let names = |p: &Profile| {
            denied_syscalls(p)
                .iter()
                .map(|s| s.name)
                .collect::<Vec<_>>()
        };
        let runner = names(&Profile::BuilderRunner);
        let b = names(&broker());
        // `socket` and `socketpair` are argument-filtered for the broker (IPv4/IPv6 sockets, AF_UNIX
        // pairs), not denied outright.
        for s in ["socket", "socketpair", "connect", "openat", "openat2"] {
            assert!(runner.contains(&s), "{s}");
            assert!(!b.contains(&s), "{s}");
        }
        for s in [
            "bind",
            "listen",
            "accept4",
            "execve",
            "ptrace",
            "io_uring_setup",
        ] {
            assert!(b.contains(&s), "{s}");
        }
        let filtered: Vec<i64> = conditional_denials(&broker()).unwrap().into_iter().map(|(nr, _)| nr).collect();
        assert!(filtered.contains(&libc::SYS_socket));
        assert!(filtered.contains(&libc::SYS_socketpair));
    }

    #[test]
    fn denylist_has_no_duplicates() {
        for p in [Profile::BuilderRunner, broker()] {
            let mut nrs: Vec<i64> = denied_syscalls(&p).iter().map(|s| s.nr).collect();
            let n = nrs.len();
            nrs.sort_unstable();
            nrs.dedup();
            assert_eq!(n, nrs.len());
        }
    }

    #[test]
    fn landlock_abi_is_queried() {
        // Not a requirement of the build host, only that the query itself works.
        assert!(landlock_abi() >= 0);
    }
}
