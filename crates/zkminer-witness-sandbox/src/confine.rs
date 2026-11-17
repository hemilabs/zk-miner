//! Confinement of the processes that run requester guests outside the sandbox profiles: the miner's
//! inline measuring and proving workers (risc0, SP1, OpenVM) and, through [`crate::supervise`], the
//! `sp1-gpu-server` an SP1 worker starts.
//!
//! Workers that run requester guests are confined: before a worker runs any guest (or does any GPU
//! work, whose caches a later guest-free process would read), it calls [`confine_all_threads`] once,
//! and from then on the process, every thread it has and everything it starts can only:
//!
//! - **sockets**: what its [`Sockets`] policy leaves (see [`crate::netdeny`]): nothing at all for
//!   the risc0 and OpenVM workers and a measuring SP1 worker; for a proving SP1 worker, only the
//!   connection to its own server that it made before;
//! - **files** (Landlock): read the system's files ([`system_read_paths`]) and the paths the worker
//!   names with [`Rights::READ`], execute only what it names with [`Rights::EXEC`] (and the dynamic
//!   loader), write only below what it names with [`Rights::WRITE`] (its private temporary
//!   directory, GPU caches it needs, `/dev/shm` where needed), open only the device nodes it names
//!   with [`Rights::DEVICE`]. Anything else, the user's home first of all (dotfiles, `~/.config`,
//!   `~/.zkminer`, the provers, keys), is out of reach, for reading and writing alike. TCP bind and
//!   connect are refused by Landlock too;
//! - **other processes**: no signal to, and no `ptrace`-class access (`/proc/<pid>/mem`, `environ`,
//!   `fd`) to, a process outside its Landlock domain (the miner, other workers); no abstract Unix
//!   socket of another domain. The miner can still signal it;
//! - **kernel surface**: no namespace and no mount, no `userfaultfd`, `perf_event_open` or file
//!   handles (see [`crate::netdeny`]).
//!
//! Since Landlock does not govern the path walk (a `stat` or a lookup reaches any directory), a
//! process confines itself only where no filesystem it can reach is a network or FUSE filesystem or
//! an automount map ([`crate::localfs`]): it refuses before applying anything, and checks again
//! after.
//!
//! Landlock is applied to every thread at once with `LANDLOCK_RESTRICT_SELF_TSYNC` (ABI 8). On an
//! older kernel the process must still be single-threaded, or confinement fails. Everything fails
//! closed: on any error the caller must not run the guest.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd,
    RestrictSelfAttr, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
    Scope, ABI,
};

pub use crate::netdeny::{OpenSocket, Sockets};
use crate::restrict::{landlock_abi, thread_count, MIN_LANDLOCK_ABI};
use crate::{localfs, netdeny, SandboxError};

/// The Landlock ABI with `LANDLOCK_RESTRICT_SELF_TSYNC`.
pub const TSYNC_LANDLOCK_ABI: i32 = 8;

/// Set once this process has applied any part of its confinement.
static INSTALLED: AtomicBool = AtomicBool::new(false);
/// Serialises [`confine_all_threads`], so two threads never stack two confinements.
static INSTALL: Mutex<()> = Mutex::new(());
/// What [`confine_all_threads`] applied, once it succeeded.
static REPORT: OnceLock<ConfinementReport> = OnceLock::new();

/// What a confined process may do below one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights(u8);

impl Rights {
    /// Read files and list directories.
    pub const READ: Rights = Rights(1);
    /// Read and execute files (and list directories).
    pub const EXEC: Rights = Rights(2);
    /// Read, create, write, truncate, rename and remove regular files and directories. No devices,
    /// sockets, fifos or symlinks, and no execution unless [`Rights::EXEC`] is given too.
    pub const WRITE: Rights = Rights(4);
    /// Open device nodes for reading and writing, with their ioctls.
    pub const DEVICE: Rights = Rights(8);
    /// Create Unix sockets (`bind` to a path).
    pub const MAKE_SOCK: Rights = Rights(16);
    /// List a directory, nothing more.
    pub const LIST: Rights = Rights(32);

    fn has(self, other: Rights) -> bool {
        self.0 & other.0 != 0
    }

    /// The Landlock rights for a directory (`dir`) or a file.
    fn access(self, dir: bool) -> BitFlags<AccessFs> {
        let mut a = BitFlags::<AccessFs>::empty();
        if self.has(Rights::READ) {
            a |= AccessFs::ReadFile | AccessFs::ReadDir;
        }
        if self.has(Rights::EXEC) {
            a |= AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
        }
        if self.has(Rights::WRITE) {
            a |= AccessFs::ReadFile
                | AccessFs::ReadDir
                | AccessFs::WriteFile
                | AccessFs::Truncate
                | AccessFs::RemoveFile
                | AccessFs::RemoveDir
                | AccessFs::MakeReg
                | AccessFs::MakeDir
                | AccessFs::Refer;
        }
        if self.has(Rights::DEVICE) {
            a |= AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::WriteFile | AccessFs::IoctlDev;
        }
        if self.has(Rights::MAKE_SOCK) {
            a |= AccessFs::MakeSock;
        }
        if self.has(Rights::LIST) {
            a |= AccessFs::ReadDir;
        }
        if dir {
            a
        } else {
            a & AccessFs::from_file(ABI::V9)
        }
    }
}

impl std::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, rhs: Rights) -> Rights {
        Rights(self.0 | rhs.0)
    }
}

/// What a confined process may still do: its socket policy and its filesystem rules.
#[derive(Debug, Clone)]
pub struct Confinement {
    sockets: Sockets,
    rules: Vec<(PathBuf, Rights)>,
}

impl Confinement {
    /// No filesystem access at all, and `sockets`.
    pub fn new(sockets: Sockets) -> Self {
        Self {
            sockets,
            rules: Vec::new(),
        }
    }

    /// `sockets`, with the host's system files readable ([`system_read_paths`]), the dynamic loader
    /// executable ([`loader_paths`]), `/dev` listable and its harmless nodes (`null`, `zero`,
    /// `full`, `random`, `urandom`) usable.
    pub fn with_system(sockets: Sockets) -> Self {
        let mut c = Self::new(sockets);
        for p in system_read_paths() {
            c.allow(p, Rights::READ);
        }
        for p in loader_paths() {
            c.allow(p, Rights::EXEC);
        }
        c.allow("/dev", Rights::LIST);
        for p in [
            "/dev/null",
            "/dev/zero",
            "/dev/full",
            "/dev/random",
            "/dev/urandom",
        ] {
            c.allow(p, Rights::DEVICE);
        }
        c
    }

    /// Adds `rights` below `path` (a missing path is skipped when the rules are applied: nothing
    /// can be reached through it then either).
    pub fn allow(&mut self, path: impl Into<PathBuf>, rights: Rights) -> &mut Self {
        self.rules.push((path.into(), rights));
        self
    }

    /// The GPU device nodes ([`gpu_device_paths`]), with their ioctls.
    pub fn allow_gpu_devices(&mut self) -> &mut Self {
        for p in gpu_device_paths() {
            self.allow(p, Rights::DEVICE);
        }
        self
    }

    pub fn sockets(&self) -> Sockets {
        self.sockets
    }

    pub fn rules(&self) -> &[(PathBuf, Rights)] {
        &self.rules
    }

    /// Every path a rule names, whatever its rights.
    pub fn granted_paths(&self) -> Vec<PathBuf> {
        self.rules.iter().map(|(p, _)| p.clone()).collect()
    }

    /// The Landlock ruleset: every filesystem right is handled (those of ABI 6 required, later ones
    /// where the kernel has them), and granted only by the rules; TCP bind and connect are handled
    /// and never granted; signals and abstract Unix sockets are scoped to the domain. With `tsync`,
    /// it is applied to every thread of the process.
    pub(crate) fn landlock_ruleset(&self, tsync: bool) -> Result<RulesetCreated, SandboxError> {
        let ll = |e: &dyn std::fmt::Display| SandboxError::Landlock(e.to_string());
        let mut created = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V6))
            .map_err(|e| ll(&e))?
            .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
            .map_err(|e| ll(&e))?
            .scope(Scope::AbstractUnixSocket | Scope::Signal)
            .map_err(|e| ll(&e))?
            // Rights of later ABIs (ABI 9's ResolveUnix: connecting to a pathname socket) are
            // handled where the kernel has them, and granted by no rule.
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(ABI::V9))
            .map_err(|e| ll(&e))?
            .create()
            .map_err(|e| ll(&e))?
            .set_compatibility(CompatLevel::HardRequirement);
        for (path, rights) in &self.rules {
            let Ok(meta) = std::fs::metadata(path) else {
                continue;
            };
            let fd = match PathFd::new(path) {
                Ok(fd) => fd,
                // Gone between the two calls: as good as missing.
                Err(_) if !path.exists() => continue,
                Err(e) => return Err(ll(&format!("{}: {e}", path.display()))),
            };
            let access = rights.access(meta.is_dir());
            if access.is_empty() {
                continue;
            }
            created = created
                .add_rule(PathBeneath::new(fd, access))
                .map_err(|e| ll(&format!("{}: {e}", path.display())))?;
        }
        if tsync {
            created = created.all_threads(true).map_err(|e| ll(&e))?;
        }
        Ok(created)
    }
}

/// What [`confine_all_threads`] applied, each part checked after the fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinementReport {
    /// The kernel's Landlock ABI.
    pub landlock_abi: i32,
    /// Whether Landlock was applied to every thread at once (`TSYNC`), rather than to a process that
    /// had one thread.
    pub tsync: bool,
    /// Whether every handled Landlock right is enforced (false where the kernel lacks a later one).
    pub landlock_fully_enforced: bool,
    pub sockets: Sockets,
    /// Threads the process had when the filters went on.
    pub threads: usize,
    /// Sockets left open that the policy lets the process keep.
    pub kept_sockets: Vec<String>,
    /// The probes that passed, by name.
    pub probes: Vec<&'static str>,
}

impl std::fmt::Display for ConfinementReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Landlock ABI {} ({}{}), seccomp: {}, {} thread{}",
            self.landlock_abi,
            if self.tsync {
                "all threads"
            } else {
                "single thread"
            },
            if self.landlock_fully_enforced {
                ""
            } else {
                ", partially enforced"
            },
            self.sockets,
            self.threads,
            if self.threads == 1 { "" } else { "s" },
        )?;
        if !self.kept_sockets.is_empty() {
            write!(f, ", kept {}", self.kept_sockets.join("; "))?;
        }
        write!(f, "; checked: {}", self.probes.join(", "))
    }
}

/// Confines this process, all of its threads and everything it starts from now on, for the rest of
/// its life: see the [module docs](self). Idempotent: a second call checks the open sockets again
/// and returns the first call's report.
///
/// First it refuses if a filesystem the process can reach is not local
/// ([`localfs::check_local_filesystems`]: a network or FUSE filesystem, or an automount map, anywhere
/// a path lookup gets to, or under a path `c` grants), before applying anything.
///
/// After applying it checks the result rather than the calls: `PR_GET_SECCOMP == 2`,
/// `PR_GET_NO_NEW_PRIVS == 1`, every thread in seccomp filter mode, sockets of every kind refused,
/// `unshare` refused and `clone3` unimplemented (no namespace), the root directory unreadable
/// (Landlock is on), the parent process unreachable by signal, and still no filesystem in reach
/// that is not local. Then it fails if a socket the policy does not let the process keep is still
/// open, which no filter can take back: the caller must not run a guest then.
///
/// Fails closed: on any error the caller must not run the guest. Once anything is applied it stays
/// applied, error or not ([`is_active`]).
pub fn confine_all_threads(c: &Confinement) -> Result<ConfinementReport, SandboxError> {
    if c.sockets == Sockets::Supervised {
        return Err(SandboxError::InvalidArgument(
            "a supervised confinement is applied by `supervise`".into(),
        ));
    }
    let _install = INSTALL.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(report) = REPORT.get() {
        check_open_sockets(c.sockets)?;
        return Ok(report.clone());
    }
    if INSTALLED.load(Ordering::Acquire) {
        return Err(SandboxError::Seccomp(
            "an earlier confinement of this process failed part-way".into(),
        ));
    }
    let abi = landlock_abi();
    if abi < MIN_LANDLOCK_ABI {
        return Err(SandboxError::LandlockUnavailable {
            need: MIN_LANDLOCK_ABI,
            have: abi,
        });
    }
    let tsync = abi >= TSYNC_LANDLOCK_ABI;
    if !tsync {
        let threads = thread_count()?;
        if threads != 1 {
            return Err(SandboxError::MultiThreaded { threads });
        }
    }
    // No network filesystem within reach: refused before anything is applied, so a later call
    // can try again once it is unmounted.
    localfs::check_local_filesystems(&c.granted_paths())?;
    // Everything that allocates or opens a path happens before anything is applied.
    let ruleset = c.landlock_ruleset(tsync)?;
    let filters = netdeny::filters(c.sockets)?;

    // SAFETY: plain prctl with valid arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    INSTALLED.store(true, Ordering::Release);
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

    let threads = thread_count()?;
    let probes = verify(c)?;
    let kept = check_open_sockets(c.sockets)?;
    let report = ConfinementReport {
        landlock_abi: abi,
        tsync,
        landlock_fully_enforced: status.ruleset == RulesetStatus::FullyEnforced,
        sockets: c.sockets,
        threads,
        kept_sockets: kept.iter().map(ToString::to_string).collect(),
        probes,
    };
    let _ = REPORT.set(report.clone());
    Ok(report)
}

/// Whether this process has applied (any part of) a confinement: it may no longer reach a network,
/// write outside its own directories, or start anything that can. One inherited from the parent does
/// not count: only one this process applied.
pub fn is_active() -> bool {
    INSTALLED.load(Ordering::Acquire)
}

/// The report of the confinement this process applied, if it succeeded.
pub fn report() -> Option<ConfinementReport> {
    REPORT.get().cloned()
}

/// The sockets still open that `sockets` lets the process keep, or an error naming the others.
fn check_open_sockets(sockets: Sockets) -> Result<Vec<OpenSocket>, SandboxError> {
    let open = netdeny::open_sockets()?;
    let bad = netdeny::sockets_not_allowed(sockets, &open);
    if !bad.is_empty() {
        return Err(SandboxError::Seccomp(format!(
            "the confinement is on, but {} socket{} opened before it {} still open ({}): a filter \
             stops new sockets, not these",
            bad.len(),
            if bad.len() == 1 { "" } else { "s" },
            if bad.len() == 1 { "is" } else { "are" },
            bad.join(", ")
        )));
    }
    Ok(open)
}

fn errno() -> Option<i32> {
    std::io::Error::last_os_error().raw_os_error()
}

/// Checks what [`confine_all_threads`] promises, not that its calls returned. The names of the
/// checks that passed.
fn verify(c: &Confinement) -> Result<Vec<&'static str>, SandboxError> {
    let fail = |what: String| Err(SandboxError::Seccomp(format!("confinement: {what}")));
    let mut passed = Vec::new();
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
    passed.push("seccomp filter mode and no_new_privs");
    if let Some(tid) = netdeny::threads_not_in_filter_mode()?.first() {
        return fail(format!("thread {tid} is not in seccomp filter mode"));
    }
    passed.push("every thread filtered");
    for (name, domain, kind) in [
        ("AF_INET", libc::AF_INET, libc::SOCK_STREAM),
        ("AF_INET6", libc::AF_INET6, libc::SOCK_DGRAM),
        ("AF_UNIX", libc::AF_UNIX, libc::SOCK_STREAM),
        ("AF_NETLINK", libc::AF_NETLINK, libc::SOCK_RAW),
    ] {
        // SAFETY: socket takes no pointers; an fd it returns is closed below.
        let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, 0) };
        let e = errno();
        if fd >= 0 {
            // SAFETY: closing the fd just opened.
            unsafe { libc::close(fd) };
            return fail(format!("socket({name}) still succeeds"));
        }
        if e != Some(libc::EPERM) {
            return fail(format!("socket({name}) failed with {e:?}, not EPERM"));
        }
    }
    passed.push("socket() refused");
    let mut pair = [-1; 2];
    // SAFETY: `pair` has room for the two fds.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    if rc == 0 {
        // SAFETY: the two fds just opened.
        unsafe {
            libc::close(pair[0]);
            libc::close(pair[1]);
        }
        return fail("a datagram socketpair still succeeds".into());
    }
    passed.push("datagram socketpair refused");
    if let Err(what) = netdeny::namespaces_refused() {
        return fail(what);
    }
    passed.push("namespaces refused");
    if !c.rules.iter().any(|(p, _)| p == Path::new("/")) {
        // SAFETY: a NUL-terminated path; an fd it returns is closed below.
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        let e = errno();
        if fd >= 0 {
            // SAFETY: closing the fd just opened.
            unsafe { libc::close(fd) };
            return fail("the root directory is still readable: Landlock is not in effect".into());
        }
        if e != Some(libc::EACCES) {
            return fail(format!("opening / failed with {e:?}, not EACCES"));
        }
        passed.push("filesystem restricted");
    }
    // SAFETY: getppid and kill with signal 0 send nothing.
    let parent = unsafe { libc::getppid() };
    if parent > 1 {
        let rc = unsafe { libc::kill(parent, 0) };
        let e = errno();
        if rc == 0 || e != Some(libc::EPERM) {
            return fail(format!(
                "the parent process {parent} can still be signalled ({rc}, {e:?})"
            ));
        }
        passed.push("parent unreachable by signal");
    }
    localfs::check_local_filesystems(&c.granted_paths())?;
    passed.push("no network filesystem in reach");
    Ok(passed)
}

/// The host's system files, readable by every confined process: `/usr`, `/etc`, `/opt`, the `lib`
/// and `bin` directories, `/sys`, `/proc` (other processes' sensitive entries are guarded by
/// Landlock's ptrace scoping) and udev's device database. Those that exist.
pub fn system_read_paths() -> Vec<PathBuf> {
    [
        "/usr",
        "/etc",
        "/opt",
        "/lib",
        "/lib32",
        "/lib64",
        "/libx32",
        "/bin",
        "/sbin",
        "/sys",
        "/proc",
        "/run/udev",
    ]
    .iter()
    .map(PathBuf::from)
    .filter(|p| p.exists())
    .collect()
}

/// The dynamic loader, which the kernel opens for execution with every dynamically linked program.
pub fn loader_paths() -> Vec<PathBuf> {
    #[cfg(target_arch = "x86_64")]
    let candidates = [
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    ];
    #[cfg(target_arch = "aarch64")]
    let candidates = [
        "/lib/ld-linux-aarch64.so.1",
        "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
    ];
    candidates
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect()
}

/// The GPU device nodes of the host: NVIDIA's (`/dev/nvidia*`, `/dev/nvidia-caps`), AMD's
/// (`/dev/kfd`) and the DRM nodes (`/dev/dri`), those that exist.
pub fn gpu_device_paths() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir("/dev")
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("nvidia"))
        .map(|e| e.path())
        .collect();
    v.extend(
        ["/dev/kfd", "/dev/dri"]
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists()),
    );
    v.sort();
    v
}

/// The absolute directories of `LD_LIBRARY_PATH`, which a GPU runtime loads libraries from.
pub fn library_path_dirs() -> Vec<PathBuf> {
    std::env::var_os("LD_LIBRARY_PATH")
        .map(|v| {
            std::env::split_paths(&v)
                .filter(|p| p.is_absolute())
                .collect()
        })
        .unwrap_or_default()
}

/// The prefix of the private temporary directories [`private_tmpdir`] creates.
const TMPDIR_PREFIX: &str = "zkminer-";

/// Creates a private temporary directory (mode 0700) for this process, under the system's temporary
/// directory: `zkminer-<tag>-<pid>-XXXXXX`. A confined process writes there instead of the shared
/// `/tmp`, so nothing it writes lands where another process, confined or not, would pick it up. The
/// caller points `TMPDIR` at it while it is still single-threaded.
///
/// First removes such directories of `tag` whose process is gone (a worker that was killed cannot
/// remove its own).
pub fn private_tmpdir(tag: &str) -> std::io::Result<PathBuf> {
    if tag.is_empty() || !tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid temporary directory tag {tag:?}"),
        ));
    }
    let base = std::env::temp_dir();
    remove_stale_tmpdirs(&base, tag);
    let template = base.join(format!(
        "{TMPDIR_PREFIX}{tag}-{}-XXXXXX",
        std::process::id()
    ));
    let mut bytes = std::ffi::CString::new(template.into_os_string().into_encoded_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
        .into_bytes_with_nul();
    // SAFETY: `bytes` is a writable, NUL-terminated template ending in XXXXXX.
    let rc = unsafe { libc::mkdtemp(bytes.as_mut_ptr().cast()) };
    if rc.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    bytes.pop();
    // SAFETY: mkdtemp wrote a path of the same length.
    Ok(PathBuf::from(unsafe {
        std::ffi::OsString::from_encoded_bytes_unchecked(bytes)
    }))
}

/// Removes `<base>/zkminer-<tag>-<pid>-*` directories of this uid whose `<pid>` is not running.
fn remove_stale_tmpdirs(base: &Path, tag: &str) {
    use std::os::unix::fs::MetadataExt;
    let prefix = format!("{TMPDIR_PREFIX}{tag}-");
    // SAFETY: geteuid has no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    for entry in std::fs::read_dir(base).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let Some(rest) = name.to_str().and_then(|n| n.strip_prefix(&prefix)) else {
            continue;
        };
        let Some(pid) = rest.split('-').next().and_then(|p| p.parse::<u32>().ok()) else {
            continue;
        };
        if Path::new(&format!("/proc/{pid}")).exists() {
            continue;
        }
        // Not following a symlink, and only our own directories.
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if meta.is_dir() && meta.uid() == uid {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}
