//! Where a proof's segments go: a directory of this worker's own on disk, not the temporary
//! directory.
//!
//! risc0's prover first executes the guest, writing every segment to a file, and then proves them.
//! Left to itself it writes them to a temporary directory under `TMPDIR`, which on most hosts is a
//! RAM-backed tmpfs: a long proof stages gigabytes there, which the host's memory admission does
//! not count. So every proof writes its segments to a directory of this worker's ([`prepare`], made
//! at startup; the confinement lets the worker write it), and the directory is emptied after each
//! proof ([`Emptied`]). The directory is:
//! - `<segment_dir>/inline/<pid>-<start>` when the miner names the segment directory of its witness
//!   proofs ([`WITNESS_SEGMENT_DIR_ENV`], from `[retention] segment_dir`): inline and witness proofs
//!   then share the disk the miner reserves segment space on;
//! - else `~/.zkminer/risc0-segments/<pid>-<start>` (`~/.zkminer` may be a link of this user's to a
//!   directory of this user's).
//!
//! `<start>` is the process's start time, so the directory of a killed worker whose pid this one
//! reuses is never taken for this one's. A worker that was killed cannot empty its own: the next
//! worker to start removes the directories of workers that are gone, told by their pid and start
//! time (`/proc` on Linux; on Windows the process's creation time, `zkminer_prover_protocol::
//! liveness`). On macOS a directory is named by the pid alone and removed once no process has
//! that pid (a killed Metal worker's segments would otherwise stay under `~/.zkminer` for good; a
//! reused pid keeps it until that process is gone too). On another OS every directory is kept.
//! Workers sharing the directory from different pid namespaces cannot see each other, and would
//! remove each other's.
//!
//! On Windows the directory is writable by every Low-integrity worker, so one of them may have put
//! a junction or a symbolic link there, named like a dead worker's directory or inside one. Neither
//! is ever followed: a link is not a directory to [`remove_stale`], and `remove_dir_all` removes a
//! link inside a directory, not what it points at.
//!
//! Without a directory (no home directory, or a directory on the way that is not this user's
//! alone), segments go where risc0 puts them by default; [`log_fallback`] says so once logging is up.
//!
//! A witness proof writes its segments to its own directory below the segment directory instead
//! (`witness.rs`).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use zkminer_prover_protocol::types::WITNESS_SEGMENT_DIR_ENV;

/// The directory under the home directory that holds each worker's segment directory.
const BASE: &str = ".zkminer/risc0-segments";

/// The directory under the miner's segment directory that holds each worker's, beside the witness
/// proofs' (which are named by a job id's hex digits, never this).
const INLINE: &str = "inline";

/// The free space below which a proof is not started: it would fill the disk part-way through its
/// execution. The miner reserves each proof's estimated segments, keeping this much free beside them.
pub const MIN_FREE_BYTES: u64 = 1 << 30;

/// This worker's segment directory, once [`prepare`] made it.
static DIR: OnceLock<PathBuf> = OnceLock::new();

/// Why there is none, for [`log_fallback`].
static FALLBACK: OnceLock<String> = OnceLock::new();

/// At startup, before the confinement (which must be told of the directory) and while the process
/// has one thread: removes the segment directories of workers that are gone, then makes this
/// worker's, empty. Without one, segments go where risc0 puts them by default, and this says so on
/// stderr (logging is not set up yet; [`log_fallback`] says it again once it is).
pub fn prepare() {
    let root = std::env::var_os(WITNESS_SEGMENT_DIR_ENV)
        .filter(|d| !d.is_empty())
        .map(PathBuf::from);
    let me = std::process::id();
    match prepare_in(
        dirs::home_dir().as_deref(),
        root.as_deref(),
        me,
        start_time(me),
    ) {
        Ok(dir) => {
            let _ = DIR.set(dir);
        }
        Err(e) => {
            eprintln!("risc0's segment files go to the temporary directory: {e}");
            let _ = FALLBACK.set(e);
        }
    }
}

/// Says, through the log, that segments go to the temporary directory, if they do.
pub fn log_fallback() {
    if let Some(why) = FALLBACK.get() {
        tracing::warn!(
            "risc0's segment files go to the temporary directory ({why}): on a tmpfs a long proof \
             stages gigabytes of RAM there that the miner does not count"
        );
    }
}

/// [`prepare`]'s work for a worker `pid` started at `start`: its directory under `root` (the miner's
/// segment directory) when given, else under `home`. The stale directories go first.
fn prepare_in(
    home: Option<&Path>,
    root: Option<&Path>,
    pid: u32,
    start: Option<u64>,
) -> Result<PathBuf, String> {
    let (top, base) = match root {
        Some(root) => {
            if !root.is_absolute() {
                return Err(format!(
                    "{WITNESS_SEGMENT_DIR_ENV} {} is not an absolute path",
                    root.display()
                ));
            }
            std::fs::create_dir_all(root).map_err(|e| format!("{}: {e}", root.display()))?;
            if !std::fs::metadata(root).is_ok_and(|m| m.is_dir()) {
                return Err(format!("{} is not a directory", root.display()));
            }
            (root.to_path_buf(), root.join(INLINE))
        }
        None => {
            let home = home.ok_or_else(|| "no home directory".to_string())?;
            (home.to_path_buf(), home.join(BASE))
        }
    };
    let name = dir_name(pid, start);
    remove_stale(&base, &name);
    let dir = make(&top, &base, &name, root.is_none())?;
    // Fresh by its name; emptied all the same, in case a worker of the same name left it.
    empty(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir)
}

/// `<pid>-<start>`, or `<pid>` where the start time cannot be read.
fn dir_name(pid: u32, start: Option<u64>) -> String {
    match start {
        Some(start) => format!("{pid}-{start}"),
        None => pid.to_string(),
    }
}

/// This worker's segment directory, if it has one.
pub fn dir() -> Option<&'static Path> {
    DIR.get().map(PathBuf::as_path)
}

/// Point a proof's executor at this worker's segment directory, and return what empties it when the
/// proof is over (hold it until then). Without a directory, risc0's default stays.
pub fn spill_here(env: &mut risc0_zkvm::ExecutorEnvBuilder<'_>) -> Emptied {
    spill_to(env, dir())
}

fn spill_to(env: &mut risc0_zkvm::ExecutorEnvBuilder<'_>, dir: Option<&Path>) -> Emptied {
    if let Some(dir) = dir {
        env.segment_path(dir);
    }
    Emptied(dir.map(Path::to_path_buf))
}

/// Refuses to start a proof while this worker's segment filesystem has less than
/// [`MIN_FREE_BYTES`] free: the proof would fill it part-way through its execution. The error is an
/// `ENOSPC` [`std::io::Error`], which the prove path reports as this host's failure, not the job's.
/// Without a directory, or where the free space cannot be read, nothing is refused.
pub fn check_room() -> std::io::Result<()> {
    match dir() {
        Some(dir) => check_room_in(dir),
        None => Ok(()),
    }
}

fn check_room_in(dir: &Path) -> std::io::Result<()> {
    match free_bytes(dir) {
        Some(free) if free < MIN_FREE_BYTES => Err(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            NoRoom {
                dir: dir.to_path_buf(),
                free,
            },
        )),
        _ => Ok(()),
    }
}

/// The free space under a segment directory was below [`MIN_FREE_BYTES`] before a proof.
#[derive(Debug)]
struct NoRoom {
    dir: PathBuf,
    free: u64,
}

impl std::fmt::Display for NoRoom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} has {} bytes free, under the {MIN_FREE_BYTES} a proof needs to start",
            self.dir.display(),
            self.free
        )
    }
}

impl std::error::Error for NoRoom {}

/// Whether `e` failed because a filesystem was full or this user's quota was used up (`ENOSPC`,
/// `EDQUOT`), judged from the types in its chain (an [`std::io::Error`]'s code, or [`check_room`]'s
/// refusal), never from its text, which can carry a guest's.
pub fn storage_exhausted(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<NoRoom>().is_some()
            || c.downcast_ref::<std::io::Error>().is_some_and(|io| {
                io.get_ref().is_some_and(|inner| inner.is::<NoRoom>())
                    || io
                        .raw_os_error()
                        .is_some_and(|n| n == enospc() || Some(n) == edquot())
            })
    })
}

#[cfg(unix)]
fn enospc() -> i32 {
    libc::ENOSPC
}

#[cfg(not(unix))]
fn enospc() -> i32 {
    28
}

#[cfg(unix)]
fn edquot() -> Option<i32> {
    Some(libc::EDQUOT)
}

#[cfg(not(unix))]
fn edquot() -> Option<i32> {
    None
}

/// Bytes available to this user on the filesystem holding `dir`, where they can be read.
#[cfg(unix)]
fn free_bytes(dir: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: statvfs fills a plain struct, and `c` is a NUL-terminated path.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)]
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

#[cfg(not(unix))]
fn free_bytes(_dir: &Path) -> Option<u64> {
    None
}

/// Empties a segment directory when dropped: at the end of a proof, whatever its outcome. Segment
/// files are named by their index, so a later, shorter proof would otherwise leave the tail of a
/// longer one behind.
#[must_use = "the directory is emptied when this is dropped"]
pub struct Emptied(Option<PathBuf>);

impl Drop for Emptied {
    fn drop(&mut self) {
        if let Some(dir) = &self.0 {
            if let Err(e) = empty(dir) {
                tracing::warn!("could not empty {}: {e}", dir.display());
            }
        }
    }
}

/// Removes everything in `dir`, never following a link.
fn empty(dir: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// Makes `base/<name>`, and every directory from `top` down to it, a directory of this user's alone
/// (mode 0700, no link): a segment holds the guest's input and memory, which no other user may read
/// or replace. The first directory below `top` may be a link of this user's to a directory of this
/// user's when `link_first` (an operator's `~/.zkminer` on another disk). Its path.
fn make(top: &Path, base: &Path, name: &str, link_first: bool) -> Result<PathBuf, String> {
    let dir = base.join(name);
    let mut at = top.to_path_buf();
    for (i, part) in dir
        .strip_prefix(top)
        .map_err(|e| e.to_string())?
        .iter()
        .enumerate()
    {
        at.push(part);
        private_dir(&at, link_first && i == 0)?;
    }
    Ok(dir)
}

/// Makes `dir` with mode 0700 if it is missing, or checks that it is a directory (not a link) of
/// this user's and makes it 0700. With `allow_link`, `dir` may instead be a link of this user's to
/// a directory of this user's, which is then made 0700.
#[cfg(unix)]
fn private_dir(dir: &Path, allow_link: bool) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    }
    let link = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    let follows = allow_link && link.file_type().is_symlink() && link.uid() == me;
    // Through the link only when it is allowed and this user's; what it reaches must be too.
    let read = |d: &Path| {
        if follows {
            std::fs::metadata(d)
        } else {
            std::fs::symlink_metadata(d)
        }
        .map_err(|e| format!("{}: {e}", d.display()))
    };
    let meta = read(dir)?;
    if !meta.is_dir() || meta.uid() != me {
        return Err(format!(
            "{} is not a directory of this user's",
            dir.display()
        ));
    }
    if meta.mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        // Again, as it was checked: what was changed must be what was checked.
        let meta = read(dir)?;
        if !meta.is_dir() || meta.uid() != me || meta.mode() & 0o077 != 0 {
            return Err(format!("{} could not be made private", dir.display()));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_dir(dir: &Path, _allow_link: bool) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

/// Removes every directory in `base` of a worker that is gone (and is not `own`, this worker's): one
/// named `<pid>-<start>` whose pid is not running or runs a process started at another time (a
/// reused pid), or one named `<pid>` (an older worker's) whose pid is not running.
fn remove_stale(base: &Path, own: &str) {
    for entry in std::fs::read_dir(base).into_iter().flatten().flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name == own || !gone(&name) {
            continue;
        }
        // `file_type` does not follow a link: only a real directory is removed.
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Whether the worker a directory `name` belongs to is gone. Anything not named by a worker is kept.
fn gone(name: &str) -> bool {
    let (pid, start) = match name.split_once('-') {
        Some((pid, start)) => match (pid.parse::<u32>(), start.parse::<u64>()) {
            (Ok(pid), Ok(start)) => (pid, Some(start)),
            _ => return false,
        },
        None => match name.parse::<u32>() {
            Ok(pid) => (pid, None),
            Err(_) => return false,
        },
    };
    if !running(pid) {
        return true;
    }
    // Running: another process with that pid unless it started when the directory's did.
    match (start, start_time(pid)) {
        (Some(want), Some(now)) => want != now,
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn running(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// macOS: whether any process has `pid` (`kill(pid, 0)`; `EPERM` is another user's process). No start
/// time is read here, so a directory is named `<pid>` and a reused pid keeps it.
#[cfg(target_os = "macos")]
fn running(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return true;
    }
    // SAFETY: signal 0 only checks that the process exists and may be signalled.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Whether a process runs under `pid` (one this worker may not open counts as running).
#[cfg(windows)]
fn running(pid: u32) -> bool {
    use zkminer_prover_protocol::liveness::{liveness, Liveness};
    liveness(pid) != Liveness::Gone
}

/// Where a pid's liveness cannot be read, every directory is kept.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn running(_pid: u32) -> bool {
    true
}

/// When process `pid` started, in clock ticks since boot (`/proc/<pid>/stat` field 22).
#[cfg(target_os = "linux")]
fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name, field 2, is in parentheses and may hold spaces and parentheses itself.
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

/// When process `pid` started: its creation time (100 ns since 1601).
#[cfg(windows)]
fn start_time(pid: u32) -> Option<u64> {
    use zkminer_prover_protocol::liveness::{liveness, Liveness};
    match liveness(pid) {
        Liveness::Running(start) => start,
        Liveness::Gone => None,
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn start_time(_pid: u32) -> Option<u64> {
    None
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// A pid no process has: not a multiple of 4.
    const GONE: u32 = 4_000_000_001;

    fn me() -> (u32, u64) {
        let pid = std::process::id();
        (pid, start_time(pid).expect("this process's start time"))
    }

    /// The directories of workers that are gone (by pid, or by a reused pid's start time) are
    /// removed, and a live worker's, this one's and anything not named by a worker are kept.
    #[test]
    fn the_directories_of_workers_that_are_gone_are_removed() {
        let home = tempfile::tempdir().unwrap();
        let base = home.path().join(BASE);
        let (pid, start) = me();
        let gone = base.join(GONE.to_string());
        let gone_new = base.join(format!("{GONE}-5"));
        // This process's pid, but started at another time: a worker whose pid this one reuses.
        let reused = base.join(format!("{pid}-{}", start + 1));
        let own = base.join(format!("{pid}-{start}"));
        let other = base.join("not-a-pid");
        for d in [&gone, &gone_new, &reused, &own, &other] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("0.bincode"), b"segment").unwrap();
        }
        remove_stale(&base, &dir_name(pid, Some(start)));
        for d in [&gone, &gone_new, &reused] {
            assert!(
                !d.exists(),
                "a dead worker's segments are kept: {}",
                d.display()
            );
        }
        for d in [&own, &other] {
            assert!(d.exists(), "{} was removed", d.display());
        }
    }

    /// A junction a Low worker planted, as a dead worker's directory or inside one, is never
    /// followed: what it points at survives.
    #[test]
    fn a_planted_junction_is_never_followed() {
        let home = tempfile::tempdir().unwrap();
        let base = home.path().join(BASE);
        std::fs::create_dir_all(&base).unwrap();
        let precious = home.path().join("precious");
        std::fs::create_dir_all(&precious).unwrap();
        std::fs::write(precious.join("key"), b"keep me").unwrap();
        // `BASE` is spelled with a `/`, which `mklink` would take for a switch.
        let native = |p: &Path| p.to_string_lossy().replace('/', "\\");
        let junction = |link: &Path| {
            let out = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(native(link))
                .arg(native(&precious))
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
        };
        // As a dead worker's directory itself.
        junction(&base.join(GONE.to_string()));
        // Inside a dead worker's real directory.
        let dead = base.join(format!("{GONE}-7"));
        std::fs::create_dir_all(&dead).unwrap();
        junction(&dead.join("0.bincode"));
        remove_stale(&base, "1-1");
        assert!(!dead.exists(), "the dead worker's directory is kept");
        assert_eq!(std::fs::read(precious.join("key")).unwrap(), b"keep me");
    }

    #[test]
    fn a_workers_directory_is_named_by_its_pid_and_start() {
        let (pid, start) = me();
        assert_eq!(dir_name(pid, start_time(pid)), format!("{pid}-{start}"));
        assert!(!gone(&dir_name(pid, Some(start))));
        assert!(gone(&dir_name(pid, Some(start + 1))));
        assert!(gone(&GONE.to_string()));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// A pid no process has: above the kernel's largest.
    const GONE: u32 = 4_194_304 + 7;

    fn me() -> (u32, u64) {
        let pid = std::process::id();
        (pid, start_time(pid).expect("this process's start time"))
    }

    #[test]
    fn the_directories_of_workers_that_are_gone_are_removed() {
        let home = tempfile::tempdir().unwrap();
        let base = home.path().join(BASE);
        let (pid, start) = me();
        let gone = base.join(GONE.to_string());
        let gone_new = base.join(format!("{GONE}-5"));
        let live = base.join("1");
        let live_new = base.join(format!("1-{}", start_time(1).unwrap_or(0)));
        // This process's pid, but started at another time: a worker whose pid this one reuses.
        let reused = base.join(format!("{pid}-{}", start + 1));
        let own = base.join(format!("{pid}-{start}"));
        let other = base.join("not-a-pid");
        let other_dash = base.join("1-x");
        for d in [
            &gone,
            &gone_new,
            &live,
            &live_new,
            &reused,
            &own,
            &other,
            &other_dash,
        ] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("0.bincode"), b"segment").unwrap();
        }
        remove_stale(&base, &dir_name(pid, Some(start)));
        for d in [&gone, &gone_new, &reused] {
            assert!(
                !d.exists(),
                "a dead worker's segments are kept: {}",
                d.display()
            );
        }
        for d in [&live, &live_new, &own, &other, &other_dash] {
            assert!(d.exists(), "{} was removed", d.display());
        }
    }

    #[test]
    fn the_directory_is_this_users_alone() {
        let home = tempfile::tempdir().unwrap();
        let base = home.path().join(BASE);
        // A loose `.zkminer`, as an older miner may have left it.
        std::fs::create_dir(home.path().join(".zkminer")).unwrap();
        std::fs::set_permissions(
            home.path().join(".zkminer"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let dir = make(home.path(), &base, "42", true).unwrap();
        assert_eq!(dir, base.join("42"));
        for d in [home.path().join(".zkminer"), base.clone(), dir.clone()] {
            assert_eq!(mode(&d), 0o700, "{}", d.display());
        }
        // A link in the way (below `.zkminer`) is refused, and what it points at is left as it is.
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::set_permissions(elsewhere.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), base.join("43")).unwrap();
        assert!(make(home.path(), &base, "43", true).is_err());
        assert_eq!(mode(elsewhere.path()), 0o755);
    }

    /// `prepare` against a throwaway home: the stale directories go (a dead worker's, and one whose
    /// pid this worker reuses, full of segments), and this worker's is made private and empty.
    #[test]
    fn prepare_clears_the_stale_and_makes_its_own() {
        let home = tempfile::tempdir().unwrap();
        let base = home.path().join(BASE);
        let (pid, start) = me();
        let dead = base.join(format!("{GONE}-9"));
        let reused = base.join(format!("{pid}-{}", start + 1));
        // This worker's own name, left full: emptied.
        let own = base.join(dir_name(pid, Some(start)));
        for d in [&dead, &reused, &own] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("4095.bincode"), vec![0u8; 1 << 16]).unwrap();
        }
        let dir = prepare_in(Some(home.path()), None, pid, Some(start)).unwrap();
        assert_eq!(dir, own);
        assert!(
            !dead.exists() && !reused.exists(),
            "a gone worker's segments were kept"
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "not emptied");
        assert_eq!(mode(&dir), 0o700);
        // No home: no directory, and why.
        assert!(prepare_in(None, None, pid, Some(start)).is_err());
    }

    /// An operator's `~/.zkminer` that is a link of this user's to a directory of this user's (on
    /// another disk) is used; the directories below it are made there.
    #[test]
    fn a_linked_zkminer_directory_of_this_users_is_used() {
        let home = tempfile::tempdir().unwrap();
        let disk = tempfile::tempdir().unwrap();
        std::fs::set_permissions(disk.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(disk.path(), home.path().join(".zkminer")).unwrap();
        let (pid, start) = me();
        let dir = prepare_in(Some(home.path()), None, pid, Some(start)).unwrap();
        assert!(disk
            .path()
            .join("risc0-segments")
            .join(dir_name(pid, Some(start)))
            .is_dir());
        assert_eq!(
            mode(disk.path()),
            0o700,
            "the linked directory is made private"
        );
        assert!(std::fs::symlink_metadata(home.path().join(".zkminer"))
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = dir;
    }

    /// With the miner's segment directory named, the worker's directory is below it, beside the
    /// witness proofs' (which it never touches).
    #[test]
    fn with_a_segment_directory_the_workers_is_below_it() {
        let home = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let witness = root.path().join("00112233aabbccdd");
        std::fs::create_dir(&witness).unwrap();
        std::fs::write(witness.join("0.bincode"), b"segment").unwrap();
        let (pid, start) = me();
        let dir = prepare_in(Some(home.path()), Some(root.path()), pid, Some(start)).unwrap();
        assert_eq!(
            dir,
            root.path().join(INLINE).join(dir_name(pid, Some(start)))
        );
        assert!(witness.join("0.bincode").exists());
        assert!(!home.path().join(".zkminer").exists());
        assert!(prepare_in(
            Some(home.path()),
            Some(Path::new("relative")),
            pid,
            Some(start)
        )
        .is_err());
    }

    /// A full disk is told apart by type, never by text: an `ENOSPC` or `EDQUOT` anywhere in the
    /// chain, or the room check's refusal; a guest's message saying so is not.
    #[test]
    fn a_full_disk_is_known_by_its_error_code() {
        let full = anyhow::Error::from(std::io::Error::from_raw_os_error(libc::ENOSPC))
            .context("write segment");
        assert!(storage_exhausted(&full));
        let quota = anyhow::Error::from(std::io::Error::from_raw_os_error(libc::EDQUOT));
        assert!(storage_exhausted(&quota));
        let dir = tempfile::tempdir().unwrap();
        let refused = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            NoRoom {
                dir: dir.path().into(),
                free: 1,
            },
        ));
        assert!(storage_exhausted(&refused));
        let guest = anyhow::anyhow!("Guest panicked: No space left on device (os error 28)");
        assert!(!storage_exhausted(&guest));
        let other = anyhow::Error::from(std::io::Error::from_raw_os_error(libc::EIO));
        assert!(!storage_exhausted(&other));
    }

    /// A proof's executor writes its segments to the directory `spill_here` names, not to the
    /// temporary directory, and they are gone once the proof is over.
    #[test]
    fn a_proofs_segments_go_to_the_segment_directory_and_are_emptied() {
        let home = tempfile::tempdir().unwrap();
        let dir = make(home.path(), &home.path().join(BASE), "7", true).unwrap();
        let mut env = risc0_zkvm::ExecutorEnv::builder();
        env.write_slice(&2000u32.to_le_bytes())
            .segment_limit_po2(16);
        let emptied = spill_to(&mut env, Some(&dir));
        let session =
            risc0_zkvm::ExecutorImpl::from_elf(env.build().unwrap(), crate::FIBONACCI_ELF)
                .unwrap()
                .run()
                .unwrap();
        let written: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
        assert!(
            !written.is_empty() && written.len() == session.segments.len(),
            "{} segment files under {} for {} segments",
            written.len(),
            dir.display(),
            session.segments.len()
        );
        drop(session);
        drop(emptied);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }
}

/// W11-ON37: on macOS the segment directories of workers that are gone are removed by pid.
#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    /// Above macOS's largest pid (99999).
    const GONE: u32 = 4_194_311;

    #[test]
    fn a_gone_workers_directory_is_removed_and_a_live_ones_kept() {
        let home = tempfile::tempdir().unwrap();
        let base = home.path().join(BASE);
        let me = std::process::id();
        assert_eq!(start_time(me), None);
        assert_eq!(dir_name(me, start_time(me)), me.to_string());
        let gone = base.join(GONE.to_string());
        let launchd = base.join("1");
        let other = base.join("not-a-pid");
        for d in [&gone, &launchd, &other] {
            std::fs::create_dir_all(d.join("sub")).unwrap();
            std::fs::write(d.join("0.segment"), b"x").unwrap();
        }
        assert!(running(me) && running(1) && !running(GONE));
        let dir = prepare_in(Some(home.path()), None, me, None).unwrap();
        assert_eq!(dir, base.join(me.to_string()));
        assert!(!gone.exists(), "a gone worker's directory is removed");
        assert!(launchd.exists(), "a running pid's directory is kept");
        assert!(other.exists(), "a directory no worker names is kept");
        assert!(dir.is_dir());
    }
}
