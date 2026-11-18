//! Where a proof's segments go: a directory of this worker's own on disk, not the temporary
//! directory.
//!
//! risc0's prover first executes the guest, writing every segment to a file, and then proves them.
//! Left to itself it writes them to a temporary directory under `TMPDIR`, which on most hosts is a
//! RAM-backed tmpfs: a long proof stages gigabytes there, which the host's memory admission does
//! not count. So every proof writes its segments to `~/.zkminer/risc0-segments/<pid>` ([`prepare`],
//! made at startup; the confinement lets the worker write it), and the directory is emptied after
//! each proof ([`Emptied`]). A worker that was killed cannot empty its own: the next worker to start
//! removes the directories of workers that are gone.
//!
//! A witness proof writes its segments to the slot's segment directory instead (`witness.rs`).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The directory under the home directory that holds each worker's segment directory.
const BASE: &str = ".zkminer/risc0-segments";

/// This worker's segment directory, once [`prepare`] made it.
static DIR: OnceLock<PathBuf> = OnceLock::new();

/// At startup, before the confinement (which must be told of the directory) and while the process
/// has one thread: removes the segment directories of workers that are gone, then makes this
/// worker's. Without one (no home directory, or a directory on the way that is not this user's
/// alone), segments go where risc0 puts them by default, and this says so on stderr (logging is not
/// set up yet).
pub fn prepare() {
    let Some(home) = dirs::home_dir() else {
        eprintln!(
            "no home directory for risc0's segment files: they go to the temporary directory"
        );
        return;
    };
    let base = home.join(BASE);
    remove_stale(&base);
    match make(&home, &base, std::process::id()) {
        Ok(dir) => {
            let _ = DIR.set(dir);
        }
        Err(e) => eprintln!("risc0's segment files go to the temporary directory: {e}"),
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

/// Makes `base/<pid>`, and every directory from `home` down to it, a directory of this user's alone
/// (mode 0700, no link): a segment holds the guest's input and memory, which no other user may read
/// or replace. Its path.
fn make(home: &Path, base: &Path, pid: u32) -> Result<PathBuf, String> {
    let dir = base.join(pid.to_string());
    let mut at = home.to_path_buf();
    for part in dir.strip_prefix(home).map_err(|e| e.to_string())? {
        at.push(part);
        private_dir(&at)?;
    }
    Ok(dir)
}

/// Makes `dir` with mode 0700 if it is missing, or checks that it is a directory (not a link) of
/// this user's and makes it 0700.
#[cfg(unix)]
fn private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    }
    let meta = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != me {
        return Err(format!(
            "{} is not a directory of this user's",
            dir.display()
        ));
    }
    if meta.mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        // Again, not through a link: what was changed must be what was checked.
        let meta = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if !meta.is_dir() || meta.mode() & 0o077 != 0 {
            return Err(format!("{} could not be made private", dir.display()));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

/// Removes `base/<pid>` for every `<pid>` that is not running (and is not this process): a worker
/// that was killed left its segments there. A directory whose pid has been reused is kept until
/// that process is gone too.
fn remove_stale(base: &Path) {
    let me = std::process::id();
    for entry in std::fs::read_dir(base).into_iter().flatten().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == me || running(pid) {
            continue;
        }
        // `file_type` does not follow a link: only a real directory is removed.
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

#[cfg(target_os = "linux")]
fn running(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Where a pid's liveness cannot be read, every directory is kept.
#[cfg(not(target_os = "linux"))]
fn running(_pid: u32) -> bool {
    true
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

    #[test]
    fn the_directories_of_workers_that_are_gone_are_removed() {
        let home = tempfile::tempdir().unwrap();
        let base = home.path().join(BASE);
        let gone = base.join(GONE.to_string());
        let live = base.join("1");
        let own = base.join(std::process::id().to_string());
        let other = base.join("not-a-pid");
        for d in [&gone, &live, &own, &other] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("0.bincode"), b"segment").unwrap();
        }
        remove_stale(&base);
        assert!(!gone.exists(), "a dead worker's segments are kept");
        assert!(live.exists() && own.exists() && other.exists());
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
        let dir = make(home.path(), &base, 42).unwrap();
        assert_eq!(dir, base.join("42"));
        for d in [home.path().join(".zkminer"), base.clone(), dir.clone()] {
            assert_eq!(mode(&d), 0o700, "{}", d.display());
        }
        // A link in the way is refused, and what it points at is left as it is.
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::set_permissions(elsewhere.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), base.join("43")).unwrap();
        assert!(make(home.path(), &base, 43).is_err());
        assert_eq!(mode(elsewhere.path()), 0o755);
    }

    /// A proof's executor writes its segments to the directory `spill_here` names, not to the
    /// temporary directory, and they are gone once the proof is over.
    #[test]
    fn a_proofs_segments_go_to_the_segment_directory_and_are_emptied() {
        let home = tempfile::tempdir().unwrap();
        let dir = make(home.path(), &home.path().join(BASE), 7).unwrap();
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
