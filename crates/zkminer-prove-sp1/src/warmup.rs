//! One-time setup before a host's first SP1 proof, done when the dispatcher asks
//! (`WorkerCommand::Warmup`) rather than inside a proof's watchdog.
//!
//! - **Groth16 circuit artifacts** (~8 GB, downloaded once per host). The SDK's own installer
//!   creates the version directory first, then downloads and extracts into it, and treats any
//!   directory it finds as installed. A download cut short, as a first proof's watchdog cuts one
//!   on a fresh host, therefore leaves a torn directory that every later Groth16 proof fails on
//!   until someone deletes it. Here the artifacts are installed into a staging directory under a
//!   lock and renamed into place once complete, and a torn directory is replaced.
//! - **The stripped circuit**, where this host's `sp1-gpu-server` runs Groth16 in a helper process
//!   (hemilabs `sp1` from v6.8.1, `--sp1-groth16-cpu-helper`). Building it reads the full circuit:
//!   ~26 s and ~14 GiB at peak, once per host. The server takes its own host-wide final-wrap slot
//!   for it. Older servers prove Groth16 in-process and have nothing to build.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use zkminer_prover_protocol::proc::{self, Outcome};

/// The files a complete Groth16 artifact directory has, all non-empty.
const REQUIRED_FILES: &[&str] = &[
    "groth16_circuit.bin",
    "groth16_pk.bin",
    "groth16_vk.bin",
    "constraints.json",
];
/// What the SDK's installer downloads into the directory before extracting it, and removes after:
/// a directory that still has it was interrupted.
const DOWNLOAD_LEFTOVER: &str = "artifacts.tar.gz";

/// The argument that makes a hemilabs `sp1-gpu-server` act as its Groth16 CPU helper.
const CPU_HELPER_ARG: &str = "--sp1-groth16-cpu-helper";
/// What the helper's `--help` says about itself.
const CPU_HELPER_ABOUT: &str = "Runs gnark's CPU Groth16 prover";
/// The `--help` probe execs a 125 MB binary that resolves the CUDA runtime, like `--version`.
const HELPER_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Building the stripped circuit takes ~26 s; leave room for a loaded host and for waiting on the
/// host-wide final-wrap slot behind a proof.
const PREPARE_TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// Enough of the helper's stderr to say why it failed.
const STDERR_CAP: u64 = 64 * 1024;

/// What the warm-up did, for the dispatcher.
pub(crate) struct WarmupReport {
    pub summary: String,
    /// Whether this host's server proves Groth16 in a helper process.
    pub groth16_helper: bool,
}

/// Installs the Groth16 circuit artifacts if they are not installed, and builds the stripped
/// circuit where the server supports it.
pub(crate) fn warm_up() -> Result<WarmupReport> {
    let dir = sp1_sdk::install::groth16_circuit_artifacts_dir()
        .context("cannot locate the Groth16 circuit artifacts directory")?;
    let started = Instant::now();
    let installed = ensure_installed(&dir, download)?;
    let mut summary = format!(
        "Groth16 circuit artifacts {} ({}, {:.0?})",
        installed.describe(),
        dir.display(),
        started.elapsed()
    );

    let server = server_path()?;
    let groth16_helper = server.exists() && server_hosts_groth16_helper(&server);
    if groth16_helper {
        let started = Instant::now();
        prepare_stripped_circuit(&server, &dir)?;
        summary.push_str(&format!(
            "; stripped circuit ready ({:.0?})",
            started.elapsed()
        ));
    } else {
        summary.push_str("; this sp1-gpu-server proves Groth16 in-process");
    }
    Ok(WarmupReport {
        summary,
        groth16_helper,
    })
}

/// `~/.sp1/bin/sp1-gpu-server`, where the SDK runs it from.
pub(crate) fn server_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| anyhow!("$HOME is not set"))?;
    Ok(PathBuf::from(home).join(".sp1/bin/sp1-gpu-server"))
}

/// How the artifacts came to be in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Installed {
    AlreadyPresent,
    /// Another worker on this host installed them while this one waited for the lock.
    ByAnother,
    Downloaded,
}

impl Installed {
    fn describe(self) -> &'static str {
        match self {
            Installed::AlreadyPresent => "already installed",
            Installed::ByAnother => "installed by another worker",
            Installed::Downloaded => "downloaded",
        }
    }
}

/// Whether `dir` holds a complete set of Groth16 circuit artifacts.
pub(crate) fn is_complete(dir: &Path) -> bool {
    !dir.join(DOWNLOAD_LEFTOVER).exists()
        && REQUIRED_FILES.iter().all(|name| {
            fs::metadata(dir.join(name)).is_ok_and(|meta| meta.is_file() && meta.len() > 0)
        })
}

/// Makes `dir` a complete artifact directory, running `install` (which fills the empty directory
/// it is given) if it is not one. One installer at a time per host; see the module docs.
pub(crate) fn ensure_installed(
    dir: &Path,
    install: impl FnOnce(&Path) -> Result<()>,
) -> Result<Installed> {
    if is_complete(dir) {
        return Ok(Installed::AlreadyPresent);
    }
    let parent = dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("{} has no parent directory", dir.display()))?;
    let name = dir
        .file_name()
        .ok_or_else(|| anyhow!("{} has no name", dir.display()))?
        .to_string_lossy()
        .into_owned();
    fs::create_dir_all(parent).with_context(|| format!("cannot create {}", parent.display()))?;
    let _lock = lock(&parent.join(format!(".{name}.zkminer-install.lock")))?;
    if is_complete(dir) {
        return Ok(Installed::ByAnother);
    }

    // With the lock held nothing else is installing, so whatever is here is debris: a torn
    // install at `dir`, and staging directories of an installer that died.
    if dir.exists() {
        tracing::warn!("{} is an incomplete install; replacing it", dir.display());
        fs::remove_dir_all(dir).with_context(|| format!("cannot remove {}", dir.display()))?;
    }
    let staging_prefix = format!(".{name}.staging.");
    for entry in fs::read_dir(parent)?.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(&staging_prefix)
        {
            let _ = fs::remove_dir_all(entry.path());
        }
    }

    let staging = parent.join(format!("{staging_prefix}{}", std::process::id()));
    fs::create_dir(&staging).with_context(|| format!("cannot create {}", staging.display()))?;
    let installed = install(&staging).and_then(|()| {
        if is_complete(&staging) {
            Ok(())
        } else {
            Err(anyhow!(
                "the download into {} is incomplete",
                staging.display()
            ))
        }
    });
    if let Err(e) = installed {
        let _ = fs::remove_dir_all(&staging);
        return Err(e);
    }
    if let Err(e) = fs::rename(&staging, dir) {
        let _ = fs::remove_dir_all(&staging);
        // Something that does not take this lock (an SDK installing during a proof) got there
        // first. Fine if what it left is complete.
        if is_complete(dir) {
            return Ok(Installed::ByAnother);
        }
        return Err(e).with_context(|| format!("cannot move the artifacts to {}", dir.display()));
    }
    Ok(Installed::Downloaded)
}

/// The SDK's download and extraction, into `staging`.
fn download(staging: &Path) -> Result<()> {
    tracing::info!(
        "downloading the Groth16 circuit artifacts (~8 GB) into {}",
        staging.display()
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start a runtime for the download")?;
    runtime.block_on(sp1_sdk::install::install_circuit_artifacts(
        staging.to_path_buf(),
        "groth16",
    ))
}

/// An exclusive `flock` on `path`, held until the file is dropped.
fn lock(path: &Path) -> Result<File> {
    use std::os::unix::io::AsRawFd;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    loop {
        // SAFETY: flock on a descriptor we own.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(file);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err).with_context(|| format!("cannot lock {}", path.display()));
        }
    }
}

/// Whether `server` can act as its own Groth16 CPU helper. An older server rejects the argument
/// (clap exits 2 at once), so asking is safe.
pub(crate) fn server_hosts_groth16_helper(server: &Path) -> bool {
    let (outcome, stdout) = proc::output_with_timeout_capturing_stdout(
        Command::new(server).args([CPU_HELPER_ARG, "--help"]),
        HELPER_PROBE_TIMEOUT,
        STDERR_CAP,
    );
    matches!(outcome, Outcome::Ran { success: true, .. }) && stdout.contains(CPU_HELPER_ABOUT)
}

/// Has `server` build the stripped circuit for the artifacts in `build_dir`.
fn prepare_stripped_circuit(server: &Path, build_dir: &Path) -> Result<()> {
    tracing::info!("building the stripped Groth16 circuit (~26 s, ~14 GiB at peak)");
    let mut cmd = Command::new(server);
    cmd.args([CPU_HELPER_ARG, "--prepare", "--build-dir"])
        .arg(build_dir);
    match proc::output_with_timeout(&mut cmd, PREPARE_TIMEOUT, STDERR_CAP) {
        Outcome::Ran { success: true, .. } => Ok(()),
        Outcome::Ran {
            success: false,
            stderr,
        } => {
            bail!("building the stripped circuit failed: {}", stderr.trim())
        }
        other => bail!("building the stripped circuit failed: {}", other.describe()),
    }
}

/// A directory for one test, removed when dropped.
#[cfg(test)]
pub(crate) struct TestDir(PathBuf);

#[cfg(test)]
impl TestDir {
    pub(crate) fn new() -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "zkminer-prove-sp1-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

#[cfg(test)]
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn fill(dir: &Path) -> Result<()> {
        for name in REQUIRED_FILES {
            fs::write(dir.join(name), b"x")?;
        }
        Ok(())
    }

    #[test]
    fn a_complete_install_is_left_alone() {
        let root = TestDir::new();
        let dir = root.path().join("v6.0.0");
        fs::create_dir(&dir).unwrap();
        fill(&dir).unwrap();
        let ran = Cell::new(false);
        let outcome = ensure_installed(&dir, |_| {
            ran.set(true);
            Ok(())
        });
        assert_eq!(outcome.unwrap(), Installed::AlreadyPresent);
        assert!(!ran.get());
    }

    /// What the SDK's installer leaves when it is killed mid-download: the directory, part of a
    /// tarball, nothing extracted. It must be replaced, not trusted.
    #[test]
    fn a_torn_install_is_replaced() {
        let root = TestDir::new();
        let dir = root.path().join("v6.0.0");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join(DOWNLOAD_LEFTOVER), b"partial").unwrap();
        assert!(!is_complete(&dir));
        assert_eq!(ensure_installed(&dir, fill).unwrap(), Installed::Downloaded);
        assert!(is_complete(&dir));
        assert!(!dir.join(DOWNLOAD_LEFTOVER).exists());

        // Extracted but cut short: an empty file counts as missing.
        fs::write(dir.join("groth16_pk.bin"), b"").unwrap();
        assert!(!is_complete(&dir));
        assert_eq!(ensure_installed(&dir, fill).unwrap(), Installed::Downloaded);
    }

    /// A failed download publishes nothing and leaves no staging directory behind; staging left by
    /// a dead installer is swept by the next one.
    #[test]
    fn a_failed_download_leaves_nothing() {
        let root = TestDir::new();
        let dir = root.path().join("v6.0.0");
        let stale = root.path().join(".v6.0.0.staging.999999");
        fs::create_dir(&stale).unwrap();
        let failed = ensure_installed(&dir, |staging| {
            fs::write(staging.join("groth16_pk.bin"), b"half")?;
            Err(anyhow!("connection reset"))
        });
        assert!(format!("{:#}", failed.unwrap_err()).contains("connection reset"));
        assert!(!dir.exists());
        let leftovers: Vec<_> = fs::read_dir(root.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains("staging"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");

        // And a download that "succeeds" without every file is not published either.
        let short = ensure_installed(&dir, |staging| {
            Ok(fs::write(staging.join("groth16_vk.bin"), b"x")?)
        });
        assert!(format!("{:#}", short.unwrap_err()).contains("incomplete"));
        assert!(!dir.exists());
    }

    /// Two workers (one per card) warming at once: one downloads, the other waits and finds it done.
    #[test]
    fn concurrent_installers_download_once() {
        let root = TestDir::new();
        let dir = root.path().join("v6.0.0");
        let downloads = std::sync::atomic::AtomicUsize::new(0);
        let outcomes: Vec<Installed> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..3)
                .map(|_| {
                    scope.spawn(|| {
                        ensure_installed(&dir, |staging| {
                            downloads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(200));
                            fill(staging)
                        })
                        .unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(downloads.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == Installed::Downloaded)
                .count(),
            1
        );
        assert!(is_complete(&dir));
    }

    /// The probe tells a helper-hosting server from one that rejects the argument, as the pinned
    /// v6.0.2 server does, without starting either as a server.
    #[test]
    fn the_helper_probe_reads_the_servers_answer() {
        // Other tests in this binary briefly point PATH elsewhere, and the scripts are written with
        // `cat` and `chmod` found on it.
        let _env = crate::usability_tests::env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = TestDir::new();
        // Written by a child process: a file this multi-threaded test process held open for
        // writing could be inherited by a fork elsewhere, and exec'ing it would then fail
        // ("text file busy").
        let script = |name: &str, body: &str| {
            let path = root.path().join(name);
            let mut writer = Command::new("/bin/sh")
                .args(["-c", r#"cat > "$1" && chmod 755 "$1""#, "sh"])
                .arg(&path)
                .stdin(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            use std::io::Write as _;
            let mut stdin = writer.stdin.take().unwrap();
            stdin
                .write_all(format!("#!/bin/sh\n{body}\n").as_bytes())
                .unwrap();
            drop(stdin);
            let written = writer.wait_with_output().unwrap();
            assert!(
                written.status.success(),
                "writing {}: {written:?}",
                path.display()
            );
            path
        };
        let new = script(
            "new",
            &format!(
                r#"[ "$1" = {CPU_HELPER_ARG} ] && [ "$2" = --help ] && echo "{CPU_HELPER_ABOUT} for one proof""#
            ),
        );
        let old = script(
            "old",
            "echo \"error: unexpected argument '$1' found\" >&2; exit 2",
        );
        assert!(server_hosts_groth16_helper(&new));
        assert!(!server_hosts_groth16_helper(&old));
        assert!(!server_hosts_groth16_helper(&root.path().join("missing")));
    }
}
