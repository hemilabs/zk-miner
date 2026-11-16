//! One-time setup before a host's first SP1 proof, done when the dispatcher asks
//! (`WorkerCommand::Warmup`) rather than inside a proof's watchdog.
//!
//! - **Groth16 circuit artifacts** (~8 GB, downloaded once per host). The SDK's own installer
//!   checks nothing it downloads (no hash, no HTTP status) and unpacks it with `tar -P`, which
//!   keeps absolute and `..` member names: whoever can serve that archive can write any file this
//!   user can. So this worker installs them itself, before the SDK or the server would: the archive
//!   is checked against its pinned SHA-256 while it downloads, unpacked with the `tar` crate (plain
//!   files and directories only, each inside the staging directory), and published only if its
//!   `groth16_vk.bin` is the one the on-chain verifier was built from (its SHA-256 is that
//!   verifier's `VERIFIER_HASH()`). An install already in place is held to the same verifying key
//!   on every warm-up and replaced if it is not. The SDK's `.complete` marker is written with it,
//!   so neither the SDK nor `sp1-gpu-server` downloads the circuit again over a checked copy.
//!   Installs go into a staging directory under a lock and are renamed into place once complete,
//!   and a torn directory is replaced.
//! - **The stripped circuit**, where this host's `sp1-gpu-server` runs Groth16 in a helper process
//!   (hemilabs `sp1` from v6.8.1, `--sp1-groth16-cpu-helper`). Building it reads the full circuit:
//!   ~26 s and ~14 GiB at peak, once per host. The server takes its own host-wide final-wrap slot
//!   for it. Older servers prove Groth16 in-process and have nothing to build.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use sha2::{Digest, Sha256};
use zkminer_prover_protocol::proc::{self, Outcome};

/// The files a complete Groth16 artifact directory has, all non-empty.
const REQUIRED_FILES: &[&str] = &[
    "groth16_circuit.bin",
    "groth16_pk.bin",
    "groth16_vk.bin",
    "constraints.json",
];
/// What the SDK's installer downloads into the directory before extracting it, and removes after:
/// a directory that still has it was interrupted. This installer downloads under the same name.
const DOWNLOAD_LEFTOVER: &str = "artifacts.tar.gz";
/// The SDK's marker of a finished install (`sp1_prover::build`'s `CIRCUIT_ARTIFACTS_COMPLETE_FILE`,
/// which is private). Without it the SDK and `sp1-gpu-server` download the circuit again.
const SDK_COMPLETE_MARKER: &str = ".complete";

/// The SP1 circuit the pins below are for. Every SDK from 6.1.0 to 6.10.0 emits it.
const PINNED_CIRCUIT_VERSION: &str = "v6.1.0";
/// SHA-256 of `v6.1.0-groth16.tar.gz` (hemiprove-abi/INTERACTION_GUIDE.md, prover checklist step 7).
const GROTH16_ARCHIVE_SHA256: &str =
    "18beebb6cd0cc9b4d4a240ee4f49511da6c2a7e51724bad4232de538a9147810";
/// SHA-256 of the circuit's `groth16_vk.bin`: the on-chain v6.1.0 Groth16 verifier's
/// `VERIFIER_HASH()` (zkminer-chain `deployment::pins::SP1_V6_1_0_GROTH16_VERIFIER_HASH`).
const GROTH16_VK_SHA256: &str = "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696";

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

/// Told of a long step's progress: the step, its bytes so far, its bytes in all.
type Progress<'a> = dyn FnMut(&str, Option<u64>, Option<u64>) + 'a;

/// What the warm-up did, for the dispatcher.
pub(crate) struct WarmupReport {
    pub summary: String,
    /// Whether this host's server proves Groth16 in a helper process.
    pub groth16_helper: bool,
}

/// Installs the Groth16 circuit artifacts if they are not installed, and builds the stripped
/// circuit where the server supports it. `report(step, done bytes, total bytes)` is told before
/// each long step, and every second during a download or an unpack.
pub(crate) fn warm_up(report: &mut Progress<'_>) -> Result<WarmupReport> {
    let dir = sp1_prover::build::groth16_circuit_artifacts_dir()
        .context("cannot locate the Groth16 circuit artifacts directory")?;
    let started = Instant::now();
    let version = sp1_prover::SP1_CIRCUIT_VERSION.trim();
    ensure!(
        version == PINNED_CIRCUIT_VERSION,
        "this SDK's SP1 circuit is {version}, but zkminer pins the Groth16 artifacts of \
         {PINNED_CIRCUIT_VERSION} only — refusing to install unchecked artifacts"
    );
    let installed = ensure_installed(&dir, GROTH16_VK_SHA256, |staging| {
        install(staging, version, report)
    })?;
    mark_complete_for_sdk(&dir)?;
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
        report(
            "Preparing the Groth16 circuit (about 30 s on a first run)",
            None,
            None,
        );
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

/// `~/.sp1/bin/sp1-gpu-server` (`.exe` on Windows), where the SDK runs it from. The home directory
/// is found as the SDK finds it: `HOME`, or on Windows, which does not set it, `USERPROFILE`.
pub(crate) fn server_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|home| !home.is_empty()))
        .ok_or_else(|| anyhow!("$HOME is not set"))?;
    Ok(PathBuf::from(home).join(".sp1/bin").join(format!(
        "{}{}",
        server_name(),
        std::env::consts::EXE_SUFFIX
    )))
}

/// The build of `sp1-gpu-server` this worker's SDK runs: `SP1_GPU_SERVER_NAME` (set by the dispatcher
/// for an AMD or Intel card, hemilabs/sp1 #19), else the SDK's default, the CUDA build.
pub(crate) fn server_name() -> String {
    std::env::var("SP1_GPU_SERVER_NAME")
        .ok()
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .unwrap_or_else(|| "sp1-gpu-server".to_string())
}

/// Whether this worker drives a CUDA card (the default server), rather than the HIP or SYCL build.
pub(crate) fn drives_cuda() -> bool {
    server_name() == "sp1-gpu-server"
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

/// Whether `dir` holds a complete set of Groth16 circuit artifacts whose `groth16_vk.bin` has the
/// SHA-256 `vk_sha256` (lowercase hex).
pub(crate) fn is_complete(dir: &Path, vk_sha256: &str) -> bool {
    !dir.join(DOWNLOAD_LEFTOVER).exists()
        && REQUIRED_FILES.iter().all(|name| {
            fs::metadata(dir.join(name)).is_ok_and(|meta| meta.is_file() && meta.len() > 0)
        })
        && file_sha256(&dir.join("groth16_vk.bin")).is_ok_and(|got| got == vk_sha256)
}

/// The SHA-256 of the file at `path`, lowercase hex.
fn file_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes the SDK's `.complete` marker into the checked install at `dir` if it has none (an install
/// made before this worker wrote it), so the SDK and the server take it as installed.
fn mark_complete_for_sdk(dir: &Path) -> Result<()> {
    let marker = dir.join(SDK_COMPLETE_MARKER);
    if !marker.is_file() {
        fs::write(&marker, []).with_context(|| format!("cannot write {}", marker.display()))?;
    }
    Ok(())
}

/// Makes `dir` a complete artifact directory whose verifying key has the SHA-256 `vk_sha256`,
/// running `install` (which fills the empty directory it is given) if it is not one. One installer
/// at a time per host; see the module docs.
pub(crate) fn ensure_installed(
    dir: &Path,
    vk_sha256: &str,
    install: impl FnOnce(&Path) -> Result<()>,
) -> Result<Installed> {
    let is_complete = |dir: &Path| is_complete(dir, vk_sha256);
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

const DOWNLOADING: &str = "Downloading the Groth16 circuit (first run)";
const UNPACKING: &str = "Unpacking the Groth16 circuit (first run)";
/// How often a long step's progress is reported.
const PROGRESS_EVERY: Duration = Duration::from_secs(1);

/// Runs `step` on a thread of its own, passing `report` what `measure` says every second: the step
/// and its bytes so far. For a download or an unpack whose library reports nothing itself.
fn with_progress<T: Send>(
    report: &mut Progress<'_>,
    measure: impl Fn() -> (&'static str, Option<u64>, Option<u64>),
    step: impl FnOnce() -> T + Send,
) -> T {
    std::thread::scope(|scope| {
        let running = scope.spawn(step);
        let mut reported = Instant::now();
        while !running.is_finished() {
            std::thread::sleep(Duration::from_millis(250));
            if reported.elapsed() >= PROGRESS_EVERY {
                reported = Instant::now();
                let (status, done, total) = measure();
                report(status, done, total);
            }
        }
        running
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

/// Bytes in `path`, a file or a directory tree; what cannot be read counts as nothing.
fn size_on_disk(path: &Path) -> u64 {
    let Ok(meta) = fs::metadata(path) else {
        return 0;
    };
    if !meta.is_dir() {
        return meta.len();
    }
    fs::read_dir(path)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| size_on_disk(&entry.path()))
        .sum()
}

/// Downloads the pinned Groth16 archive of circuit `version` into `staging`, unpacks it there and
/// writes the SDK's marker. `ensure_installed` then checks the verifying key before publishing it.
fn install(staging: &Path, version: &str, report: &mut Progress<'_>) -> Result<()> {
    let url = format!(
        "{}/{version}-groth16.tar.gz",
        sp1_prover::build::CIRCUIT_ARTIFACTS_URL_BASE
    );
    tracing::info!(
        "downloading the Groth16 circuit artifacts (~8 GB) from {url} into {}",
        staging.display()
    );
    let archive = staging.join(DOWNLOAD_LEFTOVER);
    let part = staging.join(format!("{DOWNLOAD_LEFTOVER}.part"));
    let total = AtomicU64::new(0);
    report(DOWNLOADING, Some(0), None);
    with_progress(
        report,
        || {
            let total = total.load(Ordering::Relaxed);
            (
                DOWNLOADING,
                Some(size_on_disk(&part)),
                (total > 0).then_some(total),
            )
        },
        || download(&url, GROTH16_ARCHIVE_SHA256, &part, &archive, &total),
    )?;
    report(UNPACKING, Some(0), None);
    let unpacked = with_progress(
        report,
        || {
            let unpacked = size_on_disk(staging).saturating_sub(size_on_disk(&archive));
            (UNPACKING, Some(unpacked), None)
        },
        || unpack(&archive, staging),
    );
    let _ = fs::remove_file(&archive);
    unpacked?;
    fs::write(staging.join(SDK_COMPLETE_MARKER), [])
        .with_context(|| format!("cannot write the marker in {}", staging.display()))?;
    Ok(())
}

/// Downloads `url` to `part`, checking on the way that its SHA-256 is `sha256` (lowercase hex), and
/// renames it to `to` only if it is. `total` is set to the size the server gives.
fn download(url: &str, sha256: &str, part: &Path, to: &Path, total: &AtomicU64) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(None)
        .build()
        .context("cannot build the HTTP client")?;
    let mut response = client
        .get(url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .with_context(|| format!("cannot download {url}"))?;
    if let Some(bytes) = response.content_length() {
        total.store(bytes, Ordering::Relaxed);
    }
    let fetched = (|| -> Result<(String, u64)> {
        let mut out =
            File::create(part).with_context(|| format!("cannot write {}", part.display()))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut bytes = 0u64;
        loop {
            let n = match response.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("the Groth16 circuit download was cut short"),
            };
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            bytes += n as u64;
        }
        out.sync_all()?;
        Ok((hex(&hasher.finalize()), bytes))
    })();
    let (got, bytes) = match fetched {
        Ok(fetched) => fetched,
        Err(e) => {
            let _ = fs::remove_file(part);
            return Err(e);
        }
    };
    if got != sha256 {
        let _ = fs::remove_file(part);
        bail!(
            "{url} ({bytes} bytes) has SHA-256 {got}, not the pinned {sha256} — not installing it"
        );
    }
    fs::rename(part, to).with_context(|| format!("cannot move it to {}", to.display()))?;
    Ok(())
}

/// Unpacks the gzipped tarball `archive` into `into`: plain files and directories only, each of
/// them inside `into` (the `tar` crate refuses absolute and `..` member paths). Anything else (a
/// link, a device) fails the install.
fn unpack(archive: &Path, into: &Path) -> Result<()> {
    let file = File::open(archive).with_context(|| format!("cannot open {}", archive.display()))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(BufReader::new(file)));
    tar.set_preserve_permissions(false);
    tar.set_unpack_xattrs(false);
    for entry in tar.entries().context("cannot read the Groth16 archive")? {
        let mut entry = entry.context("cannot read the Groth16 archive")?;
        let kind = entry.header().entry_type();
        let path = entry
            .path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unreadable name>".to_string());
        ensure!(
            kind.is_file() || kind.is_dir(),
            "the Groth16 archive has a {kind:?} member {path} — refusing it"
        );
        ensure!(
            entry
                .unpack_in(into)
                .with_context(|| format!("cannot unpack {path}"))?,
            "the Groth16 archive member {path} is outside the install directory — refusing it"
        );
    }
    Ok(())
}

/// An exclusive lock on `path`, held until the file is dropped: `flock` on Unix, `LockFileEx` on
/// Windows (std's `File::lock`).
fn lock(path: &Path) -> Result<File> {
    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    #[cfg(unix)]
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
    #[cfg(windows)]
    {
        file.lock()
            .with_context(|| format!("cannot lock {}", path.display()))?;
        Ok(file)
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

    /// The SHA-256 of the verifying key `fill` writes.
    fn vk() -> String {
        hex(&Sha256::digest(b"x"))
    }

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
        let outcome = ensure_installed(&dir, &vk(), |_| {
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
        assert!(!is_complete(&dir, &vk()));
        assert_eq!(
            ensure_installed(&dir, &vk(), fill).unwrap(),
            Installed::Downloaded
        );
        assert!(is_complete(&dir, &vk()));
        assert!(!dir.join(DOWNLOAD_LEFTOVER).exists());

        // Extracted but cut short: an empty file counts as missing.
        fs::write(dir.join("groth16_pk.bin"), b"").unwrap();
        assert!(!is_complete(&dir, &vk()));
        assert_eq!(
            ensure_installed(&dir, &vk(), fill).unwrap(),
            Installed::Downloaded
        );
    }

    /// A failed download publishes nothing and leaves no staging directory behind; staging left by
    /// a dead installer is swept by the next one.
    #[test]
    fn a_failed_download_leaves_nothing() {
        let root = TestDir::new();
        let dir = root.path().join("v6.0.0");
        let stale = root.path().join(".v6.0.0.staging.999999");
        fs::create_dir(&stale).unwrap();
        let failed = ensure_installed(&dir, &vk(), |staging| {
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
        let short = ensure_installed(&dir, &vk(), |staging| {
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
                        ensure_installed(&dir, &vk(), |staging| {
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
        assert!(is_complete(&dir, &vk()));
    }

    /// An install whose verifying key is not the pinned one (another circuit, or a tampered copy) is
    /// not complete, and is replaced.
    #[test]
    fn an_install_with_another_verifying_key_is_replaced() {
        let root = TestDir::new();
        let dir = root.path().join("v6.1.0");
        fs::create_dir(&dir).unwrap();
        fill(&dir).unwrap();
        fs::write(dir.join("groth16_vk.bin"), b"another key").unwrap();
        assert!(!is_complete(&dir, &vk()));
        assert_eq!(
            ensure_installed(&dir, &vk(), fill).unwrap(),
            Installed::Downloaded
        );
        assert!(is_complete(&dir, &vk()));

        // And an install whose key is wrong is not published.
        fs::write(dir.join("groth16_vk.bin"), b"another key").unwrap();
        let wrong = ensure_installed(&dir, &vk(), |staging| {
            fill(staging)?;
            Ok(fs::write(staging.join("groth16_vk.bin"), b"still another")?)
        });
        assert!(format!("{:#}", wrong.unwrap_err()).contains("incomplete"));
        assert!(!dir.exists());
    }

    #[test]
    fn the_sdk_marker_is_written_once() {
        let root = TestDir::new();
        mark_complete_for_sdk(root.path()).unwrap();
        assert!(root.path().join(SDK_COMPLETE_MARKER).is_file());
        mark_complete_for_sdk(root.path()).unwrap();
    }

    /// A gzipped tarball of `members`, written into `dir`: (name, kind, contents). A name is
    /// written into the header as given, `..` and all, as a hostile archive would have it.
    fn tarball(dir: &Path, members: &[(&str, tar::EntryType, &[u8])]) -> PathBuf {
        let path = dir.join("test.tar.gz");
        let gz = flate2::write::GzEncoder::new(File::create(&path).unwrap(), Default::default());
        let mut builder = tar::Builder::new(gz);
        for (name, kind, data) in members {
            let mut header = tar::Header::new_gnu();
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_entry_type(*kind);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            if kind.is_symlink() {
                header.set_link_name("/etc/passwd").unwrap();
            }
            header.set_cksum();
            builder.append(&header, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        path
    }

    #[test]
    fn unpack_takes_plain_members_inside_the_directory_only() {
        let root = TestDir::new();
        let into = root.path().join("into");
        fs::create_dir(&into).unwrap();
        let ok = tarball(
            root.path(),
            &[
                ("./", tar::EntryType::Directory, b""),
                ("./groth16_vk.bin", tar::EntryType::Regular, b"key"),
            ],
        );
        unpack(&ok, &into).unwrap();
        assert_eq!(fs::read(into.join("groth16_vk.bin")).unwrap(), b"key");

        let escaping = tarball(
            root.path(),
            &[("../escaped.bin", tar::EntryType::Regular, b"x")],
        );
        assert!(unpack(&escaping, &into).is_err());
        assert!(!root.path().join("escaped.bin").exists());

        let linked = tarball(root.path(), &[("link", tar::EntryType::Symlink, b"")]);
        assert!(format!("{:#}", unpack(&linked, &into).unwrap_err()).contains("refusing"));
        assert!(fs::symlink_metadata(into.join("link")).is_err());
    }

    /// The real install: downloads the pinned archive (6.2 GB), checks it, unpacks it (8.4 GB) into a
    /// scratch directory and checks the verifying key. Run by hand:
    /// `cargo test -p zkminer-prove-sp1 the_pinned_archive_installs -- --ignored`.
    #[test]
    #[ignore = "downloads 6.2 GB from SP1's artifact server"]
    fn the_pinned_archive_installs() {
        let root = TestDir::new();
        let dir = root.path().join(PINNED_CIRCUIT_VERSION);
        let installed = ensure_installed(&dir, GROTH16_VK_SHA256, |staging| {
            install(staging, PINNED_CIRCUIT_VERSION, &mut |_, _, _| {})
        })
        .unwrap();
        assert_eq!(installed, Installed::Downloaded);
        assert!(is_complete(&dir, GROTH16_VK_SHA256));
        assert!(dir.join(SDK_COMPLETE_MARKER).is_file());
    }

    /// The pins are for the circuit this SDK emits.
    #[test]
    fn the_pins_are_the_circuits() {
        assert_eq!(
            sp1_prover::SP1_CIRCUIT_VERSION.trim(),
            PINNED_CIRCUIT_VERSION
        );
        assert_eq!(GROTH16_ARCHIVE_SHA256.len(), 64);
        assert_eq!(GROTH16_VK_SHA256.len(), 64);
    }

    /// The probe tells a helper-hosting server from one that rejects the argument, as the pinned
    /// v6.0.2 server does, without starting either as a server.
    #[cfg(target_os = "linux")]
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
