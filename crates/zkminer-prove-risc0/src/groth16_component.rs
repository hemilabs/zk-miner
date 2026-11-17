//! RISC Zero's `risc0-groth16` component: the Groth16 proving key and witness generator (~5.8 GB)
//! that the final wrap of every proof needs. risc0 looks for it (`risc0_groth16::prove::component`)
//! in `RISC0_GROTH16_DIR`, else in rzup's install, `~/.risc0/extensions/v0.2.0-risc0-groth16`
//! (`$RISC0_HOME` in place of `~/.risc0`), and fails every proof without it.
//!
//! A host with only its GPU driver has no `rzup` to install it with, so the worker installs it
//! itself, in its one-time setup (`WorkerCommand::Warmup`, which the miner runs before claiming any
//! risc0 job): the archive rzup itself downloads, from RISC Zero's artifact store, where it is named
//! by its SHA-256, which is pinned here and checked; unpacked beside the final directory and renamed
//! into place, so no proof ever sees half of it. A lock file (rzup's own) keeps two workers from
//! installing it at once.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};

/// The version risc0-groth16 3.1 asks for: 0.2.0, the ceremony of the v3.1.0 Groth16 fix
/// (GHSA-g6qg-9j8p-7j87). Proofs from the 0.1.0 key do not verify against 3.1's verifier.
const VERSION: &str = "0.2.0";
/// The archive of that version, as rzup's distribution manifest lists it
/// (`rzup/components/risc0-groth16/distribution_manifest.json`).
const ARCHIVE_SHA256: &str = "173354ab0bd18417ba1080a0094b4398098a62b9c7460ba1dc34988b2baa57e5";
const ARCHIVE_URL: &str = "https://risc0-artifacts.s3.us-west-2.amazonaws.com/rzup/components/\
                           risc0-groth16/sha256/173354ab0bd18417ba1080a0094b4398098a62b9c7460ba1dc34988b2baa57e5";
/// The files a complete install holds.
const FILES: [&str; 4] = [
    "stark_verify_graph.bin",
    "stark_verify_final.zkey",
    "fuzzed_msm_results.bin",
    "preprocessed_coeffs.bin",
];

/// Makes sure the component is where risc0 will look for it, installing it if it is not. What was
/// done, for the log. `report(step, done bytes, total bytes)` is told before each long step, and every
/// second during the download and the unpack.
pub fn ensure_installed(report: &mut dyn FnMut(&str, Option<u64>, Option<u64>)) -> Result<String> {
    if let Some(dir) = std::env::var_os("RISC0_GROTH16_DIR") {
        let dir = PathBuf::from(dir);
        ensure!(
            complete(&dir),
            "RISC0_GROTH16_DIR is {} and does not hold the risc0-groth16 component",
            dir.display()
        );
        return Ok(format!(
            "risc0-groth16 component in {} (RISC0_GROTH16_DIR)",
            dir.display()
        ));
    }
    let home = risc0_home()?;
    let dir = home
        .join("extensions")
        .join(format!("v{VERSION}-risc0-groth16"));
    if complete(&dir) {
        return Ok(format!("risc0-groth16 component in {}", dir.display()));
    }
    let tmp = home.join("tmp");
    fs::create_dir_all(&tmp).with_context(|| format!("cannot create {}", tmp.display()))?;
    let lock = File::create(tmp.join(format!(".risc0-groth16-{VERSION}.lock")))?;
    lock.lock()
        .context("cannot lock the risc0-groth16 install")?;
    if complete(&dir) {
        return Ok(format!(
            "risc0-groth16 component in {} (installed meanwhile)",
            dir.display()
        ));
    }

    let start = Instant::now();
    tracing::info!(
        "installing the risc0-groth16 component (a 2.4 GB download, 5.8 GB installed) into {}",
        dir.display()
    );
    let archive = tmp.join(format!("risc0-groth16-{VERSION}.tar.xz"));
    let archive_bytes = AtomicU64::new(0);
    report(DOWNLOADING, Some(0), None);
    let part = archive.with_extension("xz.part");
    with_progress(
        report,
        || {
            let total = archive_bytes.load(Ordering::Relaxed);
            (
                DOWNLOADING,
                Some(size_on_disk(&part)),
                (total > 0).then_some(total),
            )
        },
        || download(&archive, &archive_bytes),
    )?;
    report(UNPACKING, Some(0), Some(UNPACKED_BYTES));
    let staging = tmp.join(format!("risc0-groth16-{VERSION}.{}", std::process::id()));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)?;
    let unpacked = with_progress(
        report,
        || {
            (
                UNPACKING,
                Some(size_on_disk(&staging)),
                Some(UNPACKED_BYTES),
            )
        },
        || {
            File::open(&archive)
                .map(BufReader::new)
                .map(liblzma::bufread::XzDecoder::new_parallel)
                .map(tar::Archive::new)
                .and_then(|mut a| a.unpack(&staging))
        },
    );
    let _ = fs::remove_file(&archive);
    unpacked.with_context(|| {
        format!(
            "cannot unpack the risc0-groth16 archive into {}",
            staging.display()
        )
    })?;
    ensure!(
        complete(&staging),
        "the risc0-groth16 archive does not hold {}",
        FILES.join(", ")
    );
    fs::create_dir_all(dir.parent().expect("a component directory has a parent"))?;
    if dir.exists() {
        fs::remove_dir_all(&dir).with_context(|| format!("cannot replace {}", dir.display()))?;
    }
    fs::rename(&staging, &dir).with_context(|| format!("cannot move it to {}", dir.display()))?;
    Ok(format!(
        "installed the risc0-groth16 component in {} in {:.0} s",
        dir.display(),
        start.elapsed().as_secs_f64()
    ))
}

/// Whether `dir` holds every file of the component.
fn complete(dir: &Path) -> bool {
    FILES
        .iter()
        .all(|f| fs::metadata(dir.join(f)).is_ok_and(|m| m.is_file() && m.len() > 0))
}

/// rzup's home: `$RISC0_HOME`, else `~/.risc0`.
fn risc0_home() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("RISC0_HOME") {
        return Ok(home.into());
    }
    dirs::home_dir()
        .map(|h| h.join(".risc0"))
        .context("cannot locate the risc0-groth16 component: no home directory")
}

/// Downloads the archive to `to`, checking its SHA-256 on the way.
/// `total` is set to the archive's size once the server says it.
fn download(to: &Path, total: &AtomicU64) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(None)
        .build()?;
    let mut response = client
        .get(ARCHIVE_URL)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .with_context(|| format!("cannot download {ARCHIVE_URL}"))?;
    if let Some(bytes) = response.content_length() {
        total.store(bytes, Ordering::Relaxed);
    }
    let part = to.with_extension("xz.part");
    let mut out =
        File::create(&part).with_context(|| format!("cannot write {}", part.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = match response.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let _ = fs::remove_file(&part);
                return Err(e).context("the risc0-groth16 download was cut short");
            }
        };
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])?;
        total += n as u64;
    }
    out.sync_all()?;
    let got = hex(&hasher.finalize());
    if got != ARCHIVE_SHA256 {
        let _ = fs::remove_file(&part);
        bail!("the risc0-groth16 archive ({total} bytes) has SHA-256 {got}, not {ARCHIVE_SHA256}");
    }
    fs::rename(&part, to)?;
    Ok(())
}

const DOWNLOADING: &str = "Downloading the Groth16 files (first run)";
const UNPACKING: &str = "Unpacking the Groth16 files (first run)";
/// What the pinned component unpacks to, for the unpack's progress bar.
const UNPACKED_BYTES: u64 = 5_812_781_917;
/// How often a long step's progress is reported.
const PROGRESS_EVERY: Duration = Duration::from_secs(1);

/// Runs `step` on a thread of its own, passing `report` what `measure` says every second: the step
/// and its bytes so far. For a download or an unpack whose library reports nothing itself.
fn with_progress<T: Send>(
    report: &mut dyn FnMut(&str, Option<u64>, Option<u64>),
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_component_dir_is_complete_only_with_every_file() {
        let dir = std::env::temp_dir().join(format!("zkminer-groth16-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(!complete(&dir));
        for (i, f) in FILES.iter().enumerate() {
            fs::write(dir.join(f), if i == 0 { &b""[..] } else { &b"x"[..] }).unwrap();
        }
        assert!(!complete(&dir), "an empty file is an install cut short");
        fs::write(dir.join(FILES[0]), b"x").unwrap();
        assert!(complete(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_pinned_url_names_the_pinned_hash() {
        assert!(ARCHIVE_URL.ends_with(ARCHIVE_SHA256));
        assert!(!ARCHIVE_URL.contains(char::is_whitespace));
    }
}
