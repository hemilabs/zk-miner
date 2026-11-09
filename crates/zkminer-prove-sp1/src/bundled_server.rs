//! Installing the `sp1-gpu-server` shipped beside this worker.
//!
//! The SDK runs `~/.sp1/bin/sp1-gpu-server`, and downloads upstream's build there when it is missing
//! or reports a different version. Upstream's build has none of the hemilabs fork's GPU fixes (the
//! Blackwell out-of-bounds faults, the 16 GB tier) nor, from fork v6.8.1, its Groth16 helper, and
//! its `--version` matches the fork's, so the SDK cannot tell them apart. The release therefore
//! ships the server built from the same commit as this worker's SDK, and this installs it before
//! anything runs a server.
//!
//! It is installed when the file there is missing or differs, by copying to a temporary name in
//! the same directory and renaming over it: a server already running from the old file keeps
//! running, and nothing ever sees half a binary. `ZKMINER_SP1_SERVER_INSTALL=0` turns this off, for
//! a host whose server is managed by hand.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

/// Set to `0` to leave `~/.sp1/bin/sp1-gpu-server` alone.
pub(crate) const INSTALL_ENV: &str = zkminer_prover_protocol::types::SP1_SERVER_INSTALL_ENV;

/// Libraries the server loads from its own directory. On Windows, gnark's Groth16 prover is a DLL
/// (`sp1gnark.dll`, see hemilabs/sp1's gnark-ffi), where Linux links it into the server statically;
/// and the MSVC runtime the server links, which a machine with only a GPU driver may not have. A
/// DLL beside an executable is found before System32's, so the server always gets the runtime it
/// shipped with. And the SYCL build's own kernels, `sp1_gpu_sycl.dll`: beside it, it is replaced
/// with the server, never left from an older build to shadow the new one (a DLL beside the
/// executable wins over one on PATH). Each is installed if the release ships it beside this worker.
#[cfg(windows)]
const COMPANIONS: &[&str] = &[
    "sp1gnark.dll",
    "sp1_gpu_sycl.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "msvcp140.dll",
];
#[cfg(not(windows))]
const COMPANIONS: &[&str] = &[];

/// Installs the server shipped beside this executable, if there is one; see the module docs.
/// Never fails the worker: without it the SDK runs whatever is installed, as before.
pub(crate) fn install_bundled_server() {
    if std::env::var(INSTALL_ENV).is_ok_and(|value| value.trim() == "0") {
        return;
    }
    // The build for this worker's card (`warmup::server_name`), shipped under its own name.
    let name = crate::warmup::server_name();
    let Some(bundled) = std::env::current_exe()
        .ok()
        .and_then(|exe| {
            exe.parent()
                .map(|dir| dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX)))
        })
        .filter(|path| path.is_file())
    else {
        // Not a release layout (a development build, say): nothing shipped to install.
        return;
    };
    let target = match crate::warmup::server_path() {
        Ok(target) => target,
        Err(e) => {
            tracing::warn!("not installing {}: {e:#}", bundled.display());
            return;
        }
    };
    // A build with libraries of its own ships them in `<name>-lib/` beside it, which is used where it
    // is (`server_lib_dir`), not copied: it is the whole ROCm or Intel runtime, in subdirectories.
    match install(&bundled, &target) {
        Ok(true) => tracing::info!("installed {} as {}", bundled.display(), target.display()),
        Ok(false) => tracing::debug!("{} is already installed", bundled.display()),
        Err(e) => tracing::warn!(
            "could not install {} as {} ({e:#}); the SDK will run what is there, or download \
             upstream's server, which lacks this release's GPU fixes",
            bundled.display(),
            target.display()
        ),
    }
    // What the server loads from beside itself, shipped beside it in turn.
    if let (Some(from_dir), Some(to_dir)) = (bundled.parent(), target.parent()) {
        for name in COMPANIONS {
            let from = from_dir.join(name);
            if !from.is_file() {
                continue;
            }
            if let Err(e) = install(&from, &to_dir.join(name)) {
                tracing::warn!(
                    "could not install {} beside the server ({e:#})",
                    from.display()
                );
            }
        }
    }
}

/// The directory of libraries the server for this worker's card needs and a host does not have, if
/// there is one: the HIP build's ROCm runtime, or the SYCL build's `libsp1_gpu_sycl.so`, oneAPI
/// runtime and Intel driver stack. `main` puts it first on the library path the server inherits.
///
/// The release ships it beside this worker as `<name>-lib/` (for SYCL, a link to
/// `zkminer-intel/lib`, which the risc0 Intel worker loads from too); it is used in place. Without one, or
/// with installing turned off (a server managed by hand), it is `<name>-lib/` beside the installed
/// server.
pub(crate) fn server_lib_dir() -> Option<PathBuf> {
    let installing = !std::env::var(INSTALL_ENV).is_ok_and(|value| value.trim() == "0");
    let exe = std::env::current_exe().ok();
    lib_dir_for(
        &crate::warmup::server_name(),
        exe.as_deref().and_then(Path::parent),
        crate::warmup::server_path().ok().as_deref(),
        installing,
    )
}

/// [`server_lib_dir`] for a server called `name`, a worker in `worker_dir` and the server installed
/// at `server`.
fn lib_dir_for(
    name: &str,
    worker_dir: Option<&Path>,
    server: Option<&Path>,
    installing: bool,
) -> Option<PathBuf> {
    let lib = format!("{name}-lib");
    let shipped = worker_dir.filter(|_| installing).map(|dir| dir.join(&lib));
    let installed = server.map(|server| server.with_file_name(&lib));
    shipped
        .into_iter()
        .chain(installed)
        .find(|dir| dir.is_dir())
}

/// Copies `from` to `to`, executable, unless `to` already has the same contents. Whether it
/// copied.
pub(crate) fn install(from: &Path, to: &Path) -> Result<bool> {
    if same_contents(from, to)? {
        return Ok(false);
    }
    let dir = to
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", to.display()))?;
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let base = to
        .file_name()
        .map_or_else(|| "sp1-gpu-server".into(), |n| n.to_string_lossy());
    let temp = dir.join(format!(".{base}.{}.tmp", std::process::id()));
    let copied = (|| -> Result<()> {
        fs::copy(from, &temp).with_context(|| format!("cannot copy to {}", temp.display()))?;
        // Windows has no execute bit: an .exe runs as copied.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temp, fs::Permissions::from_mode(0o755))?;
        }
        #[cfg(not(windows))]
        fs::File::open(&temp)?.sync_all()?;
        // Opened for writing: Windows flushes only through a handle with write access.
        #[cfg(windows)]
        fs::OpenOptions::new().write(true).open(&temp)?.sync_all()?;
        fs::rename(&temp, to).with_context(|| format!("cannot replace {}", to.display()))
    })();
    if copied.is_err() {
        let _ = fs::remove_file(&temp);
    }
    copied.map(|()| true)
}

/// Whether the files at `a` and `b` have the same contents; false when `b` does not exist.
fn same_contents(a: &Path, b: &Path) -> Result<bool> {
    let len_a = fs::metadata(a)
        .with_context(|| format!("cannot read {}", a.display()))?
        .len();
    let len_b = match fs::metadata(b) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", b.display())),
    };
    if len_a != len_b {
        return Ok(false);
    }
    let (mut file_a, mut file_b) = (fs::File::open(a)?, fs::File::open(b)?);
    let (mut buf_a, mut buf_b) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    loop {
        let n = file_a.read(&mut buf_a)?;
        if n == 0 {
            return Ok(true);
        }
        file_b.read_exact(&mut buf_b[..n])?;
        if buf_a[..n] != buf_b[..n] {
            return Ok(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warmup::TestDir;

    #[test]
    fn the_shipped_lib_dir_is_used_in_place_unless_installing_is_off() {
        let root = TestDir::new();
        let worker = root.path().join("provers");
        let sp1_bin = root.path().join(".sp1/bin");
        let server = sp1_bin.join("sp1-gpu-server-sycl");
        std::fs::create_dir_all(&worker).unwrap();
        std::fs::create_dir_all(&sp1_bin).unwrap();
        let find = |installing| {
            lib_dir_for(
                "sp1-gpu-server-sycl",
                Some(&worker),
                Some(&server),
                installing,
            )
        };

        assert_eq!(find(true), None, "no directory anywhere");
        std::fs::create_dir(sp1_bin.join("sp1-gpu-server-sycl-lib")).unwrap();
        assert_eq!(find(true), Some(sp1_bin.join("sp1-gpu-server-sycl-lib")));
        // The release's SYCL one: a link to the libraries the risc0 Intel worker uses.
        std::fs::create_dir_all(worker.join("zkminer-intel/lib")).unwrap();
        std::os::unix::fs::symlink("zkminer-intel/lib", worker.join("sp1-gpu-server-sycl-lib"))
            .unwrap();
        assert_eq!(find(true), Some(worker.join("sp1-gpu-server-sycl-lib")));
        // A server managed by hand keeps its own libraries.
        assert_eq!(find(false), Some(sp1_bin.join("sp1-gpu-server-sycl-lib")));
    }

    #[test]
    fn installs_when_missing_or_different_and_not_otherwise() {
        let root = TestDir::new();
        let shipped = root.path().join("sp1-gpu-server");
        fs::write(&shipped, b"server built from the pinned commit").unwrap();
        let installed = root.path().join("home/.sp1/bin/sp1-gpu-server");

        assert!(install(&shipped, &installed).unwrap(), "missing: installed");
        assert_eq!(fs::read(&installed).unwrap(), fs::read(&shipped).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        assert!(
            !install(&shipped, &installed).unwrap(),
            "the same: left alone"
        );

        // Upstream's download, the same length or not: replaced.
        fs::write(&installed, b"server downloaded from upstream!!!!").unwrap();
        assert_eq!(
            fs::metadata(&installed).unwrap().len(),
            fs::metadata(&shipped).unwrap().len()
        );
        assert!(install(&shipped, &installed).unwrap());
        fs::write(&installed, b"short").unwrap();
        assert!(install(&shipped, &installed).unwrap());
        assert_eq!(fs::read(&installed).unwrap(), fs::read(&shipped).unwrap());

        // No temporary file is left beside it.
        let names: Vec<_> = fs::read_dir(installed.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["sp1-gpu-server".to_string()]);
    }

    /// A server running from the old file keeps its file: the new one is renamed over the name,
    /// not written into the old inode.
    #[test]
    fn a_running_servers_file_is_not_overwritten() {
        let root = TestDir::new();
        let shipped = root.path().join("sp1-gpu-server");
        fs::write(&shipped, b"new").unwrap();
        let installed = root.path().join("bin/sp1-gpu-server");
        fs::create_dir_all(installed.parent().unwrap()).unwrap();
        fs::write(&installed, b"old").unwrap();
        let mut open_by_running_server = fs::File::open(&installed).unwrap();
        assert!(install(&shipped, &installed).unwrap());
        let mut old = String::new();
        open_by_running_server.read_to_string(&mut old).unwrap();
        assert_eq!(old, "old");
        assert_eq!(fs::read(&installed).unwrap(), b"new");
    }
}
