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
use std::path::Path;

use anyhow::{anyhow, Context, Result};

/// Set to `0` to leave `~/.sp1/bin/sp1-gpu-server` alone.
pub(crate) const INSTALL_ENV: &str = "ZKMINER_SP1_SERVER_INSTALL";
/// The shipped server's name, beside this worker's executable.
const BUNDLED_NAME: &str = "sp1-gpu-server";

/// Installs the server shipped beside this executable, if there is one; see the module docs.
/// Never fails the worker: without it the SDK runs whatever is installed, as before.
pub(crate) fn install_bundled_server() {
    if std::env::var(INSTALL_ENV).is_ok_and(|value| value.trim() == "0") {
        return;
    }
    let Some(bundled) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(BUNDLED_NAME)))
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
    let temp = dir.join(format!(".{BUNDLED_NAME}.{}.tmp", std::process::id()));
    let copied = (|| -> Result<()> {
        fs::copy(from, &temp).with_context(|| format!("cannot copy to {}", temp.display()))?;
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temp, fs::Permissions::from_mode(0o755))?;
        }
        fs::File::open(&temp)?.sync_all()?;
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
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn installs_when_missing_or_different_and_not_otherwise() {
        let root = TestDir::new();
        let shipped = root.path().join("sp1-gpu-server");
        fs::write(&shipped, b"server built from the pinned commit").unwrap();
        let installed = root.path().join("home/.sp1/bin/sp1-gpu-server");

        assert!(install(&shipped, &installed).unwrap(), "missing: installed");
        assert_eq!(fs::read(&installed).unwrap(), fs::read(&shipped).unwrap());
        assert_eq!(
            fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
            0o755
        );
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
