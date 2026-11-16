use alloy::signers::local::PrivateKeySigner;
use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::config::WalletConfig;

/// Load a private key signer based on the wallet configuration.
pub fn load_signer(config: &WalletConfig) -> Result<PrivateKeySigner> {
    match config.key_source.as_str() {
        "env" => load_from_env(&config.key_env_var),
        "file" => load_from_file(config.key_file_path.as_deref()),
        "keystore" => {
            bail!(
                "Keystore loading not yet supported. Use key_source = \"env\" or \"file\" instead."
            );
        }
        other => bail!(
            "Unknown key_source: '{}'. Use 'env', 'file', or 'keystore'",
            other
        ),
    }
}

fn load_from_env(env_var: &str) -> Result<PrivateKeySigner> {
    let key_hex = Zeroizing::new(
        std::env::var(env_var)
            .with_context(|| format!("Environment variable '{}' not set", env_var))?,
    );

    // Remove the key from THIS process's environment the moment it is read, so no child we
    // later spawn (prover workers, the SP1 gpu-server) can inherit it — whatever the variable
    // is named. This covers a non-standard `key_env_var`; the worker-side secret-name filter
    // (`is_secret_env_name`) remains as a second layer. Called once at startup, before any
    // worker or env-reading thread exists, so the process-global mutation is safe here.
    std::env::remove_var(env_var);

    parse_private_key(&key_hex)
}

fn load_from_file(path: Option<&str>) -> Result<PrivateKeySigner> {
    let path = path.context("key_file_path not set in config")?;

    // Check file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to read metadata for key file: {}", path))?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            tracing::warn!(
                "Key file {} has permissions {:04o} — should be 0600. \
                 Fix with: chmod 600 {}",
                path,
                mode,
                path,
            );
        }
    }

    let content = Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read key file: {}", path))?,
    );

    parse_private_key(content.trim())
}

fn parse_private_key(key_hex: &str) -> Result<PrivateKeySigner> {
    let key_hex = key_hex.trim().strip_prefix("0x").unwrap_or(key_hex.trim());

    let signer: PrivateKeySigner = key_hex.parse().context("Failed to parse private key hex")?;

    Ok(signer)
}

/// What [`generate_key_file`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFile {
    /// A fresh key was written.
    Created(alloy::primitives::Address),
    /// A key file was already there, so it was kept: a key is never overwritten.
    Kept(alloy::primitives::Address),
}

impl KeyFile {
    pub fn address(self) -> alloy::primitives::Address {
        match self {
            KeyFile::Created(a) | KeyFile::Kept(a) => a,
        }
    }
}

/// Generate a private key into `path` (hex, readable by this user only), or keep the key already
/// there — the funds behind an existing key would be lost with it, so it is never replaced.
///
/// The file is created exclusively (an existing file is never truncated). On unix it is mode 0600;
/// on Windows its ACL is set to the current user and SYSTEM only, with inheritance removed, before
/// the key is written (a folder outside the profile, such as `C:\zkminer`, would otherwise let every
/// local user read it). A write that fails part-way removes the file it created. An existing key is
/// kept only if no one else can read or write it (checked on unix).
pub fn generate_key_file(path: &std::path::Path) -> Result<KeyFile> {
    use std::io::Write;
    if path.exists() {
        check_private(path)?;
        let signer = load_from_file(Some(&path.to_string_lossy()))
            .with_context(|| format!("{} exists but is not a usable key file", path.display()))?;
        return Ok(KeyFile::Kept(signer.address()));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;
    }
    let signer = PrivateKeySigner::random();
    let mut hex = Zeroizing::new(String::with_capacity(67));
    hex.push_str("0x");
    hex.push_str(&Zeroizing::new(alloy::hex::encode(signer.to_bytes())));
    hex.push('\n');
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("Failed to create key file {}", path.display()))?;
    // From here the file is ours: remove it on any failure rather than leave a partial key that
    // every later run would refuse.
    let written = restrict_to_owner(path).and_then(|()| {
        file.write_all(hex.as_bytes())
            .and_then(|()| file.sync_all())
            .with_context(|| format!("Failed to write key file {}", path.display()))
    });
    if let Err(e) = written {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(KeyFile::Created(signer.address()))
}

/// Refuse to use an existing key file others could read or replace (unix: any group/other bits).
fn check_private(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("Failed to read metadata for {}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "{} is readable or writable by other users (mode {mode:04o}), so it is not used as \
                 the key. If it is yours: chmod 600 {}",
                path.display(),
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Windows: give `path` an ACL of the current user and SYSTEM only (`icacls /inheritance:r`).
#[cfg(windows)]
fn restrict_to_owner(path: &std::path::Path) -> Result<()> {
    let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(d), Ok(u)) if !d.is_empty() && !u.is_empty() => format!("{d}\\{u}"),
        _ => bail!("cannot restrict the key file to its owner: USERDOMAIN/USERNAME are not set"),
    };
    // By full path, not PATH: a planted `icacls` would see the key's path at least.
    let icacls = std::path::Path::new(
        &std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()),
    )
    .join("System32")
    .join("icacls.exe");
    let out = std::process::Command::new(icacls)
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("{user}:F"))
        // SYSTEM, by SID (its name is localized).
        .args(["/grant:r", "*S-1-5-18:F"])
        .output()
        .context("cannot run icacls to restrict the key file")?;
    if !out.status.success() {
        bail!(
            "cannot restrict {} to its owner: icacls said {}",
            path.display(),
            String::from_utf8_lossy(&out.stdout).trim()
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn restrict_to_owner(_path: &std::path::Path) -> Result<()> {
    Ok(()) // created 0600 above
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_loads_back_and_is_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("zkminer-keygen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("key");
        let created = generate_key_file(&path).unwrap();
        let KeyFile::Created(addr) = created else {
            panic!("expected a new key, got {created:?}")
        };
        let loaded = load_from_file(Some(&path.to_string_lossy())).unwrap();
        assert_eq!(loaded.address(), addr);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Again: the same key, kept.
        assert_eq!(generate_key_file(&path).unwrap(), KeyFile::Kept(addr));
        // On unix, a key others can read is refused, not used.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(generate_key_file(&path).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        // On Windows, only the user and SYSTEM are on its ACL.
        #[cfg(windows)]
        {
            let out = std::process::Command::new("icacls")
                .arg(&path)
                .output()
                .unwrap();
            let acl = String::from_utf8_lossy(&out.stdout).to_lowercase();
            assert!(
                !acl.contains("users:") && !acl.contains("everyone"),
                "{acl}"
            );
            assert!(!acl.contains("(i)"), "inheritance removed: {acl}");
        }
        // A file that is not a key is refused, not replaced.
        let junk = dir.join("junk");
        std::fs::write(&junk, "not a key").unwrap();
        assert!(generate_key_file(&junk).is_err());
        assert_eq!(std::fs::read_to_string(&junk).unwrap(), "not a key");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
