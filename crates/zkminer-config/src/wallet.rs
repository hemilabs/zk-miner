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
/// The file is created exclusively (an existing file is never truncated), already private: on unix
/// mode 0600; on Windows with a protected ACL of its owner and SYSTEM only, set by the call that
/// creates it, and opened unshared until the key is written. (Restricting it after creation left a
/// window in which, in a folder outside the profile such as `C:\zkminer`, any local user could open
/// it for reading, or rename it away and plant their own.) A write that fails part-way removes the
/// file it created. An existing key is kept only if no one else can read or write it (checked on
/// unix).
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
    let mut file = create_private(path)
        .with_context(|| format!("Failed to create key file {}", path.display()))?;
    // From here the file is ours: remove it on any failure rather than leave a partial key that
    // every later run would refuse.
    let written = file
        .write_all(hex.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("Failed to write key file {}", path.display()));
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

/// Create `path`, which must not exist, readable and writable by this user only (unix: 0600).
#[cfg(not(windows))]
fn create_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Create `path`, which must not exist, with a protected ACL (no inherited entries) granting full
/// access to its owner (`OW`) and SYSTEM (`SY`) only, in the same call that creates it, and open it
/// for writing with no sharing, so nothing else can open it until it is closed.
#[cfg(windows)]
fn create_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit_handle: i32,
    }
    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            attributes: *const SecurityAttributes,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        fn LocalFree(mem: *mut c_void) -> *mut c_void;
    }
    const SDDL_REVISION_1: u32 = 1;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    let invalid = usize::MAX as *mut c_void; // INVALID_HANDLE_VALUE

    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)(A;;FA;;;SY)\0".encode_utf16().collect();
    let name: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string and an out-pointer; the descriptor is freed below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let attributes = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor,
        inherit_handle: 0,
    };
    // SAFETY: a NUL-terminated path and a valid SECURITY_ATTRIBUTES that outlives the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    let error = std::io::Error::last_os_error();
    // SAFETY: allocated by the conversion above, no longer used.
    unsafe { LocalFree(descriptor) };
    if handle == invalid || handle.is_null() {
        return Err(error);
    }
    // SAFETY: a valid file handle we own, handed to `File` to close.
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
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
            assert!(
                acl.contains("owner rights:(f)") || acl.contains("s-1-3-4:(f)"),
                "the owner has full access: {acl}"
            );
        }
        // A file that is not a key is refused, not replaced.
        let junk = dir.join("junk");
        std::fs::write(&junk, "not a key").unwrap();
        assert!(generate_key_file(&junk).is_err());
        assert_eq!(std::fs::read_to_string(&junk).unwrap(), "not a key");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
