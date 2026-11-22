use alloy::signers::local::PrivateKeySigner;
use anyhow::{bail, Context, Result};
/// Re-exported for the secrets callers hold (`zkminer init --import-env-key`).
pub use zeroize::Zeroizing;

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
        // Owner-only (0600, or 0400 as systemd's `LoadCredential=` leaves it): anything for the
        // group or others is too much.
        if mode & 0o077 != 0 {
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

/// What [`generate_key_file`] or [`import_key_file`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFile {
    /// A fresh key was written.
    Created(alloy::primitives::Address),
    /// A key file was already there, so it was kept: a key is never overwritten.
    Kept(alloy::primitives::Address),
    /// A key given to [`import_key_file`] was written.
    Imported(alloy::primitives::Address),
}

impl KeyFile {
    pub fn address(self) -> alloy::primitives::Address {
        match self {
            KeyFile::Created(a) | KeyFile::Kept(a) | KeyFile::Imported(a) => a,
        }
    }
}

/// Generate a private key into `path` (hex, readable by this user only), or keep the key already
/// there — the funds behind an existing key would be lost with it, so it is never replaced.
///
/// The file is created exclusively (an existing file is never truncated), already private: on unix
/// mode 0600; on Windows with a protected ACL of its owner and SYSTEM only and a label that keeps
/// Low-integrity processes from reading it, set by the call that creates it, and opened unshared
/// until the key is written. (Restricting it after creation left a window in which, in a folder
/// outside the profile such as `C:\zkminer`, any local user could open it for reading, or rename it
/// away and plant their own; and a restore point taken before the miner first labelled it kept a
/// copy Low processes can read.) A write that fails part-way removes the file it created. An
/// existing key is kept only if no one else can read or write it ([`check_private`]).
pub fn generate_key_file(path: &std::path::Path) -> Result<KeyFile> {
    if path.exists() {
        return Ok(KeyFile::Kept(kept_key_address(path)?));
    }
    let signer = PrivateKeySigner::random();
    write_new_key(path, &signer)?;
    Ok(KeyFile::Created(signer.address()))
}

/// Write the private key `secret` (hex, with or without `0x`) into a new key file at `path`,
/// created as [`generate_key_file`] creates one, and read it back. A key file already at `path` is
/// never replaced: one holding the same key is kept ([`KeyFile::Kept`]); one holding another key
/// is refused, with both addresses. The secret is never logged or put in an error.
pub fn import_key_file(path: &std::path::Path, secret: &str) -> Result<KeyFile> {
    let signer = parse_private_key(secret)
        .map_err(|_| anyhow::anyhow!("the value given is not a private key (64 hex digits)"))?;
    if path.exists() {
        let there = kept_key_address(path)?;
        if there != signer.address() {
            bail!(
                "{} already holds the key of {there:?}, not of {:?}, the key being imported: it \
                 is never replaced. Move it aside first if you mean to (its stake and payouts stay \
                 with {there:?})",
                path.display(),
                signer.address()
            );
        }
        return Ok(KeyFile::Kept(there));
    }
    write_new_key(path, &signer)?;
    // Read back: what the miner will load must be the key given.
    let loaded = load_from_file(Some(&path.to_string_lossy()))?;
    if loaded.address() != signer.address() {
        let _ = std::fs::remove_file(path);
        bail!("{} did not read back as the key written", path.display());
    }
    Ok(KeyFile::Imported(signer.address()))
}

/// The address of the private key `secret` (hex, with or without `0x`); an error that does not
/// echo it when it is not one.
pub fn address_of_key(secret: &str) -> Result<alloy::primitives::Address> {
    parse_private_key(secret)
        .map(|s| s.address())
        .map_err(|_| anyhow::anyhow!("the value given is not a private key (64 hex digits)"))
}

/// The address of the existing key file at `path`, if it may be used ([`check_private`]).
fn kept_key_address(path: &std::path::Path) -> Result<alloy::primitives::Address> {
    check_private(path)?;
    let signer = load_from_file(Some(&path.to_string_lossy()))
        .with_context(|| format!("{} exists but is not a usable key file", path.display()))?;
    Ok(signer.address())
}

/// Write `signer`'s key into the new file `path` ([`create_private`]), removing it again on a
/// failure part-way.
fn write_new_key(path: &std::path::Path, signer: &PrivateKeySigner) -> Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;
    }
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
    Ok(())
}

/// Refuse to use an existing key file others could read or replace: on unix any group/other bits;
/// on Windows an owner other than this user or Administrators, a DACL that inherits, or one that
/// grants anyone but this user, SYSTEM and Administrators (a file someone else put beside the
/// config is not adopted as the key).
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
    #[cfg(windows)]
    {
        let user = current_user_sid().context("cannot read this process's user")?;
        let sddl = win_security::sddl(path, win_security::OWNER | win_security::DACL)
            .with_context(|| format!("cannot read the owner and ACL of {}", path.display()))?;
        let problems = key_acl_problems(&sddl, &user, &win_security::resolve_alias);
        if !problems.is_empty() {
            bail!(
                "{} is not private to this user ({}), so it is not used as the key. If this key \
                 is yours, as its owner or an administrator run: icacls \"{}\" /inheritance:r \
                 /grant:r \"%USERNAME%\":F SYSTEM:F (Administrators as its owner is accepted when \
                 the ACL is otherwise clean); if you did not put it there, do not use it",
                path.display(),
                problems.join("; "),
                path.display()
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

/// Windows: the owner of the file at `path`, as a SID string, for a report.
#[cfg(windows)]
pub fn file_owner_sid(path: &std::path::Path) -> Option<String> {
    let sddl = win_security::sddl(path, win_security::OWNER).ok()?;
    let owner = sddl_sections(&sddl).owner?;
    Some(win_security::resolve_alias(owner))
}

/// SYSTEM and BUILTIN\Administrators: who a kept key file's DACL may grant, besides the user.
#[cfg(any(windows, test))]
const SYSTEM_SID: &str = "S-1-5-18";
#[cfg(any(windows, test))]
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// The parts of an SDDL string: the owner SID, the DACL's flags (`P`, `AI`…) and ACE strings, and
/// the SACL's ACE strings (`None`/empty for a part not there).
#[cfg(any(windows, test))]
#[derive(Debug, Default, PartialEq, Eq)]
struct SddlSections<'a> {
    owner: Option<&'a str>,
    dacl: Option<(&'a str, Vec<&'a str>)>,
    #[cfg_attr(not(test), allow(dead_code))]
    sacl: Vec<&'a str>,
}

#[cfg(any(windows, test))]
fn sddl_sections(sddl: &str) -> SddlSections<'_> {
    // Section starts (`O:`, `G:`, `D:`, `S:`) outside parentheses.
    let bytes = sddl.as_bytes();
    let mut starts = Vec::new();
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'O' | b'G' | b'D' | b'S' if depth == 0 && bytes.get(i + 1) == Some(&b':') => {
                starts.push((b, i))
            }
            _ => {}
        }
    }
    let mut out = SddlSections::default();
    for (n, &(kind, at)) in starts.iter().enumerate() {
        let end = starts.get(n + 1).map_or(sddl.len(), |&(_, e)| e);
        let body = &sddl[at + 2..end];
        let flags_end = body.find('(').unwrap_or(body.len());
        let aces: Vec<&str> = body[flags_end..]
            .split(')')
            .filter_map(|a| a.strip_prefix('('))
            .collect();
        match kind {
            b'O' => out.owner = Some(body),
            b'D' => out.dacl = Some((&body[..flags_end], aces)),
            b'S' => out.sacl = aces,
            _ => {}
        }
    }
    out
}

/// What makes a key file with the owner-and-DACL `sddl` not private to the user `user` (a SID
/// string): an owner other than the user or Administrators, no DACL or one that inherits, or an
/// entry that grants anyone but the user, SYSTEM and Administrators. Deny entries and inherit-only
/// entries (which do not apply to a file) are fine. `resolve` turns an SDDL SID alias (`SY`, `BA`,
/// `WD`…) into a SID string and leaves a SID string as it is.
#[cfg(any(windows, test))]
fn key_acl_problems(sddl: &str, user: &str, resolve: &dyn Fn(&str) -> String) -> Vec<String> {
    let sections = sddl_sections(sddl);
    let mut problems = Vec::new();
    let allowed = |sid: &str| sid == user || sid == SYSTEM_SID || sid == ADMINISTRATORS_SID;
    match sections.owner.map(resolve) {
        Some(o) if o == user || o == ADMINISTRATORS_SID => {}
        Some(o) => problems.push(format!("owned by {o}")),
        None => problems.push("its owner could not be read".to_string()),
    }
    match &sections.dacl {
        Some((flags, _)) if flags.contains("NO_ACCESS_CONTROL") => {
            problems.push("it has no ACL: anyone may open it".to_string())
        }
        None => problems.push("it has no ACL: anyone may open it".to_string()),
        Some((flags, aces)) => {
            if !flags.contains('P') {
                problems.push("its ACL inherits from the folder".to_string());
            }
            for ace in aces {
                let fields: Vec<&str> = ace.split(';').collect();
                let (Some(kind), Some(ace_flags), Some(sid)) =
                    (fields.first(), fields.get(1), fields.get(5))
                else {
                    problems.push(format!("an entry it does not understand ({ace})"));
                    continue;
                };
                if ace_flags.contains("IO") || matches!(*kind, "D" | "OD" | "XD") {
                    continue;
                }
                let sid = resolve(sid);
                if *kind != "A" || !allowed(&sid) {
                    problems.push(format!("an entry ({ace}) for {sid}"));
                }
            }
        }
    }
    problems
}

/// Windows security descriptors as SDDL, for [`check_private`] and the tests.
#[cfg(windows)]
mod win_security {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    pub const OWNER: u32 = 0x1;
    pub const DACL: u32 = 0x4;
    #[cfg(test)]
    pub const LABEL: u32 = 0x10;
    const SE_FILE_OBJECT: i32 = 1;
    const SDDL_REVISION_1: u32 = 1;

    #[link(name = "advapi32")]
    extern "system" {
        fn GetNamedSecurityInfoW(
            name: *const u16,
            object_type: i32,
            information: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            descriptor: *mut *mut c_void,
        ) -> u32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor: *mut c_void,
            revision: u32,
            information: u32,
            string: *mut *mut u16,
            length: *mut u32,
        ) -> i32;
        fn ConvertStringSidToSidW(string: *const u16, sid: *mut *mut c_void) -> i32;
        fn ConvertSidToStringSidW(sid: *mut c_void, string: *mut *mut u16) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(mem: *mut c_void) -> *mut c_void;
    }

    /// A NUL-terminated wide string allocated by the system, as a `String`, and freed.
    ///
    /// # Safety
    /// `p` is a valid NUL-terminated string from a `LocalAlloc`.
    unsafe fn take(p: *mut u16) -> String {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
        LocalFree(p.cast());
        s
    }

    /// The parts `information` of `path`'s security descriptor, as SDDL. Needs READ_CONTROL only.
    pub fn sddl(path: &std::path::Path, information: u32) -> std::io::Result<String> {
        let name: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        let (mut owner, mut dacl, mut sacl) = (
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        // SAFETY: a NUL-terminated path and out-pointers; the descriptor is freed below.
        let status = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                information,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                &mut sacl,
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        let mut string: *mut u16 = std::ptr::null_mut();
        // SAFETY: the descriptor read above and an out-pointer.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                information,
                &mut string,
                std::ptr::null_mut(),
            )
        };
        let error = std::io::Error::last_os_error();
        // SAFETY: allocated by GetNamedSecurityInfoW, no longer used.
        unsafe { LocalFree(descriptor) };
        if ok == 0 {
            return Err(error);
        }
        // SAFETY: a string the conversion allocated.
        Ok(unsafe { take(string) })
    }

    /// An SDDL SID (an alias such as `SY`, `BA` or `WD`, or a SID string) as a SID string; as
    /// given when it does not convert.
    pub fn resolve_alias(sid: &str) -> String {
        if sid.starts_with("S-") {
            return sid.to_string();
        }
        let wide: Vec<u16> = sid.encode_utf16().chain([0]).collect();
        let mut binary: *mut c_void = std::ptr::null_mut();
        // SAFETY: a NUL-terminated string and out-pointers; each allocation is freed.
        unsafe {
            if ConvertStringSidToSidW(wide.as_ptr(), &mut binary) == 0 {
                return sid.to_string();
            }
            let mut string: *mut u16 = std::ptr::null_mut();
            let ok = ConvertSidToStringSidW(binary, &mut string);
            LocalFree(binary);
            if ok == 0 {
                return sid.to_string();
            }
            take(string)
        }
    }
}

/// What to do about a copy of the key's variable `var` kept in the registry (`location`, as
/// `wallet_win::persisted_key_env_copies` names it), in the order that never loses the key: copy
/// it into a key file, check the address, only then delete the copy, and plan a rotation, since
/// the copy was readable. One text for the miner's refusal, its page and `zkminer doctor`.
pub fn key_env_move_steps(var: &str, location: &str) -> String {
    let import = if var == "ZKMINER_PRIVATE_KEY" {
        "zkminer init --import-env-key".to_string()
    } else {
        format!("zkminer init --import-env-key --key-env-var {var}")
    };
    let delete = key_env_delete_step(var, location);
    format!(
        "1) copy the key into a key file: `{import}`, run as the miner's account (it reads the \
         variable from this process or the registry, writes the key file, points the config at it \
         and changes nothing else); 2) check that the address it prints is the one `zkminer \
         status` shows, the one the stake and payouts belong to; 3) only then delete the copy \
         ({delete}); 4) consider the key exposed and plan to rotate it (`zkminer unstake --all`, \
         `zkminer withdraw` 7 days on, the funds moved to a new key) rather than only deleting it"
    )
}

/// How to delete the copy of the variable `var` at `location` (as
/// `wallet_win::persisted_key_env_copies` names it; anything else is the process environment).
pub fn key_env_delete_step(var: &str, location: &str) -> String {
    if location.starts_with("HKCU") {
        format!("in PowerShell: [Environment]::SetEnvironmentVariable('{var}', $null, 'User')")
    } else if location.contains(r"\Services\") {
        format!(
            "as an administrator, remove {var} from that service's environment (NSSM: `nssm edit \
             <service>`, Environment), then restart the service"
        )
    } else if location.starts_with("HKLM") {
        format!(
            "as an administrator, in PowerShell: [Environment]::SetEnvironmentVariable('{var}', \
             $null, 'Machine')"
        )
    } else {
        format!("remove {var} from wherever it is set (a profile script, a service's environment)")
    }
}

/// The cloud-synced folder `path` is in, if any, described as `OneDrive (C:\Users\me\OneDrive)`:
/// a key file there is uploaded, kept in the service's version history and recycle bin, and
/// reachable from any device of whoever holds the account. Paths only: nothing is opened.
pub fn cloud_synced_folder(path: &std::path::Path) -> Option<String> {
    cloud_synced_root(path, &cloud_sync_roots(), cfg!(windows))
}

/// The roots of folders a sync client uploads: OneDrive's (`%OneDrive%`, `%OneDriveConsumer%`,
/// `%OneDriveCommercial%`, `~/OneDrive`) and Dropbox's, Google Drive's, iCloud Drive's and
/// Nextcloud's default folders in the home.
fn cloud_sync_roots() -> Vec<(String, std::path::PathBuf)> {
    let mut roots = Vec::new();
    for var in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
        if let Some(v) = std::env::var_os(var).filter(|v| !v.is_empty()) {
            roots.push(("OneDrive".to_string(), std::path::PathBuf::from(v)));
        }
    }
    if let Some(home) = dirs::home_dir() {
        for (name, dir) in [
            ("OneDrive", "OneDrive"),
            ("Dropbox", "Dropbox"),
            ("Google Drive", "Google Drive"),
            ("Google Drive", "My Drive"),
            ("iCloud Drive", "iCloudDrive"),
            ("Nextcloud", "Nextcloud"),
        ] {
            roots.push((name.to_string(), home.join(dir)));
        }
    }
    roots
}

/// [`cloud_synced_folder`] against `roots`, comparing whole path components (without case when
/// `ignore_case`, as on Windows). A root with no named component (a drive, `/`) is ignored: a sync
/// variable set to one would otherwise flag every path.
fn cloud_synced_root(
    path: &std::path::Path,
    roots: &[(String, std::path::PathBuf)],
    ignore_case: bool,
) -> Option<String> {
    use std::path::Component;
    let parts = |p: &std::path::Path| -> Vec<String> {
        let p = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
        p.components()
            .filter(|c| !matches!(c, Component::CurDir))
            .map(|c| {
                let s = c.as_os_str().to_string_lossy().into_owned();
                if ignore_case {
                    s.to_lowercase()
                } else {
                    s
                }
            })
            .collect()
    };
    let path_parts = parts(path);
    roots.iter().find_map(|(name, root)| {
        let named = root.components().any(|c| matches!(c, Component::Normal(_)));
        (named && path_parts.starts_with(&parts(root)))
            .then(|| format!("{name} ({})", root.display()))
    })
}

/// What `init` says about backing the key file up: offline or in a password manager, never a
/// plain copy in a synced or shared folder.
pub const KEY_BACKUP_ADVICE: &[&str] = &[
    "Back it up now, as it is the only copy: put the key in a password manager, or copy",
    "the file to a removable drive you keep offline, and label that copy (a bare key file",
    "says nothing of what it is for). Not to Documents, Desktop, OneDrive, Dropbox or",
    "Google Drive: a sync client uploads it and keeps old versions, and a plain copy there",
    "has no label keeping the miner's Low-integrity workers from reading it.",
];

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

/// Create `path`, which must not exist, owned by this user and with a protected ACL (no inherited
/// entries) granting full access to this user and SYSTEM only, and a Medium no-read-up label, in
/// the same call that creates it, and open it for writing with no sharing, so nothing else can
/// open it until it is closed. By the user's own SID, not OWNER RIGHTS: from an elevated prompt
/// the default owner is Administrators, and a later non-elevated miner could then not read its own
/// key.
#[cfg(windows)]
fn create_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let user = current_user_sid()?;
    // Labelled Medium no-read-up/no-write-up from its creation, as the miner labels it at start
    // (`windows_sandbox`): a restore point taken before then would otherwise keep a copy that
    // Low-integrity processes can read. A process may set a label up to its own level.
    create_with_sddl(
        path,
        &format!("O:{user}D:P(A;;FA;;;{user})(A;;FA;;;SY)S:(ML;;NWNR;;;ME)"),
    )
}

/// Create `path`, which must not exist, with the security descriptor `sddl`, opened for writing
/// with no sharing.
#[cfg(windows)]
fn create_with_sddl(path: &std::path::Path, sddl: &str) -> std::io::Result<std::fs::File> {
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

    let sddl: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
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

/// This process's user SID as a string (`S-1-5-21-…`), from its token. (Also the user the miner's
/// own process and threads are locked to, in `zkminer_prover::windows_sandbox`.)
#[cfg(windows)]
pub fn current_user_sid() -> std::io::Result<String> {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn LocalFree(mem: *mut c_void) -> *mut c_void;
    }
    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
        fn GetTokenInformation(
            token: *mut c_void,
            class: u32,
            info: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *mut c_void, string: *mut *mut u16) -> i32;
    }
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER: u32 = 1;
    // SAFETY: plain advapi32/kernel32 calls; every buffer outlives its use, every handle and
    // allocation is released below.
    unsafe {
        let mut token: *mut c_void = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut needed = 0u32;
        GetTokenInformation(token, TOKEN_USER, std::ptr::null_mut(), 0, &mut needed);
        // u64s: TOKEN_USER starts with a pointer, so the buffer must be pointer-aligned.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
        let ok = GetTokenInformation(
            token,
            TOKEN_USER,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut needed,
        );
        let error = std::io::Error::last_os_error();
        CloseHandle(token);
        if ok == 0 {
            return Err(error);
        }
        // TOKEN_USER { User: SID_AND_ATTRIBUTES { Sid: PSID, Attributes: u32 } }
        let sid = *(buf.as_ptr() as *const *mut c_void);
        let mut string: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut string) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let len = (0..).take_while(|&i| *string.add(i) != 0).count();
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(string, len));
        LocalFree(string.cast());
        Ok(text)
    }
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
            // The user by name (not localized, unlike SYSTEM's or OWNER RIGHTS').
            let user = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
            assert!(
                acl.contains(&format!("{user}:(f)")),
                "the user has full access: {acl}"
            );
        }
        // A file that is not a key is refused, not replaced.
        let junk = dir.join("junk");
        std::fs::write(&junk, "not a key").unwrap();
        assert!(generate_key_file(&junk).is_err());
        assert_eq!(std::fs::read_to_string(&junk).unwrap(), "not a key");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zkminer-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The well-known first Anvil/Hardhat dev key (public, never funded on a real chain).
    const TEST_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn an_imported_key_loads_back_and_never_replaces_another() {
        let dir = temp_dir("keyimport");
        let path = dir.join("key");
        let expected = parse_private_key(TEST_KEY).unwrap().address();
        assert_eq!(
            import_key_file(&path, TEST_KEY).unwrap(),
            KeyFile::Imported(expected)
        );
        let loaded = load_from_file(Some(&path.to_string_lossy())).unwrap();
        assert_eq!(loaded.address(), expected);
        // Again, the same key (without its 0x): kept.
        assert_eq!(
            import_key_file(&path, TEST_KEY.trim_start_matches("0x")).unwrap(),
            KeyFile::Kept(expected)
        );
        // Another key over it: refused, naming both addresses, and the file is untouched.
        let other = dir.join("other");
        let KeyFile::Created(other_addr) = generate_key_file(&other).unwrap() else {
            panic!("expected a new key")
        };
        let before = std::fs::read(&other).unwrap();
        let refused = import_key_file(&other, TEST_KEY).unwrap_err().to_string();
        assert!(
            refused.contains(&format!("{other_addr:?}"))
                && refused.contains(&format!("{expected:?}")),
            "{refused}"
        );
        assert_eq!(std::fs::read(&other).unwrap(), before);
        // Not a key: refused without echoing it, and no file is left.
        let bad = dir.join("bad");
        let err = import_key_file(&bad, "0xnot-a-key-value")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("not-a-key-value"), "{err}");
        assert!(!bad.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sddl_is_split_into_owner_dacl_and_sacl() {
        let s = sddl_sections("O:BAG:SYD:PAI(A;;FA;;;SY)(D;OICI;FA;;;WD)S:(ML;;NWNR;;;ME)");
        assert_eq!(s.owner, Some("BA"));
        assert_eq!(s.dacl, Some(("PAI", vec!["A;;FA;;;SY", "D;OICI;FA;;;WD"])));
        assert_eq!(s.sacl, vec!["ML;;NWNR;;;ME"]);
        let s = sddl_sections("O:S-1-5-21-1-2-3-1001D:(A;ID;FA;;;S-1-5-21-1-2-3-1001)");
        assert_eq!(s.owner, Some("S-1-5-21-1-2-3-1001"));
        assert_eq!(s.dacl, Some(("", vec!["A;ID;FA;;;S-1-5-21-1-2-3-1001"])));
        assert_eq!(sddl_sections(""), SddlSections::default());
    }

    /// KE-3: a kept key file must be private to the user: owned by them (or Administrators, as
    /// one an administrator copied in), a protected DACL, and grants to the user, SYSTEM and
    /// Administrators only.
    #[test]
    fn a_key_file_is_kept_only_when_private_to_the_user() {
        let user = "S-1-5-21-1-2-3-1001";
        let resolve = |s: &str| match s {
            "SY" => SYSTEM_SID.to_string(),
            "BA" => ADMINISTRATORS_SID.to_string(),
            "BU" => "S-1-5-32-545".to_string(),
            "WD" => "S-1-1-0".to_string(),
            other => other.to_string(),
        };
        let ok = |sddl: &str| key_acl_problems(sddl, user, &resolve);
        // As `create_private` makes it, and as the README's icacls leaves one an admin copied in.
        assert!(ok(&format!("O:{user}D:P(A;;FA;;;{user})(A;;FA;;;SY)")).is_empty());
        assert!(ok(&format!(
            "O:BAD:PAI(A;;0x1200a9;;;{user})(A;;FA;;;SY)(A;;FA;;;BA)"
        ))
        .is_empty());
        // A deny entry, or one that applies only to children, does not matter.
        assert!(ok(&format!(
            "O:{user}D:P(D;;FA;;;WD)(A;OICIIO;FA;;;BU)(A;;FA;;;{user})"
        ))
        .is_empty());
        // Another owner (a file planted by another user).
        let p = ok(&format!("O:BUD:P(A;;FA;;;{user})"));
        assert!(p.len() == 1 && p[0].contains("S-1-5-32-545"), "{p:?}");
        // Everyone may read it.
        let p = ok(&format!("O:{user}D:P(A;;FA;;;{user})(A;;FR;;;WD)"));
        assert!(p.len() == 1 && p[0].contains("S-1-1-0"), "{p:?}");
        // Inherits from the folder (a file copied in with Explorer).
        let p = ok(&format!("O:{user}D:AI(A;ID;FA;;;{user})(A;ID;FA;;;SY)"));
        assert!(p.len() == 1 && p[0].contains("inherits"), "{p:?}");
        // No DACL at all, an object entry, no owner.
        assert!(!ok(&format!("O:{user}D:NO_ACCESS_CONTROL")).is_empty());
        assert!(!ok(&format!("O:{user}")).is_empty());
        assert!(!ok(&format!("O:{user}D:P(OA;;FA;x;;{user})")).is_empty());
        assert!(!ok("D:P(A;;FA;;;SY)").is_empty());
    }

    #[test]
    fn the_env_key_remedy_imports_and_checks_before_it_deletes() {
        for location in [
            r"HKCU\Environment (ZKMINER_PRIVATE_KEY)",
            r"HKLM\SYSTEM\CurrentControlSet\Services\zkminer\Parameters (AppEnvironmentExtra)",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment (ZKMINER_PRIVATE_KEY)",
        ] {
            let steps = key_env_move_steps("ZKMINER_PRIVATE_KEY", location);
            let at = |needle: &str| {
                steps
                    .find(needle)
                    .unwrap_or_else(|| panic!("no {needle:?} in {steps}"))
            };
            assert!(at("--import-env-key") < at("zkminer status"), "{steps}");
            assert!(at("zkminer status") < at("delete"), "{steps}");
            assert!(at("delete") < at("rotate"), "{steps}");
            assert!(!steps.contains("--generate-key"), "{steps}");
        }
        assert!(
            key_env_move_steps("ZKMINER_PRIVATE_KEY", r"HKCU\Environment (X)")
                .contains("SetEnvironmentVariable('ZKMINER_PRIVATE_KEY', $null, 'User')")
        );
        assert!(key_env_move_steps("MY_KEY", r"HKCU\Environment (MY_KEY)")
            .contains("--import-env-key --key-env-var MY_KEY"));
        assert!(key_env_move_steps(
            "K",
            r"HKLM\SYSTEM\x\Services\svc\Parameters (AppEnvironmentExtra)"
        )
        .contains("nssm edit"));
    }

    /// HT-1: a path inside a sync client's folder is found, by whole components (without case on
    /// Windows); a sibling with a longer name, or a root naming no folder, is not.
    #[test]
    fn a_path_in_a_cloud_synced_folder_is_found() {
        let base = std::env::temp_dir().join("zkminer-cloud-test");
        let roots = vec![
            ("OneDrive".to_string(), base.join("OneDrive")),
            ("Dropbox".to_string(), base.join("Dropbox")),
        ];
        let found = |p: &std::path::Path, ignore_case| cloud_synced_root(p, &roots, ignore_case);
        let hit = found(&base.join("OneDrive").join("Documents").join("key"), false).unwrap();
        assert!(
            hit.starts_with("OneDrive (") && hit.contains("OneDrive"),
            "{hit}"
        );
        assert!(found(&base.join("Dropbox"), false)
            .unwrap()
            .starts_with("Dropbox"));
        assert!(found(&base.join("OneDrive - Contoso").join("key"), false).is_none());
        assert!(found(&base.join(".zkminer").join("key"), false).is_none());
        assert!(found(&base.join("onedrive").join("key"), false).is_none());
        assert!(found(&base.join("onedrive").join("key"), true).is_some());
        // A variable set to a bare root names no folder: ignored.
        let bare = vec![("OneDrive".to_string(), std::path::PathBuf::from("/"))];
        assert!(cloud_synced_root(&base.join("key"), &bare, false).is_none());
    }

    /// KE-1 (7a): a key file is labelled no-read-up from its creation, so no restore point holds
    /// a copy Low-integrity processes can read; and a file made that way is kept.
    #[cfg(windows)]
    #[test]
    fn a_created_key_file_is_labelled_and_kept() {
        let dir = temp_dir("keylabel");
        let made = dir.join("made");
        let imported = dir.join("imported");
        generate_key_file(&made).unwrap();
        import_key_file(&imported, TEST_KEY).unwrap();
        for path in [&made, &imported] {
            let sddl = win_security::sddl(path, win_security::LABEL).unwrap();
            let sacl = sddl_sections(&sddl).sacl;
            assert!(
                sacl.iter().any(|ace| {
                    let f: Vec<&str> = ace.split(';').collect();
                    f.first() == Some(&"ML")
                        && f.get(2).is_some_and(|p| p.contains("NR"))
                        && f.get(5) == Some(&"ME")
                }),
                "{}: {sddl}",
                path.display()
            );
            check_private(path).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// KE-3 on a real file: one Everyone may read, or one whose ACL inherits from its folder, is
    /// not adopted as the key.
    #[cfg(windows)]
    #[test]
    fn a_key_file_others_can_open_is_not_kept() {
        let dir = temp_dir("keyacl");
        let user = current_user_sid().unwrap();
        let everyone = dir.join("everyone");
        let inherited = dir.join("inherited");
        {
            use std::io::Write;
            let mut f = create_with_sddl(
                &everyone,
                &format!("O:{user}D:P(A;;FA;;;{user})(A;;FR;;;WD)"),
            )
            .unwrap();
            f.write_all(TEST_KEY.as_bytes()).unwrap();
        }
        std::fs::write(&inherited, TEST_KEY).unwrap();
        let e = generate_key_file(&everyone).unwrap_err().to_string();
        assert!(e.contains("S-1-1-0") && e.contains("icacls"), "{e}");
        let e = import_key_file(&inherited, TEST_KEY)
            .unwrap_err()
            .to_string();
        assert!(e.contains("inherits"), "{e}");
        assert_eq!(file_owner_sid(&everyone).as_deref(), Some(user.as_str()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
