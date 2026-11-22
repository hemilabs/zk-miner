//! Old copies of the key in Volume Shadow Copies (restore points), where a Low-integrity worker can
//! read them (review 7 KE-1).
//!
//! The label that keeps Low processes from reading a file ([`crate::windows_sandbox`]) lives in the
//! file's SACL, and a snapshot keeps the SACL a file had when the snapshot was taken. So a copy
//! snapshotted before the miner labelled the file (the key file between `zkminer init` and the
//! first run, an old `.env`, a PowerShell history from before the miner labelled histories) or
//! before the key was removed from it (`NTUSER.DAT` with a `setx` copy of the key's variable) has
//! no label, and its DACL grants this user, whose SID a Low worker's token also holds. A Low process
//! reads it through `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\<path>`.
//!
//! [`inspect`] lists the snapshot devices in the object manager's `\Device` directory (any user may)
//! and looks at each copy of the key file, `~/.zkminer/.env`, PowerShell's command histories and the
//! user's registry hive in the snapshots of the volume that holds them:
//!
//! - an unlabelled copy of the key file this account can read is an exposure;
//! - an unlabelled `.env` or history copy is read here (the miner, at Medium, is trusted with the
//!   key) and searched for the key variable's *name* only; a hit is an exposure. The value is never
//!   looked at or logged, and the buffers are zeroed;
//! - the hive is copied (with its `.LOG1`/`.LOG2`) to a fresh directory Low processes cannot read,
//!   loaded as an application hive (`RegLoadAppKeyW`, no privilege), and `Environment\<variable>`
//!   is checked for existence; the copies are then deleted.
//!
//! What cannot be checked (access denied, a hive that does not load) is "unknown": `zkminer doctor`
//! warns and the miner pages (`SNAPSHOT-UNCHECKED`) but starts its workers. An exposure pages
//! `SECRETS-IN-SNAPSHOT` and keeps Low workers from starting, as `SECRETS-UNLABELLED` does
//! ([`protect`], called from `windows_sandbox::protect_secrets`). The journal is not looked at: it
//! holds no key. Without snapshots this costs one directory listing.
//!
//! The lasting fix is a worker the DACL itself refuses (a restricted token without the user SID,
//! review 7 design 7c), planned, not done here.
//!
//! Manual check, on a test VM only (making snapshots changes the system): as an administrator,
//! `wmic shadowcopy call create Volume=C:\` with an unlabelled test file in place; from a Low
//! process (a copy of `cmd.exe` given `icacls <copy> /setintegritylevel low`), `type
//! \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\<path minus drive>` prints it. Name that file
//! as the key file in a test config: `zkminer doctor` fails with the snapshot named, and `zkminer
//! run` pages `SECRETS-IN-SNAPSHOT` and starts no worker. Delete the snapshot afterwards
//! (`vssadmin delete shadows /shadow={id}`).

use std::ffi::{c_void, OsStr};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};

/// The key variable's name when the configuration names none (`key_env_var`'s default), searched
/// for whatever the key source: a key moved to a file may have been in that variable before.
const DEFAULT_KEY_ENV_VAR: &str = "ZKMINER_PRIVATE_KEY";

/// The object manager's name of a snapshot device, before its number.
const SHADOW_COPY_DEVICE: &str = "HarddiskVolumeShadowCopy";

/// A history or `.env` copy larger than this is not read ("unknown").
const MAX_TEXT_BYTES: u64 = 64 << 20;

type Handle = *mut c_void;
/// A registry key (`HKEY`), as `windows_account` declares it.
type Hkey = isize;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: Handle,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtOpenDirectoryObject(
        handle: *mut Handle,
        access: u32,
        attributes: *const ObjectAttributes,
    ) -> i32;
    fn NtQueryDirectoryObject(
        handle: Handle,
        buffer: *mut c_void,
        length: u32,
        single_entry: u8,
        restart_scan: u8,
        context: *mut u32,
        returned: *mut u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetVolumePathNameW(path: *const u16, mount: *mut u16, length: u32) -> i32;
    fn GetVolumeInformationW(
        root: *const u16,
        name: *mut u16,
        name_length: u32,
        serial: *mut u32,
        max_component: *mut u32,
        flags: *mut u32,
        fs_name: *mut u16,
        fs_name_length: u32,
    ) -> i32;
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
extern "system" {
    fn GetSecurityInfo(
        handle: Handle,
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
        sddl: *mut *mut u16,
        length: *mut u32,
    ) -> i32;
    fn RegLoadAppKeyW(
        file: *const u16,
        key: *mut Hkey,
        access: u32,
        options: u32,
        reserved: u32,
    ) -> i32;
    fn RegOpenKeyExW(
        key: Hkey,
        sub_key: *const u16,
        options: u32,
        access: u32,
        out: *mut Hkey,
    ) -> i32;
    fn RegQueryValueExW(
        key: Hkey,
        name: *const u16,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        length: *mut u32,
    ) -> i32;
    fn RegCloseKey(key: Hkey) -> i32;
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

/// What [`inspect`] found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SnapshotReport {
    /// Copies of the key a Low-integrity worker can read, each named with its snapshot.
    pub exposed: Vec<String>,
    /// What could not be checked, and why.
    pub unknown: Vec<String>,
}

impl SnapshotReport {
    /// With an exposure: what was found and the remedy (`SECRETS-IN-SNAPSHOT`).
    pub fn refusal(&self) -> Option<String> {
        (!self.exposed.is_empty()).then(|| {
            format!(
                "old copies of the key are kept in Volume Shadow Copies (restore points), where a \
                 Low-integrity worker can read them: {}. A snapshot keeps a file as it was, label \
                 included, so a copy taken before the miner labelled the file (or before the key \
                 was removed from it) is open to the workers. No Low worker is started until they \
                 are gone: as an administrator, run `vssadmin list shadows` to find the snapshot \
                 whose \"Shadow Copy Volume\" is the device named above and `vssadmin delete \
                 shadows /shadow={{id}}` (or System Protection > Configure > Delete, which deletes \
                 every restore point of that drive; either way those restore points are lost). \
                 Then treat the key as exposed and rotate it: unstake, withdraw, and move the HEMI \
                 to a new key",
                self.exposed.join("; ")
            )
        })
    }

    /// With something unchecked: what, and what to do (`SNAPSHOT-UNCHECKED`; no refusal).
    pub fn warning(&self) -> Option<String> {
        (!self.unknown.is_empty()).then(|| {
            format!(
                "Volume Shadow Copies (restore points) could not be fully checked for old, \
                 unlabelled copies of the key, which a Low-integrity worker could read: {}. The \
                 workers still start. If the key was ever in a file, in .env, typed at a \
                 PowerShell prompt or set with setx before the miner labelled or removed it, \
                 delete the restore points made before then (as an administrator, `vssadmin list \
                 shadows`, then `vssadmin delete shadows /shadow={{id}}`, or System Protection > \
                 Configure > Delete) and treat the key as exposed",
                self.unknown.join("; ")
            )
        })
    }
}

/// [`inspect`] for the miner's start, with the account's home and roaming application data: pages
/// `SECRETS-IN-SNAPSHOT` (and returns it, so that no Low worker starts) on an exposure, and
/// `SNAPSHOT-UNCHECKED` on what could not be checked.
pub(crate) fn protect(key_file: Option<&Path>, key_env_var: Option<&str>) -> Result<(), String> {
    let report = inspect(
        key_file,
        key_env_var,
        dirs::home_dir().as_deref(),
        dirs::config_dir().as_deref(),
    );
    if let Some(warning) = report.warning() {
        tracing::warn!("PAGE: SNAPSHOT-UNCHECKED — {warning}");
    }
    match report.refusal() {
        Some(why) => {
            tracing::error!("PAGE: SECRETS-IN-SNAPSHOT — {why}");
            Err(why)
        }
        None => Ok(()),
    }
}

/// What may hold the key, by how its copies are judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The key file: an unlabelled copy this account can read is an exposure.
    KeyFile,
    /// `.env` or a command history: an unlabelled copy is searched for the variable's name.
    Text,
    /// The user's registry hive (`NTUSER.DAT`): `Environment\<variable>` is looked for.
    Hive,
}

/// A live path and what it is; a history directory is listed in each snapshot instead, so that
/// histories deleted since are seen too.
enum Target {
    File(PathBuf, Kind),
    HistoryDir(PathBuf),
}

/// The copies of the key file, `<home>/.zkminer/.env`, the command histories below `appdata`
/// (PSReadLine's, as `windows_sandbox::command_histories` names them) and `<home>/NTUSER.DAT` in
/// the snapshots of their volumes that a Low-integrity worker can read, and what could not be
/// checked. Reads label metadata, and the copies of `.env`, histories and the hive as described in
/// the module docs; never a live file's contents.
pub fn inspect(
    key_file: Option<&Path>,
    key_env_var: Option<&str>,
    home: Option<&Path>,
    appdata: Option<&Path>,
) -> SnapshotReport {
    let mut report = SnapshotReport::default();
    let devices = match shadow_copy_devices() {
        Ok(devices) => devices,
        Err(e) => {
            report
                .unknown
                .push(format!("the list of snapshots could not be read ({e})"));
            return report;
        }
    };
    if devices.is_empty() {
        return report;
    }
    let names = key_var_names(key_env_var);
    let mut targets: Vec<Target> = Vec::new();
    if let Some(key) = key_file {
        targets.push(Target::File(key.to_path_buf(), Kind::KeyFile));
    }
    if let Some(home) = home {
        targets.push(Target::File(home.join(".zkminer").join(".env"), Kind::Text));
        targets.push(Target::File(home.join("NTUSER.DAT"), Kind::Hive));
    }
    if let Some(appdata) = appdata {
        targets.push(Target::HistoryDir(
            appdata
                .join("Microsoft")
                .join("Windows")
                .join("PowerShell")
                .join("PSReadLine"),
        ));
    }
    // Each snapshot's volume serial, read once: a snapshot is a block copy of its volume, serial
    // included.
    // A snapshot device that no longer answers (deleted, or its storage gone while the name
    // lingers) holds no copy anyone can open, a Low worker included: it is skipped rather than
    // called unchecked.
    let serials: Vec<io::Result<u32>> = devices
        .iter()
        .map(|device| volume_serial(Path::new(&format!(r"\\?\GLOBALROOT\Device\{device}\"))))
        .collect();
    for target in &targets {
        let live = match target {
            Target::File(path, _) | Target::HistoryDir(path) => path,
        };
        // A relative key file path, as the miner would open it.
        let absolute = std::path::absolute(live).unwrap_or_else(|_| live.clone());
        let live = &absolute;
        let Some(mount) = mount_point(live) else {
            report
                .unknown
                .push(format!("{}: its volume could not be told", live.display()));
            continue;
        };
        let serial = volume_serial(&mount).ok();
        for (device, snapshot_serial) in devices.iter().zip(&serials) {
            if snapshot_serial.as_ref().is_err_and(device_gone) {
                continue;
            }
            // Another volume's snapshot (when both serials are known).
            if matches!((serial, snapshot_serial), (Some(a), Ok(b)) if a != *b) {
                continue;
            }
            let Some(copy) = snapshot_path(device, &mount, live) else {
                continue;
            };
            match target {
                Target::File(_, kind) => {
                    record(&mut report, live, device, judge(&copy, *kind, &names))
                }
                Target::HistoryDir(_) => match std::fs::read_dir(&copy) {
                    Ok(entries) => {
                        let mut files: Vec<PathBuf> = entries
                            .flatten()
                            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                            .map(|e| e.path())
                            .filter(|p| is_history_file(p))
                            .collect();
                        files.sort();
                        for file in files {
                            let shown = live.join(file.file_name().unwrap_or_default());
                            record(
                                &mut report,
                                &shown,
                                device,
                                judge(&file, Kind::Text, &names),
                            );
                        }
                    }
                    Err(e) if is_absent(&e) => {}
                    Err(e) => report.unknown.push(format!(
                        "{} in {device}: could not be listed ({e})",
                        live.display()
                    )),
                },
            }
        }
    }
    report
}

/// The variable names searched for: the configured one, and the default.
fn key_var_names(key_env_var: Option<&str>) -> Vec<String> {
    let mut names = vec![DEFAULT_KEY_ENV_VAR.to_string()];
    if let Some(var) = key_env_var.filter(|v| !v.is_empty()) {
        if !names.iter().any(|n| n.eq_ignore_ascii_case(var)) {
            names.push(var.to_string());
        }
    }
    names
}

fn is_history_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.to_ascii_lowercase().ends_with("_history.txt"))
}

fn record(report: &mut SnapshotReport, live: &Path, device: &str, verdict: Verdict) {
    match verdict {
        Verdict::Absent | Verdict::Safe => {}
        Verdict::Exposed(why) => report
            .exposed
            .push(format!("{} as kept in {device} ({why})", live.display())),
        Verdict::Unknown(why) => report
            .unknown
            .push(format!("{} as kept in {device} ({why})", live.display())),
    }
}

/// How a copy was judged.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Not in this snapshot.
    Absent,
    /// Labelled, or holding no copy of the key.
    Safe,
    Exposed(String),
    Unknown(String),
}

/// A copy's label.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Label {
    Absent,
    /// One that keeps Low processes from reading it.
    NoReadUp,
    /// None, or one Low processes read through.
    Open,
    Unreadable(String),
}

/// What a look inside an unlabelled copy found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Content {
    /// The copy is readable and holds the key (the key file), or the variable's name.
    Hit,
    Miss,
    Unreadable(String),
}

/// The verdict on a copy of `kind` with `label`, looking inside (`look`) only an unlabelled one.
fn verdict(kind: Kind, label: Label, look: impl FnOnce() -> Content) -> Verdict {
    match label {
        Label::Absent => Verdict::Absent,
        Label::NoReadUp => Verdict::Safe,
        Label::Unreadable(e) => Verdict::Unknown(format!("its label could not be read: {e}")),
        Label::Open => match (kind, look()) {
            (Kind::KeyFile, Content::Hit) => {
                Verdict::Exposed("an unlabelled copy of the key file".to_string())
            }
            (Kind::Text, Content::Hit) => {
                Verdict::Exposed("an unlabelled copy that names the key's variable".to_string())
            }
            (Kind::Hive, Content::Hit) => Verdict::Exposed(
                "the user's registry environment kept the key's variable (setx)".to_string(),
            ),
            (_, Content::Miss) => Verdict::Safe,
            (_, Content::Unreadable(e)) => {
                Verdict::Unknown(format!("unlabelled, but could not be read here: {e}"))
            }
        },
    }
}

/// [`verdict`] on the snapshot copy `copy`.
fn judge(copy: &Path, kind: Kind, names: &[String]) -> Verdict {
    verdict(kind, label_of(copy), || match kind {
        Kind::KeyFile => match std::fs::File::open(copy) {
            Ok(_) => Content::Hit,
            Err(e) => Content::Unreadable(e.to_string()),
        },
        Kind::Text => search_file(copy, names),
        Kind::Hive => hive_check(copy, names),
    })
}

/// Whether `e` says the file (or a directory above it) is not there.
fn is_absent(e: &io::Error) -> bool {
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PATH_NOT_FOUND: i32 = 3;
    e.kind() == io::ErrorKind::NotFound
        || matches!(
            e.raw_os_error(),
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
        )
}

/// The label of `path`, read through a handle opened for `READ_CONTROL` only.
fn label_of(path: &Path) -> Label {
    match read_label_sddl(path) {
        Ok(sddl) => label_from_sddl(&sddl),
        Err(e) if is_absent(&e) => Label::Absent,
        Err(e) => Label::Unreadable(e.to_string()),
    }
}

/// [`Label`] from a label's SDDL (`S:(ML;;NWNR;;;ME)`, or nothing for none).
fn label_from_sddl(sddl: &str) -> Label {
    if crate::windows_sandbox::label_keeps_low_from_reading(sddl) {
        Label::NoReadUp
    } else {
        Label::Open
    }
}

fn read_label_sddl(path: &Path) -> io::Result<String> {
    const READ_CONTROL: u32 = 0x0002_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const LABEL_SECURITY_INFORMATION: u32 = 0x10;
    const SE_FILE_OBJECT: i32 = 1;
    let file = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL)
        .share_mode(0x7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: an open handle and out-pointers; the descriptor is freed below.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let (mut text, mut length) = (std::ptr::null_mut(), 0u32);
    // SAFETY: a valid descriptor and out-pointers; the string (its length in UTF-16 units, the NUL
    // included) and the descriptor are freed here.
    unsafe {
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            LABEL_SECURITY_INFORMATION,
            &mut text,
            &mut length,
        );
        let result = if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            let units = std::slice::from_raw_parts(text, length.saturating_sub(1) as usize);
            let sddl = String::from_utf16_lossy(units);
            LocalFree(text.cast());
            Ok(sddl.trim_end_matches('\0').to_string())
        };
        LocalFree(descriptor);
        result
    }
}

/// Bytes zeroed when dropped: a copy that may hold the key.
struct Zeroed(Vec<u8>);

impl Drop for Zeroed {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            // SAFETY: a valid, aligned `u8` of this vector; volatile so the write is kept.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Whether `copy` names any of `names` ([`mentions_name`]). Its bytes are held only here, zeroed.
fn search_file(copy: &Path, names: &[String]) -> Content {
    let mut file = match std::fs::File::open(copy) {
        Ok(f) => f,
        Err(e) => return Content::Unreadable(e.to_string()),
    };
    let length = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => return Content::Unreadable(e.to_string()),
    };
    if length > MAX_TEXT_BYTES {
        return Content::Unreadable(format!("larger than {} MiB", MAX_TEXT_BYTES >> 20));
    }
    // Room for it all, so that reading never moves (and leaves behind) a partial copy.
    let mut bytes = Zeroed(Vec::with_capacity(length as usize + 1));
    if let Err(e) = (&mut file).take(MAX_TEXT_BYTES).read_to_end(&mut bytes.0) {
        return Content::Unreadable(e.to_string());
    }
    if names.iter().any(|name| mentions_name(&bytes.0, name)) {
        Content::Hit
    } else {
        Content::Miss
    }
}

/// Whether `haystack` holds `name` (ASCII, case-insensitive) as a whole word: not inside a longer
/// identifier. Names only: `$env:ZKMINER_PRIVATE_KEY = ...`, `ZKMINER_PRIVATE_KEY=...`, `setx
/// ZKMINER_PRIVATE_KEY ...` all match.
fn mentions_name(haystack: &[u8], name: &str) -> bool {
    let needle = name.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    (0..=haystack.len() - needle.len()).any(|at| {
        haystack[at..at + needle.len()].eq_ignore_ascii_case(needle)
            && (at == 0 || !ident(haystack[at - 1]))
            && haystack.get(at + needle.len()).is_none_or(|&b| !ident(b))
    })
}

/// Whether the hive `copy` (a snapshot's `NTUSER.DAT`) keeps any of `names` in `Environment`:
/// copied with its logs to a fresh directory Low processes cannot read, loaded there, and deleted.
fn hive_check(copy: &Path, names: &[String]) -> Content {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zkminer-hive-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let checked = (|| -> io::Result<bool> {
        crate::windows_sandbox::make_no_read_up_dir(&dir)?;
        let hive = dir.join("ntuser.dat");
        copy_zeroed(copy, &hive)?;
        for log in ["LOG1", "LOG2"] {
            let mut from = copy.as_os_str().to_os_string();
            from.push(format!(".{log}"));
            // A missing or unreadable log: the hive loads (or fails to) without it.
            let _ = copy_zeroed(Path::new(&from), &dir.join(format!("ntuser.dat.{log}")));
        }
        hive_has_env_value(&hive, names)
    })();
    remove_dir_retrying(&dir);
    match checked {
        Ok(true) => Content::Hit,
        Ok(false) => Content::Miss,
        Err(e) => Content::Unreadable(e.to_string()),
    }
}

/// Copy `from` to a new file `to` through a buffer zeroed afterwards.
fn copy_zeroed(from: &Path, to: &Path) -> io::Result<()> {
    let mut input = std::fs::File::open(from)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)?;
    let mut buffer = Zeroed(vec![0u8; 64 << 10]);
    loop {
        let n = input.read(&mut buffer.0)?;
        if n == 0 {
            return Ok(());
        }
        output.write_all(&buffer.0[..n])?;
    }
}

/// Remove `dir`, waiting briefly for an unloaded hive's file to be let go.
fn remove_dir_retrying(dir: &Path) {
    for _ in 0..20 {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => return,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
    tracing::warn!("could not remove {}", dir.display());
}

/// An open registry key, closed on drop (an application hive is unloaded with its last key).
struct Key(Hkey);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: a key this value opened.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Whether the hive file `hive` has any of `names` in its `Environment` key. Existence only: no
/// value's data is read.
fn hive_has_env_value(hive: &Path, names: &[String]) -> io::Result<bool> {
    const KEY_READ: u32 = 0x0002_0019;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const REG_PROCESS_APPKEY: u32 = 0x1;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    let file = wide(hive.as_os_str());
    let mut root: Hkey = 0;
    // SAFETY: a NUL-terminated path and an out-pointer; the key is owned at once.
    let status =
        unsafe { RegLoadAppKeyW(file.as_ptr(), &mut root, KEY_READ, REG_PROCESS_APPKEY, 0) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    let root = Key(root);
    let sub = wide(OsStr::new("Environment"));
    let mut env: Hkey = 0;
    // SAFETY: an open key, a NUL-terminated name and an out-pointer; the key is owned at once.
    let status = unsafe { RegOpenKeyExW(root.0, sub.as_ptr(), 0, KEY_QUERY_VALUE, &mut env) };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(false);
    }
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    let env = Key(env);
    for name in names {
        let value = wide(OsStr::new(name));
        // SAFETY: an open key and a NUL-terminated name; no data is asked for.
        let status = unsafe {
            RegQueryValueExW(
                env.0,
                value.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        match status {
            0 => return Ok(true),
            ERROR_FILE_NOT_FOUND => {}
            e => return Err(io::Error::from_raw_os_error(e)),
        }
    }
    Ok(false)
}

/// The mount point of the volume holding `path` (`C:\`), which need not exist.
fn mount_point(path: &Path) -> Option<PathBuf> {
    let name = wide(path.as_os_str());
    let mut buffer = vec![0u16; 1024];
    // SAFETY: a NUL-terminated path and a buffer of the length given.
    let ok = unsafe { GetVolumePathNameW(name.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    if ok != 0 {
        let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        return Some(PathBuf::from(String::from_utf16_lossy(&buffer[..end])));
    }
    // The drive's root, for want of better.
    match path.components().next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
                Some(PathBuf::from(format!("{}:\\", d as char)))
            }
            _ => None,
        },
        _ => None,
    }
}

/// Whether `e`, from opening a snapshot device's root, says the device is not there at all.
fn device_gone(e: &io::Error) -> bool {
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PATH_NOT_FOUND: i32 = 3;
    const ERROR_DEV_NOT_EXIST: i32 = 55;
    const ERROR_NO_SUCH_DEVICE: i32 = 433;
    matches!(
        e.raw_os_error(),
        Some(
            ERROR_FILE_NOT_FOUND
                | ERROR_PATH_NOT_FOUND
                | ERROR_DEV_NOT_EXIST
                | ERROR_NO_SUCH_DEVICE
        )
    )
}

/// The serial number of the volume whose root is `root`.
fn volume_serial(root: &Path) -> io::Result<u32> {
    let mut root = root.as_os_str().to_os_string();
    if !root.to_string_lossy().ends_with('\\') {
        root.push("\\");
    }
    let name = wide(&root);
    let mut serial = 0u32;
    // SAFETY: a NUL-terminated path and one out-pointer; the rest are not asked for.
    let ok = unsafe {
        GetVolumeInformationW(
            name.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(serial)
}

/// `path`'s parts: the drive (`C:`) and each name; `None` for a path that is not on a drive or
/// climbs (`..`).
fn parts(path: &Path) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(p) => match p.kind() {
                Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
                    out.push(format!("{}:", (d as char).to_ascii_uppercase()))
                }
                _ => return None,
            },
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => return None,
            Component::Normal(name) => out.push(name.to_str()?.to_string()),
        }
    }
    (!out.is_empty()).then_some(out)
}

/// `live` as kept in the snapshot device `device` of the volume mounted at `mount`:
/// `\\?\GLOBALROOT\Device\<device>\<live below mount>`. `None` if `live` is not below `mount`.
fn snapshot_path(device: &str, mount: &Path, live: &Path) -> Option<PathBuf> {
    let (mount, live) = (parts(mount)?, parts(live)?);
    if live.len() <= mount.len()
        || !mount
            .iter()
            .zip(&live)
            .all(|(a, b)| a.to_lowercase() == b.to_lowercase())
    {
        return None;
    }
    Some(PathBuf::from(format!(
        r"\\?\GLOBALROOT\Device\{device}\{}",
        live[mount.len()..].join("\\")
    )))
}

/// The snapshot devices in the object manager's `\Device` directory (`HarddiskVolumeShadowCopy<N>`),
/// by number. Listing it needs no privilege.
fn shadow_copy_devices() -> io::Result<Vec<String>> {
    Ok(shadow_copies_in(&list_object_directory(r"\Device")?))
}

/// Those of `entries` (name, type) that are snapshot devices, by number.
fn shadow_copies_in(entries: &[(String, String)]) -> Vec<String> {
    let mut found: Vec<(u64, String)> = entries
        .iter()
        .filter(|(_, kind)| kind == "Device")
        .filter_map(|(name, _)| {
            let digits = name.strip_prefix(SHADOW_COPY_DEVICE)?;
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some((digits.parse().ok()?, name.clone()))
        })
        .collect();
    found.sort();
    found.dedup();
    found.into_iter().map(|(_, name)| name).collect()
}

fn nt_error(status: i32) -> io::Error {
    // SAFETY: a plain conversion.
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

/// Every (name, type) in the object directory `dir`.
fn list_object_directory(dir: &str) -> io::Result<Vec<(String, String)>> {
    const DIRECTORY_QUERY: u32 = 0x0001;
    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001A_u32 as i32;
    let mut name: Vec<u16> = dir.encode_utf16().collect();
    let bytes = (name.len() * 2) as u16;
    let unicode = UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: name.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: std::ptr::null_mut(),
        object_name: &unicode,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut handle = std::ptr::null_mut();
    // SAFETY: valid attributes naming a live string, and an out-pointer; the handle is owned at once.
    let status = unsafe { NtOpenDirectoryObject(&mut handle, DIRECTORY_QUERY, &attributes) };
    if status < 0 {
        return Err(nt_error(status));
    }
    // SAFETY: a handle just opened, closed by `OwnedHandle`.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    // u64s, so the entries (pointers) are aligned.
    let mut buffer = vec![0u64; 8 << 10];
    let length = (buffer.len() * 8) as u32;
    let (mut context, mut restart, mut entries) = (0u32, 1u8, Vec::new());
    for _ in 0..100_000 {
        buffer.fill(0);
        let mut returned = 0u32;
        // SAFETY: an open directory handle, a buffer of `length` bytes, and out-pointers.
        let status = unsafe {
            NtQueryDirectoryObject(
                handle.as_raw_handle(),
                buffer.as_mut_ptr().cast(),
                length,
                0,
                restart,
                &mut context,
                &mut returned,
            )
        };
        restart = 0;
        if status == STATUS_NO_MORE_ENTRIES {
            break;
        }
        if status < 0 {
            return Err(nt_error(status));
        }
        // SAFETY: the same buffer, as bytes.
        let view =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), length as usize) };
        let batch = parse_directory_buffer(view);
        if batch.is_empty() {
            break;
        }
        // `STATUS_MORE_ENTRIES`, or `STATUS_SUCCESS`, which may still leave entries for the next
        // call: only "no more entries" (or an empty batch) ends it.
        entries.extend(batch);
    }
    Ok(entries)
}

/// The (name, type) entries of an `NtQueryDirectoryObject` buffer: `OBJECT_DIRECTORY_INFORMATION`s
/// (two `UNICODE_STRING`s each, whose pointers point into the buffer), ended by an empty one. An
/// entry whose strings fall outside the buffer is skipped.
fn parse_directory_buffer(buffer: &[u8]) -> Vec<(String, String)> {
    const PTR: usize = std::mem::size_of::<usize>();
    // UNICODE_STRING: two u16s, padding to the pointer, the pointer.
    const STRING: usize = 2 * PTR;
    const ENTRY: usize = 2 * STRING;
    let base = buffer.as_ptr() as usize;
    let string_at = |at: usize| -> Option<Option<String>> {
        let length = u16::from_le_bytes(buffer.get(at..at + 2)?.try_into().ok()?) as usize;
        let pointer = usize::from_le_bytes(buffer.get(at + PTR..at + 2 * PTR)?.try_into().ok()?);
        if length == 0 && pointer == 0 {
            return Some(None);
        }
        let start = pointer.checked_sub(base)?;
        let bytes = buffer.get(start..start.checked_add(length)?)?;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(Some(String::from_utf16_lossy(&units)))
    };
    let mut out = Vec::new();
    let mut at = 0;
    while at + ENTRY <= buffer.len() {
        let name = string_at(at);
        let kind = string_at(at + STRING);
        match (name, kind) {
            // The empty entry that ends the list.
            (Some(None), Some(None)) => break,
            (Some(Some(name)), Some(Some(kind))) => out.push((name, kind)),
            _ => {}
        }
        at += ENTRY;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_device_that_is_gone_is_skipped_not_unchecked() {
        for code in [2, 3, 55, 433] {
            assert!(device_gone(&io::Error::from_raw_os_error(code)), "{code}");
        }
        // Access denied or a busy device is not "gone": that stays unchecked.
        for code in [5, 21, 32] {
            assert!(!device_gone(&io::Error::from_raw_os_error(code)), "{code}");
        }
    }

    #[test]
    fn a_path_maps_into_the_snapshot_of_its_volume() {
        let device = "HarddiskVolumeShadowCopy7";
        assert_eq!(
            snapshot_path(
                device,
                Path::new(r"C:\"),
                Path::new(r"C:\Users\u\.zkminer\.env")
            ),
            Some(PathBuf::from(
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7\Users\u\.zkminer\.env"
            ))
        );
        // Drive letters and names compare without case; a verbatim path maps the same.
        assert_eq!(
            snapshot_path(device, Path::new(r"C:\"), Path::new(r"\\?\c:\Keys\k.hex")),
            Some(PathBuf::from(
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7\Keys\k.hex"
            ))
        );
        // A volume mounted in a folder: the path below the mount point.
        assert_eq!(
            snapshot_path(
                device,
                Path::new(r"C:\Mnt\Data\"),
                Path::new(r"c:\mnt\data\k.hex")
            ),
            Some(PathBuf::from(
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7\k.hex"
            ))
        );
        // Not below the mount point, the mount point itself, a climb, a share.
        assert_eq!(
            snapshot_path(device, Path::new(r"D:\"), Path::new(r"C:\k.hex")),
            None
        );
        assert_eq!(
            snapshot_path(device, Path::new(r"C:\"), Path::new(r"C:\")),
            None
        );
        assert_eq!(
            snapshot_path(device, Path::new(r"C:\"), Path::new(r"C:\a\..\k.hex")),
            None
        );
        assert_eq!(
            snapshot_path(
                device,
                Path::new(r"C:\"),
                Path::new(r"\\server\share\k.hex")
            ),
            None
        );
    }

    #[test]
    fn labels_and_verdicts() {
        assert_eq!(label_from_sddl("S:(ML;;NWNR;;;ME)"), Label::NoReadUp);
        assert_eq!(label_from_sddl("S:(ML;;NW;;;ME)"), Label::Open);
        assert_eq!(label_from_sddl("S:(ML;;NWNR;;;LW)"), Label::Open);
        assert_eq!(label_from_sddl(""), Label::Open);

        let never = || -> Content { panic!("a labelled or missing copy is never read") };
        assert_eq!(
            verdict(Kind::KeyFile, Label::Absent, never),
            Verdict::Absent
        );
        assert_eq!(
            verdict(Kind::KeyFile, Label::NoReadUp, never),
            Verdict::Safe
        );
        assert!(matches!(
            verdict(Kind::Text, Label::Unreadable("denied".into()), never),
            Verdict::Unknown(_)
        ));
        for kind in [Kind::KeyFile, Kind::Text, Kind::Hive] {
            assert!(matches!(
                verdict(kind, Label::Open, || Content::Hit),
                Verdict::Exposed(_)
            ));
            assert_eq!(verdict(kind, Label::Open, || Content::Miss), Verdict::Safe);
            // Access denied to this account: unknown, never an exposure.
            assert!(matches!(
                verdict(kind, Label::Open, || Content::Unreadable("denied".into())),
                Verdict::Unknown(_)
            ));
        }
    }

    #[test]
    fn a_report_refuses_only_on_an_exposure() {
        let mut report = SnapshotReport::default();
        assert_eq!((report.refusal(), report.warning()), (None, None));
        report
            .unknown
            .push("x as kept in HarddiskVolumeShadowCopy3 (denied)".into());
        assert!(report.refusal().is_none());
        assert!(report
            .warning()
            .unwrap()
            .contains("HarddiskVolumeShadowCopy3"));
        report
            .exposed
            .push("k as kept in HarddiskVolumeShadowCopy4 (unlabelled)".into());
        let refusal = report.refusal().unwrap();
        assert!(refusal.contains("HarddiskVolumeShadowCopy4"));
        assert!(refusal.contains("vssadmin delete shadows /shadow={id}"));
        assert!(refusal.contains("rotate"));
    }

    #[test]
    fn the_name_is_found_as_a_whole_word_only() {
        let name = "ZKMINER_PRIVATE_KEY";
        for text in [
            &b"$env:ZKMINER_PRIVATE_KEY = \"0xabc\"\r\n"[..],
            b"zkminer_private_key=0xabc",
            b"cd x\nsetx ZKMINER_PRIVATE_KEY 0xabc\n",
            b"ZKMINER_PRIVATE_KEY",
        ] {
            assert!(
                mentions_name(text, name),
                "{}",
                String::from_utf8_lossy(text)
            );
        }
        for text in [
            &b""[..],
            b"ZKMINER_PRIVATE_KEY_FILE=C:\\k",
            b"MY_ZKMINER_PRIVATE_KEY=1",
            b"ZKMINER_PRIVATE_KE",
            b"cargo build --release",
        ] {
            assert!(
                !mentions_name(text, name),
                "{}",
                String::from_utf8_lossy(text)
            );
        }
        assert_eq!(key_var_names(None), vec![DEFAULT_KEY_ENV_VAR.to_string()]);
        assert_eq!(
            key_var_names(Some("zkminer_private_key")),
            vec![DEFAULT_KEY_ENV_VAR.to_string()]
        );
        assert_eq!(
            key_var_names(Some("MY_KEY")),
            vec![DEFAULT_KEY_ENV_VAR.to_string(), "MY_KEY".to_string()]
        );
    }

    #[test]
    fn a_text_copy_is_searched_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let (with, without) = (dir.path().join("a_history.txt"), dir.path().join("b.txt"));
        std::fs::write(&with, "ls\n$env:MY_KEY = 'not-a-key'\n").unwrap();
        std::fs::write(&without, "ls\n").unwrap();
        let names = key_var_names(Some("MY_KEY"));
        assert_eq!(search_file(&with, &names), Content::Hit);
        assert_eq!(search_file(&without, &names), Content::Miss);
        assert!(matches!(
            search_file(&dir.path().join("none"), &names),
            Content::Unreadable(_)
        ));
        assert!(is_history_file(&with) && !is_history_file(&without));
    }

    /// Builds an `NtQueryDirectoryObject` buffer for `entries`, its pointers into itself.
    fn fake_listing(entries: &[(&str, &str)], corrupt: Option<usize>) -> Vec<u8> {
        const PTR: usize = std::mem::size_of::<usize>();
        let entry = 4 * PTR;
        let strings_at = entry * (entries.len() + 1);
        let total = strings_at
            + entries
                .iter()
                .map(|(n, t)| 2 * (n.len() + t.len()))
                .sum::<usize>();
        let mut buffer = vec![0u8; total];
        let base = buffer.as_ptr() as usize;
        let mut next = strings_at;
        for (i, (name, kind)) in entries.iter().enumerate() {
            for (j, text) in [name, kind].into_iter().enumerate() {
                let at = i * entry + j * 2 * PTR;
                let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
                buffer[at..at + 2].copy_from_slice(&(units.len() as u16).to_le_bytes());
                buffer[at + 2..at + 4].copy_from_slice(&(units.len() as u16).to_le_bytes());
                let pointer = if corrupt == Some(i) { 16 } else { base + next };
                buffer[at + PTR..at + 2 * PTR].copy_from_slice(&pointer.to_le_bytes());
                buffer[next..next + units.len()].copy_from_slice(&units);
                next += units.len();
            }
        }
        buffer
    }

    #[test]
    fn snapshot_devices_are_picked_from_a_directory_listing() {
        let listing = fake_listing(
            &[
                ("HarddiskVolume3", "Device"),
                ("HarddiskVolumeShadowCopy12", "Device"),
                ("HarddiskVolumeShadowCopy7", "Device"),
                ("HarddiskVolumeShadowCopy", "Device"),
                ("HarddiskVolumeShadowCopy9x", "Device"),
                ("HarddiskVolumeShadowCopy8", "SymbolicLink"),
                ("HarddiskVolumeShadowCopy5", "Device"),
            ],
            Some(6),
        );
        let entries = parse_directory_buffer(&listing);
        // The last entry's strings point outside the buffer: skipped.
        assert_eq!(entries.len(), 6);
        assert_eq!(entries[0], ("HarddiskVolume3".into(), "Device".into()));
        assert_eq!(
            shadow_copies_in(&entries),
            vec!["HarddiskVolumeShadowCopy7", "HarddiskVolumeShadowCopy12"]
        );
        assert!(parse_directory_buffer(&fake_listing(&[], None)).is_empty());
        assert!(parse_directory_buffer(&[]).is_empty());
    }

    /// A hive made here (`RegLoadAppKeyW` makes one for a missing file), with and without the
    /// variable, read back as a snapshot's copy would be.
    #[test]
    fn a_hive_copy_is_checked_for_the_variable() {
        const KEY_ALL_ACCESS: u32 = 0x000F_003F;
        const REG_SZ: u32 = 1;
        #[link(name = "advapi32")]
        extern "system" {
            fn RegCreateKeyExW(
                key: Hkey,
                sub_key: *const u16,
                reserved: u32,
                class: *const u16,
                options: u32,
                access: u32,
                security: *const c_void,
                out: *mut Hkey,
                disposition: *mut u32,
            ) -> i32;
            fn RegSetValueExW(
                key: Hkey,
                name: *const u16,
                reserved: u32,
                kind: u32,
                data: *const u8,
                length: u32,
            ) -> i32;
        }
        let dir = tempfile::tempdir().unwrap();
        let make = |file: &Path, var: Option<&str>| {
            let name = wide(file.as_os_str());
            let mut root: Hkey = 0;
            // SAFETY: test FFI on a hive file in a temporary directory.
            unsafe {
                assert_eq!(
                    RegLoadAppKeyW(name.as_ptr(), &mut root, KEY_ALL_ACCESS, 1, 0),
                    0
                );
                let root = Key(root);
                let mut env: Hkey = 0;
                let sub = wide(OsStr::new("Environment"));
                assert_eq!(
                    RegCreateKeyExW(
                        root.0,
                        sub.as_ptr(),
                        0,
                        std::ptr::null(),
                        0,
                        KEY_ALL_ACCESS,
                        std::ptr::null(),
                        &mut env,
                        std::ptr::null_mut()
                    ),
                    0
                );
                let env = Key(env);
                if let Some(var) = var {
                    let value = wide(OsStr::new(var));
                    let data = [b'x', 0, 0, 0];
                    assert_eq!(
                        RegSetValueExW(env.0, value.as_ptr(), 0, REG_SZ, data.as_ptr(), 4),
                        0
                    );
                }
            }
        };
        let (with, without) = (dir.path().join("with.dat"), dir.path().join("without.dat"));
        make(&with, Some("MY_KEY"));
        make(&without, Some("OTHER"));
        let names = key_var_names(Some("MY_KEY"));
        // The hives are let go when their keys close; retry briefly.
        let check = |hive: &Path| {
            for _ in 0..20 {
                match hive_check(hive, &names) {
                    Content::Unreadable(_) => {
                        std::thread::sleep(std::time::Duration::from_millis(50))
                    }
                    found => return found,
                }
            }
            hive_check(hive, &names)
        };
        assert_eq!(check(&with), Content::Hit);
        assert_eq!(check(&without), Content::Miss);
        assert!(matches!(
            hive_check(&dir.path().join("none.dat"), &names),
            Content::Unreadable(_)
        ));
        assert_eq!(
            verdict(Kind::Hive, Label::Open, || check(&with)),
            Verdict::Exposed(
                "the user's registry environment kept the key's variable (setx)".to_string()
            )
        );
    }

    /// The label of a file made here, read the way a snapshot's copy is.
    #[test]
    fn a_copy_label_is_read_through_its_handle() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        std::fs::write(&plain, "x").unwrap();
        assert_eq!(label_of(&plain), Label::Open);
        // A file made in a no-read-up directory inherits its label.
        let private = dir.path().join("private");
        crate::windows_sandbox::make_no_read_up_dir(&private).unwrap();
        let labelled = private.join("labelled");
        std::fs::write(&labelled, "x").unwrap();
        assert_eq!(label_of(&labelled), Label::NoReadUp);
        assert_eq!(label_of(&dir.path().join("none")), Label::Absent);
        assert_eq!(label_of(&dir.path().join("no").join("none")), Label::Absent);
    }

    /// Both entries to the Low workers' secret check consult the snapshots.
    #[test]
    fn the_secret_checks_look_at_snapshots() {
        let source = include_str!("windows_sandbox.rs");
        let body = |start: &str| {
            let at = source.find(start).unwrap();
            let end = source[at..].find("\n}\n").unwrap();
            &source[at..at + end]
        };
        for function in ["pub fn protect_secrets(", "fn secrets_labelled("] {
            assert!(
                body(function).contains("crate::windows_snapshots::protect("),
                "{function}"
            );
        }
    }
}
