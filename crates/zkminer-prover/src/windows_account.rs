//! The account the miner runs as on Windows: the privileges its token carries, whether it is an
//! administrator, and whether another user of this PC can replace what it runs.
//!
//! - A service logon's token holds the SERVICE group, and Windows grants that group
//!   `SeImpersonatePrivilege`: from a worker a requester's guest broke out of, that is one
//!   well-known step to SYSTEM. So `zkminer run` removes every privilege but [`KEPT_PRIVILEGES`]
//!   from its own token at start-up ([`strip_this_process`]), and again from each worker's before
//!   it runs ([`strip_worker`]). A removed privilege cannot be enabled again, and a process gets a
//!   copy of its creator's token, so nothing the miner starts gets one back. A worker whose token
//!   still holds one of [`DANGEROUS_PRIVILEGES`] afterwards is not started.
//! - An administrator is told by the Administrators group in its token ([`admin_state`]): enabled
//!   (an elevated console, or a service logon, which UAC never filters) or kept for deny only (an
//!   administrator's console that is not elevated). `TokenElevation` is not used: a token holding
//!   one of the privileges above counts as elevated without being an administrator's.
//! - `zkminer doctor` reads who can write the miner's executable, its configuration, its workers,
//!   and the service wrapper that starts it ([`writers_of`], [`services_running`]): on a PC with
//!   other users, one who can replace any of them runs code as the miner's account, key and all.

use std::ffi::{c_void, OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

type Handle = *mut c_void;

/// The privileges a token of the miner's keeps: traverse checking (which every path lookup
/// relies on), and two that GPU runtimes may use (a larger working set for pinned memory, named
/// sections). Every other one is removed.
pub const KEPT_PRIVILEGES: [&str; 3] = [
    "SeChangeNotifyPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeCreateGlobalPrivilege",
];

/// Privileges that make a process as good as an administrator or SYSTEM (impersonating a client
/// that connects, reading or writing any file, opening any process, loading a driver, ...). Said
/// by `zkminer doctor`, and a worker whose token still holds one is not started.
pub const DANGEROUS_PRIVILEGES: [&str; 14] = [
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeTcbPrivilege",
    "SeDebugPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeCreateTokenPrivilege",
    "SeManageVolumePrivilege",
    "SeRelabelPrivilege",
    "SeSecurityPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeCreateSymbolicLinkPrivilege",
];

/// The well-known privileges by LUID (`SE_*_PRIVILEGE` in winnt.h: the low part; the high part is
/// 0). Fixed by Windows, so no lookup is needed to name one.
const PRIVILEGE_NAMES: [(u32, &str); 35] = [
    (2, "SeCreateTokenPrivilege"),
    (3, "SeAssignPrimaryTokenPrivilege"),
    (4, "SeLockMemoryPrivilege"),
    (5, "SeIncreaseQuotaPrivilege"),
    (6, "SeMachineAccountPrivilege"),
    (7, "SeTcbPrivilege"),
    (8, "SeSecurityPrivilege"),
    (9, "SeTakeOwnershipPrivilege"),
    (10, "SeLoadDriverPrivilege"),
    (11, "SeSystemProfilePrivilege"),
    (12, "SeSystemtimePrivilege"),
    (13, "SeProfileSingleProcessPrivilege"),
    (14, "SeIncreaseBasePriorityPrivilege"),
    (15, "SeCreatePagefilePrivilege"),
    (16, "SeCreatePermanentPrivilege"),
    (17, "SeBackupPrivilege"),
    (18, "SeRestorePrivilege"),
    (19, "SeShutdownPrivilege"),
    (20, "SeDebugPrivilege"),
    (21, "SeAuditPrivilege"),
    (22, "SeSystemEnvironmentPrivilege"),
    (23, "SeChangeNotifyPrivilege"),
    (24, "SeRemoteShutdownPrivilege"),
    (25, "SeUndockPrivilege"),
    (26, "SeSyncAgentPrivilege"),
    (27, "SeEnableDelegationPrivilege"),
    (28, "SeManageVolumePrivilege"),
    (29, "SeImpersonatePrivilege"),
    (30, "SeCreateGlobalPrivilege"),
    (31, "SeTrustedCredManAccessPrivilege"),
    (32, "SeRelabelPrivilege"),
    (33, "SeIncreaseWorkingSetPrivilege"),
    (34, "SeTimeZonePrivilege"),
    (35, "SeCreateSymbolicLinkPrivilege"),
    (36, "SeDelegateSessionUserImpersonatePrivilege"),
];

const TOKEN_DUPLICATE: u32 = 0x0002;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const TOKEN_GROUPS: i32 = 2;
const TOKEN_PRIVILEGES: i32 = 3;
const SE_PRIVILEGE_REMOVED: u32 = 0x4;
const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
const ERROR_NOT_ALL_ASSIGNED: i32 = 1300;

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: i32,
        info: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
    fn AdjustTokenPrivileges(
        token: Handle,
        disable_all: i32,
        new_state: *const c_void,
        length: u32,
        previous: *mut c_void,
        returned: *mut u32,
    ) -> i32;
    fn DuplicateTokenEx(
        token: Handle,
        access: u32,
        attributes: *const c_void,
        impersonation_level: i32,
        token_type: i32,
        new_token: *mut Handle,
    ) -> i32;
    fn GetFileSecurityW(
        name: *const u16,
        information: u32,
        descriptor: *mut c_void,
        length: u32,
        needed: *mut u32,
    ) -> i32;
    fn RegOpenKeyExW(
        key: isize,
        sub_key: *const u16,
        options: u32,
        access: u32,
        result: *mut isize,
    ) -> i32;
    fn RegQueryValueExW(
        key: isize,
        name: *const u16,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        size: *mut u32,
    ) -> i32;
    fn RegEnumKeyExW(
        key: isize,
        index: u32,
        name: *mut u16,
        name_len: *mut u32,
        reserved: *mut u32,
        class: *mut u16,
        class_len: *mut u32,
        written: *mut u64,
    ) -> i32;
    fn RegCloseKey(key: isize) -> i32;
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

/// The name of the privilege with LUID `(low, high)`, or `LUID <high>:<low>` for one Windows does
/// not name in winnt.h.
pub fn privilege_name(low: u32, high: i32) -> String {
    PRIVILEGE_NAMES
        .iter()
        .find(|(luid, _)| high == 0 && *luid == low)
        .map_or_else(
            || format!("LUID {high}:{low}"),
            |(_, name)| name.to_string(),
        )
}

/// Of `held`, the privileges a stripped token gives up: all but [`KEPT_PRIVILEGES`].
pub fn to_remove<S: AsRef<str>>(held: &[S]) -> Vec<&str> {
    held.iter()
        .map(AsRef::as_ref)
        .filter(|name| !KEPT_PRIVILEGES.contains(name))
        .collect()
}

/// Of `held`, the [`DANGEROUS_PRIVILEGES`].
pub fn dangerous<S: AsRef<str>>(held: &[S]) -> Vec<&str> {
    held.iter()
        .map(AsRef::as_ref)
        .filter(|name| DANGEROUS_PRIVILEGES.contains(name))
        .collect()
}

/// `GetTokenInformation(class)` into a buffer aligned for any of its structures.
fn token_information(token: Handle, class: i32) -> io::Result<Vec<u64>> {
    let mut needed = 0u32;
    // SAFETY: a size query (no buffer); `needed` outlives the call.
    let sized = unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut needed) };
    if sized == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER) {
            return Err(e);
        }
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: a buffer of at least `needed` bytes that outlives the call.
    if unsafe {
        GetTokenInformation(
            token,
            class,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

/// One privilege of a token: its LUID and name.
struct Privilege {
    low: u32,
    high: i32,
    name: String,
}

/// Every privilege `token` holds (enabled or not).
fn token_privileges(token: Handle) -> io::Result<Vec<Privilege>> {
    let buf = token_information(token, TOKEN_PRIVILEGES)?;
    // TOKEN_PRIVILEGES { DWORD count; LUID_AND_ATTRIBUTES[count] { DWORD low; LONG high; DWORD attributes } }
    let words: Vec<u32> = buf
        .iter()
        .flat_map(|w| [*w as u32, (*w >> 32) as u32])
        .collect();
    let count = words[0] as usize;
    if 1 + 3 * count > words.len() {
        return Err(io::Error::other("a malformed TOKEN_PRIVILEGES"));
    }
    Ok((0..count)
        .map(|i| {
            let (low, high) = (words[1 + 3 * i], words[2 + 3 * i] as i32);
            Privilege {
                low,
                high,
                name: privilege_name(low, high),
            }
        })
        .collect())
}

/// Remove every privilege but [`KEPT_PRIVILEGES`] from `token` (opened with `TOKEN_QUERY` and
/// `TOKEN_ADJUST_PRIVILEGES`), then read it back: an error if one was not removed or a
/// [`DANGEROUS_PRIVILEGES`] one is still there. The names removed.
fn strip_token(token: Handle) -> io::Result<Vec<String>> {
    let held = token_privileges(token)?;
    let remove: Vec<&Privilege> = held
        .iter()
        .filter(|p| !KEPT_PRIVILEGES.contains(&p.name.as_str()))
        .collect();
    if !remove.is_empty() {
        // TOKEN_PRIVILEGES, as above, each one marked removed.
        let mut state: Vec<u32> = vec![remove.len() as u32];
        for p in &remove {
            state.extend([p.low, p.high as u32, SE_PRIVILEGE_REMOVED]);
        }
        // SAFETY: a token with TOKEN_ADJUST_PRIVILEGES and a TOKEN_PRIVILEGES that outlives the
        // call; no previous state is asked for.
        let ok = unsafe {
            AdjustTokenPrivileges(
                token,
                0,
                state.as_ptr().cast(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        // It succeeds with ERROR_NOT_ALL_ASSIGNED when it changed only some of them.
        let e = io::Error::last_os_error();
        if ok == 0 {
            return Err(e);
        }
        if e.raw_os_error() == Some(ERROR_NOT_ALL_ASSIGNED) {
            return Err(io::Error::other("not every privilege could be removed"));
        }
    }
    let left: Vec<String> = token_privileges(token)?
        .into_iter()
        .map(|p| p.name)
        .collect();
    let still = to_remove(&left);
    if !still.is_empty() {
        return Err(io::Error::other(format!(
            "still held after removal: {}",
            still.join(", ")
        )));
    }
    Ok(remove.into_iter().map(|p| p.name.clone()).collect())
}

/// Open the token of `process` with `access`.
fn process_token(process: Handle, access: u32) -> io::Result<OwnedHandle> {
    let mut token = std::ptr::null_mut();
    // SAFETY: a valid process handle (or this process's pseudo-handle) and an out-pointer; the
    // token is owned at once.
    if unsafe { OpenProcessToken(process, access, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle just opened, owned by nothing else.
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

/// What [`strip_this_process`] did at start-up, for [`log_startup_strip`].
static STARTUP_STRIP: OnceLock<Result<Vec<String>, String>> = OnceLock::new();

/// Remove every privilege but [`KEPT_PRIVILEGES`] from this process's own token: for `zkminer
/// run`'s `main`, before any thread or child starts. Every process it starts from then on (workers,
/// the SP1 server, `nvidia-smi`) gets a copy of the stripped token. The names removed.
pub fn strip_this_process() -> io::Result<Vec<String>> {
    // SAFETY: the pseudo-handle of this process.
    let token = process_token(
        unsafe { GetCurrentProcess() },
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
    )?;
    let result = strip_token(token.as_raw_handle());
    let _ = STARTUP_STRIP.set(
        result
            .as_ref()
            .map(Clone::clone)
            .map_err(ToString::to_string),
    );
    result
}

/// For `zkminer run`, once logging is up: what [`strip_this_process`] removed, or, when it failed
/// and the miner started anyway ([`crate::windows_sandbox::ALLOW_PRIVILEGED_ACCOUNT_ENV`]), a page.
pub fn log_startup_strip() {
    match STARTUP_STRIP.get() {
        Some(Ok(removed)) if !removed.is_empty() => {
            tracing::info!(
                "privileges removed from this process and its workers: {}",
                removed.join(", ")
            );
            let dangerous = dangerous(removed);
            if !dangerous.is_empty() {
                tracing::warn!(
                    "this account's token held {} (a service logon gets SeImpersonatePrivilege \
                     through the SERVICE group): removed from this process and its workers. `sc \
                     privs` keeps them from the service wrapper too (README: Windows service)",
                    dangerous.join(", ")
                );
            }
        }
        Some(Ok(_)) | None => {}
        Some(Err(e)) => tracing::error!(
            "PAGE: PRIVILEGES — this process's privileges could not be removed ({e}); started \
             anyway ({}=1). Each worker's are removed before it runs, and a worker still holding \
             one that makes it an administrator is not started",
            crate::windows_sandbox::ALLOW_PRIVILEGED_ACCOUNT_ENV
        ),
    }
}

/// Remove every privilege but [`KEPT_PRIVILEGES`] from the token of `process`, a worker created
/// suspended that has not run yet, and check that none of [`DANGEROUS_PRIVILEGES`] is left. After
/// [`strip_this_process`] there is nothing left to remove: this holds whatever started the miner.
pub(crate) fn strip_worker(process: Handle) -> io::Result<()> {
    let token = process_token(process, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)?;
    strip_token(token.as_raw_handle()).map(drop)
}

/// A worker's privileges could not be removed (`why`): it is not started, unless `allowed`
/// ([`crate::windows_sandbox::ALLOW_PRIVILEGED_ACCOUNT_ENV`]), when it is started anyway. Paged
/// either way.
pub(crate) fn worker_privileges_failed(program: &Path, why: &io::Error, allowed: bool) {
    let env = crate::windows_sandbox::ALLOW_PRIVILEGED_ACCOUNT_ENV;
    if allowed {
        tracing::error!(
            "PAGE: WORKER-PRIVILEGES — the privileges of a worker ({}) could not be removed \
             ({why}); started anyway ({env}=1): a requester's guest that breaks out of it may \
             reach SYSTEM",
            program.display()
        );
    } else {
        tracing::error!(
            "PAGE: WORKER-PRIVILEGES — the privileges of a worker ({}) could not be removed \
             ({why}), so it is not started: with one of {} a requester's guest that broke out of \
             it could reach SYSTEM. Run the miner as a dedicated standard user, and give the \
             service only `sc privs zkminer SeChangeNotifyPrivilege/SeCreateGlobalPrivilege/\
             SeIncreaseWorkingSetPrivilege` (README: Windows service)",
            program.display(),
            DANGEROUS_PRIVILEGES[..4].join(", ")
        );
    }
}

/// The names of the privileges this process's token holds.
pub fn this_process_privileges() -> io::Result<Vec<String>> {
    // SAFETY: the pseudo-handle of this process.
    let token = process_token(unsafe { GetCurrentProcess() }, TOKEN_QUERY)?;
    Ok(token_privileges(token.as_raw_handle())?
        .into_iter()
        .map(|p| p.name)
        .collect())
}

/// For `zkminer doctor`: strip a copy of this process's token as `run` strips its own, leaving this
/// one as it is. The names that would be removed.
pub fn strip_check() -> io::Result<Vec<String>> {
    const SECURITY_IMPERSONATION: i32 = 2;
    const TOKEN_PRIMARY: i32 = 1;
    // SAFETY: the pseudo-handle of this process.
    let token = process_token(
        unsafe { GetCurrentProcess() },
        TOKEN_DUPLICATE | TOKEN_QUERY,
    )?;
    let mut copy = std::ptr::null_mut();
    // SAFETY: a token opened with TOKEN_DUPLICATE and an out-pointer; the copy is owned at once.
    if unsafe {
        DuplicateTokenEx(
            token.as_raw_handle(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            std::ptr::null(),
            SECURITY_IMPERSONATION,
            TOKEN_PRIMARY,
            &mut copy,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle just opened, owned by nothing else.
    let copy = unsafe { OwnedHandle::from_raw_handle(copy) };
    strip_token(copy.as_raw_handle())
}

/// Whether a token is an administrator's, by its Administrators group (S-1-5-32-544).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminState {
    /// The group is enabled: an elevated console, or a service logon (UAC filters only interactive
    /// and remote logons). The token's holder has administrator rights now.
    Full,
    /// The group is there for deny only: an administrator's console that is not elevated. UAC is
    /// not a security boundary, so a process at this level can still become an administrator.
    Filtered,
    /// Not a member.
    None,
}

/// A SID (binary) and its attributes in a token's groups.
pub type Group = (Vec<u8>, u32);

/// BUILTIN\Administrators, S-1-5-32-544.
const ADMINISTRATORS_SID: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0];
/// NT AUTHORITY\SERVICE, S-1-5-6: every service logon has it.
const SERVICE_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 6, 0, 0, 0];

/// The [`AdminState`] of a token whose groups are `groups`.
pub fn admin_state_of(groups: &[Group]) -> AdminState {
    const SE_GROUP_ENABLED: u32 = 0x4;
    const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
    match groups.iter().find(|(sid, _)| sid[..] == ADMINISTRATORS_SID) {
        Some((_, attributes)) if attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0 => {
            AdminState::Filtered
        }
        Some((_, attributes)) if attributes & SE_GROUP_ENABLED != 0 => AdminState::Full,
        // Neither enabled nor deny-only: present, but it grants nothing now.
        Some(_) => AdminState::Filtered,
        None => AdminState::None,
    }
}

/// Whether a token whose groups are `groups` is a service's: it holds the SERVICE group, which the
/// service control manager gives every service logon. Session 0 alone is not one: an
/// administrator's OpenSSH, WinRM or PsExec logon and a "highest privileges" scheduled task run
/// there too, with a person (or a script of theirs) behind them, and are elevated consoles.
pub fn service_logon_of(groups: &[Group]) -> bool {
    groups.iter().any(|(sid, _)| sid[..] == SERVICE_SID)
}

/// The groups of this process's token.
fn this_process_groups() -> io::Result<Vec<Group>> {
    #[repr(C)]
    struct SidAndAttributes {
        sid: *const u8,
        attributes: u32,
    }
    #[repr(C)]
    struct TokenGroupsHead {
        count: u32,
        first: SidAndAttributes,
    }
    // SAFETY: the pseudo-handle of this process.
    let token = process_token(unsafe { GetCurrentProcess() }, TOKEN_QUERY)?;
    let buf = token_information(token.as_raw_handle(), TOKEN_GROUPS)?;
    let bytes = buf.len() * 8;
    // SAFETY: TOKEN_GROUPS as Windows wrote it into `buf`, which outlives every read: the count,
    // then that many SID_AND_ATTRIBUTES, whose SIDs point into the same buffer. Each SID is
    // revision, sub-authority count, 6-byte authority, then 4 bytes per sub-authority.
    unsafe {
        let base = buf.as_ptr().cast::<u8>();
        let count = *base.cast::<u32>() as usize;
        let first = std::mem::offset_of!(TokenGroupsHead, first);
        let size = std::mem::size_of::<SidAndAttributes>();
        if first + count * size > bytes {
            return Err(io::Error::other("a malformed TOKEN_GROUPS"));
        }
        let entries = base.add(first).cast::<SidAndAttributes>();
        Ok((0..count)
            .map(|i| {
                let entry = &*entries.add(i);
                let length = 8 + 4 * usize::from(*entry.sid.add(1));
                (
                    std::slice::from_raw_parts(entry.sid, length).to_vec(),
                    entry.attributes,
                )
            })
            .collect())
    }
}

/// This process's [`AdminState`].
pub fn admin_state() -> io::Result<AdminState> {
    Ok(admin_state_of(&this_process_groups()?))
}

/// Whether this process runs under a service logon ([`service_logon_of`]).
pub fn is_service_logon() -> io::Result<bool> {
    Ok(service_logon_of(&this_process_groups()?))
}

/// `S-1-…` for a binary SID, or `None` if `sid` is not one.
pub fn sid_string(sid: &[u8]) -> Option<String> {
    let count = usize::from(*sid.get(1)?);
    if sid.len() < 8 + 4 * count || sid[0] != 1 {
        return None;
    }
    let authority = sid[2..8].iter().fold(0u64, |a, b| (a << 8) | u64::from(*b));
    let mut text = format!("S-1-{authority}");
    for i in 0..count {
        let at = 8 + 4 * i;
        let sub = u32::from_le_bytes(sid[at..at + 4].try_into().ok()?);
        text.push_str(&format!("-{sub}"));
    }
    Some(text)
}

/// The rights in a file or directory ACE that let its holder replace what is there, or put
/// something new there: write or append (add a file or subdirectory), delete it or a child,
/// change its DACL or owner, and the generic rights that include those.
const REPLACE_RIGHTS: u32 =
    0x2 | 0x4 | 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x4000_0000 | 0x1000_0000;

/// The SIDs that the DACL of the self-relative security descriptor `descriptor` grants any of
/// [`REPLACE_RIGHTS`] on the object itself (an ACE only for what is made inside it does not
/// count). Deny ACEs are not weighed: a SID listed here may in fact be denied. `Err` for a
/// descriptor that cannot be read, `Ok(["S-1-1-0"])` (Everyone) for one with no DACL.
pub fn dacl_writers(descriptor: &[u8]) -> Result<Vec<String>, &'static str> {
    const SE_DACL_PRESENT: u16 = 0x4;
    const SE_SELF_RELATIVE: u16 = 0x8000;
    const ACCESS_ALLOWED_ACE: u8 = 0;
    const ACCESS_ALLOWED_CALLBACK_ACE: u8 = 9;
    const INHERIT_ONLY_ACE: u8 = 0x8;
    let u16_at = |b: &[u8], at: usize| b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]]));
    let u32_at = |b: &[u8], at: usize| {
        b.get(at..at + 4)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    };
    let control = u16_at(descriptor, 2).ok_or("too short")?;
    if control & SE_SELF_RELATIVE == 0 {
        return Err("not self-relative");
    }
    let dacl_at = u32_at(descriptor, 16).ok_or("too short")? as usize;
    if control & SE_DACL_PRESENT == 0 || dacl_at == 0 {
        return Ok(vec!["S-1-1-0".to_string()]);
    }
    let acl = descriptor.get(dacl_at..).ok_or("DACL out of bounds")?;
    let count = u16_at(acl, 4).ok_or("DACL too short")?;
    let mut at = 8;
    let mut writers: Vec<String> = Vec::new();
    for _ in 0..count {
        let kind = *acl.get(at).ok_or("ACE out of bounds")?;
        let flags = *acl.get(at + 1).ok_or("ACE out of bounds")?;
        let size = usize::from(u16_at(acl, at + 2).ok_or("ACE out of bounds")?);
        if size < 8 || at + size > acl.len() {
            return Err("ACE out of bounds");
        }
        if matches!(kind, ACCESS_ALLOWED_ACE | ACCESS_ALLOWED_CALLBACK_ACE)
            && flags & INHERIT_ONLY_ACE == 0
            && u32_at(acl, at + 4).ok_or("ACE out of bounds")? & REPLACE_RIGHTS != 0
        {
            let sid = sid_string(&acl[at + 8..at + size]).ok_or("an ACE with a bad SID")?;
            if !writers.contains(&sid) {
                writers.push(sid);
            }
        }
        at += size;
    }
    Ok(writers)
}

/// SYSTEM, Administrators and TrustedInstaller: the principals that may write what the miner runs,
/// with the miner's own account.
pub const TRUSTED_WRITERS: [&str; 3] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// A name for a SID an operator knows, where there is a well-known one.
pub fn principal_name(sid: &str) -> String {
    let name = match sid {
        "S-1-1-0" => "Everyone",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-32-545" => "Users",
        "S-1-5-4" => "INTERACTIVE",
        "S-1-5-32-546" => "Guests",
        "S-1-3-0" => "CREATOR OWNER",
        "S-1-3-4" => "OWNER RIGHTS",
        "S-1-15-2-1" => "ALL APPLICATION PACKAGES",
        _ => return sid.to_string(),
    };
    format!("{name} ({sid})")
}

/// The principals other than [`TRUSTED_WRITERS`] and `own` (the miner's account's SID) that can
/// replace `path` or put something in it ([`dacl_writers`]).
pub fn writers_of(path: &Path, own: &str) -> io::Result<Vec<String>> {
    const DACL_SECURITY_INFORMATION: u32 = 0x4;
    let name = wide(path.as_os_str());
    let mut needed = 0u32;
    // SAFETY: a NUL-terminated path; a size query.
    unsafe {
        GetFileSecurityW(
            name.as_ptr(),
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: a buffer of at least `needed` bytes that outlives the call.
    if unsafe {
        GetFileSecurityW(
            name.as_ptr(),
            DACL_SECURITY_INFORMATION,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: plain bytes of a buffer this function owns.
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len() * 8) };
    let writers = dacl_writers(bytes).map_err(io::Error::other)?;
    Ok(writers
        .into_iter()
        .filter(|sid| !TRUSTED_WRITERS.contains(&sid.as_str()) && !sid.eq_ignore_ascii_case(own))
        .collect())
}

/// A service whose program, or whose NSSM `Application`, is a given executable.
#[derive(Debug, Clone)]
pub struct ServiceImage {
    pub name: String,
    /// What the service manager starts (`nssm.exe` for an NSSM service).
    pub image: PathBuf,
    /// The `ImagePath` names a program with a space in its path, unquoted: Windows tries each
    /// prefix up to a space (`C:\Program.exe` first).
    pub unquoted_with_spaces: bool,
    /// The service's `RequiredPrivileges` (`sc privs`), when set.
    pub required_privileges: Option<Vec<String>>,
}

/// The program an `ImagePath` (or NSSM `Application`) value names, and whether it is unquoted with
/// a space in it. `%VAR%` is expanded from this process's environment, and `\??\` dropped.
pub fn image_program(value: &str) -> (PathBuf, bool) {
    let value = value.trim();
    let (program, unquoted_with_spaces) = if let Some(rest) = value.strip_prefix('"') {
        (rest.split('"').next().unwrap_or(rest).to_string(), false)
    } else {
        let lower = value.to_ascii_lowercase();
        let program = match lower.find(".exe") {
            Some(i) => &value[..i + 4],
            None => value.split(' ').next().unwrap_or(value),
        };
        (program.to_string(), program.contains(' '))
    };
    let mut expanded = String::new();
    let mut rest = program.as_str();
    while let Some(start) = rest.find('%') {
        let Some(len) = rest[start + 1..].find('%') else {
            break;
        };
        let var = &rest[start + 1..start + 1 + len];
        expanded.push_str(&rest[..start]);
        match std::env::var(var) {
            Ok(v) if !var.is_empty() => expanded.push_str(&v),
            _ => expanded.push_str(&rest[start..start + len + 2]),
        }
        rest = &rest[start + len + 2..];
    }
    expanded.push_str(rest);
    let expanded = expanded
        .strip_prefix(r"\??\")
        .map(str::to_string)
        .unwrap_or(expanded);
    (PathBuf::from(expanded), unquoted_with_spaces)
}

/// A registry key under HKLM, closed on drop.
struct Key(isize);

impl Key {
    fn open(path: &str) -> Option<Self> {
        const HKEY_LOCAL_MACHINE: isize = 0x8000_0002_u32 as i32 as isize;
        const KEY_READ: u32 = 0x2_0019;
        let path = wide(OsStr::new(path));
        let mut key = 0isize;
        // SAFETY: a NUL-terminated path and an out-pointer; the key is owned at once.
        (unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) } == 0)
            .then_some(Self(key))
    }

    /// A string value (REG_SZ, REG_EXPAND_SZ or REG_MULTI_SZ), its strings in order.
    fn strings(&self, name: &str) -> Option<Vec<String>> {
        const REG_SZ: u32 = 1;
        const REG_EXPAND_SZ: u32 = 2;
        const REG_MULTI_SZ: u32 = 7;
        let name = wide(OsStr::new(name));
        let (mut kind, mut size) = (0u32, 0u32);
        // SAFETY: a size query on an open key.
        if unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                std::ptr::null_mut(),
                &mut size,
            )
        } != 0
            || !matches!(kind, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ)
        {
            return None;
        }
        let mut data = vec![0u16; (size as usize).div_ceil(2) + 1];
        let mut size = (data.len() * 2) as u32;
        // SAFETY: a buffer of `size` bytes that outlives the call.
        if unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut size,
            )
        } != 0
        {
            return None;
        }
        data.truncate(size as usize / 2);
        Some(
            data.split(|c| *c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| OsString::from_wide(s).to_string_lossy().into_owned())
                .collect(),
        )
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: a key this value opened.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Whether `a` and `b` name the same file (canonical paths, else the paths without case).
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy()),
    }
}

/// The services that run `exe`: as their program, or through NSSM (its `Parameters\Application`,
/// the only value read there: `AppEnvironmentExtra` beside it may hold a key).
pub fn services_running(exe: &Path) -> Vec<ServiceImage> {
    const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";
    let Some(services) = Key::open(SERVICES) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for index in 0.. {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: a buffer of `len` characters and out-pointers that outlive the call.
        let status = unsafe {
            RegEnumKeyExW(
                services.0,
                index,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            break;
        }
        let name = String::from_utf16_lossy(&name[..len as usize]);
        let Some(key) = Key::open(&format!(r"{SERVICES}\{name}")) else {
            continue;
        };
        let Some(image_path) = key.strings("ImagePath").and_then(|v| v.into_iter().next()) else {
            continue;
        };
        let (image, unquoted_with_spaces) = image_program(&image_path);
        let runs_exe = same_file(&image, exe)
            || Key::open(&format!(r"{SERVICES}\{name}\Parameters"))
                .and_then(|p| p.strings("Application"))
                .and_then(|v| v.into_iter().next())
                .is_some_and(|app| same_file(&image_program(&app).0, exe));
        if runs_exe {
            found.push(ServiceImage {
                name,
                image,
                unquoted_with_spaces,
                required_privileges: key.strings("RequiredPrivileges"),
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn privileges_are_named_by_luid() {
        assert_eq!(privilege_name(29, 0), "SeImpersonatePrivilege");
        assert_eq!(privilege_name(23, 0), "SeChangeNotifyPrivilege");
        assert_eq!(privilege_name(29, 1), "LUID 1:29");
        assert_eq!(privilege_name(99, 0), "LUID 0:99");
        // Every kept and every dangerous one has a LUID.
        for name in KEPT_PRIVILEGES.iter().chain(&DANGEROUS_PRIVILEGES) {
            assert!(
                PRIVILEGE_NAMES.iter().any(|(_, n)| n == name),
                "{name} has no LUID"
            );
        }
    }

    /// The README's service token: everything goes but the kept three, and the dangerous ones are
    /// found among them.
    #[test]
    fn a_service_token_loses_all_but_the_kept_privileges() {
        let held = [
            "SeChangeNotifyPrivilege",
            "SeImpersonatePrivilege",
            "SeCreateGlobalPrivilege",
            "SeIncreaseWorkingSetPrivilege",
            "SeShutdownPrivilege",
            "SeTimeZonePrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "LUID 0:99",
        ];
        assert_eq!(
            to_remove(&held),
            [
                "SeImpersonatePrivilege",
                "SeShutdownPrivilege",
                "SeTimeZonePrivilege",
                "SeAssignPrimaryTokenPrivilege",
                "LUID 0:99"
            ]
        );
        assert_eq!(
            dangerous(&held),
            ["SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege"]
        );
        assert!(dangerous(&KEPT_PRIVILEGES).is_empty());
        assert!(to_remove(&KEPT_PRIVILEGES).is_empty());
        // None of the kept ones is dangerous, and every dangerous one goes.
        assert_eq!(
            to_remove(&DANGEROUS_PRIVILEGES).len(),
            DANGEROUS_PRIVILEGES.len()
        );
    }

    #[test]
    fn administrators_are_told_by_their_group_not_by_elevation() {
        let admins = ADMINISTRATORS_SID.to_vec();
        let service = SERVICE_SID.to_vec();
        let users = vec![1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x21, 2, 0, 0];
        assert_eq!(admin_state_of(&[(admins.clone(), 0x7)]), AdminState::Full);
        assert_eq!(
            admin_state_of(&[(admins.clone(), 0x10)]),
            AdminState::Filtered
        );
        assert_eq!(admin_state_of(&[(users.clone(), 0x7)]), AdminState::None);
        // The README's service account: SERVICE, no Administrators.
        let svc = [(users, 0x7), (service.clone(), 0x7)];
        assert_eq!(admin_state_of(&svc), AdminState::None);
        assert!(service_logon_of(&svc));
        assert!(!service_logon_of(&[(admins, 0x7)]));
        assert!(!service_logon_of(&[]));
        assert_eq!(sid_string(&ADMINISTRATORS_SID).unwrap(), "S-1-5-32-544");
        assert_eq!(sid_string(&service).unwrap(), "S-1-5-6");
        assert_eq!(sid_string(&[1, 1, 0]), None);
    }

    /// Review 6 CR6-1: only the SERVICE group makes a service logon. An administrator in session 0
    /// without it (OpenSSH, WinRM, PsExec, a "highest privileges" scheduled task) is an elevated
    /// administrator, paged and not refused; with it, refused. A standard account is neither.
    #[test]
    fn only_the_service_group_makes_a_service_logon() {
        use crate::windows_sandbox::{account_refusal, classify_account, AccountRisk};
        let admins_on = (ADMINISTRATORS_SID.to_vec(), 0x7);
        let admins_deny = (ADMINISTRATORS_SID.to_vec(), 0x10);
        let service = (SERVICE_SID.to_vec(), 0x7);
        let users = (
            vec![1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x21, 2, 0, 0],
            0x7,
        );
        let user = "S-1-5-21-1004336348-1177238915-682003330-1001";
        // (what, the token's groups, its risk, refused)
        let table: [(&str, Vec<Group>, Option<AccountRisk>, bool); 6] = [
            (
                "admin over SSH/WinRM/PsExec or a scheduled task (session 0)",
                vec![users.clone(), admins_on.clone()],
                Some(AccountRisk::Elevated),
                false,
            ),
            (
                "admin as a service",
                vec![users.clone(), admins_on.clone(), service.clone()],
                Some(AccountRisk::AdminService),
                true,
            ),
            (
                "admin console, not elevated",
                vec![users.clone(), admins_deny.clone()],
                Some(AccountRisk::FilteredAdmin),
                false,
            ),
            (
                "filtered admin under a service logon",
                vec![users.clone(), admins_deny, service.clone()],
                Some(AccountRisk::FilteredAdmin),
                false,
            ),
            (
                "the README's service account",
                vec![users.clone(), service],
                None,
                false,
            ),
            ("a standard console", vec![users], None, false),
        ];
        for (what, groups, risk, refused) in table {
            let got = classify_account(user, admin_state_of(&groups), service_logon_of(&groups));
            assert_eq!(got, risk, "{what}");
            assert_eq!(
                account_refusal(&Ok(got), false).is_some(),
                refused,
                "{what}"
            );
        }
    }

    /// This test process: its own token's groups and admin state can be read.
    #[test]
    fn this_process_token_can_be_read() {
        let groups = this_process_groups().unwrap();
        assert!(!groups.is_empty());
        assert!(groups.iter().all(|(sid, _)| sid_string(sid).is_some()));
        admin_state().unwrap();
        is_service_logon().unwrap();
        assert!(!this_process_privileges().unwrap().is_empty());
    }

    /// `doctor`'s dry run strips a copy of this process's token and leaves this one alone.
    #[test]
    fn a_copy_of_the_token_is_stripped_not_this_one() {
        let before = this_process_privileges().unwrap();
        let removed = strip_check().unwrap();
        assert_eq!(removed, to_remove(&before));
        assert_eq!(this_process_privileges().unwrap(), before);
    }

    const HELPER: &str = "ZKMINER_TEST_PRIVILEGE_HELPER";

    /// Strips its own token as `zkminer run` does, then prints the privileges of a child it starts
    /// (read with `whoami /priv`, whose privilege names are not translated).
    #[test]
    #[ignore = "run by a_child_of_a_stripped_process_has_no_removed_privilege"]
    fn stripped_helper() {
        if std::env::var(HELPER).as_deref() != Ok("strip") {
            return;
        }
        strip_this_process().unwrap();
        println!("SELF {}", this_process_privileges().unwrap().join(" "));
        let out = std::process::Command::new("whoami")
            .arg("/priv")
            .output()
            .unwrap();
        let mut text = String::new();
        out.stdout.as_slice().read_to_string(&mut text).unwrap();
        let child: Vec<&str> = text
            .split_whitespace()
            .filter(|w| w.starts_with("Se") && w.ends_with("Privilege"))
            .collect();
        println!("CHILD {}", child.join(" "));
    }

    /// A process that stripped itself keeps only the kept privileges, and so does every child it
    /// starts: none of the dangerous ones, SeImpersonate above all, comes back.
    #[test]
    fn a_child_of_a_stripped_process_has_no_removed_privilege() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "windows_account::tests::stripped_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(HELPER, "strip")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{text}");
        let list = |tag: &str| -> Vec<String> {
            let line = text
                .lines()
                .find_map(|l| l.split_once(&format!("{tag} ")).map(|(_, rest)| rest))
                .unwrap_or_else(|| panic!("no {tag} line in {text}"));
            line.split_whitespace().map(str::to_string).collect()
        };
        let (own, child) = (list("SELF"), list("CHILD"));
        assert!(!child.is_empty(), "{text}");
        for held in [&own, &child] {
            assert!(to_remove(held).is_empty(), "{held:?}");
            assert!(!held.iter().any(|p| p == "SeImpersonatePrivilege"));
        }
        // And this process, which started it, keeps what it had.
        let mine = this_process_privileges().unwrap();
        if !to_remove(&mine).is_empty() {
            assert_ne!(mine, own);
        }
    }

    /// A worker started the way the miner starts one keeps only the kept privileges, whatever the
    /// process that started it holds (this test process is not stripped).
    #[test]
    fn a_worker_is_started_without_the_removed_privileges() {
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        #[link(name = "kernel32")]
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        }
        let root = std::env::var_os("SystemRoot").unwrap();
        // cmd.exe with no arguments waits on its stdin, a pipe the test holds open.
        let cmd = std::path::PathBuf::from(root)
            .join("System32")
            .join("cmd.exe");
        let env: Vec<_> = std::env::vars_os().collect();
        let mut worker = crate::windows_sandbox::spawn_worker("test", &cmd, env).unwrap();
        // SAFETY: plain kernel32 call; the handle is owned at once.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, worker.id()) };
        assert!(!process.is_null(), "{}", io::Error::last_os_error());
        // SAFETY: a handle just opened.
        let process = unsafe { OwnedHandle::from_raw_handle(process) };
        let token = process_token(process.as_raw_handle(), TOKEN_QUERY).unwrap();
        let held: Vec<String> = token_privileges(token.as_raw_handle())
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        worker.kill().unwrap();
        assert!(to_remove(&held).is_empty(), "{held:?}");
        assert!(dangerous(&held).is_empty(), "{held:?}");
    }

    /// A self-relative descriptor from SDDL, as `GetFileSecurityW` gives one.
    fn descriptor(sddl: &str) -> Vec<u8> {
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
            fn LocalFree(mem: *mut c_void) -> *mut c_void;
        }
        let text = wide(OsStr::new(sddl));
        let (mut sd, mut size) = (std::ptr::null_mut(), 0u32);
        // SAFETY: a NUL-terminated string and out-pointers; the descriptor is copied, then freed.
        unsafe {
            assert!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut sd,
                    &mut size
                ) != 0
            );
            let bytes = std::slice::from_raw_parts(sd.cast::<u8>(), size as usize).to_vec();
            LocalFree(sd);
            bytes
        }
    }

    /// A folder under `C:\` (Authenticated Users may modify it) is found writable; Program Files'
    /// ACL (inherit-only CREATOR OWNER, Users read) is not; no DACL is Everyone.
    #[test]
    fn writers_are_read_from_the_dacl() {
        let program_files = descriptor(
            "D:PAI(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)\
             (A;OICIIO;GA;;;CO)(A;;FA;;;SY)(A;OICIIO;GA;;;SY)(A;;FA;;;BA)(A;OICIIO;GA;;;BA)\
             (A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;AC)",
        );
        let writers = dacl_writers(&program_files).unwrap();
        assert!(
            writers
                .iter()
                .all(|s| TRUSTED_WRITERS.contains(&s.as_str())),
            "{writers:?}"
        );
        let under_c = descriptor(
            "D:AI(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)\
             (A;ID;0x1301bf;;;AU)(A;OICIIOID;SDGXGWGR;;;AU)(A;ID;0x1200a9;;;BU)",
        );
        assert_eq!(
            dacl_writers(&under_c).unwrap(),
            ["S-1-5-32-544", "S-1-5-18", "S-1-5-11"]
        );
        assert_eq!(
            dacl_writers(&descriptor("D:NO_ACCESS_CONTROL")).unwrap(),
            ["S-1-1-0"]
        );
        assert!(dacl_writers(&[1, 0]).is_err());
        assert_eq!(principal_name("S-1-5-11"), "Authenticated Users (S-1-5-11)");
    }

    /// The test binary's own directory is under this user's profile or the build directory: its
    /// ACL can be read, and the user's own SID never counts.
    #[test]
    fn a_file_acl_can_be_read() {
        let own = zkminer_config::wallet::current_user_sid().unwrap();
        let exe = std::env::current_exe().unwrap();
        let writers = writers_of(&exe, &own).unwrap();
        assert!(!writers.contains(&own));
    }

    #[test]
    fn service_image_paths_are_parsed() {
        assert_eq!(
            image_program(r#""C:\Program Files\zkminer\nssm.exe""#),
            (PathBuf::from(r"C:\Program Files\zkminer\nssm.exe"), false)
        );
        assert_eq!(
            image_program(r"C:\Program Files\zkminer\nssm.exe run"),
            (PathBuf::from(r"C:\Program Files\zkminer\nssm.exe"), true)
        );
        assert_eq!(
            image_program(r"C:\tools\nssm.exe"),
            (PathBuf::from(r"C:\tools\nssm.exe"), false)
        );
        assert_eq!(
            image_program(r"\??\C:\drv\x.sys"),
            (PathBuf::from(r"C:\drv\x.sys"), false)
        );
        let root = std::env::var("SystemRoot").unwrap();
        assert_eq!(
            image_program(r"%SystemRoot%\System32\svchost.exe -k netsvcs").0,
            PathBuf::from(format!(r"{root}\System32\svchost.exe"))
        );
    }

    /// No service runs the test binary; the enumeration itself works without rights.
    #[test]
    fn no_service_runs_the_test_binary() {
        assert!(services_running(&std::env::current_exe().unwrap()).is_empty());
    }
}
