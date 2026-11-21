//! The account the miner runs as on Windows: the privileges its token carries.
//!
//! - A service logon's token holds the SERVICE group, and Windows grants that group
//!   `SeImpersonatePrivilege`: from a worker a requester's guest broke out of, that is one
//!   well-known step to SYSTEM. So `zkminer run` removes every privilege but [`KEPT_PRIVILEGES`]
//!   from its own token at start-up ([`strip_this_process`]), and again from each worker's before
//!   it runs ([`strip_worker`]). A removed privilege cannot be enabled again, and a process gets a
//!   copy of its creator's token, so nothing the miner starts gets one back. A worker whose token
//!   still holds one of [`DANGEROUS_PRIVILEGES`] afterwards is not started.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
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
}
