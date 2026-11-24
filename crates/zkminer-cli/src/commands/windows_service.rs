//! Windows: the service the miner runs as (README: Windows service), as `zkminer doctor`, `zkminer
//! run` and `zkminer stop` check it.
//!
//! - The service account's password (review 6 OJ-1). A local account's password expires after the
//!   policy's maximum age (42 days on a workgroup PC by default) unless it is set never to. The
//!   service then fails to log on at its next start (SCM error 1069/1330): nothing runs, and every
//!   lock kept for that start is slashed. Read with `NetUserGetInfo` level 1 and
//!   `NetUserModalsGet` level 0.
//! - NSSM's exit actions and stop timeout (review 6 OJ-2). NSSM restarts the program after every
//!   exit unless told otherwise, so `zkminer stop` (exit 0) only restarted the miner; and its
//!   default 1.5 s console stop timeout cuts a drain off.
//! - Where the service's output goes (review 6 D1): NSSM drops stdout and stderr unless
//!   `AppStdout`/`AppStderr` name a file, and the `zkminer` event source is registered once; and
//!   whether NSSM rotates that file while the miner runs (`AppRotateOnline`, review 7 LD-2), whose
//!   rotated copies a headless start prunes to the newest ten (NSSM deletes none).
//!
//! Only the service's own key and its NSSM `Parameters` values named here are read, never
//! `AppEnvironmentExtra`, which may hold a key.

use std::ffi::{c_void, OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

#[link(name = "netapi32")]
extern "system" {
    fn NetUserGetInfo(server: *const u16, user: *const u16, level: u32, buf: *mut *mut u8) -> u32;
    fn NetUserModalsGet(server: *const u16, level: u32, buf: *mut *mut u8) -> u32;
    fn NetApiBufferFree(buf: *mut c_void) -> u32;
}

#[link(name = "advapi32")]
extern "system" {
    fn GetUserNameW(name: *mut u16, len: *mut u32) -> i32;
    fn RegGetValueW(
        key: isize,
        sub_key: *const u16,
        value: *const u16,
        flags: u32,
        kind: *mut u32,
        data: *mut c_void,
        size: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetComputerNameW(name: *mut u16, len: *mut u32) -> i32;
}

const HKEY_LOCAL_MACHINE: isize = 0x8000_0002_u32 as i32 as isize;
const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain([0]).collect()
}

/// A string value (REG_SZ or REG_EXPAND_SZ, not expanded) of `HKLM\<sub_key>`, `None` for the
/// key's default value.
pub(crate) fn reg_string(sub_key: &str, value: Option<&str>) -> Option<String> {
    const RRF_RT_REG_SZ: u32 = 0x2;
    const RRF_RT_REG_EXPAND_SZ: u32 = 0x4;
    const RRF_NOEXPAND: u32 = 0x1000_0000;
    let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
    let key = wide(sub_key);
    let name = value.map(wide);
    let name_ptr = name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr());
    let mut size = 0u32;
    // SAFETY: a size query; every pointer outlives the call.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name_ptr,
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if status != 0 {
        return None;
    }
    let mut data = vec![0u16; (size as usize).div_ceil(2) + 1];
    let mut size = (data.len() * 2) as u32;
    // SAFETY: a buffer of `size` bytes that outlives the call.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name_ptr,
            flags,
            std::ptr::null_mut(),
            data.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != 0 {
        return None;
    }
    data.truncate(size as usize / 2);
    let end = data.iter().position(|c| *c == 0).unwrap_or(data.len());
    Some(
        OsString::from_wide(&data[..end])
            .to_string_lossy()
            .into_owned(),
    )
}

/// The services that run this program (`zkminer_prover::windows_account::services_running`), by
/// name.
pub(crate) fn services_of_this_exe() -> Vec<String> {
    std::env::current_exe()
        .map(|exe| {
            zkminer_prover::windows_account::services_running(&exe)
                .into_iter()
                .map(|s| s.name)
                .collect()
        })
        .unwrap_or_default()
}

// ---- The service account's password (OJ-1) ----

const UF_ACCOUNTDISABLE: u32 = 0x2;
const UF_LOCKOUT: u32 = 0x10;
const UF_DONT_EXPIRE_PASSWD: u32 = 0x1_0000;
const UF_PASSWORD_EXPIRED: u32 = 0x80_0000;
/// `usrmod0_max_passwd_age` when passwords never expire by policy.
const TIMEQ_FOREVER: u32 = u32::MAX;

/// How soon an expiring password is paged again while the miner runs.
const PASSWORD_SOON_SECS: u64 = 14 * 86_400;

/// A local account's password, as a service logon will find it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Password {
    /// Set never to expire (`PasswordNeverExpires`, `UF_DONT_EXPIRE_PASSWD`).
    NeverExpires,
    /// Not set never to expire, but the policy has no maximum age now: a policy change would start
    /// the clock.
    NoMaxAge,
    /// Expires in this many seconds.
    Expires(u64),
    /// Expired: the next service logon fails.
    Expired,
    /// The account is disabled: the next service logon fails.
    Disabled,
    /// The account is locked out: the next service logon fails.
    LockedOut,
}

/// [`Password`] from `usri1_flags`, `usri1_password_age` (seconds since it was set) and the
/// policy's `usrmod0_max_passwd_age` (seconds, [`TIMEQ_FOREVER`] for none).
pub(crate) fn password_state(flags: u32, age: u32, max_age: u32) -> Password {
    if flags & UF_ACCOUNTDISABLE != 0 {
        Password::Disabled
    } else if flags & UF_LOCKOUT != 0 {
        Password::LockedOut
    } else if flags & UF_DONT_EXPIRE_PASSWD != 0 {
        Password::NeverExpires
    } else if flags & UF_PASSWORD_EXPIRED != 0 {
        Password::Expired
    } else if max_age == TIMEQ_FOREVER {
        Password::NoMaxAge
    } else if age >= max_age {
        Password::Expired
    } else {
        Password::Expires(u64::from(max_age - age))
    }
}

/// How bad a [`Password`] is for a service: `None` when it is fine, else whether it fails the
/// next logon or only can (`true`: fails or can fail), and what to say. `now` is unix seconds.
pub(crate) fn password_finding(account: &str, state: Password, now: u64) -> Option<(bool, String)> {
    let fix = format!(
        "As an administrator: `Set-LocalUser -Name {account} -PasswordNeverExpires $true` (or \
         `wmic useraccount where name='{account}' set PasswordExpires=false`)"
    );
    let reset = format!(
        "Reset it (`net user {account} *`), set it never to expire \
         (`Set-LocalUser -Name {account} -PasswordNeverExpires $true`), and give the service the \
         new password (`nssm set <service> ObjectName .\\{account} <password>`)"
    );
    match state {
        Password::NeverExpires => None,
        Password::NoMaxAge => Some((
            false,
            format!(
                "account {account}'s password is not set never to expire; the password policy \
                 has no maximum age now, but a policy change would start the clock and the \
                 service would then fail to log on. {fix}"
            ),
        )),
        Password::Expires(secs) => Some((
            true,
            format!(
                "account {account}'s password expires {} (in {} day(s)): the service's next \
                 start after that fails to log on, nothing runs, and every lock kept for that \
                 start is slashed. {fix}",
                zkminer_chain::exit::fmt_unix(now.saturating_add(secs)),
                secs / 86_400
            ),
        )),
        Password::Expired => Some((
            true,
            format!(
                "account {account}'s password has expired: the service's next start fails to log \
                 on, and every lock kept for it is slashed. {reset}"
            ),
        )),
        Password::Disabled => Some((
            true,
            format!(
                "account {account} is disabled: the service's next start fails to log on. Enable \
                 it (`net user {account} /active:yes`)"
            ),
        )),
        Password::LockedOut => Some((
            true,
            format!(
                "account {account} is locked out: the service's next start fails to log on. \
                 Unlock it (lusrmgr.msc, or `net user {account} /active:yes`)"
            ),
        )),
    }
}

/// The local account a service's `ObjectName` names (`.\x`, or `<this computer>\x`), or `None`
/// for a built-in or domain account, whose password this cannot weigh.
pub(crate) fn local_account(object_name: &str, computer: &str) -> Option<String> {
    let (domain, user) = object_name.trim().split_once('\\')?;
    (!user.is_empty() && (domain == "." || domain.eq_ignore_ascii_case(computer)))
        .then(|| user.to_string())
}

fn computer_name() -> String {
    let mut buf = [0u16; 64];
    let mut len = buf.len() as u32;
    // SAFETY: a buffer of `len` characters that outlives the call.
    if unsafe { GetComputerNameW(buf.as_mut_ptr(), &mut len) } == 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..len as usize])
}

/// This process's account name (without its domain).
fn this_user() -> Option<String> {
    let mut buf = [0u16; 257];
    let mut len = buf.len() as u32;
    // SAFETY: a buffer of `len` characters that outlives the call.
    if unsafe { GetUserNameW(buf.as_mut_ptr(), &mut len) } == 0 || len == 0 {
        return None;
    }
    // `len` counts the terminating NUL.
    Some(String::from_utf16_lossy(&buf[..len as usize - 1]))
}

/// The [`Password`] of local account `user`, or the NetAPI status that refused it (2221: no such
/// local account; 5: access denied).
pub(crate) fn password_of(user: &str) -> Result<Password, u32> {
    #[repr(C)]
    struct UserInfo1 {
        name: *const u16,
        password: *const u16,
        password_age: u32,
        privilege: u32,
        home_dir: *const u16,
        comment: *const u16,
        flags: u32,
        script_path: *const u16,
    }
    #[repr(C)]
    struct UserModalsInfo0 {
        min_passwd_len: u32,
        max_passwd_age: u32,
        min_passwd_age: u32,
        force_logoff: u32,
        password_hist_len: u32,
    }
    let name = wide(user);
    let mut buf: *mut u8 = std::ptr::null_mut();
    // SAFETY: the local computer (NULL), a NUL-terminated name and an out-pointer; the buffer is
    // freed below.
    let status = unsafe { NetUserGetInfo(std::ptr::null(), name.as_ptr(), 1, &mut buf) };
    if status != 0 || buf.is_null() {
        return Err(status);
    }
    // SAFETY: a USER_INFO_1 NetUserGetInfo allocated, read before it is freed.
    let (flags, age) = unsafe {
        let info = &*buf.cast::<UserInfo1>();
        let read = (info.flags, info.password_age);
        NetApiBufferFree(buf.cast());
        read
    };
    let mut modals: *mut u8 = std::ptr::null_mut();
    // SAFETY: as above.
    let status = unsafe { NetUserModalsGet(std::ptr::null(), 0, &mut modals) };
    if status != 0 || modals.is_null() {
        return Err(status);
    }
    // SAFETY: a USER_MODALS_INFO_0 NetUserModalsGet allocated, read before it is freed.
    let max_age = unsafe {
        let max_age = (*modals.cast::<UserModalsInfo0>()).max_passwd_age;
        NetApiBufferFree(modals.cast());
        max_age
    };
    Ok(password_state(flags, age, max_age))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// How `zkminer doctor` reports a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Finding {
    Pass,
    Info,
    Warn,
    Fail,
}

/// For `zkminer doctor`: the password of each service's local account, as (level, what, text):
/// a failure when the account's next logon fails or can.
pub(crate) fn service_password_findings() -> Vec<(Finding, String, String)> {
    let services: Vec<(String, String)> = services_of_this_exe()
        .into_iter()
        .map(|name| {
            let object = reg_string(&format!(r"{SERVICES}\{name}"), Some("ObjectName"))
                .unwrap_or_else(|| "LocalSystem".to_string());
            (name, object)
        })
        .collect();
    password_findings(&services, &computer_name(), password_of, unix_now())
}

/// [`service_password_findings`] for `services` (name, `ObjectName`), with `password` reading a
/// local account's [`Password`].
fn password_findings(
    services: &[(String, String)],
    computer: &str,
    password: impl Fn(&str) -> Result<Password, u32>,
    now: u64,
) -> Vec<(Finding, String, String)> {
    let mut out = Vec::new();
    for (name, object) in services {
        let what = format!("service {name}: account");
        let Some(user) = local_account(object, computer) else {
            out.push((
                Finding::Info,
                what,
                format!("{object}: not a local account, so its password is not checked here"),
            ));
            continue;
        };
        match password(&user) {
            Ok(state) => match password_finding(&user, state, now) {
                None => out.push((
                    Finding::Pass,
                    what,
                    format!("{user}: its password never expires"),
                )),
                Some((fail, text)) => {
                    out.push((if fail { Finding::Fail } else { Finding::Warn }, what, text))
                }
            },
            Err(status) => out.push((
                Finding::Warn,
                what,
                format!(
                    "{user}: its password could not be read (NetUserGetInfo {status}); check it \
                     never expires (`Get-LocalUser {user} | Select PasswordExpires`)"
                ),
            )),
        }
    }
    out
}

/// For `zkminer run` under a service logon: page its own account's password if the next logon
/// can fail on it, now and then once a day while it runs (when within two weeks of expiring).
pub(crate) fn watch_own_password() {
    fn check(first: bool) {
        let Some(user) = this_user() else {
            return;
        };
        let state = match password_of(&user) {
            Ok(state) => state,
            // No local account of that name: a domain account, the domain's business.
            Err(2221) => return,
            Err(status) => {
                if first {
                    tracing::warn!(
                        "account {user}'s password could not be read (NetUserGetInfo {status}): \
                         check it never expires, or the service's logon fails once it does"
                    );
                }
                return;
            }
        };
        let Some((fails, text)) = password_finding(&user, state, unix_now()) else {
            return;
        };
        // An expiry far off is paged at start-up, then again once it is near; a logon that
        // fails already, every day.
        let page = match state {
            Password::Expires(secs) => first || secs <= PASSWORD_SOON_SECS,
            _ => fails,
        };
        if page {
            tracing::error!("PAGE: PASSWORD-EXPIRES — {text}");
        } else if first {
            tracing::warn!("{text}");
        }
    }
    check(true);
    let _ = std::thread::Builder::new()
        .name("password-watch".into())
        .spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(86_400));
            check(false);
        });
}

// ---- NSSM's exit and stop settings (OJ-2) ----

/// What NSSM does when the miner exits 0 (every deliberate stop: a drain, an abandon) and 130 (a
/// force exit): it must stop, or `zkminer stop` only restarts the miner. 75 (a keep-locks stop,
/// or locks left for the next start) restarts it.
pub(crate) const STOP_EXIT_CODES: [u32; 2] = [0, 130];

/// The shortest `AppStopMethodConsole` (ms) that lets a drain finish: the miner's own drain budget
/// and its release ladder, as the README recipe sets it.
pub(crate) const MIN_STOP_CONSOLE_MS: u32 = 3_900_000;

/// NSSM's `AppStopMethodConsole` when it is not set.
const NSSM_DEFAULT_STOP_CONSOLE_MS: u32 = 1_500;

/// A DWORD value of `HKLM\<sub_key>`.
fn reg_dword(sub_key: &str, value: &str) -> Option<u32> {
    const RRF_RT_REG_DWORD: u32 = 0x10;
    let key = wide(sub_key);
    let name = wide(value);
    let mut data = 0u32;
    let mut size = 4u32;
    // SAFETY: a 4-byte buffer and out-pointers that outlive the call.
    (unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    } == 0)
        .then_some(data)
}

/// The NSSM settings of a service that runs the miner, as read from its `Parameters` key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Nssm {
    /// The `AppExit` key's default value (NSSM's default action: Restart when unset).
    pub exit_default: Option<String>,
    /// `AppExit\<code>` for each of [`STOP_EXIT_CODES`].
    pub exit_for: Vec<(u32, Option<String>)>,
    /// `AppStopMethodConsole` (ms).
    pub stop_console_ms: Option<u32>,
    /// `AppStdout` and `AppStderr`: the files NSSM keeps the miner's output in (none: dropped).
    pub app_stdout: Option<String>,
    pub app_stderr: Option<String>,
    /// `AppRotateFiles` and `AppRotateOnline`: whether NSSM rotates those files, and also while the
    /// miner runs (without `AppRotateOnline 1` it rotates only when the service starts).
    pub rotate_files: Option<u32>,
    pub rotate_online: Option<u32>,
}

/// The [`Nssm`] settings of service `name`, or `None` when it is not run by NSSM (no
/// `Parameters\Application`).
pub(crate) fn nssm_of(name: &str) -> Option<Nssm> {
    let params = format!(r"{SERVICES}\{name}\Parameters");
    reg_string(&params, Some("Application"))?;
    let exit = format!(r"{params}\AppExit");
    Some(Nssm {
        exit_default: reg_string(&exit, None),
        exit_for: STOP_EXIT_CODES
            .iter()
            .map(|code| (*code, reg_string(&exit, Some(&code.to_string()))))
            .collect(),
        stop_console_ms: reg_dword(&params, "AppStopMethodConsole"),
        app_stdout: reg_string(&params, Some("AppStdout")).filter(|v| !v.trim().is_empty()),
        app_stderr: reg_string(&params, Some("AppStderr")).filter(|v| !v.trim().is_empty()),
        rotate_files: reg_dword(&params, "AppRotateFiles"),
        rotate_online: reg_dword(&params, "AppRotateOnline"),
    })
}

/// What NSSM does on exit code `code`: its `AppExit\<code>`, else the default, else Restart.
pub(crate) fn exit_action(nssm: &Nssm, code: u32) -> &str {
    nssm.exit_for
        .iter()
        .find(|(c, _)| *c == code)
        .and_then(|(_, a)| a.as_deref())
        .or(nssm.exit_default.as_deref())
        .map_or("Restart", str::trim)
}

/// The codes of [`STOP_EXIT_CODES`] on which NSSM does not stop: anything but `Exit` (`Restart`
/// starts the miner again; `Ignore` leaves the service running with nothing in it; `Suicide` ends
/// NSSM, which the service's recovery actions may restart).
pub(crate) fn restarting_codes(nssm: &Nssm) -> Vec<u32> {
    STOP_EXIT_CODES
        .iter()
        .copied()
        .filter(|code| !exit_action(nssm, *code).eq_ignore_ascii_case("Exit"))
        .collect()
}

/// For `zkminer stop` and `doctor`: the warning that service `name` starts the miner again after it
/// stops, or `None`.
pub(crate) fn restart_warning(name: &str, nssm: &Nssm) -> Option<String> {
    let codes = restarting_codes(nssm);
    if codes.is_empty() {
        return None;
    }
    let sets: Vec<String> = codes
        .iter()
        .map(|c| format!("`nssm set {name} AppExit {c} Exit`"))
        .collect();
    Some(format!(
        "service {name} (NSSM) restarts the miner after it exits (exit code(s) {}: {}), so \
         `zkminer stop` only restarts it, claiming again. Stop the service itself (`nssm stop \
         {name}`, as an administrator), or set it to stop when the miner does: {}",
        codes
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        codes
            .iter()
            .map(|c| exit_action(nssm, *c).to_string())
            .collect::<Vec<_>>()
            .join(", "),
        sets.join(", ")
    ))
}

/// For `doctor`: the warning that service `name`'s stop timeout cuts a drain off, or `None`.
pub(crate) fn stop_timeout_warning(name: &str, nssm: &Nssm) -> Option<String> {
    let ms = nssm.stop_console_ms.unwrap_or(NSSM_DEFAULT_STOP_CONSOLE_MS);
    (ms < MIN_STOP_CONSOLE_MS).then(|| {
        format!(
            "service {name} (NSSM) waits {ms} ms after Ctrl+C before it kills the miner: a drain \
             started by stopping the service is cut off, and its locks stay held. `nssm set \
             {name} AppStopMethodConsole {MIN_STOP_CONSOLE_MS}`"
        )
    })
}

/// The restart warnings of every NSSM service that runs this miner, for `zkminer stop`.
pub(crate) fn restart_warnings() -> Vec<String> {
    services_of_this_exe()
        .iter()
        .filter_map(|name| restart_warning(name, &nssm_of(name)?))
        .collect()
}

/// For `zkminer doctor`: each NSSM service's exit and stop settings, as (level, what, text).
pub(crate) fn service_nssm_findings() -> Vec<(Finding, String, String)> {
    let mut out = Vec::new();
    for name in services_of_this_exe() {
        let Some(nssm) = nssm_of(&name) else {
            continue;
        };
        let what = format!("service {name}: NSSM");
        let mut fine = true;
        for text in [
            restart_warning(&name, &nssm),
            stop_timeout_warning(&name, &nssm),
            output_warning(&name, &nssm),
            rotation_warning(&name, &nssm),
        ]
        .into_iter()
        .flatten()
        {
            fine = false;
            out.push((Finding::Warn, what.clone(), text));
        }
        if fine {
            out.push((
                Finding::Pass,
                what,
                "stops when the miner stops, waits for a drain, and keeps and rotates its output"
                    .to_string(),
            ));
        }
    }
    if !out.is_empty() && !event_source_registered() {
        out.push((
            Finding::Warn,
            "event log".to_string(),
            "the event source `zkminer` is not registered: pages still reach the Application log, \
             but Event Viewer shows them under \"description not found\". As an administrator, \
             once: `New-EventLog -LogName Application -Source zkminer`"
                .to_string(),
        ));
    }
    out
}

// ---- Where a service's output goes (D1) ----

/// The NSSM settings that keep service `name`'s stdout and stderr in the account's
/// `.zkminer\logs\service.log`, rotated at 10 MB while the miner runs too.
pub(crate) fn output_advice(name: &str) -> String {
    format!(
        "`nssm set {name} AppStdout <home>\\.zkminer\\logs\\service.log`, the same for AppStderr, \
         `nssm set {name} AppRotateFiles 1`, `nssm set {name} AppRotateOnline 1` and `nssm set \
         {name} AppRotateBytes 10485760`"
    )
}

/// For `doctor`: the warning that service `name` keeps none of the miner's output, or `None`.
/// NSSM drops stdout and stderr unless `AppStdout` or `AppStderr` names a file; the miner's own
/// log file and `pages.log` (`~/.zkminer/logs`) are kept either way, but a panic, a start-up
/// error or a refusal is said on stderr only.
pub(crate) fn output_warning(name: &str, nssm: &Nssm) -> Option<String> {
    (nssm.app_stdout.is_none() && nssm.app_stderr.is_none()).then(|| {
        format!(
            "service {name} (NSSM) keeps none of the miner's output: a start-up error, a refusal \
             or a crash is lost. {}",
            output_advice(name)
        )
    })
}

/// For `doctor`: the warning that service `name` keeps the miner's output in a file it rotates
/// only when the service starts (no `AppRotateOnline 1`), or never (no `AppRotateFiles 1`), or
/// `None` (review 7 LD-2). That file then grows for as long as the miner runs, and a full disk stops
/// claims (`PAGE: DISK-LOW`) and fails the proofs of held locks.
pub(crate) fn rotation_warning(name: &str, nssm: &Nssm) -> Option<String> {
    let kept = nssm.app_stdout.is_some() || nssm.app_stderr.is_some();
    let rotated = nssm.rotate_files == Some(1) && nssm.rotate_online == Some(1);
    (kept && !rotated).then(|| {
        format!(
            "service {name} (NSSM) keeps the miner's output in a file it does not rotate while the \
             miner runs (AppRotateFiles {}, AppRotateOnline {}): it grows until the service \
             restarts, and a full disk stops claims and fails held proofs. {}",
            nssm.rotate_files.map_or("unset".to_string(), |v| v.to_string()),
            nssm.rotate_online.map_or("unset".to_string(), |v| v.to_string()),
            output_advice(name)
        )
    })
}

// ---- NSSM's rotated files (review 7 LD-2) ----

/// How many of NSSM's rotated files of the service's output the miner keeps (NSSM deletes none).
pub(crate) const KEEP_ROTATED: usize = 10;

/// Whether `candidate` is the name NSSM gives a rotated copy of the file named `log_name`:
/// `<stem>-YYYYMMDDTHHMMSS.mmm<ext>`, where `<ext>` is `log_name`'s extension (its last `.` on),
/// possibly none. Stem and extension compare case-insensitively (NTFS names do); the timestamp must
/// be exactly that many digits. Nothing else matches, the live file included.
pub(crate) fn is_nssm_rotated(log_name: &str, candidate: &str) -> bool {
    let (stem, ext) = match log_name.rfind('.') {
        Some(dot) if dot > 0 => log_name.split_at(dot),
        _ => (log_name, ""),
    };
    if stem.is_empty() || candidate.len() != stem.len() + "-YYYYMMDDTHHMMSS.mmm".len() + ext.len() {
        return false;
    }
    let (Some(head), Some(tail)) = (
        candidate.get(..stem.len()),
        candidate.get(candidate.len() - ext.len()..),
    ) else {
        return false;
    };
    let Some(stamp) = candidate.get(stem.len()..candidate.len() - ext.len()) else {
        return false;
    };
    let digits = |s: &[u8]| !s.is_empty() && s.iter().all(u8::is_ascii_digit);
    let b = stamp.as_bytes();
    head.eq_ignore_ascii_case(stem)
        && tail.eq_ignore_ascii_case(ext)
        && b.len() == 20
        && b[0] == b'-'
        && digits(&b[1..9])
        && b[9] == b'T'
        && digits(&b[10..16])
        && b[16] == b'.'
        && digits(&b[17..20])
}

/// Of `names` (a directory's), NSSM's rotated copies of `log_name` beyond the newest `keep`, oldest
/// first. Their names sort by their time.
pub(crate) fn rotated_to_prune(log_name: &str, names: &[String], keep: usize) -> Vec<String> {
    let mut rotated: Vec<&String> = names
        .iter()
        .filter(|n| is_nssm_rotated(log_name, n))
        .collect();
    rotated.sort_by_key(|n| n.to_ascii_lowercase());
    let excess = rotated.len().saturating_sub(keep);
    rotated.into_iter().take(excess).cloned().collect()
}

/// The owner SID (`S-1-…`) of the self-relative security descriptor `descriptor`.
pub(crate) fn descriptor_owner(descriptor: &[u8]) -> Option<String> {
    const SE_SELF_RELATIVE: u16 = 0x8000;
    let control = u16::from_le_bytes(descriptor.get(2..4)?.try_into().ok()?);
    if control & SE_SELF_RELATIVE == 0 {
        return None;
    }
    let at = u32::from_le_bytes(descriptor.get(4..8)?.try_into().ok()?) as usize;
    if at == 0 {
        return None;
    }
    zkminer_prover::windows_account::sid_string(descriptor.get(at..)?)
}

/// The owner SID of `path`.
fn owner_of(path: &std::path::Path) -> std::io::Result<String> {
    #[link(name = "advapi32")]
    extern "system" {
        fn GetFileSecurityW(
            name: *const u16,
            information: u32,
            descriptor: *mut c_void,
            length: u32,
            needed: *mut u32,
        ) -> i32;
    }
    const OWNER_SECURITY_INFORMATION: u32 = 0x1;
    let name: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut needed = 0u32;
    // SAFETY: a NUL-terminated path; a size query.
    unsafe {
        GetFileSecurityW(
            name.as_ptr(),
            OWNER_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: a buffer of at least `needed` bytes that outlives the call.
    if unsafe {
        GetFileSecurityW(
            name.as_ptr(),
            OWNER_SECURITY_INFORMATION,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: plain bytes of a buffer this function owns.
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len() * 8) };
    descriptor_owner(bytes).ok_or_else(|| std::io::Error::other("no owner in the descriptor"))
}

/// At a headless start: for each NSSM service that runs this miner, delete NSSM's rotated copies of
/// its `AppStdout` file beyond the newest [`KEEP_ROTATED`]. Only in that file's own directory, only
/// when this account owns that directory (and it is not a link), only regular files whose names
/// [`is_nssm_rotated`] matches. An `AppStdout` with a variable in it, or not absolute, is left alone.
pub(crate) fn prune_rotated_service_logs() {
    let Ok(me) = zkminer_config::wallet::current_user_sid() else {
        return;
    };
    for name in services_of_this_exe() {
        let Some(stdout) = nssm_of(&name).and_then(|n| n.app_stdout) else {
            continue;
        };
        let path = std::path::PathBuf::from(stdout.trim());
        if stdout.contains('%') || !path.is_absolute() {
            continue;
        }
        let (Some(dir), Some(log_name)) = (path.parent(), path.file_name()) else {
            continue;
        };
        let Some(log_name) = log_name.to_str() else {
            continue;
        };
        let is_plain_dir =
            std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink());
        if !is_plain_dir || !owner_of(dir).is_ok_and(|owner| owner.eq_ignore_ascii_case(&me)) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let names: Vec<String> = entries
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        let mut removed = 0usize;
        for old in rotated_to_prune(log_name, &names, KEEP_ROTATED) {
            let file = dir.join(&old);
            if std::fs::symlink_metadata(&file).is_ok_and(|m| m.is_file())
                && std::fs::remove_file(&file).is_ok()
            {
                removed += 1;
            }
        }
        if removed > 0 {
            tracing::info!(
                "removed {removed} old rotated output file(s) of service {name} in {} (the newest \
                 {KEEP_ROTATED} are kept)",
                dir.display()
            );
        }
    }
}

/// Whether the event source `zkminer` is registered (`New-EventLog -Source zkminer`).
pub(crate) fn event_source_registered() -> bool {
    reg_string(
        r"SYSTEM\CurrentControlSet\Services\EventLog\Application\zkminer",
        Some("EventMessageFile"),
    )
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review 6 D1: a service that keeps neither stdout nor stderr is warned of; either one will do.
    #[test]
    fn a_service_that_drops_its_output_is_warned_of() {
        let text = output_warning("zkminer", &Nssm::default()).unwrap();
        assert!(
            text.contains("AppStdout") && text.contains("AppRotateBytes"),
            "{text}"
        );
        let kept = Nssm {
            app_stderr: Some(r"C:\Users\zkminer\zkminer-service.log".into()),
            ..Nssm::default()
        };
        assert_eq!(output_warning("zkminer", &kept), None);
    }

    /// Review 7 LD-2: the advice rotates while the miner runs and keeps the file in the account's
    /// logs; a kept output that NSSM does not rotate online is warned of, and the recipe is not.
    #[test]
    fn a_service_output_not_rotated_online_is_warned_of() {
        let advice = output_advice("zkminer");
        assert!(
            advice.contains("AppRotateOnline 1")
                && advice.contains("AppRotateFiles 1")
                && advice.contains(r"\.zkminer\logs\service.log"),
            "{advice}"
        );
        let text = output_warning("zkminer", &Nssm::default()).unwrap();
        assert!(text.contains("AppRotateOnline 1"), "{text}");
        // Nothing kept: the output warning says it all.
        assert_eq!(rotation_warning("zkminer", &Nssm::default()), None);
        let recipe = Nssm {
            app_stdout: Some(r"C:\Users\zkminer\.zkminer\logs\service.log".into()),
            app_stderr: Some(r"C:\Users\zkminer\.zkminer\logs\service.log".into()),
            rotate_files: Some(1),
            rotate_online: Some(1),
            ..Nssm::default()
        };
        assert_eq!(rotation_warning("zkminer", &recipe), None);
        for (files, online) in [
            (Some(1), None),
            (Some(1), Some(0)),
            (None, Some(1)),
            (None, None),
        ] {
            let nssm = Nssm {
                rotate_files: files,
                rotate_online: online,
                ..recipe.clone()
            };
            let text = rotation_warning("zkminer", &nssm).unwrap();
            assert!(text.contains("AppRotateOnline 1"), "{text}");
        }
    }

    /// NSSM's rotated names, and nothing else: not the live file, not another file's copies, not a
    /// near miss in the timestamp, not a longer or shorter name.
    #[test]
    fn only_nssm_rotated_names_are_matched() {
        let log = "service.log";
        for name in [
            "service-20261121T093015.123.log",
            "SERVICE-20261121T093015.123.LOG",
            "service-19991231T235959.999.log",
        ] {
            assert!(is_nssm_rotated(log, name), "{name}");
        }
        for name in [
            "service.log",
            "service.log.1",
            "zkminer.log.2026-11-21",
            "pages.log",
            "pages.log.1",
            "job_journal.json",
            "key",
            "service-20261121T093015.123.txt",
            "service-20261121T093015.123.log.bak",
            "service-20261121T093015.123",
            "service-20261121T093015.12.log",
            "service-20261121T0930151.123.log",
            "service-2026112T093015.1234.log",
            "service-20261121t093015.123.log",
            "service_20261121T093015.123.log",
            "service-20261121T093015-123.log",
            "service-2026112aT093015.123.log",
            "xservice-20261121T093015.123.log",
            "other-20261121T093015.123.log",
            "service-20261121T093015.123-1.log",
            "service-２0261121T093015.123.log",
            "",
        ] {
            assert!(!is_nssm_rotated(log, name), "{name}");
        }
        // A file with no extension, and one whose only dot leads.
        assert!(is_nssm_rotated("out", "out-20261121T093015.123"));
        assert!(!is_nssm_rotated("out", "out-20261121T093015.123.log"));
        assert!(is_nssm_rotated(".log", ".log-20261121T093015.123"));
    }

    /// Beyond the newest ten rotated copies, oldest first; other files are never listed.
    #[test]
    fn rotated_copies_beyond_the_newest_ten_are_pruned() {
        let mut names: Vec<String> = (0..13)
            .map(|i| format!("service-202611{:02}T000000.000.log", i + 1))
            .collect();
        names.extend(
            [
                "service.log",
                "zkminer.log.2026-11-01",
                "key",
                "service-1.log",
            ]
            .map(String::from),
        );
        names.reverse();
        let pruned = rotated_to_prune("service.log", &names, KEEP_ROTATED);
        assert_eq!(
            pruned,
            vec![
                "service-20261101T000000.000.log",
                "service-20261102T000000.000.log",
                "service-20261103T000000.000.log"
            ]
        );
        assert!(rotated_to_prune("service.log", &names[..5], KEEP_ROTATED).is_empty());
    }

    /// The owner of a self-relative descriptor, as `GetFileSecurityW` returns it.
    #[test]
    fn a_descriptors_owner_is_read() {
        // Revision 1, control SE_SELF_RELATIVE | SE_OWNER_DEFAULTED=0, owner at 20.
        let mut sd = vec![1u8, 0, 0x00, 0x80];
        sd.extend(20u32.to_le_bytes());
        sd.extend([0u8; 12]);
        // S-1-5-18
        sd.extend([1u8, 1, 0, 0, 0, 0, 0, 5]);
        sd.extend(18u32.to_le_bytes());
        assert_eq!(descriptor_owner(&sd).as_deref(), Some("S-1-5-18"));
        let mut absolute = sd.clone();
        absolute[3] = 0;
        assert_eq!(descriptor_owner(&absolute), None);
        let mut no_owner = sd.clone();
        no_owner[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(descriptor_owner(&no_owner), None);
        assert_eq!(descriptor_owner(&sd[..10]), None);
    }

    /// The miner's own account owns a directory it made (the prune's precondition).
    #[test]
    fn this_account_owns_a_directory_it_made() {
        let dir = std::env::temp_dir().join(format!("zkminer-owner-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let owner = owner_of(&dir).unwrap();
        let me = zkminer_config::wallet::current_user_sid().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        // An administrator's files may be owned by Administrators instead.
        assert!(
            owner.eq_ignore_ascii_case(&me) || owner == "S-1-5-32-544",
            "{owner} vs {me}"
        );
    }

    /// Review 6 OJ-2: NSSM's exit actions as the README recipe sets them stop on every deliberate
    /// stop's code and restart on 75; unset, or set only as a default, they restart on everything.
    #[test]
    fn nssm_exit_actions_are_weighed() {
        let recipe = Nssm {
            exit_default: Some("Restart".into()),
            exit_for: vec![(0, Some("Exit".into())), (130, Some("Exit".into()))],
            stop_console_ms: Some(MIN_STOP_CONSOLE_MS),
            ..Nssm::default()
        };
        assert_eq!(exit_action(&recipe, 0), "Exit");
        assert_eq!(exit_action(&recipe, 75), "Restart");
        assert!(restarting_codes(&recipe).is_empty());
        assert_eq!(restart_warning("zkminer", &recipe), None);
        assert_eq!(stop_timeout_warning("zkminer", &recipe), None);

        let unset = Nssm::default();
        assert_eq!(restarting_codes(&unset), vec![0, 130]);
        let text = restart_warning("zkminer", &unset).unwrap();
        assert!(
            text.contains("nssm stop zkminer")
                && text.contains("`nssm set zkminer AppExit 0 Exit`")
                && text.contains("`nssm set zkminer AppExit 130 Exit`"),
            "{text}"
        );
        assert!(stop_timeout_warning("zkminer", &unset)
            .unwrap()
            .contains("1500 ms"));

        // A default of Exit stops on everything (75 included, which is the operator's choice).
        let all_exit = Nssm {
            exit_default: Some(" exit ".into()),
            ..Nssm::default()
        };
        assert!(restarting_codes(&all_exit).is_empty());
        // Ignore and Suicide do not stop the service cleanly either.
        for action in ["Ignore", "Suicide"] {
            let n = Nssm {
                exit_for: vec![(0, Some(action.into())), (130, Some("Exit".into()))],
                ..Nssm::default()
            };
            assert_eq!(restarting_codes(&n), vec![0], "{action}");
        }
        let short = Nssm {
            stop_console_ms: Some(30_000),
            ..recipe
        };
        assert!(stop_timeout_warning("zkminer", &short).is_some());
    }

    /// Review 6 OJ-1: the password verdict from the account's flags, its password's age and the
    /// policy's maximum age.
    #[test]
    fn a_service_accounts_password_is_weighed() {
        const DAY: u32 = 86_400;
        const MAX: u32 = 42 * DAY;
        assert_eq!(
            password_state(UF_DONT_EXPIRE_PASSWD, 400 * DAY, MAX),
            Password::NeverExpires
        );
        assert_eq!(
            password_state(0, 32 * DAY, MAX),
            Password::Expires(u64::from(10 * DAY))
        );
        assert_eq!(password_state(0, 42 * DAY, MAX), Password::Expired);
        assert_eq!(password_state(0, 50 * DAY, MAX), Password::Expired);
        assert_eq!(
            password_state(UF_PASSWORD_EXPIRED, 0, MAX),
            Password::Expired
        );
        assert_eq!(
            password_state(0, 400 * DAY, TIMEQ_FOREVER),
            Password::NoMaxAge
        );
        assert_eq!(
            password_state(UF_DONT_EXPIRE_PASSWD | UF_ACCOUNTDISABLE, 0, MAX),
            Password::Disabled
        );
        assert_eq!(password_state(UF_LOCKOUT, 0, MAX), Password::LockedOut);

        let now = 1_900_000_000;
        assert_eq!(
            password_finding("zkminer", Password::NeverExpires, now),
            None
        );
        let (fail, text) =
            password_finding("zkminer", Password::Expires(u64::from(10 * DAY)), now).unwrap();
        assert!(fail);
        assert!(
            text.contains("in 10 day(s)") && text.contains("-PasswordNeverExpires $true"),
            "{text}"
        );
        assert!(
            !password_finding("zkminer", Password::NoMaxAge, now)
                .unwrap()
                .0
        );
        for bad in [Password::Expired, Password::Disabled, Password::LockedOut] {
            assert!(password_finding("zkminer", bad, now).unwrap().0, "{bad:?}");
        }
    }

    #[test]
    fn a_services_local_account_is_told_from_its_object_name() {
        assert_eq!(local_account(r".\zkminer", "RIG"), Some("zkminer".into()));
        assert_eq!(local_account(r"rig\zkminer", "RIG"), Some("zkminer".into()));
        assert_eq!(local_account("LocalSystem", "RIG"), None);
        assert_eq!(local_account(r"NT AUTHORITY\LocalService", "RIG"), None);
        assert_eq!(local_account(r"CORP\miner", "RIG"), None);
        assert_eq!(local_account("miner@corp.example", "RIG"), None);
        assert_eq!(local_account(r".\", "RIG"), None);
    }

    /// `doctor`'s findings for a fake service list: a never-expiring account passes, an expiring
    /// one fails, a built-in account is only noted, and an unreadable one warns.
    #[test]
    fn doctor_weighs_each_services_account() {
        let services = [
            ("a".to_string(), r".\good".to_string()),
            ("b".to_string(), r"RIG\aging".to_string()),
            ("c".to_string(), "LocalSystem".to_string()),
            ("d".to_string(), r".\hidden".to_string()),
        ];
        let found = password_findings(
            &services,
            "RIG",
            |user| match user {
                "good" => Ok(Password::NeverExpires),
                "aging" => Ok(Password::Expires(5 * 86_400)),
                _ => Err(5),
            },
            1_900_000_000,
        );
        let levels: Vec<Finding> = found.iter().map(|f| f.0).collect();
        assert_eq!(
            levels,
            [Finding::Pass, Finding::Fail, Finding::Info, Finding::Warn]
        );
        assert!(found[1].1.contains("service b") && found[1].2.contains("aging"));
    }

    /// This process's own account can be read the way `run` reads it under a service.
    #[test]
    fn this_accounts_password_can_be_read() {
        let user = this_user().expect("a user name");
        // A domain or Microsoft account may have no local SAM entry: then 2221.
        match password_of(&user) {
            Ok(_) | Err(2221) => {}
            Err(e) => panic!("NetUserGetInfo({user}): {e}"),
        }
    }
}
