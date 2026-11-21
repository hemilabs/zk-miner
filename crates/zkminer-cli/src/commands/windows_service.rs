//! Windows: the service the miner runs as (README: Windows service), as `zkminer doctor`, `zkminer
//! run` and `zkminer stop` check it.
//!
//! - The service account's password (review 6 OJ-1). A local account's password expires after the
//!   policy's maximum age (42 days on a workgroup PC by default) unless it is set never to. The
//!   service then fails to log on at its next start (SCM error 1069/1330): nothing runs, and every
//!   lock kept for that start is slashed. Read with `NetUserGetInfo` level 1 and
//!   `NetUserModalsGet` level 0.
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

#[cfg(test)]
mod tests {
    use super::*;

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
