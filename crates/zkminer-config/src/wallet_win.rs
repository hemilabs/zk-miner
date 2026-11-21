//! Windows: where a key given as an environment variable (`key_source = "env"`) is kept for good.
//!
//! The miner removes the variable from its own environment once it has read it, but a variable
//! set for good lives on in the registry, and the usual places are readable by far more than the
//! miner:
//!
//! - the machine's environment (`setx /M`, System Properties): every user of this PC, and every
//!   process of theirs, Low integrity included, gets it;
//! - a service's environment, NSSM's `AppEnvironmentExtra` (or `AppEnvironment`) in
//!   `Services\<service>\Parameters`, and the service manager's own `Environment` value: the
//!   `Services` key grants every local user read access;
//! - the user's environment (`setx`, `HKCU\Environment`): every process of this user, Low
//!   integrity included (the registry has no label that keeps Low from reading it).
//!
//! [`persisted_key_env_copies`] finds these by the variable's name. It never returns or logs a
//! value: a plain value is only checked for, and an environment block is read to compare the names
//! in it, in memory that is zeroed afterwards.

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;

use zeroize::Zeroizing;

type Hkey = *mut c_void;

/// `HKEY_CURRENT_USER` and `HKEY_LOCAL_MACHINE`: `(HKEY)(ULONG_PTR)(LONG)0x8000000N`, sign-extended.
const HKEY_CURRENT_USER: isize = 0x8000_0001u32 as i32 as isize;
const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;

const KEY_QUERY_VALUE: u32 = 0x0001;
const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
const ERROR_SUCCESS: i32 = 0;
const ERROR_MORE_DATA: i32 = 234;
const ERROR_NO_MORE_ITEMS: i32 = 259;
const REG_MULTI_SZ: u32 = 7;

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(
        key: Hkey,
        sub_key: *const u16,
        options: u32,
        desired: u32,
        result: *mut Hkey,
    ) -> i32;
    fn RegQueryValueExW(
        key: Hkey,
        value_name: *const u16,
        reserved: *mut u32,
        value_type: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> i32;
    fn RegEnumKeyExW(
        key: Hkey,
        index: u32,
        name: *mut u16,
        name_len: *mut u32,
        reserved: *mut u32,
        class: *mut u16,
        class_len: *mut u32,
        last_write: *mut c_void,
    ) -> i32;
    fn RegCloseKey(key: Hkey) -> i32;
}

/// A copy of the key's variable kept in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEnvCopy {
    /// The registry key and value, as `reg query` names them.
    pub location: String,
    /// Readable by every user of this PC (and their Low-integrity processes); otherwise by every
    /// process of this user.
    pub machine_wide: bool,
}

/// Every place in the registry that keeps the variable `name` for good: see the module docs.
/// Names only, never values. A place that cannot be read is skipped.
pub fn persisted_key_env_copies(name: &str) -> Vec<KeyEnvCopy> {
    let mut copies = Vec::new();
    let machine_env = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
    if value_exists(HKEY_LOCAL_MACHINE as Hkey, machine_env, name) {
        copies.push(KeyEnvCopy {
            location: format!(r"HKLM\{machine_env} ({name})"),
            machine_wide: true,
        });
    }
    copies.extend(
        services_with(
            HKEY_LOCAL_MACHINE as Hkey,
            r"SYSTEM\CurrentControlSet\Services",
            name,
        )
        .into_iter()
        .map(|place| KeyEnvCopy {
            location: format!(r"HKLM\{place}"),
            machine_wide: true,
        }),
    );
    if value_exists(HKEY_CURRENT_USER as Hkey, "Environment", name) {
        copies.push(KeyEnvCopy {
            location: format!(r"HKCU\Environment ({name})"),
            machine_wide: false,
        });
    }
    copies
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain([0]).collect()
}

/// An open registry key, closed on drop.
struct Key(Hkey);

impl Key {
    fn open(root: Hkey, path: &str, access: u32) -> Option<Self> {
        let path = wide(path);
        let mut key = std::ptr::null_mut();
        // SAFETY: a NUL-terminated path and an out-pointer; the key is owned at once.
        let status = unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, access, &mut key) };
        (status == ERROR_SUCCESS).then_some(Self(key))
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: a key this value opened.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Whether `path` under `root` has a value `name` (asked without its data, so none is read).
fn value_exists(root: Hkey, path: &str, name: &str) -> bool {
    let Some(key) = Key::open(root, path, KEY_QUERY_VALUE) else {
        return false;
    };
    let name = wide(name);
    // SAFETY: an open key and a NUL-terminated name; every out-pointer is null, so nothing is read.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    status == ERROR_SUCCESS || status == ERROR_MORE_DATA
}

/// The environment blocks under each service of `services` (below `root`) that set `name`, as
/// `<services>\<service>\<subkey> (<value>)`.
fn services_with(root: Hkey, services: &str, name: &str) -> Vec<String> {
    let Some(list) = Key::open(root, services, KEY_ENUMERATE_SUB_KEYS) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for index in 0.. {
        // A key name is at most 255 characters.
        let mut buf = [0u16; 256];
        let mut len = buf.len() as u32;
        // SAFETY: an open key and a buffer of `len` characters; the rest is not asked for.
        let status = unsafe {
            RegEnumKeyExW(
                list.0,
                index,
                buf.as_mut_ptr(),
                &mut len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status != ERROR_SUCCESS {
            continue;
        }
        let service = String::from_utf16_lossy(&buf[..len as usize]);
        for (sub, value) in [
            (r"\Parameters", "AppEnvironmentExtra"),
            (r"\Parameters", "AppEnvironment"),
            ("", "Environment"),
        ] {
            let path = format!(r"{services}\{service}{sub}");
            if block_sets(root, &path, value, name) {
                found.push(format!("{path} ({value})"));
            }
        }
    }
    found
}

/// Whether the `REG_MULTI_SZ` environment block `value` of `path` sets `name`. Its data is read
/// into memory zeroed on drop and only its names are compared.
fn block_sets(root: Hkey, path: &str, value: &str, name: &str) -> bool {
    let Some(key) = Key::open(root, path, KEY_QUERY_VALUE) else {
        return false;
    };
    let value = wide(value);
    for _ in 0..4 {
        let (mut kind, mut bytes) = (0u32, 0u32);
        // SAFETY: an open key, a NUL-terminated name and out-pointers; no data is asked for.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                value.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                std::ptr::null_mut(),
                &mut bytes,
            )
        };
        if status != ERROR_SUCCESS || kind != REG_MULTI_SZ {
            return false;
        }
        let mut data = Zeroizing::new(vec![0u16; (bytes as usize).div_ceil(2)]);
        let mut got = (data.len() * 2) as u32;
        // SAFETY: a buffer of `got` bytes.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                value.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut got,
            )
        };
        match status {
            ERROR_SUCCESS if kind == REG_MULTI_SZ => {
                let len = (got as usize / 2).min(data.len());
                return env_block_names_match(&data[..len], name);
            }
            // It grew in between: again.
            ERROR_MORE_DATA => continue,
            _ => return false,
        }
    }
    false
}

/// Whether the `REG_MULTI_SZ` block `block` (`NAME=value` strings, each NUL-terminated) has an
/// entry for `name`. The name is matched without case (as Windows does), up to the first `=`
/// (after the first character: Windows' hidden `=C:` variables start with one); an entry without
/// `=` names nothing. Looks at names only.
pub(crate) fn env_block_names_match(block: &[u16], name: &str) -> bool {
    let name: Vec<u16> = OsStr::new(name).encode_wide().collect();
    let eq = u16::from(b'=');
    let upper = |c: u16| {
        if (u16::from(b'a')..=u16::from(b'z')).contains(&c) {
            c - 32
        } else {
            c
        }
    };
    block
        .split(|&c| c == 0)
        .filter_map(|entry| {
            let at = entry.iter().skip(1).position(|&c| c == eq)? + 1;
            Some(&entry[..at])
        })
        .any(|entry_name| {
            entry_name.len() == name.len()
                && entry_name
                    .iter()
                    .zip(&name)
                    .all(|(&a, &b)| upper(a) == upper(b))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(entries: &[&str]) -> Vec<u16> {
        let mut b: Vec<u16> = Vec::new();
        for e in entries {
            b.extend(OsStr::new(e).encode_wide());
            b.push(0);
        }
        b.push(0);
        b
    }

    #[test]
    fn an_environment_block_is_matched_by_name_only() {
        let name = "ZKMINER_PRIVATE_KEY";
        assert!(env_block_names_match(
            &block(&["A=1", "ZKMINER_PRIVATE_KEY=0xabc"]),
            name
        ));
        assert!(env_block_names_match(
            &block(&["zkminer_private_key=x"]),
            name
        ));
        // An empty value still sets it.
        assert!(env_block_names_match(
            &block(&["ZKMINER_PRIVATE_KEY="]),
            name
        ));
        // A value that mentions it, a longer or shorter name, no `=`: no.
        assert!(!env_block_names_match(
            &block(&["OTHER=ZKMINER_PRIVATE_KEY=1"]),
            name
        ));
        assert!(!env_block_names_match(
            &block(&["ZKMINER_PRIVATE_KEY2=1", "ZKMINER_PRIVATE_KE=1"]),
            name
        ));
        assert!(!env_block_names_match(
            &block(&["ZKMINER_PRIVATE_KEY"]),
            name
        ));
        assert!(!env_block_names_match(&block(&["=C:=C:\\", "=X"]), name));
        assert!(!env_block_names_match(&[], name));
        // Not NUL-terminated at the end (as a value written by hand may be).
        let mut b = block(&["ZKMINER_PRIVATE_KEY=1"]);
        b.truncate(b.len() - 2);
        assert!(env_block_names_match(&b, name));
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn RegCreateKeyExW(
            key: Hkey,
            sub_key: *const u16,
            reserved: u32,
            class: *const u16,
            options: u32,
            desired: u32,
            attributes: *const c_void,
            result: *mut Hkey,
            disposition: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            key: Hkey,
            name: *const u16,
            reserved: u32,
            value_type: u32,
            data: *const u8,
            len: u32,
        ) -> i32;
        fn RegDeleteTreeW(key: Hkey, sub_key: *const u16) -> i32;
    }

    /// Sets `value` of `HKCU\<path>` (created) to `data` of `kind`.
    fn set(path: &str, value: &str, kind: u32, data: &[u16]) {
        const KEY_ALL_ACCESS: u32 = 0xF003F;
        let (path, value) = (wide(path), wide(value));
        let mut key = std::ptr::null_mut();
        // SAFETY: NUL-terminated strings, out-pointers and a buffer of the length given; the key
        // is closed by `Key`.
        unsafe {
            assert_eq!(
                RegCreateKeyExW(
                    HKEY_CURRENT_USER as Hkey,
                    path.as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    KEY_ALL_ACCESS,
                    std::ptr::null(),
                    &mut key,
                    std::ptr::null_mut(),
                ),
                ERROR_SUCCESS
            );
            let key = Key(key);
            assert_eq!(
                RegSetValueExW(
                    key.0,
                    value.as_ptr(),
                    0,
                    kind,
                    data.as_ptr().cast(),
                    (data.len() * 2) as u32,
                ),
                ERROR_SUCCESS
            );
        }
    }

    /// The scan over a services tree this test makes under `HKCU\Software` (with made-up values):
    /// a service whose NSSM block or own environment sets the name is found, by name only, and one
    /// that does not, a plain string value and a missing value are not.
    #[test]
    fn services_that_set_the_variable_are_found() {
        const REG_SZ: u32 = 1;
        let root = format!(r"Software\zkminer-test-{}", std::process::id());
        let services = format!(r"{root}\Services");
        set(
            &format!(r"{services}\nssm-svc\Parameters"),
            "AppEnvironmentExtra",
            REG_MULTI_SZ,
            &block(&["PATH=x", "zkminer_private_key=not-a-key"]),
        );
        set(
            &format!(r"{services}\scm-svc"),
            "Environment",
            REG_MULTI_SZ,
            &block(&["ZKMINER_PRIVATE_KEY=not-a-key"]),
        );
        set(
            &format!(r"{services}\other-svc\Parameters"),
            "AppEnvironmentExtra",
            REG_MULTI_SZ,
            &block(&["OTHER=ZKMINER_PRIVATE_KEY"]),
        );
        set(
            &format!(r"{services}\string-svc\Parameters"),
            "AppEnvironmentExtra",
            REG_SZ,
            &wide("ZKMINER_PRIVATE_KEY=not-a-key"),
        );
        set(
            &format!(r"{root}\Env"),
            "ZKMINER_PRIVATE_KEY",
            REG_SZ,
            &wide("x"),
        );
        let hkcu = HKEY_CURRENT_USER as Hkey;
        let mut found = services_with(hkcu, &services, "ZKMINER_PRIVATE_KEY");
        let in_env = value_exists(hkcu, &format!(r"{root}\Env"), "zkminer_private_key");
        let not_in_env = value_exists(hkcu, &format!(r"{root}\Env"), "OTHER");
        let none = services_with(hkcu, &format!(r"{root}\Missing"), "ZKMINER_PRIVATE_KEY");
        let root_w = wide(&root);
        // SAFETY: a NUL-terminated path under HKCU this test made.
        unsafe { RegDeleteTreeW(hkcu, root_w.as_ptr()) };
        found.sort();
        assert_eq!(
            found,
            [
                format!(r"{services}\nssm-svc\Parameters (AppEnvironmentExtra)"),
                format!(r"{services}\scm-svc (Environment)"),
            ]
        );
        assert!(found.iter().all(|f| !f.contains("not-a-key")));
        assert!(in_env && !not_in_env);
        assert!(none.is_empty());
    }
}
