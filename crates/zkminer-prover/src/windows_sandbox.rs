//! Keeping a requester's guest away from the operator's key on Windows.
//!
//! A worker runs a requester's guest program. On Linux it confines itself before the first guest
//! (`zkminer_witness_sandbox::confine`) and the miner is not dumpable; on Windows a worker is a
//! process of the operator's, and one that a guest got code execution in could read the miner's
//! memory (the signing key) or the key on disk. So, on Windows:
//!
//! - The miner's process, and each of its threads, grants this user only what a process manager
//!   needs: query its name and times, wait for it, end it ([`lock_down_this_process`]). No other
//!   process of the user's, a worker included, can read its memory, inject code, or change that
//!   back; an elevated process with `SeDebugPrivilege` still can. Its label (Medium, no write, read
//!   or execute up) keeps even those from Low processes: a Low worker cannot end the miner.
//! - Every worker starts suspended in a job of its own (`windows_job::new_worker_job`: no desktop,
//!   no clipboard, no breakaway) and is resumed once it is in it ([`spawn_worker`]).
//! - Every worker runs at Low integrity ([`low_il_workers`]): it cannot open the miner at all
//!   (another process of the user's at Medium, only to see and end it), nor write a file or
//!   registry key at Medium. Its temporary, cache and segment directories are made writable at Low
//!   before each Low worker starts ([`low_dirs`]), and the key file, `~/.zkminer/.env` and the lock
//!   journal get a label Low processes cannot read through ([`protect_secrets`],
//!   [`write_secret_file`]); a Low worker is never started beside one that could not be labelled.
//!   What its warm-up downloads or builds in the profile (`~/.risc0`, `~/.sp1`) its binary installs
//!   first, at Medium (`worker::install_artifacts_at_medium`, and [`install_sp1_server`]). No other
//!   Low worker can open its process or first thread at all ([`low_worker_descriptors`]), nor a
//!   thread it starts later but to see it (`zkminer_prover_protocol::threads`); the processes it
//!   starts (SP1's `sp1-gpu-server`) are still open to them, and it shares its temporary and cache
//!   directories with them. It still has the network.
//!   Low workers fail closed: a worker that cannot start at Low (its handshake fails, or its
//!   directories cannot be prepared) is not started at Medium instead but paged and tried again at
//!   Low after a back-off ([`low_il_worker_failed`]), as a Low process could otherwise force the
//!   fallback.
//!
//! `ZKMINER_WINDOWS_LOW_IL_WORKERS=0` runs the workers at Medium instead, for a GPU runtime that
//! does not work at Low: they can then read every file of the user's, the key file and `.env`
//! included. It is paged at every start ([`page_medium_workers`]), and `zkminer doctor` warns.
//!
//! All of this assumes the miner runs as an ordinary user. As LocalSystem the lock-down grants
//! every worker everything (its DACL grants SYSTEM all rights), and as LocalService or
//! NetworkService a worker reaches every other service run as that account; so `zkminer run`
//! refuses these accounts, and an administrator under a service logon, unless
//! [`ALLOW_PRIVILEGED_ACCOUNT_ENV`] is set, and pages an elevated console ([`account_refusal`],
//! [`page_account_risk`]).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{c_void, OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdin, ChildStdout, ExitStatus};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock};

/// Workers run at Low integrity unless this is `0` (see the module docs): the opt-out, paged at every
/// start ([`page_medium_workers`]). `1`, or anything else, leaves them at Low.
pub const LOW_IL_WORKERS_ENV: &str = "ZKMINER_WINDOWS_LOW_IL_WORKERS";

type Handle = *mut c_void;

// Process and thread rights (winnt.h).
const PROCESS_TERMINATE: u32 = 0x0001;
const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
const SYNCHRONIZE: u32 = 0x0010_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;

const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const LABEL_SECURITY_INFORMATION: u32 = 0x0000_0010;
const SE_FILE_OBJECT: i32 = 1;
const SDDL_REVISION_1: u32 = 1;

/// What this user keeps on the miner's process: see it in a process list, wait for it, end it.
const PROCESS_USER_RIGHTS: u32 =
    PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE;
/// And on each of its threads.
const THREAD_USER_RIGHTS: u32 = THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;

/// A directory, and everything made in it, that a Low process may write.
const LOW_WRITABLE_DIR: &str = "S:(ML;OICI;NW;;;LW)";
/// A file that Low processes can neither read nor write (Medium processes are not affected).
const NO_READ_UP_FILE: &str = "S:(ML;;NWNR;;;ME)";

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: *mut c_void,
    inherit_handle: i32,
}

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    reserved2_len: u16,
    reserved2: *mut u8,
    std_input: Handle,
    std_output: Handle,
    std_error: Handle,
}

#[repr(C)]
struct StartupInfoExW {
    startup_info: StartupInfoW,
    attribute_list: *mut c_void,
}

#[repr(C)]
struct ProcessInformation {
    process: Handle,
    thread: Handle,
    process_id: u32,
    thread_id: u32,
}

#[repr(C)]
struct ThreadEntry32 {
    size: u32,
    usage: u32,
    thread_id: u32,
    owner_process_id: u32,
    base_priority: i32,
    delta_priority: i32,
    flags: u32,
}

#[repr(C)]
struct TokenMandatoryLabel {
    sid: *mut c_void,
    attributes: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentThread() -> Handle;
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
    fn InitializeProcThreadAttributeList(
        list: *mut c_void,
        count: u32,
        flags: u32,
        size: *mut usize,
    ) -> i32;
    fn UpdateProcThreadAttribute(
        list: *mut c_void,
        flags: u32,
        attribute: usize,
        value: *const c_void,
        size: usize,
        previous: *mut c_void,
        returned: *mut usize,
    ) -> i32;
    fn DeleteProcThreadAttributeList(list: *mut c_void);
    fn CreateProcessW(
        application: *const u16,
        command_line: *mut u16,
        process_attributes: *const SecurityAttributes,
        thread_attributes: *const SecurityAttributes,
        inherit_handles: i32,
        flags: u32,
        environment: *const c_void,
        current_directory: *const u16,
        startup_info: *const StartupInfoExW,
        information: *mut ProcessInformation,
    ) -> i32;
    fn ResumeThread(thread: Handle) -> u32;
    fn TerminateProcess(process: Handle, exit_code: u32) -> i32;
    fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
    fn OpenThread(access: u32, inherit: i32, thread_id: u32) -> Handle;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        attributes: *const SecurityAttributes,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
}

#[link(name = "advapi32")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorSacl(
        descriptor: *mut c_void,
        present: *mut i32,
        sacl: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    fn SetNamedSecurityInfoW(
        name: *const u16,
        object_type: i32,
        information: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
    ) -> u32;
    fn SetKernelObjectSecurity(handle: Handle, information: u32, descriptor: *mut c_void) -> i32;
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn SetTokenInformation(token: Handle, class: i32, info: *const c_void, length: u32) -> i32;
    // The tests read a token's integrity level with it.
    #[cfg(test)]
    fn GetTokenInformation(
        token: Handle,
        class: i32,
        info: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

/// A security descriptor made from SDDL, freed on drop.
struct Descriptor(*mut c_void);

impl Descriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let text = wide(OsStr::new(sddl));
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: a NUL-terminated string and an out-pointer; the result is owned by `Self`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    /// Its SACL (where a mandatory label lives).
    fn sacl(&self) -> io::Result<*mut c_void> {
        let (mut present, mut defaulted, mut sacl) = (0, 0, std::ptr::null_mut());
        // SAFETY: a valid descriptor and out-pointers; the SACL points into the descriptor.
        if unsafe { GetSecurityDescriptorSacl(self.0, &mut present, &mut sacl, &mut defaulted) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        if present == 0 || sacl.is_null() {
            return Err(io::Error::other("the descriptor has no SACL"));
        }
        Ok(sacl)
    }

    /// The parts `information` names, as SDDL.
    fn to_sddl(&self, information: u32) -> io::Result<String> {
        #[link(name = "advapi32")]
        extern "system" {
            fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor: *mut c_void,
                revision: u32,
                information: u32,
                sddl: *mut *mut u16,
                length: *mut u32,
            ) -> i32;
        }
        let (mut text, mut length) = (std::ptr::null_mut(), 0u32);
        // SAFETY: a valid descriptor and out-pointers; the string is read (its length is in UTF-16
        // units, the NUL included) and freed here.
        unsafe {
            if ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.0,
                SDDL_REVISION_1,
                information,
                &mut text,
                &mut length,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let units = std::slice::from_raw_parts(text, length.saturating_sub(1) as usize);
            let sddl = String::from_utf16_lossy(units);
            LocalFree(text.cast());
            Ok(sddl.trim_end_matches('\0').to_string())
        }
    }

    /// Kept for the life of the process (the thread hook below reads it from any thread).
    fn leak(self) -> *mut c_void {
        let p = self.0;
        std::mem::forget(self);
        p
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the SDDL conversion, used by nothing any more.
        unsafe { LocalFree(self.0) };
    }
}

fn set_dacl(handle: Handle, descriptor: *mut c_void) -> io::Result<()> {
    set_security(handle, DACL_SECURITY_INFORMATION, descriptor)
}

fn set_security(handle: Handle, information: u32, descriptor: *mut c_void) -> io::Result<()> {
    // SAFETY: a handle with WRITE_DAC, and WRITE_OWNER for a label (or a pseudo-handle, which has
    // every right), and a valid descriptor.
    if unsafe { SetKernelObjectSecurity(handle, information, descriptor) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The DACL for the miner's process or one of its threads: `user_rights` for this user, the same for
/// whoever owns it (`OWNER RIGHTS`, so the owner's implicit `WRITE_DAC` cannot take the rest back),
/// everything for SYSTEM. Protected, so nothing is inherited.
fn locked_dacl(user: &str, user_rights: u32, all: u32) -> String {
    format!("D:P(A;;{user_rights:#x};;;{user})(A;;{all:#x};;;SY)(A;;{user_rights:#x};;;OW)")
}

/// The label of the miner's process and threads, and of a Low worker's: Medium, no write, read or
/// execute up. A Low process gets no right on it at all, not even the generic execute ones no
/// write or read policy withholds (`TERMINATE`, `SYNCHRONIZE`, `QUERY_LIMITED_INFORMATION`): a Low
/// worker can neither end the miner (nor a sibling) nor tell when one ends. Processes at Medium or
/// above, `zkminer stop` and the miner itself included, are not affected.
const NO_UP_LABEL: &str = "S:(ML;;NWNRNX;;;ME)";

/// [`locked_dacl`] with [`NO_UP_LABEL`].
fn locked_descriptor(user: &str, user_rights: u32, all: u32) -> io::Result<Descriptor> {
    Descriptor::from_sddl(&format!(
        "{}{NO_UP_LABEL}",
        locked_dacl(user, user_rights, all)
    ))
}

/// What [`lock_down_this_process`] sets: the DACL and the label.
const LOCKED_INFORMATION: u32 = DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;

/// The descriptor every thread of the miner gets once [`lock_down_this_process`] ran.
static THREAD_DESCRIPTOR: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Run by the loader on every thread this process starts, on that thread, before its own code:
/// a thread's object takes its DACL from the token, which grants this user everything, so each
/// new thread locks itself as the ones running at [`lock_down_this_process`] were. (Without it a
/// process of the user's could open one of the miner's threads and change its context.) Only
/// `SetKernelObjectSecurity`, which loads nothing: it runs under the loader lock.
unsafe extern "system" fn on_thread_attach(_module: *mut c_void, reason: u32, _: *mut c_void) {
    const DLL_THREAD_ATTACH: u32 = 2;
    if reason == DLL_THREAD_ATTACH {
        let descriptor = THREAD_DESCRIPTOR.load(Ordering::Acquire);
        if !descriptor.is_null() {
            // SAFETY: the pseudo-handle of the calling thread and a descriptor that is never freed.
            unsafe { SetKernelObjectSecurity(GetCurrentThread(), LOCKED_INFORMATION, descriptor) };
        }
    }
}

/// The TLS callback table entry for [`on_thread_attach`] (`.CRT$XL*`, between the CRT's own
/// `XLA` and `XLZ`, as std's is).
#[used]
#[link_section = ".CRT$XLC"]
static ON_THREAD_ATTACH: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) =
    on_thread_attach;

/// Lock this process and its threads to this user as the module docs say. For the miner's `main`,
/// first thing: everything it does to itself goes through pseudo-handles, which this does not
/// restrict, and it opens only its workers and their children by pid.
///
/// A thread started between its creation and its first instruction (when the loader runs the
/// hook above) still has the token's DACL; a process of the user's that opened it in that window
/// keeps its handle. Elevated processes with `SeDebugPrivilege` are not stopped.
pub fn lock_down_this_process() -> io::Result<()> {
    let user = zkminer_config::wallet::current_user_sid()?;
    let process = locked_descriptor(&user, PROCESS_USER_RIGHTS, PROCESS_ALL_ACCESS)?;
    // SAFETY: the pseudo-handle of this process. Its label may be set at or below this process's
    // own level with no privilege (WRITE_OWNER, which the pseudo-handle has).
    set_security(
        unsafe { GetCurrentProcess() },
        LOCKED_INFORMATION,
        process.0,
    )?;
    let thread = locked_descriptor(&user, THREAD_USER_RIGHTS, THREAD_ALL_ACCESS)?;
    let thread = thread.leak();
    // The threads started from now on lock themselves, then the ones running now are locked.
    THREAD_DESCRIPTOR.store(thread, Ordering::Release);
    // Referenced, so the linker keeps the TLS callback (as std does for its own).
    // SAFETY: a plain read of a static.
    let _ = unsafe { std::ptr::from_ref(&ON_THREAD_ATTACH).read_volatile() };
    lock_running_threads(thread)
}

/// Libraries loaded by name from now on (by this process's code or the libraries it uses: the GPU
/// vendors' telemetry, NVML) are looked for only beside the program and in System32, never in the
/// current directory or on `PATH`, where anyone who can write there could put a library of that
/// name in the miner. For the miner's `main`, first thing. A failure is reported, not fatal: the
/// vendors' libraries are loaded from System32 by full search flags anyway.
pub fn restrict_library_search() {
    const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u32 = 0x0000_0200;
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
    #[link(name = "kernel32")]
    extern "system" {
        fn SetDefaultDllDirectories(flags: u32) -> i32;
    }
    // SAFETY: a plain kernel32 call with documented flags.
    if unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)
    } == 0
    {
        eprintln!(
            "warning: the library search could not be limited to System32 ({})",
            io::Error::last_os_error()
        );
    }
}

/// Locks every thread of this process running now. A thread that ended in the meantime is skipped.
fn lock_running_threads(descriptor: *mut c_void) -> io::Result<()> {
    const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
    // SAFETY: plain kernel32 calls on a snapshot this function owns; `entry` outlives each call.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        let snapshot = OwnedHandle::from_raw_handle(snapshot);
        let me = GetCurrentProcessId();
        let mut entry: ThreadEntry32 = std::mem::zeroed();
        entry.size = std::mem::size_of::<ThreadEntry32>() as u32;
        let mut more = Thread32First(snapshot.as_raw_handle(), &mut entry) != 0;
        let mut failed = None;
        while more {
            if entry.owner_process_id == me {
                let thread = OpenThread(WRITE_DAC | WRITE_OWNER, 0, entry.thread_id);
                if !thread.is_null() {
                    let thread = OwnedHandle::from_raw_handle(thread);
                    if let Err(e) =
                        set_security(thread.as_raw_handle(), LOCKED_INFORMATION, descriptor)
                    {
                        failed = Some(e);
                    }
                }
            }
            more = Thread32Next(snapshot.as_raw_handle(), &mut entry) != 0;
        }
        failed.map_or(Ok(()), Err)
    }
}

/// Set to `1` to let `zkminer run` start anyway as LocalSystem, LocalService or NetworkService, as
/// an administrator under a service logon, or when it cannot tell which account it runs as
/// ([`account_refusal`]). Its workers then run as that account: a requester's guest that breaks
/// out of one has that account's rights, and the lock-down above keeps no worker out of the miner.
pub const ALLOW_PRIVILEGED_ACCOUNT_ENV: &str = "ZKMINER_DANGEROUSLY_ALLOW_PRIVILEGED_ACCOUNT";

/// Why the account the miner runs as is a bad one for running requesters' guests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountRisk {
    /// LocalSystem, LocalService or NetworkService (named). Under LocalSystem a worker is the
    /// whole machine, and the lock-down's DACL, which grants SYSTEM everything, grants it to every
    /// worker too; the other two are shared with other services, which a worker would reach.
    ServiceAccount(&'static str),
    /// An administrator's account under a service logon, whose token UAC never filters: every
    /// worker is an administrator of this PC, as good as SYSTEM.
    AdminService,
    /// An administrator's token with the Administrators group enabled outside a service logon (an
    /// elevated console, or in session 0 an administrator's OpenSSH, WinRM or PsExec logon or a
    /// "highest privileges" scheduled task): so are the workers' tokens.
    Elevated,
    /// An administrator's console that is not elevated (the Administrators group is there for deny
    /// only). UAC is not a security boundary: a worker a guest broke out of can elevate.
    FilteredAdmin,
}

/// What a token whose user is `user_sid` (`S-1-5-…`), with `admin` and under a service logon or
/// not, is: see [`AccountRisk`]. `TokenElevation` plays no part: a standard account's service
/// token holding SeImpersonatePrivilege can read as elevated.
pub fn classify_account(
    user_sid: &str,
    admin: crate::windows_account::AdminState,
    service_logon: bool,
) -> Option<AccountRisk> {
    use crate::windows_account::AdminState;
    match user_sid.trim().to_ascii_uppercase().as_str() {
        "S-1-5-18" => Some(AccountRisk::ServiceAccount("LocalSystem")),
        "S-1-5-19" => Some(AccountRisk::ServiceAccount("LocalService")),
        "S-1-5-20" => Some(AccountRisk::ServiceAccount("NetworkService")),
        _ => match admin {
            AdminState::Full if service_logon => Some(AccountRisk::AdminService),
            AdminState::Full => Some(AccountRisk::Elevated),
            AdminState::Filtered => Some(AccountRisk::FilteredAdmin),
            AdminState::None => None,
        },
    }
}

/// This process's [`AccountRisk`], from its token.
pub fn account_risk() -> io::Result<Option<AccountRisk>> {
    let user = zkminer_config::wallet::current_user_sid()?;
    Ok(classify_account(
        &user,
        crate::windows_account::admin_state()?,
        crate::windows_account::is_service_logon()?,
    ))
}

/// Whether [`ALLOW_PRIVILEGED_ACCOUNT_ENV`] is `1`.
pub fn privileged_account_allowed() -> bool {
    std::env::var(ALLOW_PRIVILEGED_ACCOUNT_ENV).is_ok_and(|v| v.trim() == "1")
}

/// Why `zkminer run` refuses to start as `risk` ([`account_risk`]), or `None` if it starts. A
/// service account (LocalSystem, LocalService, NetworkService), an administrator under a service
/// logon, and an account that could not be told (`Err`: fail closed) are refused unless `allowed`
/// ([`ALLOW_PRIVILEGED_ACCOUNT_ENV`]); an administrator's console is not refused
/// ([`page_account_risk`]).
pub fn account_refusal(risk: &io::Result<Option<AccountRisk>>, allowed: bool) -> Option<String> {
    if allowed {
        return None;
    }
    match risk {
        Ok(Some(AccountRisk::ServiceAccount(account))) => Some(format!(
            "refusing to run as {account}: every prover worker would run as {account} too, so a \
             requester's guest program that broke out of one would have {account}'s rights, and \
             no worker could be kept out of the miner (and its signing key). Run the miner as a \
             dedicated standard user (README: Windows service). To run as {account} anyway, \
             accepting that, set {ALLOW_PRIVILEGED_ACCOUNT_ENV}=1"
        )),
        Ok(Some(AccountRisk::AdminService)) => Some(format!(
            "refusing to run as an administrator under a service logon: its token has the \
             Administrators group enabled (UAC filters no service logon), and so would every \
             prover worker's, so a requester's guest program that broke out of one would be an \
             administrator of this PC and could take the miner's signing key. Run the miner as a \
             dedicated standard user (README: Windows service). To run as this account anyway, \
             accepting that, set {ALLOW_PRIVILEGED_ACCOUNT_ENV}=1"
        )),
        Err(e) => Some(format!(
            "refusing to run: could not tell which account the miner runs as ({e}), so not \
             whether its prover workers would be LocalSystem or an administrator. Set \
             {ALLOW_PRIVILEGED_ACCOUNT_ENV}=1 to start anyway"
        )),
        Ok(_) => None,
    }
}

/// For `zkminer run`, once logging is up: pages the operator of an account it was allowed to start
/// as ([`account_refusal`]) or of an elevated console, which it starts as anyway, and warns of an
/// administrator's console that is not elevated.
pub fn page_account_risk() {
    match account_risk() {
        Ok(Some(AccountRisk::ServiceAccount(account))) => tracing::error!(
            "PAGE: PRIVILEGED-ACCOUNT — the miner runs as {account} \
             ({ALLOW_PRIVILEGED_ACCOUNT_ENV}=1): its prover workers run as {account}, a \
             requester's guest that breaks out of one has {account}'s rights, and the miner's \
             process lock-down cannot keep the workers out of the miner. Run it as a dedicated \
             standard user (README: Windows service)"
        ),
        Ok(Some(AccountRisk::AdminService)) => tracing::error!(
            "PAGE: PRIVILEGED-ACCOUNT — the miner runs as an administrator under a service logon \
             ({ALLOW_PRIVILEGED_ACCOUNT_ENV}=1): its prover workers are administrators of this \
             PC, and a requester's guest that breaks out of one can take the miner's key. Run it \
             as a dedicated standard user (README: Windows service)"
        ),
        Ok(Some(AccountRisk::Elevated)) => tracing::error!(
            "PAGE: ELEVATED — the miner runs as an administrator with the Administrators \
             group enabled (an elevated console, or an OpenSSH, WinRM or PsExec logon or a \
             \"highest privileges\" scheduled task): its prover workers do too, so a \
             requester's guest that breaks out of one is an administrator of this PC. Run it \
             from a console that is not elevated, or as a dedicated standard user"
        ),
        Ok(Some(AccountRisk::FilteredAdmin)) => tracing::warn!(
            "the miner runs as an administrator, in a console that is not elevated: UAC is not a \
             security boundary, so a requester's guest that breaks out of a prover worker can \
             become an administrator of this PC. Run it as a dedicated standard user"
        ),
        Ok(None) => {}
        Err(e) => tracing::error!(
            "PAGE: PRIVILEGED-ACCOUNT — could not tell which account the miner runs as ({e}); \
             started anyway ({ALLOW_PRIVILEGED_ACCOUNT_ENV}=1)"
        ),
    }
}

/// Whether workers are to run at Low integrity, read once: yes, unless [`LOW_IL_WORKERS_ENV`] is
/// `0` ([`low_il_from`]).
pub fn low_il_workers() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| low_il_from(std::env::var(LOW_IL_WORKERS_ENV).ok().as_deref()))
}

/// Whether [`LOW_IL_WORKERS_ENV`] set to `value` (`None`: unset) runs the workers at Low: every
/// value but `0`, so that a typo never leaves them at Medium.
pub fn low_il_from(value: Option<&str>) -> bool {
    value.is_none_or(|v| v.trim() != "0")
}

/// The flag's value when it is set to something other than `0`, `1` or nothing (which leaves the
/// workers at Low all the same), for `zkminer doctor`.
pub fn low_il_workers_misset() -> Option<String> {
    std::env::var(LOW_IL_WORKERS_ENV)
        .ok()
        .filter(|v| !matches!(v.trim(), "0" | "1" | ""))
}

/// The opt-out ([`LOW_IL_WORKERS_ENV`]`=0`), paged at every start of a command that runs workers:
/// they run at Medium integrity, as the operator's own processes, and a requester's guest that
/// breaks out of one can read the key file, `.env` and the journal, and send them anywhere.
pub fn page_medium_workers() {
    tracing::error!(
        "PAGE: MEDIUM-WORKERS — {LOW_IL_WORKERS_ENV}=0: the prover workers run at Medium \
         integrity, with every right this user has. A requester's guest program that breaks out of \
         one can read the key file, .env and the job journal and send them anywhere: the wallet \
         and the stake. Unset {LOW_IL_WORKERS_ENV} to run them at Low integrity, the default"
    );
}

/// The worker binary's file name, which names its GPU vendor (`zkminer-prove-risc0-cuda.exe`).
fn worker_name(program: &Path) -> std::borrow::Cow<'_, str> {
    program.file_name().map_or_else(
        || program.as_os_str().to_string_lossy(),
        |n| n.to_string_lossy(),
    )
}

/// A Low worker of `backend` (`program`) did not start (`why`: what failed, the worker's last words
/// when it said any). Low workers fail closed: it is not started at Medium instead, which a Low
/// process could otherwise bring about at will (by ending a sibling before its handshake, or by
/// planting a file where a Low directory goes). The slot stays without a worker and the dispatcher
/// starts one again, at Low, after its back-off.
pub(crate) fn low_il_worker_failed(backend: &str, program: &Path, why: &str) {
    let name = worker_name(program);
    tracing::error!(
        "PAGE: LOW-IL-WORKER-FAILED ({backend}, {name}) — a worker at Low integrity did not start: \
         {why}. It is not started at Medium integrity instead (Low-integrity workers fail closed): \
         this {backend} slot proves nothing until a Low worker starts, which is tried again with \
         back-off. If {name} works on this card only at Medium, {LOW_IL_WORKERS_ENV}=0 runs every \
         worker at Medium, where a guest that breaks out can read the key"
    );
}

/// A Low worker's warm-up failed (`why`) on slot `key`, run by `program`: where a GPU runtime needs
/// something Low integrity denies, this is where it shows first, so it is paged with the worker's
/// own words, which name the call that failed.
pub(crate) fn low_il_setup_failed(key: &str, program: &Path, why: &str) {
    let name = worker_name(program);
    tracing::error!(
        "PAGE: LOW-IL-WARMUP-FAILED ({key}, {name}) — a worker at Low integrity failed its \
         warm-up: {why}. If {name} warms up on this card at Medium ({LOW_IL_WORKERS_ENV}=0, where \
         a guest that breaks out can read the key), its GPU runtime needs something Low integrity \
         denies: the call above is the one to report"
    );
}

/// Make `dir` (created if missing, with its parents) a directory whose files, made in it from now
/// on, Low processes cannot read: for what a crash leaves behind. `dir` must be a directory, not a
/// link to one ([`set_dir_label`]).
pub(crate) fn make_no_read_up_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    set_dir_label(dir, "S:(ML;OICI;NWNR;;;ME)")
}

/// Make `dir` (created if missing) and everything made in it writable by Low processes. `dir` must
/// be a directory, not a link to one ([`set_dir_label`]).
fn label_low_writable(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    set_dir_label(dir, LOW_WRITABLE_DIR)
}

/// Whether `metadata` (of the path itself, not followed) is a link: a symbolic link or a junction.
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Make `path`, whose parent exists, a plain directory: a file, a symbolic link or a junction
/// there (a Low process can put one where a directory of the Low tree should be) is removed, never
/// followed, and a directory made in its place.
fn make_plain_dir(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && !is_reparse_point(&m) => return Ok(()),
        // A link to a directory is removed as a directory (the link, not its target).
        Ok(m) if m.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0 => std::fs::remove_dir(path)?,
        Ok(_) => std::fs::remove_file(path)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::create_dir(path)
}

/// Label the directory `path` with `sddl`'s label, through a handle to `path` itself: a link there
/// is refused, not followed, so a label meant for the Low tree never lands on what it points at.
fn set_dir_label(path: &Path, sddl: &str) -> io::Result<()> {
    const READ_CONTROL: u32 = 0x0002_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_SHARE_ALL: u32 = 0x7;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    #[link(name = "advapi32")]
    extern "system" {
        fn SetSecurityInfo(
            handle: Handle,
            object_type: i32,
            information: u32,
            owner: *mut c_void,
            group: *mut c_void,
            dacl: *mut c_void,
            sacl: *mut c_void,
        ) -> u32;
    }
    let descriptor = Descriptor::from_sddl(sddl)?;
    let sacl = descriptor.sacl()?;
    let name = wide(path.as_os_str());
    // SAFETY: a NUL-terminated path; the handle is owned by `File` at once.
    let dir = unsafe {
        let handle = CreateFileW(
            name.as_ptr(),
            READ_CONTROL | WRITE_OWNER | FILE_READ_ATTRIBUTES,
            FILE_SHARE_ALL,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        );
        if handle as isize == -1 || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        std::fs::File::from_raw_handle(handle)
    };
    let metadata = dir.metadata()?;
    if is_reparse_point(&metadata) {
        return Err(io::Error::other(format!(
            "{} is a link, not a directory",
            path.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(io::Error::other(format!(
            "{} is a file, not a directory",
            path.display()
        )));
    }
    // SAFETY: an open handle with WRITE_OWNER and a SACL inside a live descriptor. Setting a label
    // at or below this process's own level needs no privilege, only WRITE_OWNER.
    let status = unsafe {
        SetSecurityInfo(
            dir.as_raw_handle(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            sacl,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

fn set_label(path: &Path, sddl: &str) -> io::Result<()> {
    let descriptor = Descriptor::from_sddl(sddl)?;
    let sacl = descriptor.sacl()?;
    let name = wide(path.as_os_str());
    // SAFETY: a NUL-terminated path and a SACL inside a live descriptor. Setting a label at or below
    // this process's own level needs no privilege, only WRITE_OWNER, which the user's files grant.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            sacl,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// Label `path` so Low processes cannot read it. Labels, never reads, the file.
fn label_no_read_up(path: &Path) -> io::Result<()> {
    set_label(path, NO_READ_UP_FILE)
}

/// [`label_no_read_up`] on a file whose DACL does not give this user `WRITE_OWNER`, which setting a
/// label needs: one made private with `icacls <file> /inheritance:r /grant:r <account>:R`, say.
/// As its owner this user may still change its DACL (an owner's implicit `WRITE_DAC`), so it adds
/// `WRITE_OWNER` for itself, sets the label, and puts the DACL back as it was. Fails where this user
/// is not the owner either.
fn label_no_read_up_as_owner(path: &Path) -> io::Result<()> {
    const READ_CONTROL: u32 = 0x0002_0000;
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
    }
    let dacl_handle = open_for(path, READ_CONTROL | WRITE_DAC)?;
    let (mut original, mut dacl) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: an open handle and out-pointers; the descriptor is owned by `Descriptor` at once.
    let status = unsafe {
        GetSecurityInfo(
            dacl_handle.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut original,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let original = Descriptor(original);
    // Written back as it was read: an auto-inherited DACL keeps that flag only when the descriptor
    // asks for it (`AR`).
    let original_sddl = with_auto_inherit_kept(&original.to_sddl(DACL_SECURITY_INFORMATION)?);
    let user = zkminer_config::wallet::current_user_sid()?;
    let granted = Descriptor::from_sddl(&format!("{original_sddl}(A;;WO;;;{user})"))?;
    let original = Descriptor::from_sddl(&original_sddl)?;
    set_dacl(dacl_handle.as_raw_handle(), granted.0)?;
    // A handle opened now, as access is checked at the open.
    let labelled = open_for(path, WRITE_OWNER).and_then(|owner_handle| {
        let label = Descriptor::from_sddl(NO_READ_UP_FILE)?;
        set_security(
            owner_handle.as_raw_handle(),
            LABEL_SECURITY_INFORMATION,
            label.0,
        )
    });
    // The DACL as it was, whether or not the label took.
    let restored = set_dacl(dacl_handle.as_raw_handle(), original.0);
    labelled.and(restored)
}

/// `sddl`, a DACL (`D:<flags>(...)`), with `AR` among its flags if `AI` is: so that setting it keeps
/// the auto-inherited flag, which the kernel drops otherwise.
fn with_auto_inherit_kept(sddl: &str) -> String {
    let Some(rest) = sddl.strip_prefix("D:") else {
        return sddl.to_string();
    };
    let flags_end = rest.find('(').unwrap_or(rest.len());
    let (flags, aces) = rest.split_at(flags_end);
    if flags.contains("AI") && !flags.contains("AR") {
        format!("D:{}ARAI{aces}", flags.replace("AI", ""))
    } else {
        sddl.to_string()
    }
}

/// `path` (the file it names, a link followed) opened for `access` and nothing else.
fn open_for(path: &Path, access: u32) -> io::Result<OwnedHandle> {
    const FILE_SHARE_ALL: u32 = 0x7;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let name = wide(path.as_os_str());
    // SAFETY: a NUL-terminated path; the handle is owned at once.
    unsafe {
        let handle = CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_ALL,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        );
        if handle as isize == -1 || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedHandle::from_raw_handle(handle))
    }
}

/// Whether `path` has a label at Medium or above with no-read-up, as [`label_no_read_up`] sets:
/// read back, so that a label that did not take never passes for one that did.
pub(crate) fn has_no_read_up_label(path: &Path) -> io::Result<bool> {
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
    }
    let name = wide(path.as_os_str());
    let (mut sacl, mut descriptor) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: a NUL-terminated path and out-pointers; the descriptor is owned by `Descriptor` at
    // once. Reading a label needs only READ_CONTROL.
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sacl,
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let sddl = Descriptor(descriptor).to_sddl(LABEL_SECURITY_INFORMATION)?;
    Ok(label_keeps_low_from_reading(&sddl))
}

/// Whether the label in `sddl` (`S:(ML;<flags>;<policy>;;;<level>)`) has no-read-up at Medium or
/// above.
pub(crate) fn label_keeps_low_from_reading(sddl: &str) -> bool {
    sddl.split('(').skip(1).any(|ace| {
        let fields: Vec<&str> = ace.trim_end_matches(')').split(';').collect();
        matches!(fields.as_slice(), ["ML", _, policy, _, _, level]
            if policy.contains("NR") && matches!(*level, "ME" | "MP" | "HI" | "SI"))
    })
}

/// Label `path` unreadable to Low processes, as this user's own file or as its owner, and check
/// that the label holds; what went wrong, otherwise.
fn label_secret(path: &Path) -> Result<(), String> {
    let labelled = label_no_read_up(path).or_else(|e| {
        label_no_read_up_as_owner(path).map_err(|as_owner| format!("{e}; as its owner: {as_owner}"))
    });
    match labelled.and_then(|()| has_no_read_up_label(path).map_err(|e| e.to_string())) {
        Ok(true) => Ok(()),
        Ok(false) => Err("the label did not take".to_string()),
        Err(e) => Err(e),
    }
}

/// [`label_secret`] on each of the key file (if the key comes from one), `<home>/.zkminer/.env` and
/// the journal that exists: those that could not be labelled, in one message with the remedy.
fn label_secrets(
    key_file: Option<&Path>,
    home: Option<&Path>,
    journal: &Path,
) -> Result<(), String> {
    let env_file = home.map(|h| h.join(".zkminer").join(".env"));
    let failed: Vec<String> = key_file
        .into_iter()
        .chain(env_file.as_deref())
        .chain([journal])
        .filter(|path| path.exists())
        .filter_map(|path| {
            label_secret(path)
                .err()
                .map(|e| format!("{} ({e})", path.display()))
        })
        .collect();
    if failed.is_empty() {
        return Ok(());
    }
    let one = failed.len() == 1;
    Err(format!(
        "{} could not be labelled unreadable to Low-integrity processes, so a Low-integrity worker \
         could read {}: no worker is started until {} labelled. Setting the label needs the right \
         to change the file's owner, which a file made private with `icacls /grant:r <account>:R` \
         does not give the miner's account unless the account owns it: as an administrator, run \
         `icacls \"<file>\" /grant <account>:(WO)` (or make the account its owner), then start \
         the miner again",
        failed.join(", "),
        if one { "it" } else { "them" },
        if one { "it is" } else { "they are" },
    ))
}

/// PowerShell's command histories (PSReadLine's `*_history.txt`) below `appdata` (the roaming
/// application data directory): where `$env:ZKMINER_PRIVATE_KEY = "0x..."`, typed at a prompt, is
/// kept for good. PSReadLine's filter for secrets does not match that variable's name.
fn command_histories(appdata: &Path) -> Vec<PathBuf> {
    let dir = appdata
        .join("Microsoft")
        .join("Windows")
        .join("PowerShell")
        .join("PSReadLine");
    let Ok(read) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = read
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.to_ascii_lowercase().ends_with("_history.txt"))
        })
        .collect();
    files.sort();
    files
}

/// What else may hold the key where a Low worker can read it, beside the files [`label_secrets`]
/// labels: PowerShell's command histories below `appdata`, labelled like them (labelled, never
/// read: one may hold an `env` key typed at a prompt); and, for an `env` key whose variable is
/// `key_env_var`, a copy of the variable kept in this user's registry environment (`setx`), which
/// every process of this user can read and no label can close. `copies` lists the variable's
/// copies in the registry (`wallet_win::persisted_key_env_copies`). What is wrong, with the
/// remedy, if anything.
fn other_key_copies(
    key_env_var: Option<&str>,
    appdata: Option<&Path>,
    copies: impl Fn(&str) -> Vec<zkminer_config::wallet_win::KeyEnvCopy>,
) -> Result<(), String> {
    let mut wrong = Vec::new();
    let unlabelled: Vec<String> = appdata
        .map(command_histories)
        .unwrap_or_default()
        .iter()
        .filter_map(|path| {
            label_secret(path)
                .err()
                .map(|e| format!("{} ({e})", path.display()))
        })
        .collect();
    if !unlabelled.is_empty() {
        wrong.push(format!(
            "PowerShell's command history {} could not be labelled unreadable to Low-integrity \
             processes, and may hold the key if it was ever typed at a prompt",
            unlabelled.join(", ")
        ));
    }
    if let Some(var) = key_env_var {
        for copy in copies(var).into_iter().filter(|c| !c.machine_wide) {
            wrong.push(format!(
                "{} holds a copy of the key's variable, which every process of this user can \
                 read, Low-integrity workers included: delete it (in PowerShell: \
                 [Environment]::SetEnvironmentVariable('{var}', $null, 'User')), move the key to \
                 a key file (`zkminer init --force --generate-key`, or key_source = \"file\"), \
                 and consider the key exposed",
                copy.location
            ));
        }
    }
    if wrong.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{}; no Low worker is started until it is fixed",
        wrong.join("; ")
    ))
}

/// `a` and `b`, with both errors when both failed.
fn both(a: Result<(), String>, b: Result<(), String>) -> Result<(), String> {
    match (a, b) {
        (Err(a), Err(b)) => Err(format!("{a}; {b}")),
        (a, b) => a.and(b),
    }
}

/// What [`protect_secrets`] found: `None` until it ran, then whether every secret is labelled.
static SECRETS: Mutex<Option<Result<(), String>>> = Mutex::new(None);

/// With Low workers, label the key file (if the key comes from one), `~/.zkminer/.env` and the lock
/// journal so no Low process can read them; a file that does not exist is skipped. Labels, never
/// reads, them, and reads each label back. A file this user may neither label nor, as its owner,
/// open to labelling is paged (`SECRETS-UNLABELLED`), and no Low worker is started in this process
/// ([`spawn_worker`]): a Low worker never runs beside a key it could read. With the workers at
/// Medium (the opt-out), labels nothing and pages that instead ([`page_medium_workers`]). Every
/// command that starts workers calls it first; a process that starts a Low worker without (a test)
/// has `.env` and the journal labelled before its first.
///
/// PowerShell's command histories are labelled too, and with an `env` key (its variable
/// `key_env_var`) a copy of the variable in this user's registry environment refuses Low workers
/// the same way ([`other_key_copies`]), and so does an unlabelled copy of the key kept in a Volume
/// Shadow Copy (`SECRETS-IN-SNAPSHOT`, [`crate::windows_snapshots`]).
pub fn protect_secrets(key_file: Option<&Path>, key_env_var: Option<&str>, journal: &Path) {
    if !low_il_workers() {
        page_medium_workers();
        return;
    }
    let labelled = both(
        label_secrets(key_file, dirs::home_dir().as_deref(), journal),
        other_key_copies(
            key_env_var,
            dirs::config_dir().as_deref(),
            zkminer_config::wallet_win::persisted_key_env_copies,
        ),
    );
    if let Err(why) = &labelled {
        tracing::error!("PAGE: SECRETS-UNLABELLED — {why}");
    }
    // Old unlabelled copies in restore points refuse Low workers too (pages its own).
    let labelled = both(
        labelled,
        crate::windows_snapshots::protect(key_file, key_env_var),
    );
    *SECRETS.lock().unwrap_or_else(|p| p.into_inner()) = Some(labelled);
}

/// Before a Low worker: whether the secrets are labelled ([`protect_secrets`]), labelling `.env`
/// and the default journal first if nothing did.
fn secrets_labelled() -> Result<(), String> {
    let mut state = SECRETS.lock().unwrap_or_else(|p| p.into_inner());
    if state.is_none() {
        let home = dirs::home_dir();
        // `JobJournal::default_path` in the CLI.
        let journal = home
            .as_deref()
            .unwrap_or(Path::new("."))
            .join(".zkminer")
            .join("job_journal.json");
        let labelled = both(
            label_secrets(None, home.as_deref(), &journal),
            other_key_copies(None, dirs::config_dir().as_deref(), |_| Vec::new()),
        );
        if let Err(why) = &labelled {
            tracing::error!("PAGE: SECRETS-UNLABELLED — {why}");
        }
        let labelled = both(labelled, crate::windows_snapshots::protect(None, None));
        *state = Some(labelled);
    }
    state.clone().unwrap_or(Ok(()))
}

/// For `zkminer doctor`, read only: those of the key file, `<home>/.zkminer/.env` and the journal
/// that exist and have no label that keeps Low processes from reading them, each with whether this
/// account could label it ([`protect_secrets`] does at the miner's start): it may change the
/// file's label, or, as its owner, its DACL. Nothing is changed.
pub fn secrets_unlabelled(
    key_file: Option<&Path>,
    home: &Path,
    journal: &Path,
) -> Vec<(PathBuf, bool)> {
    const READ_CONTROL: u32 = 0x0002_0000;
    let env_file = home.join(".zkminer").join(".env");
    key_file
        .into_iter()
        .chain([env_file.as_path(), journal])
        .filter(|path| path.exists() && !has_no_read_up_label(path).unwrap_or(false))
        .map(|path| {
            let labellable = open_for(path, WRITE_OWNER).is_ok()
                || open_for(path, READ_CONTROL | WRITE_DAC).is_ok();
            (path.to_path_buf(), labellable)
        })
        .collect()
}

/// Write `contents` to a new `path` (an existing one is replaced), labelled from its creation so Low
/// processes cannot read it when workers run at Low; a plain write otherwise.
pub fn write_secret_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    if !low_il_workers() {
        return std::fs::write(path, contents);
    }
    write_labelled_file(path, contents)
}

fn write_labelled_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_ALL: u32 = 0x7;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    // A new file: an existing one would keep its own descriptor.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // Only a SACL: the DACL is inherited from the directory, as for any new file.
    let descriptor = Descriptor::from_sddl(NO_READ_UP_FILE)?;
    let attributes = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: descriptor.0,
        inherit_handle: 0,
    };
    let name = wide(path.as_os_str());
    // SAFETY: a NUL-terminated path and a SECURITY_ATTRIBUTES that outlives the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_ALL,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 || handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid file handle this function owns, handed to `File` to close.
    let mut file = unsafe { std::fs::File::from_raw_handle(handle) };
    file.write_all(contents)
}

/// The directories a Low worker is pointed at by its environment: (variable, directory name below
/// `%LOCALAPPDATA%\zkminer\worker`).
const LOW_DIRS: &[(&[&str], &str)] = &[
    (&["TMP", "TEMP", "TMPDIR"], "tmp"),
    (&["CUDA_CACHE_PATH"], "cuda-cache"),
    (&["NEO_CACHE_DIR"], "neo"),
    (&["SYCL_CACHE_DIR"], "sycl"),
    (&["RISC0_G16_CACHE_DIR"], "risc0-groth16"),
    (&["AMD_COMGR_CACHE_DIR"], "comgr"),
];

/// The Low-writable directories outside `<local>\zkminer\worker`: `<home>\.zkminer\risc0-segments`
/// and the SP1 Groth16 queue (`~/.zkminer/locks`), which the dispatcher names to the worker.
fn low_dirs_in_home(home: &Path) -> [PathBuf; 2] {
    [
        home.join(".zkminer").join("risc0-segments"),
        zkminer_prover_protocol::types::sp1_groth16_queue_dir(home),
    ]
}

/// The directories a Low worker writes, made and labelled: (variable, directory) for those it is
/// pointed at, below `<local>\zkminer\worker`, then [`low_dirs_in_home`]. A Low process can write
/// in each of them, so each is made a plain directory again first ([`make_plain_dir`]: a file or
/// a link planted there is removed), and every label is set through the directory itself, never
/// through a link ([`set_dir_label`]).
fn prepare_low_dirs(local: &Path, home: &Path) -> Result<Vec<(&'static str, PathBuf)>, String> {
    fn at(dir: &Path) -> impl FnOnce(io::Error) -> String + '_ {
        move |e| format!("{}: {e}", dir.display())
    }
    let base = local.join("zkminer").join("worker");
    let mut dirs = Vec::new();
    let mut plain = vec![base.clone()];
    for (vars, name) in LOW_DIRS {
        let dir = base.join(name);
        dirs.extend(vars.iter().map(|var| (*var, dir.clone())));
        plain.push(dir);
    }
    plain.extend(low_dirs_in_home(home));
    for dir in &plain {
        // The parents are this user's at Medium: no Low process changes them.
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent).map_err(at(parent))?;
        }
        make_plain_dir(dir).map_err(at(dir))?;
        set_dir_label(dir, LOW_WRITABLE_DIR).map_err(at(dir))?;
    }
    sweep_dead_progress_files(&base.join("tmp"));
    Ok(dirs)
}

/// What dead SP1 workers left in the Low workers' shared `tmp` directory: their progress files
/// (`zkminer-sp1-progress-<pid>.txt`), removed once no process runs under the pid. Nothing else
/// removes them, and nothing on Windows cleans that directory. Only plain files of that name: a
/// link a Low process put there is not a file to this (never followed, never removed).
fn sweep_dead_progress_files(tmp: &Path) {
    use zkminer_prover_protocol::liveness::{liveness, Liveness};
    let Ok(read) = std::fs::read_dir(tmp) else {
        return;
    };
    for entry in read.flatten() {
        let name = entry.file_name();
        let pid = name
            .to_str()
            .and_then(|n| n.strip_prefix("zkminer-sp1-progress-"))
            .and_then(|n| n.strip_suffix(".txt"))
            .and_then(|n| n.parse::<u32>().ok());
        let Some(pid) = pid else { continue };
        if entry.file_type().is_ok_and(|t| t.is_file()) && liveness(pid) == Liveness::Gone {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// [`prepare_low_dirs`] for the next Low worker: in this user's profile, or below `root` (tests).
/// Done again before every Low worker, not once per process: a Low worker can delete any of these
/// directories or put a file or a link in its place, and the next one must not inherit that.
fn low_dirs(root: Option<&Path>) -> Result<Vec<(&'static str, PathBuf)>, String> {
    match root {
        Some(root) => prepare_low_dirs(&root.join("local"), &root.join("home")),
        None => {
            let local = dirs::data_local_dir().ok_or("no local application data directory")?;
            let home = dirs::home_dir().ok_or("no home directory")?;
            prepare_low_dirs(&local, &home)
        }
    }
}

/// For `zkminer doctor`, read only: the Low directories ([`prepare_low_dirs`]) that are a file or a
/// link, not a directory. Only a Low process (or the operator) puts one there; the miner replaces
/// it with a directory before each Low worker it starts.
pub fn low_dirs_tampered() -> Vec<String> {
    let (Some(local), Some(home)) = (dirs::data_local_dir(), dirs::home_dir()) else {
        return Vec::new();
    };
    let base = local.join("zkminer").join("worker");
    std::iter::once(base.clone())
        .chain(LOW_DIRS.iter().map(|(_, name)| base.join(name)))
        .chain(low_dirs_in_home(&home))
        .filter_map(|dir| match std::fs::symlink_metadata(&dir) {
            Ok(m) if is_reparse_point(&m) => Some(format!("{} is a link", dir.display())),
            Ok(m) if !m.is_dir() => Some(format!("{} is a file", dir.display())),
            _ => None,
        })
        .collect()
}

/// Directories a worker is pointed at by its environment that it writes (the witness proofs'
/// segment directory, an operator's SP1 queue directory): made and labelled before every Low
/// worker, as [`low_dirs`] are (one a Low worker deleted is made again; a link there is refused).
fn label_env_dirs(env: &[(OsString, OsString)]) -> Result<(), String> {
    let written = [
        zkminer_prover_protocol::types::WITNESS_SEGMENT_DIR_ENV,
        "SP1_GROTH16_QUEUE_DIR",
    ];
    for (k, v) in env {
        if v.is_empty() || !written.iter().any(|w| OsStr::new(w) == k.as_os_str()) {
            continue;
        }
        let dir = PathBuf::from(v);
        label_low_writable(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(())
}

/// A worker process started by [`spawn_worker`]: what the dispatcher uses of a
/// `std::process::Child`, which cannot be made from a process started any other way.
pub(crate) struct WorkerChild {
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    process: OwnedHandle,
    pid: u32,
    /// Its job (`windows_job::new_worker_job`), if it could be put in one. Closing it ends
    /// whatever is still in it.
    job: Option<OwnedHandle>,
    low: bool,
}

impl WorkerChild {
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Whether it runs at Low integrity.
    pub fn is_low_integrity(&self) -> bool {
        self.low
    }

    /// Ends the worker and everything it started (its job), as Unix ends its process group. Ok if it
    /// had ended already.
    pub fn kill(&mut self) -> io::Result<()> {
        if let Some(job) = &self.job {
            // SAFETY: a valid job handle.
            if unsafe { TerminateJobObject(job.as_raw_handle(), 1) } != 0 {
                return Ok(());
            }
        }
        // SAFETY: a valid process handle.
        if unsafe { TerminateProcess(self.process.as_raw_handle(), 1) } == 0 {
            let e = io::Error::last_os_error();
            // An ended process refuses to be terminated.
            if self.try_wait().is_ok_and(|s| s.is_some()) {
                return Ok(());
            }
            return Err(e);
        }
        Ok(())
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.wait_for(0)
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        // As std does: a worker reading its stdin must see it close.
        drop(self.stdin.take());
        self.wait_for(u32::MAX)?
            .ok_or_else(|| io::Error::other("the wait ended without an exit"))
    }

    fn wait_for(&self, milliseconds: u32) -> io::Result<Option<ExitStatus>> {
        const WAIT_OBJECT_0: u32 = 0;
        const WAIT_TIMEOUT: u32 = 0x102;
        // SAFETY: a valid process handle; `code` outlives the call.
        unsafe {
            match WaitForSingleObject(self.process.as_raw_handle(), milliseconds) {
                WAIT_OBJECT_0 => {
                    let mut code = 0u32;
                    if GetExitCodeProcess(self.process.as_raw_handle(), &mut code) == 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(Some(ExitStatus::from_raw(code)))
                }
                WAIT_TIMEOUT => Ok(None),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }
}

/// Start the worker `program` for `backend` with exactly `env`, its stdin, stdout and stderr piped
/// to the miner, in a console of its own with no window (`CREATE_NO_WINDOW`: the miner's console
/// events, Ctrl+C above all, must not reach it), in the miner's job and a job of its own, at Low
/// integrity when that is on (see the module docs). Nothing else of the miner's is inherited.
///
/// With Low workers on, a worker whose directories cannot be prepared, or beside a key file it could
/// read ([`protect_secrets`]), is not started at all (the flag fails closed,
/// [`low_il_worker_failed`]), and before the first SP1 worker the server it runs is installed from
/// here ([`install_sp1_server`]).
pub(crate) fn spawn_worker(
    backend: &str,
    program: &Path,
    mut env: Vec<(OsString, OsString)>,
) -> io::Result<WorkerChild> {
    #[cfg(test)]
    let test_root = TEST_LOW_ROOT.with(|root| root.borrow().clone());
    #[cfg(not(test))]
    let test_root: Option<PathBuf> = None;
    let low = low_il_workers() || test_root.is_some();
    // Set below for a Low worker, and only by the miner.
    env.retain(|(k, _)| {
        !k.eq_ignore_ascii_case(zkminer_prover_protocol::types::LOW_INTEGRITY_WORKER_ENV)
    });
    if low {
        // Never beside a key it could read (`protect_secrets`). Unit tests label none of the user's.
        if test_root.is_none() && !cfg!(test) {
            secrets_labelled().map_err(|why| {
                low_il_worker_failed(backend, program, &why);
                io::Error::other(why)
            })?;
        }
        let dirs = low_dirs(test_root.as_deref())
            .and_then(|dirs| label_env_dirs(&env).map(|()| dirs))
            .map_err(|e| {
                let why = format!(
                    "the directories a Low-integrity worker writes could not be prepared: {e}"
                );
                low_il_worker_failed(backend, program, &why);
                io::Error::other(why)
            })?;
        // Last, so they win over the miner's own: a Low process cannot write those.
        env.extend(
            dirs.iter()
                .map(|(var, dir)| (OsString::from(var), dir.into())),
        );
        if backend == "sp1" {
            install_sp1_server(program, &env);
        }
        // Its warm-up installs nothing in the profile, which the miner does at Medium
        // (`worker::install_artifacts_at_medium`).
        env.push((
            zkminer_prover_protocol::types::LOW_INTEGRITY_WORKER_ENV.into(),
            "1".into(),
        ));
    }
    #[cfg(test)]
    TEST_SPAWNS.with(|spawns| spawns.borrow_mut().push(low));
    spawn(program, &[], &env, low).inspect_err(|e| {
        if low {
            low_il_worker_failed(
                backend,
                program,
                &format!("it could not be started at Low: {e}"),
            );
        }
    })
}

#[cfg(test)]
thread_local! {
    /// Tests: the workers [`spawn_worker`] starts on this thread run at Low integrity whatever the
    /// flag, with their directories below this root instead of the user's profile.
    pub(crate) static TEST_LOW_ROOT: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
    /// And whether each one it started on this thread was at Low.
    pub(crate) static TEST_SPAWNS: std::cell::RefCell<Vec<bool>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// SP1 at Low integrity: the worker installs the `sp1-gpu-server` shipped beside it into
/// `~/.sp1/bin`, which a Low process cannot write (and must not: a Medium worker runs what is
/// there). So the miner, at Medium, has the worker binary do just that (`--install-bundled-server`:
/// no GPU, network or guest) once per worker binary and server build, before the first Low worker
/// of it. A failure is logged and tried again before the next one; the Low worker then declines
/// SP1 for want of its server, as one does at Medium.
fn install_sp1_server(program: &Path, env: &[(OsString, OsString)]) {
    static DONE: Mutex<BTreeSet<(PathBuf, OsString)>> = Mutex::new(BTreeSet::new());
    let server = env
        .iter()
        .rev()
        .find(|(k, _)| k.eq_ignore_ascii_case("SP1_GPU_SERVER_NAME"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let key = (program.to_path_buf(), server);
    let mut done = DONE.lock().unwrap_or_else(|p| p.into_inner());
    if done.contains(&key) {
        return;
    }
    let ran = std::process::Command::new(program)
        .arg(zkminer_prover_protocol::types::INSTALL_BUNDLED_SERVER_ARG)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output();
    match ran {
        Ok(out) if out.status.success() => {
            done.insert(key);
        }
        Ok(out) => tracing::warn!(
            "{} could not install the SP1 server it ships ({}): its Low-integrity workers \
             decline SP1 until it is installed",
            program.display(),
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .last()
                .unwrap_or_default()
                .trim()
        ),
        Err(e) => tracing::warn!(
            "{} could not be run to install the SP1 server it ships ({e}): its Low-integrity \
             workers decline SP1 until it is installed",
            program.display()
        ),
    }
}

/// Quote `arg` for a command line as the C runtime parses it back.
fn push_arg(line: &mut Vec<u16>, arg: &OsStr, always_quote: bool) {
    let (quote, backslash) = (u16::from(b'"'), u16::from(b'\\'));
    let arg: Vec<u16> = arg.encode_wide().collect();
    let needs = always_quote
        || arg.is_empty()
        || arg
            .iter()
            .any(|&c| c == quote || c == u16::from(b' ') || c == u16::from(b'\t'));
    if !needs {
        line.extend(arg);
        return;
    }
    line.push(quote);
    let mut backslashes = 0;
    for c in arg {
        if c == backslash {
            backslashes += 1;
        } else {
            if c == quote {
                line.extend(std::iter::repeat_n(backslash, backslashes + 1));
            }
            backslashes = 0;
        }
        line.push(c);
    }
    line.extend(std::iter::repeat_n(backslash, backslashes));
    line.push(quote);
}

fn command_line(program: &Path, args: &[&OsStr]) -> io::Result<Vec<u16>> {
    if program
        .as_os_str()
        .encode_wide()
        .any(|c| c == u16::from(b'"'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a program path with a quote",
        ));
    }
    let mut line = Vec::new();
    push_arg(&mut line, program.as_os_str(), true);
    for arg in args {
        line.push(u16::from(b' '));
        push_arg(&mut line, arg, false);
    }
    line.push(0);
    Ok(line)
}

/// A Unicode environment block: one `name=value` each, the last of a name (matched without case,
/// as Windows does) winning, sorted by name, ending in an empty one.
fn environment_block(env: &[(OsString, OsString)]) -> io::Result<Vec<u16>> {
    let mut vars: BTreeMap<String, (&OsString, &OsString)> = BTreeMap::new();
    for (k, v) in env {
        if k.is_empty() {
            continue;
        }
        let key = k.to_string_lossy().to_uppercase();
        vars.insert(key, (k, v));
    }
    let mut block = Vec::new();
    for (k, v) in vars.into_values() {
        let (k, v): (Vec<u16>, Vec<u16>) = (k.encode_wide().collect(), v.encode_wide().collect());
        if k.contains(&0) || v.contains(&0) || k[1..].contains(&u16::from(b'=')) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an environment variable with a NUL or a misplaced '='",
            ));
        }
        block.extend(k);
        block.push(u16::from(b'='));
        block.extend(v);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

/// What this user keeps on a Low worker's process: what the miner opens one by pid for (see it, its
/// times and memory figures, wait for it, end it).
const LOW_WORKER_USER_RIGHTS: u32 = PROCESS_USER_RIGHTS | PROCESS_VM_READ;

/// The descriptors of a Low worker's process and first thread. A Low worker's token keeps this
/// user's SID, and its default DACL grants that SID everything, so without these any other Low
/// worker could read another's memory (another requester's guest and inputs), run code in it or
/// end it before its handshake. With them, this user gets only [`LOW_WORKER_USER_RIGHTS`] (on the
/// thread, [`THREAD_USER_RIGHTS`]), and the Medium label ([`NO_UP_LABEL`]) keeps every one of those
/// from Low processes, the worker itself by its pid included. The threads the worker starts later
/// close themselves (`zkminer_prover_protocol::threads`); the processes it starts (SP1's
/// `sp1-gpu-server`) keep its token's default DACL, which grants this user every right.
///
/// No object can be created with a label above its creator's token's, and the handles a process's
/// creator gets are checked against the descriptor it gives, which cannot tell the miner from a
/// Low worker of the same user but by the label. So [`spawn`] creates the worker at Medium,
/// suspended, with `at_creation` (all rights for this user, and the label: a Low process can never
/// open it), lowers its token to Low, then narrows it to `before_resume` before it runs. In pairs:
/// (process, thread).
struct LowWorkerDescriptors {
    at_creation: (Descriptor, Descriptor),
    before_resume: (Descriptor, Descriptor),
}

fn low_worker_descriptors() -> io::Result<LowWorkerDescriptors> {
    let user = zkminer_config::wallet::current_user_sid()?;
    let pair = |process_rights: u32, thread_rights: u32| -> io::Result<_> {
        Ok((
            locked_descriptor(&user, process_rights, PROCESS_ALL_ACCESS)?,
            locked_descriptor(&user, thread_rights, THREAD_ALL_ACCESS)?,
        ))
    };
    Ok(LowWorkerDescriptors {
        at_creation: pair(PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS)?,
        before_resume: pair(LOW_WORKER_USER_RIGHTS, THREAD_USER_RIGHTS)?,
    })
}

/// Lower the token of `process` (a worker created suspended, not yet run) to Low integrity. A
/// token's level may always be lowered, by whoever may adjust it: here the miner, whose token that
/// one is a copy of.
fn lower_to_low_integrity(process: Handle) -> io::Result<()> {
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
    const TOKEN_INTEGRITY_LEVEL: i32 = 25;
    const SE_GROUP_INTEGRITY: u32 = 0x20;
    // S-1-16-4096: revision 1, one sub-authority, the mandatory label authority (16), Low (0x1000).
    let mut low_sid: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 16, 0x00, 0x10, 0x00, 0x00];
    // SAFETY: plain advapi32 calls on a valid process handle; the token is owned as soon as it
    // exists, and `label` and the SID it points to outlive the call that reads them.
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle::from_raw_handle(token);
        let label = TokenMandatoryLabel {
            sid: low_sid.as_mut_ptr().cast(),
            attributes: SE_GROUP_INTEGRITY,
        };
        if SetTokenInformation(
            token.as_raw_handle(),
            TOKEN_INTEGRITY_LEVEL,
            (&label as *const TokenMandatoryLabel).cast(),
            (std::mem::size_of::<TokenMandatoryLabel>() + low_sid.len()) as u32,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// A pipe: the end the child gets and the miner's. The miner's is opened for overlapped I/O, as
/// std's own pipes are: `ChildStdin`/`ChildStdout` read and write with `ReadFileEx`/`WriteFileEx`,
/// which wait forever on an anonymous pipe from `CreatePipe`. Neither end is inheritable yet: the
/// child's is made so only for the `CreateProcess` call (see [`spawn`]), so a process another
/// thread starts with std (which inherits every inheritable handle) does not get a copy.
fn pipe(child_reads: bool) -> io::Result<(OwnedHandle, OwnedHandle)> {
    const PIPE_ACCESS_INBOUND: u32 = 0x1;
    const PIPE_ACCESS_OUTBOUND: u32 = 0x2;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x8;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    const OPEN_EXISTING: u32 = 3;
    const CAPACITY: u32 = 64 * 1024;
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateNamedPipeW(
            name: *const u16,
            open_mode: u32,
            pipe_mode: u32,
            max_instances: u32,
            out_size: u32,
            in_size: u32,
            timeout: u32,
            attributes: *const SecurityAttributes,
        ) -> Handle;
    }
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    // One instance, the first of its name: a name taken already fails, and a process that connected
    // before the miner makes the miner's own connection fail rather than share the pipe.
    let name = wide(OsStr::new(&format!(
        r"\\.\pipe\zkminer-worker-{}-{}-{nanos}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )));
    let (ours_mode, theirs_access) = if child_reads {
        (PIPE_ACCESS_OUTBOUND, GENERIC_READ | FILE_WRITE_ATTRIBUTES)
    } else {
        (PIPE_ACCESS_INBOUND, GENERIC_WRITE)
    };
    // SAFETY: a NUL-terminated name; both handles are owned at once.
    unsafe {
        let ours = CreateNamedPipeW(
            name.as_ptr(),
            ours_mode | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_REJECT_REMOTE_CLIENTS,
            1,
            CAPACITY,
            CAPACITY,
            0,
            std::ptr::null(),
        );
        if ours as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        let ours = OwnedHandle::from_raw_handle(ours);
        let theirs = CreateFileW(
            name.as_ptr(),
            theirs_access,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if theirs as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok((OwnedHandle::from_raw_handle(theirs), ours))
    }
}

/// Make `handle` inheritable, or not.
fn set_inheritable(handle: &OwnedHandle, inheritable: bool) -> io::Result<()> {
    const HANDLE_FLAG_INHERIT: u32 = 1;
    #[link(name = "kernel32")]
    extern "system" {
        fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> i32;
    }
    // SAFETY: a valid handle.
    if unsafe {
        SetHandleInformation(
            handle.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            if inheritable { HANDLE_FLAG_INHERIT } else { 0 },
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// [`spawn_worker`] for any program: `args` after it, exactly `env`, at Low integrity if `low`.
fn spawn(
    program: &Path,
    args: &[&OsStr],
    env: &[(OsString, OsString)],
    low: bool,
) -> io::Result<WorkerChild> {
    const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
    const CREATE_SUSPENDED: u32 = 0x0000_0004;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;

    let application = wide(program.as_os_str());
    let mut line = command_line(program, args)?;
    let block = environment_block(env)?;
    // A Low worker's process and first thread get a descriptor of their own (its token's default
    // grants this user, and so every other Low worker, everything): see `LowWorkerDescriptors`.
    let descriptors = if low {
        Some(low_worker_descriptors()?)
    } else {
        None
    };
    let attributes = descriptors.as_ref().map(|d| {
        let (process, thread) = &d.at_creation;
        [process, thread].map(|descriptor| SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor: descriptor.0,
            inherit_handle: 0,
        })
    });
    let (process_attributes, thread_attributes) = match &attributes {
        Some([process, thread]) => (process as *const SecurityAttributes, thread as *const _),
        None => (std::ptr::null(), std::ptr::null()),
    };
    let (stdin_child, stdin_ours) = pipe(true)?;
    let (stdout_child, stdout_ours) = pipe(false)?;
    let (stderr_child, stderr_ours) = pipe(false)?;
    // The only handles it inherits.
    let inherited: [Handle; 3] = [
        stdin_child.as_raw_handle(),
        stdout_child.as_raw_handle(),
        stderr_child.as_raw_handle(),
    ];

    // SAFETY: the attribute list is sized by the first call, initialised once, deleted below, and
    // `inherited` outlives every use of it; every structure passed to CreateProcess outlives the
    // call; every handle it returns is owned at once.
    let (process, job, pid) = unsafe {
        let mut size = 0usize;
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
        let mut list = vec![0u64; size.div_ceil(8)];
        let list = list.as_mut_ptr().cast::<c_void>();
        if InitializeProcThreadAttributeList(list, 1, 0, &mut size) == 0 {
            return Err(io::Error::last_os_error());
        }
        struct List(*mut c_void);
        impl Drop for List {
            fn drop(&mut self) {
                // SAFETY: an initialised list.
                unsafe { DeleteProcThreadAttributeList(self.0) };
            }
        }
        let list = List(list);
        if UpdateProcThreadAttribute(
            list.0,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited.as_ptr().cast(),
            std::mem::size_of_val(&inherited),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut startup: StartupInfoExW = std::mem::zeroed();
        startup.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as u32;
        startup.startup_info.flags = STARTF_USESTDHANDLES;
        startup.startup_info.std_input = inherited[0];
        startup.startup_info.std_output = inherited[1];
        startup.startup_info.std_error = inherited[2];
        startup.attribute_list = list.0;
        let flags = CREATE_SUSPENDED
            | CREATE_UNICODE_ENVIRONMENT
            | EXTENDED_STARTUPINFO_PRESENT
            | CREATE_NO_WINDOW;
        let mut info: ProcessInformation = std::mem::zeroed();
        // Inheritable for this call only (the handle list keeps everything else out of it).
        for handle in [&stdin_child, &stdout_child, &stderr_child] {
            set_inheritable(handle, true)?;
        }
        // At this process's integrity: a Low worker is lowered below, before it runs.
        let ok = CreateProcessW(
            application.as_ptr(),
            line.as_mut_ptr(),
            process_attributes,
            thread_attributes,
            1,
            flags,
            block.as_ptr().cast(),
            std::ptr::null(),
            &startup,
            &mut info,
        );
        let created = io::Error::last_os_error();
        for handle in [&stdin_child, &stdout_child, &stderr_child] {
            let _ = set_inheritable(handle, false);
        }
        if ok == 0 {
            return Err(created);
        }
        let process = OwnedHandle::from_raw_handle(info.process);
        let thread = OwnedHandle::from_raw_handle(info.thread);
        // No privileges but the kept ones (`windows_account`), before it runs a single instruction:
        // one still there (SeImpersonate, from a service logon) and it is not started at all.
        if let Err(e) = crate::windows_account::strip_worker(process.as_raw_handle()) {
            let allowed = privileged_account_allowed();
            crate::windows_account::worker_privileges_failed(program, &e, allowed);
            if !allowed {
                TerminateProcess(process.as_raw_handle(), 1);
                return Err(e);
            }
        }
        // A Low worker: its token lowered to Low and its process and first thread narrowed to what
        // this user keeps (their Medium label stays), before it runs a single instruction. If
        // either fails it is not started at all, never at Medium.
        if let Some(d) = &descriptors {
            let (process_descriptor, thread_descriptor) = &d.before_resume;
            let lowered = lower_to_low_integrity(process.as_raw_handle()).and_then(|()| {
                for (handle, descriptor) in [
                    (process.as_raw_handle(), process_descriptor),
                    (thread.as_raw_handle(), thread_descriptor),
                ] {
                    set_dacl(handle, descriptor.0)?;
                }
                Ok(())
            });
            if let Err(e) = lowered {
                TerminateProcess(process.as_raw_handle(), 1);
                return Err(e);
            }
        }
        // Into the jobs while it is suspended: once running, the SP1 worker puts itself in a job of
        // its own, and could then no longer be put in this one.
        crate::windows_job::end_with_this_process(process.as_raw_handle(), info.process_id);
        let job = match crate::windows_job::new_worker_job()
            .and_then(|job| crate::windows_job::assign(&job, process.as_raw_handle()).map(|()| job))
        {
            Ok(job) => Some(job),
            Err(e) => {
                tracing::warn!(
                    "worker pid {} runs without its job ({e}): it is not kept from the desktop and \
                     the clipboard",
                    info.process_id
                );
                None
            }
        };
        if ResumeThread(thread.as_raw_handle()) == u32::MAX {
            let e = io::Error::last_os_error();
            TerminateProcess(process.as_raw_handle(), 1);
            return Err(e);
        }
        (process, job, info.process_id)
    };
    // The child's ends are the child's alone now: closed here, so the miner sees EOF when it exits.
    drop((stdin_child, stdout_child, stderr_child));
    Ok(WorkerChild {
        stdin: Some(ChildStdin::from(stdin_ours)),
        stdout: Some(ChildStdout::from(stdout_ours)),
        stderr: Some(ChildStderr::from(stderr_ours)),
        process,
        pid,
        job,
        low,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Read};

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn GetLastError() -> u32;
        fn IsProcessInJob(process: Handle, job: Handle, result: *mut i32) -> i32;
        fn GetCurrentThreadId() -> u32;
    }
    const PROCESS_VM_WRITE: u32 = 0x0020;
    const PROCESS_CREATE_THREAD: u32 = 0x0002;
    const THREAD_GET_CONTEXT: u32 = 0x0008;
    const THREAD_SET_CONTEXT: u32 = 0x0010;
    const ERROR_ACCESS_DENIED: u32 = 5;
    const HELPER: &str = "ZKMINER_TEST_SANDBOX_HELPER";

    /// `OpenProcess(access, pid)`: Ok, or the error code.
    fn open_process(pid: u32, access: u32) -> Result<(), u32> {
        // SAFETY: plain kernel32 calls; a handle opened is closed at once.
        unsafe {
            let h = OpenProcess(access, 0, pid);
            if h.is_null() {
                return Err(GetLastError());
            }
            drop(OwnedHandle::from_raw_handle(h));
            Ok(())
        }
    }

    fn open_thread(tid: u32, access: u32) -> Result<(), u32> {
        // SAFETY: as `open_process`.
        unsafe {
            let h = OpenThread(access, 0, tid);
            if h.is_null() {
                return Err(GetLastError());
            }
            drop(OwnedHandle::from_raw_handle(h));
            Ok(())
        }
    }

    /// This process's integrity level (the RID of its label).
    fn integrity_level() -> u32 {
        const TOKEN_QUERY: u32 = 0x0008;
        const TOKEN_INTEGRITY_LEVEL: i32 = 25;
        // SAFETY: plain advapi32 calls into a pointer-aligned buffer that outlives them.
        unsafe {
            let mut token = std::ptr::null_mut();
            assert!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0);
            let token = OwnedHandle::from_raw_handle(token);
            let mut buf = [0u64; 16];
            let mut needed = 0;
            assert!(
                GetTokenInformation(
                    token.as_raw_handle(),
                    TOKEN_INTEGRITY_LEVEL,
                    buf.as_mut_ptr().cast(),
                    std::mem::size_of_val(&buf) as u32,
                    &mut needed,
                ) != 0
            );
            let sid = *(buf.as_ptr() as *const *const u8);
            // SID: revision, count, 6-byte authority, then the sub-authorities (the last is the RID).
            let count = *sid.add(1) as usize;
            std::ptr::read_unaligned(sid.add(8 + 4 * (count - 1)) as *const u32)
        }
    }

    /// The test binary itself, running only `test` (an ignored helper) with `env` added.
    fn helper(test: &str, env: &[(&str, String)]) -> std::process::Command {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--ignored",
            "--exact",
            test,
            "--nocapture",
            "--test-threads=1",
        ])
        .envs(env.iter().map(|(k, v)| (*k, v)))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
        cmd
    }

    /// Locks itself down as the miner does, starts a thread, and says its pid and both thread ids,
    /// then waits for its stdin to close. Checks on the way that what the miner does to itself and
    /// its children still works.
    #[test]
    #[ignore = "run by a_locked_down_process_refuses_this_user"]
    fn locked_down_helper() {
        if std::env::var(HELPER).as_deref() != Ok("dacl") {
            return;
        }
        // SAFETY: plain kernel32 call.
        let main_tid = unsafe { GetCurrentThreadId() };
        lock_down_this_process().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            // SAFETY: plain kernel32 call.
            tx.send(unsafe { GetCurrentThreadId() }).unwrap();
            std::thread::sleep(std::time::Duration::from_secs(60));
        });
        let new_tid = rx.recv().unwrap();
        // The miner still starts and reads a child, and joins its own job.
        let out = std::process::Command::new("cmd")
            .args(["/c", "echo child-ok"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("child-ok"));
        crate::windows_job::join();
        // It still opens itself by its pid, as the miner does for its own times and memory.
        assert_eq!(
            open_process(
                std::process::id(),
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE
            ),
            Ok(())
        );
        println!(
            "READY pid={} main={main_tid} new={new_tid}",
            std::process::id()
        );
        let _ = std::io::stdin().read(&mut [0u8; 1]);
        drop(thread);
    }

    /// A process of this user, at the same integrity, can no longer read the locked-down miner's
    /// memory, write it, start a thread in it, change its DACL back, or touch its threads' contexts
    /// (one running at the lock-down and one started after); it can still see it and end it.
    /// [`locked_down_helper`] started (at this process's level), once it is locked down: it, and
    /// its pid and main and new thread ids.
    fn locked_down_child() -> (std::process::Child, u32, u32, u32) {
        let mut child = helper(
            "windows_sandbox::tests::locked_down_helper",
            &[(HELPER, "dacl".into())],
        )
        .spawn()
        .unwrap();
        // The harness prints its own lines first, and the test's name on the same line.
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        while !line.contains("READY") {
            line.clear();
            assert!(
                stdout.read_line(&mut line).unwrap() > 0,
                "the helper ended early"
            );
        }
        let field = |name: &str| -> u32 {
            line.split_whitespace()
                .find_map(|w| w.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("no {name} in {line:?}"))
                .parse()
                .unwrap()
        };
        let (pid, main, new) = (field("pid"), field("main"), field("new"));
        (child, pid, main, new)
    }

    #[test]
    fn a_locked_down_process_refuses_this_user() {
        let (mut child, pid, main, new) = locked_down_child();
        let denied = Err(ERROR_ACCESS_DENIED);
        let checks = [
            ("VM_READ", open_process(pid, PROCESS_VM_READ)),
            ("VM_WRITE", open_process(pid, PROCESS_VM_WRITE)),
            ("CREATE_THREAD", open_process(pid, PROCESS_CREATE_THREAD)),
            ("WRITE_DAC", open_process(pid, WRITE_DAC)),
            (
                "main thread context",
                open_thread(main, THREAD_SET_CONTEXT | THREAD_GET_CONTEXT),
            ),
            (
                "new thread context",
                open_thread(new, THREAD_SET_CONTEXT | THREAD_GET_CONTEXT),
            ),
            ("thread WRITE_DAC", open_thread(new, WRITE_DAC)),
        ];
        let still = [
            open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE),
            open_process(pid, PROCESS_TERMINATE),
        ];
        drop(child.stdin.take());
        let _ = child.kill();
        let _ = child.wait();
        // The control: an unlocked process of this user's is open to it.
        assert_eq!(open_process(std::process::id(), PROCESS_VM_READ), Ok(()));
        for (what, got) in checks {
            assert_eq!(got, denied, "{what} was not refused");
        }
        assert_eq!(still, [Ok(()), Ok(())]);
    }

    /// At Low integrity: says its level, then whether it could open the parent for reading, read a
    /// file labelled unreadable to it, write its own directory, and write a Medium one.
    #[test]
    #[ignore = "run by a_low_worker_is_kept_from_the_miner_and_its_secrets"]
    fn low_helper() {
        if std::env::var(HELPER).as_deref() != Ok("low") {
            return;
        }
        let var = |k: &str| std::env::var(k).unwrap();
        let parent: u32 = var("ZKMINER_TEST_PARENT").parse().unwrap();
        println!("LEVEL {:#x}", integrity_level());
        println!(
            "OPEN_PARENT {:?}",
            open_process(parent, PROCESS_VM_READ).map_err(|e| e == ERROR_ACCESS_DENIED)
        );
        let secret = std::fs::read(var("ZKMINER_TEST_SECRET"));
        println!(
            "READ_SECRET {:?}",
            secret.map(|_| ()).map_err(|e| e.raw_os_error())
        );
        let journal = std::fs::read(var("ZKMINER_TEST_JOURNAL"));
        println!(
            "READ_JOURNAL {:?}",
            journal.map(|_| ()).map_err(|e| e.raw_os_error())
        );
        let low = Path::new(&var("ZKMINER_TEST_LOW_DIR")).join("written");
        println!(
            "WRITE_LOW {:?}",
            std::fs::write(&low, b"x").map_err(|e| e.raw_os_error())
        );
        let medium = Path::new(&var("ZKMINER_TEST_MEDIUM_DIR")).join("written");
        println!(
            "WRITE_MEDIUM {:?}",
            std::fs::write(&medium, b"x").map_err(|e| e.raw_os_error())
        );
    }

    #[test]
    fn a_low_worker_is_kept_from_the_miner_and_its_secrets() {
        let dir = std::env::temp_dir().join(format!("zkminer-low-il-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (low_dir, medium_dir) = (dir.join("low"), dir.join("medium"));
        std::fs::create_dir_all(&medium_dir).unwrap();
        label_low_writable(&low_dir).unwrap();
        let secret = dir.join("secret.key");
        std::fs::write(&secret, b"not a key").unwrap();
        label_no_read_up(&secret).unwrap();
        // Written labelled from its creation (as the journal is), and still readable here.
        let journal = dir.join("journal.json");
        write_labelled_file(&journal, b"old").unwrap();
        write_labelled_file(&journal, b"{}").unwrap();
        assert_eq!(std::fs::read(&journal).unwrap(), b"{}");

        let mut env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        for (k, v) in [
            (HELPER, "low".to_string()),
            ("ZKMINER_TEST_PARENT", std::process::id().to_string()),
            ("ZKMINER_TEST_SECRET", secret.display().to_string()),
            ("ZKMINER_TEST_JOURNAL", journal.display().to_string()),
            ("ZKMINER_TEST_LOW_DIR", low_dir.display().to_string()),
            ("ZKMINER_TEST_MEDIUM_DIR", medium_dir.display().to_string()),
        ] {
            env.push((k.into(), v.into()));
        }
        let exe = std::env::current_exe().unwrap();
        let args = [
            "--ignored",
            "--exact",
            "windows_sandbox::tests::low_helper",
            "--nocapture",
            "--test-threads=1",
        ]
        .map(OsStr::new);
        let mut child = spawn(&exe, &args, &env, true).unwrap();
        assert!(child.is_low_integrity());
        // In a job of its own.
        let mut in_job = 0;
        // SAFETY: valid process and job handles.
        let ok = unsafe {
            IsProcessInJob(
                child.process.as_raw_handle(),
                child.job.as_ref().unwrap().as_raw_handle(),
                &mut in_job,
            )
        };
        assert!(ok != 0 && in_job != 0, "the worker is not in its job");
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        let status = child.wait().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(status.success(), "{status:?}\n{out}");
        assert!(out.contains("LEVEL 0x1000"), "not at Low:\n{out}");
        assert!(out.contains("OPEN_PARENT Err(true)"), "{out}");
        assert!(out.contains("READ_SECRET Err(Some(5))"), "{out}");
        assert!(out.contains("READ_JOURNAL Err(Some(5))"), "{out}");
        assert!(out.contains("WRITE_LOW Ok(())"), "{out}");
        assert!(out.contains("WRITE_MEDIUM Err(Some(5))"), "{out}");
    }

    /// `icacls <path> <args>`, which must succeed.
    fn icacls(path: &Path, args: &[&str]) {
        let out = std::process::Command::new("icacls")
            .arg(path)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "icacls {args:?}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// The file's DACL, as SDDL.
    fn dacl_of(path: &Path) -> String {
        const READ_CONTROL: u32 = 0x0002_0000;
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
        }
        let file = open_for(path, READ_CONTROL).unwrap();
        let (mut dacl, mut descriptor) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: an open handle and out-pointers; the descriptor is owned at once.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0);
        Descriptor(descriptor)
            .to_sddl(DACL_SECURITY_INFORMATION)
            .unwrap()
    }

    /// KL1: a key file made private as the README said (`/inheritance:r /grant:r <account>:R`) no
    /// longer lets its user set the label directly, but its owner still labels it, leaves its DACL
    /// as it was, and a Low worker then cannot read it.
    #[test]
    fn a_private_key_file_is_still_labelled_by_its_owner() {
        let dir = std::env::temp_dir().join(format!("zkminer-key-label-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("miner.key");
        std::fs::write(&key, b"not a key").unwrap();
        let user = zkminer_config::wallet::current_user_sid().unwrap();
        icacls(&key, &["/inheritance:r", "/grant:r", &format!("*{user}:R")]);
        let private = dacl_of(&key);
        let journal = dir.join("journal.json");
        let before = secrets_unlabelled(Some(&key), &dir, &journal);
        let direct = label_no_read_up(&key).map_err(|e| e.raw_os_error());
        let labelled = label_secret(&key);
        let label_held = has_no_read_up_label(&key).unwrap();
        let after = dacl_of(&key);
        let unlabelled_after = secrets_unlabelled(Some(&key), &dir, &journal);
        let mut child = low_helper_child(
            "windows_sandbox::tests::low_helper",
            &[
                (HELPER, "low".into()),
                ("ZKMINER_TEST_PARENT", std::process::id().to_string()),
                ("ZKMINER_TEST_SECRET", key.display().to_string()),
                ("ZKMINER_TEST_JOURNAL", journal.display().to_string()),
                ("ZKMINER_TEST_LOW_DIR", dir.display().to_string()),
                ("ZKMINER_TEST_MEDIUM_DIR", dir.display().to_string()),
            ],
        );
        let out = read_all(&mut child);
        let status = child.wait().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(direct, Err(Some(5)), "the direct label needs WRITE_OWNER");
        assert_eq!(labelled, Ok(()));
        assert!(label_held);
        assert_eq!(after, private, "the DACL was not put back");
        assert_eq!(
            before,
            vec![(key.clone(), true)],
            "doctor: labellable as its owner"
        );
        assert!(unlabelled_after.is_empty(), "{unlabelled_after:?}");
        assert!(status.success(), "{status:?}\n{out}");
        assert!(out.contains("READ_SECRET Err(Some(5))"), "{out}");
    }

    /// KL1: a key file this user can neither label nor, as its owner, open to labelling (its owner's
    /// rights taken away) is reported, with the remedy, and doctor finds it unlabelled.
    #[test]
    fn a_key_file_that_cannot_be_labelled_is_refused() {
        let dir = std::env::temp_dir().join(format!("zkminer-key-nolabel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("miner.key");
        std::fs::write(&key, b"not a key").unwrap();
        let user = zkminer_config::wallet::current_user_sid().unwrap();
        icacls(
            &key,
            &[
                "/inheritance:r",
                "/grant:r",
                &format!("*{user}:R"),
                "/grant:r",
                "*S-1-3-4:R",
            ],
        );
        let journal = dir.join("job_journal.json");
        let refused = label_secrets(Some(&key), None, &journal);
        let unlabelled = secrets_unlabelled(Some(&key), &dir, &journal);
        let _ = std::fs::remove_dir_all(&dir);
        let why = refused.unwrap_err();
        assert!(
            why.contains("miner.key")
                && why.contains("no worker is started")
                && why.contains("(WO)"),
            "{why}"
        );
        assert_eq!(unlabelled, vec![(key, false)]);
    }

    /// PowerShell's command histories are labelled unreadable to Low processes (never read), and a
    /// copy of an `env` key's variable in this user's registry environment refuses Low workers; a
    /// machine-wide copy is paged elsewhere, and a file key has no variable to look for.
    #[test]
    fn command_histories_are_labelled_and_a_user_registry_copy_refuses() {
        use zkminer_config::wallet_win::KeyEnvCopy;
        let dir = std::env::temp_dir().join(format!("zkminer-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let histories = dir
            .join("Microsoft")
            .join("Windows")
            .join("PowerShell")
            .join("PSReadLine");
        std::fs::create_dir_all(&histories).unwrap();
        let console = histories.join("ConsoleHost_history.txt");
        let code = histories.join("Visual Studio Code Host_history.txt");
        let other = histories.join("notes.txt");
        for f in [&console, &code, &other] {
            std::fs::write(f, b"Get-ChildItem\r\n").unwrap();
        }
        assert_eq!(command_histories(&dir), vec![console.clone(), code.clone()]);
        let none = |_: &str| Vec::new();
        assert_eq!(
            other_key_copies(Some("ZKMINER_PRIVATE_KEY"), Some(&dir), none),
            Ok(())
        );
        let labelled = [&console, &code].map(|f| has_no_read_up_label(f).unwrap());
        let other_labelled = has_no_read_up_label(&other).unwrap();

        let user = |name: &str| {
            vec![
                KeyEnvCopy {
                    location: format!(r"HKLM\SYSTEM\...\Environment ({name})"),
                    machine_wide: true,
                },
                KeyEnvCopy {
                    location: format!(r"HKCU\Environment ({name})"),
                    machine_wide: false,
                },
            ]
        };
        let refused = other_key_copies(Some("ZKMINER_PRIVATE_KEY"), None, user).unwrap_err();
        let machine = |name: &str| {
            vec![KeyEnvCopy {
                location: format!("HKLM ({name})"),
                machine_wide: true,
            }]
        };
        let machine_only = other_key_copies(Some("ZKMINER_PRIVATE_KEY"), None, machine);
        let file_key = other_key_copies(None, None, user);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(labelled, [true, true]);
        assert!(!other_labelled, "a file not a history was labelled");
        assert!(
            refused.contains(r"HKCU\Environment (ZKMINER_PRIVATE_KEY)")
                && refused.contains("SetEnvironmentVariable('ZKMINER_PRIVATE_KEY', $null, 'User')")
                && refused.contains("no Low worker is started")
                && !refused.contains("HKLM"),
            "{refused}"
        );
        assert_eq!(machine_only, Ok(()));
        assert_eq!(file_key, Ok(()));
        assert!(both(Err("a".into()), Err("b".into())).unwrap_err() == "a; b");
    }

    #[test]
    fn which_labels_keep_low_from_reading() {
        assert!(label_keeps_low_from_reading("S:(ML;;NWNR;;;ME)"));
        assert!(label_keeps_low_from_reading("S:(ML;;NRNW;;;HI)"));
        assert!(!label_keeps_low_from_reading("S:(ML;;NW;;;ME)"));
        assert!(!label_keeps_low_from_reading("S:(ML;;NWNR;;;LW)"));
        assert!(!label_keeps_low_from_reading("S:"));
        assert!(!label_keeps_low_from_reading(""));
    }

    /// The same process at Medium: its environment and pipes work, it gets no handle it was not
    /// given, and it ends with its job.
    #[test]
    fn a_worker_gets_its_environment_and_pipes() {
        let env = vec![
            ("SystemRoot".into(), std::env::var_os("SystemRoot").unwrap()),
            ("ZKMINER_A".into(), "first".into()),
            ("zkminer_a".into(), "last wins".into()),
        ];
        let cmd = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
        let args = [
            "/v:on",
            "/c",
            "set ZKMINER_A & echo err 1>&2 & set /p X= & echo got !X!",
        ]
        .map(OsStr::new);
        let mut child = spawn(&cmd, &args, &env, false).unwrap();
        assert!(!child.is_low_integrity());
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(b"hello\r\n").unwrap();
        }
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        let mut err = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        assert!(child.wait().unwrap().success());
        assert!(out.to_uppercase().contains("ZKMINER_A=LAST WINS"), "{out}");
        assert!(!out.contains("first"), "{out}");
        assert!(out.contains("got hello"), "{out}");
        assert!(err.contains("err"), "{err}");
        // A second one, waiting on its stdin, killed.
        let mut child = spawn(&cmd, &["/c", "set /p X="].map(OsStr::new), &env, false).unwrap();
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
    }

    /// The test binary at Low integrity as a worker would start, running only the ignored helper
    /// `test` with `vars` added.
    fn low_helper_child(test: &str, vars: &[(&str, String)]) -> WorkerChild {
        let mut env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        env.extend(vars.iter().map(|(k, v)| (k.into(), v.into())));
        let args = [
            "--ignored",
            "--exact",
            test,
            "--nocapture",
            "--test-threads=1",
        ]
        .map(OsStr::new);
        spawn(&std::env::current_exe().unwrap(), &args, &env, true).unwrap()
    }

    fn read_all(child: &mut WorkerChild) -> String {
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        out
    }

    /// A Low worker that waits for its stdin to close.
    #[test]
    #[ignore = "run by low_workers_cannot_open_each_other"]
    fn low_waiting_helper() {
        if std::env::var(HELPER).as_deref() != Ok("wait") {
            return;
        }
        let _ = std::io::stdin().read(&mut [0u8; 1]);
    }

    /// A Low worker that says which rights on the process `ZKMINER_TEST_TARGET` it got.
    #[test]
    #[ignore = "run by low_workers_cannot_open_each_other"]
    fn low_probing_helper() {
        if std::env::var(HELPER).as_deref() != Ok("probe") {
            return;
        }
        const PROCESS_VM_OPERATION: u32 = 0x0008;
        const PROCESS_DUP_HANDLE: u32 = 0x0040;
        const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
        let target: u32 = std::env::var("ZKMINER_TEST_TARGET")
            .unwrap()
            .parse()
            .unwrap();
        println!("LEVEL {:#x}", integrity_level());
        for (what, access) in [
            ("VM_READ", PROCESS_VM_READ),
            ("VM_WRITE", PROCESS_VM_WRITE | PROCESS_VM_OPERATION),
            ("CREATE_THREAD", PROCESS_CREATE_THREAD),
            ("DUP_HANDLE", PROCESS_DUP_HANDLE),
            ("SUSPEND_RESUME", PROCESS_SUSPEND_RESUME),
            ("TERMINATE", PROCESS_TERMINATE),
            ("WRITE_DAC", WRITE_DAC),
            ("QUERY", PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE),
        ] {
            println!("OPEN {what} {:?}", open_process(target, access));
        }
        // And the threads `ZKMINER_TEST_TARGET_THREADS` (ids, comma-separated), if given.
        let threads = std::env::var("ZKMINER_TEST_TARGET_THREADS").unwrap_or_default();
        for tid in threads.split(',').filter_map(|t| t.parse::<u32>().ok()) {
            const THREAD_SUSPEND_RESUME: u32 = 0x0002;
            for (what, access) in [
                (
                    "CONTEXT",
                    THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                ),
                ("ALL", THREAD_ALL_ACCESS),
                ("QUERY", THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE),
            ] {
                println!("THREAD {tid} {what} {:?}", open_thread(tid, access));
            }
        }
    }

    /// A Low worker as the workers start (`zkminer_prover_protocol::threads::lock_threads`) that,
    /// once running, starts a thread and a process (as SP1's worker starts its server), says their
    /// ids, then waits for its stdin to close and ends its process.
    #[test]
    #[ignore = "run by threads_a_low_worker_starts_later_are_closed_to_its_siblings"]
    fn low_later_helper() {
        if std::env::var(HELPER).as_deref() != Ok("later") {
            return;
        }
        zkminer_prover_protocol::threads::lock_threads().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            // SAFETY: plain kernel32 call.
            tx.send(unsafe { GetCurrentThreadId() }).unwrap();
            std::thread::sleep(std::time::Duration::from_secs(60));
        });
        let tid = rx.recv().unwrap();
        // The worker itself still opens its own thread by its id, to see it.
        println!(
            "OWN_THREAD {:?}",
            open_thread(tid, THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)
        );
        let mut child = std::process::Command::new("cmd")
            .args(["/c", "set /p X="])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        println!("READY later={tid} child={}", child.id());
        let _ = std::io::stdin().read(&mut [0u8; 1]);
        println!(
            "KILL_CHILD {:?}",
            child.kill().map_err(|e| e.raw_os_error())
        );
        println!("WAIT_CHILD {:?}", child.wait().map(|s| s.success()).ok());
        drop(thread);
    }

    /// RL2: a thread a Low worker starts once running is closed to another Low worker as its first
    /// thread is: no context, no suspending, no end; only seeing it. The worker still starts and
    /// ends a process of its own.
    #[test]
    fn threads_a_low_worker_starts_later_are_closed_to_its_siblings() {
        let mut worker = low_helper_child(
            "windows_sandbox::tests::low_later_helper",
            &[(HELPER, "later".into())],
        );
        let mut stdout = std::io::BufReader::new(worker.stdout.take().unwrap());
        let mut out = String::new();
        let mut line = String::new();
        while !line.contains("READY") {
            line.clear();
            assert!(
                stdout.read_line(&mut line).unwrap() > 0,
                "the helper ended early:\n{out}"
            );
            out.push_str(&line);
        }
        let later: u32 = line
            .split_whitespace()
            .find_map(|w| w.strip_prefix("later="))
            .unwrap_or_else(|| panic!("no thread id in {line:?}"))
            .parse()
            .unwrap();
        let mut probe = low_helper_child(
            "windows_sandbox::tests::low_probing_helper",
            &[
                (HELPER, "probe".into()),
                ("ZKMINER_TEST_TARGET", worker.id().to_string()),
                ("ZKMINER_TEST_TARGET_THREADS", later.to_string()),
            ],
        );
        let probed_out = read_all(&mut probe);
        let probed = probe.wait().unwrap();
        drop(worker.stdin.take());
        stdout.read_to_string(&mut out).unwrap();
        let status = worker.wait().unwrap();
        assert!(status.success(), "{status:?}\n{out}");
        assert!(probed.success(), "{probed:?}\n{probed_out}");
        assert!(
            probed_out.contains("LEVEL 0x1000"),
            "the probe is not at Low:\n{probed_out}"
        );
        for what in ["CONTEXT", "ALL"] {
            assert!(
                probed_out.contains(&format!("THREAD {later} {what} Err({ERROR_ACCESS_DENIED})")),
                "the later thread's {what} was not refused:\n{probed_out}"
            );
        }
        assert!(
            probed_out.contains(&format!("THREAD {later} QUERY Ok(())")),
            "{probed_out}"
        );
        assert!(out.contains("OWN_THREAD Ok(())"), "{out}");
        assert!(out.contains("KILL_CHILD Ok(())"), "{out}");
        assert!(out.contains("WAIT_CHILD Some(false)"), "{out}");
    }

    /// A Low process gets nothing on the locked-down miner: it can neither end it nor wait for
    /// it, read it or touch its threads (a thread running at the lock-down and one started after).
    /// A process of this user at Medium (`zkminer stop`, a process manager) still sees and ends it.
    #[test]
    fn a_low_process_cannot_end_or_open_the_miner() {
        let (mut miner, pid, main, new) = locked_down_child();
        let mut probe = low_helper_child(
            "windows_sandbox::tests::low_probing_helper",
            &[
                (HELPER, "probe".into()),
                ("ZKMINER_TEST_TARGET", pid.to_string()),
                ("ZKMINER_TEST_TARGET_THREADS", format!("{main},{new}")),
            ],
        );
        let out = read_all(&mut probe);
        let probed = probe.wait().unwrap();
        let still_alive = miner.try_wait().unwrap().is_none();
        let by_medium = [
            open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE),
            open_process(pid, PROCESS_TERMINATE),
        ];
        drop(miner.stdin.take());
        let _ = miner.kill();
        let _ = miner.wait();
        assert!(probed.success(), "{probed:?}\n{out}");
        assert!(
            out.contains("LEVEL 0x1000"),
            "the probe is not at Low:\n{out}"
        );
        for what in [
            "VM_READ",
            "VM_WRITE",
            "CREATE_THREAD",
            "DUP_HANDLE",
            "SUSPEND_RESUME",
            "TERMINATE",
            "WRITE_DAC",
            "QUERY",
        ] {
            assert!(
                out.contains(&format!("OPEN {what} Err({ERROR_ACCESS_DENIED})")),
                "{what} was not refused:\n{out}"
            );
        }
        for tid in [main, new] {
            for what in ["CONTEXT", "ALL", "QUERY"] {
                assert!(
                    out.contains(&format!("THREAD {tid} {what} Err({ERROR_ACCESS_DENIED})")),
                    "thread {tid} {what} was not refused:\n{out}"
                );
            }
        }
        assert!(still_alive, "the Low probe ended the miner");
        assert_eq!(by_medium, [Ok(()), Ok(())]);
    }

    /// One Low worker cannot read, write, start a thread in, suspend, re-DACL, end or even wait for
    /// another (the label withholds a process's generic execute rights from Low processes too). The
    /// miner (here, at Medium) still opens it as it does by pid, for its times and memory figures
    /// and to end it, and no more.
    #[test]
    fn low_workers_cannot_open_each_other() {
        let mut target = low_helper_child(
            "windows_sandbox::tests::low_waiting_helper",
            &[(HELPER, "wait".into())],
        );
        let mut probe = low_helper_child(
            "windows_sandbox::tests::low_probing_helper",
            &[
                (HELPER, "probe".into()),
                ("ZKMINER_TEST_TARGET", target.id().to_string()),
            ],
        );
        let out = read_all(&mut probe);
        let probed = probe.wait().unwrap();
        let by_miner = [
            open_process(
                target.id(),
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            ),
            open_process(target.id(), PROCESS_TERMINATE),
            open_process(target.id(), PROCESS_VM_WRITE),
        ];
        let still_alive = target.try_wait().unwrap().is_none();
        drop(target.stdin.take());
        let _ = target.wait();
        assert!(probed.success(), "{probed:?}\n{out}");
        assert!(
            out.contains("LEVEL 0x1000"),
            "the probe is not at Low:\n{out}"
        );
        for what in [
            "VM_READ",
            "VM_WRITE",
            "CREATE_THREAD",
            "DUP_HANDLE",
            "SUSPEND_RESUME",
            "WRITE_DAC",
            "TERMINATE",
            "QUERY",
        ] {
            assert!(
                out.contains(&format!("OPEN {what} Err({ERROR_ACCESS_DENIED})")),
                "{what} was not refused:\n{out}"
            );
        }
        // VM_WRITE, refused to the miner too.
        assert_eq!(by_miner, [Ok(()), Ok(()), Err(ERROR_ACCESS_DENIED)]);
        assert!(still_alive, "the probe ended the other worker");
    }

    /// `cmd /c mklink /J link target`: a junction, which a Low process may make (to a directory it
    /// can write) where a Low directory should be.
    fn junction(link: &Path, target: &Path) {
        let ok = std::process::Command::new("cmd")
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(ok, "mklink /J {}", link.display());
    }

    /// A file and a junction planted where Low directories go are replaced by directories, the
    /// junction's target left as it was (not emptied, not made Low-writable); a junction where a
    /// directory is to be labelled for the environment is refused, not followed.
    #[test]
    fn low_dirs_are_repaired_and_links_never_followed() {
        let root = std::env::temp_dir().join(format!("zkminer-low-dirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (local, home) = (root.join("local"), root.join("home"));
        let worker = local.join("zkminer").join("worker");
        std::fs::create_dir_all(&worker).unwrap();
        let medium = root.join("medium");
        std::fs::create_dir_all(&medium).unwrap();
        std::fs::write(medium.join("kept"), b"x").unwrap();
        std::fs::write(worker.join("neo"), b"planted").unwrap();
        junction(&worker.join("sycl"), &medium);
        std::fs::create_dir_all(home.join(".zkminer")).unwrap();
        junction(&home.join(".zkminer").join("locks"), &medium);

        // Progress files of SP1 workers: a dead one's goes, a live one's stays.
        let tmp = worker.join("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        let dead = tmp.join("zkminer-sp1-progress-4000000001.txt");
        let live = tmp.join(format!("zkminer-sp1-progress-{}.txt", std::process::id()));
        for p in [&dead, &live] {
            std::fs::write(p, b"3/7").unwrap();
        }

        let dirs = prepare_low_dirs(&local, &home).unwrap();
        assert!(!dead.exists() && live.exists(), "progress files");
        for name in ["neo", "sycl"] {
            let m = std::fs::symlink_metadata(worker.join(name)).unwrap();
            assert!(
                m.is_dir() && !is_reparse_point(&m),
                "{name} is not a plain directory"
            );
        }
        let locks = std::fs::symlink_metadata(home.join(".zkminer").join("locks")).unwrap();
        assert!(locks.is_dir() && !is_reparse_point(&locks));
        assert!(dirs.contains(&("SYCL_CACHE_DIR", worker.join("sycl"))));
        assert!(
            medium.join("kept").exists(),
            "the junction's target was emptied"
        );

        // A link where an environment's directory goes: refused.
        let env_link = root.join("segments");
        junction(&env_link, &medium);
        let refused = label_low_writable(&env_link).unwrap_err().to_string();
        assert!(refused.contains("a link"), "{refused}");

        // At Low: the repaired directory is writable, the junction's old target is not.
        let mut child = low_helper_child(
            "windows_sandbox::tests::low_helper",
            &[
                (HELPER, "low".into()),
                ("ZKMINER_TEST_PARENT", std::process::id().to_string()),
                (
                    "ZKMINER_TEST_SECRET",
                    root.join("none").display().to_string(),
                ),
                (
                    "ZKMINER_TEST_JOURNAL",
                    root.join("none").display().to_string(),
                ),
                (
                    "ZKMINER_TEST_LOW_DIR",
                    worker.join("sycl").display().to_string(),
                ),
                ("ZKMINER_TEST_MEDIUM_DIR", medium.display().to_string()),
            ],
        );
        let out = read_all(&mut child);
        let status = child.wait().unwrap();
        let _ = std::fs::remove_dir_all(&root);
        assert!(status.success(), "{status:?}\n{out}");
        assert!(out.contains("WRITE_LOW Ok(())"), "{out}");
        assert!(out.contains("WRITE_MEDIUM Err(Some(5))"), "{out}");
    }

    /// What a Low worker broke in the Low directories after one started (a file where `tmp` goes,
    /// `risc0-segments` deleted) is repaired before the next one, not left for the rest of the run.
    #[test]
    fn low_dirs_are_repaired_before_every_low_worker() {
        let root = std::env::temp_dir().join(format!("zkminer-low-respawn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let system = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
        let whoami = system.join("System32").join("whoami.exe");
        let env: Vec<(OsString, OsString)> = vec![("SystemRoot".into(), system.into())];
        TEST_LOW_ROOT.with(|r| *r.borrow_mut() = Some(root.clone()));
        let spawn_once = || {
            let mut child = spawn_worker("risc0", &whoami, env.clone()).unwrap();
            assert!(child.is_low_integrity());
            let _ = child.wait();
        };
        spawn_once();
        let tmp = root
            .join("local")
            .join("zkminer")
            .join("worker")
            .join("tmp");
        let segments = root.join("home").join(".zkminer").join("risc0-segments");
        assert!(tmp.is_dir() && segments.is_dir());
        std::fs::remove_dir_all(&tmp).unwrap();
        std::fs::write(&tmp, b"planted").unwrap();
        std::fs::remove_dir_all(&segments).unwrap();
        spawn_once();
        TEST_LOW_ROOT.with(|r| *r.borrow_mut() = None);
        let repaired = [tmp.is_dir(), segments.is_dir()];
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(repaired, [true, true], "tmp, risc0-segments");
    }

    /// X-B: workers run at Low unless the operator opts out with exactly `0`; nothing else (unset,
    /// `1`, a typo) leaves them at Medium. And a worker started with the flag unset is at Low.
    #[test]
    fn low_integrity_is_the_default() {
        assert!(low_il_from(None));
        assert!(low_il_from(Some("1")));
        assert!(low_il_from(Some("")));
        assert!(low_il_from(Some("off")));
        assert!(!low_il_from(Some("0")));
        assert!(!low_il_from(Some(" 0 ")));
        if std::env::var_os(LOW_IL_WORKERS_ENV).is_none() {
            assert!(low_il_workers());
            let system = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
            let whoami = system.join("System32").join("whoami.exe");
            let env = vec![
                ("SystemRoot".into(), system.into_os_string()),
                (
                    zkminer_prover_protocol::types::LOW_INTEGRITY_WORKER_ENV.into(),
                    "1".into(),
                ),
            ];
            TEST_SPAWNS.with(|s| s.borrow_mut().clear());
            let mut child = spawn_worker("risc0", &whoami, env).unwrap();
            let _ = child.wait();
            assert!(child.is_low_integrity());
            assert_eq!(TEST_SPAWNS.with(|s| s.borrow().clone()), vec![true]);
        }
    }

    /// LocalSystem, LocalService and NetworkService are refused whatever their admin state, and so
    /// is an administrator under a service logon and an account that could not be told, unless
    /// overridden, and the refusal names the override. An administrator's console is not refused
    /// (it is paged or warned), nor is a standard account, nor the README's service account (a
    /// service logon without Administrators, whatever its privileges).
    #[test]
    fn service_accounts_and_admin_services_are_refused_and_consoles_are_not() {
        use crate::windows_account::AdminState;
        let user = "S-1-5-21-1004336348-1177238915-682003330-1001";
        let refused = |risk: io::Result<Option<AccountRisk>>, what: &str| {
            let refusal = account_refusal(&risk, false).expect("refused");
            assert!(
                refusal.contains(what) && refusal.contains(ALLOW_PRIVILEGED_ACCOUNT_ENV),
                "{refusal}"
            );
            assert_eq!(account_refusal(&risk, true), None);
        };
        for (sid, account) in [
            ("S-1-5-18", "LocalSystem"),
            ("s-1-5-19", "LocalService"),
            ("S-1-5-20", "NetworkService"),
        ] {
            for admin in [AdminState::Full, AdminState::Filtered, AdminState::None] {
                for service in [false, true] {
                    let risk = classify_account(sid, admin, service);
                    assert_eq!(risk, Some(AccountRisk::ServiceAccount(account)), "{sid}");
                    refused(Ok(risk), account);
                }
            }
        }
        // Not to be confused with a domain or local account that merely starts the same way.
        assert_eq!(classify_account("S-1-5-180", AdminState::None, false), None);
        let admin_service = classify_account(user, AdminState::Full, true);
        assert_eq!(admin_service, Some(AccountRisk::AdminService));
        refused(Ok(admin_service), "administrator");
        // N-2: an account that could not be told fails closed.
        refused(Err(io::Error::other("no token")), "could not tell");
        for (admin, risk) in [
            (AdminState::Full, Some(AccountRisk::Elevated)),
            (AdminState::Filtered, Some(AccountRisk::FilteredAdmin)),
            (AdminState::None, None),
        ] {
            assert_eq!(classify_account(user, admin, false), risk);
            assert_eq!(account_refusal(&Ok(risk), false), None);
        }
        // An administrator's console that is not elevated stays one under a service logon too.
        assert_eq!(
            classify_account(user, AdminState::Filtered, true),
            Some(AccountRisk::FilteredAdmin)
        );
        assert_eq!(classify_account(user, AdminState::None, true), None);
        // This process's account can be told, and tests do not run as a service account (a CI
        // runner may be an administrator under a service logon).
        let here = account_risk().unwrap();
        assert!(
            !matches!(here, Some(AccountRisk::ServiceAccount(_))),
            "{here:?}"
        );
    }

    #[test]
    fn command_lines_and_environment_blocks() {
        let line = |args: &[&str]| {
            let l = command_line(
                Path::new(r"C:\a b\w.exe"),
                &args.iter().map(OsStr::new).collect::<Vec<_>>(),
            )
            .unwrap();
            String::from_utf16(&l[..l.len() - 1]).unwrap()
        };
        assert_eq!(line(&[]), r#""C:\a b\w.exe""#);
        assert_eq!(
            line(&["plain", "two words", "", r#"q"uote"#, r"tail\"]),
            r#""C:\a b\w.exe" plain "two words" "" "q\"uote" tail\"#
        );
        assert_eq!(line(&[r"a b\"]), r#""C:\a b\w.exe" "a b\\""#);
        assert!(command_line(Path::new("a\"b"), &[]).is_err());
        let block = environment_block(&[
            ("b".into(), "2".into()),
            ("A".into(), "1".into()),
            ("B".into(), "3".into()),
        ])
        .unwrap();
        assert_eq!(String::from_utf16(&block).unwrap(), "A=1\0B=3\0\0");
        assert_eq!(environment_block(&[]).unwrap(), vec![0, 0]);
        assert!(environment_block(&[("A=B".into(), "1".into())]).is_err());
    }
}
