//! Ending the workers with the miner on Windows.
//!
//! Workers run in consoles of their own (`worker::isolate_from_console`), so the miner's console
//! events (Ctrl+C, closing the window, a system shutdown) do not kill the proofs a drain is waiting
//! for. That also means closing the window, a crash or `taskkill /F` of the miner no longer ends
//! them: a worker mid-proof would go on holding VRAM until its proof ended, and an SP1 worker's
//! `sp1-gpu-server` with it, which the next start's worker could then connect to. So every worker
//! joins a job that kills everything in it when its last handle closes. The only handle is the
//! miner's, which the system closes however the miner ends. (The SP1 worker puts itself in a job
//! of its own too; jobs nest.)
//!
//! Each worker is also in a job of its own inside that one ([`new_worker_job`]), which keeps it
//! from the desktop: the clipboard, other processes' windows, the global atom table, the display
//! and system settings. Those limits are never put on the miner's job, which the miner is in.
//!
//! The miner's job also ends any process in it, the miner included, on an unhandled exception.
//! The miner's process is locked down (`windows_sandbox::lock_down_this_process`), so Windows Error
//! Reporting cannot open it: a crash left the faulting thread stuck forever and the miner alive
//! (no exit for a service manager to restart, locks held to their deadlines). The miner joins the
//! job first thing ([`join_early`]), and its own crash handler (`windows_crash`) records the crash
//! and exits before this applies; the job is the backstop if a library replaced that handler.

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::sync::OnceLock;

const JOB_OBJECT_BASIC_UI_RESTRICTIONS: i32 = 4;
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x0400;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
const JOB_OBJECT_UILIMIT_HANDLES: u32 = 0x0001;
const JOB_OBJECT_UILIMIT_READCLIPBOARD: u32 = 0x0002;
const JOB_OBJECT_UILIMIT_WRITECLIPBOARD: u32 = 0x0004;
const JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS: u32 = 0x0008;
const JOB_OBJECT_UILIMIT_DISPLAYSETTINGS: u32 = 0x0010;
const JOB_OBJECT_UILIMIT_GLOBALATOMS: u32 = 0x0020;
const JOB_OBJECT_UILIMIT_DESKTOP: u32 = 0x0040;
const JOB_OBJECT_UILIMIT_EXITWINDOWS: u32 = 0x0080;

#[repr(C)]
#[derive(Default)]
struct BasicLimitInformation {
    per_process_user_time_limit: i64,
    per_job_user_time_limit: i64,
    limit_flags: u32,
    minimum_working_set_size: usize,
    maximum_working_set_size: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

#[repr(C)]
#[derive(Default)]
struct ExtendedLimitInformation {
    basic: BasicLimitInformation,
    io_counters: [u64; 6],
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> *mut c_void;
    fn SetInformationJobObject(
        job: *mut c_void,
        class: i32,
        info: *const c_void,
        length: u32,
    ) -> i32;
    fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

/// The job's handle (as an address), made once; `Err` if it could not be made.
static JOB: OnceLock<Result<usize, String>> = OnceLock::new();

fn job() -> Result<*mut c_void, String> {
    JOB.get_or_init(|| {
        // SAFETY: plain kernel32 calls on a job this function owns; `info` outlives the call.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
            if job.is_null() {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let mut info = ExtendedLimitInformation::default();
            info.basic.limit_flags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            if SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                (&info as *const ExtendedLimitInformation).cast(),
                std::mem::size_of::<ExtendedLimitInformation>() as u32,
            ) == 0
            {
                let e = std::io::Error::last_os_error().to_string();
                CloseHandle(job);
                return Err(e);
            }
            // The miner joins it itself, before it starts any worker: a child then belongs to it
            // from its creation. (Assigning each worker after it started raced the SP1 worker,
            // which puts itself in a job of its own early; a process already in a job can join
            // another only if that one is empty or in its tree, so the miner's assignment failed.
            // Jobs nest, so the SP1 worker's job now sits inside this one.)
            if AssignProcessToJobObject(job, GetCurrentProcess()) == 0 {
                let e = std::io::Error::last_os_error().to_string();
                CloseHandle(job);
                return Err(e);
            }
            // Deliberately never closed: the system closes it when the miner ends, and that is
            // what ends the workers.
            Ok(job as usize)
        }
    })
    .clone()
    .map(|h| h as *mut c_void)
}

/// Join this process to the job before a worker is started (see the module docs). Idempotent.
pub(crate) fn join() {
    if let Err(e) = job() {
        tracing::warn!(
            "workers will not end with the miner ({e}): if the miner is killed or its window \
             closed, end them by hand before the next start"
        );
    }
}

/// [`join`] for the miner's `main`, before anything else runs: from then on an unhandled exception
/// ends the process (see the module docs). What went wrong, if it could not join.
pub(crate) fn join_early() -> Result<(), String> {
    job().map(|_| ())
}

/// Make the process `process` (pid `pid`) end when this process ends. Never fails the spawn: without
/// it a worker outlives an abruptly ended miner, as it did before. (A child started after [`join`]
/// is in the job already; assigning it again is harmless.)
pub(crate) fn end_with_this_process(process: RawHandle, pid: u32) {
    let result = job().and_then(|job| {
        // SAFETY: a valid job handle and the live child's process handle.
        let ok = unsafe { AssignProcessToJobObject(job, process) };
        if ok == 0 {
            Err(std::io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    });
    if let Err(e) = result {
        tracing::warn!(
            "worker pid {} will not end with the miner ({e}): if the miner is killed or its window \
             closed, end the worker by hand before the next start",
            pid
        );
    }
}

/// A job for one worker, to be assigned before the worker runs (it is started suspended). It nests
/// in the miner's job, so the worker still ends with the miner. It ends everything in it when its
/// handle closes (the worker's handle holds it), lets nothing in it break away, ends a process on an
/// unhandled exception rather than waiting on an error dialog, and keeps its processes from the
/// desktop: other processes' windows and hooks, the clipboard, the global atom table, other
/// desktops, display and system settings, and logging off or shutting down. A prover needs none of
/// it (the GPU runtimes do not go through the desktop for compute).
///
/// No limit on processes (the SP1 worker starts `sp1-gpu-server`, the risc0 one its Groth16 helper
/// and `nvidia-smi`) nor on memory: Windows charges a process's VRAM to its commit, so a commit
/// limit would fail GPU allocations.
pub(crate) fn new_worker_job() -> std::io::Result<OwnedHandle> {
    #[repr(C)]
    struct UiRestrictions {
        class: u32,
    }
    // SAFETY: plain kernel32 calls; the handle is owned at once, and every `info` outlives its call.
    unsafe {
        let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
        if job.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let job = OwnedHandle::from_raw_handle(job);
        let mut info = ExtendedLimitInformation::default();
        info.basic.limit_flags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        if SetInformationJobObject(
            job.as_raw_handle(),
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            (&info as *const ExtendedLimitInformation).cast(),
            std::mem::size_of::<ExtendedLimitInformation>() as u32,
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let ui = UiRestrictions {
            class: JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        };
        if SetInformationJobObject(
            job.as_raw_handle(),
            JOB_OBJECT_BASIC_UI_RESTRICTIONS,
            (&ui as *const UiRestrictions).cast(),
            std::mem::size_of::<UiRestrictions>() as u32,
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(job)
    }
}

/// Put `process` in `job` (a [`new_worker_job`]).
pub(crate) fn assign(job: &OwnedHandle, process: RawHandle) -> std::io::Result<()> {
    // SAFETY: a valid job handle and a live process handle.
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// A child joined to the job is ended when the process that joined it ends, however it ends.
    /// Run in a child test process, so this one's job is left alone.
    #[test]
    fn a_worker_ends_with_the_miner() {
        use std::process::Command;
        if std::env::var_os("ZKMINER_MINER_JOB_TEST_PARENT").is_some() {
            super::join();
            let mut cmd = Command::new("powershell");
            cmd.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 60"])
                // Not our stdout: `.output()` below would wait for it to close, and the test would
                // pass by outwaiting the sleep even with the job broken.
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            // As a worker is started: in a console of its own.
            crate::worker::isolate_from_console(&mut cmd);
            let child = cmd.spawn().unwrap();
            {
                use std::os::windows::io::AsRawHandle;
                super::end_with_this_process(child.as_raw_handle(), child.id());
            }
            println!("CHILD_PID={}", child.id());
            // Ends abruptly, as a killed miner would.
            std::process::exit(0);
        }
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows_job::tests::a_worker_ends_with_the_miner",
                "--nocapture",
            ])
            .env("ZKMINER_MINER_JOB_TEST_PARENT", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let pid: u32 = stdout
            .lines()
            .find_map(|l| l.strip_prefix("CHILD_PID="))
            .unwrap_or_else(|| panic!("no child pid in:\n{stdout}"))
            .trim()
            .parse()
            .unwrap();
        // Give the system a moment to end it, then look for it.
        let gone = (0..50).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let list = Command::new("tasklist")
                .args(["/FI", &format!("PID eq {pid}"), "/NH"])
                .output()
                .unwrap();
            !String::from_utf8_lossy(&list.stdout).contains(&pid.to_string())
        });
        if !gone {
            let _ = Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .output();
        }
        assert!(gone, "the worker outlived the process that started it");
    }
}
