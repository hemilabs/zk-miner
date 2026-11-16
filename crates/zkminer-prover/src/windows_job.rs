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

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::sync::OnceLock;

const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;

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
            info.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
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
            // Deliberately never closed: the system closes it when the miner ends, and that is
            // what ends the workers.
            Ok(job as usize)
        }
    })
    .clone()
    .map(|h| h as *mut c_void)
}

/// Make `child` end when this process ends. Never fails the spawn: without it a worker outlives an
/// abruptly ended miner, as it did before.
pub(crate) fn end_with_this_process(child: &std::process::Child) {
    let result = job().and_then(|job| {
        // SAFETY: a valid job handle and the live child's process handle.
        let ok = unsafe { AssignProcessToJobObject(job, child.as_raw_handle()) };
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
            child.id()
        );
    }
}

#[cfg(test)]
mod tests {
    /// A child joined to the job is ended when the process that joined it ends, however it ends.
    /// Run in a child test process, so this one's job is left alone.
    #[test]
    fn a_worker_ends_with_the_miner() {
        use std::process::Command;
        if std::env::var_os("ZKMINER_MINER_JOB_TEST_PARENT").is_some() {
            let mut cmd = Command::new("powershell");
            cmd.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 60"]);
            // As a worker is started: in a console of its own.
            crate::worker::isolate_from_console(&mut cmd);
            let child = cmd.spawn().unwrap();
            super::end_with_this_process(&child);
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
