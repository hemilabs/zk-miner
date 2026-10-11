//! Ending `sp1-gpu-server` with this worker on Windows.
//!
//! The SDK starts the server as a child and kills it on drop, which a worker killed abruptly never
//! reaches. On Linux `reap_orphaned_gpu_servers` then finds the orphan by its parent pid, before
//! the next worker's client would connect to it and prove on a server nothing can reap. Windows
//! keeps no parent link to find it by, so instead no server is left behind: this worker puts
//! itself in a job that kills everything in it when its last handle closes. Children join their
//! parent's job, and the only handle is this process's, which the system closes however the
//! process ends.

use std::ffi::c_void;

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
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

/// Puts this process in a job that ends with it; see the module docs. Never fails the worker:
/// without it a server outlives an abruptly killed worker, as it did before.
pub(crate) fn end_children_with_this_process() {
    if let Err(e) = try_end_children_with_this_process() {
        tracing::warn!(
            "sp1-gpu-server will not end with this worker ({e}); if the worker is killed, end \
             the server by hand before the next one starts, or it will be reused"
        );
    }
}

fn try_end_children_with_this_process() -> std::io::Result<()> {
    unsafe {
        let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
        if job.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let mut info = ExtendedLimitInformation::default();
        info.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let assigned = SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            (&info as *const ExtendedLimitInformation).cast(),
            std::mem::size_of::<ExtendedLimitInformation>() as u32,
        ) != 0
            && AssignProcessToJobObject(job, GetCurrentProcess()) != 0;
        if !assigned {
            let e = std::io::Error::last_os_error();
            CloseHandle(job);
            return Err(e);
        }
        // Deliberately never closed: the system closes it when this process ends, and that is
        // what ends the job.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    /// A child started after the call is ended when the process that made the call ends, however
    /// it ends. Run in a child test process, so this one is left out of any job.
    #[test]
    fn a_child_ends_with_its_parent() {
        use std::process::Command;
        if std::env::var_os("ZKMINER_JOB_TEST_PARENT").is_some() {
            super::try_end_children_with_this_process().unwrap();
            let child = Command::new("powershell")
                .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 60"])
                .spawn()
                .unwrap();
            println!("CHILD_PID={}", child.id());
            // Ends abruptly, as a killed worker would: no destructors, no kill-on-drop.
            std::process::exit(0);
        }
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows_job::tests::a_child_ends_with_its_parent",
                "--nocapture",
            ])
            .env("ZKMINER_JOB_TEST_PARENT", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let pid: u32 = stdout
            .lines()
            .find_map(|l| l.strip_prefix("CHILD_PID="))
            .unwrap_or_else(|| panic!("no child started: {stdout}"))
            .trim()
            .parse()
            .unwrap();
        let alive = |pid: u32| {
            let list = Command::new("tasklist")
                .args(["/FI", &format!("PID eq {pid}"), "/NH"])
                .output()
                .unwrap();
            String::from_utf8_lossy(&list.stdout).contains(&pid.to_string())
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while alive(pid) {
            assert!(
                std::time::Instant::now() < deadline,
                "child {pid} outlived its parent"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}
