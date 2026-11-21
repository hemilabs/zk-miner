//! Windows: whether a process is still running, and which one it is.
//!
//! A pid alone does not name a process for long: Windows reuses them. What a process leaves on disk
//! under its pid (a risc0 worker's segment directory, an SP1 worker's progress file) is named with
//! its start time too where it can be, and is stale once no process runs under that pid, or the one
//! that does started at another time. Linux reads the same from `/proc/<pid>/stat`.

use std::ffi::c_void;

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const STILL_ACTIVE: u32 = 259;
const ERROR_INVALID_PARAMETER: i32 = 87;

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn GetExitCodeProcess(process: *mut c_void, code: *mut u32) -> i32;
    fn GetProcessTimes(
        process: *mut c_void,
        creation: *mut u64,
        exit: *mut u64,
        kernel: *mut u64,
        user: *mut u64,
    ) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

/// What is known of process `pid` ([`liveness`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// No process runs under the pid (or it has exited and only a handle keeps it).
    Gone,
    /// A process runs under the pid, started at this time (a FILETIME: 100 ns since 1601), or at a
    /// time this process may not read (`None`: one it may not open).
    Running(Option<u64>),
}

/// Whether process `pid` runs, and when it started. A process this one may not open is taken to be
/// running, so nothing of it is ever removed.
pub fn liveness(pid: u32) -> Liveness {
    // SAFETY: a plain kernel32 call; the handle is closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(ERROR_INVALID_PARAMETER) => Liveness::Gone,
            _ => Liveness::Running(None),
        };
    }
    let (mut code, mut creation, mut other) = (0u32, 0u64, [0u64; 3]);
    // SAFETY: an open process handle and valid out pointers (a FILETIME is two u32s, as a u64).
    let (exited, started) = unsafe {
        let exited = GetExitCodeProcess(process, &mut code) != 0 && code != STILL_ACTIVE;
        let [exit, kernel, user] = &mut other;
        let started = GetProcessTimes(process, &mut creation, exit, kernel, user) != 0;
        CloseHandle(process);
        (exited, started)
    };
    if exited {
        Liveness::Gone
    } else {
        Liveness::Running(started.then_some(creation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_runs_and_a_finished_one_is_gone() {
        let me = liveness(std::process::id());
        assert!(matches!(me, Liveness::Running(Some(t)) if t > 0), "{me:?}");
        // Stable: the same process reads the same start time.
        assert_eq!(liveness(std::process::id()), me);
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .unwrap();
        let pid = child.id();
        child.wait().unwrap();
        // Its handle is closed with `child`: then no process runs under the pid (unless reused at
        // once, which a fresh pid almost never is).
        drop(child);
        assert_eq!(liveness(pid), Liveness::Gone);
        // Pids are multiples of 4: this one is never a process.
        assert_eq!(liveness(4_000_000_001), Liveness::Gone);
    }
}
