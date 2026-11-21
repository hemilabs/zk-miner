//! Capabilities: the sandbox profiles clear their sets ([`clear_capability_sets`], from
//! [`crate::restrict_self`]), and the inline workers drop every one, bounding set included, first
//! thing in `main` ([`drop_all_capabilities`]).
//!
//! A process of an unprivileged uid holds none, and all of this changes nothing for it. A miner
//! started as root (`sudo zkminer run`, a mining distribution, a container with `--privileged`)
//! would otherwise hand its workers, and a guest that escaped its executor in one, the host:
//! `CAP_SYS_MODULE` (a kernel module is ring-0 code), `CAP_SYS_BOOT`, `CAP_SYS_TIME`,
//! `CAP_SYS_RAWIO`, `CAP_NET_ADMIN`, `CAP_SYS_NICE` and the rest. The seccomp filters refuse the
//! syscalls behind the worst of them too ([`crate::netdeny`]); without the capabilities the kernel
//! refuses them as well.

use crate::SandboxError;

/// `struct __user_cap_header_struct` / `__user_cap_data_struct` (version 3: two data words).
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}
#[repr(C)]
#[derive(Default, Clone, Copy, PartialEq, Eq)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
/// `CAP_SETPCAP`: needed to drop a capability from the bounding set.
const CAP_SETPCAP: u32 = 8;
/// The highest capability number there can be: the capability sets are two 32-bit words.
const CAP_MAX: u32 = 63;

/// The calling thread's capability sets, or `None` if `capget` fails.
fn cap_get() -> Option<[CapData; 2]> {
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: a version-3 header and two data words, as capget(2) requires.
    let r = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    (r == 0).then_some(data)
}

/// Clears the calling thread's effective, permitted and inheritable capability sets (and the
/// ambient set, which cannot outlive the permitted one). Lowering capabilities needs no privilege.
/// With `NO_NEW_PRIVS` and no `exec`, none can come back.
pub(crate) fn clear_capability_sets() -> Result<(), SandboxError> {
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let none = [CapData::default(); 2];
    // SAFETY: a version-3 header and two data words, as capset(2) requires; lowering capabilities
    // needs no privilege.
    if unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapHeader,
            none.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: an integer prctl. EINVAL before Linux 4.3, which has no ambient set to clear.
    unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    Ok(())
}

/// Whether the calling thread holds no capability (effective, permitted, inheritable).
pub fn capabilities_cleared() -> bool {
    cap_get().is_some_and(|data| data == [CapData::default(); 2])
}

/// The highest capability the running kernel knows (`/proc/sys/kernel/cap_last_cap`), or
/// [`CAP_MAX`] if it cannot be read (`PR_CAPBSET_DROP` of an unknown one fails with `EINVAL`).
fn last_cap() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n <= CAP_MAX)
        .unwrap_or(CAP_MAX)
}

/// Whether the real, effective or saved uid is 0.
fn any_uid_is_root() -> bool {
    let (mut r, mut e, mut s) = (0, 0, 0);
    // SAFETY: three valid uid_t pointers.
    let rc = unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
    // A failure cannot happen with valid pointers; count it as root, the cautious answer.
    rc != 0 || r == 0 || e == 0 || s == 0
}

/// Whether a `/proc/<pid>/task/<tid>/status` text shows any capability in the effective,
/// permitted, inheritable or ambient set. A missing or unreadable line counts as holding one (the
/// cautious answer: `CapAmb` is there since Linux 4.3, the others always).
pub(crate) fn status_holds_capabilities(status: &str) -> bool {
    ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
        .iter()
        .any(|key| {
            let value = status
                .lines()
                .find_map(|l| l.strip_prefix(key))
                .map(str::trim);
            !value.is_some_and(|v| u64::from_str_radix(v, 16) == Ok(0))
        })
}

/// The threads of this process that still hold a capability ([`status_holds_capabilities`]). A
/// thread that exited while being read is skipped.
pub(crate) fn threads_holding_capabilities() -> std::io::Result<Vec<String>> {
    let mut out = Vec::new();
    for task in std::fs::read_dir("/proc/self/task")? {
        let task = task?;
        let Ok(status) = std::fs::read_to_string(task.path().join("status")) else {
            continue;
        };
        if status_holds_capabilities(&status) {
            out.push(task.file_name().to_string_lossy().into_owned());
        }
    }
    Ok(out)
}

/// Drops every capability of this process, for good: the bounding set (where `CAP_SETPCAP` allows;
/// a process of an unprivileged uid has neither it nor anything to drop), then the ambient,
/// inheritable, permitted and effective sets. A process that held any capability, or runs with a
/// uid of 0, also gets `NO_NEW_PRIVS`, so no `exec` (of a setuid-root or file-capability binary,
/// or of anything as root) can give one back, whatever is left of the bounding set. Then it checks
/// that no thread holds any.
///
/// Capabilities belong to threads: call it while the process has one thread, before anything
/// starts another (a GPU runtime, a logger, an async runtime), so that every thread the process
/// ever has inherits the empty sets. The inline workers call it first thing in `main`, before
/// their confinement ([`crate::confine::confine_all_threads`]), which checks again. Idempotent,
/// and a no-op for an unprivileged process.
pub fn drop_all_capabilities() -> Result<(), SandboxError> {
    let caps = |what: String| SandboxError::Capabilities(what);
    let held =
        cap_get().ok_or_else(|| caps(format!("capget: {}", std::io::Error::last_os_error())))?;
    let privileged = held != [CapData::default(); 2] || any_uid_is_root();
    if held[0].effective & (1 << CAP_SETPCAP) != 0 {
        for cap in 0..=last_cap() {
            // SAFETY: an integer prctl.
            let rc = unsafe {
                libc::prctl(
                    libc::PR_CAPBSET_DROP,
                    cap as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            };
            let e = std::io::Error::last_os_error();
            // EINVAL: a capability this kernel does not know.
            if rc != 0 && e.raw_os_error() != Some(libc::EINVAL) {
                return Err(caps(format!(
                    "dropping capability {cap} from the bounding set: {e}"
                )));
            }
        }
    }
    clear_capability_sets()?;
    if privileged {
        // SAFETY: a plain prctl.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(caps(format!(
                "PR_SET_NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    if !capabilities_cleared() {
        return Err(caps("capget still shows a capability after capset".into()));
    }
    if let Some(tid) = threads_holding_capabilities()?.first() {
        return Err(caps(format!(
            "thread {tid} still holds a capability: drop them before the process starts threads"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "Name:\tzkminer-prove-r\nUmask:\t0022\nState:\tR (running)\n\
        Uid:\t1000\t1000\t1000\t1000\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n\
        CapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n\
        NoNewPrivs:\t1\nSeccomp:\t2\n";

    #[test]
    fn a_status_without_capabilities_holds_none() {
        // The bounding set is not a capability held: an unprivileged process keeps a full one.
        assert!(!status_holds_capabilities(STATUS));
    }

    #[test]
    fn any_set_with_a_capability_counts() {
        for key in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            let status = STATUS.replace(
                &format!("{key}:\t0000000000000000"),
                &format!("{key}:\t0000000000200000"),
            );
            assert_ne!(status, STATUS, "{key} not in the sample");
            assert!(status_holds_capabilities(&status), "{key}");
        }
    }

    #[test]
    fn a_missing_or_garbled_line_counts_as_holding_one() {
        let no_amb = STATUS.replace("CapAmb:\t0000000000000000\n", "");
        assert!(status_holds_capabilities(&no_amb));
        let garbled = STATUS.replace("CapEff:\t0000000000000000", "CapEff:\tzz");
        assert!(status_holds_capabilities(&garbled));
        assert!(status_holds_capabilities(""));
    }

    /// In a process of its own: the test harness has threads, and capabilities are per thread.
    /// The child drops everything, then reports what it sees; as an unprivileged user (CI) this
    /// checks that the drop is a harmless no-op, as root that it drops the lot.
    #[test]
    fn dropping_every_capability_leaves_none_on_any_thread() {
        // SAFETY: the child reads /proc, allocates and starts a thread, which glibc allows after
        // `fork` (its malloc resets its locks in the child); it leaves through `_exit`, with the
        // verdict as its exit code.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let code = match drop_all_capabilities() {
                Err(_) => 1,
                Ok(()) if !capabilities_cleared() => 2,
                Ok(()) if !threads_holding_capabilities().is_ok_and(|t| t.is_empty()) => 3,
                // Root, or anyone who held a capability, cannot get one back through `exec`.
                Ok(())
                    if any_uid_is_root()
                    // SAFETY: a getter prctl.
                    && unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1 =>
                {
                    4
                }
                // A second call changes nothing and still succeeds.
                Ok(()) if drop_all_capabilities().is_err() => 5,
                // A thread started afterwards inherits the empty sets.
                Ok(())
                    if !std::thread::spawn(capabilities_cleared)
                        .join()
                        .unwrap_or(false) =>
                {
                    6
                }
                Ok(()) => 0,
            };
            // SAFETY: leaving the child without running the harness's exit handlers.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waiting for the child just forked.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status {status:#x}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "see the codes in the child");
    }

    #[test]
    fn the_kernel_s_last_capability_is_read() {
        let last = last_cap();
        // CAP_AUDIT_READ (37) is in every kernel Landlock ABI 6 runs on.
        assert!((37..=CAP_MAX).contains(&last), "{last}");
    }
}
