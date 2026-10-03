//! Does dropping a dead worker actually reap its forked GPU-helper grandchild?
//!
//! `WorkerHandle::drop` used to `break` out of its wait loop on `Ok(Some(_))` — i.e.
//! exactly when the worker had ALREADY exited — and so skipped `force_kill_group()` in
//! the single most common case, because the death-and-respawn path drops the handle
//! BECAUSE the worker died. SP1's `sp1-gpu-server` (a 236MB CUDA process) then outlived
//! it as an orphan holding its VRAM, unreachable afterwards because the stored PID is
//! zeroed before the drop. Measured in production: 10.3GB still held after exit, which
//! starved the next run into CUDA OOM panics.
//!
//! This reproduces the SHAPE with plain processes: a parent that forks a long-lived
//! child into its own process group, then exits immediately — leaving the child an
//! orphan exactly as the real worker does.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Truly running — NOT a zombie.
///
/// `kill(pid, 0)` alone returns 0 for a zombie, which is precisely the bug that made the
/// first version of this fix sleep 2s on every drop. A test that used it would be blind
/// in the same way, so read the process state from /proc instead.
#[cfg(unix)]
fn alive(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        // field 3 is the state char; Z = zombie.
        Ok(st) => st
            .rsplit(')')
            .next()
            .and_then(|rest| rest.split_whitespace().next())
            .map(|state| state != "Z")
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Spawn a parent in its own process group that forks a grandchild and exits at once,
/// mirroring a worker that dies while its GPU helper keeps running.
/// Returns (parent_pid, grandchild_pid).
#[cfg(unix)]
fn spawn_parent_that_orphans_a_child() -> (i32, i32) {
    use std::os::unix::process::CommandExt;

    let pidfile = std::env::temp_dir().join(format!(
        "orphan-test-{}-{:?}.pid",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&pidfile);

    // The grandchild writes its pid then sleeps past the test; the parent exits at once,
    // orphaning it — the same shape as a worker dying while its GPU helper runs on.
    // `$$` inside a subshell is still the PARENT's pid, so capture the background
    // child's real pid with `$!` instead.
    let script = format!(
        "sleep 300 & echo $! > '{pf}'; exit 0",
        pf = pidfile.display()
    );

    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(&script)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            // Same as the real worker: become a process-group leader so the group can
            // be signalled as a unit.
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn parent");
    let parent_pid = child.id() as i32;

    // Wait for the grandchild to report itself.
    let start = Instant::now();
    let gc = loop {
        if let Ok(s) = std::fs::read_to_string(&pidfile) {
            if let Ok(p) = s.trim().parse::<i32>() {
                break p;
            }
        }
        assert!(start.elapsed() < Duration::from_secs(10), "grandchild never started");
        std::thread::sleep(Duration::from_millis(50));
    };
    // Reap the parent so it is a true orphan situation.
    let _ = child.wait();
    let _ = std::fs::remove_file(&pidfile);
    (parent_pid, gc)
}

/// The grandchild must inherit the parent's process group, which is what makes a single
/// `kill(-pgid)` able to reap it. If this fails, group-killing cannot work at all.
#[cfg(unix)]
#[test]
fn a_forked_helper_inherits_the_workers_process_group() {
    let (parent_pid, gc) = spawn_parent_that_orphans_a_child();
    let gc_pgid = unsafe { libc::getpgid(gc) };
    assert_eq!(
        gc_pgid, parent_pid,
        "the helper must share the worker's process group, or kill(-pgid) cannot reach it"
    );
    unsafe {
        libc::kill(-parent_pid, libc::SIGKILL);
    }
}

/// THE REGRESSION. The parent is already dead; a group kill must still reap the orphan.
/// This is the case the old `Ok(Some(_)) => break` skipped.
#[cfg(unix)]
#[test]
fn group_kill_reaps_an_orphan_whose_leader_already_exited() {
    let (parent_pid, gc) = spawn_parent_that_orphans_a_child();

    assert!(!alive(parent_pid), "parent should already have exited");
    assert!(alive(gc), "the orphaned helper should still be running");

    // What the fixed Drop does: group-kill even though the leader is gone.
    unsafe {
        libc::kill(-(parent_pid), libc::SIGKILL);
    }

    let start = Instant::now();
    while alive(gc) && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !alive(gc),
        "the orphaned helper survived a group kill — this is the 10.3GB VRAM leak"
    );
}

/// The guard the fix relies on: an EMPTY process group must be distinguishable from one
/// that still has members, because `kill(-pid, SIGKILL)` on an empty group whose number
/// has been recycled would signal an unrelated group — and every worker is a group
/// leader, so a collision takes out a whole worker group mid-proof.
#[cfg(unix)]
#[test]
fn an_empty_group_is_distinguishable_from_one_with_survivors() {
    // Group WITH a survivor: probe must succeed.
    let (parent_pid, gc) = spawn_parent_that_orphans_a_child();
    assert_eq!(
        unsafe { libc::kill(-parent_pid, 0) },
        0,
        "a group with a surviving member must probe as present, or the fix skips the kill \
         it needs to make"
    );
    unsafe { libc::kill(-parent_pid, libc::SIGKILL) };
    let start = Instant::now();
    while alive(gc) && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!alive(gc), "survivor should be gone");

    // Group with NO members: probe must fail, so the fix declines to signal a number
    // that may since have been recycled.
    let start = Instant::now();
    while unsafe { libc::kill(-parent_pid, 0) } == 0 && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_ne!(
        unsafe { libc::kill(-parent_pid, 0) },
        0,
        "an empty group must NOT probe as present — that guard is what stops a recycled \
         pgid being SIGKILLed"
    );
}

/// `kill(pid, 0)` is blind to a zombie. This pins the fact that forced the probe in
/// `WorkerHandle::drop` to be `waitid(WNOWAIT)` rather than a signal-0 liveness check:
/// with signal-0 the wait loop never observes exit and burns its full 2s timeout, which
/// pushed `shutdown_all` past the 10s cap its callers impose and made the orphan warning
/// fire on every clean shutdown.
#[cfg(unix)]
#[test]
fn signal_zero_cannot_see_a_zombie_but_waitid_can() {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("exit 0")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let pid = child.id() as i32;

    // Let it exit, without reaping.
    let start = Instant::now();
    while alive(pid) && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }

    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        0,
        "signal 0 still SUCCEEDS for a zombie — this is why it cannot be used to detect exit"
    );

    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut si,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    assert_eq!(r, 0, "waitid should succeed");
    assert_ne!(
        unsafe { si.si_pid() },
        0,
        "waitid(WNOHANG|WNOWAIT) MUST observe the exit that signal 0 missed"
    );
    // WNOWAIT left it reapable, so the pid is still pinned.
    let _ = child.wait();
}
