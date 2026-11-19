//! Nothing a worker starts outlives it (`zkminer_prover::containment`).
//!
//! The mock worker's `MOCK_LURKER` starts a process that leaves the worker's process group and
//! session, which a confined worker cannot do (it is refused `setsid` and `setpgid`): only the
//! worker's own cgroup still holds it. Each test checks what ends it: the end of the worker's
//! handle, the death of the miner (the reaper), a filesystem that is not local appearing (the
//! miner's mount watch).
//!
//! Needs a cgroup of the worker's own: a delegated cgroup (run under
//! `systemd-run --user --scope -p Delegate=yes`) or the user's systemd manager (scopes). Without
//! either a test is SKIPPED, or fails with `ZKMINER_SANDBOX_TESTS_REQUIRED=1`. The mount-watch test
//! also needs rclone, fusermount3 and /dev/fuse, and holds its FUSE mount for a second at most.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zkminer_prover::worker::WorkerHandle;

const ROLE: &str = "ZKMINER_CONTAINMENT_TEST_ROLE";

fn mock() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock-worker"))
}

fn required() -> bool {
    std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some()
}

/// Running, not a zombie.
fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|st| {
            st.rsplit(')')
                .next()
                .and_then(|r| r.split_whitespace().next())
                .map(|s| s != "Z")
        })
        .unwrap_or(false)
}

fn dead_within(pid: i32, budget: Duration) -> bool {
    let until = Instant::now() + budget;
    while alive(pid) {
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

fn read_pid(file: &Path) -> i32 {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(pid) = std::fs::read_to_string(file)
            .ok()
            .and_then(|s| s.trim().parse().ok())
        {
            return pid;
        }
        assert!(Instant::now() < until, "no pid in {}", file.display());
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn cgroup_of(pid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn session_of(pid: i32) -> i32 {
    // SAFETY: getsid of a pid.
    unsafe { libc::getsid(pid) }
}

/// A mock worker that started a lurker; `None` (after cleaning up) if the worker got no cgroup of
/// its own on this host.
fn spawn_with_lurker(dir: &Path) -> Option<(WorkerHandle, i32)> {
    let file = dir.join("lurker.pid");
    let env = HashMap::from([
        ("MOCK_BACKEND".to_string(), "mock".to_string()),
        ("MOCK_LURKER".to_string(), file.display().to_string()),
    ]);
    let handle = WorkerHandle::spawn("mock", &mock(), &env).expect("spawn the mock worker");
    let worker = handle.pid() as i32;
    let lurker = read_pid(&file);
    let cg = cgroup_of(worker);
    let leaf = cg.rsplit('/').next().unwrap_or("");
    if !leaf.starts_with("zkminer-") {
        // SAFETY: kill of the lurker this test started.
        unsafe { libc::kill(lurker, libc::SIGKILL) };
        assert!(
            !required(),
            "the worker is in no cgroup of its own ({cg}): neither a delegated cgroup nor the \
             user's systemd manager"
        );
        eprintln!("SKIPPED: the worker is in no cgroup of its own ({cg})");
        return None;
    }
    assert!(alive(lurker));
    assert_eq!(
        cgroup_of(lurker),
        cg,
        "the lurker is in the worker's cgroup"
    );
    assert_ne!(
        session_of(lurker),
        session_of(worker),
        "the lurker left the worker's session and process group"
    );
    eprintln!("worker {worker} and lurker {lurker} in {cg}");
    Some((handle, lurker))
}

/// Runs this test binary's `test` alone in a child process with `ROLE=role`.
fn run_role(test: &str, role: &str, out: &Path) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(ROLE, role)
        .env("ZKMINER_CONTAINMENT_TEST_OUT", out)
        .stdin(Stdio::null())
        .status()
        .unwrap()
}

#[test]
fn what_a_worker_started_ends_with_its_handle() {
    if std::env::var_os(ROLE).is_some() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let Some((handle, lurker)) = spawn_with_lurker(dir.path()) else {
        return;
    };
    drop(handle);
    assert!(
        dead_within(lurker, Duration::from_secs(5)),
        "a process the worker started outlived the worker's handle"
    );
}

#[test]
fn the_reaper_ends_the_workers_of_a_miner_that_dies() {
    if std::env::var(ROLE).as_deref() == Ok("dying-miner") {
        let out = PathBuf::from(std::env::var_os("ZKMINER_CONTAINMENT_TEST_OUT").unwrap());
        let Some((handle, lurker)) = spawn_with_lurker(out.parent().unwrap()) else {
            std::fs::write(&out, "skipped").unwrap();
            return;
        };
        std::fs::write(&out, format!("{} {lurker}", handle.pid())).unwrap();
        std::mem::forget(handle);
        // SAFETY: the miner dies at once, as SIGKILLed or OOM-killed.
        unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
        unreachable!();
    }
    if std::env::var_os(ROLE).is_some() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("pids");
    let st = run_role(
        "the_reaper_ends_the_workers_of_a_miner_that_dies",
        "dying-miner",
        &out,
    );
    let text = std::fs::read_to_string(&out).unwrap_or_default();
    if text == "skipped" {
        return;
    }
    assert_eq!(st.signal(), Some(libc::SIGKILL), "the miner role: {st:?}");
    let pids: Vec<i32> = text
        .split_whitespace()
        .map(|p| p.parse().unwrap())
        .collect();
    let (worker, lurker) = (pids[0], pids[1]);
    assert!(
        dead_within(worker, Duration::from_secs(5)),
        "the worker outlived the miner"
    );
    assert!(
        dead_within(lurker, Duration::from_secs(5)),
        "a process the worker started outlived the miner"
    );
}

fn find(names: &[&str]) -> Option<PathBuf> {
    names
        .iter()
        .flat_map(|n| ["/usr/bin", "/usr/local/bin", "/bin"].map(|d| Path::new(d).join(n)))
        .find(|p| p.exists())
}

fn mounted(point: &Path) -> bool {
    let needle = format!(" {} ", point.display());
    std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_default()
        .lines()
        .any(|l| l.contains(&needle) && l.contains(" - fuse.rclone "))
}

/// rclone, unmounted and stopped when dropped.
struct Fuse {
    rclone: Child,
    point: PathBuf,
    fusermount: PathBuf,
}

impl Drop for Fuse {
    fn drop(&mut self) {
        let _ = Command::new(&self.fusermount)
            .arg("-u")
            .arg(&self.point)
            .status();
        let _ = self.rclone.kill();
        let _ = self.rclone.wait();
    }
}

#[test]
fn a_filesystem_that_is_not_local_ends_every_worker() {
    if std::env::var(ROLE).as_deref() == Ok("mount") {
        let (Some(rclone), Some(fusermount), true) = (
            find(&["rclone"]),
            find(&["fusermount3", "fusermount"]),
            Path::new("/dev/fuse").exists(),
        ) else {
            eprintln!("SKIPPED: needs rclone, fusermount3 and /dev/fuse");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let Some((handle, lurker)) = spawn_with_lurker(dir.path()) else {
            return;
        };
        let worker = handle.pid() as i32;
        let src = dir.path().join("src");
        let point = dir.path().join("remote");
        std::fs::create_dir(&src).unwrap();
        std::fs::create_dir(&point).unwrap();
        let conf = dir.path().join("rclone.conf");
        let fuse = Fuse {
            rclone: Command::new(&rclone)
                .arg("mount")
                .arg("--config")
                .arg(&conf)
                .arg(format!(":local:{}", src.display()))
                .arg(&point)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
            point: point.clone(),
            fusermount,
        };
        let until = Instant::now() + Duration::from_secs(30);
        while !mounted(&point) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(mounted(&point), "rclone did not mount {}", point.display());
        let at = Instant::now();
        let worker_gone = dead_within(worker, Duration::from_secs(1));
        let lurker_gone = dead_within(lurker, Duration::from_secs(1));
        let took = at.elapsed();
        drop(fuse);
        assert!(!mounted(&point));
        assert!(worker_gone, "the worker outlived a FUSE mount");
        assert!(
            lurker_gone,
            "a process the worker started outlived a FUSE mount"
        );
        eprintln!("worker and lurker killed {took:?} after the mount was seen");
        drop(handle);
        return;
    }
    if std::env::var_os(ROLE).is_some() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let st = run_role(
        "a_filesystem_that_is_not_local_ends_every_worker",
        "mount",
        &dir.path().join("out"),
    );
    assert!(st.success(), "the mount role: {st:?}");
}
