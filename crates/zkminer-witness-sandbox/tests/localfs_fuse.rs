//! A FUSE filesystem within reach refuses every confinement, live: rclone mounts a local directory
//! (FUSE, served by rclone, as sshfs or gvfs would serve a remote one) under a temporary directory
//! that no confinement grants, and the inline worker's confinement, the supervised server's and a
//! sandbox profile's (`restrict_self`) all refuse to go on, naming the mount; once it is unmounted
//! they go through again. Mounted after a process confined itself, it ends that process (its mount
//! watch) and a supervised server (its supervisor's).
//!
//! In a test binary of its own: while the mount is up, every confinement on this host built from
//! this tree refuses, the other tests' included. Needs Landlock ABI >= 6, `/dev/fuse`, `rclone` and
//! `fusermount3` (else SKIPPED; Landlock is required with `ZKMINER_SANDBOX_TESTS_REQUIRED=1`).

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use zkminer_witness_sandbox::{landlock_abi, MIN_LANDLOCK_ABI};

const PROBE: &str = env!("CARGO_BIN_EXE_zkminer-witness-sandbox-probe");

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

fn probe(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(PROBE)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn a_fuse_mount_in_reach_refuses_every_confinement() {
    let abi = landlock_abi();
    if abi < MIN_LANDLOCK_ABI {
        if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
            panic!("Landlock ABI {abi} < {MIN_LANDLOCK_ABI}");
        }
        eprintln!("SKIPPED: Landlock ABI {abi} < {MIN_LANDLOCK_ABI}");
        return;
    }
    let (Some(rclone), Some(fusermount), true) = (
        find(&["rclone"]),
        find(&["fusermount3", "fusermount"]),
        Path::new("/dev/fuse").exists(),
    ) else {
        eprintln!("SKIPPED: needs rclone, fusermount3 and /dev/fuse");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    let point = dir.path().join("remote");
    let home = dir.path().join("home");
    let write = dir.path().join("write");
    for d in [&src, &point, &home, &write] {
        std::fs::create_dir(d).unwrap();
    }
    std::fs::write(src.join("file"), b"served by rclone\n").unwrap();
    let conf = dir.path().join("rclone.conf");
    let mount = || -> Option<Fuse> {
        let rclone = Command::new(&rclone)
            .arg("mount")
            .arg("--config")
            .arg(&conf)
            .arg(format!(":local:{}", src.display()))
            .arg(&point)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let fuse = Fuse {
            rclone,
            point: point.clone(),
            fusermount: fusermount.clone(),
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !mounted(&point) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        mounted(&point).then_some(fuse)
    };
    let Some(fuse) = mount() else {
        eprintln!("SKIPPED: rclone could not mount {}", point.display());
        return;
    };
    assert_eq!(
        std::fs::read_to_string(point.join("file")).unwrap(),
        "served by rclone\n"
    );
    let named = |out: &str| out.contains(&format!("{} (fuse.rclone", point.display()));

    // The inline worker's confinement: refused before anything is applied, naming the mount.
    let confined = [
        "confined".as_ref(),
        "--sockets".as_ref(),
        "none".as_ref(),
        "--home".as_ref(),
        home.as_os_str(),
        "--write".as_ref(),
        write.as_os_str(),
    ];
    let o = probe(&confined);
    let out = text(&o);
    eprintln!("{out}");
    assert!(
        out.lines()
            .any(|l| l.starts_with("CHECK confine FAIL") && named(l) && l.contains("FUSE")),
        "{out}"
    );
    assert_eq!(o.status.code(), Some(1), "{out}");

    // The supervised server's: the supervisor starts nothing.
    let socket = dir.path().join("server.sock");
    let o = probe(&[
        "supervised".as_ref(),
        socket.as_os_str(),
        home.as_os_str(),
        write.as_os_str(),
    ]);
    let out = text(&o);
    eprintln!("{out}");
    assert!(named(&out) && !out.contains("SERVER "), "{out}");
    assert_eq!(o.status.code(), Some(1), "{out}");

    // A sandbox profile's (the builder runner's), in restrict_self.
    let o = probe(&[
        "oom".as_ref(),
        "--profile".as_ref(),
        "builder_runner".as_ref(),
        "--bytes".as_ref(),
        "0".as_ref(),
    ]);
    let out = text(&o);
    eprintln!("{out}");
    assert!(out.starts_with("ERROR ") && named(&out), "{out}");
    assert_eq!(o.status.code(), Some(2), "{out}");

    // Unmounted, the confinement goes through (the probe then waits for the test's signal).
    drop(fuse);
    assert!(!mounted(&point));
    let mut child = Command::new(PROBE)
        .args(confined)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut out = String::new();
    for line in BufReader::new(child.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        out.push_str(&line);
        out.push('\n');
        if line.starts_with("CONFINED CHECKS DONE") || line.starts_with("CHECK confine FAIL") {
            break;
        }
    }
    // SAFETY: signalling the probe this test started.
    unsafe { libc::kill(child.id() as i32, libc::SIGUSR1) };
    let _ = child.wait();
    assert!(
        out.lines()
            .any(|l| l.starts_with("CHECK confine ok")
                && l.contains("no network filesystem in reach")),
        "{out}"
    );

    // Mounted after a process confined itself: its mount watch ends it (EXIT_NOT_LOCAL), and the
    // supervisor ends its server.
    let mut child = Command::new(PROBE)
        .args(confined)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    assert!(lines.any(|l| l.is_ok_and(|l| l.starts_with("CONFINED CHECKS DONE"))));
    let started = Instant::now();
    let fuse = mount().expect("mounted again");
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the probe outlived the mount"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    eprintln!("{err}");
    assert_eq!(
        status.code(),
        Some(zkminer_witness_sandbox::confine::EXIT_NOT_LOCAL),
        "{err}"
    );
    assert!(err.contains("mount table changed") && named(&err), "{err}");
    eprintln!(
        "WATCH ended the confined probe {:?} after the mount",
        started.elapsed()
    );
    drop(fuse);

    let socket = dir.path().join("server2.sock");
    let mut sup = Command::new(PROBE)
        .args([
            "supervised".as_ref(),
            socket.as_os_str(),
            home.as_os_str(),
            write.as_os_str(),
        ])
        .env("ZKMINER_PROBE_LINGER", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(sup.stdout.take().unwrap()).lines();
    assert!(lines.any(|l| l.is_ok_and(|l| l.starts_with("LISTENING"))));
    let mut conn = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    let mut answer = String::new();
    conn.read_to_string(&mut answer).unwrap();
    assert!(answer.ends_with("DONE\n"), "{answer}");
    let started = Instant::now();
    let fuse = mount().expect("mounted again");
    let status = loop {
        if let Some(status) = sup.try_wait().unwrap() {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the server outlived the mount"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut err = String::new();
    sup.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    eprintln!("{err}");
    // The supervisor answers with the server's end: SIGKILL.
    assert_eq!(status.code(), Some(128 + libc::SIGKILL), "{err}");
    assert!(
        err.contains("changed under sp1-gpu-server") && named(&err),
        "{err}"
    );
    eprintln!(
        "WATCH ended the supervised server {:?} after the mount",
        started.elapsed()
    );
    drop(fuse);
}
