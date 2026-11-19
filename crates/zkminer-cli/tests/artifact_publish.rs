//! `zkminer artifact publish --password-fd N` on the real binary: the descriptor is taken and
//! checked at the start of `main`, before the async runtime or anything else opens descriptors of
//! its own, so a number the caller did not open (or a socket, or a terminal) is a clean error and
//! never names, reads or closes one of the process's own.

#![cfg(target_os = "linux")]

use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), "[chain]\nchain_id = 31337\n").unwrap();
        // The smallest WASM module: the input check passes, so a run that gets past the descriptor
        // stops at the RPC (refused by the network guard: nothing connects).
        std::fs::write(dir.path().join("b.wasm"), b"\0asm\x01\0\0\0").unwrap();
        std::fs::write(dir.path().join("ks.json"), "{}").unwrap();
        Env { dir }
    }

    /// `publish … --password-fd fd`, with `setup` run in the child before exec.
    fn publish(&self, fd: &str, setup: impl FnMut() -> std::io::Result<()> + Send + Sync + 'static) -> Output {
        let p = |n: &str| self.dir.path().join(n);
        let mut c = Command::new(env!("CARGO_BIN_EXE_zkminer"));
        c.arg("-c")
            .arg(p("config.toml"))
            .args(["artifact", "publish"])
            .arg(p("b.wasm"))
            .args(["--kind", "builder", "--rpc-url", "http://127.0.0.1:1", "--chain-id", "31337", "--keystore"])
            .arg(p("ks.json"))
            .args(["--password-fd", fd, "--yes"])
            .env("HOME", self.dir.path())
            .stdin(Stdio::null());
        // SAFETY: the callers' setups only call dup2.
        unsafe {
            c.pre_exec(setup);
        }
        c.output().unwrap()
    }
}

/// In the child before exec: `raw` at fd 5, inherited (`dup2` onto itself, when `raw` already is
/// 5, would leave it close-on-exec).
fn at_fd_5(raw: i32) -> std::io::Result<()> {
    // SAFETY: async-signal-safe calls on descriptors this child holds.
    unsafe {
        if raw != 5 && libc::dup2(raw, 5) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::fcntl(5, libc::F_SETFD, 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn clean_failure(out: &Output, want: &str) {
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains(want), "{err}");
    for crash in ["panicked", "IO Safety", "aborting", "fatal runtime error"] {
        assert!(!err.contains(crash), "{err}");
    }
}

#[test]
fn a_password_fd_the_caller_did_not_open_is_refused_before_anything_runs() {
    let env = Env::new();
    // Not open in the child (closed there before exec, whatever the test harness inherited): each
    // used to name one of the runtime's own descriptors (an abort, a hang, EAGAIN, a worker panic).
    for fd in [3, 4, 6, 7] {
        let out = env.publish(&fd.to_string(), move || {
            // SAFETY: async-signal-safe.
            unsafe { libc::close(fd) };
            Ok(())
        });
        clean_failure(&out, "not an open descriptor");
    }
    for fd in ["0", "2"] {
        clean_failure(&env.publish(fd, || Ok(())), "3 or above");
    }
}

#[test]
fn a_password_fd_must_be_a_pipe_or_a_file() {
    let env = Env::new();
    // A socket at fd 5.
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let raw = a.as_raw_fd();
    clean_failure(&env.publish("5", move || at_fd_5(raw)), "socket");
    // A character device at fd 5.
    let null = std::fs::File::open("/dev/null").unwrap();
    let raw = null.as_raw_fd();
    clean_failure(&env.publish("5", move || at_fd_5(raw)), "terminal or another device");
    // A regular file at fd 5 is taken: the run goes on, to the RPC (refused by the network guard
    // outside developer mode, before anything connects).
    std::fs::write(env.dir.path().join("pw"), "pw\n").unwrap();
    let pw = std::fs::File::open(env.dir.path().join("pw")).unwrap();
    let raw = pw.as_raw_fd();
    clean_failure(&env.publish("5", move || at_fd_5(raw)), "refused by the network guard");
}
