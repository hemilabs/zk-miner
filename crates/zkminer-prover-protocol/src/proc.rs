//! Running a child process under a wall-clock bound.
//!
//! Every prover worker shells out to something it does not control — `nvidia-smi`,
//! `sp1-gpu-server --version` — and `Command::output()` waits for all of them forever. That is not a theoretical hazard here:
//!
//!   * `nvidia-smi` blocks in the driver (often in uninterruptible sleep) after an Xid, a
//!     bus fall-off, an ECC remap, or while a 25 GB CUDA context is torn down — i.e. exactly
//!     on the sick hosts the probes exist to detect.
//!   * `sp1-gpu-server --version` loads a 236 MB binary and resolves `libcudart.so.12`.
//!
//! Not every such fork in the workspace routes through here yet: the `rocm-smi` and
//! `nvidia-smi` calls in `zkminer-prove-risc0` are still unbounded. `discovery.rs` and the
//! benchmark-cache fingerprint now route through here.
//!
//! Both are called from inside the Hello handshake, which the host caps at 10s and enforces
//! by SIGKILLing the worker — and the handshake runs on the single process-wide thread that
//! forks every worker (that thread exists because `PR_SET_PDEATHSIG` is thread-scoped). One
//! unbounded fork there parks every backend's spawn and respawn for the life of the miner.
//!
//! This module lives in the protocol crate only because it is the one dependency the host
//! and all the worker binaries already share.

use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The host's cap on the Hello handshake: a worker that has not answered by then is
/// SIGKILLed (`WorkerHandle::handshake`).
///
/// It lives here, rather than in the host, because the WORKERS are the ones that have to fit
/// inside it — everything a worker does before replying to Hello is spending this budget, and
/// a worker cannot assert that it fits against a constant it cannot see. `zkminer-prove-sp1`
/// asserts exactly that.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many times to try spawning before giving up, when the failure looks transient.
const SPAWN_ATTEMPTS: u32 = 3;

/// Pause between spawn attempts. The conditions being waited out (a file being written, a
/// fork failing under pressure) clear in milliseconds or not at all.
const SPAWN_RETRY_DELAY: Duration = Duration::from_millis(50);

/// How long to wait for the drainer threads once the child is gone. On the fast path they are
/// already finished and this costs nothing; the budget only bites when a grandchild inherited
/// the pipe, which no honest `--version` or `nvidia-smi` does.
const DRAIN_JOIN_BUDGET: Duration = Duration::from_millis(200);

/// How long to spend reaping a child we have just SIGKILLed.
///
/// SIGKILL does not land while the target is in uninterruptible sleep — a GPU helper stuck
/// in a driver ioctl, or paging in from a stalled mount, stays unreapable for as long as
/// that I/O takes. An unbounded `wait()` here would be the very wedge this module prevents,
/// so the reap is best-effort.
///
/// Be clear about what that costs, because it is not just a PID: in the D-state case the child
/// is still ALIVE, holding whatever it holds (a CUDA context, a 236 MB image), and the drainer
/// thread blocked on its pipe never finishes either. Each abandonment is a thread, a pipe fd
/// and that process until the kernel lets the signal land. Callers that run this repeatedly
/// must therefore stop calling it after repeated failures rather than sampling forever — see
/// the sampler's consecutive-failure cap.
const REAP_BUDGET: Duration = Duration::from_millis(200);

/// The bounded tail this runner can add beyond `timeout`, worst case.
///
/// Exists so a caller that must fit inside someone else's deadline can assert against the real
/// number instead of a guess. The SP1 worker's handshake budget test does exactly that: before
/// this existed it compared two constants and could not fail when the overhead grew.
pub fn max_overhead() -> Duration {
    DRAIN_JOIN_BUDGET
        + REAP_BUDGET
        + SPAWN_RETRY_DELAY * (SPAWN_ATTEMPTS - 1)
        // one poll interval of granularity, plus the drain-join poll
        + Duration::from_millis(20)
        + Duration::from_millis(2)
}

/// What became of the child.
#[derive(Debug)]
pub enum Outcome {
    /// Ran to completion inside the budget.
    Ran {
        success: bool,
        /// Captured stderr. The cap bounds BYTES READ, not the resulting `String`: invalid
        /// UTF-8 is replaced lossily, and U+FFFD is three bytes per bad byte, so a 64 KiB cap
        /// can yield a larger string. Bounded either way, which is what matters.
        stderr: String,
    },
    /// Still running when the budget expired; it has been SIGKILLed (best-effort reaped).
    ///
    /// Carries whatever stderr arrived before we gave up: a child that misbehaves is exactly
    /// the one whose output is worth reading, so discarding it here would throw away the
    /// evidence in the only case where the child did something wrong.
    TimedOut { stderr: String },
    /// Could not be spawned. `transient` distinguishes a property of the binary (ENOENT,
    /// ENOEXEC, EACCES — a retry cannot change it) from a momentary condition (ETXTBSY while
    /// something rewrites the file, EAGAIN/ENOMEM when the fork itself fails under pressure).
    SpawnFailed { err: io::Error, transient: bool },
    /// We could not find out. Distinct from `SpawnFailed` because the child DID start: the
    /// wait failed. The realistic cause is `ECHILD`, which happens when something else
    /// reaped it — most plausibly a `SIGCHLD` disposition of `SIG_IGN` inherited from a
    /// parent, which auto-reaps every child and makes every `waitpid` return `ECHILD`.
    ///
    /// This MUST NOT be folded into `SpawnFailed`: callers decline a backend permanently on
    /// a spawn failure, and "somebody reaped my child" says nothing about whether the
    /// backend works.
    Unsettled(io::Error),
}

impl Outcome {
    /// A short phrase naming the outcome, for assertion and log messages.
    pub fn describe(&self) -> String {
        match self {
            Outcome::Ran { success, stderr } => {
                format!("Ran{{success:{success}, stderr:{:?}}}", stderr.trim())
            }
            Outcome::TimedOut { stderr } => {
                format!("TimedOut{{stderr:{:?}}}", stderr.trim())
            }
            Outcome::SpawnFailed { err, transient } => {
                format!("SpawnFailed{{{err}, transient:{transient}}}")
            }
            Outcome::Unsettled(e) => format!("Unsettled({e})"),
        }
    }
}

/// Is this spawn failure a momentary condition rather than a verdict about the binary?
///
/// Callers disable a backend for the life of the process on a permanent spawn failure, so
/// this distinction decides whether a transient condition costs every job until restart.
///
/// * `ETXTBSY` — the file is open for writing somewhere. An SDK replacing a prebuilt server
///   with a fresh download looks exactly like this.
/// * `EAGAIN` / `ENOMEM` — the fork failed, not the exec. On a box whose provers have been
///   measured at ~25 GB RSS, memory pressure is the normal condition.
/// * `EINTR` — a signal arrived. Says nothing at all.
pub fn is_transient_spawn_error(err: &io::Error) -> bool {
    #[cfg(unix)]
    {
        // Spelled numerically so this crate needs no libc dependency. These values are fixed
        // by the Linux ABI and identical on x86_64 and aarch64 (asm-generic/errno-base.h).
        const EINTR: i32 = 4;
        const EAGAIN: i32 = 11;
        const ENOMEM: i32 = 12;
        const ENFILE: i32 = 23;
        const EMFILE: i32 = 24;
        const ETXTBSY: i32 = 26;
        matches!(
            err.raw_os_error(),
            Some(EINTR) | Some(EAGAIN) | Some(ENOMEM) | Some(ENFILE) | Some(EMFILE) | Some(ETXTBSY)
        )
    }
    // NOT shared with Windows, where `raw_os_error()` is a Win32 code and the mapping is
    // actively wrong: 11 is ERROR_BAD_FORMAT (a permanent property of the binary, which this
    // would call transient) and 8 is ERROR_NOT_ENOUGH_MEMORY (genuinely transient, which this
    // would call permanent). No Windows caller exists today, but this crate is cross-compiled
    // there, so the honest answer for an unknown platform is "not known to be transient".
    #[cfg(not(unix))]
    {
        let _ = err;
        false
    }
}

/// Owns a spawned child so that NO exit path can leave it running.
///
/// Every early return and every unwind (`thread::spawn` can panic under pid/memory pressure,
/// and a poisoned mutex can panic too) would otherwise drop the `Child` — and
/// `std::process::Child::drop` neither kills nor reaps. On the SP1 handshake path that meant
/// abandoning a live `sp1-gpu-server --version` in the worker's own process group; in the
/// power sampler it meant abandoning an `nvidia-smi`.
struct ChildGuard(Option<std::process::Child>);

/// `ECHILD`, the one error `try_wait` realistically returns here.
const ECHILD: i32 = 10;

impl ChildGuard {
    fn get(&mut self) -> &mut std::process::Child {
        self.0.as_mut().expect("child taken")
    }

    /// Give up ownership once the child is known to be dead and reaped.
    fn released(mut self) {
        self.0 = None;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            reap_briefly(&mut child);
        }
    }
}

/// Run `cmd` under a wall-clock bound, capturing at most `stderr_cap` bytes of stderr.
///
/// The bound is `timeout` plus a bounded tail: up to `DRAIN_JOIN_BUDGET` waiting for the
/// capture threads, up to `REAP_BUDGET` reaping a killed child, and up to
/// `(SPAWN_ATTEMPTS - 1) * SPAWN_RETRY_DELAY` of spawn retries. `max_overhead()` names the sum,
/// and the SP1 worker's handshake-budget test asserts against it rather than guessing.
///
/// Deliberate details, each of which was a defect in one of the call sites this replaces:
///
/// * **stdout goes to `/dev/null`.** No caller reads it, and a pipe nobody drains is how a
///   chatty child deadlocks a parent waiting for it to exit. Callers that need stdout should
///   use [`output_with_timeout_capturing_stdout`].
/// * **stderr is captured through a shared buffer, not a channel, and the reader is waited
///   for.** The reader appends as it reads, so a reader that is slow or blocked still
///   surrenders what it already has. A channel that only sends at EOF yields an EMPTY string
///   instead of a partial one — and for a loader failure (`libcudart.so.12: cannot open shared
///   object file`) that string is the whole evidence, so losing it turns a provable decline
///   into "advertised, wedges later".
/// * **past the cap the reader keeps draining into a sink.** Dropping the pipe instead would
///   SIGPIPE the child, turning what would have been a clean exit into a signal death and
///   changing `success` for reasons that have nothing to do with the child.
/// * **on timeout only the child pid is signalled, never the group.** A worker shares its
///   group with its own process (`setpgid(0,0)` made the WORKER the leader), so
///   `kill(-pgid, SIGKILL)` here would kill the caller and its siblings.
pub fn output_with_timeout(cmd: &mut Command, timeout: Duration, stderr_cap: u64) -> Outcome {
    run(cmd, timeout, stderr_cap, None)
}

/// As [`output_with_timeout`], but stdout is captured too and returned alongside the outcome.
/// For probes that parse stdout (`nvidia-smi --query-gpu=…`).
pub fn output_with_timeout_capturing_stdout(
    cmd: &mut Command,
    timeout: Duration,
    cap: u64,
) -> (Outcome, String) {
    let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let outcome = run(cmd, timeout, cap, Some(sink.clone()));
    // `snapshot`, not `unwrap_or_default()`: a poisoned mutex must still yield its contents.
    // Returning an empty stdout here is how `detect_gpu` concludes "no GPU", which on the SP1
    // path is a permanent decline.
    let stdout = snapshot(&sink);
    (outcome, stdout)
}

fn run(
    cmd: &mut Command,
    timeout: Duration,
    cap: u64,
    stdout_sink: Option<std::sync::Arc<std::sync::Mutex<Vec<u8>>>>,
) -> Outcome {
    let deadline = Instant::now() + timeout;

    cmd.stdin(Stdio::null()).stderr(Stdio::piped());
    match &stdout_sink {
        Some(_) => cmd.stdout(Stdio::piped()),
        None => cmd.stdout(Stdio::null()),
    };

    // Retry a transient spawn failure, inside the same budget.
    let mut child = None;
    let mut last_err = None;
    for attempt in 0..SPAWN_ATTEMPTS {
        match cmd.spawn() {
            Ok(c) => {
                child = Some(c);
                break;
            }
            Err(e) => {
                let transient = is_transient_spawn_error(&e);
                last_err = Some(e);
                if !transient
                    || attempt + 1 == SPAWN_ATTEMPTS
                    || Instant::now() + SPAWN_RETRY_DELAY >= deadline
                {
                    break;
                }
                std::thread::sleep(SPAWN_RETRY_DELAY);
            }
        }
    }
    let mut guard = match child {
        Some(c) => ChildGuard(Some(c)),
        None => {
            let err = last_err.unwrap_or_else(|| io::Error::other("spawn failed"));
            let transient = is_transient_spawn_error(&err);
            return Outcome::SpawnFailed { err, transient };
        }
    };

    let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut drainers = Vec::new();
    if let Some(pipe) = guard.get().stderr.take() {
        drainers.extend(spawn_drainer("stderr", pipe, stderr_buf.clone(), cap));
    }
    if let (Some(sink), Some(pipe)) = (stdout_sink.as_ref(), guard.get().stdout.take()) {
        drainers.extend(spawn_drainer("stdout", pipe, sink.clone(), cap));
    }

    loop {
        match guard.get().try_wait() {
            Ok(Some(status)) => {
                // The child is gone, so its ends of the pipes are closed and the drainers see
                // EOF immediately. WAIT FOR THEM — bounded — rather than sleeping a fixed
                // grace: the flat sleep this replaces was both a tax on every success (200ms
                // on every handshake probe and every power sample) and no guarantee at all,
                // since a thread that had not been scheduled yet still handed back an EMPTY
                // capture. Losing that string turns a provable decline into "advertised,
                // wedges later", which is the whole reason stderr is captured.
                await_drainers(&drainers, DRAIN_JOIN_BUDGET);
                let stderr = snapshot(&stderr_buf);
                guard.released();
                return Outcome::Ran {
                    success: status.success(),
                    stderr,
                };
            }
            // The child started but the wait failed; `guard` kills and reaps it on the way out
            // rather than leaving it running.
            Err(e) => {
                // `ECHILD` means the child is ALREADY REAPED — something else collected it (an
                // inherited `SIGCHLD = SIG_IGN` auto-reaps every child). Its pid number is
                // therefore free, and `ChildGuard::drop` would `kill` it: the exact
                // signal-a-recycled-pid hazard the rest of this change set removes. Release the
                // guard without signalling, and still hand back what the drainers captured.
                if e.raw_os_error() == Some(ECHILD) {
                    await_drainers(&drainers, DRAIN_JOIN_BUDGET);
                    let _ = snapshot(&stderr_buf);
                    guard.released();
                }
                return Outcome::Unsettled(e);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = guard.get().kill();
                    // Bounded: SIGKILL does not land on a process in uninterruptible sleep,
                    // so an unbounded `wait()` here would be the very wedge this prevents. An
                    // abandoned zombie costs one PID; `live_group_members` skips zombies and
                    // `reap_orphaned_gpu_servers` skips any pid whose ppid is not 1, so it
                    // raises no false alarm either.
                    reap_briefly(guard.get());
                    await_drainers(&drainers, DRAIN_JOIN_BUDGET);
                    let stderr = snapshot(&stderr_buf);
                    guard.released();
                    return Outcome::TimedOut { stderr };
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// Wait for the drainer threads to finish, up to `budget`.
///
/// Returns as soon as they are all done, which on the fast path is immediately: the child is
/// dead, so the pipes are at EOF. The budget only matters when a GRANDCHILD inherited the write
/// end, in which case the thread never finishes and is abandoned.
fn await_drainers(handles: &[std::thread::JoinHandle<()>], budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        if handles.iter().all(|h| h.is_finished()) {
            return;
        }
        if Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Read what the drainer has appended so far.
///
/// A POISONED mutex still yields its contents, via `into_inner`. `unwrap_or_default()` here
/// would hand back an empty string — bit for bit the failure the shared buffer replaced, where
/// losing the loader-error text turns a provable decline into "advertised, wedges later". The
/// drainer only panics if the OS refuses it a thread, which is precisely when we most want
/// whatever it managed to read.
fn snapshot(buf: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> String {
    let bytes = match buf.lock() {
        Ok(b) => b.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Read `pipe` into `buf` up to `cap` bytes, then keep draining into a sink so the writer is
/// never SIGPIPEd.
///
/// Returns the handle so the caller can wait for it; returns NOTHING if the thread could not be
/// created. That case is the point of using `Builder`: bare `thread::spawn` PANICS when the OS
/// refuses a thread (EAGAIN, pid limit), which is exactly the pressure the spawn retry above
/// exists to survive — and the unwind would carry out of the Hello handshake and kill the
/// worker, or silently kill the power sampler. Without a drainer we drop the pipe instead, which
/// can cost the child a SIGPIPE; that is a worse capture but a far better failure than a panic.
fn spawn_drainer(
    what: &str,
    pipe: impl io::Read + Send + 'static,
    buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    cap: u64,
) -> Option<std::thread::JoinHandle<()>> {
    let name = format!("proc-drain-{what}");
    match std::thread::Builder::new().name(name).spawn(move || {
        let mut pipe = pipe;
        {
            let mut taken = Read::take(&mut pipe, cap);
            let mut chunk = [0u8; 4096];
            loop {
                match taken.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        // Append through the poison too. `if let Ok(..)` silently discarded every
                        // chunk once the mutex was poisoned, so the reader kept draining the pipe
                        // into nothing and the caller got an empty capture — the evidence-loss
                        // failure this buffer replaced.
                        match buf.lock() {
                            Ok(mut b) => b.extend_from_slice(&chunk[..n]),
                            Err(poisoned) => {
                                poisoned.into_inner().extend_from_slice(&chunk[..n]);
                            }
                        }
                    }
                    // A signal mid-read is not the end of the output; `io::copy` retries this
                    // internally and so must we, or a stray signal truncates the evidence.
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        }
        // Past the cap: discard the rest rather than closing the pipe under the writer, which
        // would SIGPIPE it and flip its exit status for a reason of ours.
        let _ = io::copy(&mut pipe, &mut io::sink());
    }) {
        Ok(h) => Some(h),
        Err(e) => {
            // Nothing to log to from this crate; the caller sees an empty capture.
            let _ = e;
            None
        }
    }
}

/// Best-effort reap, bounded. See `REAP_BUDGET`.
fn reap_briefly(child: &mut std::process::Child) {
    let deadline = Instant::now() + REAP_BUDGET;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => {
                if Instant::now() >= deadline {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// The one lock these tests hold, for two races that were both observed (not imagined)
    /// while this code lived in `zkminer-prove-sp1`:
    ///
    /// 1. **ETXTBSY** (~1 run in 8). libtest runs tests on several threads, and a sibling's
    ///    fork holds a writable fd to a freshly written script across its own exec window —
    ///    exactly the condition ETXTBSY reports. The runner retries it (it is transient in
    ///    production too), but a test that needs the retry to pass is a test nobody believes.
    /// 2. **env mutation** (~1 run in 40). A spawned `/bin/sh` inherits whatever PATH is
    ///    current, so a sibling's `set_var` made `sleep` unfindable and a script that should
    ///    have hung exited instead — turning `TimedOut` into `Ran`.
    ///
    /// Taken ONCE per test and held for the whole body: the write and the exec must be in the
    /// same critical section to close either race.
    fn test_lock() -> &'static std::sync::Mutex<()> {
        static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| std::sync::Mutex::new(()))
    }

    struct Script(PathBuf);

    impl Script {
        fn dir_for(tag: &str) -> PathBuf {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::env::temp_dir().join(format!("zkproc-{tag}-{}-{nanos}", std::process::id()))
        }

        fn new(tag: &str, body: &str) -> Self {
            let dir = Self::dir_for(tag);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("fake-server");
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn dir(&self) -> &Path {
            self.0.parent().unwrap()
        }
    }

    impl Drop for Script {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.dir());
        }
    }

    fn run(sh: &Script, timeout: Duration) -> Outcome {
        output_with_timeout(&mut Command::new(sh.path()), timeout, 64 * 1024)
    }

    /// A child that never returns must be abandoned on a schedule WE choose. With
    /// `Command::output()` this does not fail, it HANGS — and in production that hang is on
    /// the process-wide spawner thread, after which no backend can spawn or respawn.
    #[test]
    fn a_hanging_child_times_out_on_our_budget() {
        let _g = test_lock().lock().unwrap();
        let sh = Script::new("hang", "sleep 60");
        let budget = Duration::from_millis(300);
        let t0 = Instant::now();
        let got = run(&sh, budget);
        let dt = t0.elapsed();
        assert!(
            matches!(got, Outcome::TimedOut { .. }),
            "expected a timeout, got {}",
            got.describe()
        );
        // Tight on purpose: a loose bound (the old test allowed 16x) passes for a mis-signed
        // deadline, a raised poll interval, or a grace wait raised to seconds.
        assert!(
            dt < budget * 4,
            "the budget must bound the wait: {dt:?} against a {budget:?} budget"
        );
    }

    /// Timing out is not enough — the child must actually die, or a 236 MB GPU helper keeps
    /// its VRAM and is adopted as an orphan on the next start. The script keeps touching a
    /// file, so continued life is observable without needing its pid.
    #[test]
    fn a_timed_out_child_is_killed() {
        let _g = test_lock().lock().unwrap();
        // ABSOLUTE path: `touch ./beat` resolves against the TEST process's cwd, so a
        // relative path made this assertion compare None to None (vacuous) and littered the
        // repo with a stray file.
        let dir = Script::dir_for("beat");
        std::fs::create_dir_all(&dir).unwrap();
        let beat = dir.join("beat");
        let sh = Script::new(
            "killed",
            &format!(
                "while true; do touch '{}'; sleep 0.05; done",
                beat.display()
            ),
        );
        assert!(matches!(
            run(&sh, Duration::from_millis(300)),
            Outcome::TimedOut { .. }
        ));
        std::thread::sleep(Duration::from_millis(200));
        let first = std::fs::metadata(&beat).and_then(|m| m.modified()).expect(
            "the script must have produced a heartbeat — without one this test \
                     cannot tell 'killed' from 'never ran'",
        );
        std::thread::sleep(Duration::from_millis(400));
        let second = std::fs::metadata(&beat).and_then(|m| m.modified()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(first, second, "the child kept running after we gave up");
    }

    /// stdout must not be captured when the caller does not want it: a pipe nobody drains is
    /// how a chatty child deadlocks a parent waiting for it to exit.
    #[test]
    fn a_chatty_stdout_does_not_hang_us() {
        let _g = test_lock().lock().unwrap();
        let sh = Script::new(
            "chatty-out",
            "i=0; while [ $i -lt 2048 ]; do printf '%0512d' $i; i=$((i+1)); done; exit 0",
        );
        match run(&sh, Duration::from_secs(10)) {
            Outcome::Ran { success, .. } => assert!(success),
            other => panic!("a chatty stdout broke the run: {}", other.describe()),
        }
    }

    /// stderr IS captured, so it needs the same protection by other means: a draining reader
    /// and a byte cap.
    #[test]
    fn a_chatty_stderr_is_drained_and_capped() {
        let _g = test_lock().lock().unwrap();
        let sh = Script::new(
            "chatty-err",
            "i=0; while [ $i -lt 2048 ]; do printf '%0512d' $i >&2; i=$((i+1)); done; exit 1",
        );
        match output_with_timeout(&mut Command::new(sh.path()), Duration::from_secs(10), 4096) {
            Outcome::Ran { success, stderr } => {
                assert!(!success);
                assert!(
                    stderr.len() <= 4096,
                    "captured {} bytes, cap 4096",
                    stderr.len()
                );
                assert!(!stderr.is_empty(), "the cap must not discard the evidence");
            }
            other => panic!(
                "an undrained stderr pipe broke the run: {}",
                other.describe()
            ),
        }
    }

    /// Past the cap the reader keeps draining instead of closing the pipe. Closing it would
    /// SIGPIPE the child, turning a clean exit into a signal death — so `success` would flip
    /// for a reason that has nothing to do with the child.
    #[test]
    fn exceeding_the_cap_does_not_kill_the_child() {
        let _g = test_lock().lock().unwrap();
        // Writes far past the cap, then exits 0. With the pipe closed under it, `sh` dies of
        // SIGPIPE and `success` is false.
        let sh = Script::new(
            "cap-sigpipe",
            "i=0; while [ $i -lt 512 ]; do printf '%0512d' $i >&2; i=$((i+1)); done; exit 0",
        );
        match output_with_timeout(&mut Command::new(sh.path()), Duration::from_secs(10), 1024) {
            Outcome::Ran { success, stderr } => {
                assert!(
                    success,
                    "the child must still exit 0: a cap is our limit, not its problem"
                );
                assert!(stderr.len() <= 1024);
            }
            other => panic!("unexpected: {}", other.describe()),
        }
    }

    /// The captured text is the whole evidence for a loader failure, so it must arrive.
    #[test]
    fn stderr_reaches_the_caller_verbatim() {
        let _g = test_lock().lock().unwrap();
        let sh = Script::new(
            "loader",
            "echo 'error while loading shared libraries: libcudart.so.12: cannot open \
             shared object file' >&2; exit 127",
        );
        match run(&sh, Duration::from_secs(10)) {
            Outcome::Ran { success, stderr } => {
                assert!(!success);
                assert!(
                    stderr.contains("error while loading shared libraries")
                        && stderr.contains("libcudart.so.12"),
                    "a classifier downstream needs this text: {stderr:?}"
                );
            }
            other => panic!("unexpected: {}", other.describe()),
        }
    }

    /// stdout capture, for probes that parse it (`nvidia-smi --query-gpu=…`).
    #[test]
    fn stdout_is_returned_when_asked_for() {
        let _g = test_lock().lock().unwrap();
        let sh = Script::new("stdout", "echo 'NVIDIA GeForce RTX 4090'; exit 0");
        let (outcome, stdout) = output_with_timeout_capturing_stdout(
            &mut Command::new(sh.path()),
            Duration::from_secs(5),
            4096,
        );
        assert!(matches!(outcome, Outcome::Ran { success: true, .. }));
        assert_eq!(stdout.trim(), "NVIDIA GeForce RTX 4090");
    }

    #[test]
    fn a_healthy_child_is_fast_and_successful() {
        let _g = test_lock().lock().unwrap();
        let sh = Script::new("ok", "echo hi; exit 0");
        let t0 = Instant::now();
        let got = run(&sh, Duration::from_secs(5));
        assert!(
            matches!(got, Outcome::Ran { success: true, .. }),
            "got {}",
            got.describe()
        );
        // Tight on purpose. The version this replaced slept a flat 200ms after every exit
        // "to give the drainers a moment", so every handshake probe and every power sample paid
        // it; a one-second bound could not see that. A trivial child plus one 20ms poll is tens
        // of milliseconds.
        assert!(
            t0.elapsed() < Duration::from_millis(150),
            "the healthy path must not pay a fixed grace: took {:?}",
            t0.elapsed()
        );
    }

    /// A child that had to be killed is exactly the one whose output is worth reading, so the
    /// timeout verdict must carry what arrived before we gave up. Discarding it left
    /// `sp1_usability`'s timeout warning with no evidence in it at all.
    #[test]
    fn a_timed_out_child_still_surrenders_its_stderr() {
        let _g = test_lock().lock().unwrap();
        let sh = Script::new("talk-then-hang", "echo 'about to wedge' >&2; sleep 60");
        match run(&sh, Duration::from_millis(400)) {
            Outcome::TimedOut { stderr } => assert!(
                stderr.contains("about to wedge"),
                "the timeout must carry what the child said: {stderr:?}"
            ),
            other => panic!("expected a timeout, got {}", other.describe()),
        }
    }

    /// `max_overhead` is what a caller fitting inside someone else's deadline must budget for,
    /// so it has to actually bound the tail rather than being a decorative number.
    #[test]
    fn the_overhead_is_bounded_and_honest() {
        let _g = test_lock().lock().unwrap();
        let sh = Script::new("hang-overhead", "sleep 60");
        let budget = Duration::from_millis(200);
        let t0 = Instant::now();
        let got = run(&sh, budget);
        let dt = t0.elapsed();
        assert!(matches!(got, Outcome::TimedOut { .. }));
        assert!(
            dt <= budget + max_overhead(),
            "took {dt:?}, which exceeds the declared bound of {:?} + {:?}",
            budget,
            max_overhead()
        );
    }

    /// An absent binary is a PERMANENT spawn failure: callers decline on it, and that is
    /// correct. The classification is what keeps the decline from firing on a transient.
    #[test]
    fn an_absent_binary_is_a_permanent_spawn_failure() {
        let _g = test_lock().lock().unwrap();
        match output_with_timeout(
            &mut Command::new("/nonexistent/fake-server"),
            Duration::from_secs(3),
            1024,
        ) {
            Outcome::SpawnFailed { err, transient } => {
                assert_eq!(err.raw_os_error(), Some(2), "ENOENT");
                assert!(!transient, "ENOENT is a property of the binary");
            }
            other => panic!("expected a spawn failure, got {}", other.describe()),
        }
    }

    /// The transient classifier decides whether a momentary condition disables a backend for
    /// the life of the process. ETXTBSY is not hypothetical: it is what these tests hit.
    #[test]
    fn transient_and_permanent_spawn_errors_are_separated() {
        for errno in [
            26, /*ETXTBSY*/
            11, /*EAGAIN*/
            12, /*ENOMEM*/
            4,  /*EINTR*/
        ] {
            assert!(
                is_transient_spawn_error(&io::Error::from_raw_os_error(errno)),
                "errno {errno} must be transient — declining on it disables the backend"
            );
        }
        for errno in [
            2,  /*ENOENT*/
            8,  /*ENOEXEC*/
            13, /*EACCES*/
            1,  /*EPERM*/
        ] {
            assert!(
                !is_transient_spawn_error(&io::Error::from_raw_os_error(errno)),
                "errno {errno} is a property of the binary and must still decline"
            );
        }
        // ECHILD is deliberately absent: it cannot occur at SPAWN time. It occurs at WAIT
        // time, and is reported as `Unsettled` precisely so it cannot reach a decline.
        assert!(!is_transient_spawn_error(&io::Error::from_raw_os_error(10)));
    }

    /// `describe` is what assertion and log messages carry, so it must name the variant
    /// rather than collapse two of them — a message that says "a spawn failure" for both
    /// ENOENT and ETXTBSY cost one real debugging round here.
    #[test]
    fn describe_distinguishes_the_outcomes() {
        assert!(Outcome::TimedOut {
            stderr: String::new()
        }
        .describe()
        .contains("TimedOut"));
        assert!(Outcome::Unsettled(io::Error::from_raw_os_error(10))
            .describe()
            .contains("Unsettled"));
        let d = Outcome::SpawnFailed {
            err: io::Error::from_raw_os_error(26),
            transient: true,
        }
        .describe();
        assert!(d.contains("transient:true"), "{d}");
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;

    /// R1-g's ACTUAL property: a drainer that is still blocked must still surrender what it has
    /// already read.
    ///
    /// Every other stderr test uses a child that exits promptly, so EOF always arrives and a
    /// channel-at-EOF design would pass them all. This one has the child fork a grandchild that
    /// inherits the stderr write end and outlive it, so the pipe NEVER reaches EOF: the drainer
    /// blocks forever, `await_drainers` gives up on its budget, and the text has to come out of
    /// the shared buffer anyway. With the original `recv_timeout`-at-EOF channel this returns an
    /// empty string, and `sp1_usability` then advertises SP1 on a host it has just proved cannot
    /// run it.
    #[test]
    fn a_blocked_drainer_still_surrenders_what_it_read() {
        let dir = std::env::temp_dir().join(format!(
            "zkproc-blocked-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fake-server");
        // The grandchild holds fd 2 and sleeps; the child says its piece and exits at once.
        std::fs::write(
            &script,
            "#!/bin/sh\necho 'error while loading shared libraries: libcudart.so.12' >&2\n\
             sleep 30 &\nexit 127\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let t0 = Instant::now();
        let got = output_with_timeout(
            &mut Command::new(&script),
            Duration::from_secs(5),
            64 * 1024,
        );
        let dt = t0.elapsed();
        let _ = std::fs::remove_dir_all(&dir);

        match got {
            Outcome::Ran { success, stderr } => {
                assert!(!success, "the child exits 127");
                assert!(
                    stderr.contains("libcudart.so.12"),
                    "the evidence must survive a drainer that never sees EOF, got {stderr:?}"
                );
            }
            other => panic!("expected a completed run, got {}", other.describe()),
        }
        // And it must not wait for the grandchild: the join is bounded.
        assert!(
            dt < Duration::from_secs(2),
            "a grandchild holding the pipe must not extend the call: {dt:?}"
        );
    }

    /// The spawn-retry loop, driven by the real condition it exists for. Holding the executable
    /// open for writing makes every `execve` fail with ETXTBSY, so this exercises the retry path
    /// AND the classification that keeps a transient failure from permanently declining a
    /// backend.
    #[test]
    fn a_persistently_busy_executable_is_reported_transient() {
        let dir = std::env::temp_dir().join(format!(
            "zkproc-etxtbsy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fake-server");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // Hold it open for WRITING for the whole call: ETXTBSY on every attempt.
        let held = std::fs::OpenOptions::new()
            .write(true)
            .open(&script)
            .unwrap();

        let t0 = Instant::now();
        let got = output_with_timeout(&mut Command::new(&script), Duration::from_secs(5), 4096);
        let dt = t0.elapsed();
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);

        match got {
            Outcome::SpawnFailed { err, transient } => {
                assert_eq!(err.raw_os_error(), Some(26), "ETXTBSY");
                assert!(
                    transient,
                    "ETXTBSY must be transient: declining on it disables the backend for the \
                     life of the process, and the condition clears by itself"
                );
            }
            other => panic!("expected a spawn failure, got {}", other.describe()),
        }
        // It retried rather than giving up at once, and stayed inside the budget.
        assert!(
            dt >= SPAWN_RETRY_DELAY,
            "the retry loop did not run: returned in {dt:?}"
        );
        assert!(
            dt < Duration::from_secs(2),
            "retries must stay bounded: {dt:?}"
        );
    }
}
