//! The parent side of the one-shot sandboxed witness execute (plan §5.2 step 6, §10.1, §10.2).
//!
//! [`run_witness_execute`] runs the risc0 CPU worker in its `--witness-execute` mode inside a fresh
//! cgroup of its own: the worker restricts itself (Landlock, seccomp, no new privileges) before it
//! reads anything, executes the guest on `prefix ‖ W` at each requested po2 with the seed the miner
//! derived, and answers with one [`WitnessExecuteResponse`]. Everything the worker can do wrong — run
//! out of time or memory, exit with a typed failure, die of a signal, or write something that is not
//! the response the request calls for — is a distinct [`WitnessExecError`].
//!
//! # The caller must spawn from a long-lived thread
//! `PR_SET_PDEATHSIG`, which [`prepare_command`] arms so the worker dies with the miner, fires when
//! the *thread* that spawned the child exits, not the process. [`run_witness_execute`] spawns the
//! worker on the calling thread and blocks that thread until the worker is gone, so a synchronous
//! call is safe on any thread that is not torn down under it. Keep it that way: call it from a
//! dedicated `std::thread` (or one the caller owns for the miner's life), and never split the spawn
//! from the wait onto a thread a pool may retire, such as a tokio `spawn_blocking` thread (those exit
//! after 10 s idle), or the worker is SIGKILLed mid-execution.

use std::io::{Cursor, Read, Write};
use std::os::fd::BorrowedFd;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zkminer_prover_protocol::{
    read_message, write_message, WitnessExecuteFailure, WitnessExecuteRequest,
    WitnessExecuteResponse, EXECUTE_JOURNAL_MAX_BYTES, GUEST_EXIT_HALTED, WITNESS_EXECUTE_ARG,
    WITNESS_EXECUTE_W_FD,
};
pub use zkminer_witness_sandbox::CgroupSpec;
use zkminer_witness_sandbox::{prepare_command, Cgroup, SandboxError};

/// How much of the end of the worker's stderr an error carries. Diagnostic only: it can hold guest
/// text, so nothing may branch on it.
pub const LOG_TAIL_BYTES: usize = 16 * 1024;

/// The largest response read. A real one is at most seven po2s (16..=22) of a 32 KiB journal each.
const MAX_RESPONSE_BYTES: usize = 4 << 20;

/// How a sandboxed witness execute failed.
#[derive(Debug, thiserror::Error)]
pub enum WitnessExecError {
    /// The request does not fit in a frame.
    #[error("witness execute request: {0}")]
    Request(String),
    /// The cgroup or the launch hook could not be set up; nothing ran.
    #[error("witness execute sandbox: {0}")]
    Sandbox(#[from] SandboxError),
    #[error("spawning the witness execute worker: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("waiting for the witness execute worker: {0}")]
    Wait(#[source] std::io::Error),
    /// The worker did not finish within the timeout; its cgroup was killed.
    #[error("the witness execute worker did not finish within {after:?}; its cgroup was killed")]
    Timeout { after: Duration, log_tail: String },
    /// The kernel killed the worker's cgroup at its `memory.max`.
    #[error(
        "the witness execute worker ran out of its {memory_max}-byte memory.max and was killed"
    )]
    OomKilled { memory_max: u64, log_tail: String },
    /// The worker exited with a non-zero code: a [`WitnessExecuteFailure`] when it is one of
    /// theirs (an uncaught panic is 101, a launch failure 127).
    #[error("the witness execute worker exited with code {code} ({failure:?})")]
    Exit {
        code: i32,
        failure: Option<WitnessExecuteFailure>,
        log_tail: String,
    },
    /// The worker died of a signal that was not the cgroup's OOM kill or the timeout's.
    #[error("the witness execute worker was killed by signal {signal}")]
    Signaled { signal: i32, log_tail: String },
    /// The worker exited 0, but its stdout is not exactly one response that fits the request.
    #[error("the witness execute worker's output is malformed: {reason}")]
    MalformedOutput { reason: String, log_tail: String },
}

impl WitnessExecError {
    /// The end of the worker's stderr, where the error comes from a run of it.
    pub fn log_tail(&self) -> Option<&str> {
        match self {
            Self::Timeout { log_tail, .. }
            | Self::OomKilled { log_tail, .. }
            | Self::Exit { log_tail, .. }
            | Self::Signaled { log_tail, .. }
            | Self::MalformedOutput { log_tail, .. } => Some(log_tail),
            _ => None,
        }
    }
}

/// Run one sandboxed witness execute and return its response.
///
/// - `binary`: the risc0 CPU worker (`zkminer-prove-risc0-cpu`), run with [`WITNESS_EXECUTE_ARG`].
/// - `cgroup_root`: the delegated directory per-job cgroups go in
///   (`zkminer_witness_sandbox::delegated_root`); a cgroup named `spec.name` is created there with
///   `spec`'s limits, the worker joins it before `exec`, and it is killed and removed before this
///   returns. Its `memory.max` should be charged against the dispatcher's host-RAM reservation.
/// - `req`: written to the worker's fd 0 as one frame.
/// - `w_fd`: `W`, placed at the worker's fd [`WITNESS_EXECUTE_W_FD`]: a regular file opened
///   read-only, or a memfd sealed against writing, growing and shrinking (the worker refuses any
///   other). It must stay open until this returns.
/// - `timeout`: wall clock from the spawn; past it the cgroup is killed (`cgroup.kill`).
///
/// The worker gets fds 0 (request pipe), 1 (response pipe), 2 (log pipe) and 3 (`W`) and nothing
/// else, an empty environment (it sets `RISC0_KECCAK_PO2` itself, from the request), and `/` as its
/// working directory.
///
/// Spawn from a long-lived thread: see the module docs.
pub fn run_witness_execute(
    binary: &Path,
    cgroup_root: &Path,
    spec: CgroupSpec,
    req: &WitnessExecuteRequest,
    w_fd: BorrowedFd,
    timeout: Duration,
) -> Result<WitnessExecuteResponse, WitnessExecError> {
    let mut frame = Vec::new();
    write_message(&mut frame, req).map_err(|e| WitnessExecError::Request(e.to_string()))?;
    let memory_max = spec.memory_max;
    let cgroup = Cgroup::create(cgroup_root, &spec)?;
    let run = run_in(&cgroup, binary, frame, w_fd, timeout);
    // Read before the cgroup goes.
    let oom_killed = cgroup.oom_killed();
    let memory_peak = cgroup.memory_peak();
    if let Err(e) = cgroup.remove() {
        tracing::warn!("witness execute: removing its cgroup: {e}");
    }
    let finished = run?;
    tracing::debug!(
        "witness execute: {:?} after {:.2}s, cgroup memory.peak {memory_peak:?}",
        finished.status,
        finished.elapsed.as_secs_f64()
    );
    let log_tail = finished.log_tail;
    if finished.timed_out {
        return Err(WitnessExecError::Timeout {
            after: timeout,
            log_tail,
        });
    }
    if oom_killed {
        return Err(WitnessExecError::OomKilled {
            memory_max,
            log_tail,
        });
    }
    match finished.status.code() {
        Some(0) => parse_response(req, &finished.stdout, finished.stdout_overflowed)
            .map_err(|reason| WitnessExecError::MalformedOutput { reason, log_tail }),
        Some(code) => Err(WitnessExecError::Exit {
            code,
            failure: WitnessExecuteFailure::from_code(code),
            log_tail,
        }),
        None => Err(WitnessExecError::Signaled {
            signal: finished.status.signal().unwrap_or(0),
            log_tail,
        }),
    }
}

/// What one run of the worker left behind.
struct Finished {
    status: ExitStatus,
    elapsed: Duration,
    timed_out: bool,
    stdout: Vec<u8>,
    stdout_overflowed: bool,
    log_tail: String,
}

fn run_in(
    cgroup: &Cgroup,
    binary: &Path,
    frame: Vec<u8>,
    w_fd: BorrowedFd,
    timeout: Duration,
) -> Result<Finished, WitnessExecError> {
    let mut cmd = Command::new(binary);
    cmd.arg(WITNESS_EXECUTE_ARG)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // fds 0-2 are std's pipes (dup2'ed before the hook runs); the hook maps targets >= 3 only.
    prepare_command(&mut cmd, cgroup, &[(w_fd, WITNESS_EXECUTE_W_FD)])?;
    let started = Instant::now();
    let mut child = cmd.spawn().map_err(WitnessExecError::Spawn)?;
    // The hook holds an fd to `cgroup.procs`.
    drop(cmd);

    let mut stdin = child.stdin.take().expect("stdin is piped");
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    // A worker that dies early makes this fail with EPIPE: its status says why.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&frame);
    });
    let reader = std::thread::spawn(move || read_capped(&mut stdout, MAX_RESPONSE_BYTES));
    let logger = std::thread::spawn(move || read_tail(&mut stderr, LOG_TAIL_BYTES));

    let deadline = started + timeout;
    let mut timed_out = false;
    let mut poll = Duration::from_millis(1);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {}
            Err(e) => {
                let _ = cgroup.kill();
                let _ = child.wait();
                break Err(WitnessExecError::Wait(e));
            }
        }
        let now = Instant::now();
        if now >= deadline {
            timed_out = true;
            // Every task in the job's cgroup, whatever it has become.
            if let Err(e) = cgroup.kill() {
                tracing::warn!("witness execute: cgroup.kill: {e}");
                let _ = child.kill();
            }
            break child.wait().map_err(WitnessExecError::Wait);
        }
        std::thread::sleep(poll.min(deadline - now));
        poll = (poll * 2).min(Duration::from_millis(25));
    };
    let elapsed = started.elapsed();
    // Anything left in the cgroup could hold a pipe open and keep the threads below waiting: the
    // worker cannot fork, but this does not rely on it.
    let _ = cgroup.kill();
    let _ = writer.join();
    let (stdout, stdout_overflowed) = reader.join().unwrap_or_default();
    let log_tail = logger.join().unwrap_or_default();
    Ok(Finished {
        status: status?,
        elapsed,
        timed_out,
        stdout,
        stdout_overflowed,
        log_tail,
    })
}

/// All of `r`, keeping at most `cap` bytes (and whether there was more): never stops reading, so the
/// writer never blocks on a full pipe.
fn read_capped(r: &mut impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut overflowed = false;
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let room = cap.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
                overflowed |= n > room;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    (kept, overflowed)
}

/// The last `cap` bytes of `r`, as lossy UTF-8.
fn read_tail(r: &mut impl Read, cap: usize) -> String {
    let mut tail: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                tail.extend_from_slice(&buf[..n]);
                if tail.len() > 2 * cap {
                    tail.drain(..tail.len() - cap);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    if tail.len() > cap {
        tail.drain(..tail.len() - cap);
    }
    String::from_utf8_lossy(&tail).into_owned()
}

/// The response in `stdout`: exactly one frame, and one that answers `req`.
fn parse_response(
    req: &WitnessExecuteRequest,
    stdout: &[u8],
    overflowed: bool,
) -> Result<WitnessExecuteResponse, String> {
    if overflowed {
        return Err(format!("more than {MAX_RESPONSE_BYTES} bytes on stdout"));
    }
    let mut cursor = Cursor::new(stdout);
    let resp: WitnessExecuteResponse =
        read_message(&mut cursor).map_err(|e| format!("not a response frame: {e}"))?;
    let rest = stdout.len() as u64 - cursor.position();
    if rest != 0 {
        return Err(format!("{rest} bytes after the response"));
    }
    validate_response(req, &resp)?;
    Ok(resp)
}

/// Whether `resp` is a response the worker can have given to `req`: a result per po2, in order, up to
/// and including the first that did not halt with code 0 (and only then fewer than requested); each
/// journal carried exactly when it fits the cap, and hashing to its hash; some cycles each.
/// The longest `sdk_version` / `worker_version` a response may name.
const MAX_BUILD_FIELD_BYTES: usize = 64;

/// A build field a bundle may record: short, and only letters, digits and ` .+-_` (the response
/// comes from a process that ran a requester's guest, and the bundle keeps no free text of it).
fn build_field_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_BUILD_FIELD_BYTES
        && s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'+' | b'-' | b'_'))
}

fn validate_response(
    req: &WitnessExecuteRequest,
    resp: &WitnessExecuteResponse,
) -> Result<(), String> {
    if !build_field_ok(&resp.sdk_version) || !build_field_ok(&resp.worker_version) {
        return Err("the response names no usable executor build".to_string());
    }
    if resp.results.is_empty() || resp.results.len() > req.po2s.len() {
        return Err(format!(
            "{} results for {} po2s",
            resp.results.len(),
            req.po2s.len()
        ));
    }
    let last = resp.results.len() - 1;
    for (i, r) in resp.results.iter().enumerate() {
        if r.po2 != req.po2s[i] {
            return Err(format!(
                "result {i} is for po2 {}, not {}",
                r.po2, req.po2s[i]
            ));
        }
        let halted_zero = r.exit_kind == GUEST_EXIT_HALTED && r.exit_code == 0;
        if !halted_zero && i != last {
            return Err(format!(
                "execution went on after po2 {}, which did not halt with code 0",
                r.po2
            ));
        }
        if halted_zero && i == last && resp.results.len() < req.po2s.len() {
            return Err(format!(
                "execution stopped after po2 {}, which halted with code 0",
                r.po2
            ));
        }
        let fits = r.journal_len as usize <= EXECUTE_JOURNAL_MAX_BYTES;
        if fits && r.journal.len() != r.journal_len as usize {
            return Err(format!(
                "po2 {}: a {}-byte journal carried as {} bytes",
                r.po2,
                r.journal_len,
                r.journal.len()
            ));
        }
        if !fits && !r.journal.is_empty() {
            return Err(format!("po2 {}: a journal over the cap was carried", r.po2));
        }
        if fits && <[u8; 32]>::from(Sha256::digest(&r.journal)) != r.journal_sha256 {
            return Err(format!(
                "po2 {}: the journal does not hash to its hash",
                r.po2
            ));
        }
        // Every run is at least one segment (padded to the power of two that holds it).
        if r.cycles == 0 {
            return Err(format!("po2 {}: no cycles", r.po2));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkminer_prover_protocol::{WitnessExecutePo2, GUEST_EXIT_PAUSED};

    fn request(po2s: &[u8]) -> WitnessExecuteRequest {
        WitnessExecuteRequest {
            elf: vec![],
            prefix: vec![],
            w_len: 0,
            input_sha256: [0; 32],
            sys_rand_seed: [0; 32],
            po2s: po2s.to_vec(),
            keccak_po2: 17,
            max_cycles: None,
        }
    }

    fn result(po2: u8, journal: &[u8]) -> WitnessExecutePo2 {
        WitnessExecutePo2 {
            po2,
            cycles: 1 << po2,
            journal: journal.to_vec(),
            journal_len: journal.len() as u32,
            journal_sha256: Sha256::digest(journal).into(),
            exit_kind: GUEST_EXIT_HALTED,
            exit_code: 0,
            segment_bytes: 1,
            peak_host_bytes: 1,
        }
    }

    fn check(req: &WitnessExecuteRequest, results: Vec<WitnessExecutePo2>) -> Result<(), String> {
        validate_response(
            req,
            &WitnessExecuteResponse {
                image_id: [0; 32],
                results,
                sdk_version: "risc0-zkvm 3.1.0".into(),
                worker_version: "0.1.0".into(),
            },
        )
    }

    #[test]
    fn a_response_names_a_plain_executor_build() {
        let req = request(&[16]);
        let with = |sdk: &str, worker: &str| {
            validate_response(
                &req,
                &WitnessExecuteResponse {
                    image_id: [0; 32],
                    results: vec![result(16, b"j")],
                    sdk_version: sdk.into(),
                    worker_version: worker.into(),
                },
            )
        };
        assert!(with("risc0-zkvm 3.1.0", "0.1.0").is_ok());
        assert!(with("", "0.1.0").is_err());
        assert!(with("risc0-zkvm 3.1.0", "0.1.0\nPAGE: x").is_err());
        assert!(with(&"a".repeat(MAX_BUILD_FIELD_BYTES + 1), "0.1.0").is_err());
    }

    #[test]
    fn a_response_answers_its_request_po2_by_po2() {
        let req = request(&[16, 20]);
        assert!(check(&req, vec![result(16, b"j"), result(20, b"j")]).is_ok());
        // Missing, extra, reordered or empty.
        assert!(check(&req, vec![result(16, b"j")]).is_err());
        assert!(check(&req, vec![]).is_err());
        assert!(check(&req, vec![result(20, b"j"), result(16, b"j")]).is_err());
        assert!(check(
            &req,
            vec![result(16, b"j"), result(20, b"j"), result(22, b"j")]
        )
        .is_err());
        // It may stop early only after a run that did not halt with 0, which is then the last.
        let mut paused = result(16, b"");
        paused.exit_kind = GUEST_EXIT_PAUSED;
        assert!(check(&req, vec![paused.clone()]).is_ok());
        assert!(check(&req, vec![paused, result(20, b"j")]).is_err());
        let mut halted_one = result(16, b"");
        halted_one.exit_code = 1;
        assert!(check(&req, vec![halted_one]).is_ok());
    }

    #[test]
    fn a_journal_is_carried_exactly_when_it_fits_and_hashes_to_its_hash() {
        let req = request(&[16]);
        let mut r = result(16, b"journal");
        r.journal_sha256[0] ^= 1;
        assert!(check(&req, vec![r]).is_err(), "wrong hash");
        let mut r = result(16, b"journal");
        r.journal.pop();
        assert!(check(&req, vec![r]).is_err(), "short");
        // Over the cap: length and hash only.
        let mut r = result(16, b"");
        r.journal_len = EXECUTE_JOURNAL_MAX_BYTES as u32 + 1;
        r.journal_sha256 = [7; 32];
        assert!(check(&req, vec![r.clone()]).is_ok());
        r.journal = vec![0; 3];
        assert!(check(&req, vec![r]).is_err(), "carried over the cap");
        let mut r = result(16, b"j");
        r.cycles = 0;
        assert!(check(&req, vec![r]).is_err(), "no segment");
    }

    #[test]
    fn stdout_must_be_exactly_one_frame() {
        let req = request(&[16]);
        let resp = WitnessExecuteResponse {
            image_id: [1; 32],
            results: vec![result(16, b"j")],
            sdk_version: "risc0-zkvm 3.1.0".into(),
            worker_version: "0.1.0".into(),
        };
        let mut frame = Vec::new();
        write_message(&mut frame, &resp).unwrap();
        assert_eq!(parse_response(&req, &frame, false).unwrap(), resp);
        assert!(parse_response(&req, &frame, true).is_err(), "overflowed");
        let mut extra = frame.clone();
        extra.push(0);
        assert!(parse_response(&req, &extra, false)
            .unwrap_err()
            .contains("after the response"));
        assert!(parse_response(&req, &frame[..frame.len() - 1], false).is_err());
        assert!(parse_response(&req, b"", false).is_err());
        assert!(parse_response(&req, b"garbage!", false).is_err());
    }

    #[test]
    fn pipes_are_drained_whatever_they_hold() {
        let data = vec![5u8; 100_000];
        let (kept, over) = read_capped(&mut &data[..], 10);
        assert_eq!((kept.len(), over), (10, true));
        let (kept, over) = read_capped(&mut &data[..], data.len());
        assert_eq!((kept, over), (data.clone(), false));
        let text: Vec<u8> = (0..50_000u32)
            .flat_map(|i| format!("{i}\n").into_bytes())
            .collect();
        let tail = read_tail(&mut &text[..], 12);
        assert_eq!(tail, "49998\n49999\n");
    }
}
