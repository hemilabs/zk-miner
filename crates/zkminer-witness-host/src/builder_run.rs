//! One builder run (plan §5.2 step 5, §9, §10.1): the runner binary in a fresh job cgroup, its socket
//! registered with the broker, `W` streamed to a sink (the retention store's writer) in pieces of at
//! most 1 MiB and counted against `maxWitnessBytes`, then the outcome classified (§16).

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use alloy_primitives::B256;
use zkminer_witness::abi::{LOG_CAP_BYTES, W_CHUNK_BYTES};
use zkminer_witness::envelope::Limits;
use zkminer_witness::ipc::{decode_summary_pipe, BuilderSummary, SUMMARY_PIPE_MAX_BYTES};
use zkminer_witness::verdict::{builder_verdict, BuilderOutcome, SkipReason};
use zkminer_witness_broker::client::{job_socketpair, BrokerClient, JobRegistration, JobStats, RunnerCgroups};
use zkminer_witness_broker::egress::sanitize_log;
use zkminer_witness_sandbox::{prepare_command, Cgroup, CgroupSpec};

use crate::abort::AbortToken;
use crate::spawner::Spawner;

/// Where `W` goes as it streams (the store's `BundleWriter` in the miner).
pub trait WitnessSink: Send + 'static {
    fn write(&mut self, chunk: &[u8]) -> Result<(), String>;
}

/// An in-memory sink (tests and `simulate`).
#[derive(Default)]
pub struct VecSink(pub Vec<u8>);
impl WitnessSink for VecSink {
    fn write(&mut self, chunk: &[u8]) -> Result<(), String> {
        self.0.extend_from_slice(chunk);
        Ok(())
    }
}

/// Runner threads plus slack (the runner uses three; a fourth is spare).
pub const RUNNER_PIDS_MAX: u32 = 4;
/// Memory beyond the guest's linear-memory clamp for wasmtime, Cranelift and the runner itself.
pub const RUNNER_MEMORY_OVERHEAD: u64 = 768 << 20;
/// How long past the runner's own deadline the miner waits before killing it.
pub const OUTER_DEADLINE_GRACE: Duration = Duration::from_secs(3);
/// The diagnostic log kept by the miner (the runner already caps the guest's share at 64 KiB).
const MINER_LOG_CAP: usize = LOG_CAP_BYTES + 16 * 1024;

pub struct BuilderRun<'a> {
    pub binary: &'a Path,
    pub cgroup_root: &'a Path,
    pub job_key: B256,
    pub module: &'a [u8],
    pub context: &'a [u8],
    /// Effective (clamped) limits.
    pub limits: &'a Limits,
}

/// What a run produced. `w_bytes` were delivered to the sink; they are only valid when `verdict` is
/// `None`.
#[derive(Debug)]
pub struct BuilderRunResult {
    pub outcome: BuilderOutcome,
    pub verdict: Option<SkipReason>,
    pub summary: Option<BuilderSummary>,
    pub stats: Option<JobStats>,
    pub w_bytes: u64,
    /// The miner stopped reading because `W` passed `maxWitnessBytes`.
    pub w_overflow: bool,
    /// The abort token fired and the miner killed the runner's cgroup. The run is then judged the
    /// miner's own failure (`RunnerInternal`, never the caller's), but nothing about the job should
    /// be recorded: check this before `verdict`.
    pub aborted: bool,
    pub log: String,
    pub elapsed: Duration,
    /// The runner cgroup's `memory.peak` (module, compiled code and runner together), when the
    /// kernel reports it.
    pub memory_peak: Option<u64>,
}

struct Raw {
    exit: Option<i32>,
    signal: Option<i32>,
    oom_killed: bool,
    memory_peak: Option<u64>,
    wall_clock_hit: bool,
    aborted: bool,
    summary_bytes: Vec<u8>,
    log: Vec<u8>,
    w_bytes: u64,
    w_overflow: bool,
    sink_error: Option<String>,
    spawn_error: Option<String>,
    /// The broker's session ended while the runner ran, and the runner was killed with it.
    broker_gone: bool,
}

fn pipe() -> io::Result<(File, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills two fds that we then own.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (File::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// A sealed memfd holding `bytes` (read-only for the runner).
pub fn sealed_memfd(name: &str, bytes: &[u8]) -> io::Result<OwnedFd> {
    let cname = std::ffi::CString::new(name).map_err(|_| io::Error::other("NUL in memfd name"))?;
    // SAFETY: plain syscalls on a fd we own.
    let fd = unsafe { libc::memfd_create(cname.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut f = unsafe { File::from_raw_fd(fd) };
    f.write_all(bytes)?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedFd::from(f))
}

fn read_capped(mut r: File, cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => return out,
            Ok(n) => {
                let room = cap.saturating_sub(out.len());
                out.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
}

static RUN_SEQ: AtomicU64 = AtomicU64::new(0);

/// The runner's argv for `limits`.
pub fn runner_args(limits: &Limits) -> Vec<String> {
    vec![
        "--fuel".into(),
        limits.maxBuilderFuel.to_string(),
        "--memory-bytes".into(),
        limits.maxBuilderMemoryBytes.to_string(),
        "--wall-ms".into(),
        (u64::from(limits.maxBuilderSeconds) * 1000).to_string(),
        "--max-witness-bytes".into(),
        limits.maxWitnessBytes.to_string(),
        "--max-request-bytes".into(),
        limits.maxRequestBytes.to_string(),
        "--max-response-bytes".into(),
        limits.maxResponseBytes.to_string(),
    ]
}

/// The blocking core: spawn, stream, wait, kill on the outer deadline. `broker_fd` is the runner's end
/// of the job socket (already registered with the broker); the runner's cgroup is registered in
/// `runners` while it runs, so the end of the broker's session kills it.
#[allow(clippy::too_many_arguments)]
fn run_blocking<S: WitnessSink>(
    spawner: &Spawner,
    binary: PathBuf,
    cgroup_root: PathBuf,
    job_key: B256,
    module: OwnedFd,
    context: OwnedFd,
    broker_fd: OwnedFd,
    limits: Limits,
    mut sink: S,
    abort: AbortToken,
    runners: &RunnerCgroups,
) -> (Raw, S) {
    let mut raw = Raw {
        exit: None,
        signal: None,
        oom_killed: false,
        memory_peak: None,
        wall_clock_hit: false,
        aborted: false,
        summary_bytes: Vec::new(),
        log: Vec::new(),
        w_bytes: 0,
        w_overflow: false,
        sink_error: None,
        spawn_error: None,
        broker_gone: false,
    };
    let name = format!("builder-{}-{}", hex_prefix(job_key), RUN_SEQ.fetch_add(1, Ordering::Relaxed));
    let cgroup = match Cgroup::create(
        &cgroup_root,
        &CgroupSpec {
            name,
            memory_max: limits.maxBuilderMemoryBytes.saturating_add(RUNNER_MEMORY_OVERHEAD),
            pids_max: RUNNER_PIDS_MAX,
            cpu_max: None,
            cpu_weight: 20,
        },
    ) {
        Ok(c) => c,
        Err(e) => {
            raw.spawn_error = Some(format!("cgroup: {e}"));
            return (raw, sink);
        }
    };
    let pipes = (|| -> io::Result<_> { Ok((pipe()?, pipe()?, pipe()?)) })();
    let ((mut w_read, w_write), (sum_read, sum_write), (log_read, log_write)) = match pipes {
        Ok(p) => p,
        Err(e) => {
            raw.spawn_error = Some(format!("pipes: {e}"));
            return (raw, sink);
        }
    };
    let args = runner_args(&limits);
    let spawned = spawner.run(move || {
        let mut cmd = Command::new(&binary);
        cmd.args(&args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::from(log_write));
        let child = prepare_command(
            &mut cmd,
            &cgroup,
            &[
                (w_write.as_fd(), 3),
                (sum_write.as_fd(), 4),
                (broker_fd.as_fd(), 5),
                (module.as_fd(), 6),
                (context.as_fd(), 7),
            ],
        )
        .map_err(io::Error::other)
        .and_then(|()| cmd.spawn());
        // The child holds its own copies now; ours must close so the readers see EOF.
        drop((w_write, sum_write, broker_fd, module, context, cmd));
        (child, cgroup)
    });
    let (child, cgroup) = match spawned {
        Ok((Ok(c), cg)) => (c, cg),
        Ok((Err(e), cg)) => {
            raw.spawn_error = Some(format!("spawn: {e}"));
            let _ = cg.remove();
            return (raw, sink);
        }
        Err(e) => {
            raw.spawn_error = Some(format!("spawner: {e}"));
            return (raw, sink);
        }
    };
    // The runner is in its cgroup now (spawn returns after the exec), with the job socket: from
    // here until it is reaped, the end of the broker's session kills it (at once, if it ended
    // already: the broker may have queued a socket on the job socket before it went).
    let registered = runners.add(cgroup.path());
    let start = Instant::now();
    let deadline = start + Duration::from_secs(u64::from(limits.maxBuilderSeconds)) + OUTER_DEADLINE_GRACE;
    let summary_t = thread::spawn(move || read_capped(sum_read, SUMMARY_PIPE_MAX_BYTES));
    let log_t = thread::spawn(move || read_capped(log_read, MINER_LOG_CAP));
    let cg_path = cgroup.path().to_path_buf();
    // The waiter kills the cgroup at the outer deadline or when the abort token fires (so the W loop
    // below always ends).
    let waiter = thread::spawn(move || {
        let mut child = child;
        let kill = |child: &mut std::process::Child| {
            let _ = std::fs::write(cg_path.join("cgroup.kill"), "1");
            child.wait().expect("wait for the killed runner")
        };
        loop {
            match child.try_wait() {
                Ok(Some(st)) => return (st, Killed::No),
                Ok(None) if abort.is_aborted() => return (kill(&mut child), Killed::Aborted),
                Ok(None) if Instant::now() >= deadline => return (kill(&mut child), Killed::Deadline),
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => return (kill(&mut child), Killed::Deadline),
            }
        }
    });
    let mut buf = vec![0u8; W_CHUNK_BYTES];
    loop {
        match w_read.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.w_bytes += n as u64;
                if raw.w_bytes > limits.maxWitnessBytes {
                    raw.w_overflow = true;
                    let _ = cgroup.kill();
                    break;
                }
                if raw.sink_error.is_none() {
                    if let Err(e) = sink.write(&buf[..n]) {
                        raw.sink_error = Some(e);
                        let _ = cgroup.kill();
                        break;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                raw.sink_error = Some(format!("reading W: {e}"));
                let _ = cgroup.kill();
                break;
            }
        }
    }
    drop(w_read);
    let (status, killed) = waiter.join().expect("waiter thread");
    match registered {
        Some(id) => runners.remove(id),
        None => raw.broker_gone = true,
    }
    raw.broker_gone |= runners.closed();
    raw.wall_clock_hit = killed == Killed::Deadline;
    raw.aborted = killed == Killed::Aborted;
    raw.exit = status.code();
    raw.signal = status.signal();
    raw.summary_bytes = summary_t.join().unwrap_or_default();
    raw.log = log_t.join().unwrap_or_default();
    raw.oom_killed = cgroup.oom_killed();
    raw.memory_peak = cgroup.memory_peak();
    let _ = cgroup.remove();
    (raw, sink)
}

/// Why the waiter killed the runner, if it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Killed {
    No,
    Deadline,
    Aborted,
}

fn hex_prefix(b: B256) -> String {
    b.0[..6].iter().map(|x| format!("{x:02x}")).collect()
}

/// Runs one builder end to end: registers the job with the broker, runs the sandboxed runner,
/// ends the job, classifies. Returns the sink so the caller can finish the bundle on success.
pub async fn run_builder<S: WitnessSink>(
    spawner: &Spawner,
    broker: &BrokerClient,
    run: &BuilderRun<'_>,
    registration: JobRegistration,
    sink: S,
) -> anyhow::Result<(BuilderRunResult, S)> {
    run_builder_abortable(spawner, broker, run, registration, sink, &AbortToken::new()).await
}

/// [`run_builder`], killing the runner's cgroup as soon as `abort` fires (it is polled with the
/// runner's status, every 20 ms); the result then says `aborted`.
pub async fn run_builder_abortable<S: WitnessSink>(
    spawner: &Spawner,
    broker: &BrokerClient,
    run: &BuilderRun<'_>,
    registration: JobRegistration,
    sink: S,
    abort: &AbortToken,
) -> anyhow::Result<(BuilderRunResult, S)> {
    let started = Instant::now();
    let (runner_end, broker_end) = job_socketpair()?;
    broker.register_job(registration, broker_end).await.map_err(|e| anyhow::anyhow!("register_job: {e}"))?;
    let module = sealed_memfd("builder-module", run.module)?;
    let context = sealed_memfd("builder-context", run.context)?;
    let spawner = spawner.clone();
    // Absolute: the sandbox launcher starts the runner in `/`.
    let binary = std::path::absolute(run.binary).unwrap_or_else(|_| run.binary.to_path_buf());
    let (binary, root, key, limits, abort, runners) =
        (binary, run.cgroup_root.to_path_buf(), run.job_key, run.limits.clone(), abort.clone(), broker.runners().clone());
    let joined = tokio::task::spawn_blocking(move || {
        run_blocking(&spawner, binary, root, key, module, context, OwnedFd::from(runner_end), limits, sink, abort, &runners)
    })
    .await;
    let (raw, sink) = joined.map_err(|e| anyhow::anyhow!("builder run thread: {e}"))?;
    let stats = broker.end_job(run.job_key).await.ok();
    let (module_started, summary) = decode_summary_pipe(&raw.summary_bytes);
    // An abort kill is the miner's doing, never the module's; so is a kill with the broker.
    let miner_side_failure =
        raw.sink_error.is_some() || raw.spawn_error.is_some() || stats.is_none() || raw.aborted || raw.broker_gone;
    let outcome = BuilderOutcome {
        exit: raw.exit,
        oom_killed: raw.oom_killed,
        wall_clock_hit: raw.wall_clock_hit,
        operator_failure: stats.is_some_and(|s| s.operator_failure),
        source_lagging: stats.is_some_and(|s| s.lagging_unconfirmed),
        fetch_in_flight_at_end: stats.is_some_and(|s| s.fetch_in_flight_at_end),
        in_flight_operator_wait: stats.is_some_and(|s| s.in_flight_operator_wait),
        module_started,
        signal: raw.signal,
        miner_side_failure,
    };
    let verdict = if raw.w_overflow {
        Some(SkipReason::BuilderWitnessTooLarge)
    } else {
        builder_verdict(&outcome)
    };
    let mut log = sanitize_log(&raw.log, MINER_LOG_CAP * 2);
    for e in [raw.spawn_error.as_deref(), raw.sink_error.as_deref()].into_iter().flatten() {
        log.push_str("\n[miner] ");
        log.push_str(e);
    }
    Ok((
        BuilderRunResult {
            outcome,
            verdict,
            summary,
            stats,
            w_bytes: raw.w_bytes,
            w_overflow: raw.w_overflow,
            aborted: raw.aborted,
            log,
            elapsed: started.elapsed(),
            memory_peak: raw.memory_peak,
        },
        sink,
    ))
}
