//! Single worker process handle.
//!
//! Manages the lifecycle of a subprocess worker: spawn, handshake, IPC, shutdown.

use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// When true, worker stderr forwarding is suppressed (TUI mode).
static SUPPRESS_WORKER_STDERR: AtomicBool = AtomicBool::new(false);

/// Suppress worker stderr forwarding to prevent TUI corruption.
pub fn suppress_worker_stderr(suppress: bool) {
    SUPPRESS_WORKER_STDERR.store(suppress, Ordering::Relaxed);
}

use anyhow::{bail, Context, Result};
use zkminer_prover_protocol::{
    read_message, write_message, FrameError, WorkerCommand, WorkerResponse, PROTOCOL_VERSION,
};

/// Typed error indicating the worker process died (EOF on its stdout pipe).
/// Used instead of string matching to distinguish "worker died" from "stream corrupted".
#[derive(Debug)]
pub struct WorkerDied {
    pub backend: String,
}

impl std::fmt::Display for WorkerDied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Worker {} process died (EOF)", self.backend)
    }
}

impl std::error::Error for WorkerDied {}

/// Timeout for the initial Hello handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Handle to a running worker subprocess.
pub struct WorkerHandle {
    pub backend: String,
    pub path: PathBuf,
    pub sdk_version: Option<String>,
    pub worker_version: Option<String>,
    child: Child,
    reader: BufReader<ChildStdout>,
    writer: BufWriter<ChildStdin>,
    stderr_task: Option<std::thread::JoinHandle<()>>,
}

/// Request to the spawner thread: build a worker, hand back the handle.
struct SpawnRequest {
    backend: String,
    path: PathBuf,
    env: HashMap<String, String>,
    reply: std::sync::mpsc::Sender<Result<WorkerHandle>>,
}

/// Channel to the single, long-lived thread that forks EVERY worker.
static SPAWNER: std::sync::OnceLock<std::sync::mpsc::Sender<SpawnRequest>> =
    std::sync::OnceLock::new();

/// Get (or start) the spawner thread.
///
/// WHY THIS EXISTS: workers are forked with `PR_SET_PDEATHSIG, SIGKILL` so they can't
/// outlive a crashed miner. That signal is **thread-scoped** — the kernel delivers it
/// when the thread that forked the child exits, NOT when the process dies. Respawns
/// happen inside `tokio::task::spawn_blocking`, and tokio retires idle blocking threads
/// (~10s), so every respawned worker was being SIGKILLed shortly after it went idle.
///
/// Symptom before this fix: the miner ran cleanly until the first 20-proof recycle
/// forced a respawn, then ~90% of proofs were preceded by
/// `Worker risc0:cuda died (killed by signal 9), will attempt respawn` — permanently,
/// which also meant workers never survived to 20 proofs and the recycle hygiene the
/// recycle exists to provide never actually ran.
///
/// Forking from one thread that lives for the whole process keeps the crash-cleanup
/// guarantee (PDEATHSIG still fires if the miner dies, because this thread dies with it)
/// while removing the spurious kills.
fn spawner() -> &'static std::sync::mpsc::Sender<SpawnRequest> {
    SPAWNER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<SpawnRequest>();
        std::thread::Builder::new()
            .name("worker-spawner".to_string())
            .spawn(move || {
                // Deliberately never returns: exiting would SIGKILL every worker this
                // thread forked. It parks on the channel for the process lifetime.
                for req in rx {
                    let res =
                        WorkerHandle::spawn_on_this_thread(&req.backend, &req.path, &req.env);
                    let _ = req.reply.send(res);
                }
            })
            .expect("failed to start worker-spawner thread");
        tx
    })
}

impl WorkerHandle {
    /// Spawn a worker via the long-lived spawner thread (see `spawner()`).
    ///
    /// Blocks the caller until the worker is up, so behaviour is otherwise identical
    /// to spawning inline — including the handshake.
    pub fn spawn(
        backend: &str,
        path: &PathBuf,
        env_overrides: &HashMap<String, String>,
    ) -> Result<Self> {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        spawner()
            .send(SpawnRequest {
                backend: backend.to_string(),
                path: path.clone(),
                env: env_overrides.clone(),
                reply: reply_tx,
            })
            .map_err(|_| anyhow::anyhow!("worker-spawner thread is gone"))?;
        reply_rx
            .recv()
            .map_err(|_| anyhow::anyhow!("worker-spawner thread dropped the request"))?
    }

    /// Spawn a new worker process and perform the Hello handshake.
    /// Spawn on the caller's thread. PRIVATE: call `spawn()` instead, which routes
    /// through the long-lived spawner thread. See `spawn()` for why that matters.
    fn spawn_on_this_thread(
        backend: &str,
        path: &PathBuf,
        env_overrides: &HashMap<String, String>,
    ) -> Result<Self> {
        tracing::info!("Spawning worker {backend} from {}", path.display());

        let mut cmd = Command::new(path);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for (k, v) in env_overrides {
            cmd.env(k, v);
        }

        // Kill worker if parent process dies (prevents orphan GPU processes after host crash).
        // PR_SET_PDEATHSIG is Linux-specific.
        #[cfg(target_os = "linux")]
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                // Put the worker in its own process group (pgid == its own pid) so
                // the dispatcher's watchdogs can SIGKILL the ENTIRE group via
                // kill(-pgid) on timeout. Without this, a worker that forks a GPU
                // or helper child hands that child a copy of the stdout pipe's
                // write end; killing only the main worker PID then leaves the pipe
                // open, so the dispatcher's blocking read never sees EOF and hangs
                // forever.
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn worker {backend} at {}", path.display()))?;

        let child_stdout = child
            .stdout
            .take()
            .context("Failed to capture worker stdout")?;
        let child_stdin = child
            .stdin
            .take()
            .context("Failed to capture worker stdin")?;
        let child_stderr = child.stderr.take();

        let reader = BufReader::new(child_stdout);
        let writer = BufWriter::new(child_stdin);

        // Spawn stderr reader thread that forwards to tracing
        let backend_name = backend.to_string();
        let stderr_task = child_stderr.map(|stderr| {
            std::thread::Builder::new()
                .name(format!("worker-stderr-{backend_name}"))
                .spawn(move || {
                    use std::io::BufRead;
                    let reader = BufReader::new(stderr);
                    for line in reader.lines() {
                        match line {
                            Ok(line) if !line.is_empty() => {
                                // DIAGNOSTIC: surface WITSUM / EVALCHECK_DIFF lines directly to stderr
                                // (the test harness installs no tracing subscriber, so warn is dropped).
                                if line.starts_with("[WITSUM]") || line.starts_with("[EVALCHECK_DIFF]") {
                                    eprintln!("[worker:{backend_name}] {line}");
                                }
                                if !SUPPRESS_WORKER_STDERR.load(Ordering::Relaxed) {
                                    tracing::warn!(target: "worker", "[worker:{backend_name}] {line}");
                                }
                            }
                            Err(_) => break,
                            _ => {}
                        }
                    }
                })
                .ok()
        }).flatten();

        let mut handle = Self {
            backend: backend.to_string(),
            path: path.clone(),
            sdk_version: None,
            worker_version: None,
            child,
            reader,
            writer,
            stderr_task,
        };

        // Perform Hello handshake
        handle.handshake()?;

        Ok(handle)
    }

    fn handshake(&mut self) -> Result<()> {
        let cmd = WorkerCommand::Hello {
            protocol_version: PROTOCOL_VERSION,
        };
        self.send(&cmd)?;

        // Spawn a watchdog thread that SIGKILLs the child if the handshake
        // doesn't complete within HANDSHAKE_TIMEOUT. This is necessary because
        // recv() calls read_exact() which blocks indefinitely on a pipe — there
        // is no way to set a read timeout on a pipe fd. When the child is killed,
        // read_exact() returns UnexpectedEof, unblocking this thread.
        let child_pid = self.child.id();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = cancel.clone();
        let backend = self.backend.clone();

        #[cfg(unix)]
        let watchdog = std::thread::Builder::new()
            .name(format!("handshake-watchdog-{backend}"))
            .spawn(move || {
                let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
                while Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(100));
                    if cancel_clone.load(Ordering::Relaxed) {
                        return;
                    }
                }
                if !cancel_clone.load(Ordering::Relaxed) {
                    tracing::error!(
                        "Handshake watchdog: worker {backend} (PID {child_pid}) did not respond \
                         within {HANDSHAKE_TIMEOUT:?}, killing"
                    );
                    // Kill the worker's whole process group (see setpgid in spawn)
                    // so any forked child dies too and releases the stdout pipe,
                    // unblocking the recv() read below.
                    unsafe {
                        libc::kill(-(child_pid as i32), libc::SIGKILL);
                        libc::kill(child_pid as i32, libc::SIGKILL);
                    }
                }
            })
            .ok();

        let result = self.recv();

        // Cancel the watchdog regardless of outcome
        cancel.store(true, Ordering::Relaxed);
        #[cfg(unix)]
        if let Some(handle) = watchdog {
            let _ = handle.join();
        }

        let resp = result.map_err(|e| {
            anyhow::anyhow!(
                "Handshake with worker {} failed (timeout={:?}): {e}",
                self.backend, HANDSHAKE_TIMEOUT
            )
        })?;

        match resp {
            WorkerResponse::HelloAck {
                protocol_version,
                backend,
                sdk_version,
                worker_version,
            } => {
                if protocol_version != PROTOCOL_VERSION {
                    bail!(
                        "Protocol version mismatch with {}: expected {PROTOCOL_VERSION}, got {protocol_version}",
                        self.backend
                    );
                }
                if backend != self.backend {
                    tracing::warn!(
                        "Worker reports backend '{backend}' but expected '{}'",
                        self.backend
                    );
                }
                self.sdk_version = Some(sdk_version.clone());
                self.worker_version = Some(worker_version.clone());
                tracing::info!(
                    "Worker {} connected: {sdk_version} (worker v{worker_version})",
                    self.backend
                );
                Ok(())
            }
            // A worker that CAN speak the protocol but CANNOT prove reports itself here
            // rather than answering HelloAck. Surface its reason verbatim: the handshake
            // still fails (so the backend is never advertised and run.rs's pre-claim gate
            // skips it), but the operator gets an actionable message instead of a bare
            // "expected HelloAck". This is how an SP1 worker on a host with no usable
            // CUDA runtime declines, instead of claiming jobs it would lose.
            WorkerResponse::Error { kind, message, .. } => {
                // Tagged with WORKER_DECLINED so the dispatcher can tell this from a
                // transient spawn failure. Without the tag the slot is registered as
                // dead-but-eligible, `is_backend_healthy` returns true, and the miner
                // goes on claiming jobs this worker has just said it cannot prove.
                bail!(
                    "{} Worker {} declined the handshake ({kind:?}): {message}",
                    zkminer_prover_protocol::types::WORKER_DECLINED,
                    self.backend
                );
            }
            other => {
                bail!(
                    "Expected HelloAck from worker {}, got: {other:?}",
                    self.backend
                );
            }
        }
    }

    /// Send a command to the worker.
    pub fn send(&mut self, cmd: &WorkerCommand) -> Result<()> {
        write_message(&mut self.writer, cmd).map_err(|e| anyhow::anyhow!("Send error: {e}"))
    }

    /// Receive a response from the worker.
    pub fn recv(&mut self) -> Result<WorkerResponse> {
        read_message(&mut self.reader).map_err(|e| match e {
            FrameError::UnexpectedEof => WorkerDied {
                backend: self.backend.clone(),
            }.into(),
            other => anyhow::anyhow!("Recv error from {}: {other}", self.backend),
        })
    }

    /// Receive proof responses, forwarding Progress updates via callback.
    /// Returns on ProofResult, Error, or Cancelled matching `expected_request_id`.
    /// Stale responses from previous requests are discarded with a warning.
    pub fn recv_proof(
        &mut self,
        expected_request_id: u64,
        on_progress: &Option<Box<dyn Fn(f64) + Send>>,
    ) -> Result<WorkerResponse> {
        const MAX_STALE_DISCARDS: u32 = 16;
        let mut stale_count: u32 = 0;

        loop {
            let resp = self.recv()?;
            match &resp {
                WorkerResponse::Progress { request_id, fraction, .. } => {
                    if *request_id == expected_request_id {
                        if let Some(cb) = on_progress {
                            cb(*fraction);
                        }
                    }
                    // Continue reading (don't count progress toward stale limit)
                }
                WorkerResponse::ProofResult { request_id, .. }
                | WorkerResponse::ExecuteResult { request_id, .. }
                | WorkerResponse::Error { request_id, .. }
                | WorkerResponse::Cancelled { request_id, .. } => {
                    if *request_id == expected_request_id {
                        return Ok(resp);
                    }
                    // Stale response from a previous request — discard
                    stale_count += 1;
                    tracing::warn!(
                        "Discarding stale response for request {request_id} \
                         (expected {expected_request_id}) [{stale_count}/{MAX_STALE_DISCARDS}]"
                    );
                    if stale_count >= MAX_STALE_DISCARDS {
                        bail!(
                            "Worker {} protocol desync: discarded {MAX_STALE_DISCARDS} stale \
                             responses while waiting for request {expected_request_id}",
                            self.backend,
                        );
                    }
                }
                other => {
                    tracing::warn!(
                        "Unexpected response from worker {} during proving: {other:?}",
                        self.backend
                    );
                }
            }
        }
    }

    /// Receive benchmark responses, forwarding BenchmarkProgress updates via callback.
    /// Returns the final BenchmarkResult response.
    pub fn recv_benchmark(
        &mut self,
        on_progress: &dyn Fn(&zkminer_prover_protocol::BenchmarkEntry, u32, u32),
    ) -> Result<WorkerResponse> {
        loop {
            let resp = self.recv()?;
            match &resp {
                WorkerResponse::BenchmarkProgress {
                    entry,
                    program_index,
                    total_programs,
                } => {
                    on_progress(entry, *program_index, *total_programs);
                }
                WorkerResponse::BenchmarkResult { .. } | WorkerResponse::Error { .. } => {
                    return Ok(resp);
                }
                other => {
                    tracing::warn!(
                        "Unexpected response from worker {} during benchmarking: {other:?}",
                        self.backend
                    );
                }
            }
        }
    }

    /// Check if the worker process is still alive.
    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Why the worker is no longer alive — the datum `is_alive()` throws away.
    /// Distinguishes an external SIGKILL (signal 9) from a panic/abort (6/11), a
    /// clean exit (code 0 = graceful Shutdown), and a `try_wait` Err (which would
    /// make `is_alive()` report a LIVE process as dead).
    pub fn exit_reason(&mut self) -> String {
        #[cfg(unix)]
        use std::os::unix::process::ExitStatusExt;
        match self.child.try_wait() {
            Ok(Some(st)) => {
                #[cfg(unix)]
                if let Some(sig) = st.signal() {
                    return format!("killed by signal {sig}");
                }
                format!("exited with code {:?}", st.code())
            }
            Ok(None) => "still running (spurious)".to_string(),
            Err(e) => format!("try_wait ERROR: {e}"),
        }
    }

    /// Get the worker's PID.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// SIGKILL the worker's ENTIRE process group, then reap it.
    ///
    /// The worker calls `setpgid(0,0)` at spawn, so this kills any forked
    /// GPU/helper child too — most importantly SP1's `sp1-gpu-server` (moongate),
    /// which holds GPU VRAM (~18.6 GB). Killing only the main PID (`child.kill()`)
    /// orphans that child, leaking VRAM across proofs and, if it inherited the
    /// stdout write end, hanging the dispatcher's `recv_proof`. Mirrors the
    /// timeout-watchdog kill path in the dispatcher.
    fn force_kill_group(&mut self) {
        let pid = self.child.id();
        #[cfg(unix)]
        {
            // pid is a live spawned child's id, hence non-zero; guard anyway so
            // kill(-pid) can never degenerate into kill(0)/kill(-1).
            if pid != 0 {
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }

    /// Immediate kill: SIGKILL the worker (and its whole process group) without a
    /// graceful shutdown. Used for stream corruption recovery and OOM recovery.
    pub fn kill(&mut self) {
        tracing::warn!("Killing worker {} (PID {})", self.backend, self.child.id());
        self.force_kill_group();
    }

    /// Graceful shutdown: send Shutdown command, wait up to 5s, then SIGKILL.
    pub fn shutdown(&mut self) {
        tracing::info!("Shutting down worker {}", self.backend);

        // Try graceful shutdown
        let _ = self.send(&WorkerCommand::Shutdown);

        // Wait up to 5 seconds for the process to exit
        let start = Instant::now();
        let timeout = Duration::from_secs(5);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    tracing::info!("Worker {} exited with {status}", self.backend);
                    return;
                }
                Ok(None) => {
                    if start.elapsed() > timeout {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    tracing::warn!("Error waiting for worker {}: {e}", self.backend);
                    break;
                }
            }
        }

        // Force kill (whole process group — reaps any forked GPU server child).
        tracing::warn!("Worker {} did not exit gracefully, killing", self.backend);
        self.force_kill_group();
    }
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        // Captured BEFORE any wait: the pid doubles as the process-group id.
        let pid = self.child.id();
        // Best-effort shutdown
        let _ = self.send(&WorkerCommand::Shutdown);

        // Poll for exit WITHOUT reaping.
        //
        // `kill(pid, 0)` CANNOT be used here: it succeeds for a ZOMBIE (verified), so it
        // never observes death and the loop degenerates into an unconditional 2s sleep.
        // With four workers that pushed `shutdown_all` to ~10.2s against the hard 10s cap
        // its callers impose, so the cap fired on every clean stop and printed the
        // "check for an orphaned sp1-gpu-server holding VRAM" warning when nothing had
        // leaked -- training the operator to ignore the one alarm that means "go look".
        //
        // `waitid(WNOHANG|WNOWAIT)` reports the exit and LEAVES the zombie, which is what
        // keeps the pid -- and therefore the process-group NUMBER -- pinned until we are
        // done signalling it. `try_wait` would reap and free the number.
        #[cfg(unix)]
        {
            let start = Instant::now();
            let timeout = Duration::from_secs(2);
            loop {
                let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let r = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut si,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if r != 0 {
                    // ECHILD: already reaped by someone else (ensure_alive / kill /
                    // shutdown all reap upstream). Nothing left to wait for.
                    break;
                }
                // si_pid == 0 means still running under WNOHANG.
                if unsafe { si.si_pid() } != 0 {
                    break;
                }
                if start.elapsed() >= timeout {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        // Kill the process group, but ONLY while it still has members.
        //
        // This is the whole point of the fix: the old code `break`ed out of its wait loop
        // precisely when the worker had already exited -- the death-and-respawn path drops
        // the handle BECAUSE the worker died -- and so never group-killed. A forked GPU
        // helper (SP1's `sp1-gpu-server`, a 236MB CUDA process) then outlived it as an
        // orphan holding VRAM, unreachable afterwards because `handle_worker_death` zeroes
        // the stored PID before dropping the handle. Measured in production: 10.3GB still
        // held after the miner exited, which starved the next run into CUDA OOM panics.
        //
        // The `kill(-pid, 0)` guard matters. When the worker left no children the group is
        // EMPTY and its number is free for reuse, so an unconditional `kill(-pid, SIGKILL)`
        // could signal an unrelated group -- and since every worker is a group leader, a
        // collision would take out somebody's whole worker group mid-proof. A non-empty
        // group pins the number, so probing first is both safe and sufficient: if members
        // exist we kill them, and if none exist there is nothing to leak.
        #[cfg(unix)]
        unsafe {
            if pid != 0 && libc::kill(-(pid as i32), 0) == 0 {
                tracing::warn!(
                    "worker {} (PID {pid}) left process-group members behind — killing the \
                     group so a forked GPU helper cannot orphan and hold VRAM",
                    self.backend
                );
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill();
        }

        // Now reap.
        let _ = self.child.wait();

        // Join stderr thread
        if let Some(handle) = self.stderr_task.take() {
            let _ = handle.join();
        }
    }
}
