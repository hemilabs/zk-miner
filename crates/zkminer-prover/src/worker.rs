//! Single worker process handle.
//!
//! Manages the lifecycle of a subprocess worker: spawn, handshake, IPC, shutdown.

use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
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
///
/// Defined in the protocol crate so the workers that must fit inside it can assert that they
/// do, instead of hard-coding a copy of a number they cannot see.
use zkminer_prover_protocol::proc::HANDSHAKE_TIMEOUT;

/// Outcome of a NON-REAPING exit check. See `probe_exit_nowait`.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitProbe {
    /// Still running.
    Running,
    /// Exited, and left a zombie: the pid — and with it the process-GROUP number — stays
    /// pinned until someone reaps it.
    Exited {
        signal: Option<i32>,
        code: Option<i32>,
    },
    /// Already reaped. The pid number is free and MUST NOT be signalled.
    Gone,
}

/// Observe a child's exit WITHOUT reaping it.
///
/// `try_wait`/`wait` reap, which frees the pid — and with it the process-GROUP number,
/// because every worker is its own group leader (`setpgid(0,0)` at spawn). Two things
/// depend on that number staying pinned:
///
///   * the forked-helper sweep: `kill(-pgid, SIGKILL)` is the only handle we have on an
///     `sp1-gpu-server` the worker forked (measured still holding 10.3 GB of VRAM after
///     the miner exited, which starved the next run into CUDA OOM), and
///   * safety: once the number is free the kernel can hand it to an unrelated process
///     group, so a late `kill(-pgid, SIGKILL)` would take out somebody else's processes.
///
/// So nothing here reaps until the sweep has run. `ensure_alive` already documents this
/// contract — "before `WorkerHandle::drop` reaps the zombie" — and `try_wait` broke it:
/// the liveness check that detects the death was also the thing that destroyed the only
/// handle the cleanup had.
#[cfg(unix)]
fn probe_exit_nowait(pid: u32) -> ExitProbe {
    if pid == 0 {
        return ExitProbe::Gone;
    }
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        let r = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut si,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if r == 0 {
            break;
        }
        // `Gone` is the one verdict that disables ALL cleanup — `Drop`'s `Gone` arm neither
        // sweeps nor kills — so only the error that actually means "not our child any more"
        // may produce it. Anything else resolves to `Running`, which is the safe default in
        // both directions: it keeps the worker treated as alive (no spurious respawn
        // alongside a live 18 GB prover) and keeps the group sweep armed.
        match std::io::Error::last_os_error().raw_os_error() {
            // A signal merely arrived; says nothing about the child.
            Some(libc::EINTR) => continue,
            // ECHILD: already reaped, so the pid number is free and must not be signalled.
            Some(libc::ECHILD) => return ExitProbe::Gone,
            other => {
                tracing::warn!(
                    "waitid({pid}) failed with {other:?}, which is neither EINTR nor ECHILD; \
                     treating the worker as RUNNING so cleanup stays armed"
                );
                return ExitProbe::Running;
            }
        }
    }
    // Under WNOHANG a still-running child leaves si_pid == 0.
    if unsafe { si.si_pid() } == 0 {
        return ExitProbe::Running;
    }
    let status = unsafe { si.si_status() };
    if si.si_code == libc::CLD_EXITED {
        ExitProbe::Exited {
            signal: None,
            code: Some(status),
        }
    } else {
        // CLD_KILLED / CLD_DUMPED: si_status carries the signal number.
        ExitProbe::Exited {
            signal: Some(status),
            code: None,
        }
    }
}

/// May we send a signal to the process GROUP whose id equals this worker's pid?
///
/// No, if that number is our own process-group id. A worker is supposed to be its own group
/// leader (`setpgid(0,0)` at spawn), so `pgid == worker_pid`; if that call had failed the worker
/// would share OUR group, and `kill(-worker_pid)` would then be either harmless (ESRCH) or, after
/// pid recycling, a stranger's group. The case this really forbids is the one that costs
/// everything: `kill(-our_pgid, SIGKILL)` kills the miner and every live prover.
///
/// Note what it does NOT detect, because three comments previously claimed it did: a failed
/// `setpgid` leaves the worker's pid unequal to our pgid, so this predicate is true and the
/// signal goes out. Detecting that needs the worker's actual pgrp, and `setpgid` failing already
/// aborts the spawn (`spawn_on_this_thread`), so the condition is unreachable rather than
/// screened.
#[cfg(unix)]
fn may_signal_group(pid: u32) -> bool {
    pid != 0 && (pid as i32) != unsafe { libc::getpgrp() }
}

/// Live (non-zombie) members of process group `pgid`, excluding the group leader itself.
///
/// This is the predicate the orphan alarm actually needs. `kill(-pgid, 0)` cannot answer
/// it: a ZOMBIE leader keeps the group non-empty, so the probe succeeded on every clean
/// worker exit and the "left process-group members behind" warning fired even when the
/// worker had forked nothing at all — 6 times in a single SP1-decline run. A zombie holds
/// no VRAM, so it is not a leak, and raising the alarm on it trains the operator to ignore
/// the one message that means "go look for 10 GB of held VRAM".
///
/// `proc_root` is a parameter so the discriminator can be tested against a synthetic tree.
#[cfg(unix)]
fn live_group_members(proc_root: &Path, pgid: i32) -> Option<Vec<(i32, String)>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(proc_root) {
        Ok(e) => e,
        // `None` means WE COULD NOT LOOK, which is not the same as "nothing leaked" — and since
        // the group kill is now gated on this scan, folding the two together meant no kill at all.
        // The condition that causes it is the one this project treats as normal: at the NOFILE
        // limit (which `is_transient_spawn_error` adds EMFILE/ENFILE for) `read_dir` fails, a
        // forked `sp1-gpu-server` keeps ~18 GB of VRAM, and nothing kills it. The old
        // `kill(-pgid, 0)` probe needed no descriptor at all, so this would have been a regression
        // in exactly that state.
        Err(e) => {
            tracing::warn!("cannot read {}: {e}", proc_root.display());
            return None;
        }
    };
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        // The leader is the handle's own child, not something it left behind.
        if pid == pgid {
            continue;
        }
        // Read bytes, not a String: `comm` is whatever `prctl(PR_SET_NAME)` was handed and
        // need not be UTF-8. `read_to_string` returns Err(InvalidData) for such a process, so
        // it would be skipped — and since the group kill is now gated on this scan finding
        // something, a single non-UTF-8 member meant no kill at all.
        let Ok(stat_bytes) = std::fs::read(e.path().join("stat")) else {
            continue; // raced exit, or another user's process
        };
        let stat = String::from_utf8_lossy(&stat_bytes);
        let Some((state, pgrp)) = parse_stat_state_pgrp(&stat) else {
            continue;
        };
        if pgrp != pgid || state == 'Z' {
            continue;
        }
        out.push((pid, comm_from_stat(&stat).unwrap_or_default()));
    }
    out.sort();
    Some(out)
}

/// `(state, pgrp)` from a `/proc/<pid>/stat` line.
///
/// Parsed from the LAST `)` rather than by splitting on whitespace: field 2 is `comm`, an
/// unquoted executable basename that may itself contain spaces and parentheses, so a
/// positional split would read the wrong fields for e.g. `(sp1 gpu (server))`.
#[cfg(unix)]
fn parse_stat_state_pgrp(stat: &str) -> Option<(char, i32)> {
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    let mut f = rest.split_whitespace();
    let state = f.next()?.chars().next()?;
    let _ppid = f.next()?;
    let pgrp = f.next()?.parse().ok()?;
    Some((state, pgrp))
}

/// `comm` from a `/proc/<pid>/stat` line, for naming what leaked.
#[cfg(unix)]
fn comm_from_stat(stat: &str) -> Option<String> {
    let start = stat.find('(')? + 1;
    let end = stat.rfind(')')?;
    if start > end {
        return None;
    }
    Some(stat[start..end].to_string())
}

/// SIGKILL whatever the worker's process group still holds, and name it in the log.
///
/// MUST be called with an UNREAPED, already-EXITED worker (a zombie): that is what keeps
/// the pid — and therefore the group number — pinned, and it is why excluding the leader from
/// the scan is correct. See `probe_exit_nowait`.
///
/// Deliberately NOT for a live leader: with the leader still running and nothing forked, the
/// scan finds nothing and this returns without killing anything, which is not what a caller
/// wanting "kill this worker" would expect. That case is `force_kill_group`.
#[cfg(unix)]
fn sweep_process_group(pid: u32, backend: &str) -> usize {
    sweep_process_group_in(
        Path::new("/proc"),
        pid,
        backend,
        unsafe { libc::getpgrp() },
        &|pgid| {
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        },
    )
}

/// The sweep, with its two environmental inputs injected so it can be tested.
///
/// Returns the number of live members it found (and therefore signalled). `0` means nothing
/// leaked. The previous version hardcoded `/proc`, read `getpgrp()` directly and returned `()`,
/// so neither the reporting nor — more importantly — the self-group refusal below could be
/// tested at all.
///
/// `kill_group` is injected for the same reason, and because injecting only the SCAN was not
/// enough: a test supplying a synthetic `/proc` with a live member still reached a real
/// `kill(-pgid, SIGKILL)`, so the one test exercising the kill path performed one against the
/// host kernel — harmless as an unprivileged user, a live process group as root or in a
/// container with low pids.
#[cfg(unix)]
fn sweep_process_group_in(
    proc_root: &Path,
    pid: u32,
    backend: &str,
    our_pgid: i32,
    kill_group: &dyn Fn(i32),
) -> usize {
    if pid == 0 {
        return 0;
    }
    let pgid = pid as i32;
    // If `setpgid(0,0)` failed at spawn the worker shares OUR group, in which case `pgid` is not
    // a group id at all. Refuse to signal our own group: `kill(-our_pgid, SIGKILL)` kills the
    // miner and every worker it is running.
    if pgid == our_pgid {
        tracing::error!(
            "refusing to sweep process group {pgid}: it is OUR OWN group — signalling it would \
             SIGKILL the miner and every live prover (worker {backend})"
        );
        return 0;
    }
    let leftovers = match live_group_members(proc_root, pgid) {
        Some(l) => l,
        // We could not scan. The pid is still pinned (callers hold an unreaped child), so the
        // group number is ours and signalling it is safe — and it is what the old unconditional
        // kill did. Killing blind beats leaking 18 GB of VRAM because a descriptor was unavailable.
        None => {
            tracing::warn!(
                "worker {backend} (PID {pid}): cannot scan for leaked process-group members, so \
                 killing the group unconditionally rather than risk leaving a GPU helper behind"
            );
            kill_group(pgid);
            return 0;
        }
    };
    if leftovers.is_empty() {
        return 0; // nothing leaked — stay silent, so the alarm keeps its meaning
    }
    let who: Vec<String> = leftovers.iter().map(|(p, c)| format!("{c}({p})")).collect();
    tracing::warn!(
        "worker {backend} (PID {pid}) left {} live process-group member(s) behind [{}] — \
         killing the group so a forked GPU helper cannot orphan and hold VRAM",
        leftovers.len(),
        who.join(", ")
    );
    kill_group(pgid);
    leftovers.len()
}

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
    /// True once this handle has reaped its child. Every `kill(-pgid, …)` is gated on
    /// this: after the reap the pid number is free and may name an unrelated group.
    reaped: bool,
    /// Cumulative OOM-kill count of our cgroup subtree when this worker started, if readable.
    ///
    /// Compared against the same counter at death to tell a host OOM from a prover fault. The
    /// worker's own cgroup cannot answer: a transient scope is destroyed the instant its last
    /// process exits, so the question has to be asked of an ancestor, which means asking it as a
    /// DELTA. See `memory::oom_kill_count`.
    oom_kills_at_spawn: Option<u64>,
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
/// A failed thread creation yields a live channel with no reader, so `spawn` fails cleanly with
/// "worker-spawner thread is gone" rather than panicking out of whatever called it — which, with
/// the old `expect`, unwound through `ensure_alive` into `prove_on_slot` WITH THE SLOT GUARD HELD,
/// poisoning the mutex. `is_backend_healthy` then reads a poisoned slot as healthy forever while
/// every `try_lock` fails, so the miner keeps claiming for a backend it can never dispatch to.
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
                    // `catch_unwind`, because this thread exiting is unrecoverable: `rx` drops,
                    // and every subsequent spawn in the process fails with "worker-spawner thread
                    // is gone" — no restart, no backoff, nothing. A panic anywhere inside
                    // `spawn_on_this_thread` (an allocation failure, a poisoned lock, a thread
                    // the OS refuses) would otherwise take the whole pool down with it, and it is
                    // reached under exactly the memory pressure this project documents. Report the
                    // panic to the ONE caller waiting on it and keep serving the next request.
                    let backend = req.backend.clone();
                    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        WorkerHandle::spawn_on_this_thread(&req.backend, &req.path, &req.env)
                    }))
                    .unwrap_or_else(|_| {
                        Err(anyhow::anyhow!(
                            "panic while spawning worker {backend}; the spawner thread \
                             survived and later spawns will still be served"
                        ))
                    });
                    let _ = req.reply.send(res);
                }
            })
            .ok();
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
                // Volunteer as the kernel's OOM victim.
                //
                // This is the cheapest protection the miner has and the one that decides whether a
                // memory crunch costs a proof or the whole host. On 2026-10-04 this box was frozen
                // hard enough to need a power cycle by four concurrent risc0 provers; the kernel
                // got there eventually, but a `global_oom` is free to pick sshd, systemd or the
                // miner — and the miner is the process that has to survive in order to RELEASE the
                // collateral of the job it just lost.
                //
                // +800 (of the kernel's -1000..=1000 range, added to the heuristic score) makes a prover the
                // first choice essentially always, and `sp1-gpu-server` INHERITS it, which is the
                // property that really matters: the SDK forks that one, not us, so we cannot set it
                // there directly. Raising is unprivileged; only lowering needs CAP_SYS_RESOURCE.
                //
                // The raw-syscall details, and why they have to be raw here, live on
                // `memory::volunteer_as_oom_victim`. Shared with the test that checks the value
                // actually reaches the kernel, so that test cannot pass over a deleted call.
                crate::memory::volunteer_as_oom_victim();
                Ok(())
            });
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn worker {backend} at {}", path.display()))?;

        // From here until the `WorkerHandle` owns it, the child is held by a plain local and
        // `std::process::Child::drop` neither kills nor reaps. Everything between this point and the
        // construction below can panic — `cap_process_memory` goes through `proc::`, the stderr
        // thread setup allocates — and an unwind past a bare local leaks a fully LIVE worker holding
        // VRAM, with no handle left to kill it.
        //
        // `PR_SET_PDEATHSIG` used to collect it by accident, because the forking thread died with
        // the panic. It no longer does: that signal is THREAD-scoped, and the spawner's
        // `catch_unwind` deliberately keeps the thread alive to serve the next request — so the
        // orphan now survives indefinitely. The guard makes the cleanup explicit instead of relying
        // on a side effect that was removed.
        struct SpawnGuard<'a>(Option<Child>, &'a str);
        impl SpawnGuard<'_> {
            fn get(&mut self) -> &mut Child {
                self.0.as_mut().expect("child released before use")
            }
            fn release(mut self) -> Child {
                self.0.take().expect("child released twice")
            }
        }
        impl Drop for SpawnGuard<'_> {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let child = &mut child;
                    tracing::warn!(
                        "unwinding out of worker {} spawn; killing the orphan it would otherwise \
                         leave holding VRAM",
                        self.1
                    );
                    let pid = child.id();
                    #[cfg(unix)]
                    if may_signal_group(pid) {
                        unsafe {
                            libc::kill(-(pid as i32), libc::SIGKILL);
                        }
                    }
                    let _ = child.kill();
                    let _ = reap_within(child, DROP_REAP_BUDGET);
                }
            }
        }
        let mut spawn_guard = SpawnGuard(Some(child), backend);

        let child_stdout = spawn_guard
            .get()
            .stdout
            .take()
            .context("Failed to capture worker stdout")?;
        let child_stdin = spawn_guard
            .get()
            .stdin
            .take()
            .context("Failed to capture worker stdin")?;
        let child_stderr = spawn_guard.get().stderr.take();

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

        // Kernel-enforced ceiling on this worker, best effort. Adoption of a pid we already own,
        // NOT a wrapper process — see `memory::cap_process_memory` for why that distinction is
        // load-bearing for every pid-keyed path in this file.
        let pid_for_cap = spawn_guard.get().id();
        match crate::memory::worker_memory_ceiling_bytes(crate::memory::DEFAULT_HOST_RESERVE_BYTES)
        {
            Some(ceiling) => {
                match crate::memory::cap_process_memory(pid_for_cap, backend, ceiling) {
                    Ok(unit) => tracing::info!(
                        "worker {backend} (PID {pid_for_cap}) capped at {:.1} GiB of RAM, no swap \
                         ({unit})",
                        ceiling as f64 / (1024.0 * 1024.0 * 1024.0)
                    ),
                    // No cap is survivable: `oom_score_adj` still points the kernel at the prover.
                    Err(why) => tracing::warn!(
                        "worker {backend} (PID {pid_for_cap}) could NOT be memory-capped ({why}); \
                         it can still be OOM-killed first thanks to oom_score_adj, but one runaway \
                         prover could now stall the host"
                    ),
                }
            }
            None => tracing::warn!(
                "cannot size a memory ceiling for worker {backend}: /proc/meminfo unreadable or \
                 the host reserve exceeds total RAM"
            ),
        }

        // Baseline for attributing a later SIGKILL. See `WorkerHandle::died_of_host_oom`.
        let oom_kills_at_spawn = crate::memory::oom_kill_count();

        // The handle takes ownership from here, so the guard stops being responsible for it.
        let child = spawn_guard.release();

        let mut handle = Self {
            backend: backend.to_string(),
            path: path.clone(),
            sdk_version: None,
            worker_version: None,
            child,
            reader,
            writer,
            stderr_task,
            reaped: false,
            oom_kills_at_spawn,
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
                        // Guarded like every other group kill in this file. It is safe here by
                        // ownership — the `Child` is live and unreaped in `self.child` for the whole
                        // of `handshake()`, and the caller joins this thread before the handle can
                        // drop, so the pid cannot be recycled — but that argument is non-local, and
                        // the asymmetry invites someone to "fix" the wrong site.
                        if may_signal_group(child_pid) {
                            libc::kill(-(child_pid as i32), libc::SIGKILL);
                        }
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
                self.backend,
                HANDSHAKE_TIMEOUT
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
            }
            .into(),
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
                WorkerResponse::Progress {
                    request_id,
                    fraction,
                    ..
                } => {
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
    ///
    /// Does NOT reap. `try_wait` here was the bug: the liveness check that detects the
    /// death also destroyed the pid — and hence the process-group number — that the
    /// forked-helper sweep needs, and freed it for reuse before the later `kill(-pgid)`.
    ///
    /// The cost is that a dead worker stays a zombie until its handle is dropped. That is
    /// bounded by the number of slots, and it is the better trade in both directions: the
    /// dispatcher also stores the pid in an `AtomicU32` and signals it later, so keeping the
    /// number pinned removes a stale-PID kill window rather than adding one.
    pub fn is_alive(&mut self) -> bool {
        #[cfg(unix)]
        {
            // Short-circuit BEFORE the syscall: once reaped, the pid number may name an
            // unrelated process and `waitid` would be asking about it.
            !self.reaped && matches!(probe_exit_nowait(self.child.id()), ExitProbe::Running)
        }
        #[cfg(not(unix))]
        {
            matches!(self.child.try_wait(), Ok(None))
        }
    }

    /// Why the worker is no longer alive — the datum `is_alive()` throws away.
    ///
    /// Distinguishes an external SIGKILL (signal 9) from a panic/abort (6/11) and a clean
    /// exit (code 0 = graceful Shutdown). On unix it reads the zombie without reaping it, so
    /// it can be called after `is_alive()` has already observed the death; the old
    /// `try_wait`-Err case is gone with `try_wait` itself.
    pub fn exit_reason(&mut self) -> String {
        #[cfg(unix)]
        {
            // After the reap the pid number may belong to someone else; report on nothing.
            if self.reaped {
                return "already reaped (status unavailable)".to_string();
            }
            match probe_exit_nowait(self.child.id()) {
                ExitProbe::Exited {
                    signal: Some(sig), ..
                } => format!("killed by signal {sig}"),
                ExitProbe::Exited { code, .. } => format!("exited with code {code:?}"),
                ExitProbe::Running => "still running (spurious)".to_string(),
                ExitProbe::Gone => "already reaped (status unavailable)".to_string(),
            }
        }
        #[cfg(not(unix))]
        {
            match self.child.try_wait() {
                Ok(Some(st)) => format!("exited with code {:?}", st.code()),
                Ok(None) => "still running (spurious)".to_string(),
                Err(e) => format!("try_wait ERROR: {e}"),
            }
        }
    }

    /// Was this worker killed because the HOST ran out of memory, rather than failing on its own?
    ///
    /// Only meaningful once the worker is dead. Two conditions must hold: it died by `SIGKILL`, and
    /// our cgroup subtree's cumulative OOM-kill counter advanced during its lifetime.
    ///
    /// This exists because the alternative is misattribution, and that has already cost real time
    /// on this box: an OOM-killed prover surfaces as EOF on its pipe, a broken pipe, or a bare
    /// "killed by signal 9", all of which read exactly like a prover regression and invite
    /// debugging the prover. The project's own notes record making that mistake. A host OOM is an
    /// environmental fact — on a box with less RAM than the workload needs, no amount of prover
    /// debugging helps — and it deserves to be said out loud.
    ///
    /// Deliberately conservative. The counter is subtree-wide, so a kill elsewhere in the subtree
    /// during this worker's lifetime can produce a false positive; that is the right direction to
    /// err, because the consequence is a more informative log line rather than a wrong decision.
    /// `None` means we cannot tell: no cgroup v2, `memory.events` unreadable, or the child has
    /// already been reaped so its pid no longer identifies it.
    #[cfg(unix)]
    pub fn died_of_host_oom(&mut self) -> Option<bool> {
        // Once reaped, the pid number may name an unrelated process, and `waitid` would be
        // answering about THAT one. The same guard `is_alive` and `exit_reason` carry, and here it
        // is the difference between "cannot tell" and claiming a host OOM because some stranger
        // that inherited the pid happened to be SIGKILLed. In the dispatcher's path `exit_reason`
        // runs first and probes without reaping, so the usual caller is unaffected.
        if self.reaped {
            return None;
        }
        let before = self.oom_kills_at_spawn?;
        let now = crate::memory::oom_kill_count()?;
        let killed_by_signal = matches!(
            probe_exit_nowait(self.child.id()),
            ExitProbe::Exited {
                signal: Some(libc::SIGKILL),
                ..
            }
        );
        Some(killed_by_signal && now > before)
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
            //
            // `reaped` is the second guard, and it is the one that matters on a repeat
            // call: once the child has been reaped its pid number is free, so the kernel
            // may have given it to an unrelated process group — and a blind
            // `kill(-pid, SIGKILL)` would then kill somebody else's processes.
            if pid != 0 && !self.reaped {
                // Name what is about to die before killing it. The blind group kill below is
                // enough to free the VRAM, but it logs nothing — so an operator who hit a
                // real orphan on this path had no way to know. `sweep_process_group` reports
                // and kills; the kill after it then takes the leader too (and covers a member
                // forked in the gap).
                let _ = sweep_process_group(pid, &self.backend);
                // Gated on the SAME refusal the sweep applies. Issuing `kill(-pid)`
                // unconditionally here voided that guarantee two lines after making it: if
                // `setpgid` had failed at spawn, the sweep would decline and this would kill
                // the miner's own group anyway, every live prover with it.
                if may_signal_group(pid) {
                    unsafe {
                        libc::kill(-(pid as i32), libc::SIGKILL);
                    }
                }
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill();
        }
        // BOUNDED, like `Drop`'s reap and for the same reason: SIGKILL does not land on a task in
        // uninterruptible sleep, and this call is made microseconds after SIGKILLing a CUDA process
        // — the likeliest place in the whole program to meet a D-state task inside a driver ioctl.
        //
        // A bare `wait()` here was the hazard that matters most, because of WHO is waiting. Every
        // caller of `kill()` holds the slot guard AND the per-GPU guard: the 20-proof recycle, the
        // stream-corruption path, the GPU-OOM path. A wedged reap there parks that card forever,
        // the proving watchdog cannot help (the thread is blocked in `wait`, not in `read`),
        // `abort_at` is never re-evaluated so the collateral strands, and `shutdown_all`'s final
        // blocking `slot.lock()` never returns — so the miner cannot even exit. Exactly the shape of
        // the `bus_id_for_slot` deadlock already fixed in this work.
        //
        // The cost of giving up is one zombie, which is bounded by the slot count and which
        // `Drop` tries again to collect. `reaped` records what actually happened: claiming a reap
        // that did not occur would let the group-kill guards believe the pid is free to recycle.
        self.reaped = reap_within(&mut self.child, DROP_REAP_BUDGET);
        if !self.reaped {
            tracing::warn!(
                "worker {} did not reap within {:?} after SIGKILL; leaving it as a zombie rather \
                 than blocking this GPU's slot. Its pid stays pinned, so no signal can land on a \
                 recycled number.",
                self.backend,
                DROP_REAP_BUDGET,
            );
        }
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

        // Nothing to do for a handle that has already reaped its child: the pid number is
        // free, so neither the sweep nor a group kill may use it. Checked rather than
        // assumed — the invariant "no kill(-pgid) after the reap" should hold by
        // construction, not by the order callers happen to use.
        if self.reaped {
            return;
        }

        // Try graceful shutdown
        let _ = self.send(&WorkerCommand::Shutdown);

        // Wait up to 5 seconds for the process to exit.
        //
        // The wait does NOT reap (see `probe_exit_nowait`). The old `try_wait` loop
        // returned early on a clean exit having ALREADY reaped, which freed the process-
        // group number before anything swept the group — so a `sp1-gpu-server` the worker
        // had forked survived the one shutdown path most likely to be taken, and became
        // unreachable: `Drop` then saw ECHILD and had nothing left to kill.
        let start = Instant::now();
        let timeout = Duration::from_secs(5);
        let pid = self.child.id();
        loop {
            #[cfg(unix)]
            let exited = match probe_exit_nowait(pid) {
                ExitProbe::Running => false,
                // Gone means somebody else reaped it; there is nothing left to sweep and
                // the pid number is no longer ours to signal.
                ExitProbe::Gone => {
                    self.reaped = true;
                    return;
                }
                ExitProbe::Exited { .. } => true,
            };
            #[cfg(not(unix))]
            let exited = matches!(self.child.try_wait(), Ok(Some(_)) | Err(_));

            if exited {
                let reason = self.exit_reason();
                tracing::info!("Worker {} exited ({reason})", self.backend);
                // Sweep BEFORE reaping, while the group number is still pinned.
                #[cfg(unix)]
                let _ = sweep_process_group(pid, &self.backend);
                let _ = self.child.wait();
                self.reaped = true;
                return;
            }
            if start.elapsed() > timeout {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
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
        // The common case is now ~2.2s, because phase 3 of `shutdown_all` has already
        // SIGKILLed the group and the first probe here sees `Exited`. The 10.2s worst case is
        // NOT eliminated: a worker whose `entry.pid` was momentarily 0 is skipped by phases 2
        // and 3, so this poll finds it `Running` and burns the full 2s before killing it.
        // Both callers bound the whole call off-thread, which is what makes that survivable.
        //
        // `waitid(WNOHANG|WNOWAIT)` reports the exit and LEAVES the zombie, which is what
        // keeps the pid -- and therefore the process-group NUMBER -- pinned until we are
        // done signalling it. `try_wait` would reap and free the number.
        #[cfg(unix)]
        if self.reaped {
            // Already reaped by `kill`/`shutdown`/`force_kill_group`, each of which swept
            // while the number was still pinned. Re-probing here would ask about whatever
            // process now owns that pid number, and signalling it would kill a stranger's
            // process group. Reached routinely: the 20-proof recycle, the OOM path, stream-
            // corruption recovery and the post-benchmark recycle all `kill()` and then drop.
        } else {
            let start = Instant::now();
            let timeout = Duration::from_secs(2);
            let mut state;
            loop {
                state = probe_exit_nowait(pid);
                if state != ExitProbe::Running {
                    break;
                }
                if start.elapsed() >= timeout {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }

            match state {
                // Reaped by something OUTSIDE this handle (`self.reaped` is false, or the
                // branch above would have been taken). We cannot sweep: the pid number is
                // free, so the kernel may already have handed it to an unrelated process
                // group and `kill(-pid, …)` would hit a stranger.
                //
                // This is a genuine gap, not a case already covered elsewhere: an outside
                // reaper taking the leader says nothing about a forked `sp1-gpu-server`. Say
                // so, because it is the one state in which a VRAM orphan can survive us.
                ExitProbe::Gone => {
                    tracing::warn!(
                        "worker {} (PID {pid}) was reaped outside its handle; its process group \
                         can no longer be swept safely — if a GPU helper was forked, check for a \
                         leftover sp1-gpu-server holding VRAM",
                        self.backend
                    );
                }

                // It ignored Shutdown. It must not outlive its handle: the group is pinned
                // by the live leader, so killing the group is both safe and necessary --
                // without it the `wait()` below would block forever.
                ExitProbe::Running => {
                    tracing::warn!(
                        "worker {} (PID {pid}) ignored Shutdown — SIGKILLing its process group",
                        self.backend
                    );
                    if pid != 0 {
                        // Same refusal as the sweep: never `kill(-our_own_pgid)`.
                        if may_signal_group(pid) {
                            unsafe {
                                libc::kill(-(pid as i32), libc::SIGKILL);
                            }
                        }
                        unsafe {
                            libc::kill(pid as i32, libc::SIGKILL);
                        }
                    }
                }

                // Exited, still a zombie. Kill anything it LEFT BEHIND -- and only that.
                //
                // This is the whole point of the fix: the old code `break`ed out of its
                // wait loop precisely when the worker had already exited -- the
                // death-and-respawn path drops the handle BECAUSE the worker died -- and so
                // never group-killed. A forked GPU helper (SP1's `sp1-gpu-server`, a 236MB
                // CUDA process) then outlived it as an orphan holding VRAM, unreachable
                // afterwards because the dispatcher zeroes the stored PID around dropping
                // dropping the handle. Measured in production: 10.3GB still held after the
                // miner exited, which starved the next run into CUDA OOM panics.
                //
                // The membership test is `live_group_members`, NOT `kill(-pid, 0)`: the
                // zombie leader is itself a member, so the old probe reported "members left
                // behind" on every clean exit -- 6 false alarms in one SP1-decline run, for
                // a worker that had forked nothing.
                ExitProbe::Exited { .. } => {
                    let _ = sweep_process_group(pid, &self.backend);
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill();
        }

        // Now reap -- BOUNDED. `wait()` blocks until the child is reapable, and SIGKILL does not
        // land on a process in uninterruptible sleep (a GPU helper inside a driver ioctl, or
        // paging a 236MB image in from a stalled mount). `proc::reap_briefly` bounds its reap for
        // exactly this reason; this one did not.
        #[cfg(unix)]
        {
            // Record what actually happened, not what we attempted. `reaped` is the flag every
            // group kill in this file consults before signalling a pid, so setting it
            // unconditionally after a FAILED reap records a false fact: it says the number may now
            // be recycled when the zombie is in fact still pinning it. Harmless here, since the
            // handle dies immediately after, but the flag should never lie.
            self.reaped = reap_within(&mut self.child, DROP_REAP_BUDGET);
            if !self.reaped {
                tracing::warn!(
                    "worker {} (PID {pid}) did not become reapable within {DROP_REAP_BUDGET:?}; \
                     abandoning the zombie rather than blocking the caller",
                    self.backend
                );
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.wait();
            self.reaped = true;
        }

        // Join the stderr forwarder -- BOUNDED, and this is the one that mattered.
        //
        // That thread ends on EOF of the worker's stderr pipe. The SP1 worker `dup2`s fd 1 onto
        // fd 2, so every grandchild -- `sp1-gpu-server` included -- inherits a copy of the write
        // end; only the IPC descriptor is CLOEXEC. So the join waits for the GPU HELPER, not for
        // the worker.
        //
        // The old `Drop` got away with an unbounded join by accident: its `kill(-pid, 0)` guard is
        // true for a zombie leader, so it group-killed unconditionally and the pipe always reached
        // EOF. The new sweep kills only when it finds a live member, and the `Gone` arm kills
        // nothing at all -- so an unbounded join here could block forever, holding the slot mutex
        // (`mark_slot_*` drops the handle under it) or parking the process-wide spawner thread
        // that every worker is forked from. That is the wedge `proc` was introduced to remove.
        if let Some(handle) = self.stderr_task.take() {
            let deadline = Instant::now() + STDERR_JOIN_BUDGET;
            while !handle.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                // Abandoned: it is blocked reading a pipe a surviving grandchild still holds. It
                // costs one thread and one fd, and it ends by itself when that process dies.
                tracing::warn!(
                    "worker {} (PID {pid}) stderr forwarder still blocked after \
                     {STDERR_JOIN_BUDGET:?} — a forked helper is holding the pipe. Abandoning the \
                     thread; if VRAM stays allocated, that helper is why",
                    self.backend
                );
            }
        }
    }
}

/// Bound on becoming reapable in `Drop`. A zombie is reaped instantly; this budget only matters
/// when the kernel has not finished tearing the process down.
const DROP_REAP_BUDGET: Duration = Duration::from_millis(300);

/// Bound on waiting for the stderr forwarder. Normally instant: the pipe is at EOF the moment the
/// last holder dies.
const STDERR_JOIN_BUDGET: Duration = Duration::from_millis(300);

/// `wait()` with a deadline. Returns false if the child is still not reapable.
///
/// Portable: `try_wait` works on every platform. Only the ECHILD arm below is Unix-specific, and it is
/// the only thing that ever kept this function — and its callers in `Drop` and `kill` — Unix-only.
fn reap_within(child: &mut Child, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            // ECHILD means somebody already reaped it, which is as good as us doing it. Any OTHER
            // error is not evidence of a reap, and claiming one is load-bearing: `shutdown()` early
            // -returns on `self.reaped`, so a spurious error here used to skip the group sweep and
            // leak the `sp1-gpu-server` that sweep exists to kill.
            #[cfg(unix)]
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => return true,
            Err(_) => return false,
            Ok(None) => {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{comm_from_stat, live_group_members, parse_stat_state_pgrp};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    /// A throwaway `/proc`-shaped tree. Removed on drop.
    struct FakeProc(PathBuf);

    impl FakeProc {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "zkminer-pgsweep-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        /// Write one `/proc/<pid>/stat` with the fields the sweep reads.
        fn proc(&self, pid: i32, comm: &str, state: char, ppid: i32, pgrp: i32) -> &Self {
            self.proc_raw(pid, comm.as_bytes(), state, ppid, pgrp)
        }

        /// As `proc`, but `comm` is raw BYTES.
        ///
        /// `comm` is whatever `prctl(PR_SET_NAME)` was handed and need not be UTF-8, and the
        /// previous helper took `&str` through `format!` — so it was structurally incapable of
        /// expressing the case the byte-oriented read exists for.
        fn proc_raw(&self, pid: i32, comm: &[u8], state: char, ppid: i32, pgrp: i32) -> &Self {
            let dir = self.0.join(pid.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            // Real layout: pid (comm) state ppid pgrp session tty_nr ...
            let mut line = format!("{pid} (").into_bytes();
            line.extend_from_slice(comm);
            line.extend_from_slice(
                format!(") {state} {ppid} {pgrp} {pgrp} 0 -1 4194304 0 0\n").as_bytes(),
            );
            std::fs::write(dir.join("stat"), line).unwrap();
            self
        }

        /// Non-pid entries exist in a real /proc (`self`, `meminfo`, …) and must be skipped.
        fn noise(&self) -> &Self {
            std::fs::create_dir_all(self.0.join("self")).unwrap();
            std::fs::write(self.0.join("meminfo"), "MemFree: 1 kB\n").unwrap();
            self
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for FakeProc {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// [D6] The end-to-end scenario, as it actually occurred. After a clean exit the
    /// worker is a ZOMBIE group leader, and a zombie keeps its own group non-empty — which
    /// is why `kill(-pgid, 0)` returned success on every clean stop and the "left
    /// process-group members behind … could orphan and hold VRAM" warning fired 6 times in
    /// one SP1-decline run, for a worker that had forked nothing at all.
    ///
    /// Two independent filters exclude it (`pid == pgid` and `state == 'Z'`), so this test
    /// alone cannot fail from either one regressing — it asserts the observable outcome.
    /// `live_leader_alone_is_not_a_leftover` and `zombie_helper_is_not_a_leftover` are the
    /// discriminators for the two filters; each fails when its own filter is removed
    /// (verified by restoring both bugs in turn).
    #[test]
    fn zombie_group_leader_is_not_a_leftover() {
        let fp = FakeProc::new("zombie-leader");
        fp.noise()
            .proc(100, "zkminer-prove-sp1", 'Z', 1, 100) // the worker we just shut down
            .proc(200, "unrelated", 'S', 1, 200); // somebody else's group
        assert!(
            live_group_members(fp.path(), 100)
                .expect("a readable tree")
                .is_empty(),
            "a zombie group leader holds no VRAM and is not something the worker left behind"
        );
    }

    /// The alarm must still fire for what it was written for: a forked GPU helper that
    /// outlived its parent still holding VRAM.
    #[test]
    fn live_forked_helper_is_a_leftover() {
        let fp = FakeProc::new("live-helper");
        fp.proc(100, "zkminer-prove-sp1", 'Z', 1, 100)
            .proc(101, "sp1-gpu-server", 'S', 100, 100)
            .proc(200, "unrelated", 'S', 1, 200);
        assert_eq!(
            live_group_members(fp.path(), 100).expect("a readable tree"),
            vec![(101, "sp1-gpu-server".to_string())],
            "a live group member other than the leader is exactly the leak this detects"
        );
    }

    /// A helper that has already died is not a leak either: a zombie holds no GPU memory,
    /// and it is reaped with the group when the leader is.
    #[test]
    fn zombie_helper_is_not_a_leftover() {
        let fp = FakeProc::new("zombie-helper");
        fp.proc(100, "zkminer-prove-sp1", 'Z', 1, 100)
            .proc(101, "sp1-gpu-server", 'Z', 100, 100);
        assert!(live_group_members(fp.path(), 100)
            .expect("a readable tree")
            .is_empty());
    }

    /// A worker that is still RUNNING is handled by `Drop`'s own `Running` arm (it
    /// SIGKILLs the group outright). The sweep reports only what was left BEHIND, so the
    /// live leader alone must not trip the warning.
    #[test]
    fn live_leader_alone_is_not_a_leftover() {
        let fp = FakeProc::new("live-leader");
        fp.proc(100, "zkminer-prove-sp1", 'R', 1, 100);
        assert!(live_group_members(fp.path(), 100)
            .expect("a readable tree")
            .is_empty());
    }

    /// `comm` is an unquoted basename that may contain spaces AND parentheses, so the
    /// fields after it must be found from the LAST `)`. A positional whitespace split
    /// reads `state`/`pgrp` out of the middle of the name and silently misclassifies
    /// every process — either missing a real leak or killing a live group.
    #[test]
    fn stat_fields_survive_a_hostile_comm() {
        let stat = "101 (sp1 gpu (server) :3) S 100 100 100 0 -1 4194304\n";
        assert_eq!(parse_stat_state_pgrp(stat), Some(('S', 100)));
        assert_eq!(comm_from_stat(stat).as_deref(), Some("sp1 gpu (server) :3"));

        // And the same hostile name must still be matched by the directory scan.
        let fp = FakeProc::new("hostile-comm");
        fp.proc(100, "zkminer-prove-sp1", 'Z', 1, 100).proc(
            101,
            "sp1 gpu (server) :3",
            'S',
            100,
            100,
        );
        assert_eq!(
            live_group_members(fp.path(), 100).expect("a readable tree"),
            vec![(101, "sp1 gpu (server) :3".to_string())]
        );
    }

    /// Truncated/raced reads must be skipped, not panic or count.
    #[test]
    fn unparseable_stat_is_ignored() {
        assert_eq!(parse_stat_state_pgrp("garbage with no paren"), None);
        assert_eq!(parse_stat_state_pgrp("101 (x) S 100"), None);
        assert_eq!(parse_stat_state_pgrp(""), None);
        assert_eq!(comm_from_stat(""), None);
    }

    /// A member whose `comm` is not UTF-8 must still be found.
    ///
    /// `prctl(PR_SET_NAME)` takes arbitrary bytes. With `read_to_string` such a process yields
    /// `Err(InvalidData)` and is skipped — and because the group kill is gated on this scan
    /// finding something, ONE such member meant no kill at all: the orphan keeps its VRAM and
    /// the alarm stays silent. Reverting the read to `read_to_string` makes this fail.
    #[test]
    fn a_non_utf8_comm_does_not_hide_a_leaked_member() {
        let fp = FakeProc::new("non-utf8");
        fp.proc(100, "zkminer-prove-sp1", 'Z', 1, 100)
            // Invalid UTF-8: a lone 0xFF byte cannot appear in any valid sequence.
            .proc_raw(101, b"sp1-gpu\xffserver", 'S', 100, 100);
        let found = live_group_members(fp.path(), 100).expect("a readable tree");
        assert_eq!(
            found.len(),
            1,
            "a non-UTF-8 comm must not hide the member: {found:?}"
        );
        assert_eq!(found[0].0, 101);
        assert!(
            found[0].1.contains('\u{FFFD}'),
            "the name should come through lossily rather than not at all: {:?}",
            found[0].1
        );
    }

    /// The self-group refusal. If `setpgid(0,0)` failed at spawn, the worker shares OUR group and
    /// `pgid` is not a group id — so sweeping it would `kill(-our_pgid, SIGKILL)`, killing the
    /// miner and every prover it is running. Nothing else stands in the way.
    #[test]
    #[cfg(unix)]
    fn the_sweep_refuses_to_signal_our_own_group() {
        let fp = FakeProc::new("self-group");
        // A populated group that WOULD otherwise be swept.
        fp.proc(100, "zkminer-prove-sp1", 'Z', 1, 100)
            .proc(101, "sp1-gpu-server", 'S', 100, 100);

        // The signaller is RECORDED, not performed. Injecting only the `/proc` scan was not
        // enough: the fake tree supplies a live member, so this call used to reach a real
        // `kill(-100, SIGKILL)` against the host kernel — harmless as an unprivileged user, and
        // somebody's live process group as root or in a container where pids are low.
        let signalled = std::cell::RefCell::new(Vec::new());
        let record = |pgid: i32| signalled.borrow_mut().push(pgid);

        // Treated as somebody else's group: reported AND signalled.
        assert_eq!(
            super::sweep_process_group_in(fp.path(), 100, "sp1", 999_999, &record),
            1,
            "a populated foreign group is exactly what the sweep is for"
        );
        assert_eq!(
            signalled.borrow().as_slice(),
            &[100],
            "it must signal the group it reported, and only that group"
        );

        // Treated as OUR group: refused, however populated it looks, and NOT signalled.
        signalled.borrow_mut().clear();
        assert_eq!(
            super::sweep_process_group_in(fp.path(), 100, "sp1", 100, &record),
            0,
            "the sweep must never signal our own process group"
        );
        assert!(
            signalled.borrow().is_empty(),
            "refusing must mean no signal, not just a zero return: signalling our own group \
             SIGKILLs the miner and every live prover"
        );
    }

    /// The refusal has to hold at the OTHER group-kill sites too. `force_kill_group` and `Drop`'s
    /// `Running` arm used to issue `kill(-pid, SIGKILL)` unconditionally two lines after the sweep
    /// declined, which voided the guarantee the sweep's own doc makes.
    #[test]
    #[cfg(unix)]
    fn our_own_pgid_is_never_a_legal_group_target() {
        let ours = unsafe { libc::getpgrp() } as u32;
        assert!(
            !super::may_signal_group(ours),
            "our own process-group id must never be a legal target"
        );
        assert!(
            !super::may_signal_group(0),
            "pid 0 means kill(-0) = our group"
        );
        // Any other pid is fair game; the sweep decides whether there is anything to kill.
        assert!(super::may_signal_group(ours.wrapping_add(1).max(1)));
    }

    // ---- against the real kernel, contrasting the old predicate with the new ----

    /// Spawn `sh -c <body>` as its own process-group leader, like a worker.
    #[cfg(unix)]
    fn spawn_group_leader(body: &str) -> std::process::Child {
        use std::os::unix::process::CommandExt;
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(body)
            .process_group(0)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn /bin/sh")
    }

    /// Block until `pid` is a zombie, WITHOUT reaping it — the exact state `Drop` inspects.
    #[cfg(unix)]
    fn wait_for_zombie(pid: u32) {
        for _ in 0..500 {
            match super::probe_exit_nowait(pid) {
                super::ExitProbe::Exited { .. } => return,
                super::ExitProbe::Gone => panic!("something reaped the child out from under us"),
                super::ExitProbe::Running => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        panic!("child never exited");
    }

    /// [D6] THE regression test, against the real kernel: for a worker that exited cleanly
    /// and forked nothing, the OLD predicate (`kill(-pgid, 0) == 0`) succeeds — that is why
    /// the "left process-group members behind … could orphan and hold VRAM" alarm fired on
    /// every clean stop — and the NEW predicate reports nothing.
    ///
    /// Both halves are asserted, so this fails if either the old behaviour returns or the
    /// new predicate stops being able to tell the two apart.
    #[test]
    #[cfg(unix)]
    fn a_zombie_leader_satisfies_the_old_guard_but_is_not_a_leftover() {
        let mut child = spawn_group_leader("exit 0");
        let pid = child.id();
        wait_for_zombie(pid);

        // The old guard: a zombie keeps its own group non-empty.
        let old_guard_fires = unsafe { libc::kill(-(pid as i32), 0) } == 0;
        assert!(
            old_guard_fires,
            "precondition: the old kill(-pgid, 0) guard must still succeed for a zombie \
             leader — if the kernel no longer behaves this way, the bug this test pins is gone"
        );

        // The new predicate: nothing was left behind.
        assert!(
            live_group_members(Path::new("/proc"), pid as i32)
                .expect("/proc is readable")
                .is_empty(),
            "a worker that forked nothing must raise no orphan alarm"
        );

        let _ = child.wait();
    }

    /// And the alarm must still fire for the case it exists for: the leader is gone but a
    /// forked helper in its group is alive and holding GPU memory.
    #[test]
    #[cfg(unix)]
    fn a_surviving_group_member_is_detected_and_killable() {
        // The leader forks a long sleeper (inheriting its group) and exits immediately.
        let mut child = spawn_group_leader("sleep 300 & exit 0");
        let pid = child.id();
        wait_for_zombie(pid);

        // Give the grandchild a moment to appear in /proc.
        let mut members = Vec::new();
        for _ in 0..200 {
            members =
                live_group_members(Path::new("/proc"), pid as i32).expect("/proc is readable");
            if !members.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !members.is_empty(),
            "a live forked helper in the worker's group is exactly what must be reported"
        );
        let leaked = members[0].0;
        assert_ne!(
            leaked, pid as i32,
            "the leader itself must never be reported"
        );

        // The group kill the alarm triggers must actually reach it.
        unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
        let mut gone = false;
        for _ in 0..200 {
            if live_group_members(Path::new("/proc"), pid as i32)
                .expect("/proc is readable")
                .is_empty()
            {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.wait();
        if !gone {
            // Do not leak a `sleep 300` into the rest of the suite on failure.
            unsafe { libc::kill(leaked, libc::SIGKILL) };
        }
        assert!(
            gone,
            "kill(-pgid, SIGKILL) must clear the leaked member (pid {leaked})"
        );
    }

    /// `probe_exit_nowait` must not reap: the pid — and with it the group number the sweep
    /// signals — has to stay pinned across repeated probes. This is the property that
    /// `try_wait` broke.
    #[test]
    #[cfg(unix)]
    fn the_exit_probe_does_not_reap() {
        let mut child = spawn_group_leader("exit 7");
        let pid = child.id();
        wait_for_zombie(pid);
        for i in 0..5 {
            match super::probe_exit_nowait(pid) {
                super::ExitProbe::Exited { code, signal } => {
                    assert_eq!(code, Some(7), "exit code must survive probe {i}");
                    assert_eq!(signal, None);
                }
                other => panic!("probe {i} lost the zombie: {other:?}"),
            }
            // Still signallable, i.e. the group number is still ours.
            assert_eq!(unsafe { libc::kill(-(pid as i32), 0) }, 0);
        }
        let _ = child.wait();
        assert!(
            matches!(super::probe_exit_nowait(pid), super::ExitProbe::Gone),
            "after the real reap the probe must report Gone, so nothing signals a freed pid"
        );
    }

    /// A signal death must be reported as one, because `exit_reason` is what distinguishes an
    /// external SIGKILL (the OOM killer, a watchdog) from a panic or a clean shutdown.
    #[test]
    #[cfg(unix)]
    fn a_signalled_child_is_reported_as_signalled() {
        let mut child = spawn_group_leader("sleep 300");
        let pid = child.id();
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        wait_for_zombie(pid);
        match super::probe_exit_nowait(pid) {
            super::ExitProbe::Exited { signal, code } => {
                assert_eq!(signal, Some(libc::SIGKILL));
                assert_eq!(code, None);
            }
            other => panic!("expected a signalled exit, got {other:?}"),
        }
        let _ = child.wait();
    }

    /// An empty or absent `/proc` yields no members rather than an error or a panic.
    ///
    /// Note what that costs, because the silence is not free: with `/proc` unreadable the sweep
    /// finds nothing, so a real orphan keeps its VRAM and is never killed. The exposure is
    /// small — `hidepid` hides OTHER users' processes and the workers run as us — but "no
    /// members" here means "we could not look", not "nothing leaked".
    #[test]
    fn missing_proc_root_reports_no_members() {
        // NotFound is "nothing there", which is an answer; any OTHER error is "we could not
        // look", which must not be reported as "nothing leaked" — the sweep kills blind instead.
        assert_eq!(
            live_group_members(Path::new("/nonexistent-proc-root"), 100),
            None,
            "an unreadable tree must be distinguishable from an empty one"
        );
    }
}
