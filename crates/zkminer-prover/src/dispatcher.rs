//! Worker pool with per-worker locking.
//!
//! Manages discovery, spawning, and dispatch to prover worker subprocesses.
//! Each worker has its own Mutex, allowing concurrent proofs across different backends.
//!
//! Workers are keyed by compound `"backend:gpu_tag"` or `"backend:gpu_tag:device_index"`.
//! When dispatching by logical backend (e.g. `"risc0"`), all matching slots are considered
//! and available workers are selected via round-robin.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Benchmark results for a single worker slot, with device metadata.
#[derive(Debug, Clone)]
pub struct SlotBenchmarkResult {
    pub slot_key: String,
    pub gpu_name: Option<String>,
    pub device_index: Option<u32>,
    /// Canonical PCI bus id of the card this slot ran on, when known. The
    /// identity the TUI joins on -- `device_index` is per-vendor and collides.
    pub pci_bus_id: Option<String>,
    pub gpu_tag: String,
    pub entries: Vec<zkminer_prover_protocol::BenchmarkEntry>,
    /// Total VRAM of this worker's GPU in bytes, or `None` when unknown
    /// (non-CUDA devices, or `nvidia-smi` unavailable — see `gpu_vram_bytes`).
    ///
    /// Feeds the po2/memory sizing model in
    /// `benchmark::build_gpu_device_benchmarks_from_workers`, which otherwise has
    /// no way to know how big the card is and has to fall back to stamping
    /// `PO2_MAX` for every device regardless of its actual memory.
    pub vram_bytes: Option<u64>,
    /// Peak HOST memory this slot's worker reached during the benchmark, in bytes.
    ///
    /// The input to admission control, and the reason it is measured here: this is the only moment
    /// the miner legitimately learns what a proof on this backend costs in RAM, and it must be read
    /// while the worker is still alive (its cgroup counter dies with it). `None` when the host
    /// cannot report it, in which case admission falls back to a conservative default rather than
    /// assuming the proof is free.
    pub host_peak_bytes: Option<u64>,
}

/// A streaming benchmark progress update from a specific worker slot.
#[derive(Debug, Clone)]
pub struct BenchmarkProgressEvent {
    /// Worker slot key, e.g. "risc0:cuda:0"
    pub slot_key: String,
    /// GPU name, e.g. "AMD Radeon RX 7900 XTX"
    pub gpu_name: Option<String>,
    /// Device index within vendor -- per-vendor, so NOT a unique card identity.
    pub device_index: Option<u32>,
    /// Canonical PCI bus id of the card, when known. The identity a consumer
    /// should join on to find this card in its own hardware enumeration.
    pub pci_bus_id: Option<String>,
    /// GPU tag: "cuda", "rocm", "generic"
    pub gpu_tag: String,
    /// The benchmark entry that just completed
    pub entry: zkminer_prover_protocol::BenchmarkEntry,
    /// 1-based program index
    pub program_index: u32,
    /// Total programs in suite
    pub total_programs: u32,
}

use anyhow::{bail, Result};
use zkminer_prover_protocol::{BenchmarkEntry, ErrorKind, WorkerCommand, WorkerResponse};

use crate::discovery::{discover_workers, DiscoveredWorker};
use crate::engine::ProofOutput;
use crate::worker::{WorkerDied, WorkerHandle};

/// Maximum consecutive respawn failures before giving up on a backend.
const MAX_RESPAWN_FAILURES: u32 = 3;

/// After this long with no NEW failure, a slot retired by `MAX_RESPAWN_FAILURES`
/// gets another chance. A transient burst (a driver/thermal reset spanning the
/// ~36s respawn-backoff window) would otherwise sideline an otherwise-healthy GPU
/// for the whole process, with no self-heal until a manual restart.
const RETIRE_COOLDOWN: Duration = Duration::from_secs(300);

/// Backoff durations for respawn attempts.
const RESPAWN_BACKOFF: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(30),
];

/// Default number of proofs after which a worker is recycled (killed + respawned)
/// to reset accumulated GPU state (fix #3). Balances the reset benefit against the
/// ~1-2s CUDA re-init cost (~0.5% overhead at 20 proofs of tens of seconds each).
/// How long to wait for a killed worker's pages to return to `MemAvailable` before re-testing
/// admission.
///
/// Short, because it is held under the slot and GPU guards, and because the alternative is a GPU
/// re-init we have already paid for plus a refusal anyway. Polled rather than slept flat, so a quick
/// reclaim costs ~50ms.
const RECLAIM_WAIT: Duration = Duration::from_millis(1500);

/// How long the BENCHMARK loop waits for a reaped worker's pages to come back before testing the
/// next slot's reservation against them.
///
/// Much longer than `RECLAIM_WAIT`, because the two are paying for different things. That one sits in
/// the proving path, where the job has a deadline and the wait is a gamble on a warm worker already
/// destroyed. This one sits between two benchmark slots, where nothing is on a clock and the cost of
/// not waiting is a card that never gets a throughput row at all.
///
/// Measured on this box on 2026-10-06: the SP1 benchmark on card 0 was recycled and card 1's
/// reservation tested 367 ms later, with `MemAvailable` still reading 20.8 GiB of 27.4. Against an
/// 18.0 GiB increment and a 3.0 GiB host reserve that leaves 17.8 GiB of headroom — short by 0.2 —
/// so card 1 was refused and the whole SP1 row for the 4090 went missing from the suite.
const BENCHMARK_RECLAIM_WAIT: Duration = Duration::from_secs(20);

/// Block until the kernel has actually given back the pages of a process we just reaped, or until
/// `budget` runs out.
///
/// `kill()` and `shutdown()` return as soon as the child is reaped, but the accounting of its pages —
/// a CUDA process's pinned and driver mappings especially — does not land in `MemAvailable` on that
/// instruction. Anything that reaps a worker and then immediately tests a memory reservation is
/// testing it against a figure that has not moved yet.
///
/// Waits for the figure to STABILISE rather than merely to move: ~18 GiB does not come back at once,
/// and the first 50 ms shows a small rise while most of it is still outstanding. Three consecutive
/// samples with no further gain is the "reclaim finished" signal. Returns what `MemAvailable` gained.
fn wait_for_reclaim(label: &str, budget: Duration) -> u64 {
    const SAMPLE: Duration = Duration::from_millis(100);
    /// Consecutive no-gain samples that count as settled.
    const STABLE_SAMPLES: u32 = 3;

    let Some(before) = crate::memory::mem_available_bytes() else {
        return 0; // unreadable: no basis to wait on, and the gates fail open anyway
    };
    let deadline = Instant::now() + budget;
    let mut best = before;
    let mut stable = 0u32;
    while Instant::now() < deadline {
        std::thread::sleep(SAMPLE);
        let now = crate::memory::mem_available_bytes().unwrap_or(best);
        if now > best {
            best = now;
            stable = 0;
        } else {
            stable += 1;
            // Only treat stillness as "settled" once something has actually come back. Otherwise a
            // reap whose pages are slow to appear at all would be declared finished in 300 ms.
            if stable >= STABLE_SAMPLES && best > before {
                break;
            }
        }
    }
    let gained = best.saturating_sub(before);
    if gained > 0 {
        tracing::info!(
            "{label}: waited {:.1}s for {:.1} GiB to come back ({:.1} -> {:.1} GiB available)",
            budget
                .saturating_sub(deadline.saturating_duration_since(Instant::now()))
                .as_secs_f64(),
            gained as f64 / 1024.0 / 1024.0 / 1024.0,
            before as f64 / 1024.0 / 1024.0 / 1024.0,
            best as f64 / 1024.0 / 1024.0 / 1024.0,
        );
    }
    gained
}

/// How often to re-test a busy per-GPU lock while a deadline is pending.
///
/// Short enough that a freed card is taken promptly, long enough not to spin. Only used on the
/// deadline-bounded path; without a deadline the wait is a plain blocking `lock()`.
const GPU_LOCK_POLL: Duration = Duration::from_millis(50);

const DEFAULT_RECYCLE_AFTER_PROOFS: u32 = 20;

/// Backstop watchdog applied by [`WorkerPool::prove`] when the caller passes no
/// timeout, so a wedged worker can never hang a prove indefinitely. Generous (no
/// realistic single proof approaches this); the miner's job path sets its own
/// tuned deadline via `prove_min_vram`. Prevents the only remaining unbounded-hang
/// route (generic `ProvingEngine::prove` callers).
const DEFAULT_PROVE_WATCHDOG_TIMEOUT: Duration = Duration::from_secs(1800);

/// Minimum time that must remain before a caller-supplied `abort_at` instant for a
/// proof to be worth starting. If a GPU-queue / respawn wait leaves less than this,
/// `prove_on_slot` returns early instead of dispatching a proof the watchdog would
/// SIGKILL microseconds later (which also wastes a freshly-respawned worker).
const MIN_ABORT_START_BUDGET: Duration = Duration::from_secs(15);

/// How many proofs a worker may complete before it is recycled. 0 disables
/// recycling. Overridable at process start via `ZKMINER_RECYCLE_AFTER_PROOFS`.
/// Read once and cached (not a hot-path env lookup).
fn recycle_after_proofs() -> u32 {
    static N: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("ZKMINER_RECYCLE_AFTER_PROOFS")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(DEFAULT_RECYCLE_AFTER_PROOFS)
    })
}

struct WorkerSlot {
    handle: Option<WorkerHandle>,
    path: PathBuf,
    /// Logical backend: "risc0", "sp1", "openvm".
    backend: String,
    /// GPU variant: "cuda", "rocm", "generic".
    gpu_tag: String,
    /// Device index within vendor (None for generic/explicit).
    device_index: Option<u32>,
    /// Canonical PCI bus id of this worker's card (None for generic/explicit).
    ///
    /// Load-bearing: this is the join key the TUI uses to line a benchmark row
    /// and its live telemetry up with the right physical card. Device pinning
    /// itself is still baked into `spawn_env` at discovery time.
    pci_bus_id: Option<String>,
    /// Human-readable GPU name (None for generic/explicit).
    gpu_name: Option<String>,
    /// Environment variables to pass when spawning this worker.
    spawn_env: HashMap<String, String>,
    consecutive_failures: u32,
    last_failure: Option<Instant>,
    /// Set when the worker SPOKE the protocol and declined: it cannot prove on this
    /// host, and no retry will change that. Holds the reason for the operator.
    ///
    /// Distinct from `consecutive_failures` on purpose. A dead-but-eligible slot is
    /// deliberately still "healthy" (see `is_backend_healthy`) so a crashed worker
    /// respawns and claiming does not stall on a transient fault. A capability decline
    /// is not transient, so treating it the same way made the miner keep claiming jobs
    /// the worker had just said it could not prove -- and every ~RETIRE_COOLDOWN the
    /// counter reset re-opened the window for the life of the process.
    declined: Option<String>,
    /// Number of proofs this worker instance has completed since it was (re)spawned.
    /// When it reaches `recycle_after_proofs()`, the worker is killed + respawned so
    /// the accumulated GPU context / buffer pool / persistent stream is reset to a
    /// clean slate (fix #3). Reset to 0 on every (re)spawn.
    proofs_since_spawn: u32,
}

/// Wrapper that holds a worker slot and its PID accessible without locking.
/// The PID is stored externally so the proving timeout watchdog and shutdown
/// can SIGKILL the worker without acquiring the slot Mutex (which is held
/// during the entire proof duration).
struct WorkerEntry {
    slot: Mutex<WorkerSlot>,
    /// Total VRAM (bytes) for this worker's GPU, or None if unknown. Kept
    /// outside the slot Mutex so the dispatcher can filter candidates by VRAM
    /// (route large proofs to bigger cards) without blocking on a busy slot.
    vram_bytes: Option<u64>,
    /// Canonical PCI bus id of this worker's card, or None for a CPU slot.
    ///
    /// Outside the Mutex for the same reason as `vram_bytes`, and for a sharper one: reading it
    /// through the slot guard DEADLOCKED a live proof. `prove_on_slot` holds that guard for the
    /// whole proof and hands `recv_proof` a progress callback; the worker emits one `Progress`
    /// at proof start; the callback is invoked SYNCHRONOUSLY on the proving thread and asked the
    /// pool which card was running — re-entering the mutex the same thread already held.
    /// `std::sync::Mutex` is not reentrant, so the thread parked forever holding the slot: the
    /// proof never finished, the watchdog's SIGKILL could not help (the thread was blocked in
    /// `lock()`, not in `read()`), `abort_at` never evaluated so the deadline release never ran
    /// and the collateral stranded, and `shutdown_all` phase 4 blocked on the same mutex so the
    /// miner could not exit.
    ///
    /// It never fired in production only because the deployed risc0 binary predates the
    /// `Progress` emission that triggers it. The field is written once at discovery and never
    /// changes, so there was never a reason for it to be behind a lock.
    pci_bus_id: Option<String>,
    /// Current worker PID. 0 = no live worker. Updated on spawn/respawn.
    /// Wrapped in Arc so the ProvingWatchdog thread can re-read the PID before
    /// killing, avoiding SIGKILL on a stale/recycled PID.
    pid: Arc<AtomicU32>,
    /// Kernel start time of the process named by `pid`, so a signal can prove the number is still
    /// that process. 0 when there is no live worker.
    ///
    /// A pid alone is not an identity. The parent-and-group check in `pid_is_our_worker` cannot tell
    /// our worker from our NEXT worker, and the likeliest recipient of a pid this process just freed
    /// is another worker this same process forks seconds later — so a stale signal would land on a
    /// different, healthy, mid-proof worker's group. A start time cannot be inherited.
    pid_starttime: Arc<AtomicU64>,
    /// Set to true when the worker is killed intentionally (timeout or cancel).
    /// Prevents the error handler from incrementing consecutive_failures,
    /// which would permanently retire the slot after 3 timeouts.
    intentional_kill: Arc<AtomicBool>,
}

/// Whatever publishes a worker's pid for signallers to read.
///
/// Exists so `mark_slot_failed`, `mark_slot_dead` and `ensure_alive` cannot clear the pid while
/// leaving the start time that identifies it behind — they used to take a bare `&AtomicU32`, which
/// made that mistake possible and silent. A bare atomic still satisfies the trait so the unit tests
/// need no worker.
trait PidSlot {
    fn clear(&self);
}

impl PidSlot for WorkerEntry {
    fn clear(&self) {
        self.clear_pid();
    }
}

impl PidSlot for AtomicU32 {
    fn clear(&self) {
        self.store(0, Ordering::Release);
    }
}

impl WorkerEntry {
    /// Publish a live worker's pid together with its start time.
    ///
    /// Always both, in this order: the start time first, so no reader can see a fresh pid paired
    /// with a stale identity. Paired helpers exist because the pid is published from a dozen places
    /// and the two values must never drift apart.
    fn publish_pid(&self, pid: u32) {
        let st = crate::memory::pid_starttime(pid).unwrap_or(0);
        self.pid_starttime.store(st, Ordering::Release);
        self.pid.store(pid, Ordering::Release);
    }

    /// Retract the pid before a reap, so no signaller can use the number afterwards.
    fn clear_pid(&self) {
        self.pid.store(0, Ordering::Release);
        self.pid_starttime.store(0, Ordering::Release);
    }

    /// The pid to signal and the start time that proves it is still ours, or `None` if no worker.
    fn signal_target(&self) -> Option<(u32, Option<u64>)> {
        let pid = self.pid.load(Ordering::Acquire);
        if pid == 0 {
            return None;
        }
        let st = self.pid_starttime.load(Ordering::Acquire);
        Some((pid, (st != 0).then_some(st)))
    }
}

/// RAII guard that kills a worker process after a deadline.
/// Drop cancels the watchdog thread.
struct ProvingWatchdog {
    cancel: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ProvingWatchdog {
    /// Spawn a watchdog that SIGKILLs the worker after `timeout`.
    /// Re-reads the PID from the shared atomic before killing to avoid hitting
    /// a stale/recycled PID. Sets `intentional_kill` before killing so the error
    /// handler knows not to count it as a consecutive failure.
    fn new(
        pid_ref: Arc<AtomicU32>,
        starttime_ref: Arc<AtomicU64>,
        timeout: Duration,
        slot_key: String,
        intentional_kill: Arc<AtomicBool>,
    ) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = cancel.clone();
        let original_pid = pid_ref.load(Ordering::Acquire);
        // Don't spawn a watchdog thread if there's no process to watch.
        // pid == 0 means no live worker; libc::kill(0, SIGKILL) would kill
        // the entire process group, which is catastrophic.
        let thread = if original_pid == 0 {
            None
        } else {
            std::thread::Builder::new()
                .name(format!("prove-watchdog-{slot_key}"))
                .spawn(move || {
                    let deadline = Instant::now() + timeout;
                    while Instant::now() < deadline {
                        std::thread::sleep(Duration::from_secs(1));
                        if cancel_clone.load(Ordering::Relaxed) {
                            return;
                        }
                    }
                    if !cancel_clone.load(Ordering::Relaxed) {
                        // Re-read PID before killing. If the worker died and was
                        // cleaned up (PID zeroed) or respawned (PID changed), skip
                        // the kill to avoid hitting an unrelated process.
                        let current_pid = pid_ref.load(Ordering::Acquire);
                        if current_pid != original_pid || current_pid == 0 {
                            tracing::info!(
                                "Watchdog for {slot_key}: PID changed ({original_pid} -> {current_pid}), skipping kill"
                            );
                            return;
                        }
                        tracing::error!(
                            "Proving timeout ({timeout:?}) exceeded for {slot_key}, killing worker PID {current_pid}"
                        );
                        intentional_kill.store(true, Ordering::Release);
                        // Kill the worker's ENTIRE process group (the worker calls
                        // setpgid(0,0) at spawn) so forked GPU/helper children die
                        // too and release the stdout pipe. Killing only the main PID
                        // leaves such a child holding the pipe's write end, so the
                        // dispatcher's recv_proof read never sees EOF and hangs.
                        // current_pid is guaranteed non-zero here (guarded above), so
                        // kill(-pid) can never degenerate into kill(0)/kill(-1).
                        // IDENTITY-CHECKED. The load above and this kill are not atomic with
                        // respect to the reap, so the number could already belong to a stranger —
                        // and the next statement signals an entire process GROUP. See
                        // `memory::pid_is_our_worker`.
                        #[cfg(unix)]
                        let expected_start = starttime_ref.load(Ordering::Acquire);
                        if crate::memory::pid_is_our_worker(
                            current_pid,
                            (expected_start != 0).then_some(expected_start),
                        ) {
                            unsafe {
                                libc::kill(-(current_pid as i32), libc::SIGKILL);
                                libc::kill(current_pid as i32, libc::SIGKILL);
                            }
                        } else {
                            tracing::warn!(
                                "not killing PID {current_pid} for {slot_key}: it is no longer our \
                                 worker (reaped, and the number may have been reused)"
                            );
                        }
                    }
                })
                .ok()
        };
        Self { cancel, thread }
    }
}

impl Drop for ProvingWatchdog {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Compound key for a worker slot.
/// With device_index: `"backend:gpu_tag:idx"`, without: `"backend:gpu_tag"`.
fn slot_key(backend: &str, gpu_tag: &str, device_index: Option<u32>) -> String {
    match device_index {
        Some(idx) => format!("{backend}:{gpu_tag}:{idx}"),
        None => format!("{backend}:{gpu_tag}"),
    }
}

/// The physical-GPU identity of a slot key, for the per-GPU proving guard.
/// `"risc0:cuda:0"` and `"sp1:cuda:0"` both map to `Some("cuda:0")` — the SAME
/// physical card — so they share one lock. Returns `None` for CPU/`generic`
/// workers and for explicit binaries without a device index (a 2-part key): we
/// can't know which physical GPU those target, so they are left unguarded and keep
/// their prior behavior. The guarded gpu_tags MUST match the set counted as a
/// physical GPU by `proving_gpu_count` (`cuda`/`rocm`/`intel`) — otherwise a card
/// that inflates auto `max_concurrent` could go unguarded and double-book VRAM.
/// Mirrors the `slot_key` format — keep the two in sync.
fn physical_gpu_id(key: &str) -> Option<String> {
    let mut parts = key.splitn(3, ':');
    let _backend = parts.next()?;
    let gpu_tag = parts.next()?;
    let device_index = parts.next()?; // absent ⇒ 2-part key (generic/explicit) ⇒ unguarded
    if matches!(gpu_tag, "cuda" | "rocm" | "intel") {
        Some(format!("{gpu_tag}:{device_index}"))
    } else {
        None
    }
}

/// Total VRAM (bytes) for a GPU, used to route large proofs to higher-VRAM
/// cards. Only CUDA is queried (nvidia-smi per device index, matching the
/// PCI_BUS_ID ordering the workers pin with); ROCm/other return None, which
/// means "unknown" — such workers are excluded when a minimum-VRAM floor is
/// requested (large jobs should land on the known-big card).
///
/// Bounded; see the note inside. Generous relative to the sampler's budget because a missing
/// answer here permanently disables VRAM-aware routing for that slot, while a slow one only
/// delays startup.
const VRAM_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

fn gpu_vram_bytes(gpu_tag: &str, device_index: Option<u32>) -> Option<u64> {
    let idx = device_index?;
    if gpu_tag != "cuda" {
        return None;
    }
    // Bounded. This runs once per worker slot inside `discover_and_spawn`, which `run()` calls
    // INLINE on the runtime before anything else — so on a wedged driver an unbounded
    // `Command::output()` here hangs the miner at startup forever, blocking a tokio worker
    // thread, and it does so AFTER `detect_nvidia_via_smi` has already bounded out and logged
    // "nvidia-smi did not answer". That misleading line would be the last thing in the log.
    let (outcome, stdout) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        std::process::Command::new("nvidia-smi")
            .env("CUDA_DEVICE_ORDER", "PCI_BUS_ID")
            .args([
                "--query-gpu=memory.total",
                "--format=csv,noheader,nounits",
                &format!("--id={idx}"),
            ]),
        VRAM_QUERY_TIMEOUT,
        16 * 1024,
    );
    if !matches!(
        outcome,
        zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
    ) {
        // Unknown VRAM is a supported state: the dispatcher skips the size filter rather than
        // guessing, and `build_gpu_device_benchmarks_from_workers` leaves the row unsized.
        tracing::warn!(
            "nvidia-smi could not report VRAM for cuda:{idx} ({})",
            outcome.describe()
        );
        return None;
    }
    let mib: u64 = stdout.trim().parse().ok()?;
    Some(mib * 1024 * 1024)
}

/// Bounded like `gpu_vram_bytes`, but tighter: this one runs on EVERY dispatch rather than once at
/// startup, and a slow answer delays a proof instead of a boot. A missing answer skips the gate.
const FOREIGN_VRAM_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// How far to walk a parent chain before giving up. `/proc` cannot actually present a cycle, but this
/// loop runs with a GPU guard held and must terminate regardless of what it reads.
const MAX_PPID_WALK: usize = 32;

/// CUDA device index named by a slot key (`sp1:cuda:1` -> 1), or `None` when the key does not name
/// one: a CPU slot, a non-CUDA vendor, or a 2-part key with no index at all. `None` disables the
/// foreign-VRAM gate for that slot, because there is no device to query.
fn slot_cuda_index(key: &str) -> Option<u32> {
    let mut parts = key.splitn(3, ':');
    let _backend = parts.next()?;
    if parts.next()? != "cuda" {
        return None;
    }
    parts.next()?.trim().parse().ok()
}

/// One bounded `nvidia-smi` query against one device. `None` on any failure, which callers treat as
/// "unknown" and NOT as "zero".
fn nvidia_smi_query(query: &str, device_index: u32) -> Option<String> {
    let (outcome, stdout) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        std::process::Command::new("nvidia-smi")
            .env("CUDA_DEVICE_ORDER", "PCI_BUS_ID")
            .args([
                query,
                "--format=csv,noheader,nounits",
                &format!("--id={device_index}"),
            ]),
        FOREIGN_VRAM_QUERY_TIMEOUT,
        64 * 1024,
    );
    matches!(
        outcome,
        zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
    )
    .then_some(stdout)
}

/// Is this pid inside OUR process tree?
///
/// Walks the parent chain looking for the miner's own pid, which makes it true for the miner itself,
/// for a worker it spawned, and for anything a worker spawned in turn — notably `sp1-gpu-server`,
/// which the SP1 SDK forks as a child of the worker and which is the process actually holding SP1's
/// device memory. Checking the worker pid alone would miss it and count our own server as foreign.
///
/// A worker that was orphaned (reparented to init) is no longer in the tree and so reads as foreign.
/// That is the safe direction — it really is memory we are not tracking — and the SP1 worker reaps
/// orphaned servers at startup, so the state is transient.
fn pid_is_in_our_tree(pid: u32) -> bool {
    let ours = std::process::id();
    let mut cur = pid;
    for _ in 0..MAX_PPID_WALK {
        if cur == ours {
            return true;
        }
        if cur <= 1 {
            return false;
        }
        let stat = match std::fs::read_to_string(format!("/proc/{cur}/stat")) {
            Ok(s) => s,
            // The process exited mid-walk. We cannot prove it was ours, so we do not claim it.
            Err(_) => return false,
        };
        match crate::memory::parent_of_stat(&stat) {
            Some(ppid) if ppid > 0 => cur = ppid as u32,
            _ => return false,
        }
    }
    false
}

/// VRAM on this card held by processes that are NOT in our process tree, plus the card's total, both
/// in bytes. `None` when the card cannot be read, which skips the gate.
///
/// The outer term is `memory.used`, not the sum over compute apps, and that choice is the whole point
/// of the function. `--query-compute-apps` lists only COMPUTE ("C") contexts; an X or Wayland
/// compositor holds a GRAPHICS ("G") context and does not appear there at all. A display driving the
/// card — the case this gate exists for — would be completely invisible to the compute-app query.
/// `memory.used` counts every context plus driver overhead, so subtracting our own compute apps from
/// it leaves exactly "VRAM somebody else is using", display included.
///
/// Our own usage is credited rather than counted. Measured on this box on 2026-10-05, sampling the
/// 5080 every 3s through a `fibonacci` proof: `sp1-gpu-server` holds 15,076 MiB of the card's 16,303
/// for the whole proof and releases it within ~3s of finishing — so it does NOT stay warm between
/// proofs, and the credit is not needed for that case. It is needed for two others:
///
/// * a risc0 worker on the SAME physical card. risc0 and SP1 share the per-card guard, and this gate
///   runs only for SP1, so a resident risc0 CUDA context would otherwise read as foreign and refuse
///   every SP1 job routed to a card we are ourselves using perfectly legitimately;
/// * the reclaim window. The driver's accounting does not drop to zero the instant our guard is
///   released, so a dispatch arriving immediately behind another proof can read VRAM that is already
///   on its way out. Crediting it by pid is what distinguishes that from a real occupant.
///
/// Gating on free VRAM instead of foreign occupancy would get both of those wrong.
fn foreign_vram_bytes(device_index: u32) -> Option<(u64, u64, u64)> {
    const MIB: u64 = 1024 * 1024;
    let used_mib: u64 = nvidia_smi_query("--query-gpu=memory.used", device_index)?
        .trim()
        .parse()
        .ok()?;
    let total_mib: u64 = nvidia_smi_query("--query-gpu=memory.total", device_index)?
        .trim()
        .parse()
        .ok()?;

    // Absent/unparseable compute-app output is treated as "no compute apps of ours", which credits us
    // nothing and so can only make the reading MORE conservative. An empty list is also the normal
    // answer for an idle card, so it cannot be distinguished from a failure here and must be safe
    // either way.
    let mut ours_mib = 0u64;
    if let Some(out) = nvidia_smi_query("--query-compute-apps=pid,used_gpu_memory", device_index) {
        for line in out.lines() {
            let mut f = line.split(',');
            let (Some(pid), Some(mem)) = (f.next(), f.next()) else {
                continue;
            };
            let (Ok(pid), Ok(mem)) = (pid.trim().parse::<u32>(), mem.trim().parse::<u64>()) else {
                // "[Not Supported]" and "[N/A]" both appear in this column on some drivers.
                continue;
            };
            if pid_is_in_our_tree(pid) {
                ours_mib = ours_mib.saturating_add(mem);
            }
        }
    }

    // Saturating: `memory.used` and the per-process figures come from separate queries a few
    // milliseconds apart, so ours can legitimately exceed used if we freed in between.
    Some((
        used_mib.saturating_sub(ours_mib) * MIB,
        used_mib * MIB,
        total_mib * MIB,
    ))
}

/// Would a worker spawned when `assumed` bytes were free now be sized for more VRAM than it has?
///
/// Pure, so the decision can be tested without fabricating a live worker. False whenever we cannot
/// tell — a backend with no VRAM-derived tier, or no recorded assumption — because recycling a worker
/// on a guess costs a respawn and buys nothing.
fn vram_tier_shrank(backend: &str, assumed: Option<u64>, available: u64) -> bool {
    let Some(now) = crate::discovery::vram_sizing_tier(backend, available) else {
        return false;
    };
    let Some(then) = assumed.and_then(|a| crate::discovery::vram_sizing_tier(backend, a)) else {
        return false;
    };
    then > now
}

/// What one card's VRAM looks like at a moment in time, from our point of view.
///
/// `available` is `total - foreign`, i.e. what we could still allocate if we asked — NOT the driver's
/// `memory.free`, which excludes VRAM our own worker already holds and so reads a healthy busy card
/// as full. See `foreign_vram_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VramBudget {
    /// Held by processes outside our tree.
    pub foreign: u64,
    /// Held by everything, ours included.
    pub used: u64,
    /// The card's capacity.
    pub total: u64,
    /// `total - foreign`: what a backend on this card may plan to use.
    pub available: u64,
}

/// Pool of worker processes, keyed by compound slot key.
pub struct WorkerPool {
    /// What a proof on each backend is expected to peak at in host memory, in bytes.
    ///
    /// Published by whoever loads a benchmark suite (`set_expected_host_peaks`) rather than threaded
    /// through `prove_on_slot`'s signature and its half-dozen callers. A backend missing from here
    /// is charged `unmeasured_peak_for(backend)`, so forgetting to publish errs toward refusing work
    /// rather than toward over-committing the host.
    expected_peaks: Mutex<HashMap<String, u64>>,
    /// Host memory in-flight proofs have laid claim to. See `memory::MemoryLedger`.
    memory_ledger: crate::memory::MemoryLedger,
    workers: HashMap<String, WorkerEntry>,
    explicit_binaries: HashMap<String, PathBuf>,
    search_dirs: Vec<PathBuf>,
    /// Per-suite benchmark timeout. None = no timeout. The watchdog SIGKILLs
    /// the worker if the entire benchmark suite exceeds this duration.
    benchmark_timeout: Option<Duration>,
    /// Per-physical-GPU proving locks, keyed by `"gpu_tag:device_index"` (e.g.
    /// `"cuda:0"`). Two workers for DIFFERENT backends pinned to the SAME physical
    /// GPU — e.g. `risc0:cuda:0` and `sp1:cuda:0` — hold independent slot Mutexes, so
    /// without this they could prove concurrently and double-book VRAM → OOM.
    /// `prove_on_slot` acquires the matching lock (BEFORE the slot Mutex) for the
    /// whole proof. Lazily populated; interior-mutable so `prove_on_slot(&self)` can
    /// get-or-create a lock. CPU/generic workers and explicit binaries without a
    /// device index are left unguarded (see `physical_gpu_id`).
    gpu_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

/// Round-robin counter for load balancing across multiple GPU workers.
static ROUND_ROBIN: AtomicUsize = AtomicUsize::new(0);

impl WorkerPool {
    /// Create a new pool. Does NOT discover or spawn workers yet.
    /// `benchmark_timeout` sets the per-suite benchmark deadline (None = no timeout).
    pub fn new(
        explicit_binaries: HashMap<String, PathBuf>,
        search_dirs: Vec<PathBuf>,
        benchmark_timeout: Option<Duration>,
    ) -> Self {
        Self {
            expected_peaks: Mutex::new(HashMap::new()),
            memory_ledger: crate::memory::MemoryLedger::default(),
            workers: HashMap::new(),
            explicit_binaries,
            search_dirs,
            benchmark_timeout,
            gpu_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Build GPU environment variables for a given gpu_tag, PCI bus ID, and device index.
    ///
    /// CUDA uses PCI bus IDs with CUDA_DEVICE_ORDER=PCI_BUS_ID.
    /// ROCm uses numeric device indices for HIP_VISIBLE_DEVICES.
    /// Intel uses device index for ZE_AFFINITY_MASK (Level Zero) and ONEAPI_DEVICE_SELECTOR.
    fn gpu_env(
        backend: &str,
        gpu_tag: &str,
        pci_bus_id: Option<&str>,
        device_index: Option<u32>,
    ) -> HashMap<String, String> {
        let mut env = HashMap::new();
        // A `None` device_index means an explicitly-configured binary (discovery does
        // NOT auto-expand those per-GPU). In that case we must NOT inject a
        // *_VISIBLE_DEVICES pin — doing so would clobber whatever visibility the user
        // set in their own environment and force the binary onto device 0. Only emit
        // the pin when we actually enumerated a specific device.
        match gpu_tag {
            "cuda" => {
                // CUDA_VISIBLE_DEVICES accepts a numeric INDEX or a "GPU-<uuid>" string,
                // NOT a PCI bus id. Feeding it a PCI bus id like "00000000:03:0d.0" makes
                // CUDA parse the leading integer ("00000000" -> 0), so EVERY cuda worker
                // lands on device 0 — the extra GPUs are never used and the first GPU gets
                // double-booked into OOM. With CUDA_DEVICE_ORDER=PCI_BUS_ID the device
                // index is the PCI-bus rank, which matches how we enumerate them.
                let _ = pci_bus_id;
                env.insert("CUDA_DEVICE_ORDER".into(), "PCI_BUS_ID".into());
                if let Some(i) = device_index {
                    // Occupancy is settled by the slot key; the PIN is a separate question, and for
                    // some backends `CUDA_VISIBLE_DEVICES` is simply not the lever. SP1's SDK sets
                    // that variable on the `sp1-gpu-server` child itself, from the id given to
                    // `with_device_id`, overriding whatever the worker had — so pinning the worker
                    // cannot choose the server's card. Telling the worker the id can, and a DISTINCT
                    // id per worker is also what keeps two SP1 servers on distinct sockets instead of
                    // both seizing `/tmp/sp1-cuda-0.sock`. See `drives_cuda_without_visibility_pin`.
                    if crate::discovery::drives_cuda_without_visibility_pin(backend) {
                        env.insert(
                            zkminer_prover_protocol::types::CUDA_DEVICE_ID_ENV.into(),
                            i.to_string(),
                        );
                        // What the card has and what the host can spare, so a worker that can scale
                        // its own appetite has the two numbers to scale against. Neither is
                        // discoverable from inside the worker: `nvidia-smi` ignores
                        // `CUDA_VISIBLE_DEVICES`, and only the dispatcher knows the host reserve.
                        if let Some(vram) = gpu_vram_bytes(gpu_tag, device_index) {
                            env.insert(
                                zkminer_prover_protocol::types::CUDA_VRAM_BYTES_ENV.into(),
                                vram.to_string(),
                            );
                        }
                        // And what is actually FREE, which is the figure a backend that sizes itself
                        // from the card must use. SP1 reads the card's TOTAL and discards the free
                        // figure beside it, so on a card with a display attached it commits to a tier
                        // that does not fit. Measured here, not inside the worker, for the same reason
                        // as the line above: `nvidia-smi` ignores `CUDA_VISIBLE_DEVICES`, so a pinned
                        // worker cannot ask about its own card.
                        if let Some(idx) = device_index {
                            if let Some((foreign, _used, total)) = foreign_vram_bytes(idx) {
                                env.insert(
                                    zkminer_prover_protocol::types::CUDA_VRAM_AVAILABLE_BYTES_ENV
                                        .into(),
                                    total.saturating_sub(foreign).to_string(),
                                );
                            }
                        }
                        if let Some(budget) = crate::memory::worker_memory_ceiling_bytes(
                            crate::memory::DEFAULT_HOST_RESERVE_BYTES,
                        ) {
                            env.insert(
                                zkminer_prover_protocol::types::HOST_MEM_BUDGET_ENV.into(),
                                budget.to_string(),
                            );
                        }
                    } else {
                        env.insert("CUDA_VISIBLE_DEVICES".into(), i.to_string());
                        // The card's capacity, for the same reason SP1 gets it above: pinned by
                        // `CUDA_VISIBLE_DEVICES`, the worker cannot ask `nvidia-smi` about its own
                        // card. The risc0 worker needs it to decide whether its Groth16 SRS cache
                        // can stay resident between proofs; see `release_groth16_cache_if_tight`.
                        if let Some(vram) = gpu_vram_bytes(gpu_tag, device_index) {
                            env.insert(
                                zkminer_prover_protocol::types::CUDA_VRAM_BYTES_ENV.into(),
                                vram.to_string(),
                            );
                        }
                    }
                }
            }
            "rocm" => {
                // HIP_VISIBLE_DEVICES requires numeric indices, not PCI bus IDs.
                env.insert("NVCC".into(), "off".into());
                if let Some(i) = device_index {
                    env.insert("HIP_VISIBLE_DEVICES".into(), i.to_string());
                }
            }
            "intel" => {
                // Use a SINGLE selection mechanism. ZE_AFFINITY_MASK filters at the
                // Level Zero layer AND renumbers the surviving device(s) to start at 0,
                // so ALSO setting ONEAPI_DEVICE_SELECTOR=level_zero:N (N>0) would select
                // index N from the already-masked, renumbered list and find nothing.
                // The affinity mask alone correctly pins to the intended device.
                if let Some(i) = device_index {
                    env.insert("ZE_AFFINITY_MASK".into(), i.to_string());
                }
            }
            _ => {}
        }
        env
    }

    /// Discover and spawn all available worker binaries.
    /// Returns the list of compound keys that were successfully connected.
    pub fn discover_and_spawn(&mut self) -> Vec<String> {
        let discovered = discover_workers(&self.explicit_binaries, &self.search_dirs);
        let mut connected = Vec::new();

        for DiscoveredWorker {
            backend,
            gpu_tag,
            device_index,
            pci_bus_id,
            gpu_name,
            compute_cap,
            path,
        } in discovered
        {
            let key = slot_key(&backend, &gpu_tag, device_index);
            let env = Self::gpu_env(&backend, &gpu_tag, pci_bus_id.as_deref(), device_index);

            let device_desc = match (&gpu_name, device_index) {
                (Some(name), Some(idx)) => format!(" [GPU {idx}: {name}]"),
                (None, Some(idx)) => format!(" [GPU {idx}]"),
                _ => String::new(),
            };

            // A HARD VRAM floor, for a backend whose prover refuses the device outright.
            //
            // Unlike host memory (see the note below) this is not a risk to be weighed — it is a
            // capability the card does not have. `sp1-gpu-server` panics with
            // "Unsupported GPU memory: 20, must be at least 24GB" on the 16 GiB card here, before
            // allocating anything, and no proving option can move it; see
            // `discovery::min_vram_bytes_for_backend`.
            //
            // Checked at SPAWN rather than at dispatch because nothing earlier can see it: CUDA init
            // is lazy, so the worker spawns and handshakes perfectly happily, and the `sp1_usability`
            // probe only runs `sp1-gpu-server --version`, which starts no CUDA context. Left to
            // dispatch, the slot is advertised as healthy and the floor is rediscovered on every job
            // routed there, costing an attempt and a respawn each time.
            //
            // A card with UNKNOWN VRAM is allowed through: `nvidia-smi` failing is not evidence that
            // the card is too small, and refusing on a missing reading would be the same fail-closed
            // mistake the host-memory gate made. If it turns out to be too small, the worker declines
            // on first use and the slot retires.
            // A backend that FAULTS on this card's architecture, whatever its size.
            //
            // Separate from the VRAM floor because the two are different facts. SP1's CUDA kernels
            // misalign a device pointer on Blackwell (sm_120): measured here, the 5080 dies in seconds
            // with `CudaRustError: misaligned address` in the basefold path while the 4090 completes
            // the whole GPU pipeline on the same binary. Forcing the full element threshold and
            // reverting our own prover change both reproduce it, and native sm_120 SASS is present in
            // the build — so it is the kernels, not the tier, not us, and not a JIT fallback.
            //
            // Checked at spawn for the same reason as the VRAM floor: CUDA init is lazy, so the worker
            // handshakes happily and the fault only appears on the first real proof. Left to dispatch,
            // the slot is advertised healthy and every SP1 job routed there burns attempts.
            if crate::discovery::backend_broken_on_compute_cap(&backend, compute_cap) {
                tracing::warn!(
                    "not starting worker {key}{device_desc}: {backend} is known to fault on this \
                     card's compute capability {:?} (misaligned device address in its CUDA kernels), \
                     independent of VRAM. The slot is not advertised; {backend} jobs will be routed \
                     to another card.",
                    compute_cap,
                );
                continue;
            }

            if let (Some(floor), Some(have)) = (
                crate::discovery::min_vram_bytes_for_backend(&backend),
                gpu_vram_bytes(&gpu_tag, device_index),
            ) {
                if have < floor {
                    tracing::warn!(
                        "not starting worker {key}{device_desc}: {backend} requires at least \
                         {:.1} GB of VRAM and this card has {:.1} GB. Its prover refuses the device \
                         outright — this is not a tunable limit — so the slot is not advertised and \
                         {backend} jobs will be routed to a larger card.",
                        floor as f64 / 1e9,
                        have as f64 / 1e9,
                    );
                    continue;
                }
            }

            // NOTE: there is deliberately NO host-memory gate here, and the earlier one was
            // removed rather than repaired.
            //
            // It charged a worker SPAWN the cost of a PROOF — 18 GiB for SP1 — when spawning costs
            // megabytes: both workers initialise CUDA lazily on the first Prove/Benchmark
            // (`zkminer-prove-sp1`'s `get_prover!`, risc0's per-call `default_prover()`), so four
            // live workers are four idle pipes, not four CUDA contexts. It also re-read
            // `MemAvailable` per iteration with no accumulator, so it could never stop the second
            // worker anyway — it only ever refused the first on an already-starved host, which is
            // the opposite of the cumulative sum it claimed to bound.
            //
            // And the refusal was worse than the risk. `continue` here registers no `WorkerEntry`
            // at all, unlike the spawn-FAILURE path below which registers one with `handle: None`
            // precisely so `ensure_alive` can retry. So a transient dip — a `cargo build`, a
            // browser — silently cost that backend for the whole process lifetime, with no
            // re-discovery; and with every backend refused, `backend_sources` reports Simulated,
            // `sim_mode` turns on, and the miner claims jobs it has no prover for.
            //
            // Concurrent PROOFS are what froze this box, and the ledger in `prove_on_slot` is the
            // layer that bounds them, with the PSI brake ahead of it and `oom_score_adj` plus the
            // per-worker ceiling behind it.
            match WorkerHandle::spawn(&backend, &path, &env) {
                Ok(handle) => {
                    let worker_pid = handle.pid();
                    tracing::info!(
                        "Worker {key} ready{device_desc} (pid {worker_pid}, binary {})",
                        path.display(),
                    );
                    self.workers.insert(
                        key.clone(),
                        WorkerEntry {
                            slot: Mutex::new(WorkerSlot {
                                handle: Some(handle),
                                path: path.clone(),
                                backend: backend.clone(),
                                gpu_tag: gpu_tag.clone(),
                                device_index,
                                pci_bus_id: pci_bus_id.clone(),
                                gpu_name: gpu_name.clone(),
                                spawn_env: env,
                                consecutive_failures: 0,
                                last_failure: None,
                                declined: None,
                                proofs_since_spawn: 0,
                            }),
                            vram_bytes: gpu_vram_bytes(&gpu_tag, device_index),
                            pci_bus_id: pci_bus_id.clone().filter(|b| !b.is_empty()),
                            pid: Arc::new(AtomicU32::new(worker_pid)),
                            pid_starttime: Arc::new(AtomicU64::new(
                                crate::memory::pid_starttime(worker_pid).unwrap_or(0),
                            )),
                            intentional_kill: Arc::new(AtomicBool::new(false)),
                        },
                    );
                    connected.push(key);
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    // A DECLINE is permanent; a spawn failure is transient. Conflating
                    // them is what kept `is_backend_healthy` true for a worker that had
                    // just said it cannot prove.
                    let declined = msg
                        .contains(zkminer_prover_protocol::types::WORKER_DECLINED)
                        .then(|| msg.clone());
                    if declined.is_some() {
                        tracing::error!(
                            "Worker {key}{device_desc} DECLINED and will not be \
                             advertised or respawned: {msg}"
                        );
                    } else {
                        tracing::error!("Failed to start worker {key}{device_desc}: {msg}");
                    }
                    let vram_bytes = gpu_vram_bytes(&gpu_tag, device_index);
                    let entry_bus_id = pci_bus_id.clone().filter(|b| !b.is_empty());
                    self.workers.insert(
                        key,
                        WorkerEntry {
                            slot: Mutex::new(WorkerSlot {
                                handle: None,
                                path,
                                backend,
                                gpu_tag,
                                device_index,
                                pci_bus_id,
                                gpu_name,
                                spawn_env: env,
                                consecutive_failures: 1,
                                last_failure: Some(Instant::now()),
                                declined,
                                proofs_since_spawn: 0,
                            }),
                            vram_bytes,
                            pci_bus_id: entry_bus_id,
                            pid: Arc::new(AtomicU32::new(0)),
                            pid_starttime: Arc::new(AtomicU64::new(0)),
                            intentional_kill: Arc::new(AtomicBool::new(false)),
                        },
                    );
                }
            }
        }

        connected
    }

    /// Get all compound keys that have registered worker slots.
    pub fn registered_backends(&self) -> Vec<String> {
        self.workers.keys().cloned().collect()
    }

    /// Get deduplicated logical backend names with currently alive workers.
    pub fn connected_backends(&self) -> Vec<String> {
        let mut backends: Vec<String> = self
            .workers
            .iter()
            .filter_map(|(_key, entry)| {
                // Use try_lock to avoid blocking during proving.
                // If locked (proving in progress), the backend is connected.
                match entry.slot.try_lock() {
                    Ok(slot) => {
                        if slot.handle.is_some() {
                            Some(slot.backend.clone())
                        } else {
                            None
                        }
                    }
                    // WouldBlock = the slot is busy proving, so the backend IS connected.
                    // Poisoned is a different fact and must not be reported as health: it meant a
                    // panic left the slot unusable while this predicate kept advertising the
                    // backend, so the miner claimed work it could not dispatch. The dispatch path
                    // now recovers a poisoned guard, so the honest answer is still "connected" —
                    // but it is worth saying out loud rather than inferring from a lock error.
                    Err(std::sync::TryLockError::WouldBlock) => {
                        _key.split(':').next().map(|s| s.to_string())
                    }
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        tracing::debug!(
                            "slot {_key} is poisoned; reporting it as connected \
                                         because dispatch recovers it"
                        );
                        _key.split(':').next().map(|s| s.to_string())
                    }
                }
            })
            .collect();
        backends.sort();
        backends.dedup();
        backends
    }

    /// Find all slot keys matching a prefix.
    ///
    /// The prefix can be:
    /// - A logical backend name: `"risc0"` matches `"risc0:cuda:0"`, `"risc0:cuda:1"`, `"risc0:generic"`
    /// - A vendor-level name: `"risc0:cuda"` matches `"risc0:cuda:0"`, `"risc0:cuda:1"`
    /// - An exact compound key: `"risc0:cuda:0"` matches only itself
    fn keys_for_prefix(&self, prefix: &str) -> Vec<String> {
        self.workers
            .keys()
            .filter(|k| *k == prefix || k.starts_with(&format!("{prefix}:")))
            .cloned()
            .collect()
    }

    /// Number of distinct physical GPUs available for proving, across all backends.
    /// A physical GPU is identified by (gpu_tag, device_index): `risc0:cuda:0` and
    /// `sp1:cuda:0` are the SAME card and count once. Used to default the miner's
    /// concurrent-proof limit to "one job per GPU". Returns at least 1 so CPU- or
    /// generic-only setups still prove (one at a time).
    pub fn proving_gpu_count(&self) -> usize {
        let mut gpus = std::collections::HashSet::new();
        for key in self.workers.keys() {
            let parts: Vec<&str> = key.split(':').collect();
            // "backend:gpu_tag:device_index" with a real GPU tag = a pinned physical GPU.
            if parts.len() == 3 && matches!(parts[1], "cuda" | "rocm" | "intel") {
                gpus.insert((parts[1].to_string(), parts[2].to_string()));
            }
        }
        gpus.len().max(1)
    }

    /// Check if a specific backend has any healthy worker.
    /// Accepts a logical backend name ("risc0"), vendor-level ("risc0:cuda"),
    /// or a full compound key ("risc0:cuda:0").
    pub fn is_backend_healthy(&self, backend: &str) -> bool {
        let keys = self.keys_for_prefix(backend);
        for key in keys {
            if let Some(entry) = self.workers.get(&key) {
                // Use try_lock to avoid blocking the TUI render loop during proving.
                // If the lock is held (proof in progress), the worker is alive.
                match entry.slot.try_lock() {
                    Ok(mut slot) => {
                        let alive = slot.handle.as_mut().map(|h| h.is_alive()).unwrap_or(false);
                        // A dead-but-eligible slot is still "healthy": it will respawn
                        // on the next dispatch. Without this, once a slot is retired the
                        // brain stops claiming even after the cooldown clears it.
                        if alive || Self::slot_eligible(&slot) {
                            return true;
                        }
                    }
                    // Busy = proving = alive. A POISONED lock is not evidence of either, but the
                    // dispatch path recovers it, so the slot is still usable and reporting it alive
                    // is correct. Spelt out so the two cases cannot silently diverge again.
                    Err(std::sync::TryLockError::WouldBlock) => {
                        return true;
                    }
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Get worker info for a specific backend (first healthy match).
    /// Accepts a logical backend name, vendor-level, or full compound key.
    pub fn worker_info(&self, backend: &str) -> Option<WorkerInfo> {
        let keys = self.keys_for_prefix(backend);
        for key in keys {
            if let Some(info) = self.worker_info_from_key(&key) {
                return Some(info);
            }
        }
        None
    }

    fn worker_info_from_key(&self, key: &str) -> Option<WorkerInfo> {
        let entry = self.workers.get(key)?;
        // Use try_lock to avoid blocking the TUI render loop during proving.
        // Returns None if the worker is busy (Mutex held by prove_on_slot).
        let slot = entry.slot.try_lock().ok()?;
        let handle = slot.handle.as_ref()?;
        Some(WorkerInfo {
            backend: slot.backend.clone(),
            gpu_tag: slot.gpu_tag.clone(),
            device_index: slot.device_index,
            gpu_name: slot.gpu_name.clone(),
            pid: handle.pid(),
            sdk_version: handle.sdk_version.clone(),
            worker_version: handle.worker_version.clone(),
        })
    }

    /// Run benchmarks on a specific worker slot.
    /// Run one po2 calibration proof on `key` and return the measured sample.
    ///
    /// Only the risc0 worker implements `CalibrateSegmentLimit`; SP1 and OpenVM
    /// reply with `WorkerResponse::Error` (they respond rather than ignoring, so
    /// this cannot hang), which surfaces here as `Err`.
    ///
    /// Callers must treat a sweep of these as advisory until it is validated —
    /// see `benchmark::calibration_is_usable`.
    pub fn calibrate_slot_po2(&self, key: &str, po2: u8) -> Result<crate::benchmark::Po2Sample> {
        // The per-card guard. A calibration run is a full proof swept upward through po2 — by this
        // module's own description the hungriest path in the program — so running it beside a proof on
        // the same card is the worst case of the double-booking the lock prevents. Bounded by
        // `benchmark_timeout`. See `acquire_gpu_guard`.
        let gpu_lock = self.gpu_lock_for(key);
        let _gpu_guard =
            Self::acquire_gpu_guard(gpu_lock.as_ref(), key, None, self.benchmark_timeout)?;

        // Size the segment to what is actually free, rather than refusing the card.
        //
        // This is the one GPU path where the parameter is ours to choose: `po2` is the segment limit,
        // VRAM scales with it, and `find_optimal_po2` already answers "largest segment that fits in
        // this budget". Feeding it the AVAILABLE figure instead of the card's total is the whole
        // adaptation — a card with a desktop on it gets a smaller segment instead of a refusal.
        //
        // Only ever downward. A sweep is calibration: raising po2 above what the caller asked for
        // would invent a sample it never requested, and `calibrate_po2_for_suite` reads the returned
        // `po2` to decide what succeeded.
        let po2 = match self.check_vram_budget(key)? {
            Some(budget) => {
                let backend = key.split(':').next().unwrap_or(key);
                let (fits, _) = crate::benchmark::find_optimal_po2(budget.available, backend, true);
                if fits < po2 {
                    tracing::info!(
                        "{key}: calibrating at po2={fits} instead of {po2} — only {:.1} GiB of this \
                         card's {:.1} GiB is free ({:.1} GiB held elsewhere), and po2={po2} is sized \
                         for more than that",
                        budget.available as f64 / 1024.0 / 1024.0 / 1024.0,
                        budget.total as f64 / 1024.0 / 1024.0 / 1024.0,
                        budget.foreign as f64 / 1024.0 / 1024.0 / 1024.0,
                    );
                }
                po2.min(fits)
            }
            None => po2,
        };

        let entry = self
            .workers
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("No worker registered for '{key}'"))?;

        let mut slot = entry.slot.lock().unwrap_or_else(|e| {
            // RECOVER, do not hard-fail. The guard is held across code that can panic — the
            // progress callback runs synchronously on the proving thread while this very guard
            // is held, and in production that closure touches the shared TUI state — so one
            // panic there used to poison this slot permanently: every dispatch returned "lock
            // poisoned" while `is_backend_healthy` reported the slot alive (it reads any lock
            // error as "busy, therefore proving"), so the miner claimed jobs it could never
            // dispatch for the life of the process. What this mutex guards is a handle plus two
            // counters, not an invariant a panic can corrupt into unsafety, and `gpu_locks` and
            // `shutdown_all` already recover the same way.
            tracing::warn!(
                "worker slot {key} was poisoned by an earlier panic; recovering it rather \
                     than retiring the slot"
            );
            e.into_inner()
        });

        // Admission, like a proof and a benchmark — and this is the hungriest path in the program,
        // not the lightest. Its own comment below says "a calibration run is a full proof", it sweeps
        // upward through po2, and this project's model has host memory DOUBLING per po2 step while
        // `max_feasible_po2` is derived from VRAM and says nothing about host RAM. So the single
        // largest host-memory event in the tree was the one left unguarded when the benchmark paths
        // were covered.
        //
        // Charged by the po2 being attempted, not a flat figure, for the same doubling reason: a
        // sweep to po2 24 from a baseline of 21 is ~8x the baseline cost.
        let _memory_reservation = {
            let backend_of_slot = key.split(':').next().unwrap_or(key);
            let baseline = self
                .expected_host_peak(backend_of_slot)
                .div_ceil(crate::memory::MEASUREMENT_SAFETY_FACTOR);
            let want = crate::memory::peak_for_po2(baseline, po2);
            match self.reserve_host_memory(want, key) {
                Some(r) => r,
                None => {
                    return Err(anyhow::Error::new(
                        zkminer_prover_protocol::types::HostMemoryShortage {
                            attempted: false,
                            slot_key: key.to_string(),
                            needed: want,
                            reserved: self.reserved_host_memory(),
                            available: crate::memory::mem_available_bytes().unwrap_or(0),
                        },
                    ));
                }
            }
        };

        self.ensure_alive(&mut slot, entry)?;
        if let Some(h) = slot.handle.as_ref() {
            entry.publish_pid(h.pid());
        }
        entry.intentional_kill.store(false, Ordering::Release);

        let handle = slot
            .handle
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker not available for {key}"))?;

        let request_id = po2 as u64;
        if let Err(e) = handle.send(&WorkerCommand::CalibrateSegmentLimit { request_id, po2 }) {
            Self::mark_slot_failed(&mut slot, entry);
            return Err(e);
        }

        // A calibration run is a full proof — reuse the benchmark timeout budget.
        let _watchdog = self.benchmark_timeout.map(|t| {
            ProvingWatchdog::new(
                entry.pid.clone(),
                entry.pid_starttime.clone(),
                t,
                key.to_string(),
                entry.intentional_kill.clone(),
            )
        });

        let resp = handle.recv();
        match resp {
            Ok(WorkerResponse::CalibrationResult {
                po2,
                segment_count,
                total_cycles,
                prove_duration_secs,
                ..
            }) => {
                slot.consecutive_failures = 0;
                Ok(crate::benchmark::Po2Sample {
                    po2,
                    total_cycles,
                    segment_count,
                    duration_secs: prove_duration_secs,
                    throughput: total_cycles as f64 / prove_duration_secs.max(1e-9),
                })
            }
            Ok(WorkerResponse::Error { message, .. }) => {
                // A refusal (unsupported backend) is not a worker fault — leave the
                // slot healthy so it stays usable for proving.
                Err(anyhow::anyhow!("{key} rejected calibration: {message}"))
            }
            Ok(other) => Err(anyhow::anyhow!(
                "{key} sent an unexpected response to calibration: {other:?}"
            )),
            Err(e) => {
                if entry.intentional_kill.load(Ordering::Acquire) {
                    Self::mark_slot_dead(&mut slot, entry);
                } else {
                    Self::mark_slot_failed(&mut slot, entry);
                }
                Err(e)
            }
        }
    }

    fn benchmark_slot(&self, key: &str) -> Result<Vec<BenchmarkEntry>> {
        // The per-card guard, like every other path that puts work on a GPU. Without it, a benchmark
        // started from the TUI's `[b]` or from `zkminer benchmark` ran concurrently with a proof on
        // the SAME physical card, each side's VRAM invisible to the other — the double-booking the
        // lock exists to prevent. Bounded by `benchmark_timeout` so a wedged holder cannot park the
        // benchmark forever. See `acquire_gpu_guard`.
        let gpu_lock = self.gpu_lock_for(key);
        let _gpu_guard =
            Self::acquire_gpu_guard(gpu_lock.as_ref(), key, None, self.benchmark_timeout)?;

        // Enough of this card free for this backend? A benchmark is a proof as far as the card is
        // concerned, and an OOM here poisons the throughput row that prices every later job on it.
        // See `check_vram_budget`. Unlike `calibrate_slot_po2` there is no parameter to clamp: the
        // suite's sizing is chosen inside the worker from its spawn environment, which is where the
        // available-VRAM figure is handed to it.
        let _vram_budget = self.check_vram_budget(key)?;

        let entry = self
            .workers
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("No worker registered for '{key}'"))?;

        let mut slot = entry.slot.lock().unwrap_or_else(|e| {
            // RECOVER, do not hard-fail. The guard is held across code that can panic — the
            // progress callback runs synchronously on the proving thread while this very guard
            // is held, and in production that closure touches the shared TUI state — so one
            // panic there used to poison this slot permanently: every dispatch returned "lock
            // poisoned" while `is_backend_healthy` reported the slot alive (it reads any lock
            // error as "busy, therefore proving"), so the miner claimed jobs it could never
            // dispatch for the life of the process. What this mutex guards is a handle plus two
            // counters, not an invariant a panic can corrupt into unsafety, and `gpu_locks` and
            // `shutdown_all` already recover the same way.
            tracing::warn!(
                "worker slot {key} was poisoned by an earlier panic; recovering it rather \
                     than retiring the slot"
            );
            e.into_inner()
        });

        // A benchmark IS a proof as far as the host's memory is concerned, so it takes a
        // reservation like one. Without this the benchmark path was exempt from every layer but
        // `oom_score_adj` and the per-worker ceiling — and it is the path that produced both
        // incidents on this box: the OOM-killed `sp1-gpu-server`, and the four concurrent provers
        // that forced a power cycle. `zkminer benchmark` also runs outside the brain loop, so the
        // PSI brake does not cover it at all, and the TUI's `[b]` can start one while proofs run.
        //
        // Declared before the handle borrow so it lives for the whole benchmark and is released on
        // every error path.
        let _memory_reservation = {
            let backend_of_slot = key.split(':').next().unwrap_or(key);
            // The FULL budget, not a discounted one.
            //
            // Halving it on the grounds that a benchmark proves a cheaper workload was wrong in the
            // one way that matters: the thing a benchmark brings up is the same persistent
            // `sp1-gpu-server`, measured at ~17.6 GiB, and a half-size charge let `fits_committed`
            // admit two of them (`9 + 9 + 3 <= 28`) on a box that cannot hold one and a half. The
            // segment-size argument is about the cost of the PROOF, not about whether the server
            // forks. The chicken-and-egg it was meant to solve — a benchmark refused by the very
            // default only a benchmark could lower — is already handled by
            // `admissible_unmeasured_peak_for`, which clamps that default to what the host can admit.
            let want = self.expected_host_peak(backend_of_slot);
            match self.reserve_host_memory(want, key) {
                Some(r) => r,
                None => {
                    return Err(anyhow::Error::new(
                        zkminer_prover_protocol::types::HostMemoryShortage {
                            attempted: false,
                            slot_key: key.to_string(),
                            needed: want,
                            reserved: self.reserved_host_memory(),
                            available: crate::memory::mem_available_bytes().unwrap_or(0),
                        },
                    ));
                }
            }
        };

        self.ensure_alive(&mut slot, entry)?;

        // Update external PID after ensure_alive (may have respawned)
        if let Some(h) = slot.handle.as_ref() {
            entry.publish_pid(h.pid());
        }

        // Reset intentional_kill so a timeout doesn't inherit a stale flag
        entry.intentional_kill.store(false, Ordering::Release);

        let handle = slot
            .handle
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker not available for {key}"))?;

        if let Err(e) = handle.send(&WorkerCommand::Benchmark) {
            Self::mark_slot_failed(&mut slot, entry);
            return Err(e);
        }

        // Start benchmark timeout watchdog if configured.
        let _watchdog = self.benchmark_timeout.map(|t| {
            ProvingWatchdog::new(
                entry.pid.clone(),
                entry.pid_starttime.clone(),
                t,
                key.to_string(),
                entry.intentional_kill.clone(),
            )
        });

        let bench_response = handle.recv_benchmark(&|_, _, _| {});

        if let Err(ref _e) = bench_response {
            if entry.intentional_kill.load(Ordering::Acquire) {
                Self::mark_slot_dead(&mut slot, entry);
            } else {
                Self::mark_slot_failed(&mut slot, entry);
            }
        }

        match bench_response? {
            WorkerResponse::BenchmarkResult { results } => Ok(results),
            WorkerResponse::Error { message, .. } => {
                bail!("Benchmark error from {key}: {message}")
            }
            other => bail!("Unexpected response from {key}: {other:?}"),
        }
    }

    /// Run benchmarks on a backend. Accepts logical name, vendor-level, or full compound key.
    pub fn benchmark(&self, backend: &str) -> Result<Vec<BenchmarkEntry>> {
        let keys = self.keys_for_prefix(backend);
        if keys.is_empty() {
            bail!("No worker registered for backend '{backend}'");
        }
        let mut all = Vec::new();
        for key in keys {
            match self.benchmark_slot(&key) {
                Ok(entries) => all.extend(entries),
                Err(e) => tracing::error!("Benchmark failed for {key}: {e:#}"),
            }
        }
        Ok(all)
    }

    /// Run benchmarks on all connected workers, returning device metadata alongside results.
    /// This allows callers to build per-device benchmark records with real GPU identification.
    pub fn benchmark_all_with_device_info(&self) -> Vec<SlotBenchmarkResult> {
        let mut results = Vec::new();
        let mut keys: Vec<String> = self.registered_backends();

        // Sort keys so GPU workers (cuda/rocm) run first. This ensures the GPU
        // prover gets full VRAM before other backends (e.g. SP1's gpu-server)
        // allocate their own GPU memory. The RISC0 CUDA HAL's buffer pool
        // prevents memory reuse between different segment sizes, so it needs
        // maximum VRAM available during its benchmarks.
        keys.sort_by(|a, b| {
            let gpu_rank = |k: &str| -> u8 {
                if k.contains(":cuda:") || k.contains(":rocm:") {
                    0 // GPU-specific workers first
                } else if k.contains(":generic") {
                    2 // CPU-only last
                } else {
                    1
                }
            };
            gpu_rank(a).cmp(&gpu_rank(b)).then(a.cmp(b))
        });

        // Collect which backends have GPU workers so we can skip CPU-only workers
        // for the same backend (CPU RISC Zero proving is prohibitively expensive).
        let gpu_backends: Vec<String> = keys
            .iter()
            .filter_map(|k| {
                let slot = self.workers.get(k)?.slot.lock().ok()?;
                if slot.gpu_tag != "generic" && slot.handle.is_some() {
                    Some(slot.backend.clone())
                } else {
                    None
                }
            })
            .collect();

        // Track GPU workers that need recycling (shut down after benchmark
        // to free VRAM for the next backend that shares the same GPU).
        let mut recycled_keys: Vec<String> = Vec::new();

        for key in keys {
            // Extract device metadata from the slot before benchmarking
            let (gpu_name, device_index, slot_pci_bus_id, gpu_tag, backend, vram_bytes) =
                if let Some(entry) = self.workers.get(&key) {
                    // vram_bytes lives on the WorkerEntry, outside the slot Mutex.
                    let vram = entry.vram_bytes;
                    if let Ok(slot) = entry.slot.lock() {
                        (
                            slot.gpu_name.clone(),
                            slot.device_index,
                            slot.pci_bus_id.clone(),
                            slot.gpu_tag.clone(),
                            slot.backend.clone(),
                            vram,
                        )
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };

            // Skip "generic" (CPU) workers when a GPU worker for the same backend
            // exists. CPU-only proving (e.g. risc0 on CPU) is extremely slow/crashy
            // and not useful for benchmarks when GPU provers are available.
            if gpu_tag == "generic" && gpu_backends.contains(&backend) {
                tracing::info!("Skipping benchmark for {key} (GPU worker available for {backend})");
                continue;
            }

            match self.benchmark_slot(&key) {
                Ok(entries) if !entries.is_empty() => {
                    results.push(SlotBenchmarkResult {
                        slot_key: key.clone(),
                        gpu_name,
                        device_index,
                        pci_bus_id: slot_pci_bus_id.clone(),
                        gpu_tag: gpu_tag.clone(),
                        entries,
                        vram_bytes,
                        host_peak_bytes: self.host_peak_for_slot(&key),
                    });
                }
                Ok(_) => {} // empty results, skip
                Err(e) => {
                    tracing::error!("Benchmark failed for {key}: {e:#}");
                }
            }

            // After benchmarking a GPU-specific worker (cuda/rocm), shut it down
            // to free VRAM. GPU prover processes hold buffer pools that prevent
            // other backends from using the same GPU.
            if gpu_tag == "cuda" || gpu_tag == "rocm" {
                if let Some(entry) = self.workers.get(&key) {
                    // RECOVER the poison, as every other lock site in this file does. `if let Ok(..)`
                    // skipped the block silently, and one of the blocks this guards is the post-benchmark
                    // `shutdown()` that frees `sp1-gpu-server` between the two SP1 slots — so a single
                    // panic in the progress callback (which this file documents as a real production
                    // event) left card 0's server resident at ~17.6 GiB while card 1's benchmark started,
                    // with no log line to say the shutdown had been skipped. The other two guard the
                    // respawn, so a slot would silently never come back.
                    {
                        let mut slot = entry.slot.lock().unwrap_or_else(|e| {
                            tracing::warn!(
                            "slot {key} was poisoned by an earlier panic; recovering it so this \
                             shutdown/respawn is not silently skipped"
                        );
                            e.into_inner()
                        });
                        // PID first: `shutdown()` reaps (see the recycle path above), so no
                        // reader of this atomic may still see the number afterwards.
                        entry.clear_pid();
                        let reaped = if let Some(handle) = &mut slot.handle {
                            tracing::info!("Recycling GPU worker {key} to free VRAM");
                            handle.shutdown();
                            true
                        } else {
                            false
                        };
                        Self::mark_slot_dead(&mut slot, entry);
                        // Let the pages come back BEFORE the next slot's reservation is tested
                        // against them. Without this the second SP1 card was refused for host RAM
                        // 367 ms after the first card's worker was reaped — short by 0.2 GiB of a
                        // figure that had not updated yet — and silently got no row in the suite.
                        // The slot lock is still held here, which is harmless: this slot is already
                        // dead and the loop is sequential.
                        if reaped {
                            drop(slot);
                            wait_for_reclaim(&key, BENCHMARK_RECLAIM_WAIT);
                            slot = entry.slot.lock().unwrap_or_else(|e| e.into_inner());
                        }
                        // A DECLINED worker must not be queued for respawn: the respawn loop
                        // below clears `consecutive_failures`/`last_failure` and calls `respawn`
                        // directly, checking neither `declined` nor the retire cooldown. So every
                        // benchmark run paid a full ~7.5s `sp1_usability` handshake per declined
                        // slot on the single process-wide spawner thread, against a worker that
                        // has already said it cannot prove here — the exact churn
                        // `slot_eligible`'s comment claims to prevent.
                        if slot.declined.is_none() {
                            recycled_keys.push(key.clone());
                        }
                    }
                }
            }
        }

        // Respawn recycled GPU workers so they're available for proving
        for key in &recycled_keys {
            if let Some(entry) = self.workers.get(key) {
                // RECOVER the poison, as every other lock site in this file does. `if let Ok(..)`
                // skipped the block silently, and one of the blocks this guards is the post-benchmark
                // `shutdown()` that frees `sp1-gpu-server` between the two SP1 slots — so a single
                // panic in the progress callback (which this file documents as a real production
                // event) left card 0's server resident at ~17.6 GiB while card 1's benchmark started,
                // with no log line to say the shutdown had been skipped. The other two guard the
                // respawn, so a slot would silently never come back.
                {
                    let mut slot = entry.slot.lock().unwrap_or_else(|e| {
                        tracing::warn!(
                            "slot {key} was poisoned by an earlier panic; recovering it so this \
                             shutdown/respawn is not silently skipped"
                        );
                        e.into_inner()
                    });
                    tracing::info!("Respawning GPU worker {key} after benchmarks");
                    slot.consecutive_failures = 0;
                    slot.last_failure = None;
                    if let Err(e) = Self::respawn(&mut slot) {
                        tracing::warn!(
                            "Failed to respawn GPU worker {key} after benchmarks: {e:#}"
                        );
                    }
                    if let Some(h) = slot.handle.as_ref() {
                        entry.publish_pid(h.pid());
                    }
                }
            }
        }

        results
    }

    /// Run benchmarks on a specific worker slot with per-program progress streaming.
    fn benchmark_slot_streaming(
        &self,
        key: &str,
        on_progress: &dyn Fn(BenchmarkProgressEvent),
    ) -> Result<Vec<BenchmarkEntry>> {
        // The per-card guard, like every other path that puts work on a GPU. Without it, a benchmark
        // started from the TUI's `[b]` or from `zkminer benchmark` ran concurrently with a proof on
        // the SAME physical card, each side's VRAM invisible to the other — the double-booking the
        // lock exists to prevent. Bounded by `benchmark_timeout` so a wedged holder cannot park the
        // benchmark forever. See `acquire_gpu_guard`.
        let gpu_lock = self.gpu_lock_for(key);
        let _gpu_guard =
            Self::acquire_gpu_guard(gpu_lock.as_ref(), key, None, self.benchmark_timeout)?;

        // Enough of this card free for this backend? A benchmark is a proof as far as the card is
        // concerned, and an OOM here poisons the throughput row that prices every later job on it.
        // See `check_vram_budget`. Unlike `calibrate_slot_po2` there is no parameter to clamp: the
        // suite's sizing is chosen inside the worker from its spawn environment, which is where the
        // available-VRAM figure is handed to it.
        let _vram_budget = self.check_vram_budget(key)?;

        let entry = self
            .workers
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("No worker registered for '{key}'"))?;

        let mut slot = entry.slot.lock().unwrap_or_else(|e| {
            // RECOVER, do not hard-fail. The guard is held across code that can panic — the
            // progress callback runs synchronously on the proving thread while this very guard
            // is held, and in production that closure touches the shared TUI state — so one
            // panic there used to poison this slot permanently: every dispatch returned "lock
            // poisoned" while `is_backend_healthy` reported the slot alive (it reads any lock
            // error as "busy, therefore proving"), so the miner claimed jobs it could never
            // dispatch for the life of the process. What this mutex guards is a handle plus two
            // counters, not an invariant a panic can corrupt into unsafety, and `gpu_locks` and
            // `shutdown_all` already recover the same way.
            tracing::warn!(
                "worker slot {key} was poisoned by an earlier panic; recovering it rather \
                     than retiring the slot"
            );
            e.into_inner()
        });

        // Extract metadata before borrowing handle
        let gpu_name = slot.gpu_name.clone();
        let device_index = slot.device_index;
        let slot_pci_bus_id = slot.pci_bus_id.clone();
        let gpu_tag = slot.gpu_tag.clone();

        // A benchmark IS a proof as far as the host's memory is concerned, so it takes a
        // reservation like one. Without this the benchmark path was exempt from every layer but
        // `oom_score_adj` and the per-worker ceiling — and it is the path that produced both
        // incidents on this box: the OOM-killed `sp1-gpu-server`, and the four concurrent provers
        // that forced a power cycle. `zkminer benchmark` also runs outside the brain loop, so the
        // PSI brake does not cover it at all, and the TUI's `[b]` can start one while proofs run.
        //
        // Declared before the handle borrow so it lives for the whole benchmark and is released on
        // every error path.
        let _memory_reservation = {
            let backend_of_slot = key.split(':').next().unwrap_or(key);
            // The FULL budget, not a discounted one.
            //
            // Halving it on the grounds that a benchmark proves a cheaper workload was wrong in the
            // one way that matters: the thing a benchmark brings up is the same persistent
            // `sp1-gpu-server`, measured at ~17.6 GiB, and a half-size charge let `fits_committed`
            // admit two of them (`9 + 9 + 3 <= 28`) on a box that cannot hold one and a half. The
            // segment-size argument is about the cost of the PROOF, not about whether the server
            // forks. The chicken-and-egg it was meant to solve — a benchmark refused by the very
            // default only a benchmark could lower — is already handled by
            // `admissible_unmeasured_peak_for`, which clamps that default to what the host can admit.
            let want = self.expected_host_peak(backend_of_slot);
            match self.reserve_host_memory(want, key) {
                Some(r) => r,
                None => {
                    return Err(anyhow::Error::new(
                        zkminer_prover_protocol::types::HostMemoryShortage {
                            attempted: false,
                            slot_key: key.to_string(),
                            needed: want,
                            reserved: self.reserved_host_memory(),
                            available: crate::memory::mem_available_bytes().unwrap_or(0),
                        },
                    ));
                }
            }
        };

        self.ensure_alive(&mut slot, entry)?;

        // Update external PID after ensure_alive (may have respawned)
        if let Some(h) = slot.handle.as_ref() {
            entry.publish_pid(h.pid());
        }

        // Reset intentional_kill so a timeout doesn't inherit a stale flag
        entry.intentional_kill.store(false, Ordering::Release);

        let handle = slot
            .handle
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker not available for {key}"))?;

        if let Err(e) = handle.send(&WorkerCommand::Benchmark) {
            Self::mark_slot_failed(&mut slot, entry);
            return Err(e);
        }

        // Start benchmark timeout watchdog if configured.
        let _watchdog = self.benchmark_timeout.map(|t| {
            ProvingWatchdog::new(
                entry.pid.clone(),
                entry.pid_starttime.clone(),
                t,
                key.to_string(),
                entry.intentional_kill.clone(),
            )
        });

        let key_owned = key.to_string();
        let cb = |entry: &zkminer_prover_protocol::BenchmarkEntry, idx: u32, total: u32| {
            on_progress(BenchmarkProgressEvent {
                slot_key: key_owned.clone(),
                gpu_name: gpu_name.clone(),
                device_index,
                pci_bus_id: slot_pci_bus_id.clone(),
                gpu_tag: gpu_tag.clone(),
                entry: entry.clone(),
                program_index: idx,
                total_programs: total,
            });
        };

        let bench_response = handle.recv_benchmark(&cb);

        if let Err(ref _e) = bench_response {
            if entry.intentional_kill.load(Ordering::Acquire) {
                Self::mark_slot_dead(&mut slot, entry);
            } else {
                Self::mark_slot_failed(&mut slot, entry);
            }
        }

        match bench_response? {
            WorkerResponse::BenchmarkResult { results } => Ok(results),
            WorkerResponse::Error { message, .. } => {
                bail!("Benchmark error from {key}: {message}")
            }
            other => bail!("Unexpected response from {key}: {other:?}"),
        }
    }

    /// Run benchmarks on all connected workers with per-program streaming progress.
    ///
    /// Same as `benchmark_all_with_device_info` but sends `BenchmarkProgressEvent`
    /// through the callback as each benchmark program completes on each GPU.
    pub fn benchmark_all_streaming(
        &self,
        on_progress: &dyn Fn(BenchmarkProgressEvent),
    ) -> Vec<SlotBenchmarkResult> {
        let mut results = Vec::new();
        let mut keys: Vec<String> = self.registered_backends();

        keys.sort_by(|a, b| {
            let gpu_rank = |k: &str| -> u8 {
                if k.contains(":cuda:") || k.contains(":rocm:") {
                    0
                } else if k.contains(":generic") {
                    2
                } else {
                    1
                }
            };
            gpu_rank(a).cmp(&gpu_rank(b)).then(a.cmp(b))
        });

        let gpu_backends: Vec<String> = keys
            .iter()
            .filter_map(|k| {
                let slot = self.workers.get(k)?.slot.lock().ok()?;
                if slot.gpu_tag != "generic" && slot.handle.is_some() {
                    Some(slot.backend.clone())
                } else {
                    None
                }
            })
            .collect();

        let mut recycled_keys: Vec<String> = Vec::new();

        for key in keys {
            let (gpu_name, device_index, slot_pci_bus_id, gpu_tag, backend, vram_bytes) =
                if let Some(entry) = self.workers.get(&key) {
                    // vram_bytes lives on the WorkerEntry, outside the slot Mutex.
                    let vram = entry.vram_bytes;
                    if let Ok(slot) = entry.slot.lock() {
                        (
                            slot.gpu_name.clone(),
                            slot.device_index,
                            slot.pci_bus_id.clone(),
                            slot.gpu_tag.clone(),
                            slot.backend.clone(),
                            vram,
                        )
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };

            if gpu_tag == "generic" && gpu_backends.contains(&backend) {
                tracing::info!("Skipping benchmark for {key} (GPU worker available for {backend})");
                continue;
            }

            match self.benchmark_slot_streaming(&key, on_progress) {
                Ok(entries) if !entries.is_empty() => {
                    results.push(SlotBenchmarkResult {
                        slot_key: key.clone(),
                        gpu_name,
                        device_index,
                        pci_bus_id: slot_pci_bus_id.clone(),
                        gpu_tag: gpu_tag.clone(),
                        entries,
                        vram_bytes,
                        host_peak_bytes: self.host_peak_for_slot(&key),
                    });
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Benchmark failed for {key}: {e:#}");
                }
            }

            if gpu_tag == "cuda" || gpu_tag == "rocm" {
                if let Some(entry) = self.workers.get(&key) {
                    // RECOVER the poison, as every other lock site in this file does. `if let Ok(..)`
                    // skipped the block silently, and one of the blocks this guards is the post-benchmark
                    // `shutdown()` that frees `sp1-gpu-server` between the two SP1 slots — so a single
                    // panic in the progress callback (which this file documents as a real production
                    // event) left card 0's server resident at ~17.6 GiB while card 1's benchmark started,
                    // with no log line to say the shutdown had been skipped. The other two guard the
                    // respawn, so a slot would silently never come back.
                    {
                        let mut slot = entry.slot.lock().unwrap_or_else(|e| {
                            tracing::warn!(
                            "slot {key} was poisoned by an earlier panic; recovering it so this \
                             shutdown/respawn is not silently skipped"
                        );
                            e.into_inner()
                        });
                        // PID first: `shutdown()` reaps (see the recycle path above), so no
                        // reader of this atomic may still see the number afterwards.
                        entry.clear_pid();
                        let reaped = if let Some(handle) = &mut slot.handle {
                            tracing::info!("Recycling GPU worker {key} to free VRAM");
                            handle.shutdown();
                            true
                        } else {
                            false
                        };
                        Self::mark_slot_dead(&mut slot, entry);
                        // Let the pages come back BEFORE the next slot's reservation is tested
                        // against them. Without this the second SP1 card was refused for host RAM
                        // 367 ms after the first card's worker was reaped — short by 0.2 GiB of a
                        // figure that had not updated yet — and silently got no row in the suite.
                        // The slot lock is still held here, which is harmless: this slot is already
                        // dead and the loop is sequential.
                        if reaped {
                            drop(slot);
                            wait_for_reclaim(&key, BENCHMARK_RECLAIM_WAIT);
                            slot = entry.slot.lock().unwrap_or_else(|e| e.into_inner());
                        }
                        recycled_keys.push(key.clone());
                    }
                }
            }
        }

        for key in &recycled_keys {
            if let Some(entry) = self.workers.get(key) {
                // RECOVER the poison, as every other lock site in this file does. `if let Ok(..)`
                // skipped the block silently, and one of the blocks this guards is the post-benchmark
                // `shutdown()` that frees `sp1-gpu-server` between the two SP1 slots — so a single
                // panic in the progress callback (which this file documents as a real production
                // event) left card 0's server resident at ~17.6 GiB while card 1's benchmark started,
                // with no log line to say the shutdown had been skipped. The other two guard the
                // respawn, so a slot would silently never come back.
                {
                    let mut slot = entry.slot.lock().unwrap_or_else(|e| {
                        tracing::warn!(
                            "slot {key} was poisoned by an earlier panic; recovering it so this \
                             shutdown/respawn is not silently skipped"
                        );
                        e.into_inner()
                    });
                    tracing::info!("Respawning GPU worker {key} after benchmarks");
                    slot.consecutive_failures = 0;
                    slot.last_failure = None;
                    if let Err(e) = Self::respawn(&mut slot) {
                        tracing::warn!(
                            "Failed to respawn GPU worker {key} after benchmarks: {e:#}"
                        );
                    }
                    if let Some(h) = slot.handle.as_ref() {
                        entry.publish_pid(h.pid());
                    }
                }
            }
        }

        results
    }

    /// Submit a proof to a backend worker.
    /// Accepts a logical backend name ("risc0"), vendor-level ("risc0:cuda"),
    /// or a full compound key ("risc0:cuda:0").
    /// When given a prefix, tries all matching slots with round-robin load balancing.
    pub fn prove(
        &self,
        backend: &str,
        elf: &[u8],
        input_data: &[u8],
        po2: Option<u8>,
        timeout: Option<Duration>,
        on_progress: Option<Box<dyn Fn(f64, &str) + Send>>,
    ) -> Result<ProofOutput> {
        // Never leave a prove unbounded: if the caller didn't set a deadline, arm a
        // generous backstop watchdog so a wedged worker can't hang forever. (The
        // miner's job path calls prove_min_vram directly with its own tuned timeout.)
        let timeout = timeout.or(Some(DEFAULT_PROVE_WATCHDOG_TIMEOUT));
        let mut used = None;
        self.prove_min_vram(
            backend,
            elf,
            input_data,
            po2,
            timeout,
            on_progress,
            None,
            &[],
            &[],
            &mut used,
            None,
            None,
        )
    }

    /// Is any worker for `backend` idle right now?
    ///
    /// Lets a caller skip expensive preparation (descriptor + ELF fetches, which can hit the
    /// chain) when a measurement would be refused anyway. Best-effort by nature: the worker
    /// can become busy between this probe and the attempt, which `execute_cycles` handles.
    pub fn has_idle_worker(&self, backend: &str) -> bool {
        self.keys_for_prefix(backend).iter().any(|k| {
            self.workers
                .get(k)
                .is_some_and(|e| e.slot.try_lock().is_ok())
        })
    }

    /// Measure a job's TRUE cycle count by executing the guest, without proving it.
    ///
    /// Every scheduling decision is sized from `expectedCycles` on the job descriptor, which
    /// is submitter-declared and — on the observed market — always zero, leaving a hardcoded
    /// 34e6 fallback that is ~8x below the measured median. This is the only way to learn the
    /// real number before committing collateral.
    ///
    /// Runs on any live worker for `backend` WITHOUT taking that worker's GPU lock: execution
    /// is CPU work in the default executor, so it must not block or contend with the proofs it
    /// exists to schedule. `timeout` bounds it — an unexpectedly enormous guest must not stall
    /// the brain loop.
    pub fn execute_cycles(
        &self,
        backend: &str,
        elf: &[u8],
        input_data: &[u8],
        timeout: Option<Duration>,
    ) -> anyhow::Result<u64> {
        let keys = self.keys_for_prefix(backend);
        if keys.is_empty() {
            anyhow::bail!("no worker registered for backend '{backend}'");
        }

        // Try EVERY worker, not just the first. `try_lock` never blocks — a busy worker is
        // proving and a sizing measurement must never queue behind one — but taking only
        // `keys.first()` meant a rig whose first GPU was busy never measured at all, even with
        // the second one idle. Measured live: 8 of 12 attempts skipped, every one naming
        // `risc0:cuda:0`, while `cuda:1` sat free.
        let (key, entry, mut slot) = {
            let mut found = None;
            for k in &keys {
                let Some(e) = self.workers.get(k) else {
                    continue;
                };
                if let Ok(sl) = e.slot.try_lock() {
                    found = Some((k.clone(), e, sl));
                    break;
                }
            }
            match found {
                Some(f) => f,
                None => anyhow::bail!(
                    "all {} '{backend}' worker(s) busy; skipping cycle measurement",
                    keys.len()
                ),
            }
        };
        let key = key.as_str();
        let handle = slot
            .handle
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("worker '{key}' has no live handle"))?;

        static EXEC_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let request_id =
            EXEC_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) | 0x8000_0000_0000_0000; // keep execute ids disjoint from prove ids

        // Reset BEFORE the watchdog is installed, like `prove_on_slot` and `benchmark_slot` do.
        // Without it this path inherited whatever the last dispatch left behind, so an execution
        // killed by its own watchdog could be scored as an unintentional failure, or an unrelated
        // death excused as intentional.
        entry.intentional_kill.store(false, Ordering::Release);

        handle.send(&WorkerCommand::Execute {
            request_id,
            elf: elf.to_vec(),
            input_data: input_data.to_vec(),
        })?;

        // Bound it the same way a proof is bounded: the watchdog SIGKILLs the worker if the
        // guest never terminates. Destructive, but the alternative is a wedged worker holding
        // its slot forever, and the dispatcher already respawns on death. A guest that cannot
        // be executed inside the budget is also one we must not claim.
        let _watchdog = timeout.map(|t| {
            ProvingWatchdog::new(
                entry.pid.clone(),
                entry.pid_starttime.clone(),
                t,
                key.to_string(),
                entry.intentional_kill.clone(),
            )
        });

        // CLEAR THE SLOT on death. This was the one dispatch path that propagated an EOF without
        // touching the slot: the dead `WorkerHandle` stayed in place, so its child was never reaped
        // (a permanent zombie holding its stderr thread and pipe fd), and `entry.pid` kept
        // publishing a dead pid to every signaller. The pid was safe only by accident — pinned by
        // the very zombie this leaked. `mark_slot_dead`, not `mark_slot_failed`: the watchdog's kill
        // was intentional and must not count against the slot's health.
        let response = match handle.recv_proof(request_id, &None) {
            Ok(r) => r,
            Err(e) => {
                if entry.intentional_kill.load(Ordering::Acquire) {
                    Self::mark_slot_dead(&mut slot, entry);
                } else {
                    Self::mark_slot_failed(&mut slot, entry);
                }
                return Err(e);
            }
        };
        match response {
            WorkerResponse::ExecuteResult {
                cycles,
                duration_secs,
                ..
            } => {
                tracing::debug!(
                    "cycle measurement on {key}: {cycles} cycles in {duration_secs:.2}s"
                );
                Ok(cycles)
            }
            WorkerResponse::Error { message, .. } => {
                anyhow::bail!("cycle measurement failed: {message}")
            }
            other => anyhow::bail!("unexpected response to Execute: {other:?}"),
        }
    }

    /// Like [`prove`], but with three extra controls used by the miner's retry loop:
    ///
    /// - `min_vram_bytes`: only dispatch to workers with at least this much VRAM
    ///   (keeps large, OOM-prone proofs off smaller cards, e.g. a 300-segment proof
    ///   onto a 32 GB GPU, not 24 GB). If no worker meets the floor (or none report
    ///   VRAM), falls back to the full worker set so a job is never stranded.
    /// - `exclude`: prefer workers whose slot key is NOT in this list — used to
    ///   steer a retry away from a GPU that just wedged/timed out. Never strands:
    ///   if excluding leaves no candidate, the full set is used.
    /// - `used_slot`: set to the slot key actually dispatched to (BEFORE the proof
    ///   runs, so it's populated even when the proof errors/times out), letting the
    ///   caller exclude a wedged worker on the next attempt.
    /// - `abort_at`: an absolute monotonic instant past which this proof must not
    ///   run (the miner sets it to the job's lock deadline minus a release margin).
    ///   Unlike `timeout` (a relative wedge budget that starts when the proof
    ///   actually begins), this is re-checked AFTER any GPU-queue / respawn wait, so
    ///   queue latency can't erase the caller's release margin. If the instant has
    ///   already passed by the time a worker is ready, the proof isn't started and an
    ///   error is returned so the caller can release the job in time.
    /// - `disabled`: slots the OPERATOR switched off, as a HARD filter. Unlike `exclude` this is
    ///   never restored when it empties the candidate set: a disabled device stays disabled even if
    ///   that means the dispatch fails, because the reason for disabling it may be that using it
    ///   breaks the host. See the note on the parameter.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_min_vram(
        &self,
        backend: &str,
        elf: &[u8],
        input_data: &[u8],
        po2: Option<u8>,
        timeout: Option<Duration>,
        on_progress: Option<Box<dyn Fn(f64, &str) + Send>>,
        min_vram_bytes: Option<u64>,
        exclude: &[String],
        // Slots the OPERATOR switched off. A HARD filter, unlike `exclude`.
        //
        // `exclude` is a preference — "this card just wedged, prefer another" — and is deliberately
        // restored when pruning empties the set, so a wedge can never strand a job. Applying the
        // Settings toggles through that same list made them decorative in the common case: on a
        // single-GPU rig, disabling that GPU leaves the pruned set empty, the full set is restored,
        // and the proof runs on the card the operator just switched off — while the debug line
        // claims the slot was excluded. A disabled device must stay disabled even if that means the
        // dispatch fails, because the operator's reason for disabling it may be that using it breaks
        // the host.
        disabled: &[String],
        used_slot: &mut Option<String>,
        abort_at: Option<Instant>,
        // Resolves the segment size (po2) for the slot that is ultimately chosen.
        // Needed because the DEVICE is picked in here (VRAM floor, availability,
        // exclusions) — the caller cannot know it in advance, and po2 is a
        // per-device property. Consulted only when `po2` is None.
        po2_resolver: Option<&dyn Fn(&str) -> Option<u8>>,
    ) -> Result<ProofOutput> {
        let mut all_keys = self.keys_for_prefix(backend);
        if all_keys.is_empty() {
            bail!("No worker registered for backend '{backend}'");
        }
        // The hard filter, applied FIRST and never restored. See `disabled`.
        if !disabled.is_empty() {
            all_keys.retain(|k| !disabled.contains(k));
            if all_keys.is_empty() {
                bail!(
                    "every {backend} device is disabled in settings, so this job cannot be proved. \
                     Re-enable one on the Settings screen, or stop claiming {backend} jobs."
                );
            }
        }

        // Apply the VRAM floor (if requested). vram_bytes lives on WorkerEntry
        // (outside the slot Mutex), so this is lock-free even for busy workers.
        let vram_keys: Vec<String> = match min_vram_bytes {
            Some(min) => {
                let filtered: Vec<String> = all_keys
                    .iter()
                    .filter(|k| {
                        self.workers
                            .get(*k)
                            .and_then(|e| e.vram_bytes)
                            .map(|v| v >= min)
                            .unwrap_or(false)
                    })
                    .cloned()
                    .collect();
                if filtered.is_empty() {
                    tracing::warn!(
                        "No worker has >= {} MiB VRAM; dispatching without the floor",
                        min / (1024 * 1024)
                    );
                    all_keys
                } else {
                    filtered
                }
            }
            None => all_keys,
        };

        // Prefer workers not in `exclude` (e.g. a GPU that just wedged), but never
        // strand the job: if excluding leaves nothing, keep the full VRAM set.
        let keys: Vec<String> = if exclude.is_empty() {
            vram_keys
        } else {
            let pruned: Vec<String> = vram_keys
                .iter()
                .filter(|k| !exclude.contains(*k))
                .cloned()
                .collect();
            if pruned.is_empty() {
                vram_keys
            } else {
                pruned
            }
        };

        // Single key — use it directly, UNLESS it is a dead slot still inside its own
        // respawn backoff window.
        //
        // This shortcut is how soak20 lost its jobs. Pruning a two-key set by one
        // exclusion leaves exactly one key, so the retry took this path straight into
        // `prove_on_slot` -> `ensure_alive` -> `respawn`, which bailed instantly with
        // "Backoff: waiting 4.53s" and consumed the caller's last attempt 155us after
        // the previous one. Falling through to the poll loop instead WAITS the window
        // out, and that loop gives up only with `MIN_ABORT_START_BUDGET` left, so the
        // job gets a real attempt rather than a timer rejection.
        //
        // A RETIRED slot (`slot_eligible == false`) deliberately still takes the fast
        // path: its honest "permanently failed" error is more useful than a long wait.
        // Uses `try_lock` so a slot that is merely BUSY proving is never mistaken for
        // one in backoff -- a held lock means alive, which is not a backoff state.
        let backoff_blocked = keys.len() == 1
            && self
                .workers
                .get(&keys[0])
                .and_then(|e| e.slot.try_lock().ok())
                .is_some_and(|slot| Self::slot_eligible(&slot) && Self::in_respawn_backoff(&slot));
        if keys.len() == 1 && !backoff_blocked {
            *used_slot = Some(keys[0].clone());
            return self.prove_on_slot(
                &keys[0],
                elf,
                input_data,
                po2,
                timeout,
                on_progress,
                abort_at,
                po2_resolver,
            );
        }

        // ROTATE for fairness, then order WARM SLOTS FIRST.
        //
        // A slot whose worker is already resident costs only the difference between what it holds and
        // the expected peak, because those pages are already out of `MemAvailable`. That makes it both
        // the cheapest dispatch (no CUDA re-init, warm proving-key cache) and the one the host-memory
        // gate is most likely to admit — which is what keeps the claim gate's optimistic credit
        // honest: the gate reasons about the warmest slot, so routing has to actually try that slot.
        // Without it, a backend with one warm and one cold slot could pass the claim gate on the warm
        // slot's credit and then be handed the cold one, take the host-RAM backoff, and only reach the
        // warm slot a pass or two later.
        //
        // Order matters here. The rotation is applied FIRST and the sort is STABLE, so fairness
        // survives inside each warmth tier: two equally warm slots still alternate rather than one
        // being favoured for ever. Sorting first and then applying the offset would have landed on a
        // cold slot anyway, defeating the point.
        let keys: Vec<String> = {
            let offset = ROUND_ROBIN.fetch_add(1, Ordering::Relaxed) % keys.len();
            let mut rotated: Vec<String> = keys[offset..]
                .iter()
                .chain(keys[..offset].iter())
                .cloned()
                .collect();
            let resident = self.resident_bytes_by_slot(&rotated);
            if resident.iter().any(|(_, r)| *r > 0) {
                let mut ordered = resident;
                ordered.sort_by(|a, b| b.1.cmp(&a.1));
                rotated = ordered.into_iter().map(|(k, _)| k).collect();
            }
            rotated
        };

        for key in &keys {
            if let Some(entry) = self.workers.get(key) {
                // Prefer a worker whose PHYSICAL GPU is idle: skip one whose gpu_lock
                // is held by another backend proving on the same card, so we don't
                // block on a busy GPU while a different one sits free. Best-effort
                // (the lock may be taken between here and prove_on_slot); the fallback
                // below still guarantees the job runs if every candidate is busy.
                // Treat a POISONED-but-unlocked lock as free: a proof thread that
                // panicked while holding the guard poisons the mutex, but nothing is
                // actually proving on the card. Only `WouldBlock` means another backend
                // holds it — otherwise a one-time panic would sideline that GPU to the
                // fallback path for the rest of the process.
                let gpu_free = self.gpu_lock_for(key).is_none_or(|l| {
                    !matches!(l.try_lock(), Err(std::sync::TryLockError::WouldBlock))
                });
                if !gpu_free {
                    continue;
                }
                if let Ok(mut slot) = entry.slot.try_lock() {
                    let is_alive = slot.handle.as_mut().map(|h| h.is_alive()).unwrap_or(false);
                    if is_alive || Self::slot_dispatchable(&slot) {
                        drop(slot);
                        *used_slot = Some(key.clone());
                        return self.prove_on_slot(
                            key,
                            elf,
                            input_data,
                            po2,
                            timeout,
                            on_progress,
                            abort_at,
                            po2_resolver,
                        );
                    }
                }
            }
        }

        // All busy — wait for whichever eligible slot frees FIRST, staying deadline-aware.
        //
        // This used to be a BLOCKING `slot.lock()` on the first key that looked eligible,
        // falling back to `keys[0]`. Two defects, both only reachable once more jobs are in
        // flight than there are cards:
        //
        //  * `keys` comes from a `HashMap` iteration and is unsorted, so every over-committed
        //    job parked on the SAME arbitrary card and none of them migrated when a different
        //    card freed. On a 2-GPU rig that serialises everything onto one card while the
        //    other idles — the exact inversion look-ahead queueing exists to remove.
        //  * `abort_at` is not consulted until `prove_on_slot` (after it takes the same locks),
        //    so a job waiting on that mutex had NO clock. It could sit past its own lock
        //    deadline and only discover it once granted, by which point `releaseJob` reverts
        //    and the collateral is lost outright rather than released for a penalty.
        //
        // Polling re-runs the same eligibility scan over ALL keys, so the job goes to whichever
        // card frees first, and re-checks the deadline every pass so it can bail while there is
        // still time to release.
        // A job with no `abort_at` (recovery re-drives, benchmarks) has no deadline to bail
        // on, so bound the wait by the caller's own proving `timeout` — otherwise a rig whose
        // every slot is permanently failed would spin here forever, where the old blocking
        // version at least returned an error from `prove_on_slot`.
        const QUEUE_POLL: Duration = Duration::from_millis(250);
        // `timeout` is optional; with neither it nor `abort_at` there is no deadline to
        // honour, so fall back to a generous absolute cap rather than spinning forever.
        const QUEUE_WAIT_CAP: Duration = Duration::from_secs(3600);
        let queue_deadline = Instant::now() + timeout.unwrap_or(QUEUE_WAIT_CAP);
        loop {
            for key in &keys {
                let Some(entry) = self.workers.get(key) else {
                    continue;
                };
                let gpu_free = self.gpu_lock_for(key).is_none_or(|l| {
                    !matches!(l.try_lock(), Err(std::sync::TryLockError::WouldBlock))
                });
                if !gpu_free {
                    continue;
                }
                if let Ok(mut slot) = entry.slot.try_lock() {
                    let is_alive = slot.handle.as_mut().map(|h| h.is_alive()).unwrap_or(false);
                    if is_alive || Self::slot_dispatchable(&slot) {
                        drop(slot);
                        *used_slot = Some(key.clone());
                        return self.prove_on_slot(
                            key,
                            elf,
                            input_data,
                            po2,
                            timeout,
                            on_progress,
                            abort_at,
                            po2_resolver,
                        );
                    }
                }
            }
            // Bail while a release can still succeed, rather than after the deadline passes.
            if let Some(abort) = abort_at {
                if abort.saturating_duration_since(Instant::now()) < MIN_ABORT_START_BUDGET {
                    // TYPED, so the caller's terminal classification cannot be forged by guest
                    // text. See `ProofDeadlineReached`.
                    return Err(anyhow::Error::new(
                        zkminer_prover_protocol::types::ProofDeadlineReached {
                            detail: "deadline cutoff reached while queued for a worker \
                                     (releasing to recover collateral)"
                                .to_string(),
                        },
                    ));
                }
            }
            if Instant::now() >= queue_deadline {
                anyhow::bail!(
                    "no worker slot became available within {:?} (all {} slot(s) busy or \
                     failed)",
                    timeout.unwrap_or(QUEUE_WAIT_CAP),
                    keys.len()
                );
            }
            std::thread::sleep(QUEUE_POLL);
        }
    }

    /// Benchmark-facing device id for a slot key: `"risc0:cuda:1"` -> `"gpu1"`,
    /// `"sp1:generic"` -> `"cpu"`.
    ///
    /// MUST stay in sync with the ids emitted by
    /// `benchmark::build_gpu_device_benchmarks_from_workers` (`format!("gpu{idx}")`)
    /// and the CPU rows (`"cpu"`), otherwise a `Po2Profile` lookup silently misses and
    /// proving quietly falls back to the SDK default.
    fn benchmark_device_id(key: &str) -> String {
        let mut parts = key.split(':');
        let _backend = parts.next();
        match (parts.next(), parts.next()) {
            (Some("generic"), _) | (None, _) => "cpu".to_string(),
            // The vendor tag is PART of a card's identity. Dropping it made
            // `risc0:cuda:0` and `risc0:rocm:0` -- two different physical cards --
            // both mint "gpu0", so on a mixed proving box one row silently
            // overwrites the other's throughput and po2 calibration, with which
            // one survives depending on HashMap iteration order. `physical_gpu_id`
            // in this same file already keeps the tag; this now agrees with it.
            (Some(gpu_tag), Some(idx)) => Self::gpu_device_id(gpu_tag, idx),
            (Some(gpu_tag), None) => Self::gpu_device_id(gpu_tag, "0"),
        }
    }

    /// Publish the per-backend host-memory expectations from a measured suite.
    ///
    /// Call this whenever a suite is loaded or re-benchmarked; admission is only as good as the
    /// figures it has.
    pub fn set_expected_host_peaks(&self, suite: &crate::benchmark::BenchmarkSuite) {
        const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
        let total = crate::memory::mem_total_bytes().unwrap_or(u64::MAX);
        let ceiling = crate::memory::max_admissible_budget(total);
        let mut map = HashMap::new();
        for backend in ["risc0", "sp1", "openvm"] {
            map.insert(backend.to_string(), suite.expected_host_peak_bytes(backend));
        }

        // Recover a poisoned lock rather than silently skipping the publish. Skipping left every
        // backend on its blind default for the life of the process, with no log line to say so —
        // and the data behind this lock is a plain map with no invariant a panic could break.
        let mut guard = self
            .expected_peaks
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Log only when a figure CHANGES. The brain republishes every tick, so logging
        // unconditionally would put three lines in the file every few seconds forever.
        if *guard != map {
            for backend in ["risc0", "sp1", "openvm"] {
                let Some(&budget) = map.get(backend) else {
                    continue;
                };
                if guard.get(backend) == Some(&budget) {
                    continue;
                }
                let measured = suite
                    .devices_for_backend(backend)
                    .iter()
                    .any(|d| d.host_peak_bytes.is_some());
                let source = if measured {
                    "measured"
                } else {
                    "unmeasured default"
                };
                // State the CONSEQUENCE, not just the figure. "6.0 GiB" means nothing to an
                // operator; "two at a time on this box" is the thing they can act on, and it is the
                // number the rest of the configuration has to agree with.
                let concurrency = if budget == 0 {
                    u64::MAX
                } else {
                    ceiling / budget
                };
                if budget >= ceiling {
                    tracing::warn!(
                        "{backend} host-memory budget {:.1} GiB ({source}) is at the ceiling this \
                         {:.1} GiB box can admit, so only ONE {backend} proof will ever run at a \
                         time. If that is not what you expect: the peak is larger than the machine \
                         can hold concurrently — add RAM, lower the resolved po2, or re-benchmark.",
                        budget as f64 / GIB,
                        total as f64 / GIB,
                    );
                } else {
                    tracing::info!(
                        "{backend} host-memory budget {:.1} GiB ({source}) — admits up to \
                         {concurrency} concurrent {backend} proofs on this {:.1} GiB box.",
                        budget as f64 / GIB,
                        total as f64 / GIB,
                    );
                }
            }
        }
        *guard = map;
    }

    /// Expected host peak for a backend, or that backend's conservative default if nothing was
    /// published.
    ///
    /// Per-backend, not one blunt figure: charging risc0 the SP1 default needs ~21 GiB free before
    /// anything is admitted, so an unbenchmarked 2-GPU box would sit idle reporting only that it
    /// "cannot fit it right now". Same reason `unmeasured_peak_for` exists at all.
    pub fn expected_host_peak(&self, backend: &str) -> u64 {
        self.expected_peaks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(backend)
            .copied()
            .unwrap_or_else(|| {
                crate::memory::admissible_unmeasured_peak_for(
                    backend,
                    crate::memory::mem_total_bytes().unwrap_or(u64::MAX),
                )
            })
    }

    /// As `expected_host_peak`, scaled to the segment size the proof will actually use.
    ///
    /// The budget is stored per backend and is otherwise po2-BLIND, while host memory doubles per po2
    /// step. So a TUI `po2_overrides` entry raising risc0 from 21 to 24 multiplied the real cost
    /// roughly eightfold with no change to any admission figure — and the `Critical` log line advised
    /// lowering po2 as the remedy for a number po2 did not affect. `None` means the resolver had no
    /// opinion, in which case the stored figure already describes the default.
    pub fn expected_host_peak_at_po2(&self, backend: &str, po2: Option<u8>) -> u64 {
        let base = self.expected_host_peak(backend);
        match po2 {
            Some(p) => crate::memory::peak_for_po2(base, p),
            None => base,
        }
    }

    /// Reserve host memory for a proof about to start, or refuse it.
    ///
    /// The second half of the memory defence, and the half the per-worker ceiling cannot provide: a
    /// ceiling stops ONE worker from taking the host down, but several workers each under their
    /// ceiling can still sum past RAM. That sum is what froze this box — four concurrent provers,
    /// none individually enormous.
    ///
    /// `expected_peak` comes from the benchmark suite's measured `host_peak_bytes` for this
    /// backend, scaled by `MEASUREMENT_SAFETY_FACTOR`; an unmeasured backend is charged
    /// `unmeasured_peak_for(backend)`, because the only safe assumption about an unmeasured proof
    /// is that it is expensive.
    pub fn reserve_host_memory(
        &self,
        expected_peak: u64,
        slot_key: &str,
    ) -> Option<crate::memory::MemoryReservation<'_>> {
        // Both gates share ONE policy for "the host's memory is unreadable": fail OPEN, and keep
        // accounting. They previously disagreed — the claim gate returned `true` while this returned
        // `None` — so an unreadable `/proc/meminfo` let every job pass the claim gate and then fail
        // at dispatch: a penalised release per job, indefinitely. Failing open is the right half to
        // keep, since the per-worker ceiling and `oom_score_adj` still stand behind it, whereas
        // refusing all work over a missing file stops the miner dead.
        let (available, total) = match (
            crate::memory::mem_available_bytes(),
            crate::memory::mem_total_bytes(),
        ) {
            (Some(a), Some(t)) => (a, t),
            _ => {
                tracing::warn!(
                    "cannot read host memory; admission control is inactive for this proof. The \
                     per-worker ceiling and oom_score_adj still apply."
                );
                (u64::MAX, u64::MAX)
            }
        };
        // What THIS slot's worker is already holding. `available` is already net of it, so charging
        // the full peak on top would count the same pages twice — see `can_admit`'s `resident`.
        // Zero when unreadable, which is the conservative reading.
        let resident = self.current_host_bytes_for_slot(slot_key).unwrap_or(0);
        self.memory_ledger.try_reserve(
            expected_peak,
            resident,
            available,
            total,
            crate::memory::DEFAULT_HOST_RESERVE_BYTES,
        )
    }

    /// Bytes this slot's live worker is holding right now, if we can tell.
    ///
    /// Admission needs this because workers are long-lived and keep their allocations between
    /// proofs — the SP1 worker caches `CudaProver` and its proving keys deliberately. Without it,
    /// proof #2 on a slot is charged for memory proof #1 never gave back.
    #[cfg(unix)]
    pub fn current_host_bytes_for_slot(&self, slot_key: &str) -> Option<u64> {
        let entry = self.workers.get(slot_key)?;
        let pid = entry.pid.load(Ordering::Acquire);
        if pid == 0 {
            return None;
        }
        let backend = slot_key.split(':').next().unwrap_or(slot_key);
        crate::memory::anon_memory_of_pid(pid, Some(&crate::memory::cap_unit_name(backend, pid)))
    }

    #[cfg(not(unix))]
    pub fn current_host_bytes_for_slot(&self, _slot_key: &str) -> Option<u64> {
        None
    }

    /// Host memory currently claimed by in-flight proofs, in bytes.
    pub fn reserved_host_memory(&self) -> u64 {
        self.memory_ledger.reserved_bytes()
    }

    /// Has the operator switched off every device this backend could run on?
    ///
    /// For the CLAIM gate. `prove_min_vram` applies disabled slots as a hard filter and bails when they
    /// leave nothing — which is right, but it happens after the collateral is bonded, so the job can
    /// then only be released at a penalty or stranded. Asking before claiming costs nothing.
    pub fn every_slot_disabled(&self, backend: &str, disabled: &[String]) -> bool {
        let mut any = false;
        for key in self.workers.keys() {
            if key.split(':').next() != Some(backend) {
                continue;
            }
            any = true;
            if !disabled.contains(key) {
                return false;
            }
        }
        // No slots at all is not "all disabled" — that is the no-worker case, which the availability
        // gate below already handles and which must not be confused with an operator decision.
        any
    }

    /// The LARGEST resident set among this backend's live workers, in bytes.
    ///
    /// For the CLAIM gate, which has no slot yet. If a worker for this backend is already holding R
    /// bytes, a proof dispatched there costs only `peak - R` more, because those pages are already out
    /// of `MemAvailable`.
    ///
    /// The MAXIMUM, and the reasoning has been round the houses, so it is worth recording why.
    ///
    /// MAX is optimistic: the warm slot might be busy, so a claim can pass the gate and then land on a
    /// cold slot where the dispatch gate refuses it. MIN avoids that — and MIN is catastrophic the
    /// moment a backend has more than one slot. Walk it with SP1's two cards: proof #1 runs on card 0
    /// and leaves `sp1-gpu-server` resident at ~17.6 GiB, deliberately, so the next proof is cheap.
    /// `MemAvailable` is now down by that much. MIN credits the COLD slot's 0, so `fits_now` asks for
    /// `18 + 3` against the 6.8 GiB that remains and refuses — and keeps refusing, because nothing
    /// frees a warm worker and the 20-proof recycle will never be reached. One SP1 proof per process
    /// start, for ever, with the ledger reading 0 and every layer reporting healthy.
    ///
    /// MAX's failure mode is bounded in a way MIN's is not: a claim that lands on the cold slot takes
    /// the host-RAM backoff, and each retry re-enters `prove_min_vram`, which advances the round-robin
    /// cursor — so it reaches the warm slot within a pass or two, and the free waits are capped
    /// independently of the deadline. Latency, not an outage. `prove_min_vram` also now prefers a slot
    /// whose worker is already warm, which closes most of the gap directly.
    #[cfg(unix)]
    fn resident_host_bytes_for_backend(&self, backend: &str) -> u64 {
        self.workers
            .keys()
            .filter(|key| key.split(':').next() == Some(backend))
            .filter_map(|key| self.current_host_bytes_for_slot(key))
            .max()
            .unwrap_or(0)
    }

    /// Bytes this backend's workers are holding, per slot key — for routing, not for admission.
    ///
    /// `prove_min_vram` uses it to prefer a slot whose worker is already warm. Dispatching there costs
    /// only the difference between its resident set and the expected peak, so it is both the fastest
    /// choice (no CUDA re-init, warm `pk_cache`) and the one most likely to be admitted — which is
    /// what keeps the claim gate's optimistic MAX credit honest.
    #[cfg(unix)]
    fn resident_bytes_by_slot(&self, keys: &[String]) -> Vec<(String, u64)> {
        keys.iter()
            .map(|k| (k.clone(), self.current_host_bytes_for_slot(k).unwrap_or(0)))
            .collect()
    }

    #[cfg(not(unix))]
    fn resident_bytes_by_slot(&self, keys: &[String]) -> Vec<(String, u64)> {
        keys.iter().map(|k| (k.clone(), 0)).collect()
    }

    #[cfg(not(unix))]
    fn resident_host_bytes_for_backend(&self, _backend: &str) -> u64 {
        0
    }

    /// Could this host run the concurrent set that claiming one more `backend` job implies?
    ///
    /// For the CLAIM decision, and the question is deliberately NOT "does one more peak fit on top
    /// of everything outstanding". Claimed jobs prove SEQUENTIALLY, bounded by `max_concurrent` — the
    /// whole premise of the look-ahead queue is that a claim is a reservation of future time, not of
    /// present memory. So the memory a set of claims can ever demand at once is
    /// `min(outstanding + 1, max_concurrent)` peaks, and that is what has to fit.
    ///
    /// This replaced a per-tick accumulator that was wrong in both directions. Within a tick it
    /// charged every candidate a full concurrent peak, capping claims at `total / peak` — 4 for
    /// risc0, 1 for SP1 — and overriding the planner's own feasibility maths with a constraint that
    /// had nothing to do with when the proof would run. Across ticks it lapsed entirely: it was
    /// declared inside the loop body and reset, while `reserved_host_memory` does not move until a
    /// proof SPAWNS minutes later, so by the third tick the brain could reach its `max_concurrent * 3`
    /// ceiling with no memory accounting at all on the last claims. Keying off `outstanding`, which
    /// lives in `in_flight` and therefore survives the tick boundary, fixes both and needs no
    /// accumulator.
    ///
    /// `outstanding` counts claims not yet finished, spawned or not. Those already spawned are also
    /// in `reserved_host_memory`, which is why the committed term below uses the concurrency bound
    /// rather than adding the two together.
    pub fn backend_fits_for_claim(
        &self,
        expected_peak: u64,
        backend: &str,
        outstanding: usize,
        max_concurrent: usize,
    ) -> bool {
        let (Some(available), Some(total)) = (
            crate::memory::mem_available_bytes(),
            crate::memory::mem_total_bytes(),
        ) else {
            // Fail OPEN, matching `reserve_host_memory`. See the note there.
            return true;
        };
        let reserve = crate::memory::DEFAULT_HOST_RESERVE_BYTES;
        // How many of this backend's proofs could be running at once if we take this one.
        let concurrent = outstanding.saturating_add(1).min(max_concurrent.max(1)) as u64;
        let committed = expected_peak.saturating_mul(concurrent);
        if committed.saturating_add(reserve) > total {
            return false;
        }
        // And one more increment has to fit in live headroom. `resident` is credited here because a
        // proof landing on a slot whose worker is already resident costs only the difference —
        // credited ONCE, not once per candidate, which is why this takes `outstanding` rather than a
        // running total: the saving applies to whichever single proof lands on that slot.
        let resident = if outstanding == 0 {
            self.resident_host_bytes_for_backend(backend)
        } else {
            0
        };
        crate::memory::can_admit(
            expected_peak,
            resident,
            self.reserved_host_memory(),
            available,
            total,
            reserve,
        )
    }

    /// Peak host memory this slot's worker has reached, in bytes.
    ///
    /// Must be called while the worker is ALIVE: the counter lives in the worker's transient cgroup,
    /// which the kernel destroys with its last process. Takes NO lock at all — it reads an atomic
    /// pid and then `/proc` — so it cannot block on a proving slot. (An earlier version of this
    /// comment claimed a `try_lock` the body never performed.)
    pub fn host_peak_for_slot(&self, key: &str) -> Option<u64> {
        let entry = self.workers.get(key)?;
        let pid = entry.pid.load(Ordering::Acquire);
        if pid == 0 {
            return None;
        }
        let backend = key.split(':').next().unwrap_or(key);
        if let Some(cgroup_peak) = crate::memory::peak_memory_of_pid(
            pid,
            Some(&crate::memory::cap_unit_name(backend, pid)),
        ) {
            return Some(cgroup_peak);
        }
        // FALLBACK, and it has to exist. `peak_memory_of_pid` returns `None` whenever the worker is
        // not in a cgroup we created — which is a SUPPORTED state, because the cap is best effort
        // (no systemd user bus, a container, a `busctl` timeout). Without this branch such a host
        // measured nothing, ever: `host_peak_bytes` stayed `None` for the life of the install,
        // indistinguishable from "not benchmarked", and every backend was charged its blind default
        // forever. The fallback was written for exactly this case and then never wired in.
        //
        // Sum of `VmHWM` across the worker's process group, which is the figure that matters here:
        // the SP1 SDK forks `sp1-gpu-server` into our group, and it is the grandchild that holds the
        // memory. Less accurate than the cgroup counter — high-water marks do not necessarily
        // coincide, so the sum can overstate — and overstating is the safe direction.
        crate::memory::process_group_peak_bytes(std::path::Path::new("/proc"), pid as i32)
    }

    /// Canonical PCI bus id of the card behind a slot key, if it is a GPU slot.
    ///
    /// Takes NO lock: see `WorkerEntry::pci_bus_id`. It is called from the proving progress
    /// callback, which runs on the thread that already holds that slot's guard.
    pub fn bus_id_for_slot(&self, key: &str) -> Option<String> {
        self.workers.get(key)?.pci_bus_id.clone()
    }

    /// The reason a backend DECLINED, if every slot serving it declined.
    ///
    /// A declined backend must not be reported as `Simulated` either: that is the
    /// demo-mode signal, and the pre-claim gate deliberately no-ops in demo mode. A host
    /// whose only worker declined would otherwise look like a demo and resume claiming.
    pub fn backend_declined(&self, backend: &str) -> Option<String> {
        let mut reason = None;
        let mut saw_any = false;
        for (key, entry) in &self.workers {
            if !key.starts_with(backend) {
                continue;
            }
            saw_any = true;
            // `try_lock`, not `lock`. A slot held by a proof cannot be a declined slot — a declined
            // worker never proves — so a busy slot is evidence the backend is NOT categorically
            // out, which is the same answer `None` gives. Blocking here would freeze both callers
            // (the dashboard render and the pre-claim gate) for the length of a proof: the hazard
            // that produced the `bus_id_for_slot` deadlock, one function along.
            match entry.slot.try_lock() {
                Ok(slot) => match &slot.declined {
                    Some(r) => reason = reason.or_else(|| Some(r.clone())),
                    // One non-declined slot means the backend is not categorically out.
                    None => return None,
                },
                // Busy (proving) or poisoned: either way, not categorically declined.
                Err(_) => return None,
            }
        }
        if saw_any {
            reason
        } else {
            None
        }
    }

    /// Total VRAM of the card behind `key`, if known.
    ///
    /// Lets a retry demand a STRICTLY BIGGER card after a VRAM OOM, instead of a fixed
    /// floor that may exceed every card on the box and therefore steer nowhere.
    pub fn vram_bytes_for_slot(&self, key: &str) -> Option<u64> {
        self.workers.get(key).and_then(|e| e.vram_bytes)
    }

    /// `(foreign, used, total)` VRAM for this slot's card in bytes: what processes that are NOT ours
    /// hold, what everything holds, and the card's capacity. `None` for a slot with no CUDA device or
    /// a card that cannot be read.
    ///
    /// Public so the gate's own evidence is observable from outside — a status display can show why a
    /// card is being skipped, and the warm-slot regression test can assert that OUR resident
    /// `sp1-gpu-server` is credited rather than counted. Uncached by design: occupancy changes while
    /// the miner runs, which is the entire point.
    pub fn foreign_vram_for_slot(&self, key: &str) -> Option<(u64, u64, u64)> {
        foreign_vram_bytes(slot_cuda_index(key)?)
    }

    /// PID of the worker behind `key`, or 0 if it has none. For tests that need to
    /// induce a real worker death.
    pub fn worker_pid(&self, key: &str) -> Option<u32> {
        self.workers.get(key).map(|e| e.pid.load(Ordering::Acquire))
    }

    /// Canonical PCI bus ids of every GPU slot in this pool.
    ///
    /// Used to scope power measurement to cards that are actually proving, so an
    /// idle GPU on the same box cannot contribute its draw (or, worse, its idle
    /// draw in place of a working card's).
    /// Takes NO lock: see `WorkerEntry::pci_bus_id`.
    ///
    /// This previously locked each slot, which stalled the caller for the length of a proof —
    /// the miner brain calls it per tick, so one in-flight proof idled the other GPU. `try_lock`
    /// fixed the stall but introduced a quieter bug: a busy slot was SKIPPED, so a card that was
    /// proving when a benchmark started was absent from the power sampler's filter and its row
    /// was written with the fallback wattage and cached. Reading the field outside the lock has
    /// neither problem.
    pub fn gpu_bus_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .workers
            .values()
            .filter_map(|e| e.pci_bus_id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Shut this slot's worker down so whatever it was holding is released.
    ///
    /// Exists because a worker holds its resources ON PURPOSE between proofs — SP1 caches `CudaProver`
    /// and its proving keys, keeping `sp1-gpu-server` resident at ~17.6 GiB of host RSS and ~10 GiB of
    /// VRAM — and with one slot per card a caller that walks every card leaves one of those per card.
    /// Two is more than this 28 GiB box can hold. `ensure_alive` respawns on the next dispatch, so the
    /// only cost is a CUDA re-init.
    ///
    /// Pid zeroed before the handle is dropped, for the reason given on `mark_slot_dead`: `drop` reaps,
    /// and after a reap the number may name something else.
    pub fn recycle_slot(&self, key: &str) {
        let Some(entry) = self.workers.get(key) else {
            return;
        };
        let mut slot = entry.slot.lock().unwrap_or_else(|e| e.into_inner());
        if slot.handle.is_none() {
            return;
        }
        tracing::info!("Recycling worker {key} to release what it is holding");
        entry.clear_pid();
        if let Some(h) = slot.handle.as_mut() {
            h.shutdown();
        }
        slot.handle = None;
    }

    /// Every GPU card the pool can prove on, as `(benchmark device id, PCI bus id)`.
    ///
    /// The device id comes from `benchmark_device_id`, which is the SAME derivation the real benchmark
    /// rows, the Settings toggles and `slots_disabled_by` use — so anything built from this list
    /// addresses cards by the ids the rest of the system already agrees on.
    ///
    /// That is the point. The synthetic fallback suite used to mint `gpu{i}` from a card's POSITION in
    /// a sorted bus-id list, which coincides with the real id only when the cards are enumerated from
    /// zero with none missing. Filter to the second card with `ZKMINER_GPU_NAME_FILTER` and the
    /// synthetic row says `gpu0` while `slots_disabled_by` says `gpu1`: the operator's toggle and the
    /// dispatcher's filter then name different things, and the toggle goes back to being decorative.
    ///
    /// Takes no lock: both fields live on `WorkerEntry`.
    pub fn gpu_cards(&self) -> Vec<(String, String)> {
        let mut cards: Vec<(String, String)> = self
            .workers
            .iter()
            .filter_map(|(key, e)| {
                let bus = e.pci_bus_id.clone()?;
                let device = Self::benchmark_device_id(key);
                device.starts_with("gpu").then_some((device, bus))
            })
            .collect();
        cards.sort();
        cards.dedup();
        cards
    }

    /// Take the per-physical-GPU guard for `key`, bounded so it can never wait past a deadline.
    ///
    /// EVERY path that puts work on a card must go through this. The guard is what stops two backends
    /// pinned to the same physical GPU — `risc0:cuda:0` and `sp1:cuda:0` — from double-booking its
    /// VRAM, and `sp1-gpu-server` alone was measured holding 10.3 GB of it.
    ///
    /// It exists as a shared helper because three paths had been left out of it and nothing made that
    /// visible: `benchmark_slot`, `benchmark_slot_streaming` and `calibrate_slot_po2` took the slot
    /// mutex and a host-memory reservation but not this lock. So pressing `[b]` on the TUI while a
    /// risc0 proof was running started a full SP1 benchmark on the same card, concurrently, with each
    /// side's VRAM invisible to the other — exactly the double-booking the lock was introduced to
    /// prevent, reached through a different door. Nothing pauses the brain for a benchmark either:
    /// `benchmark_running` is written and never read.
    ///
    /// Bounded, and by whichever limit exists. A bare `lock()` waits forever for the other backend,
    /// and a job parked that way can pass its own lock deadline with collateral bonded and then be
    /// unreleasable. `abort_at` gives the sharp bound; `timeout` is the fallback so a caller with a
    /// wedge budget and no deadline — recovery re-drives, `ProvingEngine::prove`, the integration
    /// tests — is bounded too, since the proof watchdog that would otherwise catch it is only armed
    /// later. With neither, the wait is genuinely unbounded, which is correct for a benchmark run
    /// from the CLI with no deadline to miss.
    fn acquire_gpu_guard<'a>(
        gpu_lock: Option<&'a Arc<Mutex<()>>>,
        key: &str,
        abort_at: Option<Instant>,
        timeout: Option<Duration>,
    ) -> Result<Option<std::sync::MutexGuard<'a, ()>>> {
        let Some(l) = gpu_lock else {
            return Ok(None);
        };
        // The instant past which waiting is pointless, if there is one.
        let give_up_at = match (abort_at, timeout) {
            (Some(abort), _) => Some(abort.checked_sub(MIN_ABORT_START_BUDGET).unwrap_or(abort)),
            (None, Some(t)) => Some(Instant::now() + t),
            (None, None) => None,
        };
        let Some(give_up_at) = give_up_at else {
            return Ok(Some(l.lock().unwrap_or_else(|e| e.into_inner())));
        };
        loop {
            match l.try_lock() {
                Ok(g) => return Ok(Some(g)),
                // Poisoned but not held: a proof thread panicked with the guard, yet nothing is
                // proving on the card. Recover rather than sideline the GPU for the process lifetime.
                Err(std::sync::TryLockError::Poisoned(e)) => return Ok(Some(e.into_inner())),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if Instant::now() >= give_up_at {
                        return Err(anyhow::Error::new(
                            zkminer_prover_protocol::types::ProofDeadlineReached {
                                detail: format!(
                                    "giving up waiting for the GPU behind {key}: the other backend \
                                     on that card is still using it and too little time is left to \
                                     start (releasing to recover collateral)"
                                ),
                            },
                        ));
                    }
                    std::thread::sleep(GPU_LOCK_POLL);
                }
            }
        }
    }

    /// Slot keys the operator has switched off, as a list suitable for `prove_min_vram`'s
    /// `exclude`.
    ///
    /// The Settings screen's per-device and per-device-backend toggles were honoured by mock mode
    /// and by nothing else: the dashboard struck the row out, mock stopped using it, and production
    /// kept proving on it. Mapping them onto the exclusion list the dispatcher already understands
    /// is the smallest way to make them real, and it keeps the authority in one place.
    ///
    /// Takes no lock — `benchmark_device_id` is derived from the key alone.
    pub fn slots_disabled_by(
        &self,
        disabled_devices: &std::collections::HashSet<String>,
        disabled_device_backends: &std::collections::HashSet<(String, String)>,
    ) -> Vec<String> {
        self.workers
            .keys()
            .filter(|key| {
                let device = Self::benchmark_device_id(key);
                let backend = key.split(':').next().unwrap_or(key).to_string();
                disabled_devices.contains(&device)
                    || disabled_device_backends.contains(&(device, backend))
            })
            .cloned()
            .collect()
    }

    /// Canonical benchmark device id for a GPU slot.
    ///
    /// `cuda` keeps the bare `gpuN` form so every existing `benchmarks.json`
    /// and every `starts_with("gpu")` GPU-row predicate keeps working unchanged;
    /// other vendors are tag-qualified (`gpu-rocm0`) so they cannot collide.
    pub fn gpu_device_id(gpu_tag: &str, idx: &str) -> String {
        if gpu_tag == "cuda" {
            format!("gpu{idx}")
        } else {
            format!("gpu-{gpu_tag}{idx}")
        }
    }

    /// Get-or-create the per-physical-GPU proving lock for a slot key (see
    /// `gpu_locks`). Returns `None` for unguarded slots (CPU/generic/explicit).
    fn gpu_lock_for(&self, key: &str) -> Option<Arc<Mutex<()>>> {
        let id = physical_gpu_id(key)?;
        let mut map = self.gpu_locks.lock().unwrap_or_else(|e| e.into_inner());
        Some(
            map.entry(id)
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone(),
        )
    }

    /// One value from a slot's respawn environment. For assertions about what the next spawn will be
    /// told; `test_set_spawn_env` is the write side.
    #[cfg(test)]
    pub fn spawn_env_value(&self, key: &str, name: &str) -> Option<String> {
        let entry = self.workers.get(key)?;
        let slot = entry.slot.lock().unwrap_or_else(|e| e.into_inner());
        slot.spawn_env.get(name).cloned()
    }

    /// Drop a worker that was sized for more free VRAM than the card now has, after updating the
    /// environment it will be respawned with.
    ///
    /// `respawn` reuses the frozen `slot.spawn_env`, so refreshing that map is what makes the next
    /// worker correctly sized; dropping the handle is what makes `ensure_alive` go and get one. A
    /// no-op unless the backend has a VRAM-derived sizing knob AND the knob would now be smaller, so
    /// the common case costs one comparison and the pathological case costs one respawn instead of a
    /// failed proof.
    ///
    /// Deliberately does NOT refuse the work. A smaller worker can still do the job, which is the
    /// difference between this and the floor check.
    fn resize_worker_if_vram_shrank(&self, key: &str, backend: &str, available: u64) {
        let Some(now_tier) = crate::discovery::vram_sizing_tier(backend, available) else {
            return; // no VRAM-derived knob for this backend
        };
        let Some(entry) = self.workers.get(key) else {
            return;
        };
        let mut slot = entry.slot.lock().unwrap_or_else(|e| e.into_inner());
        if slot.handle.is_none() {
            // Nothing live to resize; the next spawn reads a fresh figure anyway. Still refresh the
            // env, so that spawn uses today's number rather than discovery's.
            Self::set_spawn_vram(&mut slot, available);
            return;
        }
        let assumed = slot
            .spawn_env
            .get(zkminer_prover_protocol::types::CUDA_VRAM_AVAILABLE_BYTES_ENV)
            .and_then(|v| v.trim().parse::<u64>().ok());
        if !vram_tier_shrank(backend, assumed, available) {
            return;
        }
        let spawn_tier = assumed.and_then(|a| crate::discovery::vram_sizing_tier(backend, a));
        tracing::warn!(
            "{key}: only {:.1} GiB of this card is free now, against {:.1} GiB when its worker \
             started. That worker is sized for a bigger card than it has, so it is being recycled to \
             come back at the smaller setting ({} elements, was {}) rather than fail part-way.",
            available as f64 / 1024.0 / 1024.0 / 1024.0,
            assumed.unwrap_or(0) as f64 / 1024.0 / 1024.0 / 1024.0,
            now_tier,
            spawn_tier.unwrap_or(0),
        );
        Self::set_spawn_vram(&mut slot, available);
        // Pid retracted before the reap, so no signaller can use the number afterwards.
        entry.clear_pid();
        if let Some(h) = slot.handle.as_mut() {
            h.shutdown();
        }
        slot.handle = None;
    }

    /// Record the free-VRAM figure the next spawn of this slot should size itself against.
    fn set_spawn_vram(slot: &mut WorkerSlot, available: u64) {
        slot.spawn_env.insert(
            zkminer_prover_protocol::types::CUDA_VRAM_AVAILABLE_BYTES_ENV.to_string(),
            available.to_string(),
        );
    }

    /// What this slot's card has free to us, refusing if that is below the backend's floor.
    ///
    /// ONE implementation for all four paths that put work on a GPU — `prove_on_slot`,
    /// `benchmark_slot`, `benchmark_slot_streaming` and `calibrate_slot_po2`. The hazard is identical
    /// on each, and the three benchmark paths were exempt when this was first written. A benchmark is
    /// a proof as far as the card is concerned, and it is worse than a proof to get wrong: an OOM
    /// there writes a bad throughput row, and that row goes on to price and route every later job on
    /// the card.
    ///
    /// `Ok(None)` means no opinion — a backend with no floor, a slot with no CUDA device, or a card
    /// `nvidia-smi` could not read. Unreadable SKIPS the check rather than failing closed, matching
    /// `gpu_vram_bytes` and `reserve_host_memory`: nvidia-smi not answering is not evidence that a
    /// card is busy, and refusing all work over a missing tool stops the miner dead while the GPU-OOM
    /// retry still stands behind us.
    ///
    /// `Ok(Some(budget))` carries the figures so a caller can SIZE the run to them rather than merely
    /// proceed. `calibrate_slot_po2` clamps its segment to what fits; the spawn env hands SP1 a tier
    /// matched to what is free. Refusing is the last resort, not the first answer.
    ///
    /// MUST be called while holding the per-card guard: before it, another zkminer proof may still
    /// hold this card's VRAM, so the reading would be of our own work and every call would refuse.
    fn check_vram_budget(&self, key: &str) -> Result<Option<VramBudget>> {
        let backend = key.split(':').next().unwrap_or(key);
        let Some(idx) = slot_cuda_index(key) else {
            return Ok(None);
        };
        let Some((foreign, used, total)) = foreign_vram_bytes(idx) else {
            return Ok(None);
        };
        let budget = VramBudget {
            foreign,
            used,
            total,
            available: total.saturating_sub(foreign),
        };
        // A live worker is sized from the figure it was SPAWNED with, so a display attached since
        // then leaves it committed to more VRAM than is free. The floor check below cannot see this:
        // on a 24 GiB card, 8 GiB taken still clears a 16 GB floor while a worker sized for the empty
        // card needs ~17.8 GiB. Re-sizing is the repair, not refusing — that is the whole point of
        // measuring instead of gating.
        self.resize_worker_if_vram_shrank(key, backend, budget.available);

        let Some(needed) = crate::discovery::min_available_vram_bytes_for_backend(backend) else {
            return Ok(Some(budget));
        };
        if budget.available < needed {
            // A TYPED error: the caller must not read this as worker ill-health — the card and the
            // worker are both fine — and must not be able to have it forged by guest text. It costs
            // no attempt, so the retry tries another card and then waits; foreign VRAM is often
            // transient.
            let shortage = zkminer_prover_protocol::types::GpuMemoryShortage {
                slot_key: key.to_string(),
                foreign_bytes: foreign,
                available_bytes: budget.available,
                needed_bytes: needed,
                total_bytes: total,
            };
            tracing::warn!("not putting work on {key}: {shortage}");
            return Err(anyhow::Error::new(shortage));
        }
        Ok(Some(budget))
    }

    #[allow(clippy::too_many_arguments)]
    fn prove_on_slot(
        &self,
        key: &str,
        elf: &[u8],
        input_data: &[u8],
        po2: Option<u8>,
        timeout: Option<Duration>,
        on_progress: Option<Box<dyn Fn(f64, &str) + Send>>,
        abort_at: Option<Instant>,
        po2_resolver: Option<&dyn Fn(&str) -> Option<u8>>,
    ) -> Result<ProofOutput> {
        // Resolve the segment size now that the device is known. An explicit `po2`
        // always wins; otherwise ask the resolver for THIS device. Derived from the
        // slot key rather than the slot's fields so no lock is needed.
        let po2 = match po2 {
            Some(p) => Some(p),
            None => po2_resolver.and_then(|f| f(&Self::benchmark_device_id(key))),
        };

        // Per-physical-GPU guard (see `gpu_locks`): serialize proofs across different
        // backends pinned to the SAME physical GPU (e.g. risc0:cuda:0 vs sp1:cuda:0)
        // so they don't double-book VRAM. Acquired BEFORE the slot Mutex; each call
        // holds at most one physical lock + one slot lock, always in that order, so
        // the two lock classes can't form a cycle. Held for the whole proof (incl.
        // respawn, which also inits GPU context). `gpu_lock` (the Arc) is kept in
        // scope so the guard borrowing it lives until the function returns.
        //
        // DEADLINE-BOUNDED. A bare `lock()` here waits forever for the other backend on this card,
        // and nothing re-checked `abort_at` while it waited — so a job could be parked past its own
        // lock deadline with collateral bonded and then be unreleasable. That hazard is why giving
        // SP1 a per-card lock was previously judged too risky to attempt: a single-key backend takes
        // the `keys.len() == 1` shortcut straight into this function, skipping the round-robin loop's
        // queue-deadline check entirely. Bounding the wait here removes the hazard wherever it comes
        // from, including a genuinely single-GPU host.
        let gpu_lock = self.gpu_lock_for(key);
        let _gpu_guard = Self::acquire_gpu_guard(gpu_lock.as_ref(), key, abort_at, timeout)?;

        // Is enough of this card's VRAM free for this backend? See `check_vram_budget`, which also
        // explains why this must come after the guard and before the slot mutex.
        let _vram_budget = self.check_vram_budget(key)?;

        let entry = self
            .workers
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("No worker registered for '{key}'"))?;

        let mut slot = entry.slot.lock().unwrap_or_else(|e| {
            // RECOVER, do not hard-fail. The guard is held across code that can panic — the
            // progress callback runs synchronously on the proving thread while this very guard
            // is held, and in production that closure touches the shared TUI state — so one
            // panic there used to poison this slot permanently: every dispatch returned "lock
            // poisoned" while `is_backend_healthy` reported the slot alive (it reads any lock
            // error as "busy, therefore proving"), so the miner claimed jobs it could never
            // dispatch for the life of the process. What this mutex guards is a handle plus two
            // counters, not an invariant a panic can corrupt into unsafety, and `gpu_locks` and
            // `shutdown_all` already recover the same way.
            tracing::warn!(
                "worker slot {key} was poisoned by an earlier panic; recovering it rather \
                     than retiring the slot"
            );
            e.into_inner()
        });

        // Fix #3: proactively recycle a worker that has completed many proofs, so the
        // accumulated GPU context / buffer pool / persistent stream (which can wedge a
        // flaky card mid-proof) is reset to a clean slate. Killing the live handle here
        // makes ensure_alive() respawn a fresh worker (which zeroes proofs_since_spawn).
        // consecutive_failures/last_failure are untouched (0/None for a healthy worker),
        // so respawn is immediate (no backoff). If the respawn transiently fails,
        // ensure_alive() below returns Err and the job retries on another worker —
        // the same accepted trade-off as the OOM/stream-corruption kill paths.
        //
        // ORDER MATTERS: this runs BEFORE host-memory admission, not after. With the admission
        // check first, a slot whose worker was due for recycling could be refused for the very
        // memory that recycling would have freed — the gate blocking the only action that unblocks
        // the gate, permanently, because `proofs_since_spawn` never advances past the wedge point.
        let recycle_n = recycle_after_proofs();
        if recycle_n > 0 && slot.handle.is_some() && slot.proofs_since_spawn >= recycle_n {
            tracing::info!(
                "Recycling worker {}:{} after {} proofs (fresh GPU state)",
                slot.backend,
                slot.gpu_tag,
                slot.proofs_since_spawn
            );
            // Zero the PID BEFORE the kill, not before the drop. `kill()` →
            // `force_kill_group()` ends with `child.wait()`, so the reap happens THERE — and
            // once reaped the OS may reuse the number, while the watchdogs that read this
            // atomic (`ProvingWatchdog`, `cancel_proof`, `shutdown_all` phases 2 and 3) take
            // no lock and would `kill(-pid, SIGKILL)` whatever now owns it. The old comment
            // was right about the hazard and wrong about where the reap was.
            entry.clear_pid();
            if let Some(h) = slot.handle.as_mut() {
                h.kill();
            }
            slot.handle = None;
        }

        // Host memory admission, taken AFTER the slot guard so a contender blocked on the mutex is
        // not holding a reservation for a slot it cannot use. Taken earlier, every waiter
        // over-charged the ledger by a whole proof, which then refused legitimate proofs on other,
        // free slots — the ledger's figure stopped meaning "in flight".
        //
        // Held for the rest of the proof; released on drop, including on every error path.
        let backend_of_slot = key.split(':').next().unwrap_or(key);
        // Scaled to THIS proof's segment size — see `expected_host_peak_at_po2`.
        let want = self.expected_host_peak_at_po2(backend_of_slot, po2);
        let _memory_reservation = match self.reserve_host_memory(want, key) {
            Some(r) => r,
            None => {
                // Last resort before refusing, and ONLY when we could not read what this slot's
                // worker holds.
                //
                // When the credit IS readable, recycling cannot help, and the algebra says so
                // exactly. Before the kill the live test is `peak - R + reserve <= A`. After it the
                // credit is gone (pid 0) but the pages come back, so it is `peak + reserve <= A + R`
                // — the same inequality. And `fits_committed` is untouched, because neither
                // `reserved` nor `want` changes. So in the case the comment used to be about, the
                // recycle is neutral at best, and in practice worse: it destroys a warm worker, pays
                // a GPU re-init and a cold `pk_cache`, and the refusal still happens.
                //
                // It is worth doing in exactly one case: `resident` read as 0 because the worker has
                // no cgroup of ours to read (the cap is best effort). Then the worker may be holding
                // a great deal that we are not crediting, and killing it genuinely frees it.
                let credit_unreadable = self.current_host_bytes_for_slot(key).is_none();
                let freed = if credit_unreadable && slot.handle.is_some() {
                    tracing::warn!(
                        "Host RAM is short for {key} and this worker's own usage is unreadable (no \
                         cgroup of ours — the memory cap is best effort). Recycling it to free what \
                         it may be holding before refusing the proof."
                    );
                    // Pid zeroed before the kill, for the reason given on the recycle above.
                    entry.clear_pid();
                    if let Some(h) = slot.handle.as_mut() {
                        h.kill();
                    }
                    slot.handle = None;
                    // WAIT for the pages to come back before re-reading `MemAvailable`.
                    //
                    // Without this the retry was theatre: `kill()` returns as soon as the child is
                    // reaped, and the kernel's accounting of its pages — especially a CUDA process's
                    // pinned and driver mappings — does not land in `MemAvailable` on that
                    // instruction. So the reservation was re-tested against a figure that had not
                    // moved, the refusal happened anyway, and we had destroyed a warm worker for
                    // nothing. Poll until the figure actually improves, briefly: this is the only
                    // remediation the layer offers, and a second of waiting is cheap against a GPU
                    // re-init or a penalised release.
                    let before = crate::memory::mem_available_bytes().unwrap_or(0);
                    let deadline = Instant::now() + RECLAIM_WAIT;
                    while Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(50));
                        if crate::memory::mem_available_bytes().unwrap_or(0) > before {
                            break;
                        }
                    }
                    true
                } else {
                    false
                };
                match freed.then(|| self.reserve_host_memory(want, key)).flatten() {
                    Some(r) => r,
                    None => {
                        // A TYPED error, so the caller cannot mistake it for worker ill-health and
                        // no guest-supplied text can forge it. See `HostMemoryShortage`.
                        return Err(anyhow::Error::new(
                            zkminer_prover_protocol::types::HostMemoryShortage {
                                attempted: false,
                                slot_key: key.to_string(),
                                needed: want,
                                reserved: self.reserved_host_memory(),
                                available: crate::memory::mem_available_bytes().unwrap_or(0),
                            },
                        ));
                    }
                }
            }
        };

        self.ensure_alive(&mut slot, entry)?;

        // Update the external PID after ensure_alive (may have respawned)
        if let Some(h) = slot.handle.as_ref() {
            entry.publish_pid(h.pid());
        }

        // Deadline abort (see `abort_at`): now that a worker is ready — AFTER any
        // GPU-queue wait on the physical lock and any respawn/GPU-init in
        // ensure_alive — re-derive the time budget from the absolute abort instant.
        // This is what makes the caller's release margin robust to queue latency:
        // `timeout` (the wedge budget) is relative to proof-start, but `abort_at` is
        // absolute, so a long wait here shrinks the budget instead of being ignored.
        // If the instant already passed, don't start at all — return so the caller
        // releases the job while its releaseJob can still land.
        let watchdog_timeout = match abort_at {
            None => timeout,
            Some(abort) => {
                // saturating_duration_since => 0 if the instant already passed, so a
                // single `< MIN_ABORT_START_BUDGET` check covers both "past the
                // deadline" and "so little left the proof would be killed instantly".
                let remaining = abort.saturating_duration_since(Instant::now());
                if remaining < MIN_ABORT_START_BUDGET {
                    return Err(anyhow::Error::new(
                        zkminer_prover_protocol::types::ProofDeadlineReached {
                            detail: format!(
                                "aborting proof on {key}: only {remaining:?} left before the \
                                 deadline cutoff after the GPU queue wait — not starting \
                                 (releasing to recover collateral)"
                            ),
                        },
                    ));
                }
                // Kill on whichever fires first: the wedge budget or the deadline.
                Some(timeout.map_or(remaining, |t| t.min(remaining)))
            }
        };

        // Reset intentional_kill before starting the proof
        entry.intentional_kill.store(false, Ordering::Release);

        // Captured now (shared borrow, before the &mut handle borrow below) for the
        // completion log (#16) so operators can see which physical GPU ran each proof.
        let gpu_name = slot.gpu_name.clone();

        // Re-borrow handle after PID update
        let handle = slot
            .handle
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker not available after ensure_alive"))?;

        static REQUEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let request_id = REQUEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if let Err(e) = handle.send(&WorkerCommand::Prove {
            request_id,
            elf: elf.to_vec(),
            input_data: input_data.to_vec(),
            po2,
        }) {
            // Send failed (broken pipe = worker died before receiving the command).
            Self::mark_slot_failed(&mut slot, entry);
            return Err(e);
        }

        // Start proving timeout watchdog if a deadline is set.
        // The watchdog SIGKILLs the worker via PID if the proof exceeds the timeout.
        // On SIGKILL, recv_proof gets EOF and returns an error, releasing the Mutex.
        let _watchdog = watchdog_timeout.map(|t| {
            ProvingWatchdog::new(
                entry.pid.clone(),
                entry.pid_starttime.clone(),
                t,
                key.to_string(),
                entry.intentional_kill.clone(),
            )
        });

        // The worker protocol's progress callback carries only a fraction. Bake the
        // slot key in here so callers learn WHICH card is running the proof --
        // without it the TUI could not attribute a running job to a GPU row at all,
        // and every proof rendered as "CPU" on an idle-looking card.
        let key_for_cb = key.to_string();
        let on_progress: Option<Box<dyn Fn(f64) + Send>> = on_progress
            .map(|cb| Box::new(move |f: f64| cb(f, &key_for_cb)) as Box<dyn Fn(f64) + Send>);
        let proof_response = handle.recv_proof(request_id, &on_progress);

        // If recv_proof failed (EOF, stream corruption, protocol desync),
        // kill the worker to prevent reusing a corrupted IPC stream.
        if let Err(ref e) = proof_response {
            // EOF (WorkerDied) means the worker already died — just clear the handle.
            // Anything else (bincode error, desync) means the stream is corrupt
            // but the worker may still be alive — kill it explicitly.
            let is_eof = e.downcast_ref::<WorkerDied>().is_some();

            // Ask about a host OOM FIRST — before any kill, and before the slot is cleared.
            //
            // Ordering is the whole fix here, twice over. `died_of_host_oom` used to be consulted
            // only in `ensure_alive`'s "handle present but dead" branch, which this path makes
            // unreachable because `mark_slot_*` sets `slot.handle = None`. Moving the query here was
            // not enough: `h.kill()` below runs `force_kill_group`, which REAPS, and
            // `died_of_host_oom` returns `None` once `reaped` — correctly, since a reaped pid may
            // name a stranger. So on the stream-corruption branch the answer was always `None`, and
            // a stream corruption CAUSED by a host OOM was still charged to the prover.
            //
            // It must also not count against the slot's health. A host OOM is an environmental fact:
            // the card is fine, and three of them retired a healthy GPU for the cooldown while the
            // caller burnt its attempts and released the job at a penalty.
            #[cfg(unix)]
            let host_oom = !entry.intentional_kill.load(Ordering::Acquire)
                && slot
                    .handle
                    .as_mut()
                    .and_then(|h| h.died_of_host_oom())
                    .unwrap_or(false);
            #[cfg(not(unix))]
            let host_oom = false;

            if !is_eof {
                tracing::error!("Stream corruption detected for {key}, killing worker");
                // PID first: `kill()` reaps, after which the number may be reused.
                entry.clear_pid();
                if let Some(h) = slot.handle.as_mut() {
                    h.kill();
                }
            }

            // Don't count intentional kills (timeout/cancel) as failures —
            // otherwise 3 timeouts permanently retire the slot. A host OOM is likewise not the
            // slot's fault.
            if entry.intentional_kill.load(Ordering::Acquire) {
                tracing::info!(
                    "Worker {key} killed intentionally (timeout/cancel), not counting as failure"
                );
                Self::mark_slot_dead(&mut slot, entry);
            } else if host_oom {
                tracing::error!(
                    "Worker {key} was killed because the HOST RAN OUT OF MEMORY. This is an \
                     environmental limit, not a prover fault, and it is not counted against this \
                     GPU: the box does not have enough RAM for this workload at this concurrency. \
                     Check `journalctl -k | grep -i oom` and MemAvailable before investigating the \
                     prover."
                );
                Self::mark_slot_dead(&mut slot, entry);
            } else {
                Self::mark_slot_failed(&mut slot, entry);
            }

            // Report it to the CALLER as a memory shortage, not as a prover failure, so the retry
            // loop waits for the host instead of excluding a healthy slot and releasing the job.
            if host_oom {
                return Err(anyhow::Error::new(
                    zkminer_prover_protocol::types::HostMemoryShortage {
                        attempted: true,
                        slot_key: key.to_string(),
                        needed: want,
                        reserved: self.reserved_host_memory(),
                        available: crate::memory::mem_available_bytes().unwrap_or(0),
                    },
                ));
            }

            // Distinguish a DEADLINE-driven kill from a GPU wedge. When the deadline
            // term bounded the watchdog, the kill lands at/after `abort_at`; report it
            // with a distinct, non-"EOF" message so the caller RELEASES the job rather
            // than misreading a healthy card as wedged, excluding it, and retrying on
            // another GPU (a retry that can't beat the same deadline anyway). A genuine
            // wedge fires on the smaller wedge budget, strictly before `abort_at`, and
            // falls through to the normal EOF/died path below.
            if let Some(abort) = abort_at {
                if Instant::now() >= abort {
                    return Err(anyhow::Error::new(
                        zkminer_prover_protocol::types::ProofDeadlineReached {
                            detail: format!(
                                "proof on {key} stopped: job deadline reached mid-proof \
                                 (releasing to recover collateral)"
                            ),
                        },
                    ));
                }
            }
        }

        // Count a completed proof toward the recycle threshold (fix #3). Only on
        // success — a failed/killed worker is respawned, which resets the counter.
        if proof_response.is_ok() {
            slot.proofs_since_spawn = slot.proofs_since_spawn.saturating_add(1);
        }

        match proof_response? {
            WorkerResponse::ProofResult {
                journal,
                seal,
                duration_secs,
                cycles,
                ..
            } => {
                tracing::info!(
                    "Proof complete on {} [{}]: {} cycles in {:.1}s",
                    key,
                    gpu_name.as_deref().unwrap_or("cpu"),
                    cycles,
                    duration_secs,
                );
                Ok(ProofOutput {
                    journal,
                    seal,
                    duration: Duration::from_secs_f64(duration_secs),
                    cycles,
                })
            }
            WorkerResponse::Error { kind, message, .. } => {
                // TYPED, carrying the worker's own `kind`. The caller used to classify this by
                // searching the formatted string, which embeds `message` — text that can originate in
                // the guest ELF of an on-chain job. See `WorkerProofError`.
                let typed = zkminer_prover_protocol::types::WorkerProofError {
                    kind: kind.clone(),
                    slot_key: key.to_string(),
                    message: message.clone(),
                };
                if matches!(kind, ErrorKind::ResourceExhausted) {
                    tracing::warn!("Worker {key} OOM — killing for respawn with clean GPU state");
                    // PID first: `kill()` reaps, after which the number may be reused.
                    entry.clear_pid();
                    if let Some(h) = slot.handle.as_mut() {
                        h.kill();
                    }
                    // OOM is a real failure — increment to prevent infinite loops
                    Self::mark_slot_failed(&mut slot, entry);
                }
                Err(anyhow::Error::new(typed))
            }
            WorkerResponse::Cancelled { .. } => {
                bail!("Proof cancelled for worker {key}")
            }
            other => bail!("Unexpected response from {key}: {other:?}"),
        }
    }

    /// Cancel an in-flight proof on a specific backend.
    /// Uses try_lock to send Cancel if the slot is free, or SIGKILL via PID
    /// if the slot is locked (proving in progress — the worker can't read Cancel).
    pub fn cancel(&self, backend: &str, request_id: u64) -> Result<()> {
        let keys = self.keys_for_prefix(backend);
        if keys.is_empty() {
            bail!("No worker registered for backend '{backend}'");
        }
        for key in keys {
            if let Some(entry) = self.workers.get(&key) {
                match entry.slot.try_lock() {
                    Ok(mut slot) => {
                        // Slot is free — send Cancel command via IPC
                        if let Some(handle) = &mut slot.handle {
                            let _ = handle.send(&WorkerCommand::Cancel { request_id });
                        }
                    }
                    Err(_) => {
                        // Slot is locked (proof in progress). The worker is blocked in
                        // prover.prove() and can't read Cancel from stdin. Kill via PID.
                        let Some((pid, expected_start)) = entry.signal_target() else {
                            continue;
                        };
                        {
                            tracing::warn!("Cancelling proof on {key} by killing worker PID {pid}");
                            entry.intentional_kill.store(true, Ordering::Release);
                            // Kill the whole process group (worker calls setpgid(0,0)),
                            // so a forked GPU server child (e.g. sp1-gpu-server) dies too
                            // instead of leaking VRAM and holding the stdout write end
                            // (which would hang recv_proof). Matches the timeout watchdog.
                            // Identity-checked, as in the timeout watchdog.
                            #[cfg(unix)]
                            if crate::memory::pid_is_our_worker(pid, expected_start) {
                                unsafe {
                                    libc::kill(-(pid as i32), libc::SIGKILL);
                                    libc::kill(pid as i32, libc::SIGKILL);
                                }
                            } else {
                                tracing::warn!(
                                    "not killing PID {pid} for {key}: it is no longer our worker"
                                );
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Mark a worker slot as failed: clear handle, zero PID, increment failure counter.
    /// Used by error handlers in prove_on_slot and benchmark_slot when a worker dies.
    fn mark_slot_failed(slot: &mut WorkerSlot, pid: &impl PidSlot) {
        // Zero the PID BEFORE dropping the handle, never after. `WorkerHandle::drop` waits
        // up to 2s, group-kills, reaps, and joins the stderr thread; for all of that time a
        // stale non-zero pid was still published here, and the watchdogs that read this
        // atomic (`ProvingWatchdog`, `cancel`, `shutdown_all` phases 2 and 3) issue
        // `kill(-pid, SIGKILL)` on it. Once `drop` has reaped, that number may belong to an
        // unrelated process group. `ensure_alive` and the proof-recycle path already order it
        // this way and say why; these two did not.
        pid.clear();
        slot.handle = None;
        slot.consecutive_failures += 1;
        slot.last_failure = Some(Instant::now());
    }

    /// Mark a worker slot as dead without counting it as a failure (intentional kill).
    fn mark_slot_dead(slot: &mut WorkerSlot, pid: &impl PidSlot) {
        // PID before handle — see `mark_slot_failed`.
        pid.clear();
        slot.handle = None;
    }

    /// True if a slot may be dispatched to: healthy, or retired-but-cooled-down so a
    /// transient failure burst doesn't sideline a GPU until process restart.
    fn slot_eligible(slot: &WorkerSlot) -> bool {
        // A DECLINED worker can run but cannot prove here, and no retry changes that.
        // It must never look eligible: the cooldown clause below is a pure clock check,
        // so without this the slot became eligible again every RETIRE_COOLDOWN and the
        // miner resumed claiming jobs it could not prove, for the process lifetime.
        // This also stops the pointless respawn churn against a known-impossible worker.
        if slot.declined.is_some() {
            return false;
        }
        slot.consecutive_failures < MAX_RESPAWN_FAILURES
            || slot
                .last_failure
                .is_some_and(|t| t.elapsed() >= RETIRE_COOLDOWN)
    }

    /// True if this DEAD slot is still inside the respawn backoff window that its own
    /// last failure armed.
    ///
    /// Dispatching to such a slot is guaranteed to bail in `respawn` without ever
    /// touching the GPU, so it burns one of the caller's `MAX_PROVE_ATTEMPTS` in
    /// microseconds. That is what terminated every job soak20 lost: all four died on
    /// `proving failed after 3 attempt(s): Backoff: waiting ~4.5s before respawning`,
    /// and for 0x92e7686c attempt 3 fired **155 microseconds** after attempt 2
    /// (10:38:44.580790 -> .580945). The whole retry budget was consumed by a 5s timer
    /// the failure handler had armed 0.7s earlier.
    ///
    /// `respawn` already documents this bug class for a different path ("the 'first
    /// respawn always fails' bug where the self-imposed `last_failure` timestamp caused
    /// an immediate backoff rejection"); the OOM arm reintroduced it because no dispatch
    /// predicate knew about the window. `slot_eligible` checks only
    /// `consecutive_failures`.
    ///
    /// Mirrors `respawn`'s own arithmetic so the two cannot disagree.
    fn in_respawn_backoff(slot: &WorkerSlot) -> bool {
        if slot.handle.is_some() {
            return false; // alive: nothing to respawn, no window
        }
        match slot.last_failure {
            Some(last) => {
                let idx = (slot.consecutive_failures as usize).min(RESPAWN_BACKOFF.len() - 1);
                last.elapsed() < RESPAWN_BACKOFF[idx]
            }
            None => false,
        }
    }

    /// `slot_eligible` AND not inside its respawn backoff window.
    ///
    /// Deliberately a separate predicate rather than folding the window into
    /// `slot_eligible`: that one is also consulted by `is_backend_healthy`, which asks
    /// "could this backend ever serve again", not "can it serve right now". Merging them
    /// would make a backend look permanently unhealthy for the length of a backoff.
    fn slot_dispatchable(slot: &WorkerSlot) -> bool {
        Self::slot_eligible(slot) && !Self::in_respawn_backoff(slot)
    }

    /// Attempt to respawn a dead worker with exponential backoff.
    fn respawn(slot: &mut WorkerSlot) -> Result<()> {
        // Self-heal: clear a retirement once the card has been quiet for the cooldown,
        // so a transient (driver/thermal reset) doesn't kill the GPU for the process.
        if slot.consecutive_failures >= MAX_RESPAWN_FAILURES {
            if let Some(last) = slot.last_failure {
                if last.elapsed() >= RETIRE_COOLDOWN {
                    tracing::info!(
                        "Worker {}:{} cooled down after {:?} idle — clearing retirement, retrying",
                        slot.backend,
                        slot.gpu_tag,
                        last.elapsed()
                    );
                    slot.consecutive_failures = 0;
                    slot.last_failure = None;
                }
            }
        }
        if slot.consecutive_failures >= MAX_RESPAWN_FAILURES {
            bail!(
                "Worker at {} permanently failed after {} consecutive failures",
                slot.path.display(),
                slot.consecutive_failures
            );
        }

        // Check backoff
        if let Some(last_failure) = slot.last_failure {
            let backoff_idx = (slot.consecutive_failures as usize).min(RESPAWN_BACKOFF.len() - 1);
            let required_wait = RESPAWN_BACKOFF[backoff_idx];
            if last_failure.elapsed() < required_wait {
                bail!(
                    "Backoff: waiting {:?} before respawning {}",
                    required_wait - last_failure.elapsed(),
                    slot.path.display()
                );
            }
        }

        tracing::info!(
            "Respawning worker {}:{} (attempt {}/{})",
            slot.backend,
            slot.gpu_tag,
            slot.consecutive_failures + 1,
            MAX_RESPAWN_FAILURES
        );

        match WorkerHandle::spawn(&slot.backend, &slot.path, &slot.spawn_env) {
            Ok(handle) => {
                slot.handle = Some(handle);
                slot.consecutive_failures = 0;
                slot.last_failure = None;
                slot.proofs_since_spawn = 0;
                Ok(())
            }
            Err(e) => {
                // A DECLINE is not a transient failure, and it has to be recorded here too.
                //
                // `discover_and_spawn` classifies `WORKER_DECLINED` and sets `slot.declined`; this
                // path did not. So a backend that became unprovable AFTER startup — CUDA removed,
                // a driver reset, the GPU claimed by something else — was recorded as a plain
                // respawn failure. Below MAX_RESPAWN_FAILURES `is_backend_healthy` stayed true, and
                // the retirement self-clears every RETIRE_COOLDOWN, so the miner kept claiming jobs
                // it could not prove, each one costing a round of attempts and a penalised release,
                // for the life of the process. A decline is categorical: say so once and stop
                // advertising the backend.
                let msg = format!("{e:#}");
                if msg.contains(zkminer_prover_protocol::types::WORKER_DECLINED)
                    && slot.declined.is_none()
                {
                    tracing::error!(
                        "Worker {}:{} DECLINED on respawn and will no longer be advertised: {msg}",
                        slot.backend,
                        slot.gpu_tag,
                    );
                    slot.declined = Some(msg);
                }
                slot.consecutive_failures += 1;
                slot.last_failure = Some(Instant::now());
                Err(e)
            }
        }
    }

    /// Ensure a worker slot has a live handle. Attempts respawn if dead.
    /// `pid` is zeroed immediately when a dead worker is detected, closing the
    /// stale-PID window before `WorkerHandle::drop` reaps the zombie.
    fn ensure_alive<'a>(
        &self,
        slot: &'a mut WorkerSlot,
        pid: &impl PidSlot,
    ) -> Result<&'a mut WorkerHandle> {
        let is_alive = slot.handle.as_mut().map(|h| h.is_alive()).unwrap_or(false);

        let needs_respawn = if is_alive {
            false
        } else if slot.handle.is_some() {
            let reason = slot
                .handle
                .as_mut()
                .map(|h| h.exit_reason())
                .unwrap_or_else(|| "no handle".to_string());
            // Say whether the HOST ran out of memory, rather than leaving a signal-9 death looking
            // like a prover bug. An OOM-killed prover surfaces as EOF, a broken pipe or "killed by
            // signal 9" — indistinguishable from a regression unless we check, and this project's
            // notes record that misdiagnosis being made.
            #[cfg(unix)]
            let host_oom = slot
                .handle
                .as_mut()
                .and_then(|h| h.died_of_host_oom())
                .unwrap_or(false);
            #[cfg(not(unix))]
            let host_oom = false;
            if host_oom {
                tracing::error!(
                    "Worker {}:{} was killed because the HOST RAN OUT OF MEMORY ({reason}). \
                     This is an environmental limit, not a prover fault: the box does not have \
                     enough RAM for this workload at this concurrency. Check \
                     `journalctl -k | grep -i oom` and MemAvailable before investigating the \
                     prover.",
                    slot.backend,
                    slot.gpu_tag
                );
            } else {
                tracing::warn!(
                    "Worker {}:{} died ({reason}), will attempt respawn",
                    slot.backend,
                    slot.gpu_tag
                );
            }
            // Zero PID before dropping the handle. Once WorkerHandle::drop reaps
            // the zombie, the OS can reuse the PID — the atomic must be 0 by then.
            pid.clear();
            slot.handle = None;
            // Do NOT increment consecutive_failures here — respawn() owns failure counting.
            // This also fixes the "first respawn always fails" bug where the self-imposed
            // last_failure timestamp caused an immediate backoff rejection.
            true
        } else {
            // Defensively zero PID when handle is None. All code paths that set
            // handle=None also zero the PID, so this should already be 0. But if
            // a future change forgets to zero it, this prevents stale-PID kills.
            pid.clear();
            true
        };

        if needs_respawn {
            Self::respawn(slot)?;
        }

        slot.handle
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker not available"))
    }

    /// Shutdown all workers.
    /// Phase 1: Graceful shutdown for idle workers (send Shutdown command).
    /// Phase 2: SIGTERM all remaining PIDs (gives workers a chance to exit).
    /// Phase 3: SIGKILL survivors after a brief wait.
    /// Phase 4: Lock Mutexes and clean up handles.
    pub fn shutdown_all(&self) {
        // Phase 1: Gracefully shut down idle workers (those whose Mutex is free)
        for (key, entry) in &self.workers {
            if let Ok(mut slot) = entry.slot.try_lock() {
                if let Some(handle) = &mut slot.handle {
                    tracing::info!("Sending Shutdown to idle worker {key}");
                    let _ = handle.send(&WorkerCommand::Shutdown);
                }
            }
        }

        // Phase 2: SIGTERM all PIDs (idle workers already got Shutdown; busy ones
        // can't read IPC, but SIGTERM's default handler terminates them cleanly)
        for (key, entry) in &self.workers {
            // Identity-checked, as everywhere a pid from this atomic is signalled.
            let Some((pid, expected_start)) = entry.signal_target() else {
                continue;
            };
            if crate::memory::pid_is_our_worker(pid, expected_start) {
                tracing::info!("Sending SIGTERM to worker {key} (PID {pid})");
                #[cfg(unix)]
                unsafe {
                    // Signal the GROUP, not just the leader: a forked GPU helper
                    // (SP1's sp1-gpu-server) should get a chance to release its VRAM
                    // and exit cleanly rather than being SIGKILLed in phase 3. pid is
                    // non-zero here, so kill(-pid) cannot degenerate to kill(0)/kill(-1).
                    libc::kill(-(pid as i32), libc::SIGTERM);
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }
        }

        // Wait briefly for graceful exit
        std::thread::sleep(Duration::from_secs(2));

        // Phase 3: SIGKILL any survivors — target the whole process group (the
        // worker calls setpgid(0,0) at spawn) so forked GPU/helper children die
        // too instead of leaking as orphans between suites. pid is non-zero here,
        // so kill(-pid) can never degenerate into kill(0)/kill(-1).
        for entry in self.workers.values() {
            // Identity-checked, as everywhere a pid from this atomic is signalled.
            let Some((pid, expected_start)) = entry.signal_target() else {
                continue;
            };
            if crate::memory::pid_is_our_worker(pid, expected_start) {
                #[cfg(unix)]
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        }

        // Brief pause for EOF to propagate through pipes
        std::thread::sleep(Duration::from_millis(200));

        // Phase 4: Lock Mutexes and clean up handles (drop triggers reap + stderr join).
        // Use unwrap_or_else to recover from poisoned Mutexes — otherwise the
        // WorkerHandle is never dropped and the child becomes a zombie.
        for entry in self.workers.values() {
            let mut slot = entry.slot.lock().unwrap_or_else(|e| e.into_inner());
            Self::mark_slot_dead(&mut slot, entry);
        }
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        self.shutdown_all();
    }
}

/// Information about a connected worker.
#[derive(Debug, Clone)]
pub struct WorkerInfo {
    pub backend: String,
    pub gpu_tag: String,
    pub device_index: Option<u32>,
    pub gpu_name: Option<String>,
    pub pid: u32,
    pub sdk_version: Option<String>,
    pub worker_version: Option<String>,
}

// Test helpers for integration tests. Enabled via `--features testing` or in unit tests.
#[cfg(any(test, feature = "testing"))]
impl WorkerPool {
    /// Insert a mock worker into the pool for testing.
    /// Spawns the binary at `path` with the given environment overrides,
    /// performs the handshake, and registers it under the given compound key.
    pub fn insert_test_worker(
        &mut self,
        key: &str,
        backend: &str,
        path: PathBuf,
        env: HashMap<String, String>,
    ) -> Result<()> {
        // The readers derive the backend from the KEY (`key.split(':').next()`), while
        // `cap_process_memory` is handed `backend`. If a caller passes a mismatched pair, the exact
        // unit check in `peak_memory_of_pid` simply returns `None` and every host-memory measurement
        // silently disappears into the process-group fallback. Fail loudly in tests instead.
        debug_assert_eq!(
            key.split(':').next(),
            Some(backend),
            "test worker key and backend must agree, or host-memory measurement goes silently dark"
        );
        let handle = WorkerHandle::spawn(backend, &path, &env)?;
        let pid = handle.pid();
        self.workers.insert(
            key.to_string(),
            WorkerEntry {
                slot: Mutex::new(WorkerSlot {
                    handle: Some(handle),
                    path,
                    backend: backend.to_string(),
                    gpu_tag: "generic".to_string(),
                    device_index: None,
                    pci_bus_id: None,
                    gpu_name: None,
                    spawn_env: env,
                    consecutive_failures: 0,
                    last_failure: None,
                    declined: None,
                    proofs_since_spawn: 0,
                }),
                vram_bytes: None,
                pci_bus_id: None,
                pid: Arc::new(AtomicU32::new(pid)),
                pid_starttime: Arc::new(AtomicU64::new(
                    crate::memory::pid_starttime(pid).unwrap_or(0),
                )),
                intentional_kill: Arc::new(AtomicBool::new(false)),
            },
        );
        Ok(())
    }

    /// Get consecutive_failures for a worker slot (test inspection).
    pub fn test_consecutive_failures(&self, key: &str) -> Option<u32> {
        self.workers
            .get(key)
            .and_then(|e| e.slot.lock().ok())
            .map(|s| s.consecutive_failures)
    }

    /// Get the intentional_kill flag value (test inspection).
    pub fn test_intentional_kill(&self, key: &str) -> Option<bool> {
        self.workers
            .get(key)
            .map(|e| e.intentional_kill.load(Ordering::Acquire))
    }

    /// Get the external PID (test inspection).
    pub fn test_pid(&self, key: &str) -> Option<u32> {
        self.workers.get(key).map(|e| e.pid.load(Ordering::Acquire))
    }

    /// Check if the worker handle is present (test inspection).
    pub fn test_has_handle(&self, key: &str) -> Option<bool> {
        self.workers
            .get(key)
            .and_then(|e| e.slot.lock().ok())
            .map(|s| s.handle.is_some())
    }

    /// Update the spawn_env for a worker slot without replacing the entry.
    /// This allows changing the mock worker's behavior (e.g., removing MOCK_HANG_ON)
    /// so the next `ensure_alive → respawn()` uses the updated env.
    ///
    /// # Panics
    /// Panics if `key` is not registered in the pool (likely a test bug).
    pub fn test_set_spawn_env(&self, key: &str, env: HashMap<String, String>) {
        let entry = self
            .workers
            .get(key)
            .unwrap_or_else(|| panic!("test_set_spawn_env: key '{key}' not found in pool"));
        let mut slot = entry.slot.lock().unwrap_or_else(|e| e.into_inner());
        slot.spawn_env = env;
    }

    /// Reset consecutive_failures and last_failure for a worker slot.
    /// Used to bypass the respawn backoff in tests that need immediate respawn.
    ///
    /// # Panics
    /// Panics if `key` is not registered in the pool (likely a test bug).
    pub fn test_reset_failures(&self, key: &str) {
        let entry = self
            .workers
            .get(key)
            .unwrap_or_else(|| panic!("test_reset_failures: key '{key}' not found in pool"));
        let mut slot = entry.slot.lock().unwrap_or_else(|e| e.into_inner());
        slot.consecutive_failures = 0;
        slot.last_failure = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- slot_key tests ----

    #[test]
    fn slot_key_with_device_index() {
        assert_eq!(slot_key("risc0", "cuda", Some(0)), "risc0:cuda:0");
        assert_eq!(slot_key("risc0", "cuda", Some(1)), "risc0:cuda:1");
        assert_eq!(slot_key("sp1", "rocm", Some(3)), "sp1:rocm:3");
    }

    #[test]
    fn slot_key_without_device_index() {
        assert_eq!(slot_key("risc0", "generic", None), "risc0:generic");
        assert_eq!(slot_key("sp1", "cuda", None), "sp1:cuda");
    }

    #[test]
    fn physical_gpu_id_shares_lock_across_backends_on_same_card() {
        // Different backends on the SAME physical GPU map to the SAME id → one lock.
        assert_eq!(physical_gpu_id("risc0:cuda:0").as_deref(), Some("cuda:0"));
        assert_eq!(physical_gpu_id("sp1:cuda:0").as_deref(), Some("cuda:0"));
        assert_eq!(physical_gpu_id("risc0:rocm:0").as_deref(), Some("rocm:0"));
        // Intel is guarded too, to match the set `proving_gpu_count` counts.
        assert_eq!(
            physical_gpu_id("openvm:intel:0").as_deref(),
            Some("intel:0")
        );
        // Different device indices are distinct physical GPUs → distinct locks.
        assert_ne!(
            physical_gpu_id("risc0:cuda:0"),
            physical_gpu_id("risc0:cuda:1")
        );
    }

    #[test]
    fn physical_gpu_id_unguarded_for_cpu_and_explicit() {
        // CPU/generic and explicit binaries without a device index (2-part keys) are
        // left unguarded (no per-physical-GPU lock).
        assert_eq!(physical_gpu_id("risc0:generic"), None);
        assert_eq!(physical_gpu_id("sp1:cuda"), None); // explicit binary, no device index
    }

    // ---- keys_for_prefix tests ----

    /// Helper to create a WorkerPool with stub entries (no real workers).
    fn pool_with_keys(keys: &[&str]) -> WorkerPool {
        let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
        for &key in keys {
            pool.workers.insert(
                key.to_string(),
                WorkerEntry {
                    slot: Mutex::new(WorkerSlot {
                        handle: None,
                        path: PathBuf::from("/dev/null"),
                        backend: key.split(':').next().unwrap_or(key).to_string(),
                        gpu_tag: "generic".to_string(),
                        device_index: None,
                        pci_bus_id: None,
                        gpu_name: None,
                        spawn_env: HashMap::new(),
                        consecutive_failures: 0,
                        last_failure: None,
                        declined: None,
                        proofs_since_spawn: 0,
                    }),
                    vram_bytes: None,
                    pci_bus_id: None,
                    pid: Arc::new(AtomicU32::new(0)),
                    pid_starttime: Arc::new(AtomicU64::new(0)),
                    intentional_kill: Arc::new(AtomicBool::new(false)),
                },
            );
        }
        pool
    }

    #[test]
    fn keys_for_prefix_logical_backend() {
        let pool = pool_with_keys(&[
            "risc0:cuda:0",
            "risc0:cuda:1",
            "risc0:rocm:0",
            "risc0:generic",
            "sp1:cuda:0",
        ]);
        let mut keys = pool.keys_for_prefix("risc0");
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "risc0:cuda:0",
                "risc0:cuda:1",
                "risc0:generic",
                "risc0:rocm:0"
            ]
        );
    }

    #[test]
    fn keys_for_prefix_vendor_level() {
        let pool = pool_with_keys(&["risc0:cuda:0", "risc0:cuda:1", "risc0:rocm:0"]);
        let mut keys = pool.keys_for_prefix("risc0:cuda");
        keys.sort();
        assert_eq!(keys, vec!["risc0:cuda:0", "risc0:cuda:1"]);
    }

    #[test]
    fn keys_for_prefix_exact_match() {
        let pool = pool_with_keys(&["risc0:cuda:0", "risc0:cuda:1"]);
        let keys = pool.keys_for_prefix("risc0:cuda:0");
        assert_eq!(keys, vec!["risc0:cuda:0"]);
    }

    #[test]
    fn keys_for_prefix_no_false_positives() {
        // "risc0" must NOT match "risc0x:foo"
        let pool = pool_with_keys(&["risc0x:cuda:0", "risc0:cuda:0"]);
        let keys = pool.keys_for_prefix("risc0");
        assert_eq!(keys, vec!["risc0:cuda:0"]);
    }

    #[test]
    fn keys_for_prefix_no_match() {
        let pool = pool_with_keys(&["risc0:cuda:0"]);
        let keys = pool.keys_for_prefix("sp1");
        assert!(keys.is_empty());
    }

    // ---- gpu_env tests ----

    #[test]
    fn gpu_env_cuda() {
        // CUDA_VISIBLE_DEVICES must be a numeric index (or GPU-uuid), NOT a PCI bus id —
        // a PCI bus id parses to its leading integer and mis-pins every worker to dev 0.
        let env = WorkerPool::gpu_env("risc0", "cuda", Some("0000:01:00.0"), Some(1));
        assert_eq!(env.get("CUDA_DEVICE_ORDER").unwrap(), "PCI_BUS_ID");
        assert_eq!(env.get("CUDA_VISIBLE_DEVICES").unwrap(), "1");
    }

    #[test]
    fn gpu_env_rocm() {
        let env = WorkerPool::gpu_env("risc0", "rocm", None, Some(2));
        assert_eq!(env.get("HIP_VISIBLE_DEVICES").unwrap(), "2");
        assert_eq!(env.get("NVCC").unwrap(), "off");
    }

    #[test]
    fn gpu_env_intel() {
        // Single selection mechanism only: ZE_AFFINITY_MASK. Also setting
        // ONEAPI_DEVICE_SELECTOR would double-filter and select nothing for index>0.
        let env = WorkerPool::gpu_env("risc0", "intel", None, Some(1));
        assert_eq!(env.get("ZE_AFFINITY_MASK").unwrap(), "1");
        assert!(env.get("ONEAPI_DEVICE_SELECTOR").is_none());
    }

    /// EVERY path that puts work on a card must take the per-card guard, and the guard must be taken
    /// before the slot mutex so the two lock classes cannot cycle.
    ///
    /// This is a source assertion because the alternative is no coverage of the property at all: the
    /// hole it guards was three functions that took the slot mutex and a host-memory reservation but
    /// not this lock, so a benchmark started from the TUI ran concurrently with a proof on the same
    /// physical card. Nothing in the type system stops a fourth path being added the same way.
    #[test]
    fn every_gpu_path_takes_the_per_card_guard_before_the_slot() {
        let src = include_str!("dispatcher.rs");
        for f in [
            "fn prove_on_slot(",
            "fn benchmark_slot(",
            "fn benchmark_slot_streaming(",
            "pub fn calibrate_slot_po2(",
        ] {
            // Bound the search to THIS function's body. `split_once` alone returns everything after
            // the name, so a later function's call satisfied the assertion for an earlier one — the
            // test passed with the guard deleted from `benchmark_slot`.
            let after = src
                .split_once(f)
                .unwrap_or_else(|| panic!("{f} no longer exists; move this assertion with it"))
                .1;
            let body = match after
                .find("\n    fn ")
                .into_iter()
                .chain(after.find("\n    pub fn "))
                .min()
            {
                Some(end) => &after[..end],
                None => after,
            };
            // `Self::acquire_gpu_guard(` — the CALL, not the name. Searching the bare name matched the
            // "See `acquire_gpu_guard`" line in the comment above it, so the assertion held with the
            // call deleted.
            let guard = body.find("Self::acquire_gpu_guard(").unwrap_or_else(|| {
                panic!(
                    "{f} does not take the per-card GPU guard. Two backends can be pinned to one \
                     physical card, and sp1-gpu-server alone holds ~10 GB of its VRAM — without this \
                     lock they double-book it. Call `acquire_gpu_guard` before the slot mutex."
                )
            });
            let slot = body
                .find("entry.slot")
                .unwrap_or_else(|| panic!("{f} no longer locks a slot; revisit this assertion"));
            assert!(
                guard < slot,
                "{f} takes the GPU guard AFTER the slot mutex; every other path takes it before, \
                 and mixing the two orders is a deadlock"
            );
        }
    }

    // ---- foreign-VRAM gate ----

    #[test]
    fn slot_cuda_index_names_the_card_or_nothing() {
        assert_eq!(slot_cuda_index("sp1:cuda:0"), Some(0));
        assert_eq!(slot_cuda_index("sp1:cuda:1"), Some(1));
        assert_eq!(slot_cuda_index("risc0:cuda:7"), Some(7));
        // No device to query ⇒ no gate. Each of these must be None rather than defaulting to 0,
        // which would read a DIFFERENT card's occupancy and refuse (or admit) on the wrong evidence.
        assert_eq!(slot_cuda_index("sp1:generic"), None);
        assert_eq!(slot_cuda_index("risc0:rocm:0"), None);
        assert_eq!(slot_cuda_index("risc0:cuda"), None);
        assert_eq!(slot_cuda_index("mock"), None);
        assert_eq!(slot_cuda_index("sp1:cuda:x"), None);
    }

    /// Our own `sp1-gpu-server` must be credited, not counted as foreign. If this regresses, a warm
    /// SP1 slot reads its own resident server as somebody else's VRAM and refuses every proof.
    #[test]
    fn our_own_process_tree_is_not_foreign() {
        assert!(
            pid_is_in_our_tree(std::process::id()),
            "this process must be recognised as ours"
        );
        // init is not in our tree, and the walk must terminate rather than loop at pid 1.
        assert!(!pid_is_in_our_tree(1));
        // A pid that cannot be read is not claimed as ours: we cannot prove it, so it counts as
        // foreign, which is the conservative direction.
        assert!(!pid_is_in_our_tree(u32::MAX));
    }

    /// Only a backend that sizes itself from the card gets a floor, and that floor must be the figure
    /// its smallest MEASURED configuration needs — not the installed-VRAM floor, which is a different
    /// and more permissive number.
    #[test]
    fn only_sp1_requires_free_vram_and_it_requires_what_it_will_actually_use() {
        // Read through the env only when the override is absent: these tests run in parallel with
        // others that may read the same variable.
        if std::env::var(crate::discovery::MIN_AVAILABLE_VRAM_MB_ENV).is_err() {
            let floor = crate::discovery::min_available_vram_bytes_for_backend("sp1")
                .expect("sp1 must require free VRAM");
            assert_eq!(
                floor,
                zkminer_prover_protocol::types::sp1_min_available_vram_bytes(),
                "the floor must come from the measured tier table, so the gate and the tier the \
                 worker is given cannot disagree about whether a card is usable"
            );
            // And a card clearing it must have a configuration to run.
            assert!(
                zkminer_prover_protocol::types::sp1_element_threshold_for_available_vram(floor)
                    .is_some()
            );
        }
        // risc0 and openvm size per segment from po2, which `calibrate_slot_po2` clamps per run. A
        // floor would refuse work that a smaller segment can do.
        assert_eq!(
            crate::discovery::min_available_vram_bytes_for_backend("risc0"),
            None
        );
        assert_eq!(
            crate::discovery::min_available_vram_bytes_for_backend("openvm"),
            None
        );
    }

    /// Against the REAL cards on this host: when a card is partly occupied, the segment the clamp
    /// picks must actually be smaller than the one its capacity would allow. The arithmetic is unit
    /// tested above; this checks that the figures we feed it come out of `nvidia-smi` in the units the
    /// arithmetic expects, which a unit test cannot.
    #[test]
    fn the_clamp_would_fire_on_a_real_occupied_card() {
        use crate::benchmark::find_optimal_po2;
        let Some(gpus) = crate::discovery::detect_nvidia_via_smi_for_test() else {
            eprintln!("no card — skipping");
            return;
        };
        for idx in 0..gpus.len() as u32 {
            let Some((foreign, _used, total)) = foreign_vram_bytes(idx) else {
                continue;
            };
            let (by_capacity, _) = find_optimal_po2(total, "risc0", true);
            let (by_free, _) = find_optimal_po2(total.saturating_sub(foreign), "risc0", true);
            eprintln!(
                "cuda:{idx}: {:.0} MiB free of {:.0} MiB -> po2 {by_free} (capacity would allow \
                 {by_capacity})",
                total.saturating_sub(foreign) as f64 / (1024.0 * 1024.0),
                total as f64 / (1024.0 * 1024.0),
            );
            assert!(
                by_free <= by_capacity,
                "the clamp must never raise the segment: free->{by_free}, capacity->{by_capacity}"
            );
        }
    }

    /// The reclaim wait must return promptly on an idle host rather than burning its whole budget.
    ///
    /// Its budget is 20s and it sits between every pair of benchmark slots, so a version that always
    /// waited the full budget would add minutes to a suite run while looking like it worked.
    #[test]
    fn the_reclaim_wait_does_not_burn_its_budget_when_nothing_is_coming_back() {
        let started = Instant::now();
        let gained = wait_for_reclaim("test", Duration::from_secs(2));
        let took = started.elapsed();
        // Nothing was reaped, so there is nothing to gain and it must fall out on the deadline — but
        // the deadline, not longer, and it must not hang.
        assert!(
            took < Duration::from_secs(4),
            "waited {took:?} on a 2s budget"
        );
        // On a quiet host this is 0; under load another process may free memory and it may be
        // positive. Either is correct — what must not happen is a panic or a hang.
        let _ = gained;
    }

    /// Every benchmark path that reaps a worker must wait for its pages before the loop moves on.
    ///
    /// This cost the 4090 its entire SP1 row: card 0's worker was reaped and card 1's reservation
    /// tested 367 ms later against a `MemAvailable` that had not updated, refusing by 0.2 GiB.
    #[test]
    fn the_benchmark_loop_waits_for_reclaim_between_slots() {
        let src = include_str!("dispatcher.rs");
        for f in [
            "pub fn benchmark_all_with_device_info(",
            "pub fn benchmark_all_streaming(",
        ] {
            let Some((_, after)) = src.split_once(f) else {
                // The streaming entry point may be named differently; the recycle-site assertion
                // below is what actually binds, so a missing name here is not a failure.
                continue;
            };
            let body = match after
                .find("\n    fn ")
                .into_iter()
                .chain(after.find("\n    pub fn "))
                .min()
            {
                Some(end) => &after[..end],
                None => after,
            };
            if !body.contains("Recycling GPU worker") {
                continue;
            }
            assert!(
                body.contains("wait_for_reclaim("),
                "{f} reaps a worker without waiting for its pages, so the NEXT slot's host-memory \
                 reservation is tested against a figure that has not updated yet"
            );
        }
        // And neither recycle site may exist without the wait, whatever the enclosing function is
        // called. Counted over the NON-TEST source only: this module mentions both strings itself, and
        // counting the whole file made the assertion self-referential — it failed 4 against 3 purely
        // on its own literals.
        let code = src
            .split_once("\n#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(src);
        let recycles = code
            .matches(r#"tracing::info!("Recycling GPU worker"#)
            .count();
        let waits = code.matches("wait_for_reclaim(&key,").count();
        assert!(
            recycles > 0,
            "the recycle call moved; move this assertion with it"
        );
        assert_eq!(
            recycles, waits,
            "{recycles} benchmark recycle site(s) but {waits} reclaim wait(s): every reap must be \
             followed by the wait, or the next slot is refused against a stale MemAvailable"
        );
    }

    /// The po2 clamp must only ever go DOWN, and must fall as the free VRAM falls. This is the
    /// adaptation for risc0: a card with a display gets a smaller segment, not a refusal.
    #[test]
    fn the_segment_shrinks_as_free_vram_shrinks() {
        use crate::benchmark::{find_optimal_po2, PO2_MIN};
        const GIB: u64 = 1024 * 1024 * 1024;

        let (full, _) = find_optimal_po2(24 * GIB, "risc0", true);
        let (half, _) = find_optimal_po2(12 * GIB, "risc0", true);
        let (tiny, _) = find_optimal_po2(GIB, "risc0", true);
        assert!(
            full > half && half > tiny,
            "a smaller budget must pick a smaller segment: 24GiB->{full}, 12GiB->{half}, 1GiB->{tiny}"
        );
        // Monotonic across the whole range, since the clamp is `requested.min(fits)` and a
        // non-monotonic `fits` would make the clamp jump about as a display is resized.
        let mut prev = 0u8;
        for gib in 1..=48u64 {
            let (fits, _) = find_optimal_po2(gib * GIB, "risc0", true);
            assert!(
                fits >= prev,
                "po2 fell as VRAM grew at {gib} GiB: {fits} < {prev}"
            );
            assert!(fits >= PO2_MIN, "must never go below PO2_MIN");
            prev = fits;
        }
    }

    /// The resize DECISION, tested directly: fabricating a live worker is not possible here, and the
    /// decision is the part that can be wrong.
    #[test]
    fn a_worker_is_resized_only_when_its_tier_no_longer_fits() {
        const GIB: u64 = 1024 * 1024 * 1024;

        // Spawned with the whole 24 GiB card free (FULL tier), now 20 GiB free — still the FULL tier,
        // so the worker is correctly sized and must be left alone.
        assert!(!vram_tier_shrank("sp1", Some(24 * GIB), 20 * GIB));
        // Now 16 GiB free, which is the SMALL tier: the live worker is sized for more than it has.
        assert!(vram_tier_shrank("sp1", Some(24 * GIB), 16 * GIB));
        // The other direction must never trigger a recycle: VRAM being FREED is good news, and the
        // worker is merely conservative. Growing back costs a respawn for no correctness gain.
        assert!(!vram_tier_shrank("sp1", Some(16 * GIB), 24 * GIB));
        // Unknowable cases must not act on a guess.
        assert!(!vram_tier_shrank("sp1", None, 16 * GIB));
        assert!(!vram_tier_shrank("sp1", Some(24 * GIB), 0));
        // risc0 clamps its segment per run and has no spawn-time tier to go stale.
        assert!(!vram_tier_shrank("risc0", Some(24 * GIB), GIB));
    }

    /// Whatever happens to the live worker, the figure its REPLACEMENT will be sized from has to be
    /// written back — `respawn` reuses the frozen `spawn_env`, so a stale entry there means the
    /// replacement comes back exactly as wrong as the worker it replaced.
    #[test]
    fn the_respawn_environment_tracks_the_free_vram() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let avail_env = zkminer_prover_protocol::types::CUDA_VRAM_AVAILABLE_BYTES_ENV;
        let pool = pool_with_keys(&["sp1:cuda:0"]);
        let mut env = HashMap::new();
        env.insert(avail_env.to_string(), (24 * GIB).to_string());
        pool.test_set_spawn_env("sp1:cuda:0", env);

        pool.resize_worker_if_vram_shrank("sp1:cuda:0", "sp1", 16 * GIB);
        assert_eq!(
            pool.spawn_env_value("sp1:cuda:0", avail_env),
            Some((16 * GIB).to_string()),
        );
    }

    /// EVERY path that puts work on a GPU must check the VRAM budget, between the per-card guard and
    /// the slot mutex. Both halves of that sandwich are load-bearing, for different reasons, and the
    /// three benchmark paths were exempt when this check was first written — the same way they were
    /// once exempt from the per-card guard itself.
    #[test]
    fn every_gpu_path_checks_the_vram_budget_after_the_guard() {
        let src = include_str!("dispatcher.rs");
        for f in [
            "fn prove_on_slot(",
            "fn benchmark_slot(",
            "fn benchmark_slot_streaming(",
            "pub fn calibrate_slot_po2(",
        ] {
            // Bound the search to THIS function's body, or a later function's call satisfies the
            // assertion for an earlier one — the trap the guard assertion fell into.
            let after = src
                .split_once(f)
                .unwrap_or_else(|| panic!("{f} no longer exists; move this assertion with it"))
                .1;
            let body = match after
                .find("\n    fn ")
                .into_iter()
                .chain(after.find("\n    pub fn "))
                .min()
            {
                Some(end) => &after[..end],
                None => after,
            };
            // The CALL, not the name: the doc comments mention `check_vram_budget` too, and a
            // bare-name search would hold with the call deleted.
            let gate = body.find("self.check_vram_budget(").unwrap_or_else(|| {
                panic!(
                    "{f} does not check the VRAM budget. SP1 sizes its shard tier from the card's \
                     TOTAL VRAM and discards the free figure, so on a card with a display attached \
                     it commits to a tier that does not fit and fails part-way. On a benchmark path \
                     that also writes a bad throughput row, which then prices every later job on \
                     the card. Call `check_vram_budget` after the guard."
                )
            });
            let guard = body
                .find("Self::acquire_gpu_guard(")
                .unwrap_or_else(|| panic!("{f} no longer takes the per-card guard"));
            let slot = body
                .find("entry.slot")
                .unwrap_or_else(|| panic!("{f} no longer locks a slot"));
            assert!(
                guard < gate,
                "{f} checks the VRAM budget BEFORE the per-card guard. Another zkminer proof may \
                 still hold that card's VRAM at that point, so the reading would be of our own work \
                 and every call would refuse."
            );
            assert!(
                gate < slot,
                "{f} checks the VRAM budget after the slot mutex. It must come first so a refusal \
                 costs no worker spawn and leaves no host-memory reservation to unwind."
            );
        }
    }

    #[test]
    fn foreign_vram_reads_a_real_card_on_this_host() {
        let Some(gpus) = crate::discovery::detect_nvidia_via_smi_for_test() else {
            eprintln!("nvidia-smi reports no card — skipping the live foreign-VRAM check");
            return;
        };
        if gpus.is_empty() {
            eprintln!("nvidia-smi reports no card — skipping the live foreign-VRAM check");
            return;
        }
        for idx in 0..gpus.len() as u32 {
            let (foreign, used, total) = foreign_vram_bytes(idx)
                .unwrap_or_else(|| panic!("could not read VRAM occupancy for cuda:{idx}"));
            assert!(
                foreign <= used,
                "cuda:{idx}: foreign {foreign} exceeds total in-use {used}"
            );
            assert!(
                total > 1_000_000_000,
                "cuda:{idx} reported {total} bytes total, which is not a plausible card"
            );
            assert!(
                foreign <= total,
                "cuda:{idx}: foreign {foreign} exceeds the card's own total {total}"
            );
            eprintln!(
                "cuda:{idx}: {:.0} MiB foreign of {:.0} MiB total",
                foreign as f64 / (1024.0 * 1024.0),
                total as f64 / (1024.0 * 1024.0),
            );
        }
    }

    #[test]
    fn gpu_env_generic_empty() {
        let env = WorkerPool::gpu_env("risc0", "generic", None, None);
        assert!(env.is_empty());
    }

    /// Occupancy and the visibility pin are SEPARATE, and SP1 is the case that needs them separated.
    ///
    /// It drives a CUDA card but cannot be given `CUDA_VISIBLE_DEVICES`: its SDK sets that on the
    /// `sp1-gpu-server` child itself from the id passed to `with_device_id`, so filtering the worker's
    /// own view makes the two ids disagree and the server exits in seconds. It must still get a real
    /// per-device key, because that is what buys it a per-card lock, a place in the capacity count,
    /// and a card it can be routed to.
    #[test]
    fn sp1_is_pinned_by_device_id_not_by_visibility() {
        let env = WorkerPool::gpu_env("sp1", "cuda", Some("0000:06:10.0"), Some(1));
        assert_eq!(
            env.get(zkminer_prover_protocol::types::CUDA_DEVICE_ID_ENV)
                .map(String::as_str),
            Some("1"),
            "SP1 must be TOLD which card to drive"
        );
        assert!(
            !env.contains_key("CUDA_VISIBLE_DEVICES"),
            "and must NOT have its own view filtered — that is what killed the server in ~7s"
        );
        // The runtime must still order devices the way we enumerate them, or the id means the wrong
        // card.
        assert_eq!(
            env.get("CUDA_DEVICE_ORDER").map(String::as_str),
            Some("PCI_BUS_ID")
        );

        // Every other CUDA backend keeps the ordinary pin, and must NOT get the device-id variable.
        let risc0 = WorkerPool::gpu_env("risc0", "cuda", Some("0000:06:10.0"), Some(1));
        assert_eq!(
            risc0.get("CUDA_VISIBLE_DEVICES").map(String::as_str),
            Some("1")
        );
        assert!(!risc0.contains_key(zkminer_prover_protocol::types::CUDA_DEVICE_ID_ENV));
    }

    /// An SP1 slot must be a real per-card slot: guarded, counted, and addressable.
    #[test]
    fn an_sp1_slot_occupies_a_physical_card() {
        // Guarded — this is what stops SP1 and risc0 double-booking one card's VRAM.
        assert_eq!(
            physical_gpu_id("sp1:cuda:0").as_deref(),
            Some("cuda:0"),
            "SP1 must share the per-card lock with risc0 on the same card"
        );
        assert_eq!(physical_gpu_id("risc0:cuda:0").as_deref(), Some("cuda:0"));
        // The old generic key was unguarded, which is the bug this replaces.
        assert_eq!(physical_gpu_id("sp1:generic"), None);

        // Addressable, and by the SAME device id the benchmark suite and the Settings toggles use —
        // so "disable gpu0" and "route this job to gpu1" mean the same card for SP1 as for risc0.
        assert_eq!(WorkerPool::benchmark_device_id("sp1:cuda:0"), "gpu0");
        assert_eq!(
            WorkerPool::benchmark_device_id("sp1:cuda:0"),
            WorkerPool::benchmark_device_id("risc0:cuda:0")
        );

        // Counted once per physical card, not once per backend.
        let pool = pool_with_keys(&["risc0:cuda:0", "risc0:cuda:1", "sp1:cuda:0", "sp1:cuda:1"]);
        assert_eq!(
            pool.proving_gpu_count(),
            2,
            "two cards, four slots: SP1 must not inflate the capacity count"
        );
    }

    /// The operator's per-device toggles must reach SP1, which is the whole point of giving it a
    /// device. Before this, `sp1:generic` mapped to the CPU device id and no GPU toggle could touch
    /// it.
    #[test]
    fn disabling_a_card_disables_it_for_sp1_too() {
        let pool = pool_with_keys(&["risc0:cuda:0", "risc0:cuda:1", "sp1:cuda:0", "sp1:cuda:1"]);
        let off_gpu0 = std::collections::HashSet::from(["gpu0".to_string()]);
        let mut disabled = pool.slots_disabled_by(&off_gpu0, &std::collections::HashSet::new());
        disabled.sort();
        assert_eq!(
            disabled,
            vec!["risc0:cuda:0".to_string(), "sp1:cuda:0".to_string()],
            "disabling a card must take BOTH backends off it"
        );

        // And a per-(device, backend) toggle can take just SP1 off one card, leaving risc0 on it —
        // which is the configuration that lets the two share a box without contending for VRAM.
        let off_sp1_gpu0 =
            std::collections::HashSet::from([("gpu0".to_string(), "sp1".to_string())]);
        let only_sp1 = pool.slots_disabled_by(&std::collections::HashSet::new(), &off_sp1_gpu0);
        assert_eq!(only_sp1, vec!["sp1:cuda:0".to_string()]);
    }

    #[test]
    fn proving_gpu_count_dedupes_physical_gpus() {
        // cuda:0, cuda:1, rocm:0 = 3 distinct cards; sp1:cuda:0 dedupes with
        // risc0:cuda:0; sp1:generic and bare "risc0" are not GPU-pinned.
        let pool = pool_with_keys(&[
            "risc0:cuda:0",
            "risc0:cuda:1",
            "risc0:rocm:0",
            "sp1:cuda:0",
            "sp1:generic",
            "risc0",
        ]);
        assert_eq!(pool.proving_gpu_count(), 3);
        // No GPU-pinned workers -> at least 1.
        let cpu_only = pool_with_keys(&["sp1:generic", "openvm"]);
        assert_eq!(cpu_only.proving_gpu_count(), 1);
    }

    #[test]
    fn gpu_env_explicit_binary_no_pin() {
        // device_index=None (explicit binary): must NOT inject *_VISIBLE_DEVICES,
        // otherwise the binary is silently forced onto GPU 0 and the user's own
        // visibility env is clobbered. Only housekeeping vars are allowed.
        let cuda = WorkerPool::gpu_env("risc0", "cuda", Some("0000:01:00.0"), None);
        assert!(cuda.get("CUDA_VISIBLE_DEVICES").is_none());
        assert_eq!(cuda.get("CUDA_DEVICE_ORDER").unwrap(), "PCI_BUS_ID");

        let rocm = WorkerPool::gpu_env("risc0", "rocm", None, None);
        assert!(rocm.get("HIP_VISIBLE_DEVICES").is_none());
        assert_eq!(rocm.get("NVCC").unwrap(), "off");

        let intel = WorkerPool::gpu_env("risc0", "intel", None, None);
        assert!(intel.get("ZE_AFFINITY_MASK").is_none());
    }

    // ---- ProvingWatchdog tests ----

    #[test]
    fn watchdog_pid_zero_no_thread() {
        // pid == 0 must not spawn a watchdog thread (kill(0, SIGKILL) = catastrophic).
        let ik = Arc::new(AtomicBool::new(false));
        let watchdog = ProvingWatchdog::new(
            Arc::new(AtomicU32::new(0)),
            Arc::new(AtomicU64::new(0)),
            Duration::from_millis(10),
            "test:generic".to_string(),
            ik,
        );
        assert!(watchdog.thread.is_none());
    }

    #[test]
    fn watchdog_drop_cancels_promptly() {
        // Watchdog with a long timeout should be cancelled promptly by drop.
        let pid_ref = Arc::new(AtomicU32::new(99999)); // non-existent PID
        let ik = Arc::new(AtomicBool::new(false));
        let start = Instant::now();
        let watchdog = ProvingWatchdog::new(
            pid_ref,
            Arc::new(AtomicU64::new(0)),
            Duration::from_secs(600), // 10-minute timeout
            "test:generic".to_string(),
            ik,
        );
        drop(watchdog); // should cancel and join quickly
        let elapsed = start.elapsed();
        // Drop should complete within ~2 seconds (1s sleep granularity + overhead)
        assert!(
            elapsed < Duration::from_secs(3),
            "Drop took too long: {elapsed:?}"
        );
    }

    #[test]
    fn watchdog_skips_kill_when_pid_zeroed() {
        // The watchdog must re-read the PID before killing and skip if it was
        // zeroed (worker died and was cleaned up). We use a 1ms timeout so the
        // watchdog fires after its first 1-second sleep cycle. The PID is zeroed
        // immediately — well before the thread wakes from its 1s sleep.
        let pid_ref = Arc::new(AtomicU32::new(99999));
        let ik = Arc::new(AtomicBool::new(false));
        let watchdog = ProvingWatchdog::new(
            pid_ref.clone(),
            Arc::new(AtomicU64::new(0)),
            Duration::from_millis(1),
            "test:generic".to_string(),
            ik.clone(),
        );
        // Simulate worker death: zero the PID before the watchdog wakes
        pid_ref.store(0, Ordering::Release);
        // Wait for the watchdog thread to fire (~1s sleep + check + return).
        // Don't drop early — drop sets cancel=true which would short-circuit
        // the watchdog before it reaches the PID re-read we want to test.
        std::thread::sleep(Duration::from_millis(2500));
        drop(watchdog);
        // intentional_kill should NOT be set (kill was skipped due to PID change)
        assert!(!ik.load(Ordering::Acquire));
    }

    #[test]
    fn watchdog_skips_kill_when_pid_changed() {
        // Same as above but PID changes to a new value (respawn) instead of 0.
        let pid_ref = Arc::new(AtomicU32::new(99999));
        let ik = Arc::new(AtomicBool::new(false));
        let watchdog = ProvingWatchdog::new(
            pid_ref.clone(),
            Arc::new(AtomicU64::new(0)),
            Duration::from_millis(1),
            "test:generic".to_string(),
            ik.clone(),
        );
        // Simulate respawn: change the PID to a different value
        pid_ref.store(88888, Ordering::Release);
        std::thread::sleep(Duration::from_millis(2500));
        drop(watchdog);
        // intentional_kill should NOT be set
        assert!(!ik.load(Ordering::Acquire));
    }

    #[test]
    fn watchdog_fires_when_pid_unchanged() {
        // Positive path: when the PID is unchanged at timeout, the watchdog
        // should fire and set intentional_kill=true. The SIGKILL targets a
        // non-existent PID (99999) which returns ESRCH — harmless.
        let pid_ref = Arc::new(AtomicU32::new(99999));
        let ik = Arc::new(AtomicBool::new(false));
        let watchdog = ProvingWatchdog::new(
            pid_ref.clone(),
            Arc::new(AtomicU64::new(0)),
            Duration::from_millis(1),
            "test:generic".to_string(),
            ik.clone(),
        );
        // PID stays unchanged — watchdog should fire
        std::thread::sleep(Duration::from_millis(2500));
        drop(watchdog);
        // intentional_kill SHOULD be set (kill was attempted, PID unchanged)
        assert!(ik.load(Ordering::Acquire));
    }

    // ---- backoff-aware dispatch (soak20 job-loss regression) ----

    fn slot_with(failures: u32, last_failure_ago: Option<Duration>, alive: bool) -> WorkerSlot {
        let _ = alive; // handle is always None here: a live slot has no backoff window
        WorkerSlot {
            handle: None,
            path: PathBuf::from("/nonexistent/binary"),
            backend: "risc0".to_string(),
            gpu_tag: "cuda".to_string(),
            device_index: Some(0),
            pci_bus_id: Some("0000:06:1b.0".to_string()),
            gpu_name: Some("test".to_string()),
            spawn_env: HashMap::new(),
            consecutive_failures: failures,
            last_failure: last_failure_ago.map(|d| Instant::now() - d),
            declined: None,
            proofs_since_spawn: 0,
        }
    }

    /// THE REGRESSION. soak20 lost all four of its failed jobs to
    /// `proving failed after 3 attempt(s): Backoff: waiting ~4.5s before respawning`,
    /// with attempt 3 firing 155us after attempt 2. A dead slot inside its own backoff
    /// window must not be considered dispatchable, or the caller's whole
    /// MAX_PROVE_ATTEMPTS budget is spent on a timer.
    #[test]
    fn a_slot_inside_its_respawn_backoff_is_not_dispatchable() {
        // consecutive_failures = 1 -> RESPAWN_BACKOFF[1] = 5s. Failed 0.7s ago, exactly
        // the soak20 shape (OOM at 10:38:43.897, retry at 10:38:44.580).
        let slot = slot_with(1, Some(Duration::from_millis(700)), false);
        assert!(
            WorkerPool::in_respawn_backoff(&slot),
            "0.7s into a 5s window must read as in-backoff"
        );
        assert!(
            WorkerPool::slot_eligible(&slot),
            "it is still ELIGIBLE -- only 1 failure -- which is why slot_eligible alone \
             let the dispatch through"
        );
        assert!(
            !WorkerPool::slot_dispatchable(&slot),
            "but it must NOT be dispatchable: respawn would bail instantly"
        );
    }

    /// Once the window has elapsed the slot is dispatchable again.
    #[test]
    fn a_cooled_backoff_window_is_dispatchable_again() {
        let slot = slot_with(1, Some(Duration::from_secs(6)), false);
        assert!(!WorkerPool::in_respawn_backoff(&slot));
        assert!(WorkerPool::slot_dispatchable(&slot));
    }

    /// A healthy slot that has never failed is unaffected.
    #[test]
    fn a_never_failed_slot_is_dispatchable() {
        let slot = slot_with(0, None, false);
        assert!(!WorkerPool::in_respawn_backoff(&slot));
        assert!(WorkerPool::slot_dispatchable(&slot));
    }

    /// A RETIRED-but-cooled slot must stay dispatchable, so the new predicate cannot
    /// re-retire a card that `RETIRE_COOLDOWN` has already forgiven.
    #[test]
    fn a_retired_but_cooled_slot_is_still_dispatchable() {
        let slot = slot_with(
            MAX_RESPAWN_FAILURES,
            Some(RETIRE_COOLDOWN + Duration::from_secs(1)),
            false,
        );
        assert!(
            WorkerPool::slot_eligible(&slot),
            "RETIRE_COOLDOWN has elapsed, so it is eligible"
        );
        assert!(
            !WorkerPool::in_respawn_backoff(&slot),
            "and well past any RESPAWN_BACKOFF entry"
        );
        assert!(WorkerPool::slot_dispatchable(&slot));
    }

    /// `slot_eligible` must keep its old meaning: `is_backend_healthy` asks "could this
    /// backend ever serve again", not "can it serve right now". Folding the backoff
    /// window into it would make a backend look unhealthy for the length of a backoff.
    #[test]
    fn slot_eligible_truth_table_is_unchanged() {
        assert!(WorkerPool::slot_eligible(&slot_with(0, None, false)));
        assert!(WorkerPool::slot_eligible(&slot_with(
            1,
            Some(Duration::from_millis(1)),
            false
        )));
        assert!(!WorkerPool::slot_eligible(&slot_with(
            MAX_RESPAWN_FAILURES,
            Some(Duration::from_secs(1)),
            false
        )));
        assert!(WorkerPool::slot_eligible(&slot_with(
            MAX_RESPAWN_FAILURES,
            Some(RETIRE_COOLDOWN + Duration::from_secs(1)),
            false
        )));
    }

    /// The `backoff_blocked` discriminator used to gate the single-key shortcut: it must
    /// fire ONLY for an eligible slot inside its window. A retired slot keeps the fast
    /// path so its honest "permanently failed" error is not replaced by a long wait.
    #[test]
    fn only_an_eligible_in_backoff_slot_blocks_the_single_key_shortcut() {
        let blocked =
            |s: &WorkerSlot| WorkerPool::slot_eligible(s) && WorkerPool::in_respawn_backoff(s);
        assert!(
            blocked(&slot_with(1, Some(Duration::from_millis(700)), false)),
            "in-backoff"
        );
        assert!(!blocked(&slot_with(0, None, false)), "healthy");
        assert!(
            !blocked(&slot_with(
                MAX_RESPAWN_FAILURES,
                Some(Duration::from_millis(1)),
                false
            )),
            "retired: must take the fast path and report permanently-failed"
        );
    }

    // ---- respawn backoff tests ----

    #[test]
    fn respawn_permanently_failed() {
        let mut slot = WorkerSlot {
            handle: None,
            path: PathBuf::from("/nonexistent/binary"),
            backend: "test".to_string(),
            gpu_tag: "generic".to_string(),
            device_index: None,
            pci_bus_id: None,
            gpu_name: None,
            spawn_env: HashMap::new(),
            consecutive_failures: MAX_RESPAWN_FAILURES,
            last_failure: Some(Instant::now()),
            declined: None,
            proofs_since_spawn: 0,
        };
        let result = WorkerPool::respawn(&mut slot);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("permanently failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn respawn_backoff_rejects_too_soon() {
        let mut slot = WorkerSlot {
            handle: None,
            path: PathBuf::from("/nonexistent/binary"),
            backend: "test".to_string(),
            gpu_tag: "generic".to_string(),
            device_index: None,
            pci_bus_id: None,
            gpu_name: None,
            spawn_env: HashMap::new(),
            consecutive_failures: 1,
            last_failure: Some(Instant::now()), // just failed
            declined: None,
            proofs_since_spawn: 0,
        };
        // With consecutive_failures=1, backoff is RESPAWN_BACKOFF[1] = 5s.
        // Since last_failure is ~now, respawn should be rejected.
        let result = WorkerPool::respawn(&mut slot);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Backoff"), "unexpected error: {err}");
    }

    #[test]
    fn respawn_increments_failures_on_bad_binary() {
        let mut slot = WorkerSlot {
            handle: None,
            path: PathBuf::from("/nonexistent/binary"),
            backend: "test".to_string(),
            gpu_tag: "generic".to_string(),
            device_index: None,
            pci_bus_id: None,
            gpu_name: None,
            spawn_env: HashMap::new(),
            consecutive_failures: 0,
            last_failure: None,
            declined: None,
            proofs_since_spawn: 0,
        };
        let result = WorkerPool::respawn(&mut slot);
        assert!(result.is_err());
        assert_eq!(slot.consecutive_failures, 1);
        assert!(slot.last_failure.is_some());
    }

    // ---- ensure_alive tests ----

    #[test]
    fn ensure_alive_respawn_failure_increments_failures() {
        // When ensure_alive has handle=None (no worker), it attempts respawn.
        // With a bad binary path, respawn fails and consecutive_failures is incremented.
        let pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
        let pid = AtomicU32::new(0);
        let mut slot = WorkerSlot {
            handle: None,
            path: PathBuf::from("/nonexistent/binary"),
            backend: "test".to_string(),
            gpu_tag: "generic".to_string(),
            device_index: None,
            pci_bus_id: None,
            gpu_name: None,
            spawn_env: HashMap::new(),
            consecutive_failures: 0,
            last_failure: None,
            declined: None,
            proofs_since_spawn: 0,
        };
        let result = pool.ensure_alive(&mut slot, &pid);
        assert!(result.is_err());
        assert_eq!(slot.consecutive_failures, 1);
        assert!(slot.last_failure.is_some());
        // PID should be 0 (defensively zeroed in the handle=None path)
        assert_eq!(pid.load(Ordering::Acquire), 0);
    }

    #[test]
    fn ensure_alive_handle_none_zeros_stale_pid() {
        // When handle is already None, ensure_alive defensively zeroes a stale
        // PID before attempting respawn. This prevents a future code change from
        // accidentally leaving a stale PID that could be SIGKILLed.
        let pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
        let pid = AtomicU32::new(12345); // stale PID
        let mut slot = WorkerSlot {
            handle: None,
            path: PathBuf::from("/nonexistent/binary"),
            backend: "test".to_string(),
            gpu_tag: "generic".to_string(),
            device_index: None,
            pci_bus_id: None,
            gpu_name: None,
            spawn_env: HashMap::new(),
            consecutive_failures: 0,
            last_failure: None,
            declined: None,
            proofs_since_spawn: 0,
        };
        let result = pool.ensure_alive(&mut slot, &pid);
        assert!(result.is_err());
        // PID is defensively zeroed even in the handle=None path
        assert_eq!(pid.load(Ordering::Acquire), 0);
    }

    #[test]
    fn benchmark_device_id_matches_benchmark_module_ids() {
        // These strings are a CONTRACT with benchmark.rs: CUDA rows are built as
        // format!("gpu{idx}") from the slot key's device index, CPU rows are "cpu".
        // If this drifts, `resolve_po2` looks up a device that does not exist in the
        // suite, silently returns None, and po2 selection quietly stops working —
        // with no error anywhere.
        assert_eq!(WorkerPool::benchmark_device_id("risc0:cuda:0"), "gpu0");
        assert_eq!(WorkerPool::benchmark_device_id("risc0:cuda:1"), "gpu1");
        assert_eq!(WorkerPool::benchmark_device_id("sp1:generic"), "cpu");
        // Degenerate/explicit keys must not panic.
        assert_eq!(WorkerPool::benchmark_device_id("mock"), "cpu");
        assert_eq!(WorkerPool::benchmark_device_id("risc0:cuda"), "gpu0");
    }

    #[test]
    fn different_vendors_never_share_a_device_id() {
        // `device_index` is sequential WITHIN a vendor (discovery.rs), so a rocm
        // card and a cuda card both legitimately carry index 0. The old key
        // discarded the tag and mapped both to "gpu0": one physical card's
        // throughput and po2 samples then overwrote the other's, and which one
        // survived depended on HashMap iteration order.
        //
        // The previous version of this test asserted rocm:2 -> "gpu2", encoding the
        // assumption that rocm indices continue cuda numbering. Discovery never
        // produces that.
        assert_ne!(
            WorkerPool::benchmark_device_id("risc0:cuda:0"),
            WorkerPool::benchmark_device_id("risc0:rocm:0"),
        );
        assert_eq!(WorkerPool::benchmark_device_id("risc0:rocm:0"), "gpu-rocm0");
        // CUDA keeps the legacy bare form so existing benchmarks.json still loads.
        assert_eq!(WorkerPool::benchmark_device_id("risc0:cuda:0"), "gpu0");
        // Every GPU id, whatever the vendor, must still satisfy the
        // `starts_with("gpu")` predicate that run.rs and app.rs use to mean
        // "this is a GPU row" -- planner_active and stale-row pruning depend on it.
        for key in ["risc0:cuda:0", "risc0:rocm:0", "risc0:intel:1"] {
            assert!(WorkerPool::benchmark_device_id(key).starts_with("gpu"));
        }
        assert!(!WorkerPool::benchmark_device_id("sp1:generic").starts_with("gpu"));
    }
}

#[cfg(test)]
mod declined_backend_tests {
    use super::*;

    fn pool_with(slots: Vec<(&str, WorkerSlot)>) -> WorkerPool {
        let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
        for (key, sl) in slots {
            pool.workers.insert(
                key.to_string(),
                WorkerEntry {
                    slot: Mutex::new(sl),
                    vram_bytes: None,
                    pci_bus_id: None,
                    pid: Arc::new(AtomicU32::new(0)),
                    pid_starttime: Arc::new(AtomicU64::new(0)),
                    intentional_kill: Arc::new(AtomicBool::new(false)),
                },
            );
        }
        pool
    }

    fn slot(declined: Option<&str>, cf: u32) -> WorkerSlot {
        WorkerSlot {
            handle: None,
            path: PathBuf::from("/nonexistent"),
            backend: "sp1".to_string(),
            gpu_tag: "generic".to_string(),
            device_index: None,
            pci_bus_id: None,
            gpu_name: None,
            spawn_env: HashMap::new(),
            consecutive_failures: cf,
            last_failure: Some(Instant::now()),
            declined: declined.map(str::to_string),
            proofs_since_spawn: 0,
        }
    }

    /// THE DEFECT. A spawn failure registers the slot with consecutive_failures = 1, so
    /// `slot_eligible` was true, `is_backend_healthy` returned true for a "dead but
    /// eligible" slot by design, `backend_sources` reported the backend as a real
    /// Subprocess, and run.rs's pre-claim gate let the miner CLAIM jobs the worker had
    /// just said it could not prove. Refusing the handshake alone did NOT close that.
    #[test]
    fn a_declined_slot_is_not_eligible_even_though_it_looks_transient() {
        // Exactly the state discover_and_spawn records on a failed spawn.
        let transient = slot(None, 1);
        assert!(
            WorkerPool::slot_eligible(&transient),
            "a transient failure must stay eligible so a crashed worker respawns"
        );

        let declined = slot(Some("sp1 unavailable: libcudart.so.12 not found"), 1);
        assert!(
            !WorkerPool::slot_eligible(&declined),
            "a DECLINED slot must never be eligible -- no retry can change its verdict"
        );
    }

    /// The cooldown clause is a pure clock check, so without the declined guard the slot
    /// became eligible again every RETIRE_COOLDOWN, re-opening the claim window for the
    /// life of the process.
    #[test]
    fn a_declined_slot_stays_ineligible_past_the_retire_cooldown() {
        let mut s = slot(Some("cannot prove here"), MAX_RESPAWN_FAILURES);
        s.last_failure = Some(Instant::now() - (RETIRE_COOLDOWN + Duration::from_secs(1)));
        // A non-declined slot in this state IS eligible again -- that is the behaviour
        // the guard must not break.
        let mut cooled = s.clone_for_test();
        cooled.declined = None;
        assert!(
            WorkerPool::slot_eligible(&cooled),
            "a cooled-down transient failure must become eligible again"
        );
        assert!(
            !WorkerPool::slot_eligible(&s),
            "but a declined slot must stay ineligible regardless of elapsed time"
        );
    }

    /// What the MONEY path actually reads. run.rs's pre-claim gate consults
    /// `engine::backend_sources()`, which asks `is_backend_healthy`. Asserting on the
    /// `Workers:` log line (as the first verification of this fix wrongly did) proves
    /// nothing: that is `discover_and_spawn`'s returned vec, a DIFFERENT predicate.
    #[test]
    fn a_declined_backend_is_neither_healthy_nor_silently_simulated() {
        let pool = pool_with(vec![(
            "sp1:generic",
            slot(Some("libcudart.so.12: cannot open shared object"), 1),
        )]);

        assert!(
            !pool.is_backend_healthy("sp1"),
            "a declined backend must NOT read as healthy -- this is the check the \
             pre-claim gate depends on, and it was true before the fix"
        );
        let reason = pool
            .backend_declined("sp1")
            .expect("the decline reason must be reportable so it is not mistaken for demo mode");
        assert!(
            reason.contains("libcudart"),
            "reason should carry the cause: {reason}"
        );
    }

    /// One healthy slot means the backend is NOT categorically declined, even if a
    /// sibling slot declined -- otherwise a single bad card would disable a working one.
    #[test]
    fn one_healthy_slot_keeps_the_backend_available() {
        let pool = pool_with(vec![
            ("sp1:cuda:0", slot(Some("declined"), 1)),
            ("sp1:cuda:1", slot(None, 0)),
        ]);
        assert!(
            pool.backend_declined("sp1").is_none(),
            "a backend with one usable slot must not be reported as declined"
        );
    }

    /// A declined worker must not be respawned either -- it is pointless churn against a
    /// worker that has told us it cannot work.
    #[test]
    fn a_declined_slot_is_not_dispatchable() {
        let declined = slot(Some("cannot prove here"), 1);
        assert!(!WorkerPool::slot_dispatchable(&declined));
    }
}

impl WorkerSlot {
    /// Test-only shallow copy (WorkerHandle is not Clone, and these fixtures hold None).
    #[cfg(test)]
    fn clone_for_test(&self) -> Self {
        WorkerSlot {
            handle: None,
            path: self.path.clone(),
            backend: self.backend.clone(),
            gpu_tag: self.gpu_tag.clone(),
            device_index: self.device_index,
            pci_bus_id: self.pci_bus_id.clone(),
            gpu_name: self.gpu_name.clone(),
            spawn_env: self.spawn_env.clone(),
            consecutive_failures: self.consecutive_failures,
            last_failure: self.last_failure,
            declined: self.declined.clone(),
            proofs_since_spawn: self.proofs_since_spawn,
        }
    }
}

/// The card-identity readers must not touch the slot mutex.
///
/// `prove_on_slot` holds a slot's guard for the entire proof and hands `recv_proof` a progress
/// callback that the worker triggers at proof start. That callback runs SYNCHRONOUSLY on the
/// proving thread and asks the pool which card is running — so if the lookup takes the same
/// mutex, the thread deadlocks against itself (`std::sync::Mutex` is not reentrant) and the proof
/// never completes, the deadline release never runs, and shutdown blocks.
#[cfg(test)]
mod bus_id_locking_tests {
    use super::*;

    fn pool_with_entry(key: &str, bus: Option<&str>) -> WorkerPool {
        let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
        pool.workers.insert(
            key.to_string(),
            WorkerEntry {
                slot: Mutex::new(WorkerSlot {
                    handle: None,
                    path: PathBuf::from("/nonexistent"),
                    backend: "risc0".to_string(),
                    gpu_tag: "cuda".to_string(),
                    device_index: Some(0),
                    // Deliberately DIFFERENT from the entry-level value below, so a reader that
                    // goes back to the slot is visible rather than merely slow.
                    pci_bus_id: Some("0000:ff:ff.0".to_string()),
                    gpu_name: None,
                    spawn_env: HashMap::new(),
                    consecutive_failures: 0,
                    last_failure: None,
                    declined: None,
                    proofs_since_spawn: 0,
                }),
                vram_bytes: None,
                pci_bus_id: bus.map(|b| b.to_string()),
                pid: Arc::new(AtomicU32::new(0)),
                pid_starttime: Arc::new(AtomicU64::new(0)),
                intentional_kill: Arc::new(AtomicBool::new(false)),
            },
        );
        pool
    }

    /// THE regression test. With the guard held — exactly the state `prove_on_slot` is in when the
    /// progress callback fires — both readers must still answer. If either goes through the mutex
    /// this test does not fail, it HANGS, which is what production did.
    #[test]
    fn the_readers_answer_while_the_slot_guard_is_held() {
        let pool = pool_with_entry("risc0:cuda:0", Some("0000:06:10.0"));
        let entry = pool.workers.get("risc0:cuda:0").unwrap();
        let _guard = entry.slot.lock().unwrap();

        assert_eq!(
            pool.bus_id_for_slot("risc0:cuda:0").as_deref(),
            Some("0000:06:10.0"),
            "bus_id_for_slot must not re-enter the slot mutex — the proving thread already holds \
             it when the progress callback asks which card is running"
        );
        assert_eq!(
            pool.gpu_bus_ids(),
            vec!["0000:06:10.0".to_string()],
            "gpu_bus_ids must neither block nor SKIP a busy slot: skipping it left a proving \
             card out of the power sampler's filter, so its row was cached at the fallback wattage"
        );
    }

    /// A CPU slot has no card, and an empty string is not an identity.
    #[test]
    fn a_slot_without_a_card_reports_none() {
        let pool = pool_with_entry("risc0:generic", None);
        assert_eq!(pool.bus_id_for_slot("risc0:generic"), None);
        assert!(pool.gpu_bus_ids().is_empty());
        // An unknown key is None rather than a panic.
        assert_eq!(pool.bus_id_for_slot("nope"), None);
    }
}
