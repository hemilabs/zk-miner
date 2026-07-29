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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Benchmark results for a single worker slot, with device metadata.
#[derive(Debug, Clone)]
pub struct SlotBenchmarkResult {
    pub slot_key: String,
    pub gpu_name: Option<String>,
    pub device_index: Option<u32>,
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
}

/// A streaming benchmark progress update from a specific worker slot.
#[derive(Debug, Clone)]
pub struct BenchmarkProgressEvent {
    /// Worker slot key, e.g. "risc0:cuda:0"
    pub slot_key: String,
    /// GPU name, e.g. "AMD Radeon RX 7900 XTX"
    pub gpu_name: Option<String>,
    /// Device index within vendor
    pub device_index: Option<u32>,
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
    /// PCI bus ID for GPU pinning (None for generic/explicit).
    /// Stored for diagnostic logging; the actual device pinning is
    /// baked into `spawn_env` at discovery time.
    #[allow(dead_code)]
    pci_bus_id: Option<String>,
    /// Human-readable GPU name (None for generic/explicit).
    gpu_name: Option<String>,
    /// Environment variables to pass when spawning this worker.
    spawn_env: HashMap<String, String>,
    consecutive_failures: u32,
    last_failure: Option<Instant>,
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
    /// Current worker PID. 0 = no live worker. Updated on spawn/respawn.
    /// Wrapped in Arc so the ProvingWatchdog thread can re-read the PID before
    /// killing, avoiding SIGKILL on a stale/recycled PID.
    pid: Arc<AtomicU32>,
    /// Set to true when the worker is killed intentionally (timeout or cancel).
    /// Prevents the error handler from incrementing consecutive_failures,
    /// which would permanently retire the slot after 3 timeouts.
    intentional_kill: Arc<AtomicBool>,
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
                        #[cfg(unix)]
                        unsafe {
                            libc::kill(-(current_pid as i32), libc::SIGKILL);
                            libc::kill(current_pid as i32, libc::SIGKILL);
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
fn gpu_vram_bytes(gpu_tag: &str, device_index: Option<u32>) -> Option<u64> {
    let idx = device_index?;
    if gpu_tag != "cuda" {
        return None;
    }
    let output = std::process::Command::new("nvidia-smi")
        .env("CUDA_DEVICE_ORDER", "PCI_BUS_ID")
        .args([
            "--query-gpu=memory.total",
            "--format=csv,noheader,nounits",
            &format!("--id={idx}"),
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mib: u64 = String::from_utf8_lossy(&output.stdout).trim().parse().ok()?;
    Some(mib * 1024 * 1024)
}

/// Pool of worker processes, keyed by compound slot key.
pub struct WorkerPool {
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
                    env.insert("CUDA_VISIBLE_DEVICES".into(), i.to_string());
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
            path,
        } in discovered
        {
            let key = slot_key(&backend, &gpu_tag, device_index);
            let env = Self::gpu_env(&gpu_tag, pci_bus_id.as_deref(), device_index);

            let device_desc = match (&gpu_name, device_index) {
                (Some(name), Some(idx)) => format!(" [GPU {idx}: {name}]"),
                (None, Some(idx)) => format!(" [GPU {idx}]"),
                _ => String::new(),
            };

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
                    proofs_since_spawn: 0,
                            }),
                            vram_bytes: gpu_vram_bytes(&gpu_tag, device_index),
                            pid: Arc::new(AtomicU32::new(worker_pid)),
                            intentional_kill: Arc::new(AtomicBool::new(false)),
                        },
                    );
                    connected.push(key);
                }
                Err(e) => {
                    tracing::error!("Failed to start worker {key}{device_desc}: {e:#}");
                    let vram_bytes = gpu_vram_bytes(&gpu_tag, device_index);
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
                                proofs_since_spawn: 0,
                            }),
                            vram_bytes,
                            pid: Arc::new(AtomicU32::new(0)),
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
                    Err(_) => {
                        // Mutex held = worker is busy = backend is connected.
                        // Extract backend from key format "backend:gpu_tag[:idx]".
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
            .filter(|k| {
                *k == prefix || k.starts_with(&format!("{prefix}:"))
            })
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
                        let alive = slot
                            .handle
                            .as_mut()
                            .map(|h| h.is_alive())
                            .unwrap_or(false);
                        // A dead-but-eligible slot is still "healthy": it will respawn
                        // on the next dispatch. Without this, once a slot is retired the
                        // brain stops claiming even after the cooldown clears it.
                        if alive || Self::slot_eligible(&slot) {
                            return true;
                        }
                    }
                    Err(_) => {
                        // Mutex held = proving in progress = worker is alive
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
        let entry = self
            .workers
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("No worker registered for '{key}'"))?;

        let mut slot = entry
            .slot
            .lock()
            .map_err(|_| anyhow::anyhow!("Worker lock poisoned for {key}"))?;

        self.ensure_alive(&mut slot, &entry.pid)?;
        if let Some(h) = slot.handle.as_ref() {
            entry.pid.store(h.pid(), Ordering::Release);
        }
        entry.intentional_kill.store(false, Ordering::Release);

        let handle = slot
            .handle
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker not available for {key}"))?;

        let request_id = po2 as u64;
        if let Err(e) = handle.send(&WorkerCommand::CalibrateSegmentLimit { request_id, po2 }) {
            Self::mark_slot_failed(&mut slot, &entry.pid);
            return Err(e);
        }

        // A calibration run is a full proof — reuse the benchmark timeout budget.
        let _watchdog = self.benchmark_timeout.map(|t| {
            ProvingWatchdog::new(
                entry.pid.clone(),
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
                    Self::mark_slot_dead(&mut slot, &entry.pid);
                } else {
                    Self::mark_slot_failed(&mut slot, &entry.pid);
                }
                Err(e)
            }
        }
    }

    fn benchmark_slot(&self, key: &str) -> Result<Vec<BenchmarkEntry>> {
        let entry = self
            .workers
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("No worker registered for '{key}'"))?;

        let mut slot = entry.slot
            .lock()
            .map_err(|_| anyhow::anyhow!("Worker lock poisoned for {key}"))?;

        self.ensure_alive(&mut slot, &entry.pid)?;

        // Update external PID after ensure_alive (may have respawned)
        if let Some(h) = slot.handle.as_ref() {
            entry.pid.store(h.pid(), Ordering::Release);
        }

        // Reset intentional_kill so a timeout doesn't inherit a stale flag
        entry.intentional_kill.store(false, Ordering::Release);

        let handle = slot.handle.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker not available for {key}"))?;

        if let Err(e) = handle.send(&WorkerCommand::Benchmark) {
            Self::mark_slot_failed(&mut slot, &entry.pid);
            return Err(e);
        }

        // Start benchmark timeout watchdog if configured.
        let _watchdog = self.benchmark_timeout.map(|t| {
            ProvingWatchdog::new(entry.pid.clone(), t, key.to_string(), entry.intentional_kill.clone())
        });

        let bench_response = handle.recv_benchmark(&|_, _, _| {});

        if let Err(ref _e) = bench_response {
            if entry.intentional_kill.load(Ordering::Acquire) {
                Self::mark_slot_dead(&mut slot, &entry.pid);
            } else {
                Self::mark_slot_failed(&mut slot, &entry.pid);
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
    pub fn benchmark_all_with_device_info(
        &self,
    ) -> Vec<SlotBenchmarkResult> {
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
            let (gpu_name, device_index, gpu_tag, backend, vram_bytes) =
                if let Some(entry) = self.workers.get(&key) {
                    // vram_bytes lives on the WorkerEntry, outside the slot Mutex.
                    let vram = entry.vram_bytes;
                    if let Ok(slot) = entry.slot.lock() {
                        (
                            slot.gpu_name.clone(),
                            slot.device_index,
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
                tracing::info!(
                    "Skipping benchmark for {key} (GPU worker available for {backend})"
                );
                continue;
            }

            match self.benchmark_slot(&key) {
                Ok(entries) if !entries.is_empty() => {
                    results.push(SlotBenchmarkResult {
                        slot_key: key.clone(),
                        gpu_name,
                        device_index,
                        gpu_tag: gpu_tag.clone(),
                        entries,
                        vram_bytes,
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
                    if let Ok(mut slot) = entry.slot.lock() {
                        if let Some(handle) = &mut slot.handle {
                            tracing::info!("Recycling GPU worker {key} to free VRAM");
                            handle.shutdown();
                        }
                        Self::mark_slot_dead(&mut slot, &entry.pid);
                        recycled_keys.push(key.clone());
                    }
                }
            }
        }

        // Respawn recycled GPU workers so they're available for proving
        for key in &recycled_keys {
            if let Some(entry) = self.workers.get(key) {
                if let Ok(mut slot) = entry.slot.lock() {
                    tracing::info!("Respawning GPU worker {key} after benchmarks");
                    slot.consecutive_failures = 0;
                    slot.last_failure = None;
                    if let Err(e) = Self::respawn(&mut slot) {
                        tracing::warn!("Failed to respawn GPU worker {key} after benchmarks: {e:#}");
                    }
                    if let Some(h) = slot.handle.as_ref() {
                        entry.pid.store(h.pid(), Ordering::Release);
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
        let entry = self
            .workers
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("No worker registered for '{key}'"))?;

        let mut slot = entry.slot
            .lock()
            .map_err(|_| anyhow::anyhow!("Worker lock poisoned for {key}"))?;

        // Extract metadata before borrowing handle
        let gpu_name = slot.gpu_name.clone();
        let device_index = slot.device_index;
        let gpu_tag = slot.gpu_tag.clone();

        self.ensure_alive(&mut slot, &entry.pid)?;

        // Update external PID after ensure_alive (may have respawned)
        if let Some(h) = slot.handle.as_ref() {
            entry.pid.store(h.pid(), Ordering::Release);
        }

        // Reset intentional_kill so a timeout doesn't inherit a stale flag
        entry.intentional_kill.store(false, Ordering::Release);

        let handle = slot.handle.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker not available for {key}"))?;

        if let Err(e) = handle.send(&WorkerCommand::Benchmark) {
            Self::mark_slot_failed(&mut slot, &entry.pid);
            return Err(e);
        }

        // Start benchmark timeout watchdog if configured.
        let _watchdog = self.benchmark_timeout.map(|t| {
            ProvingWatchdog::new(entry.pid.clone(), t, key.to_string(), entry.intentional_kill.clone())
        });

        let key_owned = key.to_string();
        let cb = |entry: &zkminer_prover_protocol::BenchmarkEntry, idx: u32, total: u32| {
            on_progress(BenchmarkProgressEvent {
                slot_key: key_owned.clone(),
                gpu_name: gpu_name.clone(),
                device_index,
                gpu_tag: gpu_tag.clone(),
                entry: entry.clone(),
                program_index: idx,
                total_programs: total,
            });
        };

        let bench_response = handle.recv_benchmark(&cb);

        if let Err(ref _e) = bench_response {
            if entry.intentional_kill.load(Ordering::Acquire) {
                Self::mark_slot_dead(&mut slot, &entry.pid);
            } else {
                Self::mark_slot_failed(&mut slot, &entry.pid);
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
            let (gpu_name, device_index, gpu_tag, backend, vram_bytes) =
                if let Some(entry) = self.workers.get(&key) {
                    // vram_bytes lives on the WorkerEntry, outside the slot Mutex.
                    let vram = entry.vram_bytes;
                    if let Ok(slot) = entry.slot.lock() {
                        (
                            slot.gpu_name.clone(),
                            slot.device_index,
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
                tracing::info!(
                    "Skipping benchmark for {key} (GPU worker available for {backend})"
                );
                continue;
            }

            match self.benchmark_slot_streaming(&key, on_progress) {
                Ok(entries) if !entries.is_empty() => {
                    results.push(SlotBenchmarkResult {
                        slot_key: key.clone(),
                        gpu_name,
                        device_index,
                        gpu_tag: gpu_tag.clone(),
                        entries,
                        vram_bytes,
                    });
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Benchmark failed for {key}: {e:#}");
                }
            }

            if gpu_tag == "cuda" || gpu_tag == "rocm" {
                if let Some(entry) = self.workers.get(&key) {
                    if let Ok(mut slot) = entry.slot.lock() {
                        if let Some(handle) = &mut slot.handle {
                            tracing::info!("Recycling GPU worker {key} to free VRAM");
                            handle.shutdown();
                        }
                        Self::mark_slot_dead(&mut slot, &entry.pid);
                        recycled_keys.push(key.clone());
                    }
                }
            }
        }

        for key in &recycled_keys {
            if let Some(entry) = self.workers.get(key) {
                if let Ok(mut slot) = entry.slot.lock() {
                    tracing::info!("Respawning GPU worker {key} after benchmarks");
                    slot.consecutive_failures = 0;
                    slot.last_failure = None;
                    if let Err(e) = Self::respawn(&mut slot) {
                        tracing::warn!("Failed to respawn GPU worker {key} after benchmarks: {e:#}");
                    }
                    if let Some(h) = slot.handle.as_ref() {
                        entry.pid.store(h.pid(), Ordering::Release);
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
        on_progress: Option<Box<dyn Fn(f64) + Send>>,
    ) -> Result<ProofOutput> {
        // Never leave a prove unbounded: if the caller didn't set a deadline, arm a
        // generous backstop watchdog so a wedged worker can't hang forever. (The
        // miner's job path calls prove_min_vram directly with its own tuned timeout.)
        let timeout = timeout.or(Some(DEFAULT_PROVE_WATCHDOG_TIMEOUT));
        let mut used = None;
        self.prove_min_vram(
            backend, elf, input_data, po2, timeout, on_progress, None, &[], &mut used, None, None,
        )
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
    #[allow(clippy::too_many_arguments)]
    pub fn prove_min_vram(
        &self,
        backend: &str,
        elf: &[u8],
        input_data: &[u8],
        po2: Option<u8>,
        timeout: Option<Duration>,
        on_progress: Option<Box<dyn Fn(f64) + Send>>,
        min_vram_bytes: Option<u64>,
        exclude: &[String],
        used_slot: &mut Option<String>,
        abort_at: Option<Instant>,
        // Resolves the segment size (po2) for the slot that is ultimately chosen.
        // Needed because the DEVICE is picked in here (VRAM floor, availability,
        // exclusions) — the caller cannot know it in advance, and po2 is a
        // per-device property. Consulted only when `po2` is None.
        po2_resolver: Option<&dyn Fn(&str) -> Option<u8>>,
    ) -> Result<ProofOutput> {
        let all_keys = self.keys_for_prefix(backend);
        if all_keys.is_empty() {
            bail!("No worker registered for backend '{backend}'");
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
            let pruned: Vec<String> =
                vram_keys.iter().filter(|k| !exclude.contains(*k)).cloned().collect();
            if pruned.is_empty() { vram_keys } else { pruned }
        };

        // Single key — use it directly
        if keys.len() == 1 {
            *used_slot = Some(keys[0].clone());
            return self.prove_on_slot(&keys[0], elf, input_data, po2, timeout, on_progress, abort_at, po2_resolver);
        }

        // Multiple keys — round-robin to find an available worker
        let start = ROUND_ROBIN.fetch_add(1, Ordering::Relaxed) % keys.len();
        for i in 0..keys.len() {
            let key = &keys[(start + i) % keys.len()];
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
                let gpu_free = self.gpu_lock_for(key).map_or(true, |l| {
                    !matches!(l.try_lock(), Err(std::sync::TryLockError::WouldBlock))
                });
                if !gpu_free {
                    continue;
                }
                if let Ok(mut slot) = entry.slot.try_lock() {
                    let is_alive = slot
                        .handle
                        .as_mut()
                        .map(|h| h.is_alive())
                        .unwrap_or(false);
                    if is_alive || Self::slot_eligible(&slot) {
                        drop(slot);
                        *used_slot = Some(key.clone());
                        return self.prove_on_slot(key, elf, input_data, po2, timeout, on_progress, abort_at, po2_resolver);
                    }
                }
            }
        }

        // All busy — block on first non-permanently-failed slot
        let fallback = keys
            .iter()
            .find(|k| {
                self.workers
                    .get(*k)
                    .and_then(|e| e.slot.lock().ok())
                    .map(|s| Self::slot_eligible(&s))
                    .unwrap_or(false)
            })
            .unwrap_or(&keys[0]);
        *used_slot = Some(fallback.clone());
        self.prove_on_slot(fallback, elf, input_data, po2, timeout, on_progress, abort_at, po2_resolver)
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
            (Some(_gpu_tag), Some(idx)) => format!("gpu{idx}"),
            (Some(_gpu_tag), None) => "gpu0".to_string(),
        }
    }

    /// Get-or-create the per-physical-GPU proving lock for a slot key (see
    /// `gpu_locks`). Returns `None` for unguarded slots (CPU/generic/explicit).
    fn gpu_lock_for(&self, key: &str) -> Option<Arc<Mutex<()>>> {
        let id = physical_gpu_id(key)?;
        let mut map = self.gpu_locks.lock().unwrap_or_else(|e| e.into_inner());
        Some(map.entry(id).or_insert_with(|| Arc::new(Mutex::new(()))).clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn prove_on_slot(
        &self,
        key: &str,
        elf: &[u8],
        input_data: &[u8],
        po2: Option<u8>,
        timeout: Option<Duration>,
        on_progress: Option<Box<dyn Fn(f64) + Send>>,
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
        let gpu_lock = self.gpu_lock_for(key);
        let _gpu_guard = gpu_lock
            .as_ref()
            .map(|l| l.lock().unwrap_or_else(|e| e.into_inner()));

        let entry = self
            .workers
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("No worker registered for '{key}'"))?;

        let mut slot = entry.slot
            .lock()
            .map_err(|_| anyhow::anyhow!("Worker lock poisoned for {key}"))?;

        // Fix #3: proactively recycle a worker that has completed many proofs, so the
        // accumulated GPU context / buffer pool / persistent stream (which can wedge a
        // flaky card mid-proof) is reset to a clean slate. Killing the live handle here
        // makes ensure_alive() respawn a fresh worker (which zeroes proofs_since_spawn).
        // consecutive_failures/last_failure are untouched (0/None for a healthy worker),
        // so respawn is immediate (no backoff). If the respawn transiently fails,
        // ensure_alive() below returns Err and the job retries on another worker —
        // the same accepted trade-off as the OOM/stream-corruption kill paths.
        let recycle_n = recycle_after_proofs();
        if recycle_n > 0 && slot.handle.is_some() && slot.proofs_since_spawn >= recycle_n {
            tracing::info!(
                "Recycling worker {}:{} after {} proofs (fresh GPU state)",
                slot.backend, slot.gpu_tag, slot.proofs_since_spawn
            );
            if let Some(h) = slot.handle.as_mut() {
                h.kill();
            }
            // Zero the PID BEFORE dropping the handle (WorkerHandle::drop reaps the
            // zombie, after which the OS may reuse the PID — must be 0 by then).
            entry.pid.store(0, Ordering::Release);
            slot.handle = None;
        }

        self.ensure_alive(&mut slot, &entry.pid)?;

        // Update the external PID after ensure_alive (may have respawned)
        if let Some(h) = slot.handle.as_ref() {
            entry.pid.store(h.pid(), Ordering::Release);
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
                    return Err(anyhow::anyhow!(
                        "aborting proof on {key}: only {:?} left before deadline cutoff after \
                         GPU queue wait — not starting (releasing to recover collateral)",
                        remaining
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
        let handle = slot.handle.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Worker not available after ensure_alive"))?;

        static REQUEST_COUNTER: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let request_id =
            REQUEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if let Err(e) = handle.send(&WorkerCommand::Prove {
            request_id,
            elf: elf.to_vec(),
            input_data: input_data.to_vec(),
            po2,
        }) {
            // Send failed (broken pipe = worker died before receiving the command).
            Self::mark_slot_failed(&mut slot, &entry.pid);
            return Err(e);
        }

        // Start proving timeout watchdog if a deadline is set.
        // The watchdog SIGKILLs the worker via PID if the proof exceeds the timeout.
        // On SIGKILL, recv_proof gets EOF and returns an error, releasing the Mutex.
        let _watchdog = watchdog_timeout.map(|t| {
            ProvingWatchdog::new(entry.pid.clone(), t, key.to_string(), entry.intentional_kill.clone())
        });

        let proof_response = handle.recv_proof(request_id, &on_progress);

        // If recv_proof failed (EOF, stream corruption, protocol desync),
        // kill the worker to prevent reusing a corrupted IPC stream.
        if let Err(ref e) = proof_response {
            // EOF (WorkerDied) means the worker already died — just clear the handle.
            // Anything else (bincode error, desync) means the stream is corrupt
            // but the worker may still be alive — kill it explicitly.
            let is_eof = e.downcast_ref::<WorkerDied>().is_some();
            if !is_eof {
                tracing::error!("Stream corruption detected for {key}, killing worker");
                if let Some(h) = slot.handle.as_mut() {
                    h.kill();
                }
            }
            // Don't count intentional kills (timeout/cancel) as failures —
            // otherwise 3 timeouts permanently retire the slot.
            if entry.intentional_kill.load(Ordering::Acquire) {
                tracing::info!("Worker {key} killed intentionally (timeout/cancel), not counting as failure");
                Self::mark_slot_dead(&mut slot, &entry.pid);
            } else {
                Self::mark_slot_failed(&mut slot, &entry.pid);
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
                    return Err(anyhow::anyhow!(
                        "proof on {key} stopped: job deadline reached mid-proof (releasing to \
                         recover collateral)"
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
            WorkerResponse::Error {
                kind, message, ..
            } => {
                let err_msg = format!("Worker {key} proof error ({kind:?}): {message}");
                if matches!(kind, ErrorKind::ResourceExhausted) {
                    tracing::warn!("Worker {key} OOM — killing for respawn with clean GPU state");
                    if let Some(h) = slot.handle.as_mut() {
                        h.kill();
                    }
                    // OOM is a real failure — increment to prevent infinite loops
                    Self::mark_slot_failed(&mut slot, &entry.pid);
                }
                bail!(err_msg)
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
                        let pid = entry.pid.load(Ordering::Acquire);
                        if pid != 0 {
                            tracing::warn!("Cancelling proof on {key} by killing worker PID {pid}");
                            entry.intentional_kill.store(true, Ordering::Release);
                            // Kill the whole process group (worker calls setpgid(0,0)),
                            // so a forked GPU server child (e.g. sp1-gpu-server) dies too
                            // instead of leaking VRAM and holding the stdout write end
                            // (which would hang recv_proof). Matches the timeout watchdog.
                            #[cfg(unix)]
                            unsafe {
                                libc::kill(-(pid as i32), libc::SIGKILL);
                                libc::kill(pid as i32, libc::SIGKILL);
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
    fn mark_slot_failed(slot: &mut WorkerSlot, pid: &AtomicU32) {
        slot.handle = None;
        pid.store(0, Ordering::Release);
        slot.consecutive_failures += 1;
        slot.last_failure = Some(Instant::now());
    }

    /// Mark a worker slot as dead without counting it as a failure (intentional kill).
    fn mark_slot_dead(slot: &mut WorkerSlot, pid: &AtomicU32) {
        slot.handle = None;
        pid.store(0, Ordering::Release);
    }

    /// True if a slot may be dispatched to: healthy, or retired-but-cooled-down so a
    /// transient failure burst doesn't sideline a GPU until process restart.
    fn slot_eligible(slot: &WorkerSlot) -> bool {
        slot.consecutive_failures < MAX_RESPAWN_FAILURES
            || slot.last_failure.map_or(false, |t| t.elapsed() >= RETIRE_COOLDOWN)
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
                        slot.backend, slot.gpu_tag, last.elapsed()
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
            let backoff_idx =
                (slot.consecutive_failures as usize).min(RESPAWN_BACKOFF.len() - 1);
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
        pid: &AtomicU32,
    ) -> Result<&'a mut WorkerHandle> {
        let is_alive = slot
            .handle
            .as_mut()
            .map(|h| h.is_alive())
            .unwrap_or(false);

        let needs_respawn = if is_alive {
            false
        } else if slot.handle.is_some() {
            tracing::warn!(
                "Worker {}:{} died, will attempt respawn",
                slot.backend,
                slot.gpu_tag
            );
            // Zero PID before dropping the handle. Once WorkerHandle::drop reaps
            // the zombie, the OS can reuse the PID — the atomic must be 0 by then.
            pid.store(0, Ordering::Release);
            slot.handle = None;
            // Do NOT increment consecutive_failures here — respawn() owns failure counting.
            // This also fixes the "first respawn always fails" bug where the self-imposed
            // last_failure timestamp caused an immediate backoff rejection.
            true
        } else {
            // Defensively zero PID when handle is None. All code paths that set
            // handle=None also zero the PID, so this should already be 0. But if
            // a future change forgets to zero it, this prevents stale-PID kills.
            pid.store(0, Ordering::Release);
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
            let pid = entry.pid.load(Ordering::Acquire);
            if pid != 0 {
                tracing::info!("Sending SIGTERM to worker {key} (PID {pid})");
                #[cfg(unix)]
                unsafe {
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
        for (_key, entry) in &self.workers {
            let pid = entry.pid.load(Ordering::Acquire);
            if pid != 0 {
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
        for (_key, entry) in &self.workers {
            let mut slot = entry.slot.lock().unwrap_or_else(|e| e.into_inner());
            Self::mark_slot_dead(&mut slot, &entry.pid);
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
                    proofs_since_spawn: 0,
                }),
                vram_bytes: None,
                pid: Arc::new(AtomicU32::new(pid)),
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
        self.workers
            .get(key)
            .map(|e| e.pid.load(Ordering::Acquire))
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
        let entry = self.workers.get(key)
            .unwrap_or_else(|| panic!("test_set_spawn_env: key '{key}' not found in pool"));
        let mut slot = entry.slot.lock()
            .unwrap_or_else(|e| e.into_inner());
        slot.spawn_env = env;
    }

    /// Reset consecutive_failures and last_failure for a worker slot.
    /// Used to bypass the respawn backoff in tests that need immediate respawn.
    ///
    /// # Panics
    /// Panics if `key` is not registered in the pool (likely a test bug).
    pub fn test_reset_failures(&self, key: &str) {
        let entry = self.workers.get(key)
            .unwrap_or_else(|| panic!("test_reset_failures: key '{key}' not found in pool"));
        let mut slot = entry.slot.lock()
            .unwrap_or_else(|e| e.into_inner());
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
        assert_eq!(physical_gpu_id("openvm:intel:0").as_deref(), Some("intel:0"));
        // Different device indices are distinct physical GPUs → distinct locks.
        assert_ne!(physical_gpu_id("risc0:cuda:0"), physical_gpu_id("risc0:cuda:1"));
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
                    proofs_since_spawn: 0,
                    }),
                    vram_bytes: None,
                    pid: Arc::new(AtomicU32::new(0)),
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
            vec!["risc0:cuda:0", "risc0:cuda:1", "risc0:generic", "risc0:rocm:0"]
        );
    }

    #[test]
    fn keys_for_prefix_vendor_level() {
        let pool = pool_with_keys(&[
            "risc0:cuda:0",
            "risc0:cuda:1",
            "risc0:rocm:0",
        ]);
        let mut keys = pool.keys_for_prefix("risc0:cuda");
        keys.sort();
        assert_eq!(keys, vec!["risc0:cuda:0", "risc0:cuda:1"]);
    }

    #[test]
    fn keys_for_prefix_exact_match() {
        let pool = pool_with_keys(&[
            "risc0:cuda:0",
            "risc0:cuda:1",
        ]);
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
        let env = WorkerPool::gpu_env("cuda", Some("0000:01:00.0"), Some(1));
        assert_eq!(env.get("CUDA_DEVICE_ORDER").unwrap(), "PCI_BUS_ID");
        assert_eq!(env.get("CUDA_VISIBLE_DEVICES").unwrap(), "1");
    }

    #[test]
    fn gpu_env_rocm() {
        let env = WorkerPool::gpu_env("rocm", None, Some(2));
        assert_eq!(env.get("HIP_VISIBLE_DEVICES").unwrap(), "2");
        assert_eq!(env.get("NVCC").unwrap(), "off");
    }

    #[test]
    fn gpu_env_intel() {
        // Single selection mechanism only: ZE_AFFINITY_MASK. Also setting
        // ONEAPI_DEVICE_SELECTOR would double-filter and select nothing for index>0.
        let env = WorkerPool::gpu_env("intel", None, Some(1));
        assert_eq!(env.get("ZE_AFFINITY_MASK").unwrap(), "1");
        assert!(env.get("ONEAPI_DEVICE_SELECTOR").is_none());
    }

    #[test]
    fn gpu_env_generic_empty() {
        let env = WorkerPool::gpu_env("generic", None, None);
        assert!(env.is_empty());
    }

    #[test]
    fn proving_gpu_count_dedupes_physical_gpus() {
        // cuda:0, cuda:1, rocm:0 = 3 distinct cards; sp1:cuda:0 dedupes with
        // risc0:cuda:0; sp1:generic and bare "risc0" are not GPU-pinned.
        let pool = pool_with_keys(&[
            "risc0:cuda:0", "risc0:cuda:1", "risc0:rocm:0", "sp1:cuda:0", "sp1:generic", "risc0",
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
        let cuda = WorkerPool::gpu_env("cuda", Some("0000:01:00.0"), None);
        assert!(cuda.get("CUDA_VISIBLE_DEVICES").is_none());
        assert_eq!(cuda.get("CUDA_DEVICE_ORDER").unwrap(), "PCI_BUS_ID");

        let rocm = WorkerPool::gpu_env("rocm", None, None);
        assert!(rocm.get("HIP_VISIBLE_DEVICES").is_none());
        assert_eq!(rocm.get("NVCC").unwrap(), "off");

        let intel = WorkerPool::gpu_env("intel", None, None);
        assert!(intel.get("ZE_AFFINITY_MASK").is_none());
    }

    // ---- ProvingWatchdog tests ----

    #[test]
    fn watchdog_pid_zero_no_thread() {
        // pid == 0 must not spawn a watchdog thread (kill(0, SIGKILL) = catastrophic).
        let ik = Arc::new(AtomicBool::new(false));
        let watchdog = ProvingWatchdog::new(
            Arc::new(AtomicU32::new(0)),
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
            Duration::from_secs(600), // 10-minute timeout
            "test:generic".to_string(),
            ik,
        );
        drop(watchdog); // should cancel and join quickly
        let elapsed = start.elapsed();
        // Drop should complete within ~2 seconds (1s sleep granularity + overhead)
        assert!(elapsed < Duration::from_secs(3), "Drop took too long: {elapsed:?}");
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
            proofs_since_spawn: 0,
        };
        let result = WorkerPool::respawn(&mut slot);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("permanently failed"), "unexpected error: {err}");
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
            proofs_since_spawn: 0,
        };
        let result = pool.ensure_alive(&mut slot, &pid);
        assert!(result.is_err());
        // PID is defensively zeroed even in the handle=None path
        assert_eq!(pid.load(Ordering::Acquire), 0);
    }

    #[test]
    fn benchmark_device_id_matches_benchmark_module_ids() {
        // These strings are a CONTRACT with benchmark.rs: GPU rows are built as
        // format!("gpu{idx}") from the slot key's device index, CPU rows are "cpu".
        // If this drifts, `resolve_po2` looks up a device that does not exist in the
        // suite, silently returns None, and po2 selection quietly stops working —
        // with no error anywhere.
        assert_eq!(WorkerPool::benchmark_device_id("risc0:cuda:0"), "gpu0");
        assert_eq!(WorkerPool::benchmark_device_id("risc0:cuda:1"), "gpu1");
        assert_eq!(WorkerPool::benchmark_device_id("risc0:rocm:2"), "gpu2");
        assert_eq!(WorkerPool::benchmark_device_id("sp1:generic"), "cpu");
        // Degenerate/explicit keys must not panic.
        assert_eq!(WorkerPool::benchmark_device_id("mock"), "cpu");
        assert_eq!(WorkerPool::benchmark_device_id("risc0:cuda"), "gpu0");
    }
}
