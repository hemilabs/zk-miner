//! Proving engine trait and CPU prover dispatch.
//!
//! Provides a trait-based interface for ZK proving that dispatches to
//! whichever backend is compiled in (risc0, sp1, or openvm), or to
//! subprocess workers discovered at runtime.

use anyhow::Result;
use std::sync::OnceLock;
use std::time::Duration;

use crate::dispatcher::WorkerPool;

/// Global worker pool. Initialized explicitly via `init_worker_pool()`.
static WORKER_POOL: OnceLock<WorkerPool> = OnceLock::new();

/// Initialize the global worker pool. Must be called after config is loaded,
/// before TUI starts rendering. Subsequent calls are ignored.
pub fn init_worker_pool(pool: WorkerPool) {
    WORKER_POOL.set(pool).ok();
}

/// Returns the global worker pool, or None if not yet initialized.
pub fn worker_pool() -> Option<&'static WorkerPool> {
    WORKER_POOL.get()
}

/// Result of a proving operation.
#[derive(Debug, Clone)]
pub struct ProofOutput {
    /// The journal (public values / output committed by the guest).
    pub journal: Vec<u8>,
    /// The seal (cryptographic proof).
    pub seal: Vec<u8>,
    /// Total proving duration.
    pub duration: Duration,
    /// Estimated cycle count.
    pub cycles: u64,
}

/// Trait for the proving engine, allowing mock implementations for testing.
pub trait ProvingEngine: Send + Sync {
    /// Prove execution of the given ELF with the provided input data.
    /// `po2` sets the risc0 segment_limit_po2; None = SDK default.
    fn prove(&self, elf: &[u8], input_data: &[u8], po2: Option<u8>) -> Result<ProofOutput>;

    /// Prove with a specific backend. Default impl delegates to prove().
    fn prove_with_backend(
        &self,
        _backend: &str,
        elf: &[u8],
        input_data: &[u8],
        po2: Option<u8>,
    ) -> Result<ProofOutput> {
        self.prove(elf, input_data, po2)
    }
}

/// Resolve the po2 to use for a proof, applying the priority chain:
///   1. Manual override from po2_overrides (if set for this device+backend)
///   2. Dynamic selection via Po2Profile calibration data
///   3. None (let the SDK use its default)
///
/// Returns None for non-risc0 backends (SP1/OpenVM ignore po2).
pub fn resolve_po2(
    device_id: &str,
    backend: &str,
    estimated_cycles: u64,
    po2_overrides: &std::collections::HashMap<(String, String), u8>,
    po2_profile: Option<&crate::benchmark::Po2Profile>,
) -> Option<u8> {
    if backend != "risc0" {
        return None;
    }

    // Priority 1: Manual override
    let key = (device_id.to_string(), backend.to_string());
    if let Some(&po2) = po2_overrides.get(&key) {
        return Some(po2);
    }

    // Priority 2: Dynamic selection from calibration data
    if let Some(profile) = po2_profile {
        if estimated_cycles > 0 {
            // Only override the SDK when calibration shows a DECISIVE winner. A plain
            // argmax would act on differences inside measurement noise, which measured
            // 5% SLOWER than the default on a 4090 — see `confident_po2_for_job`.
            if let Some(po2) = profile.confident_po2_for_job(estimated_cycles) {
                return Some(po2);
            }
        }
    }

    // Priority 3: Let the SDK choose
    None
}

/// How a backend is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendSource {
    /// Compiled into the binary via feature flag.
    InProcess,
    /// Available via subprocess worker.
    Subprocess,
    /// No real backend; simulated benchmarks only.
    Simulated,
}

/// Returns the list of prover backends enabled at compile time.
/// When no backend feature is compiled (mock/simulated mode), returns all three.
pub fn enabled_backends() -> Vec<&'static str> {
    let mut backends = Vec::new();
    if cfg!(feature = "risc0") {
        backends.push("risc0");
    }
    if cfg!(feature = "sp1") {
        backends.push("sp1");
    }
    if cfg!(feature = "openvm") {
        backends.push("openvm");
    }
    if backends.is_empty() {
        // Check subprocess workers
        if let Some(pool) = worker_pool() {
            let connected = pool.connected_backends();
            if !connected.is_empty() {
                return connected
                    .iter()
                    .map(|s| {
                        // Leak strings so we can return &'static str
                        // This is fine since backends are a fixed small set
                        match s.as_str() {
                            "risc0" => "risc0",
                            "sp1" => "sp1",
                            "openvm" => "openvm",
                            _ => {
                                tracing::warn!("Unknown backend from worker: {s}");
                                "unknown"
                            }
                        }
                    })
                    .collect();
            }
        }
        // Mock / simulated mode — show all engines as available
        backends.extend_from_slice(&["risc0", "sp1", "openvm"]);
    }
    backends
}

/// Returns all available backends with their source (in-process, subprocess, or simulated).
/// True if any backend's worker spoke the protocol and said it cannot prove here.
///
/// `backend_sources` reports NOTHING for such a backend, which is right — but it means the
/// remaining entries can be all-`Simulated`, and the pre-claim gate reads an all-`Simulated` list
/// as "demo mode, claim freely". On a host whose only discovered worker is a declining SP1 (the
/// fresh-install-of-the-release-artifacts case), the gate would then claim every job, including
/// the SP1 jobs that worker has just proved it cannot serve — a guaranteed loss, and a stranded
/// collateral if the deadline passes before the release.
pub fn any_backend_declined() -> bool {
    worker_pool().is_some_and(|pool| {
        ["risc0", "sp1", "openvm"]
            .iter()
            .any(|b| pool.backend_declined(b).is_some())
    })
}

pub fn backend_sources() -> Vec<(&'static str, BackendSource)> {
    let mut sources = Vec::new();

    // Check compile-time features first
    let all_backends = &["risc0", "sp1", "openvm"];
    let features = [
        cfg!(feature = "risc0"),
        cfg!(feature = "sp1"),
        cfg!(feature = "openvm"),
    ];

    let any_feature = features.iter().any(|&f| f);

    for (i, &backend) in all_backends.iter().enumerate() {
        if features[i] {
            sources.push((backend, BackendSource::InProcess));
        } else if let Some(pool) = worker_pool() {
            if pool.is_backend_healthy(backend) {
                sources.push((backend, BackendSource::Subprocess));
            } else if let Some(reason) = pool.backend_declined(backend) {
                // Report NOTHING for a backend whose worker spoke the protocol and said
                // it cannot prove here. Reporting `Simulated` would be worse than
                // reporting nothing: that is the demo-mode marker, and the pre-claim gate
                // in run.rs treats an all-Simulated list as "demo, claim freely".
                tracing::debug!("backend {backend} declined, not advertising it: {reason}");
            } else if !any_feature {
                sources.push((backend, BackendSource::Simulated));
            }
        } else if !any_feature {
            sources.push((backend, BackendSource::Simulated));
        }
    }

    sources
}

/// CPU-based prover that dispatches to the enabled backend.
///
/// When built with `--features risc0`, delegates to RISC Zero.
/// When built with `--features sp1`, delegates to SP1.
/// When built with `--features openvm`, delegates to OpenVM.
/// When a subprocess worker is available, delegates to it.
/// With no features and no workers, returns an error.
pub struct CpuProver {
    /// Number of threads to use (0 = auto-detect).
    pub threads: usize,
    /// Specific backend to use. None = auto-select.
    pub backend: Option<String>,
}

impl CpuProver {
    pub fn new() -> Self {
        Self {
            threads: 0,
            backend: None,
        }
    }

    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads;
        self
    }

    pub fn with_backend(mut self, backend: String) -> Self {
        self.backend = Some(backend);
        self
    }
}

impl Default for CpuProver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvingEngine for CpuProver {
    #[allow(unreachable_code, unused_variables)]
    fn prove(&self, elf: &[u8], input_data: &[u8], po2: Option<u8>) -> Result<ProofOutput> {
        // If a specific backend is requested, use prove_with_backend
        if let Some(ref backend) = self.backend {
            return self.prove_with_backend(backend, elf, input_data, po2);
        }

        // Dispatch to the first enabled prover backend (priority: risc0 > sp1 > openvm).
        #[cfg(feature = "risc0")]
        {
            return crate::risc0::Risc0Prover.prove(elf, input_data, po2);
        }

        #[cfg(feature = "sp1")]
        {
            return crate::sp1::Sp1Prover::new().prove(elf, input_data, po2);
        }

        #[cfg(feature = "openvm")]
        {
            return crate::openvm::OpenVmProver.prove(elf, input_data, po2);
        }

        // Try subprocess workers
        if let Some(pool) = worker_pool() {
            let connected = pool.connected_backends();
            if let Some(backend) = connected.first() {
                return pool.prove(backend, elf, input_data, po2, None, None);
            }
        }

        // Fall-through when no in-process backend was compiled in and no
        // subprocess worker is connected. With one of the risc0/sp1/openvm
        // features enabled, the early returns above fire and this is dead —
        // the `#[allow(unreachable_code)]` on the fn permits it.
        anyhow::bail!(
            "No prover backend available. Build with --features risc0/sp1/openvm, \
             or install a worker binary (zkminer-prove-risc0, etc.)"
        )
    }

    fn prove_with_backend(
        &self,
        backend: &str,
        elf: &[u8],
        input_data: &[u8],
        po2: Option<u8>,
    ) -> Result<ProofOutput> {
        // 1. Check compile-time backends
        match backend {
            #[cfg(feature = "risc0")]
            "risc0" => return crate::risc0::Risc0Prover.prove(elf, input_data, po2),
            #[cfg(feature = "sp1")]
            "sp1" => return crate::sp1::Sp1Prover::new().prove(elf, input_data, po2),
            #[cfg(feature = "openvm")]
            "openvm" => return crate::openvm::OpenVmProver.prove(elf, input_data, po2),
            _ => {}
        }

        // 2. Try subprocess worker
        if let Some(pool) = worker_pool() {
            if pool.is_backend_healthy(backend) {
                return pool.prove(backend, elf, input_data, po2, None, None);
            }
        }

        anyhow::bail!(
            "Backend '{}' not available. Install zkminer-prove-{} or build with --features {}",
            backend,
            backend,
            backend
        )
    }
}

/// Async wrapper for CPU proving (runs in blocking thread pool).
pub async fn prove_async(
    backend: &str,
    elf: Vec<u8>,
    input_data: Vec<u8>,
    po2: Option<u8>,
    timeout: Option<Duration>,
    on_progress: Option<Box<dyn Fn(f64) + Send>>,
) -> Result<ProofOutput> {
    let backend = backend.to_string();
    tokio::task::spawn_blocking(move || {
        // If a specific backend is requested, use it
        let prover = CpuProver {
            threads: 0,
            backend: if backend.is_empty() {
                None
            } else {
                Some(backend)
            },
        };

        // For subprocess backends with progress, use the pool directly
        if let Some(ref backend_name) = prover.backend {
            if let Some(pool) = worker_pool() {
                if pool.is_backend_healthy(backend_name) {
                    // engine's public callback is Fn(f64); the pool now also reports
                    // the slot key. Drop it here rather than widening this API.
                    let cb: Option<Box<dyn Fn(f64, &str) + Send>> = on_progress.map(|f| {
                        Box::new(move |p: f64, _slot: &str| f(p)) as Box<dyn Fn(f64, &str) + Send>
                    });
                    return pool.prove(backend_name, &elf, &input_data, po2, timeout, cb);
                }
            }
        }

        prover.prove(&elf, &input_data, po2)
    })
    .await?
}
