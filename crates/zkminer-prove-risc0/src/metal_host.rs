//! Apple GPU (Metal) specifics of the risc0 worker (feature `metal`).
//!
//! Unified memory changes three things against a discrete card:
//! - The GPU's memory is the owner's RAM. Metal's own ceiling for one process is the device's
//!   `recommendedMaxWorkingSetSize` (about 75% of RAM; 30.15 GB of 36 GiB on the dev machine), and the
//!   risc0 fork honours an artificial lower one, `RISC0_METAL_MAX_WORKING_SET_BYTES` (PLAN 9.1, Z6).
//!   [`working_set_limit`] is the smallest of those and the host's figure (`ZKMINER_CUDA_VRAM_BYTES`,
//!   which the dispatcher sets to `hw.memsize` less an 8 GiB host reserve on a Mac).
//! - The segment size a Mac can prove at follows from that limit, not from a fixed default
//!   ([`job_po2_for_limit`]).
//! - Pipeline-state (PSO) creation for the big translated kernels takes tens of seconds to minutes
//!   the first time on a machine (PLAN 9.1, notes R4/R6/C4/K3/G7), so the worker builds every
//!   circuit's PSOs once at start ([`warm_up_pipelines`]), outside any job deadline.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use zkminer_prover_protocol::types::CUDA_VRAM_BYTES_ENV;

const GIB: u64 = 1 << 30;

/// Macs with less RAM than this are refused (PLAN 9.1: "any 8 GB Mac" is not supported). 12 GiB, not
/// 16, so a 16 GB machine is never refused over how the OS rounds `hw.memsize`.
pub const MIN_HOST_MEMORY_BYTES: u64 = 12 * GIB;

/// The Groth16 prover's resident footprint on the GPU while its proving key is cached
/// (`risc0-groth16-sys` Metal prover, note G7: 5628.7 MiB measured, 5655.5 MiB planned).
pub const GROTH16_RESIDENT_BYTES: u64 = 5_930_236_936;

/// Headroom kept free beside the largest GPU phase when deciding whether to keep the Groth16 cache.
/// Large because on unified memory the proof's host-side state (preflight traces, recursion
/// witnesses) comes out of the same RAM: the full po2 20 benchmark on the 36 GB dev machine peaked
/// at 17.6 GB of GPU allocations (5.7 GB of it the kept key) but at a 31 GB process footprint, so
/// ~13 GB of host-side state.
const KEEP_HEADROOM_BYTES: u64 = 12 * GIB;

/// The Mac this worker runs on, if it is one the worker supports.
#[derive(Debug, Clone)]
pub struct MetalHost {
    /// The Metal device's name (`risc0_zkp::hal::metal::device_name`), e.g. "Apple M5 Max".
    pub name: String,
    /// `recommendedMaxWorkingSetSize` of the system default device.
    pub recommended_working_set: u64,
    /// `hw.memsize`.
    pub host_memory: u64,
}

fn sysctl_u64(name: &str) -> Option<u64> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = [0u8; 8];
    let mut len: libc::size_t = buf.len();
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    match (rc, len) {
        (0, 4) => Some(u32::from_ne_bytes(buf[..4].try_into().ok()?) as u64),
        (0, 8) => Some(u64::from_ne_bytes(buf)),
        _ => None,
    }
}

/// Whether this Mac can run the worker: `Err` carries the message the worker refuses with.
pub fn support() -> &'static Result<MetalHost, String> {
    static SUPPORT: OnceLock<Result<MetalHost, String>> = OnceLock::new();
    SUPPORT.get_or_init(|| {
        let refused = check_support();
        if let Err(msg) = &refused {
            tracing::error!("{msg}");
        }
        refused
    })
}

fn check_support() -> Result<MetalHost, String> {
    // An x86_64 build runs on an Intel Mac, or under Rosetta on Apple Silicon; neither is supported
    // (Rosetta does not translate Metal's Apple-GPU families the kernels are built for).
    if !cfg!(target_arch = "aarch64") {
        return Err(
            "the Metal risc0 worker needs an Apple Silicon Mac and an aarch64-apple-darwin build: \
             Intel Macs (and x86_64 builds under Rosetta) are not supported"
                .to_string(),
        );
    }
    if sysctl_u64("sysctl.proc_translated") == Some(1) {
        return Err(
            "the Metal risc0 worker is running under Rosetta translation; build it for \
             aarch64-apple-darwin"
                .to_string(),
        );
    }
    let Some(device) = metal::Device::system_default() else {
        return Err("no Metal device: the Metal risc0 worker needs an Apple Silicon GPU".into());
    };
    let name = risc0_zkp::hal::metal::device_name().unwrap_or_else(|| device.name().to_string());
    if !name.starts_with("Apple") || !device.has_unified_memory() {
        return Err(format!(
            "Metal device {name:?} is not an Apple Silicon GPU: the Metal risc0 worker supports \
             Apple Silicon Macs only (Intel Macs and discrete GPUs are not supported)"
        ));
    }
    let host_memory = sysctl_u64("hw.memsize").unwrap_or(0);
    if host_memory < MIN_HOST_MEMORY_BYTES {
        return Err(format!(
            "this Mac has {:.1} GiB of memory: the Metal risc0 worker needs at least 16 GB \
             (8 GB Macs cannot hold a proof beside macOS; PLAN 9.1)",
            host_memory as f64 / GIB as f64
        ));
    }
    Ok(MetalHost {
        name,
        recommended_working_set: device.recommended_max_working_set_size(),
        host_memory,
    })
}

/// `RISC0_METAL_MAX_WORKING_SET_BYTES`, parsed with the fork's grammar (`4294967296`, `4G`, ...).
fn budget_env() -> Option<u64> {
    risc0_groth16_sys::metal::working_set_budget()
}

/// The GPU memory this worker may plan with: the smallest of the device's
/// `recommendedMaxWorkingSetSize`, `RISC0_METAL_MAX_WORKING_SET_BYTES` and the host's
/// `ZKMINER_CUDA_VRAM_BYTES`. `None` on an unsupported Mac.
pub fn working_set_limit() -> Option<u64> {
    let host = support().as_ref().ok()?;
    let vram_env = std::env::var(CUDA_VRAM_BYTES_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v > 0);
    Some(
        [Some(host.recommended_working_set), budget_env(), vram_env]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(host.recommended_working_set),
    )
}

/// The default segment size for a working-set limit (PLAN 9.1). Peak GPU memory measured with this
/// worker's benchmark (memory-merkle, M5 Max, merged fork; docs/metal-port-notes/M1.md), segments /
/// recursion phase:
///
/// | limit           | po2 | STARK peak (MiB) | typical Mac                                     |
/// |-----------------|-----|------------------|-------------------------------------------------|
/// | < 6 GiB         | 17  | 2082 / 3971      | 16 GB base chip under a ~4 GB owner-active cap  |
/// | 6 to < 12 GiB   | 18  | 2700 / 4390      | 16 GB Mac (~10.7 GB recommended, 8 GiB host)    |
/// | 12 to < 20 GiB  | 19  | 4976 / 6668      | 24 GB Mac (16 GiB host figure)                  |
/// | >= 20 GiB       | 20  | 9473 / 11169     | 32 GB and up (28.1 GiB on the 36 GB dev machine)|
///
/// The Groth16 wrap needs ~7.4 GB on its own (5.7 GB key + identity_p254), so below ~8 GiB a
/// proof's STARK fits but its wrap does not (M1 note). Never above
/// [`zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2`].
pub fn job_po2_for_limit(limit: u64) -> u8 {
    let po2 = if limit < 6 * GIB {
        17
    } else if limit < 12 * GIB {
        18
    } else if limit < 20 * GIB {
        19
    } else {
        20
    };
    po2.min(zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2)
}

/// This Mac's default segment size ([`job_po2_for_limit`] of [`working_set_limit`]), or the protocol
/// default on an unsupported Mac (which proves nothing anyway).
pub fn default_job_po2() -> u8 {
    static PO2: OnceLock<u8> = OnceLock::new();
    *PO2.get_or_init(|| match working_set_limit() {
        Some(limit) => {
            let po2 = job_po2_for_limit(limit);
            tracing::info!(
                "Metal working-set limit {:.1} GiB: default segment po2 {po2}",
                limit as f64 / GIB as f64
            );
            po2
        }
        None => zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2,
    })
}

/// Peak GPU memory of the largest STARK phase at `po2`: the recursion phase, which runs beside the
/// segment prover's cached pool. Measured with the worker's benchmark on the M5 Max (M1 note):
/// 3971 / 4390 / 6668 / 11169-11938 MiB at po2 17 / 18 / 19 / 20, rounded up.
pub fn stark_peak_bytes(po2: u8) -> u64 {
    match po2 {
        0..=17 => 4 * GIB,
        18 => 5 * GIB,
        19 => 7 * GIB,
        20 => 12 * GIB,
        p => 12 * GIB << (p - 20).min(4),
    }
}

/// Whether the Groth16 proving key may stay cached on the GPU between proofs: only when it fits
/// beside the next proof's largest STARK phase with headroom. On unified memory a kept key is 5.6 GB
/// of the owner's RAM held while idle, so this is the high-end tier only.
pub fn keep_groth16_cache(limit: u64, po2: u8) -> bool {
    limit >= stark_peak_bytes(po2) + GROTH16_RESIDENT_BYTES + KEEP_HEADROOM_BYTES
}

/// The device's `currentAllocatedSize` (this process's GPU allocations), or 0 without a device.
pub fn allocated_bytes() -> u64 {
    static DEVICE: OnceLock<Option<metal::Device>> = OnceLock::new();
    DEVICE
        .get_or_init(metal::Device::system_default)
        .as_ref()
        .map_or(0, |d| d.current_allocated_size())
}

pub fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1u64 << 20) as f64
}

/// After every proof (success or failure), on the proving thread: drop the recursion provers this
/// thread caches (their HALs' pools). The zkvm already does this, and drops the segment prover too,
/// after every Groth16 wrap (`release_hal_buffers`), so on a successful proof this finds nothing; a
/// proof that failed before its wrap leaves the segment prover's pool cached until the next
/// proof, because the zkvm has no public entry point to drop it (M1 note, issue for the zkvm owner).
pub fn release_after_proof() {
    risc0_circuit_recursion::prove::release_cached_provers();
    tracing::info!(
        "Metal GPU memory held after the proof: {:.1} MiB",
        mib(allocated_bytes())
    );
}

/// Samples `currentAllocatedSize` every 2 ms on a background thread and records the peak per named
/// phase (PLAN 9.1: peak GPU memory per phase is a first-class metric).
pub struct PeakSampler {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
    phases: Mutex<Vec<(String, u64)>>,
}

impl PeakSampler {
    pub fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(allocated_bytes()));
        let handle = {
            let (stop, peak) = (stop.clone(), peak.clone());
            std::thread::Builder::new()
                .name("metal-mem-sampler".into())
                .spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        peak.fetch_max(allocated_bytes(), Ordering::Relaxed);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                })
                .ok()
        };
        Self {
            stop,
            peak,
            handle,
            phases: Mutex::new(Vec::new()),
        }
    }

    /// Close the current phase: record its peak and start the next one from the current size.
    pub fn phase(&self, name: &str) -> u64 {
        let now = allocated_bytes();
        let peak = self.peak.swap(now, Ordering::Relaxed).max(now);
        self.phases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((name.to_string(), peak));
        peak
    }

    /// Record what is allocated now (not a peak), e.g. after the post-proof release.
    pub fn held(&self, name: &str) -> u64 {
        let now = allocated_bytes();
        self.peak.store(now, Ordering::Relaxed);
        self.phases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((name.to_string(), now));
        now
    }

    /// "phase peak MiB, ..." for a log line.
    pub fn summary(&self) -> String {
        self.phases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(n, b)| format!("{n} {:.0} MiB", mib(*b)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Drop for PeakSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Build every circuit's Metal pipeline states once per process: rv32im (with the zkp kernels),
/// recursion, keccak (through its binary archive, K5) and the Groth16 prover, each on its own thread
/// so the compiler service builds them in parallel. None of them takes the GPU lock for long, and
/// each is process-wide, so later proofs find them built. Returns (and logs) how long each took: tens
/// of seconds to minutes cold (first run of a newly built binary), well under a second warm.
pub fn warm_up_pipelines() -> &'static str {
    static DONE: OnceLock<String> = OnceLock::new();
    DONE.get_or_init(|| {
        let started = Instant::now();
        let timed = |f: fn()| {
            move || {
                let t = Instant::now();
                f();
                t.elapsed()
            }
        };
        let (rv32im, recursion, keccak, groth16) = std::thread::scope(|s| {
            let rv32im = s.spawn(timed(risc0_circuit_rv32im::prove::metal_warmup));
            let recursion = s.spawn(timed(risc0_circuit_recursion::prove::metal_warmup));
            let keccak = s.spawn(timed(risc0_circuit_keccak::prove::metal_warmup));
            let groth16 = s.spawn(|| {
                let t = Instant::now();
                if let Err(e) = risc0_groth16_sys::metal_warmup() {
                    tracing::warn!("Groth16 Metal warmup failed: {e:#}");
                }
                t.elapsed()
            });
            let get = |h: std::thread::ScopedJoinHandle<'_, Duration>| h.join().unwrap_or_default();
            (get(rv32im), get(recursion), get(keccak), get(groth16))
        });
        let total = started.elapsed();
        let cold = total > Duration::from_secs(10);
        let summary = format!(
            "built the Metal pipelines in {:.1} s ({}): rv32im+zkp {:.1} s, recursion {:.1} s, \
             keccak {:.1} s, groth16 {:.1} s",
            total.as_secs_f64(),
            if cold { "cold" } else { "warm" },
            rv32im.as_secs_f64(),
            recursion.as_secs_f64(),
            keccak.as_secs_f64(),
            groth16.as_secs_f64(),
        );
        tracing::info!("{summary}");
        summary
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn po2_follows_the_working_set_limit() {
        assert_eq!(job_po2_for_limit(4 * GIB), 17);
        assert_eq!(job_po2_for_limit(8 * GIB), 18);
        // A 16 GB Mac: ~10.7 GB recommended, 8 GiB host figure.
        assert_eq!(job_po2_for_limit(10_700_000_000), 18);
        assert_eq!(job_po2_for_limit(16 * GIB), 19);
        // The 36 GB dev machine: min(30.15 GB, 28 GiB).
        assert_eq!(job_po2_for_limit(28 * GIB), 20);
        assert_eq!(job_po2_for_limit(180 * GIB), 20);
    }

    #[test]
    fn the_groth16_cache_is_kept_on_the_high_end_only() {
        assert!(!keep_groth16_cache(8 * GIB, 18));
        assert!(!keep_groth16_cache(16 * GIB, 19));
        // The 36 GB dev machine (28.1 GiB) releases it; a 48 GB Mac (~36 GiB) keeps it.
        assert!(!keep_groth16_cache(28 * GIB, 20));
        assert!(keep_groth16_cache(36 * GIB, 20));
    }

    #[test]
    fn this_mac_is_supported() {
        let host = support()
            .as_ref()
            .expect("the dev machine is an Apple Silicon Mac");
        assert!(host.name.starts_with("Apple"));
        assert!(working_set_limit().unwrap() <= host.recommended_working_set);
    }
}
