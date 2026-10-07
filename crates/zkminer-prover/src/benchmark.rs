//! Benchmarking for zkVM proving performance.
//!
//! Provides 6 diverse benchmark programs with a blended **zkOP/s** metric
//! normalized so that an AMD Threadripper 3970X baseline = 100,000 zkOP/s.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Descriptor for a benchmark program.
#[derive(Debug, Clone)]
pub struct BenchmarkProgram {
    pub name: &'static str,
    pub description: &'static str,
    /// Uses zkVM precompile acceleration (SHA-256, ECDSA).
    pub precompile: bool,
    /// Representative cycle count for this workload.
    pub simulated_cycles: u64,
    /// Weight in the zkOP/s blend (all weights sum to 1.0).
    pub weight: f64,
    /// Reference throughput (cycles/sec) on the 3970X baseline machine.
    pub reference_throughput: f64,
}

/// The 6 canonical benchmark programs with their reference calibration constants.
///
/// Reference throughputs are calibrated so that the AMD Threadripper 3970X
/// scores approximately 100,000 zkOP/s.  These are placeholder values that
/// should be replaced after running on the actual reference hardware.
///
/// Weight distribution:
///   40% pure compute (fibonacci 0.10, chacha-mix 0.20, bigint-mul 0.10)
///   45% precompile   (sha256-chain 0.20, ecdsa-verify 0.25)
///   15% mixed        (memory-merkle 0.15)
pub const BENCHMARK_PROGRAMS: [BenchmarkProgram; 6] = [
    BenchmarkProgram {
        name: "fibonacci",
        description: "Tight integer loop with wrapping arithmetic",
        precompile: false,
        simulated_cycles: 500_000,
        weight: 0.10,
        // Calibrated on AMD Threadripper 3970X (release mode)
        reference_throughput: 5_100_000_000.0,
    },
    BenchmarkProgram {
        name: "sha256-chain",
        description: "Sequential SHA-256 hashing (precompile-accelerated)",
        precompile: true,
        simulated_cycles: 2_000_000,
        weight: 0.20,
        reference_throughput: 825_000_000.0,
    },
    BenchmarkProgram {
        name: "ecdsa-verify",
        description: "Elliptic curve signature verification (precompile-accelerated)",
        precompile: true,
        simulated_cycles: 5_000_000,
        weight: 0.25,
        reference_throughput: 824_000_000.0,
    },
    BenchmarkProgram {
        name: "bigint-mul",
        description: "4096-bit integer schoolbook multiplication",
        precompile: false,
        simulated_cycles: 1_000_000,
        weight: 0.10,
        reference_throughput: 255_000_000.0,
    },
    BenchmarkProgram {
        name: "memory-merkle",
        description: "Build 1024-leaf Merkle tree with repeated hashing",
        precompile: true, // Uses sha2 crate which triggers SHA-256 precompile
        simulated_cycles: 3_000_000,
        weight: 0.15,
        reference_throughput: 545_000_000.0,
    },
    BenchmarkProgram {
        name: "chacha-mix",
        description: "Pure ARX computation (Add-Rotate-XOR), no precompiles",
        precompile: false,
        simulated_cycles: 34_000_000,
        weight: 0.20,
        reference_throughput: 340_000_000.0,
    },
];

/// Single benchmark result (per-program).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchmarkResult {
    pub program_name: String,
    /// Which prover backend produced this result: "risc0", "sp1", "openvm", or "simulated".
    pub prover_backend: String,
    pub cycles: u64,
    pub duration: Duration,
    /// Cycles per second throughput.
    pub throughput: f64,
    /// Weight in the zkOP/s blend.
    pub weight: f64,
    /// Whether this program uses zkVM precompile acceleration.
    pub precompile: bool,
}

/// One program's proving time on one (device, backend), split at the point where the cost stops
/// depending on the program.
///
/// `stark_secs` is everything up to one constant-size STARK (execution, the core/segment proofs, and
/// the recursion that folds them) and scales with cycles. `wrap_secs` turns that STARK into the
/// Groth16 proof submitted on chain; it proves a fixed circuit with a fixed key, so it does not.
/// Keeping them apart is what lets a time estimate be `wrap + cycles / rate` instead of a single
/// rate that is wrong in opposite directions for small and large jobs.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProgramStage {
    pub program_name: String,
    pub cycles: u64,
    pub stark_secs: f64,
    /// `None` when the wrap was not measured for this program. SP1 measures it on one program per
    /// slot; see `BenchmarkEntry::wrap_secs`.
    pub wrap_secs: Option<f64>,
}

/// Measured throughput for one (device, prover-backend) combination.
///
/// A device is "cpu", "gpu0", "gpu1", etc.  Each device may support multiple
/// backends (risc0, sp1, openvm) at different throughput levels.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceBenchmark {
    /// Device identifier: `"cpu"`, `"gpu0"`, `"gpu1"`, etc.
    pub device_id: String,
    /// Human-readable label, e.g. `"AMD Ryzen 9 7950X"` or `"GPU0 RX 7900 XTX"`.
    pub device_label: String,
    /// Prover backend: `"risc0"`, `"sp1"`, `"openvm"`.
    pub prover_backend: String,
    /// Average throughput in cycles/sec for this (device, backend) pair.
    pub throughput: f64,
    /// Device power draw in watts during proving.
    pub power_watts: f64,
    /// Optimal continuation size (log2 of rows per segment).
    #[serde(default = "default_po2")]
    pub optimal_po2: u8,
    /// Estimated memory usage at optimal po2 (bytes).
    #[serde(default)]
    pub memory_usage_bytes: u64,
    /// Maximum feasible po2 given device memory.
    #[serde(default = "default_po2")]
    pub max_feasible_po2: u8,
    /// Per-program throughputs for this device (cycles/sec).
    /// Keys are canonical program names. Enables per-workload-type predictions.
    #[serde(default)]
    pub program_throughputs: std::collections::HashMap<String, f64>,
    /// Measured po2 calibration samples. Empty = uncalibrated (use heuristic model).
    /// Only meaningful for risc0 backend; SP1/OpenVM ignore po2.
    #[serde(default)]
    pub po2_samples: Vec<Po2Sample>,
    /// Per-program STARK and Groth16-wrap times, for rows measured by a worker that reports them
    /// (protocol v4 and later). Empty for estimated and CPU rows, and for caches written before it.
    ///
    /// MUST stay `#[serde(default)]`, for the reason given on `pci_bus_id`: a required field makes
    /// every existing benchmarks.json fail to load, and the loader discards it as corrupt.
    #[serde(default)]
    pub program_stages: Vec<ProgramStage>,
    /// Canonical PCI bus id of the card this row was measured on, e.g.
    /// `0000:06:1b.0`. Empty for CPU rows and for caches written before this
    /// field existed.
    ///
    /// This is the identity the TUI joins on to line a row up with a physical
    /// card. `device_id` is an ordinal in the prover's own per-vendor index
    /// space and means nothing to a consumer that enumerated hardware
    /// differently -- which is exactly how an NVIDIA card's throughput ended
    /// up displayed against an AMD card.
    ///
    /// MUST stay `#[serde(default)]`: a required field makes every existing
    /// benchmarks.json fail to deserialize, and the loader treats that as a
    /// corrupt cache and discards hours of measured po2 calibration.
    #[serde(default)]
    pub pci_bus_id: String,
    /// Peak HOST memory a proof on this device/backend reached when measured, in bytes.
    ///
    /// Admission control's input. `#[serde(default)]` so a cache written before this field existed
    /// still loads — it then reads `None`, and the admission gate falls back to a conservative
    /// estimate rather than treating an unmeasured backend as free.
    #[serde(default)]
    pub host_peak_bytes: Option<u64>,
}

fn default_po2() -> u8 {
    18
}

/// A single measured throughput data point at a specific po2 value.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Po2Sample {
    pub po2: u8,
    pub total_cycles: u64,
    pub segment_count: u32,
    pub duration_secs: f64,
    /// Derived: total_cycles / duration_secs.
    pub throughput: f64,
}

/// Performance profile for po2 selection, built from calibration data.
/// Enables per-job dynamic po2 selection to minimize total proving time.
#[derive(Debug, Clone)]
pub struct Po2Profile {
    pub samples: Vec<Po2Sample>,
    pub max_po2: u8,
    pub backend: String,
}

impl Po2Profile {
    /// Build from a DeviceBenchmark's calibration data.
    pub fn from_device_benchmark(db: &DeviceBenchmark) -> Option<Self> {
        if db.po2_samples.is_empty() || db.prover_backend != "risc0" {
            return None;
        }
        Some(Self {
            samples: db.po2_samples.clone(),
            max_po2: db.max_feasible_po2,
            backend: db.prover_backend.clone(),
        })
    }

    /// Interpolate throughput at a given po2 from measured samples.
    /// Linearly interpolates between the two nearest measured points.
    /// Clamps to the nearest measured value outside the measured range.
    pub fn throughput_at_po2(&self, po2: u8) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let mut sorted: Vec<&Po2Sample> = self.samples.iter().collect();
        sorted.sort_by_key(|s| s.po2);

        // Below lowest measured po2
        if po2 <= sorted[0].po2 {
            return sorted[0].throughput;
        }
        // Above highest measured po2
        if po2 >= sorted[sorted.len() - 1].po2 {
            return sorted[sorted.len() - 1].throughput;
        }
        // Interpolate between bracketing samples
        for w in sorted.windows(2) {
            if po2 >= w[0].po2 && po2 <= w[1].po2 {
                let range = (w[1].po2 - w[0].po2) as f64;
                if range == 0.0 {
                    return w[0].throughput;
                }
                let frac = (po2 - w[0].po2) as f64 / range;
                return w[0].throughput + frac * (w[1].throughput - w[0].throughput);
            }
        }
        sorted[0].throughput
    }

    /// Estimate total proving time for a job at a given po2.
    ///
    /// Models: `total = segments × segment_time + overhead_per_segment × segments`
    /// where overhead_per_segment is derived from calibration data.
    pub fn total_time_at_po2(&self, cycles: u64, po2: u8) -> f64 {
        if cycles == 0 {
            return 0.0;
        }
        let throughput = self.throughput_at_po2(po2);
        if throughput <= 0.0 {
            return f64::MAX;
        }
        // Simple model: total_time = cycles / throughput_at_po2
        // The measured throughput already includes lift/join overhead baked in
        // because calibration wall-clock time includes all phases.
        cycles as f64 / throughput
    }

    /// Like [`optimal_po2_for_job`], but returns `None` unless the winner is decisive.
    ///
    /// `optimal_po2_for_job` is a plain argmax over measured throughput, so when two
    /// segment sizes are within measurement noise it still returns one of them — and
    /// forcing that choice on the prover can be WORSE than letting the SDK decide.
    /// Measured on this hardware: the 4090's sweep put po2=19 ahead of po2=20 by
    /// **0.04%** (2.0179M vs 2.0170M c/s), and forcing po2=19 on a real 1.05M-cycle job
    /// then ran **5% slower** than the SDK default (3.02s vs 2.88s). On the 5090 the
    /// calibrated pick was merely identical to the default (2.53s vs 2.53s).
    ///
    /// So an override is only worth making when the evidence is unambiguous. Below the
    /// margin this yields `None`, `resolve_po2` falls through, and the SDK keeps
    /// choosing — which is also what protects against adopting a noisy sweep on
    /// hardware where po2 simply does not matter much.
    pub fn confident_po2_for_job(&self, cycles: u64) -> Option<u8> {
        /// Minimum relative throughput advantage over the runner-up before the SDK's
        /// own choice is overridden. Well above the ~1% run-to-run spread seen here.
        const PO2_DECISION_MARGIN: f64 = 0.05;

        if cycles == 0 || self.samples.is_empty() {
            return None;
        }
        let mut scored: Vec<(u8, f64)> = (PO2_MIN..=self.max_po2.min(PO2_MAX))
            .map(|p| (p, self.throughput_at_po2(p)))
            .filter(|(_, tp)| *tp > 0.0)
            .collect();
        if scored.len() < 2 {
            return None;
        }
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        let (best_po2, best_tp) = scored[0];
        let (_, runner_up_tp) = scored[1];
        if runner_up_tp <= 0.0 {
            return None;
        }
        if (best_tp - runner_up_tp) / runner_up_tp >= PO2_DECISION_MARGIN {
            Some(best_po2)
        } else {
            None
        }
    }

    /// Find the po2 that minimizes total proving time for a job.
    pub fn optimal_po2_for_job(&self, cycles: u64) -> u8 {
        let mut best_po2 = PO2_MIN;
        let mut best_time = f64::MAX;

        for po2 in PO2_MIN..=self.max_po2.min(PO2_MAX) {
            let time = self.total_time_at_po2(cycles, po2);
            if time < best_time {
                best_time = time;
                best_po2 = po2;
            }
        }
        best_po2
    }
}

impl DeviceBenchmark {
    /// This device's STARK proving rate weighted by cycles: total cycles over total STARK seconds
    /// across the programs in `program_stages`, or `None` without any.
    ///
    /// Not `throughput`, which is the unweighted mean of per-program RATES and is what the planner
    /// reads. A 33k-cycle program still carries fixed per-proof STARK overhead, so its rate is tiny
    /// (67.8K c/s against 1.3-1.4M for every real program on the 4090, measured 2026-10-06) and an
    /// unweighted mean lets it drag the device figure down by ~20%. For the `wrap + cycles / rate`
    /// model the rate that matters is the one large jobs see, which is what weighting by cycles gives.
    pub fn stark_rate(&self) -> Option<f64> {
        let cycles: u64 = self.program_stages.iter().map(|p| p.cycles).sum();
        let secs: f64 = self.program_stages.iter().map(|p| p.stark_secs).sum();
        (cycles > 0 && secs > 0.0).then(|| cycles as f64 / secs)
    }

    /// This device's steady-state Groth16 wrap time: the MEDIAN over the programs it was measured on,
    /// or `None` if it was measured on none.
    ///
    /// Not the mean. The measurements are not all repeats of one quantity: the FIRST wrap in a worker
    /// process is ~0.9 s slower than every later one, mostly the first read of the 3.45 GB proving key.
    /// Measured on the 4090 on 2026-10-06: 2.96 s for the first, then 2.02 / 2.00 / 2.01 / 2.02 / 2.02 s.
    /// A long-lived worker pays the warm figure on every proof and the cold one once, so the median is
    /// the per-proof cost and the mean overstates it by a one-off amortised over however many programs
    /// the suite happened to run.
    pub fn wrap_secs(&self) -> Option<f64> {
        let mut measured: Vec<f64> = self
            .program_stages
            .iter()
            .filter_map(|p| p.wrap_secs)
            .filter(|w| w.is_finite())
            .collect();
        if measured.is_empty() {
            return None;
        }
        measured.sort_by(f64::total_cmp);
        let mid = measured.len() / 2;
        Some(if measured.len() % 2 == 1 {
            measured[mid]
        } else {
            (measured[mid - 1] + measured[mid]) / 2.0
        })
    }

    /// Coefficient of variation across per-program throughputs.
    /// Higher values indicate the device has uneven performance across
    /// workload types, warranting a larger safety margin.
    pub fn throughput_cov(&self) -> f64 {
        let values: Vec<f64> = self.program_throughputs.values().copied().collect();
        if values.len() < 2 {
            return 0.0;
        }
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        if mean <= 0.0 {
            return 0.0;
        }
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
        variance.sqrt() / mean
    }
}

/// Aggregate benchmark results.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BenchmarkSuite {
    /// Per-program benchmark results (used for zkOP/s scoring).
    pub results: Vec<BenchmarkResult>,
    /// Per-(device, backend) throughput measurements.
    #[serde(default)]
    pub device_benchmarks: Vec<DeviceBenchmark>,
    /// Worst measured HOST-memory peak per backend, in bytes.
    ///
    /// Kept OUTSIDE `device_benchmarks` deliberately, because routing it through the GPU rows made it
    /// unobtainable for the backend that needs it most. `build_gpu_device_benchmarks_from_workers`
    /// skips any slot whose `gpu_tag` is `generic`, and SP1 is permanently `generic`: it ships as
    /// `zkminer-prove-sp1` with no `-cuda` suffix, and `discovery.rs` records that re-tagging it was
    /// tried and reverted because it breaks SP1 proving outright. So the SP1 peak WAS measured, from
    /// the right cgroup while the worker was alive, and then discarded one function later.
    /// `expected_host_peak_bytes("sp1")` therefore returned the 18 GiB blind default for the life of
    /// the install — which on a 28 GiB box means one SP1 proof at a time, forever, and no SP1
    /// claiming at all once ~5 GiB is used elsewhere. No benchmark, calibration or TUI action could
    /// fix it, and the only test covering a measured SP1 budget built a row the pipeline cannot
    /// emit, so the dead end was invisible to the suite.
    ///
    /// Host memory is a property of the WORKER PROCESS, not of the card, so this is also its more
    /// honest home. `#[serde(default)]` so an older cache loads with an empty map and falls back
    /// exactly as an unmeasured suite does.
    #[serde(default)]
    pub host_peaks: std::collections::HashMap<String, u64>,
    pub cpu_info: String,
    pub timestamp: String,
    /// Blended zkOP/s score (3970X baseline = 100,000).
    pub zkops: f64,
    /// Precompile sub-score (sha256-chain + ecdsa-verify + memory-merkle), normalized.
    #[serde(default)]
    pub precompile_score: f64,
    /// Pure compute sub-score (fibonacci + bigint-mul), normalized.
    #[serde(default)]
    pub compute_score: f64,
    /// Average CPU package power draw during benchmarks (watts), via RAPL.
    #[serde(default)]
    pub cpu_power_watts: Option<f64>,
    /// TOTAL GPU power during benchmarks (watts): each proving card's PEAK over the window,
    /// summed. AMD via hwmon, NVIDIA via nvidia-smi. `None` means no proving card could be
    /// measured.
    ///
    /// Display only — the cost model reads `device_benchmarks[i].power_watts`, which carries each
    /// card's own figure (or `FALLBACK_GPU_WATTS` when unmeasured). The peaks need not be
    /// simultaneous, so this is an upper bound rather than an instantaneous draw.
    #[serde(default)]
    pub gpu_power_watts: Option<f64>,
}

/// The three supported prover backends.
pub const PROVER_BACKENDS: [&str; 3] = ["risc0", "sp1", "openvm"];

/// Per-backend performance profile. Consolidates CPU factors, GPU acceleration,
/// and memory multipliers into a single source of truth.
struct BackendProfile {
    name: &'static str,
    /// CPU throughput relative to risc0 baseline.
    cpu_factor: f64,
    /// GPU acceleration relative to same backend on CPU. None = no GPU support.
    gpu_acceleration: Option<f64>,
    /// Memory usage multiplier relative to risc0 baseline.
    memory_multiplier: f64,
}

const BACKEND_PROFILES: [BackendProfile; 3] = [
    BackendProfile {
        name: "risc0",
        cpu_factor: 1.00,
        gpu_acceleration: Some(12.0),
        memory_multiplier: 1.0,
    },
    BackendProfile {
        name: "sp1",
        cpu_factor: 0.85,
        gpu_acceleration: Some(8.0),
        memory_multiplier: 1.1,
    },
    BackendProfile {
        name: "openvm",
        cpu_factor: 0.70,
        gpu_acceleration: None,
        memory_multiplier: 1.2,
    },
];

fn backend_profile(name: &str) -> Option<&'static BackendProfile> {
    BACKEND_PROFILES.iter().find(|p| p.name == name)
}

/// Valid po2 range for continuation segments.
pub const PO2_MIN: u8 = 18;
pub const PO2_MAX: u8 = 24;

/// Estimate memory usage for a given po2, backend, and device type.
///
/// Base memory at po2=18: CPU 512 MB, GPU 256 MB.
/// Doubles each po2 step. Backend multiplier applied on top.
pub fn estimate_po2_memory(po2: u8, backend: &str, is_gpu: bool) -> u64 {
    let base: u64 = if is_gpu {
        256 * 1024 * 1024 // 256 MB
    } else {
        512 * 1024 * 1024 // 512 MB
    };
    let backend_mult = backend_profile(backend)
        .map(|p| p.memory_multiplier)
        .unwrap_or(1.0);
    let shift = po2.saturating_sub(PO2_MIN) as u32;
    let scaled = base.checked_shl(shift).unwrap_or(u64::MAX);
    (scaled as f64 * backend_mult) as u64
}

/// Throughput scaling factor for a given po2.
///
/// ~15% improvement per po2 step above 18, with diminishing returns above po2=22.
pub fn po2_throughput_factor(po2: u8) -> f64 {
    let steps = (po2.saturating_sub(PO2_MIN)) as f64;
    let penalty_steps = (po2 as i32 - 22).max(0) as f64;
    1.0 + 0.15 * steps - 0.02 * penalty_steps * penalty_steps
}

/// Sweep po2 from 18..=24 and find the largest that fits in the memory budget.
///
/// Returns `(optimal_po2, memory_at_optimal)`.
pub fn find_optimal_po2(device_memory_bytes: u64, backend: &str, is_gpu: bool) -> (u8, u64) {
    let budget = (device_memory_bytes as f64 * 0.90) as u64;
    let mut best_po2 = PO2_MIN;
    let mut best_mem = estimate_po2_memory(PO2_MIN, backend, is_gpu);

    for po2 in PO2_MIN..=PO2_MAX {
        let mem = estimate_po2_memory(po2, backend, is_gpu);
        if mem <= budget {
            best_po2 = po2;
            best_mem = mem;
        } else {
            break;
        }
    }

    (best_po2, best_mem)
}

impl BenchmarkSuite {
    /// Returns true if all benchmark results are from simulated workloads
    /// (no real prover backend was available). Simulated throughput numbers
    /// are not reliable for profitability decisions and should not be used
    /// to auto-claim jobs.
    pub fn is_simulated(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.prover_backend == "simulated")
    }

    /// Average throughput in cycles/second across canonical benchmark programs.
    ///
    /// Excludes programs with weight 0.0 to prevent non-scoring programs
    /// from diluting the average used for timing predictions.
    pub fn average_throughput(&self) -> f64 {
        let canonical: Vec<_> = self.results.iter().filter(|r| r.weight > 0.0).collect();
        if canonical.is_empty() {
            return 0.0;
        }
        let total: f64 = canonical.iter().map(|r| r.throughput).sum();
        total / canonical.len() as f64
    }

    /// Look up throughput for a specific (device, backend) pair.
    ///
    /// Returns `None` if no benchmark exists for that combination.
    pub fn throughput_for(&self, device_id: &str, backend: &str) -> Option<f64> {
        self.device_benchmarks
            .iter()
            .find(|d| d.device_id == device_id && d.prover_backend == backend)
            .map(|d| d.throughput)
    }

    /// Get all device benchmarks that support a given prover backend.
    /// What a proof on `backend` is expected to peak at in HOST memory, in bytes.
    ///
    /// The largest measured figure across this backend's devices, because admission must budget for
    /// the worst card rather than the average. Falls back to `unmeasured_peak_for` when
    /// nothing has been measured — an unmeasured backend must look expensive, since assuming it is
    /// free is what permits the unlimited concurrency that froze this host.
    pub fn expected_host_peak_bytes(&self, backend: &str) -> u64 {
        let host_total = crate::memory::mem_total_bytes().unwrap_or(u64::MAX);
        // The backend-keyed map FIRST. It is the only source that works for a `generic`-tagged
        // backend, i.e. for SP1 — see `host_peaks`. The device rows remain as a fallback so a cache
        // written before this field existed still yields what it measured.
        if let Some(&measured) = self.host_peaks.get(backend) {
            if measured > 0 {
                return crate::memory::budget_from_measurement(measured, backend, host_total);
            }
        }
        let rows: Vec<&DeviceBenchmark> = self
            .device_benchmarks
            .iter()
            .filter(|d| d.prover_backend == backend && d.device_id != CPU_DEVICE_ID)
            .collect();
        if rows.is_empty() {
            return crate::memory::admissible_unmeasured_peak_for(backend, host_total);
        }
        // If ANY device for this backend is unmeasured, fall back for the whole backend. Taking the
        // max of only the measured rows silently charged an unmeasured card the measured card's
        // figure — and on a mixed rig the unmeasured one is as likely as not the expensive one. The
        // doc says "budget for the worst card"; an unmeasured card is not budgeted at all.
        if rows.iter().any(|d| d.host_peak_bytes.is_none()) {
            return crate::memory::admissible_unmeasured_peak_for(backend, host_total);
        }
        let worst = rows
            .iter()
            .filter_map(|d| d.host_peak_bytes)
            .max()
            .unwrap_or(0);
        // A raw measurement is a LOWER bound on the production cost — see
        // `MEASUREMENT_SAFETY_FACTOR`. Using it unscaled is worse than having no measurement,
        // because it replaces the conservative default.
        //
        // The host total is passed so the budget can be clamped to something the machine can
        // actually admit; an unreadable `/proc/meminfo` yields `u64::MAX`, which disables only the
        // clamp and leaves the scaling and the floor intact.
        crate::memory::budget_from_measurement(worst, backend, host_total)
    }

    pub fn devices_for_backend(&self, backend: &str) -> Vec<&DeviceBenchmark> {
        self.device_benchmarks
            .iter()
            .filter(|d| d.prover_backend == backend)
            .collect()
    }

    /// Get all backends a specific device supports.
    pub fn backends_for_device(&self, device_id: &str) -> Vec<&str> {
        self.device_benchmarks
            .iter()
            .filter(|d| d.device_id == device_id)
            .map(|d| d.prover_backend.as_str())
            .collect()
    }
}

/// Minimal GPU description for generating device benchmarks.
pub struct GpuDesc {
    pub index: u32,
    pub name: String,
    pub vram_bytes: u64,
    pub power_watts: f64,
}

/// Add GPU device benchmarks to an existing suite.
///
/// Call this after hardware detection to populate GPU entries.  The GPU
/// throughput is estimated from the CPU baseline throughput scaled by
/// per-backend GPU acceleration factors and a VRAM capacity adjustment.
pub fn add_gpu_device_benchmarks(suite: &mut BenchmarkSuite, gpus: &[GpuDesc]) {
    let cpu_base = suite.average_throughput();
    if cpu_base <= 0.0 {
        return;
    }

    for gpu in gpus {
        let device_id = format!("gpu{}", gpu.index);
        let device_label = format!("GPU{} {}", gpu.index, gpu.name);

        let vram_gb = gpu.vram_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        let vram_factor = if vram_gb >= 8.0 {
            1.0 + (vram_gb / 8.0).log2() * 0.3
        } else {
            (vram_gb / 8.0).max(0.5)
        };

        for profile in &BACKEND_PROFILES {
            let Some(accel) = profile.gpu_acceleration else {
                continue;
            };

            let (optimal_po2, memory_usage_bytes) =
                find_optimal_po2(gpu.vram_bytes, profile.name, true);
            // Only apply po2 throughput factor for risc0 — SP1/OpenVM have their
            // own segmentation that ignores the risc0 po2 parameter.
            let po2_factor = if profile.name == "risc0" {
                po2_throughput_factor(optimal_po2)
            } else {
                1.0
            };
            let throughput = cpu_base * profile.cpu_factor * accel * vram_factor * po2_factor;

            suite.device_benchmarks.push(DeviceBenchmark {
                program_stages: Vec::new(),
                device_id: device_id.clone(),
                device_label: device_label.clone(),
                prover_backend: profile.name.to_string(),
                throughput,
                power_watts: gpu.power_watts,
                optimal_po2,
                memory_usage_bytes,
                max_feasible_po2: optimal_po2,
                program_throughputs: std::collections::HashMap::new(),
                pci_bus_id: String::new(),
                po2_samples: Vec::new(),
                // An ESTIMATED row (no worker ran), so there is nothing measured to record.
                host_peak_bytes: None,
            });
        }
    }
}

/// Compute the blended zkOP/s score from benchmark results.
///
/// Formula: `Σ(weight_i × throughput_i / reference_throughput_i) × 100,000`
/// with weights renormalized over the programs that have results.
///
/// Returns 0.0 if no programs have results.
pub fn compute_zkops(results: &[BenchmarkResult]) -> f64 {
    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;

    for program in &BENCHMARK_PROGRAMS {
        let result = results
            .iter()
            .find(|r| r.program_name.starts_with(program.name));
        let Some(result) = result else {
            continue; // Skip missing programs, renormalize over available ones
        };
        if program.reference_throughput <= 0.0 || result.throughput <= 0.0 {
            continue;
        }
        let ratio = result.throughput / program.reference_throughput;
        weighted_sum += program.weight * ratio;
        total_weight += program.weight;
    }

    if total_weight <= 0.0 {
        return 0.0;
    }

    // Renormalize: scale as if available weights summed to 1.0
    (weighted_sum / total_weight) * 100_000.0
}

/// Compute per-category sub-scores (precompile, compute).
///
/// Each sub-score is the normalized ratio averaged across programs in that category.
/// Precompile: programs with `precompile=true` (sha256-chain, ecdsa-verify, memory-merkle).
/// Compute: programs with `precompile=false` (fibonacci, bigint-mul, chacha-mix).
///
/// Returns `(precompile_score, compute_score)` as multipliers (1.0 = baseline).
pub fn compute_category_scores(results: &[BenchmarkResult]) -> (f64, f64) {
    let mut precompile_sum = 0.0;
    let mut precompile_count = 0;
    let mut compute_sum = 0.0;
    let mut compute_count = 0;

    for program in &BENCHMARK_PROGRAMS {
        let result = results
            .iter()
            .find(|r| r.program_name.starts_with(program.name));
        let Some(result) = result else { continue };
        if program.reference_throughput <= 0.0 {
            continue;
        }
        let ratio = result.throughput / program.reference_throughput;
        if program.precompile {
            precompile_sum += ratio;
            precompile_count += 1;
        } else {
            compute_sum += ratio;
            compute_count += 1;
        }
    }

    let precompile = if precompile_count > 0 {
        precompile_sum / precompile_count as f64
    } else {
        0.0
    };
    let compute = if compute_count > 0 {
        compute_sum / compute_count as f64
    } else {
        0.0
    };
    (precompile, compute)
}

/// Get CPU info string.
pub fn get_cpu_info() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in info.lines() {
                if line.starts_with("model name") {
                    if let Some(name) = line.split(':').nth(1) {
                        return name.trim().to_string();
                    }
                }
            }
        }
    }
    "Unknown CPU".to_string()
}

/// Get number of available CPU cores.
pub fn get_cpu_cores() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
}

/// Read the CPU package energy counter (microjoules).
///
/// Tries in order:
/// 1. Linux powercap RAPL sysfs (`/sys/class/powercap/{intel-rapl,amd_rapl}:0/energy_uj`)
/// 2. Direct MSR read (`/dev/cpu/0/msr`, AMD MSR `0xC001_029B` / Intel MSR `0x611`)
///
/// Returns `None` if all methods fail (no permissions, no kernel support, etc.).
fn read_rapl_energy_uj() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        // Method 1: powercap sysfs
        for prefix in &["intel-rapl", "amd_rapl"] {
            let path = format!("/sys/class/powercap/{}:0/energy_uj", prefix);
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(val) = contents.trim().parse::<u64>() {
                    return Some(val);
                }
            }
        }

        // Method 2: direct MSR read
        if let Some(uj) = read_rapl_msr_energy_uj() {
            return Some(uj);
        }
    }
    None
}

/// Read CPU package energy via the MSR device.
///
/// AMD Zen: RAPL_PWR_UNIT = 0xC001_0299, PKG_ENERGY_STAT = 0xC001_029B
/// Intel:   MSR_RAPL_POWER_UNIT = 0x606, MSR_PKG_ENERGY_STATUS = 0x611
#[cfg(target_os = "linux")]
fn read_rapl_msr_energy_uj() -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};

    let mut f = std::fs::File::open("/dev/cpu/0/msr").ok()?;

    // Try AMD MSRs first, then Intel
    let configs: &[(u64, u64)] = &[
        (0xC001_0299, 0xC001_029B), // AMD: unit, pkg_energy
        (0x606, 0x611),             // Intel: unit, pkg_energy
    ];

    for &(unit_msr, energy_msr) in configs {
        let mut buf = [0u8; 8];

        if f.seek(SeekFrom::Start(unit_msr)).is_err() {
            continue;
        }
        if f.read_exact(&mut buf).is_err() {
            continue;
        }
        let unit_raw = u64::from_le_bytes(buf);
        let energy_unit_bits = (unit_raw >> 8) & 0x1F;
        if energy_unit_bits == 0 || energy_unit_bits > 31 {
            continue;
        }

        if f.seek(SeekFrom::Start(energy_msr)).is_err() {
            continue;
        }
        if f.read_exact(&mut buf).is_err() {
            continue;
        }
        let energy_raw = u64::from_le_bytes(buf);

        // Convert to microjoules: energy_raw * (1 / 2^unit) * 1_000_000
        // = energy_raw * 1_000_000 / 2^unit
        let uj = energy_raw
            .checked_mul(1_000_000)
            .map(|v| v >> energy_unit_bits)?;
        return Some(uj);
    }

    None
}

/// The `device_id` of the CPU row. One constant, because the cost model filters on it: a
/// rename to "cpu0" would otherwise fold the CPU's draw into the GPU mean, silently.
pub const CPU_DEVICE_ID: &str = "cpu";

/// A short, STABLE tag for a failed query, for the hardware fingerprint.
///
/// Stable matters: the fingerprint is compared for equality across runs, so this must not carry a
/// pid, an errno text or anything else that varies — two failures of the same kind should compare
/// equal, and neither should equal the GPU-less marker.
fn short_outcome(o: &zkminer_prover_protocol::proc::Outcome) -> &'static str {
    use zkminer_prover_protocol::proc::Outcome;
    match o {
        Outcome::TimedOut { .. } => "query-timed-out",
        Outcome::Unsettled(_) => "query-unsettled",
        Outcome::SpawnFailed {
            transient: true, ..
        } => "query-spawn-transient",
        Outcome::SpawnFailed { .. } => "query-spawn-failed",
        Outcome::Ran { .. } => "query-nonzero-exit",
    }
}

/// Budget for the fingerprint query. Longer than the sampler's, because a slow answer here only
/// delays startup, whereas a missing one silently invalidates the benchmark cache and forces a
/// re-benchmark costing real GPU time.
const NVIDIA_SMI_FINGERPRINT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long `nvidia-smi` may take before we treat it as having no answer.
///
/// Short on purpose: the power sampler calls it repeatedly during a benchmark, and a missing
/// sample costs one data point while a hung one costs the whole run.
const NVIDIA_SMI_TIMEOUT: Duration = Duration::from_secs(2);

/// Fallback per-card draw when nothing on the box will report one.
///
/// Also the figure `zkminer_strategy::cost_model::DEFAULT_GPU_WATTS` mirrors; the two must
/// stay equal or the cost model and the stored device rows disagree about the same card.
pub const FALLBACK_GPU_WATTS: f64 = 300.0;

/// Average CPU package power over a window, from the RAPL energy counters.
///
/// `None` when RAPL is unreadable (no `/dev/cpu/*/msr`, no accessible powercap tree) or the
/// window is degenerate. Callers fall back to `DEFAULT_CPU_WATTS`.
fn cpu_power_over(before: Option<u64>, window: Duration) -> Option<f64> {
    let after = read_rapl_energy_uj()?;
    let before = before?;
    if window.as_secs_f64() <= 0.0 {
        return None;
    }
    let watts = after.saturating_sub(before) as f64 / 1_000_000.0 / window.as_secs_f64();
    tracing::info!("CPU power: {watts:.1}W (avg over the benchmark window)");
    Some(watts)
}

/// Merge a power sample into an accumulator, keeping the LARGER reading per card.
///
/// The one place this fold lives. It was open-coded in four places — the two vendor readers,
/// the sampler thread, and (fatally) inside the sampler's own unit test, which meant the test
/// asserted a property of code written in the test file and would have passed with the
/// production fold reverted to last-sample-wins. Last-sample-wins is not a hypothetical
/// regression: it is the idle-draw bug this sampler exists to fix.
///
/// MAX rather than sum, because the inputs are repeated observations of ONE card: two hwmon
/// nodes on the same device, or successive samples over a benchmark window. Summing them
/// double-charges a card for being measured twice.
pub(crate) fn fold_peak<I>(dst: &mut BTreeMap<String, f64>, samples: I)
where
    I: IntoIterator<Item = (String, f64)>,
{
    for (bus, watts) in samples {
        let e = dst.entry(bus).or_insert(0.0);
        if watts > *e {
            *e = watts;
        }
    }
}

/// Instantaneous draw of each PROVING card, in watts, keyed by normalized PCI bus id.
///
/// Per-card rather than one total, because the two consumers want different things: a
/// device row wants its OWN card's draw (the total was being stamped onto every row, so on
/// a two-card box each row claimed the whole machine's GPU power), while the suite-level
/// figure wants the sum.
///
/// Both vendors are read:
///
/// * AMD through hwmon `power1_average`.
/// * NVIDIA through `nvidia-smi --query-gpu=power.draw`. This was missing entirely, and
///   this box is all NVIDIA — so every reading failed, every device row took the 300 W
///   fallback, and the suite recorded `gpu_power_watts: None` while two cards drew a
///   measured ~840 W between them.
///
/// `proving_bus_ids` is the set of bus ids the prover is actually using; a card outside it
/// is ignored. That filter is the whole point. This used to sum EVERY AMD card on the box
/// and stamp the total onto every device row regardless of vendor. On a machine whose only
/// AMD card sits idle while two NVIDIA cards prove, it recorded 8.5 W for cards drawing
/// ~520 W and ~270 W -- and because it "succeeded", it suppressed the fallback that would
/// have been within 2x. Reporting nothing for a card we cannot measure is strictly better
/// than reporting a confidently wrong number for it.
fn read_gpu_power_by_card(proving_bus_ids: &[String]) -> PowerSample {
    let mut out: BTreeMap<String, f64> = BTreeMap::new();
    #[cfg(target_os = "linux")]
    let probe_failed = {
        read_amd_power_by_card(proving_bus_ids, &mut out);
        !read_nvidia_power_by_card(proving_bus_ids, &mut out)
    };
    #[cfg(not(target_os = "linux"))]
    let probe_failed = {
        let _ = proving_bus_ids;
        true
    };
    PowerSample {
        per_card: out,
        probe_failed,
    }
}

/// NVIDIA per-card draw via nvidia-smi.
/// Returns false when the QUERY itself did not answer — which is the leak signal the sampler's
/// give-up cap counts. A successful query that reports no usable row for some card returns true:
/// that is a fact about the card, not a failure of the probe.
#[cfg(target_os = "linux")]
fn read_nvidia_power_by_card(proving_bus_ids: &[String], out: &mut BTreeMap<String, f64>) -> bool {
    // Bounded. `nvidia-smi` blocks in the driver after an Xid, a bus fall-off or an ECC remap,
    // and the sampler calls this every couple of seconds for the whole benchmark window. The
    // sampler runs on its own named thread, not inside `spawn_blocking` — but `finish()` joins
    // it, so an unbounded `Command::output()` here would hang the benchmark through that join.
    // Same hazard the SP1 handshake probe was fixed for; same shared runner.
    let (outcome, stdout) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        std::process::Command::new("nvidia-smi").args([
            "--query-gpu=pci.bus_id,power.draw",
            "--format=csv,noheader,nounits",
        ]),
        NVIDIA_SMI_TIMEOUT,
        64 * 1024,
    );
    if !matches!(
        outcome,
        zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
    ) {
        // Not evidence that the cards draw nothing: leave them absent and let the caller fall
        // back to `FALLBACK_GPU_WATTS`, which is wrong-but-high rather than wrong-and-free.
        return false;
    }
    // `fold_peak`, never a bare insert: the AMD reader runs first, and an overwrite would
    // silently discard its reading for the same card.
    fold_peak(out, parse_nvidia_power_csv(&stdout, proving_bus_ids));
    true
}

/// Parse `pci.bus_id, power.draw` CSV rows, keeping only proving cards.
///
/// Split out so the parsing is testable without a GPU -- including the rows nvidia-smi
/// emits for a card that cannot report power (`[N/A]`, `[Not Supported]`), which must be
/// skipped rather than parsed as 0 W. A card silently recorded at 0 W would make a proof
/// look free, which is the direction that loses money.
fn parse_nvidia_power_csv(csv: &str, proving_bus_ids: &[String]) -> Vec<(String, f64)> {
    let mut found = Vec::new();
    for line in csv.lines() {
        let mut parts = line.split(',');
        let (Some(bus_raw), Some(watts_raw)) = (parts.next(), parts.next()) else {
            continue;
        };
        // nvidia-smi prints an 8-digit domain; sysfs uses 4. Normalize so both sides of the
        // join produce the same string.
        let bus = crate::discovery::normalize_pci_bus_id(bus_raw.trim());
        if bus.is_empty() || !proving_bus_ids.contains(&bus) {
            continue;
        }
        // Tolerate a trailing unit ("341.52 W"). nvidia-smi only prints it without
        // `nounits`, but if that flag is ever dropped from the query every row would fail to
        // parse, every card would go absent, and every device row would silently take the
        // fallback — reinstating the exact bug this reader was written to remove. Nothing in
        // the argument list is testable from here, so the parser absorbs the risk.
        let watts_text = watts_raw
            .trim()
            .trim_end_matches(|c: char| c.is_alphabetic())
            .trim();
        let Ok(watts) = watts_text.parse::<f64>() else {
            continue; // "[N/A]" / "[Not Supported]"
        };
        if watts.is_finite() && watts > 0.0 {
            found.push((bus, watts));
        }
    }
    found
}

/// AMD per-card draw via hwmon.
#[cfg(target_os = "linux")]
fn read_amd_power_by_card(proving_bus_ids: &[String], out: &mut BTreeMap<String, f64>) {
    {
        for card_idx in 0..16u32 {
            let device_path = format!("/sys/class/drm/card{}/device", card_idx);

            // Check vendor — 0x1002 = AMD
            let vendor_path = format!("{device_path}/vendor");
            match std::fs::read_to_string(&vendor_path) {
                Ok(v) if v.trim() == "0x1002" => {}
                _ => continue,
            }

            // Only count a card the prover is actually using. An empty list means
            // "no GPU bus ids known", in which case counting nothing is correct:
            // a wrong power figure feeds the profitability model directly.
            let bus = crate::discovery::normalize_pci_bus_id(
                &crate::discovery::read_pci_slot_from_uevent(std::path::Path::new(&format!(
                    "{device_path}/uevent"
                )))
                .unwrap_or_default(),
            );
            if bus.is_empty() || !proving_bus_ids.contains(&bus) {
                continue;
            }

            // Find hwmon directory and read power1_average
            let hwmon_dir = format!("{device_path}/hwmon");
            if let Ok(entries) = std::fs::read_dir(&hwmon_dir) {
                for entry in entries.flatten() {
                    let power_path = entry.path().join("power1_average");
                    if let Ok(contents) = std::fs::read_to_string(&power_path) {
                        if let Ok(microwatts) = contents.trim().parse::<u64>() {
                            let watts = microwatts as f64 / 1_000_000.0;
                            // MAX across this card's hwmon nodes, not a sum: a card exposing
                            // two `power1_average` sensors would otherwise be charged twice.
                            fold_peak(out, [(bus.clone(), watts)]);
                        }
                    }
                }
            }
        }
    }
}

/// Samples per-card GPU power WHILE the benchmark runs, keeping each card's peak.
///
/// This exists because sampling around the load does not work, and the previous attempt to
/// fix the power reading got this wrong in a way that made the cost model worse than the
/// fallback it replaced. `benchmark_all_streaming` dispatches slots SEQUENTIALLY, so by the
/// time it returns:
///
///   * the last card has been idle since its final program finished, and
///   * every earlier card has been idle for the whole duration of all later cards' work —
///     minutes on a multi-GPU box.
///
/// `nvidia-smi power.draw` tracks within ~100ms, so a sample taken then is an IDLE figure
/// (~20-60 W for these cards) being recorded as the proving draw. Charging 40 W where the
/// card really draws 400 W makes every job look nearly free, which is the direction that
/// loses money — and worse than the flat 300 W fallback it displaced.
///
/// The PEAK over the window is the right statistic, not the mean: the question the cost model
/// asks is "what does this machine draw while proving", and between samples the card is
/// either working (near peak) or waiting for the next slot (near idle). A mean over a
/// sequential multi-slot run would average in the idle stretches of every card but the one
/// currently working.
/// One power sample.
///
/// `probe_failed` is the distinction the give-up cap needs. A card that is simply unable to report
/// `power.draw` (nvidia-smi prints `[N/A]` or `[Not Supported]`) is absent from EVERY sample
/// forever, with a perfectly healthy probe — whereas a wedged driver is what leaks a process, a
/// thread and an fd per attempt. Counting "a card is missing" as the leak signal stopped sampling
/// ~6s into a minutes-long benchmark on a box with one unreportable card, recording the healthy
/// card's warm-up draw as its peak: the idle-draw bug again, through the leak cap.
#[derive(Debug, Default)]
pub(crate) struct PowerSample {
    pub(crate) per_card: BTreeMap<String, f64>,
    /// True when the query itself did not answer (timed out, could not spawn, non-zero exit).
    pub(crate) probe_failed: bool,
}

/// How a sample is taken. Injectable so the fold and the timing can be tested without a GPU:
/// with the real reader, a test on a GPU-less box exercises nothing at all.
type PowerReader = fn(&[String]) -> PowerSample;

struct PowerSampler {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<BTreeMap<String, f64>>>,
}

/// How often to sample. Cheap (one bounded `nvidia-smi` fork plus a few sysfs reads) against a
/// benchmark window measured in minutes, and frequent enough to catch a per-program peak.
const POWER_SAMPLE_INTERVAL: Duration = Duration::from_secs(2);

/// Stop sampling after this many consecutive empty results.
///
/// Each sample forks `nvidia-smi` under a bound, and the bound's cost when the driver is wedged
/// is an abandoned process plus a blocked drainer thread and its fd (see `proc::REAP_BUDGET`).
/// Sampling every 2s for a benchmark window measured in minutes would turn that one-off cost
/// into a leak RATE — and fd exhaustion then makes the NEXT worker spawn fail, which is a
/// condition a caller may read as permanent. A card that cannot report power will not start, so
/// giving up after a few tries loses nothing.
const POWER_SAMPLE_GIVE_UP_AFTER: u32 = 3;

impl PowerSampler {
    /// Sample for the duration of `load`, and return (its result, each card's peak draw).
    ///
    /// The ordering is the fix, so it is expressed as structure rather than as a convention:
    /// sampling cannot be moved after the load without deleting this function. Sampling AROUND
    /// the load is what made the previous attempt worse than the fallback it replaced —
    /// `benchmark_all_streaming` dispatches slots sequentially, so by the time it returns the
    /// last card has just gone idle and every earlier card has been idle for minutes.
    fn around<T>(bus_ids: Vec<String>, load: impl FnOnce() -> T) -> (T, BTreeMap<String, f64>) {
        Self::around_with(bus_ids, read_gpu_power_by_card, POWER_SAMPLE_INTERVAL, load)
    }

    fn around_with<T>(
        bus_ids: Vec<String>,
        reader: PowerReader,
        interval: Duration,
        load: impl FnOnce() -> T,
    ) -> (T, BTreeMap<String, f64>) {
        let sampler = Self::start_with(bus_ids, reader, interval);
        let out = load();
        (out, sampler.finish())
    }

    /// Start sampling. An empty `bus_ids` makes this a no-op, which is correct — a figure for a
    /// card we are not proving on is not evidence.
    fn start_with(bus_ids: Vec<String>, reader: PowerReader, interval: Duration) -> Self {
        if bus_ids.is_empty() {
            return Self {
                stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
                handle: None,
            };
        }
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::Builder::new()
            .name("gpu-power-sampler".to_string())
            .spawn(move || {
                let mut peak: BTreeMap<String, f64> = BTreeMap::new();
                let mut failed_probes = 0u32;
                while !stop_thread.load(std::sync::atomic::Ordering::Relaxed) {
                    let sample = reader(&bus_ids);
                    // Count PROBE FAILURES, not missing cards. The leak this cap bounds is one
                    // abandoned process + thread + fd per failed query, so the signal has to be
                    // "the query failed" — a card that cannot report its draw is a capability
                    // fact, true of every sample, and treating it as the leak signal stopped
                    // sampling after three intervals while the benchmark still had minutes to run.
                    if sample.probe_failed {
                        failed_probes += 1;
                        if failed_probes >= POWER_SAMPLE_GIVE_UP_AFTER {
                            tracing::warn!(
                                "the GPU power query failed {failed_probes} times in a row — \
                                 stopping sampling for this run rather than retrying every \
                                 {interval:?} and abandoning a process each time"
                            );
                            fold_peak(&mut peak, sample.per_card);
                            break;
                        }
                    } else {
                        failed_probes = 0;
                    }
                    // Whatever answered is worth folding in, failure or not.
                    fold_peak(&mut peak, sample.per_card);
                    // Sleep in small slices so `stop` is observed promptly: `finish` joins this
                    // thread, so a coarse sleep would make every benchmark pay out the interval.
                    let until = Instant::now() + interval;
                    while Instant::now() < until
                        && !stop_thread.load(std::sync::atomic::Ordering::Relaxed)
                    {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
                peak
            })
            .ok();
        Self { stop, handle }
    }

    /// Stop sampling and return each card's peak draw over the window.
    ///
    /// `join` is unbounded, which is safe only because the thread's own waits are bounded: it
    /// checks `stop` every 20ms and its one blocking call is the bounded power read.
    fn finish(mut self) -> BTreeMap<String, f64> {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        match self.handle.take() {
            Some(h) => h.join().unwrap_or_default(),
            None => BTreeMap::new(),
        }
    }
}

impl Drop for PowerSampler {
    /// Stop the thread even if `finish` is never reached.
    ///
    /// A panic between `start` and `finish` would otherwise leave a thread forking `nvidia-smi`
    /// every two seconds for the life of the miner, contending with live proofs — and the
    /// benchmark entry points run inside `spawn_blocking(...).await.unwrap_or_default()`, which
    /// swallows the panic, so nothing would report it.
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The proving cards, as the worker pool reports them. Known BEFORE the load, which is what
/// the sampler needs.
fn proving_bus_ids_from_pool() -> Vec<String> {
    crate::engine::worker_pool()
        .map(|p| p.gpu_bus_ids())
        .unwrap_or_default()
}

/// Total draw over the cards we MEASURED, or `None` if we measured none.
///
/// One function for all three benchmark entry points, so they cannot each invent their own
/// total. It is not the same quantity as the sum of the device rows: a card we could not measure
/// contributes `FALLBACK_GPU_WATTS` to its row and nothing here, so on a partially measured box
/// the two differ by design. This figure is display-only — the cost model reads the per-card
/// rows, never this — and a fabricated fallback does not belong in a number labelled as measured.
///
/// It is also a sum of PEAKS that were not necessarily simultaneous (slots are dispatched
/// sequentially), so it is an upper bound on what the box drew at any one instant.
fn suite_total_watts(per_card: &BTreeMap<String, f64>) -> Option<f64> {
    if per_card.is_empty() {
        return None;
    }
    Some(per_card.values().sum())
}

/// Run benchmarks using whichever prover backends are compiled in.
///
/// When no prover feature is enabled, falls back to simulated benchmarks.
/// Measures CPU and GPU power consumption during the benchmark window.
pub fn run_benchmark() -> BenchmarkSuite {
    let cpu_info = get_cpu_info();
    let cores = get_cpu_cores();
    let timestamp = chrono::Utc::now().to_rfc3339();

    tracing::info!("Running benchmarks on {} ({} cores)", cpu_info, cores);

    // Snapshot power counters before benchmarks
    let rapl_before = read_rapl_energy_uj();
    if rapl_before.is_none() {
        tracing::warn!(
            "CPU power monitoring unavailable. \
             To enable, run: sudo chmod o+r /dev/cpu/0/msr"
        );
    }
    // This path's load is a long inline sequence (CPU programs, then GPU workers), so it uses
    // the explicit start/finish pair rather than `around`. The two GPU-only paths, where the
    // load is a single call, wrap it instead so the ordering cannot be got wrong.
    let power_sampler = PowerSampler::start_with(
        proving_bus_ids_from_pool(),
        read_gpu_power_by_card,
        POWER_SAMPLE_INTERVAL,
    );
    let power_start = Instant::now();

    let mut results = Vec::new();

    #[cfg(feature = "risc0")]
    {
        results.push(crate::risc0::benchmark_fibonacci(1000));
        results.push(crate::risc0::benchmark_sha256_chain(10_000));
    }

    #[cfg(feature = "sp1")]
    {
        results.push(crate::sp1::benchmark_fibonacci(1000));
        results.push(crate::sp1::benchmark_sha256_chain(10_000));
    }

    #[cfg(feature = "openvm")]
    results.push(crate::openvm::benchmark_fibonacci(1000));

    // Subprocess worker benchmarks (always try — captures GPU provers).
    // Use benchmark_all_with_device_info to get GPU metadata alongside results.
    let worker_device_results = if let Some(pool) = crate::engine::worker_pool() {
        let device_results = pool.benchmark_all_with_device_info();
        if !device_results.is_empty() {
            let total: usize = device_results.iter().map(|r| r.entries.len()).sum();
            tracing::info!(
                "Got {} benchmark results from {} subprocess workers",
                total,
                device_results.len()
            );
        }
        device_results
    } else {
        Vec::new()
    };

    // Flatten worker entries for main results (if no compile-time backend)
    if results.is_empty() {
        for slot_result in &worker_device_results {
            for entry in &slot_result.entries {
                results.push(benchmark_entry_to_result(entry));
            }
        }
    }

    // Fallback: simulated benchmarks when no prover backend is enabled
    if results.is_empty() {
        results = run_simulated_benchmarks();
    }

    // Snapshot power counters after benchmarks
    let power_elapsed = power_start.elapsed();
    let per_card = power_sampler.finish();

    // Compute average CPU power from the RAPL energy delta (shared with the GPU-only paths, so
    // all three record the same quantity the same way).
    let cpu_power_watts = cpu_power_over(rapl_before, power_elapsed);

    let gpu_power_watts = match suite_total_watts(&per_card) {
        None => {
            tracing::warn!(
                "GPU power unavailable for the proving cards — device rows will carry the \
                 {FALLBACK_GPU_WATTS:.0}W fallback, which feeds the profitability model directly"
            );
            None
        }
        Some(total) => {
            // "peak", not "average": see `PowerSampler`. Saying "avg over the window" would be
            // false. Note this is NOT the number the cost model uses — that is the per-card row,
            // and the charge adds CPU and overhead and takes the MEAN of the cards, not the sum.
            // An operator reconciling against a wall meter should expect this to read high.
            tracing::info!(
                "GPU power: {total:.1}W total over {} card(s) (peak per card while proving)",
                per_card.len()
            );
            Some(total)
        }
    };

    let zkops = compute_zkops(&results);
    let (precompile_score, compute_score) = compute_category_scores(&results);

    // Generate CPU device benchmarks (per-backend throughput)
    let cpu_avg = if results.is_empty() {
        0.0
    } else {
        results.iter().map(|r| r.throughput).sum::<f64>() / results.len() as f64
    };
    let cpu_power = cpu_power_watts.unwrap_or(200.0);
    let cpu_memory = get_total_memory_bytes();
    let mut device_benchmarks: Vec<DeviceBenchmark> = BACKEND_PROFILES
        .iter()
        .map(|profile| {
            let (optimal_po2, memory_usage_bytes) =
                find_optimal_po2(cpu_memory, profile.name, false);
            let po2_factor = if profile.name == "risc0" {
                po2_throughput_factor(optimal_po2)
            } else {
                1.0
            };
            DeviceBenchmark {
                program_stages: Vec::new(),
                device_id: CPU_DEVICE_ID.to_string(),
                device_label: cpu_info.clone(),
                prover_backend: profile.name.to_string(),
                throughput: cpu_avg * profile.cpu_factor * po2_factor,
                power_watts: cpu_power,
                optimal_po2,
                memory_usage_bytes,
                max_feasible_po2: optimal_po2,
                program_throughputs: std::collections::HashMap::new(),
                pci_bus_id: String::new(),
                po2_samples: Vec::new(),
                // A CPU row's host cost is the CPU benchmark itself, which the admission gate does
                // not govern (there is no worker to cap); left unmeasured rather than guessed.
                host_peak_bytes: None,
            }
        })
        .collect();

    // Build GPU device benchmarks from real worker results.
    // Workers are keyed like "risc0:cuda:0", "risc0:rocm:1", etc.
    // Each worker ran the full benchmark suite on its assigned GPU — use
    // the measured average throughput directly.
    let mut gpu_device_benchmarks =
        build_gpu_device_benchmarks_from_workers(&worker_device_results, &per_card);
    device_benchmarks.append(&mut gpu_device_benchmarks);

    BenchmarkSuite {
        results,
        device_benchmarks,
        cpu_info,
        timestamp,
        zkops,
        precompile_score,
        compute_score,
        cpu_power_watts,
        gpu_power_watts,
        host_peaks: host_peaks_from_workers(&worker_device_results),
    }
}

/// Run only GPU worker benchmarks, skipping CPU proof programs.
///
/// This is much faster than `run_benchmark()` and is used at startup to avoid
/// the lengthy CPU benchmark. CPU benchmarks can be run on demand from the TUI.
///
/// If no GPU workers are available, returns a minimal suite with no device
/// benchmarks (the user can trigger CPU benchmarks later).
pub fn run_benchmark_gpu_only() -> BenchmarkSuite {
    let cpu_info = get_cpu_info();
    let timestamp = chrono::Utc::now().to_rfc3339();

    // Sampling WRAPS the load, so it cannot be reordered after it. Sampling afterwards reads an
    // idle card: slots are dispatched sequentially, so by the time the load returns every card
    // but the last has been idle for minutes.
    let (worker_device_results, per_card) =
        PowerSampler::around(proving_bus_ids_from_pool(), || {
            if let Some(pool) = crate::engine::worker_pool() {
                let device_results = pool.benchmark_all_with_device_info();
                if !device_results.is_empty() {
                    let total: usize = device_results.iter().map(|r| r.entries.len()).sum();
                    tracing::info!(
                        "Got {} benchmark results from {} GPU workers (CPU benchmarks skipped)",
                        total,
                        device_results.len()
                    );
                }
                device_results
            } else {
                Vec::new()
            }
        });
    let gpu_power_watts = suite_total_watts(&per_card);

    // Build GPU device benchmarks from worker results
    let device_benchmarks =
        build_gpu_device_benchmarks_from_workers(&worker_device_results, &per_card);

    // Build results from worker entries (for zkOP/s scoring if available)
    let mut results = Vec::new();
    for slot_result in &worker_device_results {
        for entry in &slot_result.entries {
            results.push(benchmark_entry_to_result(entry));
        }
    }
    let zkops = if results.is_empty() {
        0.0
    } else {
        compute_zkops(&results)
    };
    let (precompile_score, compute_score) = compute_category_scores(&results);

    BenchmarkSuite {
        results,
        device_benchmarks,
        cpu_info,
        timestamp,
        zkops,
        precompile_score,
        compute_score,
        cpu_power_watts: None, // see the note in the streaming path below
        gpu_power_watts,
        host_peaks: host_peaks_from_workers(&worker_device_results),
    }
}

/// Run GPU benchmarks with per-program streaming progress.
///
/// Same as `run_benchmark_gpu_only` but sends progress events through the
/// callback as each benchmark program completes on each GPU.
pub fn run_benchmark_gpu_only_streaming(
    on_progress: &dyn Fn(crate::dispatcher::BenchmarkProgressEvent),
) -> BenchmarkSuite {
    let cpu_info = get_cpu_info();
    let timestamp = chrono::Utc::now().to_rfc3339();

    // Read RAPL across the window here too. These GPU-only paths are what the miner and the
    // TUI's [b] key actually run, and they used to hardcode `cpu_power_watts: None` — so the
    // cost model fell back to `DEFAULT_CPU_WATTS` even on a host where the CPU draw is readable.
    // The CPU is still working during GPU proving (it drives the executor), so this is not a
    // rounding term on a many-core part.
    let rapl_before = read_rapl_energy_uj();
    let cpu_window = Instant::now();

    // Sampling WRAPS the load — see `PowerSampler::around`.
    let (worker_device_results, per_card) =
        PowerSampler::around(proving_bus_ids_from_pool(), || {
            if let Some(pool) = crate::engine::worker_pool() {
                pool.benchmark_all_streaming(on_progress)
            } else {
                Vec::new()
            }
        });
    let gpu_power_watts = suite_total_watts(&per_card);

    let device_benchmarks =
        build_gpu_device_benchmarks_from_workers(&worker_device_results, &per_card);

    let mut results = Vec::new();
    for slot_result in &worker_device_results {
        for entry in &slot_result.entries {
            results.push(benchmark_entry_to_result(entry));
        }
    }
    let zkops = if results.is_empty() {
        0.0
    } else {
        compute_zkops(&results)
    };
    let (precompile_score, compute_score) = compute_category_scores(&results);

    BenchmarkSuite {
        results,
        device_benchmarks,
        cpu_info,
        timestamp,
        zkops,
        precompile_score,
        compute_score,
        cpu_power_watts: cpu_power_over(rapl_before, cpu_window.elapsed()),
        gpu_power_watts,
        host_peaks: host_peaks_from_workers(&worker_device_results),
    }
}

/// Convert a protocol `BenchmarkEntry` (from subprocess) to our `BenchmarkResult`.
///
/// Looks up the matching `BenchmarkProgram` by exact canonical name to copy
/// weight and precompile fields. If no match found, logs a warning and assigns weight 0.0.
fn benchmark_entry_to_result(entry: &zkminer_prover_protocol::BenchmarkEntry) -> BenchmarkResult {
    let program = BENCHMARK_PROGRAMS
        .iter()
        .find(|p| p.name == entry.program_name);

    if program.is_none() {
        tracing::debug!(
            "Unknown benchmark program '{}' from worker, assigning weight 0.0",
            entry.program_name
        );
    }

    BenchmarkResult {
        program_name: entry.program_name.clone(),
        prover_backend: entry.prover_backend.clone(),
        cycles: entry.cycles,
        duration: Duration::from_secs_f64(entry.duration_secs),
        throughput: entry.throughput,
        weight: program.map(|p| p.weight).unwrap_or(0.0),
        precompile: program.map(|p| p.precompile).unwrap_or(false),
    }
}

/// Build GPU `DeviceBenchmark` entries from real worker benchmark results.
///
/// Build GPU `DeviceBenchmark` entries from real worker benchmark results.
///
/// The slot_key looks like `"risc0:cuda:0"` — we use the device_index and gpu_tag
/// to produce device IDs like `"gpu0"`, `"gpu1"`.
///
/// `per_card_watts` is keyed by normalized PCI bus id. A card we could not measure takes
/// `FALLBACK_GPU_WATTS`; it does NOT take another card's reading, which is what stamping one
/// total onto every row amounted to.
/// Worst measured host peak per backend, across every slot that reported one.
///
/// EVERY slot, regardless of `gpu_tag` — that is the whole point; see `BenchmarkSuite::host_peaks`.
/// The worst, because admission has to hold for whichever slot the dispatcher picks, and it does not
/// pick the cheapest.
fn host_peaks_from_workers(
    worker_results: &[crate::dispatcher::SlotBenchmarkResult],
) -> std::collections::HashMap<String, u64> {
    let mut peaks: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for r in worker_results {
        let Some(peak) = r.host_peak_bytes else {
            continue;
        };
        let backend = r
            .slot_key
            .split(':')
            .next()
            .unwrap_or(&r.slot_key)
            .to_string();
        let e = peaks.entry(backend).or_insert(0);
        *e = (*e).max(peak);
    }
    peaks
}

fn build_gpu_device_benchmarks_from_workers(
    worker_results: &[crate::dispatcher::SlotBenchmarkResult],
    per_card_watts: &BTreeMap<String, f64>,
) -> Vec<DeviceBenchmark> {
    let mut benchmarks = Vec::new();

    for r in worker_results {
        if r.entries.is_empty() || r.gpu_tag == "generic" {
            continue;
        }

        let idx = r.device_index.unwrap_or(0);
        // Tag-qualified: `device_index` is sequential WITHIN a vendor, so a cuda
        // card and a rocm card both carry index 0 and the bare `gpu{idx}` form
        // made them collide onto one row. Must match `WorkerPool::benchmark_device_id`.
        let device_id = crate::dispatcher::WorkerPool::gpu_device_id(&r.gpu_tag, &idx.to_string());
        let device_label = match &r.gpu_name {
            Some(name) => format!("GPU{idx} {name}"),
            None => format!("GPU{idx} ({})", r.gpu_tag),
        };
        let slot_key = &r.slot_key;
        let entries = &r.entries;
        let vram_bytes = r.vram_bytes;

        // Average throughput across canonical benchmark programs for this worker.
        // Exclude zero-weight programs to match average_throughput().
        let canonical: Vec<_> = entries.iter().filter(|e| e.weight > 0.0).collect();
        let avg_throughput = if canonical.is_empty() {
            entries.iter().map(|e| e.throughput).sum::<f64>() / entries.len().max(1) as f64
        } else {
            canonical.iter().map(|e| e.throughput).sum::<f64>() / canonical.len() as f64
        };

        // Extract the backend from the first entry (all entries from same worker share backend)
        let backend = entries
            .first()
            .map(|e| e.prover_backend.as_str())
            .unwrap_or("risc0");

        // Build per-program throughput map for workload-specific predictions
        let mut program_throughputs = std::collections::HashMap::new();
        for entry in entries {
            program_throughputs.insert(entry.program_name.clone(), entry.throughput);
        }
        // And the STARK/wrap split behind those rates, per program. `duration_secs` is the STARK
        // time from protocol v4 on; see `BenchmarkEntry::duration_secs`.
        let program_stages: Vec<ProgramStage> = entries
            .iter()
            .map(|e| ProgramStage {
                program_name: e.program_name.clone(),
                cycles: e.cycles,
                stark_secs: e.duration_secs,
                wrap_secs: e.wrap_secs,
            })
            .collect();

        tracing::info!(
            "{slot_key}: {device_label} / {backend} → {:.1}M cycles/sec (avg of {} canonical programs)",
            avg_throughput / 1_000_000.0,
            canonical.len(),
        );

        // Size the segment (po2) against this card's ACTUAL VRAM, mirroring the
        // estimated-GPU path in `add_gpu_device_benchmarks`. Previously these three
        // fields were hardcoded to `(PO2_MAX, 0, PO2_MAX)`, which claimed the largest
        // segment is feasible on every GPU regardless of its memory and rendered the
        // "Memory" column a constant 0 MB.
        //
        // NOTE: throughput is NOT scaled by `po2_throughput_factor` here (unlike the
        // CPU/estimated paths) because `avg_throughput` is a MEASURED value — the
        // po2 effect is already baked into it. Applying the factor would double-count.
        //
        // When VRAM is unknown (`gpu_vram_bytes` returns None for non-CUDA devices)
        // the previous behaviour is preserved rather than guessing a size. In that
        // case `memory_usage_bytes` stays 0, which is the documented sentinel for
        // "not VRAM-derived — do NOT trust max_feasible_po2". Any future po2
        // calibration must gate on that before raising a device's segment size.
        let (optimal_po2, memory_usage_bytes) = match vram_bytes {
            Some(vram) if vram > 0 => find_optimal_po2(vram, backend, true),
            _ => {
                tracing::warn!(
                    "{slot_key}: VRAM unknown — leaving po2 at {PO2_MAX} (unsized). \
                     max_feasible_po2 is not memory-derived for this device."
                );
                (PO2_MAX, 0)
            }
        };

        let pci_bus_id = r.pci_bus_id.clone().unwrap_or_default();
        // Floor at WRITE time as well as at load. `floor_implausible_gpu_power`'s doc claimed the
        // fix was write-time; it was not, so a sample that caught only a card's warm-up draw (the
        // sampler gives up on a repeatedly failing probe) was used AS MEASURED for the whole
        // session and floored only on the next start — the running process and the restarted one
        // disagreeing about the same file.
        let measured = per_card_watts.get(&pci_bus_id).copied();
        let power_watts = match measured {
            Some(w) if w >= MIN_PLAUSIBLE_GPU_WATTS => w,
            Some(w) => {
                tracing::warn!(
                    "{slot_key}: measured {w:.1}W for {pci_bus_id}, which is below the \
                     {MIN_PLAUSIBLE_GPU_WATTS:.0}W a proving card must draw — recording \
                     {FALLBACK_GPU_WATTS:.0}W instead of pricing this card as nearly free"
                );
                FALLBACK_GPU_WATTS
            }
            None => FALLBACK_GPU_WATTS,
        };

        benchmarks.push(DeviceBenchmark {
            device_id,
            device_label,
            prover_backend: backend.to_string(),
            throughput: avg_throughput,
            power_watts,
            optimal_po2,
            memory_usage_bytes,
            max_feasible_po2: optimal_po2,
            program_throughputs,
            po2_samples: Vec::new(),
            program_stages,
            pci_bus_id,
            // Measured by the dispatcher while this worker was still alive.
            host_peak_bytes: r.host_peak_bytes,
        });
    }

    benchmarks
}

/// True when a calibration sweep actually exercised segmentation and is therefore
/// safe to adopt as a `Po2Profile`.
///
/// `Po2Profile::optimal_po2_for_job` reduces to `argmax(throughput_at_po2)`, so a sweep
/// whose workload fit in a SINGLE segment at every po2 carries no po2 signal at all —
/// the throughput differences are warm-up and timer noise. Adopting such a sweep would
/// make the miner pick a segment size essentially at random and override the SDK's own
/// (currently working) choice on every job.
///
/// This is not hypothetical: measured on an RTX 5090, the risc0 worker's built-in
/// calibration workload is 32,768 cycles and reports `segment_count == 1` for every po2
/// in 18..=24, with throughput varying 72K→624K purely from warm-up. Such a sweep is
/// rejected here, leaving `po2_samples` empty so proving falls back to the SDK.
pub fn calibration_is_usable(samples: &[Po2Sample]) -> bool {
    samples.len() >= 2
        && samples.iter().any(|s| s.segment_count > 1)
        && samples
            .iter()
            .all(|s| s.duration_secs > 0.0 && s.total_cycles > 0 && s.throughput > 0.0)
}

/// Run a po2 calibration sweep on every eligible GPU device and attach the samples.
///
/// Eligibility — ALL must hold:
/// - risc0 backend (SP1/OpenVM reply `Error`; they have their own segmentation).
/// - a GPU device row (`gpu*`), since po2 is chosen per proving device.
/// - **`memory_usage_bytes != 0`** — the sentinel meaning `max_feasible_po2` was derived
///   from real VRAM. A device whose VRAM is unknown must NOT have its segment size
///   raised on the strength of a guess.
///
/// Cost: one full proof per po2 step per device, so this is opt-in
/// (`zkminer benchmark --calibrate`), never part of a default run.
pub fn calibrate_po2_for_suite(suite: &mut BenchmarkSuite, pool: &crate::dispatcher::WorkerPool) {
    // Free every worker's GPU memory first. By the time calibration runs, the SP1
    // benchmark has already started `sp1-gpu-server`, which holds ~18.5 GB and is NOT
    // covered by the per-slot recycle in `benchmark_all_*` (that only recycles
    // cuda/rocm-tagged slots, and SP1 is tagged "generic"). Calibrating on top of it
    // makes the risc0 worker on the same card die with
    // `cudaGetLastError() ... failed: "out of memory"` — observed on the 5090, while
    // the 4090 (no gpu-server) calibrated fine.
    //
    // `shutdown_all` SIGKILLs each worker's whole process group, so the gpu-server
    // goes too. Slots are marked dead (not failed), so `ensure_alive` respawns each
    // risc0 worker on demand with no backoff — and each device gets a clean GPU
    // context, which is what we want to measure against anyway.
    tracing::info!("Releasing worker GPU memory before po2 calibration");
    pool.shutdown_all();

    // Sort: `registered_backends()` iterates a HashMap, so calibration order --
    // and, before the tag fix, which colliding card's samples survived -- varied
    // between runs on identical hardware. dispatcher.rs already sorts elsewhere.
    let mut backend_keys: Vec<_> = pool.registered_backends();
    backend_keys.sort();
    for key in backend_keys {
        // Slot keys look like "risc0:cuda:0" — backend:gpu_tag:device_index.
        let mut parts = key.split(':');
        let (Some(backend), Some(gpu_tag), Some(idx)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if backend != "risc0" || gpu_tag == "generic" {
            continue;
        }
        let device_id = crate::dispatcher::WorkerPool::gpu_device_id(gpu_tag, idx);

        let Some(db) = suite
            .device_benchmarks
            .iter_mut()
            .find(|d| d.device_id == device_id && d.prover_backend == "risc0")
        else {
            continue;
        };

        if db.memory_usage_bytes == 0 {
            tracing::warn!(
                "{key}: skipping po2 calibration — VRAM unknown, so max_feasible_po2 \
                 ({}) is not memory-derived and must not be raised",
                db.max_feasible_po2
            );
            continue;
        }

        // Bound the sweep by what is FREE on the card, not only by what the card holds.
        //
        // `max_feasible_po2` is derived from the card's total VRAM, so on a card with a display
        // attached the top of this range is sized for memory that is not there. Sweeping into it costs
        // a full proof attempt per step, each one failing, and `hit_failure` then truncates the sweep
        // and CLAMPS `max_feasible_po2` down — recording the display's footprint as a permanent
        // property of the card, in a suite that persists to disk and prices every later job on it.
        //
        // `calibrate_slot_po2` clamps each individual run as well, so a sample taken here can still
        // come back at a lower po2 than requested; stopping the range early just avoids asking.
        let free_po2 = match pool.foreign_vram_for_slot(&key) {
            Some((foreign, _used, total)) if total > 0 => {
                let (fits, _) = find_optimal_po2(total.saturating_sub(foreign), "risc0", true);
                Some(fits)
            }
            _ => None,
        };
        let max_po2 = match free_po2 {
            Some(fits) if fits < db.max_feasible_po2.min(PO2_MAX) => {
                tracing::info!(
                    "{key}: capping the po2 sweep at {fits} rather than {} — part of this card's                      VRAM is in use by another process",
                    db.max_feasible_po2.min(PO2_MAX),
                );
                fits
            }
            _ => db.max_feasible_po2.min(PO2_MAX),
        };
        if max_po2 < PO2_MIN {
            tracing::warn!(
                "{key}: skipping po2 calibration — not enough free VRAM for even po2={PO2_MIN}"
            );
            continue;
        }
        tracing::info!("{key}: calibrating po2 {PO2_MIN}..={max_po2}");
        let mut samples = Vec::new();
        let mut hit_failure = false;
        for po2 in PO2_MIN..=max_po2 {
            // Retry once on failure. A worker can be SIGKILLed out from under us
            // between `ensure_alive`'s liveness check and the response — the worker
            // inherits PR_SET_PDEATHSIG, which is THREAD-scoped, so a retired tokio
            // blocking thread takes its worker with it (observed here as
            // "Worker risc0 process died (EOF)" on the first sample). The retry goes
            // back through `ensure_alive`, which respawns.
            let mut attempt = 0;
            let sample = loop {
                attempt += 1;
                match pool.calibrate_slot_po2(&key, po2) {
                    Ok(s) => break Some(s),
                    Err(e) if attempt == 1 => {
                        // The first EOF marks the slot failed, so `respawn` now imposes
                        // an exponential backoff (5s after one failure). Retrying
                        // immediately is guaranteed to be rejected with
                        // "Backoff: waiting …", so wait past it before trying again.
                        const RETRY_AFTER: Duration = Duration::from_secs(6);
                        tracing::warn!(
                            "{key}: po2={po2} calibration failed ({e:#}) — retrying in {}s",
                            RETRY_AFTER.as_secs()
                        );
                        std::thread::sleep(RETRY_AFTER);
                    }
                    Err(e) => {
                        tracing::warn!("{key}: po2={po2} calibration failed twice: {e:#}");
                        break None;
                    }
                }
            };
            match sample {
                Some(s) => {
                    tracing::info!(
                        "{key}: po2={} segments={} cycles={} {:.2}s → {:.0} c/s",
                        s.po2,
                        s.segment_count,
                        s.total_cycles,
                        s.duration_secs,
                        s.throughput
                    );
                    samples.push(s);
                }
                // A partial sweep is still evaluated below; the usability gate
                // requires >= 2 samples spanning a segmentation change.
                None => {
                    hit_failure = true;
                    break;
                }
            }
        }

        if calibration_is_usable(&samples) {
            // Clamp max_feasible_po2 to the highest po2 that actually SUCCEEDED.
            //
            // A po2 that OOMed or was rejected produces no sample, so without this it
            // simply vanishes from the profile — and `throughput_at_po2` CLAMPS above
            // the measured range, meaning an unmeasured (failing) po2 inherits the
            // throughput of the best measured one and can win the argmax. Measured on a
            // 4090: po2=22 died with "allocation of 14159970304 bytes for evaluated
            // failed", and only a marginal throughput difference kept selection off it.
            //
            // The heuristic is badly optimistic here — `estimate_po2_memory` predicts
            // 4 GB for po2=22 against a real ~14 GB — so the measured ceiling wins.
            let highest_ok = samples.iter().map(|s| s.po2).max().unwrap_or(PO2_MIN);
            // Leave ONE STEP of headroom below an OBSERVED failure boundary.
            //
            // "Highest po2 that calibrated once" is NOT "reliably safe". Measured on a
            // 4090: po2=22 OOMed so the ceiling was clamped to 21, calibration at 21
            // then SUCCEEDED (38.5s on a 62M-cycle sweep) — yet a real 15.7M-cycle proof
            // at po2=21 died with
            //   "failed to run groth16 prove operation: cudaMallocAsync ... out of memory".
            // The calibration sweep and a live job do not see the same memory state
            // (fragmentation, buffer pools, a second worker on the card), so the very top
            // of the measured range is marginal. Each po2 step doubles the segment, so
            // backing off one step buys ~2x headroom.
            //
            // Only applied when a higher po2 was actually ATTEMPTED AND FAILED; a sweep
            // that ran clean to the top needs no backoff.
            let highest_ok = if hit_failure {
                let backed_off = highest_ok.saturating_sub(1).max(PO2_MIN);
                if backed_off < highest_ok {
                    tracing::info!(
                        "{key}: backing off po2 ceiling {highest_ok} → {backed_off} \
                         (one step below the observed failure boundary)"
                    );
                }
                backed_off
            } else {
                highest_ok
            };
            // Drop samples above the ceiling so the argmax and the Po2Profile agree with it.
            samples.retain(|s| s.po2 <= highest_ok);
            if !calibration_is_usable(&samples) {
                tracing::warn!(
                    "{key}: DISCARDING po2 calibration — too few usable samples remain \
                     below the safe ceiling {highest_ok}"
                );
                continue;
            }
            if highest_ok < db.max_feasible_po2 {
                tracing::warn!(
                    "{key}: lowering max_feasible_po2 {} → {highest_ok} (higher po2 failed \
                     to calibrate — OOM or rejected by the SDK)",
                    db.max_feasible_po2
                );
                db.max_feasible_po2 = highest_ok;
                if db.optimal_po2 > highest_ok {
                    db.optimal_po2 = highest_ok;
                }
            }
            // Prefer the MEASURED best over the heuristic for the advertised optimum.
            // `optimal_po2` is what the TUI shows and defaults to; leaving it at the
            // heuristic's value while holding samples that say otherwise is just
            // misleading (measured on a 5090: heuristic said 22 after clamping, the
            // measurement says 20). Per-job selection still goes through
            // `Po2Profile::optimal_po2_for_job`; this only fixes the advertised value.
            if let Some(best) = samples
                .iter()
                .max_by(|a, b| a.throughput.total_cmp(&b.throughput))
            {
                if db.optimal_po2 != best.po2 {
                    tracing::info!(
                        "{key}: optimal_po2 {} → {} (measured fastest: {:.2}M c/s)",
                        db.optimal_po2,
                        best.po2,
                        best.throughput / 1_000_000.0
                    );
                    db.optimal_po2 = best.po2;
                }
                db.memory_usage_bytes = estimate_po2_memory(best.po2, backend, true);
            }
            tracing::info!("{key}: adopting {} po2 calibration samples", samples.len());
            db.po2_samples = samples;
        } else {
            tracing::warn!(
                "{key}: DISCARDING po2 calibration ({} samples) — the workload never \
                 exceeded one segment, so the measurements carry no po2 signal. \
                 Proving will keep letting the SDK choose the segment size.",
                samples.len()
            );
        }
    }
}

/// Run simulated benchmarks for all canonical programs.
fn run_simulated_benchmarks() -> Vec<BenchmarkResult> {
    tracing::info!("No prover backend enabled — running simulated benchmarks");

    let mut results = Vec::new();

    for program in &BENCHMARK_PROGRAMS {
        let start = Instant::now();

        match program.name {
            "fibonacci" => simulate_fibonacci(),
            "sha256-chain" => simulate_sha256_chain(),
            "ecdsa-verify" => simulate_ecdsa_verify(),
            "bigint-mul" => simulate_bigint_mul(),
            "memory-merkle" => simulate_memory_merkle(),
            "chacha-mix" => simulate_chacha_mix(),
            _ => unreachable!(),
        }

        let duration = start.elapsed();
        let throughput = program.simulated_cycles as f64 / duration.as_secs_f64();

        tracing::info!(
            "  {}: {} cycles in {:?} ({:.0} cycles/sec){}",
            program.name,
            program.simulated_cycles,
            duration,
            throughput,
            if program.precompile {
                " [precompile]"
            } else {
                ""
            },
        );

        results.push(BenchmarkResult {
            program_name: program.name.to_string(),
            prover_backend: "simulated".to_string(),
            cycles: program.simulated_cycles,
            duration,
            throughput,
            weight: program.weight,
            precompile: program.precompile,
        });
    }

    results
}

// ---------------------------------------------------------------------------
// Simulation workloads — each exercises a distinct CPU pattern.
// All use black_box() to prevent dead-code elimination.
// ---------------------------------------------------------------------------

/// Fibonacci: tight integer loop with wrapping arithmetic (500 iterations of LCG).
fn simulate_fibonacci() {
    let mut a = 0u64;
    let mut b = 1u64;
    for _ in 0..500 {
        let next = a.wrapping_add(b);
        a = b;
        b = next;
        // Inner LCG churn — black_box on each iteration prevents unrolling/vectorization
        for _ in 0..200 {
            b = std::hint::black_box(b)
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }
    }
    std::hint::black_box(b);
}

/// SHA-256 chain: simulates 1000 SHA-256 block compressions (64 rounds each, 2000 total blocks).
fn simulate_sha256_chain() {
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for block in 0u32..2000 {
        // 64 rounds per block, like real SHA-256
        for round in 0u32..64 {
            let s = std::hint::black_box(state);
            let k = round.wrapping_mul(0x428a2f98).wrapping_add(block);
            for i in 0..8 {
                let sigma0 = s[(i + 1) % 8].rotate_right(2)
                    ^ s[(i + 1) % 8].rotate_right(13)
                    ^ s[(i + 1) % 8].rotate_right(22);
                let sigma1 = s[(i + 5) % 8].rotate_right(6)
                    ^ s[(i + 5) % 8].rotate_right(11)
                    ^ s[(i + 5) % 8].rotate_right(25);
                let ch = (s[(i + 5) % 8] & s[(i + 6) % 8]) ^ (!s[(i + 5) % 8] & s[(i + 7) % 8]);
                let maj = (s[i] & s[(i + 1) % 8])
                    ^ (s[i] & s[(i + 2) % 8])
                    ^ (s[(i + 1) % 8] & s[(i + 2) % 8]);
                let t1 = s[(i + 7) % 8]
                    .wrapping_add(sigma1)
                    .wrapping_add(ch)
                    .wrapping_add(k);
                let t2 = sigma0.wrapping_add(maj);
                state[i] = t1.wrapping_add(t2);
            }
        }
    }
    std::hint::black_box(state);
}

/// ECDSA verify: modular exponentiation simulation with multiply-and-reduce loop (5000 iterations).
fn simulate_ecdsa_verify() {
    // Large 128-bit prime simulating EC field arithmetic
    let modulus: u128 = 0xFFFFFFFFFFFFFFFFC90FDAA22168C235;
    let mut base: u128 = 0xDEADBEEFCAFEBABE_1234567890ABCDEF;
    let mut result: u128 = 1;
    for _ in 0..5000 {
        // Square-and-multiply step
        result = multiply_mod_128(result, base, modulus);
        base = multiply_mod_128(base, base, modulus);
        // Mix to prevent trivial patterns
        result ^= base.rotate_left(13);
    }
    std::hint::black_box(result);
}

/// 128-bit modular multiplication via repeated addition/shift (no u256 needed).
#[inline(never)]
fn multiply_mod_128(a: u128, b: u128, modulus: u128) -> u128 {
    let mut result: u128 = 0;
    let mut a = a % modulus;
    let mut b = b % modulus;
    while b > 0 {
        if b & 1 != 0 {
            result = result.wrapping_add(a);
            if result >= modulus || result < a {
                result = result.wrapping_sub(modulus);
            }
        }
        a = a.wrapping_shl(1);
        if a >= modulus {
            a = a.wrapping_sub(modulus);
        }
        b >>= 1;
    }
    result
}

/// BigInt multiply: schoolbook multiplication of two 512-element u64 arrays (1000 iterations).
fn simulate_bigint_mul() {
    let mut a = [0u64; 64];
    let mut b = [0u64; 64];
    // Seed arrays with pseudo-random values
    for i in 0..64 {
        a[i] = (i as u64)
            .wrapping_mul(0x9E3779B97F4A7C15)
            .wrapping_add(0x6A09E667F3BCC908);
        b[i] = (i as u64)
            .wrapping_mul(0x517CC1B727220A95)
            .wrapping_add(0xBB67AE8584CAA73B);
    }

    for _ in 0..1000 {
        let mut result = [0u64; 128];
        for i in 0..64 {
            let mut carry = 0u128;
            for j in 0..64 {
                let prod = a[i] as u128 * b[j] as u128 + result[i + j] as u128 + carry;
                result[i + j] = prod as u64;
                carry = prod >> 64;
            }
            result[i + 64] = carry as u64;
        }
        // Feed result back into inputs for next iteration
        a[0] = result[0].wrapping_add(1);
        b[0] = result[127].wrapping_add(1);
        std::hint::black_box(&result);
    }
    std::hint::black_box((a, b));
}

/// Memory-Merkle: build binary tree with random memory access and hash combine (3000 iterations).
fn simulate_memory_merkle() {
    // 2048 leaves, build 1024-leaf Merkle tree
    let mut tree = vec![0u64; 4096];

    // Initialize leaves with pseudo-random values
    for i in 0..2048 {
        tree[2048 + i] = (i as u64)
            .wrapping_mul(0x9E3779B97F4A7C15)
            .wrapping_add(0x243F6A8885A308D3);
    }

    for round in 0u64..3000 {
        // Build tree bottom-up — black_box on each node prevents vectorization
        for i in (1..2048).rev() {
            let left = std::hint::black_box(tree[2 * i]);
            let right = std::hint::black_box(tree[2 * i + 1]);
            tree[i] = left
                .rotate_left(7)
                .wrapping_add(right.rotate_right(11))
                .wrapping_mul(0x517CC1B727220A95)
                ^ round;
        }
        // Perturb some leaves for next iteration
        let idx = (round as usize) % 2048;
        tree[2048 + idx] = tree[1].wrapping_add(round);
    }
    std::hint::black_box(&tree[..16]);
}

/// ChaCha-Mix: pure ARX computation — Add, Rotate, XOR (5000 iterations).
/// Simulates the ChaCha20 quarter-round operation with no precompile shortcuts.
fn simulate_chacha_mix() {
    let mut state = [0u32; 16];
    for i in 0..16 {
        state[i] = (i as u32).wrapping_mul(0x9E3779B9).wrapping_add(0x6A09E667);
    }

    for round in 0u64..5000 {
        // ChaCha20 quarter-round on columns and diagonals
        for _ in 0..10 {
            // Column rounds
            quarter_round_sim(&mut state, 0, 4, 8, 12);
            quarter_round_sim(&mut state, 1, 5, 9, 13);
            quarter_round_sim(&mut state, 2, 6, 10, 14);
            quarter_round_sim(&mut state, 3, 7, 11, 15);
            // Diagonal rounds
            quarter_round_sim(&mut state, 0, 5, 10, 15);
            quarter_round_sim(&mut state, 1, 6, 11, 12);
            quarter_round_sim(&mut state, 2, 7, 8, 13);
            quarter_round_sim(&mut state, 3, 4, 9, 14);
        }
        state[0] = std::hint::black_box(state[0]).wrapping_add(round as u32);
    }
    std::hint::black_box(&state);
}

#[inline(always)]
fn quarter_round_sim(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = std::hint::black_box(s[a].wrapping_add(s[b]));
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = std::hint::black_box(s[c].wrapping_add(s[d]));
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = std::hint::black_box(s[a].wrapping_add(s[b]));
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = std::hint::black_box(s[c].wrapping_add(s[d]));
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

// ---------------------------------------------------------------------------
// Benchmark persistence — save/load from ~/.zkminer/benchmarks.json
// ---------------------------------------------------------------------------

/// Benchmark suite version, derived from the benchmark program definitions.
/// Automatically invalidates cached results when programs, weights, or
/// reference throughputs change — no manual version bumps needed.
///
/// Uses a hand-rolled FNV-1a hash instead of `DefaultHasher` because
/// `DefaultHasher` is explicitly not guaranteed to be stable across Rust
/// releases — a toolchain upgrade would unnecessarily invalidate caches.
pub fn suite_version() -> String {
    // FNV-1a 64-bit — simple, fast, stable across all platforms/versions.
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut h = FNV_OFFSET;
    for p in &BENCHMARK_PROGRAMS {
        for b in p.name.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        for b in p.weight.to_bits().to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        for b in p.reference_throughput.to_bits().to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        let pre = if p.precompile { 1u8 } else { 0u8 };
        h ^= pre as u64;
        h = h.wrapping_mul(FNV_PRIME);
        for b in p.simulated_cycles.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
    }
    format!("v2-{h:016x}")
}

/// On-disk benchmark cache with hardware fingerprint for staleness detection.
#[derive(serde::Serialize, serde::Deserialize)]
struct SavedBenchmark {
    #[serde(default)]
    suite_version: String,
    hardware_fingerprint: String,
    suite: BenchmarkSuite,
}

/// Build a hardware fingerprint from CPU, RAM, and GPU information.
///
/// Format: `"{cpu_model}|{cores}|{ram_bytes}|{gpu_summary}"`
///
/// The GPU summary includes model names, count, and driver version so that
/// adding/removing/swapping a GPU or updating drivers invalidates the cache.
///
/// Only tracks physical hardware — backend/worker state is excluded because
/// subprocess workers may not be healthy yet at cache-load time, causing
/// spurious fingerprint mismatches and unnecessary re-benchmarking.
pub fn hardware_fingerprint() -> String {
    let cpu = get_cpu_info();
    let cores = get_cpu_cores();
    // Bucket RAM to whole GiB. `MemTotal` is not stable across reboots — the kernel
    // reserves a slightly different amount each boot — so comparing raw bytes made the
    // fingerprint mismatch on EVERY reboot and silently discarded the benchmark cache.
    // Observed live: 39_936_479_232 -> 39_936_471_040, an 8 KiB drift out of 37 GiB, which
    // threw away a ~10-minute `--calibrate` run and dropped proving back to the SDK's
    // default segment size with only an INFO line to show for it.
    // A real RAM change (adding/removing a DIMM) moves this by whole GiB and is still caught.
    let ram_gib = get_total_memory_bytes() / (1024 * 1024 * 1024);
    let gpu = gpu_fingerprint();
    format!("{cpu}|{cores}|{ram_gib}GiB|{gpu}")
}

/// Build the GPU portion of the hardware fingerprint.
///
/// Detects GPUs via nvidia-smi and sysfs (same sources as discovery.rs)
/// and includes model names, count, and driver version.
fn gpu_fingerprint() -> String {
    let mut parts: Vec<String> = Vec::new();

    // NVIDIA: query model names and driver version. Bounded — this runs at startup to decide
    // whether the benchmark cache is still valid, so an unbounded fork here hangs the miner
    // before it does anything.
    {
        let (outcome, text) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
            std::process::Command::new("nvidia-smi").args([
                "--query-gpu=name,driver_version",
                "--format=csv,noheader,nounits",
            ]),
            NVIDIA_SMI_FINGERPRINT_TIMEOUT,
            64 * 1024,
        );
        // A TIMEOUT is not "no NVIDIA GPU". Folding the two together is wrong in both
        // directions: it discards a cached suite (and its po2 calibration) over a momentary
        // driver stall, and — worse — it writes the same `none` fingerprint a GPU-less box
        // writes, so a suite saved while the driver was wedged later MATCHES a box with no GPU
        // at all and its calibration is adopted for absent hardware.
        //
        // EVERY non-answer, not just a timeout: a transient spawn failure (EAGAIN/ENOMEM, which
        // this project calls the normal condition on a box with 25 GB provers), an absent
        // nvidia-smi in a CUDA container that `sp1_usability` explicitly supports, and `Unsettled`
        // all previously fell through to the GPU-less marker. Both directions of the original
        // defect were still open: a pressured start discarded a valid cache, and a suite saved
        // under that marker later MATCHED a box with no GPU at all.
        if !matches!(
            outcome,
            zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
        ) {
            parts.push(format!("nv:unknown({})", short_outcome(&outcome)));
        } else if matches!(
            outcome,
            zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
        ) {
            for line in text.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    parts.push(format!("nv:{line}"));
                }
            }
        }
    }

    // AMD: enumerate discrete GPUs with model names and driver version
    let drm = std::path::Path::new("/sys/class/drm");
    if drm.is_dir() {
        let mut amd_names: Vec<String> = Vec::new();
        let mut sorted_entries: Vec<_> = std::fs::read_dir(drm)
            .into_iter()
            .flatten()
            .flatten()
            .collect();
        sorted_entries.sort_by_key(|e| e.file_name());

        for entry in &sorted_entries {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with("card") || name_str.contains('-') {
                continue;
            }
            let device_dir = entry.path().join("device");
            let vendor_path = device_dir.join("vendor");
            if let Ok(v) = std::fs::read_to_string(&vendor_path) {
                if v.trim().to_lowercase() == "0x1002" {
                    // Check it has VRAM (skip iGPUs)
                    let vram_path = device_dir.join("mem_info_vram_total");
                    if let Ok(vram_str) = std::fs::read_to_string(&vram_path) {
                        if let Ok(vram) = vram_str.trim().parse::<u64>() {
                            if vram > 0 {
                                // Read GPU model name
                                let gpu_name =
                                    std::fs::read_to_string(device_dir.join("product_name"))
                                        .or_else(|_| {
                                            std::fs::read_to_string(device_dir.join("device"))
                                                .map(|d| format!("AMD({})", d.trim()))
                                        })
                                        .unwrap_or_else(|_| "AMD GPU".to_string())
                                        .trim()
                                        .to_string();
                                amd_names.push(gpu_name);
                            }
                        }
                    }
                }
            }
        }
        if !amd_names.is_empty() {
            // Read amdgpu driver version
            let driver_ver = std::fs::read_to_string("/sys/module/amdgpu/version")
                .unwrap_or_default()
                .trim()
                .to_string();
            for name in &amd_names {
                parts.push(format!("amd:{name},drv={driver_ver}"));
            }
        }
    }

    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.sort();
        parts.join(";")
    }
}

/// Read total physical memory in bytes from `/proc/meminfo`.
///
/// Returns 0 on non-Linux or if the file can't be parsed.
pub fn get_total_memory_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
            for line in contents.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    // Format: "MemTotal:       16384000 kB"
                    let rest = rest.trim();
                    if let Some(kb_str) =
                        rest.strip_suffix("kB").or_else(|| rest.strip_suffix("KB"))
                    {
                        if let Ok(kb) = kb_str.trim().parse::<u64>() {
                            return kb * 1024;
                        }
                    }
                }
            }
        }
    }
    0
}

/// Returns the path to the benchmark cache file: `~/.zkminer/benchmarks.json`.
pub fn benchmark_cache_path() -> PathBuf {
    zkminer_config::ZkMinerConfig::default_dir().join("benchmarks.json")
}

/// Load cached benchmarks from disk, verifying the hardware fingerprint.
///
/// Returns `None` if the file is missing, corrupt, or the hardware has changed.
pub fn load_cached_benchmark() -> Option<BenchmarkSuite> {
    load_cached_benchmark_from(
        &benchmark_cache_path(),
        &suite_version(),
        &hardware_fingerprint(),
    )
}

/// The body of `load_cached_benchmark`, with its three environmental inputs injected.
///
/// Split out so the WIRING is testable, not merely the helpers. `floor_implausible_gpu_power`
/// and `migrate_device_identity` both had unit tests and neither had a test proving this
/// function calls them — so deleting a call here left the suite green while the 8.5 W cache
/// loaded untouched and the cost model priced proving at 148 W against ~872 W measured.
pub(crate) fn load_cached_benchmark_from(
    path: &std::path::Path,
    current_version: &str,
    current_fp: &str,
) -> Option<BenchmarkSuite> {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => return None,
    };

    let saved: SavedBenchmark = match serde_json::from_str(&data) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Corrupt benchmark cache, will re-benchmark: {e}");
            return None;
        }
    };

    if saved.suite_version != current_version {
        tracing::info!(
            "Benchmark suite version changed ({:?} -> {current_version}), re-benchmarking needed",
            if saved.suite_version.is_empty() {
                "none"
            } else {
                &saved.suite_version
            },
        );
        return None;
    }

    if saved.hardware_fingerprint != current_fp {
        tracing::info!(
            "Hardware changed (saved: {}, current: {current_fp}), re-benchmarking needed",
            saved.hardware_fingerprint,
        );
        return None;
    }

    let mut suite = saved.suite;
    migrate_device_identity(&mut suite);
    floor_implausible_gpu_power(&mut suite);
    Some(suite)
}

/// The lowest GPU draw that can plausibly be a PROVING measurement.
///
/// An idle discrete card reports ~15-25 W and a proving one 200-500 W, so a stored figure below
/// this did not measure proving. 40 W keeps clear of an idle discrete card while staying under
/// anything that could be a real proving draw.
///
/// Two honest limits. It is a floor, not a detector: an idle-draw reading in the 40-200 W band
/// from the same old bug passes untouched and still under-charges several-fold. And a genuinely
/// low-power proving device — an Intel iGPU or Arc part, which `gpu_env` does support — can draw
/// under 40 W legitimately; such a reading is used as measured for the session that takes it and
/// floored on the next start, so the two disagree. Both are preferable to the alternative, which
/// is pricing a 450 W card at 8.5 W.
const MIN_PLAUSIBLE_GPU_WATTS: f64 = 40.0;

/// Replace an implausible stored GPU power with the fallback.
///
/// The power fix is write-time: it corrects what a NEW benchmark records. It does nothing for a
/// suite already on disk — and the cache on this box carries `power_watts: 8.5` on both GPU
/// rows, which is an idle AMD card's draw stamped onto every row by the bug being fixed. If the
/// hardware fingerprint still matched, that file would load unchanged and the cost model would
/// charge 65 + 8.5 + 75 = 148 W against ~872 W at the wall: the headline bug, still live, from a
/// file nothing looks at. Neither `suite_version` (which hashes only the program list) nor
/// `migrate_device_identity` (which touches only identity) notices.
///
/// Floor rather than invalidate, deliberately: these rows carry po2 calibration that costs real
/// GPU time to reproduce, and discarding them drops proving back to the SDK-default segment
/// size. The power column is the only part that is wrong, and `FALLBACK_GPU_WATTS` is the same
/// value a fresh benchmark would record for a card it could not measure.
fn floor_implausible_gpu_power(suite: &mut BenchmarkSuite) {
    let mut fixed = Vec::new();
    for d in &mut suite.device_benchmarks {
        if d.device_id == CPU_DEVICE_ID {
            continue;
        }
        if d.power_watts < MIN_PLAUSIBLE_GPU_WATTS {
            fixed.push(format!("{} ({:.1}W)", d.device_id, d.power_watts));
            d.power_watts = FALLBACK_GPU_WATTS;
        }
    }
    if !fixed.is_empty() {
        tracing::warn!(
            "cached benchmark carries implausible GPU power for {} — raising to \
             {FALLBACK_GPU_WATTS:.0}W so the cost model does not price proving as nearly free. \
             Re-benchmark to record real figures.",
            fixed.join(", ")
        );
        // The suite-level total is derived from the same readings, so it is wrong too — clear it
        // unconditionally. The previous condition compared a PER-CARD threshold against a
        // multi-card SUM, so four cards at 8.5 W (sum 34) cleared it while ten (sum 85) kept a
        // figure this function had just declared bogus. Display-only, but the comment claimed
        // what the code did not do.
        suite.gpu_power_watts = None;
    }
}

/// Backfill `pci_bus_id` on GPU rows written before that field existed, and
/// re-key any row whose `device_id` no longer matches the slot its card occupies.
///
/// Migrate rather than invalidate: these rows carry measured po2 calibration that
/// costs real GPU time to reproduce, and discarding the cache silently drops
/// proving back to the SDK-default segment size. A row is only dropped when its
/// identity cannot be established at all.
///
/// Matching is by GPU model name embedded in `device_label`, and only when
/// exactly one current card and one legacy row agree -- on a box with two
/// identical cards the name is ambiguous, and guessing there would reintroduce
/// the very misattribution this is fixing.
fn migrate_device_identity(suite: &mut BenchmarkSuite) {
    let live = crate::discovery::detect_all_gpus();
    if live.is_empty() {
        return;
    }

    for gpu in &live {
        let want = normalize_gpu_name_for_match(&gpu.name);
        if want.is_empty() {
            continue;
        }
        let correct_id = crate::dispatcher::WorkerPool::gpu_device_id(
            &gpu.gpu_tag,
            &gpu.device_index.to_string(),
        );

        // Only rows that carry no identity yet are candidates.
        let matches: Vec<usize> = suite
            .device_benchmarks
            .iter()
            .enumerate()
            .filter(|(_, d)| {
                d.pci_bus_id.is_empty()
                    && d.device_id.starts_with("gpu")
                    && normalize_gpu_name_for_match(&d.device_label).contains(&want)
            })
            .map(|(i, _)| i)
            .collect();

        // Ambiguous when the legacy rows under this name span more than one
        // device_id -- several backends for ONE card is the normal case.
        let distinct: std::collections::BTreeSet<&str> = matches
            .iter()
            .map(|i| suite.device_benchmarks[*i].device_id.as_str())
            .collect();
        if distinct.len() != 1 {
            continue;
        }

        for i in matches {
            let d = &mut suite.device_benchmarks[i];
            if d.device_id != correct_id {
                tracing::info!(
                    "Benchmark cache: re-keying {} -> {} ({}, {})",
                    d.device_id,
                    correct_id,
                    gpu.name,
                    gpu.pci_bus_id
                );
                d.device_id = correct_id.clone();
            }
            d.pci_bus_id = gpu.pci_bus_id.clone();
        }
    }
}

/// Name normalization for cache migration. Mirrors the TUI's matching so both
/// sides agree on whether two spellings denote the same card.
fn normalize_gpu_name_for_match(s: &str) -> String {
    s.to_lowercase()
        .replace("nvidia", " ")
        .replace("geforce", " ")
        .replace("advanced micro devices", " ")
        .replace("amd", " ")
        .replace("intel", " ")
        .replace(['(', ')', ',', '-', '_'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Save benchmark results to disk alongside the current hardware fingerprint.
pub fn save_benchmark(suite: &BenchmarkSuite) {
    let saved = SavedBenchmark {
        suite_version: suite_version(),
        hardware_fingerprint: hardware_fingerprint(),
        suite: suite.clone(),
    };

    let path = benchmark_cache_path();

    // Ensure the directory exists
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::error!("Failed to create benchmark cache directory: {e}");
            return;
        }
    }

    // TMP + RENAME, not an in-place truncating write.
    //
    // This is the one process on the box the kernel OOM-killer deliberately targets
    // (`oom_score_adj = 800` on the workers, and the miner shares their fate when the host is
    // short). A kill partway through an O_TRUNC write leaves invalid JSON, and the loader's
    // response is a hard discard — so one badly timed kill threw away every measured
    // `host_peak_bytes` and hours of po2 calibration, reported as a single WARN at the next start.
    // `rename` within a directory is atomic, so a reader sees either the old file or the new one.
    // `JobJournal::save_to` next door already does exactly this.
    match serde_json::to_string_pretty(&saved) {
        Ok(json) => {
            // A UNIQUE temp name, not a fixed one. Two savers can overlap — the TUI's `[b]` and a
            // calibrate pass — and with a shared `benchmarks.json.tmp` they interleave into one file
            // and rename a torn result, while the error path below deletes the other writer's temp.
            let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
            // fsync the handle we actually WROTE. The first version reopened the file `O_RDONLY` and
            // synced that, which syncs nothing we care about and whose result was discarded anyway.
            let written = std::fs::File::create(&tmp).and_then(|mut f| {
                use std::io::Write;
                f.write_all(json.as_bytes())?;
                f.sync_all()
            });
            if let Err(e) = written {
                tracing::error!("Failed to write benchmark cache temp file: {e}");
                let _ = std::fs::remove_file(&tmp);
                return;
            }
            if let Err(e) = std::fs::rename(&tmp, &path) {
                tracing::error!("Failed to install benchmark cache: {e}");
                let _ = std::fs::remove_file(&tmp);
            } else {
                // And the DIRECTORY, so the rename itself survives a power loss rather than only the
                // bytes it points at.
                if let Some(parent) = path.parent() {
                    if let Ok(d) = std::fs::File::open(parent) {
                        let _ = d.sync_all();
                    }
                }
                tracing::info!("Saved benchmarks to {}", path.display());
            }
        }
        Err(e) => {
            tracing::error!("Failed to serialize benchmark cache: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_tolerates_reboot_ram_drift() {
        // The fingerprint must not change for a few-KB MemTotal drift, or every reboot
        // silently discards the benchmark cache (observed live 2026-08-02: an 8 KiB
        // difference invalidated a 10-minute calibration run).
        let a = 39_936_479_232u64 / (1024 * 1024 * 1024);
        let b = 39_936_471_040u64 / (1024 * 1024 * 1024);
        assert_eq!(a, b, "KB-scale drift must bucket to the same GiB");
        // ...but a genuine DIMM change must still invalidate.
        let c = (39_936_479_232u64 + 8 * 1024 * 1024 * 1024) / (1024 * 1024 * 1024);
        assert_ne!(a, c, "a real 8 GiB change must still be detected");
    }

    #[test]
    fn weights_sum_to_one() {
        let sum: f64 = BENCHMARK_PROGRAMS.iter().map(|p| p.weight).sum();
        assert!(
            (sum - 1.0).abs() < 1e-9,
            "weights sum to {sum}, expected 1.0"
        );
    }

    #[test]
    fn six_programs_defined() {
        assert_eq!(BENCHMARK_PROGRAMS.len(), 6);
    }

    #[test]
    fn compute_zkops_baseline() {
        // If throughput == reference_throughput for all programs, score should be 100,000.
        let results: Vec<BenchmarkResult> = BENCHMARK_PROGRAMS
            .iter()
            .map(|p| BenchmarkResult {
                program_name: p.name.to_string(),
                prover_backend: "test".to_string(),
                cycles: p.simulated_cycles,
                duration: Duration::from_secs(1),
                throughput: p.reference_throughput,
                weight: p.weight,
                precompile: p.precompile,
            })
            .collect();
        let score = compute_zkops(&results);
        assert!(
            (score - 100_000.0).abs() < 1.0,
            "expected ~100,000 but got {score}"
        );
    }

    #[test]
    fn compute_zkops_missing_program_renormalizes() {
        // Missing one program should renormalize weights over the rest,
        // not return 0.0 — this supports SP1 workers that lack chacha-mix.
        let results: Vec<BenchmarkResult> = BENCHMARK_PROGRAMS[..5]
            .iter()
            .map(|p| BenchmarkResult {
                program_name: p.name.to_string(),
                prover_backend: "test".to_string(),
                cycles: p.simulated_cycles,
                duration: Duration::from_secs(1),
                throughput: p.reference_throughput,
                weight: p.weight,
                precompile: p.precompile,
            })
            .collect();
        // With 5 of 6 programs at baseline, renormalized score should still be ~100K
        let score = compute_zkops(&results);
        assert!(
            (score - 100_000.0).abs() < 1.0,
            "expected ~100,000 but got {score}"
        );
    }

    #[test]
    fn compute_zkops_double_speed() {
        // 2× throughput on all programs → 200,000 zkOP/s.
        let results: Vec<BenchmarkResult> = BENCHMARK_PROGRAMS
            .iter()
            .map(|p| BenchmarkResult {
                program_name: p.name.to_string(),
                prover_backend: "test".to_string(),
                cycles: p.simulated_cycles,
                duration: Duration::from_secs(1),
                throughput: p.reference_throughput * 2.0,
                weight: p.weight,
                precompile: p.precompile,
            })
            .collect();
        let score = compute_zkops(&results);
        assert!(
            (score - 200_000.0).abs() < 1.0,
            "expected ~200,000 but got {score}"
        );
    }

    #[test]
    fn simulated_benchmarks_run() {
        let results = run_simulated_benchmarks();
        assert_eq!(results.len(), BENCHMARK_PROGRAMS.len());
        for (r, p) in results.iter().zip(BENCHMARK_PROGRAMS.iter()) {
            assert_eq!(r.program_name, p.name);
            assert_eq!(r.prover_backend, "simulated");
            assert_eq!(r.cycles, p.simulated_cycles);
            assert!(r.throughput > 0.0);
            assert_eq!(r.weight, p.weight);
            assert_eq!(r.precompile, p.precompile);
        }
    }

    #[test]
    fn device_benchmarks_populated_by_run_benchmark() {
        // run_benchmark() should generate CPU device benchmarks for all 3 backends.
        let suite = run_benchmark();
        assert_eq!(
            suite.device_benchmarks.len(),
            3,
            "expected 3 CPU device benchmarks (risc0, sp1, openvm)"
        );
        for db in &suite.device_benchmarks {
            assert_eq!(db.device_id, "cpu");
            assert!(
                db.throughput > 0.0,
                "throughput for {} should be > 0",
                db.prover_backend
            );
            assert!(
                PROVER_BACKENDS.contains(&db.prover_backend.as_str()),
                "unexpected backend: {}",
                db.prover_backend
            );
        }
    }

    #[test]
    fn add_gpu_benchmarks_generates_entries() {
        let mut suite = run_benchmark();
        let gpus = [GpuDesc {
            index: 0,
            name: "RX 7900 XTX".to_string(),
            vram_bytes: 24 * 1024 * 1024 * 1024,
            power_watts: 355.0,
        }];
        add_gpu_device_benchmarks(&mut suite, &gpus);

        // Should now have 3 CPU + 2 GPU entries (risc0+sp1, no openvm GPU)
        assert_eq!(suite.device_benchmarks.len(), 5);

        let gpu_entries: Vec<_> = suite
            .device_benchmarks
            .iter()
            .filter(|d| d.device_id == "gpu0")
            .collect();
        assert_eq!(gpu_entries.len(), 2);

        // GPU entries should be faster than CPU entries for backends with GPU support
        for profile in &BACKEND_PROFILES {
            let Some(_) = profile.gpu_acceleration else {
                continue;
            };
            let cpu_tp = suite.throughput_for("cpu", profile.name).unwrap();
            let gpu_tp = suite.throughput_for("gpu0", profile.name).unwrap();
            assert!(
                gpu_tp > cpu_tp,
                "GPU should be faster than CPU for {}: gpu={:.0} cpu={:.0}",
                profile.name,
                gpu_tp,
                cpu_tp
            );
        }
    }

    #[test]
    fn risc0_gpu_faster_than_sp1_gpu() {
        let mut suite = run_benchmark();
        let gpus = [GpuDesc {
            index: 0,
            name: "Test GPU".to_string(),
            vram_bytes: 16 * 1024 * 1024 * 1024,
            power_watts: 300.0,
        }];
        add_gpu_device_benchmarks(&mut suite, &gpus);

        let risc0_tp = suite.throughput_for("gpu0", "risc0").unwrap();
        let sp1_tp = suite.throughput_for("gpu0", "sp1").unwrap();

        assert!(
            risc0_tp > sp1_tp,
            "risc0 GPU should be faster than sp1 GPU: risc0={:.0} sp1={:.0}",
            risc0_tp,
            sp1_tp
        );

        // OpenVM has no GPU prover — no entry should exist
        assert!(
            suite.throughput_for("gpu0", "openvm").is_none(),
            "OpenVM should not have GPU device benchmark entries"
        );
    }

    #[test]
    fn devices_for_backend_filters_correctly() {
        let mut suite = run_benchmark();
        let gpus = [
            GpuDesc {
                index: 0,
                name: "GPU A".to_string(),
                vram_bytes: 8 * 1024 * 1024 * 1024,
                power_watts: 200.0,
            },
            GpuDesc {
                index: 1,
                name: "GPU B".to_string(),
                vram_bytes: 16 * 1024 * 1024 * 1024,
                power_watts: 300.0,
            },
        ];
        add_gpu_device_benchmarks(&mut suite, &gpus);

        let risc0_devices = suite.devices_for_backend("risc0");
        assert_eq!(risc0_devices.len(), 3); // cpu + gpu0 + gpu1

        let unknown_devices = suite.devices_for_backend("nonexistent");
        assert!(unknown_devices.is_empty());
    }

    #[test]
    fn po2_memory_doubles_each_step() {
        let m18 = estimate_po2_memory(18, "risc0", false);
        let m19 = estimate_po2_memory(19, "risc0", false);
        let m20 = estimate_po2_memory(20, "risc0", false);
        assert_eq!(m19, m18 * 2);
        assert_eq!(m20, m18 * 4);
    }

    #[test]
    fn po2_memory_gpu_lower_base() {
        let cpu = estimate_po2_memory(18, "risc0", false);
        let gpu = estimate_po2_memory(18, "risc0", true);
        assert_eq!(cpu, 512 * 1024 * 1024);
        assert_eq!(gpu, 256 * 1024 * 1024);
    }

    #[test]
    fn po2_memory_backend_multiplier() {
        let risc0 = estimate_po2_memory(20, "risc0", false);
        let sp1 = estimate_po2_memory(20, "sp1", false);
        let openvm = estimate_po2_memory(20, "openvm", false);
        assert!(sp1 > risc0, "sp1 should use more memory than risc0");
        assert!(openvm > sp1, "openvm should use more memory than sp1");
    }

    #[test]
    fn po2_throughput_increases() {
        for po2 in PO2_MIN..PO2_MAX {
            let f1 = po2_throughput_factor(po2);
            let f2 = po2_throughput_factor(po2 + 1);
            assert!(
                f2 > f1,
                "throughput should increase from po2={po2} to {}",
                po2 + 1
            );
        }
    }

    #[test]
    fn po2_throughput_diminishing_returns() {
        // Gap between 22->23 should be smaller than 20->21
        let gap_low = po2_throughput_factor(21) - po2_throughput_factor(20);
        let gap_high = po2_throughput_factor(23) - po2_throughput_factor(22);
        assert!(
            gap_high < gap_low,
            "diminishing returns above po2=22: gap_low={gap_low:.4} gap_high={gap_high:.4}"
        );
    }

    #[test]
    fn find_optimal_po2_small_memory() {
        // 1 GB should fit po2=18 (512 MB) but not po2=19 (1024 MB) for CPU risc0
        // Budget = 1GB * 0.9 = 921 MB
        let (po2, mem) = find_optimal_po2(1024 * 1024 * 1024, "risc0", false);
        assert_eq!(po2, 18, "1 GB CPU should get po2=18");
        assert_eq!(mem, 512 * 1024 * 1024);
    }

    #[test]
    fn find_optimal_po2_large_memory() {
        // 64 GB should fit high po2 values
        let (po2, _mem) = find_optimal_po2(64 * 1024 * 1024 * 1024, "risc0", false);
        assert!(po2 >= 23, "64 GB CPU should get po2>=23, got {po2}");
    }

    #[test]
    fn find_optimal_po2_gpu_8gb() {
        // 8 GB GPU, risc0: base=256MB at po2=18, 512MB at 19, 1GB at 20, 2GB at 21, 4GB at 22
        // Budget = 8GB * 0.9 = 7.2 GB → po2=22 (4 GB) fits, po2=23 (8 GB) doesn't
        let (po2, _mem) = find_optimal_po2(8 * 1024 * 1024 * 1024, "risc0", true);
        assert!(
            po2 == 22 || po2 == 23,
            "8 GB GPU risc0 should get po2=22 or 23, got {po2}"
        );
    }

    #[test]
    fn device_benchmarks_have_po2_fields() {
        let suite = run_benchmark();
        for db in &suite.device_benchmarks {
            assert!(
                db.optimal_po2 >= PO2_MIN && db.optimal_po2 <= PO2_MAX,
                "optimal_po2 {} out of range for {}",
                db.optimal_po2,
                db.prover_backend
            );
            assert!(
                db.memory_usage_bytes > 0,
                "memory_usage_bytes should be > 0"
            );
            assert_eq!(db.optimal_po2, db.max_feasible_po2);
        }
    }

    // ---- is_simulated tests ----

    fn make_result(backend: &str) -> BenchmarkResult {
        BenchmarkResult {
            program_name: "test".to_string(),
            prover_backend: backend.to_string(),
            cycles: 1000,
            duration: Duration::from_millis(100),
            throughput: 10_000.0,
            weight: 0.20,
            precompile: false,
        }
    }

    #[test]
    fn is_simulated_all_simulated() {
        let suite = BenchmarkSuite {
            results: vec![make_result("simulated"), make_result("simulated")],
            ..Default::default()
        };
        assert!(suite.is_simulated());
    }

    #[test]
    fn is_simulated_all_real() {
        let suite = BenchmarkSuite {
            results: vec![make_result("risc0"), make_result("risc0")],
            ..Default::default()
        };
        assert!(!suite.is_simulated());
    }

    #[test]
    fn is_simulated_mixed() {
        let suite = BenchmarkSuite {
            results: vec![make_result("simulated"), make_result("risc0")],
            ..Default::default()
        };
        assert!(
            !suite.is_simulated(),
            "mixed results should not be considered simulated"
        );
    }

    #[test]
    fn is_simulated_empty() {
        let suite = BenchmarkSuite::default();
        assert!(
            !suite.is_simulated(),
            "empty results should not be considered simulated"
        );
    }

    // ---- GPU acceleration constants ----

    #[test]
    fn gpu_acceleration_excludes_openvm() {
        // OpenVM has no GPU prover — phantom entries must not be generated.
        for profile in &BACKEND_PROFILES {
            if profile.name == "openvm" {
                assert!(
                    profile.gpu_acceleration.is_none(),
                    "OpenVM should not have GPU acceleration"
                );
            }
        }
    }

    // ---- average_throughput excludes zero-weight ----

    #[test]
    fn average_throughput_excludes_zero_weight() {
        // Programs with weight 0.0 should not dilute the average
        let suite = BenchmarkSuite {
            results: vec![
                BenchmarkResult {
                    program_name: "fibonacci".to_string(),
                    prover_backend: "risc0".to_string(),
                    cycles: 65_000,
                    duration: Duration::from_millis(10),
                    throughput: 6_500_000.0, // 6.5M c/s
                    weight: 0.15,
                    precompile: false,
                },
                BenchmarkResult {
                    program_name: "chacha-mix".to_string(),
                    prover_backend: "risc0".to_string(),
                    cycles: 34_000_000,
                    duration: Duration::from_secs(5),
                    throughput: 100.0, // artificially low — should be excluded
                    weight: 0.0,
                    precompile: false,
                },
            ],
            ..Default::default()
        };
        // Should average only the canonical program (6.5M), not be dragged down by chacha-mix (100)
        let avg = suite.average_throughput();
        assert!(avg > 6_000_000.0, "average should be ~6.5M, got {avg}");
    }

    #[test]
    fn average_throughput_all_zero_weight_returns_zero() {
        let suite = BenchmarkSuite {
            results: vec![BenchmarkResult {
                program_name: "chacha-mix".to_string(),
                prover_backend: "risc0".to_string(),
                cycles: 34_000_000,
                duration: Duration::from_secs(5),
                throughput: 6_800_000.0,
                weight: 0.0,
                precompile: false,
            }],
            ..Default::default()
        };
        assert_eq!(suite.average_throughput(), 0.0);
    }

    // ---- memory-merkle precompile flag ----

    #[test]
    fn memory_merkle_is_precompile() {
        let mm = BENCHMARK_PROGRAMS
            .iter()
            .find(|p| p.name == "memory-merkle")
            .unwrap();
        assert!(
            mm.precompile,
            "memory-merkle uses sha2 crate which triggers SHA-256 precompile"
        );
    }

    // ---- suite_version is content-addressable ----

    #[test]
    fn suite_version_deterministic() {
        let v1 = suite_version();
        let v2 = suite_version();
        assert_eq!(v1, v2, "suite_version should be deterministic");
        assert!(
            v1.starts_with("v2-"),
            "suite_version should start with 'v2-'"
        );
        assert!(v1.len() > 10, "suite_version should include a hash");
    }

    // ---- category sub-scores ----

    #[test]
    fn category_scores_at_baseline() {
        let results: Vec<BenchmarkResult> = BENCHMARK_PROGRAMS
            .iter()
            .map(|p| BenchmarkResult {
                program_name: p.name.to_string(),
                prover_backend: "risc0".to_string(),
                cycles: p.simulated_cycles,
                duration: Duration::from_secs(1),
                throughput: p.reference_throughput, // exactly baseline
                weight: p.weight,
                precompile: p.precompile,
            })
            .collect();
        let (pre, comp) = compute_category_scores(&results);
        assert!(
            (pre - 1.0).abs() < 0.01,
            "precompile at baseline should be 1.0, got {pre}"
        );
        assert!(
            (comp - 1.0).abs() < 0.01,
            "compute at baseline should be 1.0, got {comp}"
        );
    }

    #[test]
    fn category_scores_double_precompile() {
        // 2x precompile throughput, 1x compute
        let results: Vec<BenchmarkResult> = BENCHMARK_PROGRAMS
            .iter()
            .map(|p| BenchmarkResult {
                program_name: p.name.to_string(),
                prover_backend: "risc0".to_string(),
                cycles: p.simulated_cycles,
                duration: Duration::from_secs(1),
                throughput: if p.precompile {
                    p.reference_throughput * 2.0
                } else {
                    p.reference_throughput
                },
                weight: p.weight,
                precompile: p.precompile,
            })
            .collect();
        let (pre, comp) = compute_category_scores(&results);
        assert!(
            (pre - 2.0).abs() < 0.01,
            "precompile should be 2.0x, got {pre}"
        );
        assert!(
            (comp - 1.0).abs() < 0.01,
            "compute should be 1.0x, got {comp}"
        );
    }

    // ---- compute_zkops renormalization ----

    #[test]
    fn compute_zkops_empty_returns_zero() {
        assert_eq!(compute_zkops(&[]), 0.0);
    }

    #[test]
    fn compute_zkops_single_program_renormalizes() {
        // A single program at baseline should still produce 100K after renormalization.
        let p = &BENCHMARK_PROGRAMS[0]; // fibonacci
        let results = vec![BenchmarkResult {
            program_name: p.name.to_string(),
            prover_backend: "test".to_string(),
            cycles: p.simulated_cycles,
            duration: Duration::from_secs(1),
            throughput: p.reference_throughput,
            weight: p.weight,
            precompile: p.precompile,
        }];
        let score = compute_zkops(&results);
        assert!(
            (score - 100_000.0).abs() < 1.0,
            "single program at baseline should renormalize to ~100K, got {score}"
        );
    }

    // ---- throughput_cov tests ----

    #[test]
    fn throughput_cov_empty() {
        let db = DeviceBenchmark {
            program_stages: Vec::new(),
            device_id: "test".into(),
            device_label: "test".into(),
            prover_backend: "risc0".into(),
            throughput: 0.0,
            power_watts: 0.0,
            optimal_po2: 18,
            memory_usage_bytes: 0,
            max_feasible_po2: 18,
            program_throughputs: std::collections::HashMap::new(),
            pci_bus_id: String::new(),
            po2_samples: Vec::new(),
            host_peak_bytes: None,
        };
        assert_eq!(db.throughput_cov(), 0.0);
    }

    #[test]
    fn throughput_cov_uniform() {
        let mut tp = std::collections::HashMap::new();
        tp.insert("a".into(), 1000.0);
        tp.insert("b".into(), 1000.0);
        tp.insert("c".into(), 1000.0);
        let db = DeviceBenchmark {
            program_stages: Vec::new(),
            device_id: "test".into(),
            device_label: "test".into(),
            prover_backend: "risc0".into(),
            throughput: 1000.0,
            power_watts: 0.0,
            optimal_po2: 18,
            memory_usage_bytes: 0,
            max_feasible_po2: 18,
            program_throughputs: tp,
            pci_bus_id: String::new(),
            po2_samples: Vec::new(),
            host_peak_bytes: None,
        };
        assert_eq!(db.throughput_cov(), 0.0);
    }

    #[test]
    fn throughput_cov_known_spread() {
        let mut tp = std::collections::HashMap::new();
        tp.insert("a".into(), 100.0);
        tp.insert("b".into(), 200.0);
        // mean = 150, stddev = 50, cov = 50/150 = 0.333...
        let db = DeviceBenchmark {
            program_stages: Vec::new(),
            device_id: "test".into(),
            device_label: "test".into(),
            prover_backend: "risc0".into(),
            throughput: 150.0,
            power_watts: 0.0,
            optimal_po2: 18,
            memory_usage_bytes: 0,
            max_feasible_po2: 18,
            program_throughputs: tp,
            pci_bus_id: String::new(),
            po2_samples: Vec::new(),
            host_peak_bytes: None,
        };
        let cov = db.throughput_cov();
        assert!((cov - 0.333).abs() < 0.01, "expected ~0.333, got {cov}");
    }

    // ---- GPU power is measured per card, for both vendors ----

    /// nvidia-smi power was never read at all: the reader was AMD-hwmon-only, documented as
    /// "NVIDIA power comes from NVML" — and nothing ever came from NVML. On an all-NVIDIA
    /// box every reading failed, so every device row carried the 300 W fallback and the
    /// suite stored `gpu_power_watts: None` while two cards drew a measured ~840 W.
    #[test]
    fn nvidia_power_is_read_for_proving_cards_only() {
        let csv = "00000000:06:10.0, 341.52\n00000000:06:1B.0, 455.10\n00000000:0A:00.0, 22.57\n";
        let proving = vec!["0000:06:10.0".to_string(), "0000:06:1b.0".to_string()];
        let got = super::parse_nvidia_power_csv(csv, &proving);
        assert_eq!(
            got,
            vec![
                ("0000:06:10.0".to_string(), 341.52),
                ("0000:06:1b.0".to_string(), 455.10),
            ],
            "only the cards the prover is using may be charged to a proof"
        );
    }

    /// nvidia-smi prints an 8-digit PCI domain; sysfs and the dispatcher use 4. Without
    /// normalization no row ever matches a proving bus id, and the reader silently reports
    /// nothing on a machine it can read perfectly — the exact failure mode this replaces.
    #[test]
    fn nvidia_bus_ids_are_normalized_before_the_join() {
        let got = super::parse_nvidia_power_csv(
            "00000000:06:10.0, 100.0\n",
            &["0000:06:10.0".to_string()],
        );
        assert_eq!(
            got.len(),
            1,
            "the 8-vs-4 digit domain must not break the join"
        );
    }

    /// A card that cannot report power prints `[N/A]`. That must be ABSENT, not 0 W: a 0 W
    /// card makes a proof look free, and free proofs are always worth claiming.
    #[test]
    fn an_unreportable_card_is_absent_not_zero() {
        let csv = "00000000:06:10.0, [N/A]\n00000000:06:1B.0, [Not Supported]\n";
        let proving = vec!["0000:06:10.0".to_string(), "0000:06:1b.0".to_string()];
        assert!(
            super::parse_nvidia_power_csv(csv, &proving).is_empty(),
            "an unmeasurable card must fall back, never be charged at 0 W"
        );
        // And the same for a nonsensical zero.
        assert!(super::parse_nvidia_power_csv(
            "00000000:06:10.0, 0.00\n",
            &["0000:06:10.0".to_string()]
        )
        .is_empty());
    }

    /// The one check that can catch a wrong `--query-gpu` argument list: run the real command
    /// against the real cards. Skips (rather than fails) where there is no NVIDIA GPU, so it is
    /// a no-op in CI and a real assertion on a prover box.
    ///
    /// Everything else about this reader is unit-tested through `parse_nvidia_power_csv`, which
    /// cannot see the flags. Dropping `nounits`, or swapping the two columns, would leave every
    /// parser test green while silently reporting no power at all.
    #[test]
    fn nvidia_smi_reports_power_for_a_real_card_on_this_host() {
        // Ask the driver directly for the bus ids, through the same normalization the join
        // uses, so this does not depend on a worker pool being initialised.
        // Gate on nvidia-smi SPECIFICALLY, not on `detect_all_gpus`: that falls back to
        // /proc/driver/nvidia/gpus, which populates a bus id on a host that has the kernel driver
        // and no `nvidia-smi` binary at all — the CUDA-container case production deliberately
        // supports. There the correct behaviour is the fallback wattage, and this test would have
        // failed while blaming the --query-gpu arguments.
        let nvidia: Vec<String> = match crate::discovery::detect_nvidia_via_smi_for_test() {
            Some(gpus) => gpus
                .into_iter()
                .map(|g| g.pci_bus_id)
                .filter(|b: &String| !b.is_empty())
                .collect(),
            None => Vec::new(),
        };
        if nvidia.is_empty() {
            eprintln!("nvidia-smi reports no card — skipping the live power check");
            return;
        }
        let sample = super::read_gpu_power_by_card(&nvidia);
        assert!(
            !sample.probe_failed,
            "nvidia-smi did not answer at all; the --query-gpu arguments or the bound are wrong"
        );
        let per_card = sample.per_card;
        assert!(
            !per_card.is_empty(),
            "nvidia-smi reported no power for any of {nvidia:?}. Either the --query-gpu \
             arguments are wrong, or the bus-id join is broken — both of which make every \
             device row fall back to {FALLBACK_GPU_WATTS}W and the suite store None."
        );
        for bus in &nvidia {
            let watts = per_card.get(bus).copied().unwrap_or_else(|| {
                panic!("nvidia-smi reported no power for {bus}; per_card = {per_card:?}")
            });
            assert!(
                watts > 0.0 && watts < 2_000.0,
                "implausible draw for {bus}: {watts}W"
            );
        }
    }

    /// Each device row must carry ITS OWN card's draw. The old code passed one figure — the
    /// SUM over every proving card — and stamped it on every row, so on a two-card box each
    /// row claimed the whole machine's GPU power and a per-device cost estimate doubled.
    #[test]
    fn each_device_row_takes_its_own_cards_power() {
        let mut a = gpu_slot(Some(32 << 30));
        a.pci_bus_id = Some("0000:06:10.0".to_string());
        let mut b = gpu_slot(Some(24 << 30));
        b.slot_key = "risc0:cuda:1".to_string();
        b.device_index = Some(1);
        b.pci_bus_id = Some("0000:06:1b.0".to_string());
        // A third card the reader could not measure at all.
        let mut c = gpu_slot(Some(16 << 30));
        c.slot_key = "risc0:cuda:2".to_string();
        c.device_index = Some(2);
        c.pci_bus_id = Some("0000:0a:00.0".to_string());

        let per_card = BTreeMap::from([
            ("0000:06:10.0".to_string(), 341.5),
            ("0000:06:1b.0".to_string(), 455.1),
        ]);
        let rows = build_gpu_device_benchmarks_from_workers(&[a, b, c], &per_card);
        assert_eq!(rows.len(), 3);
        let by_bus: std::collections::HashMap<_, _> = rows
            .iter()
            .map(|r| (r.pci_bus_id.as_str(), r.power_watts))
            .collect();
        assert_eq!(by_bus["0000:06:10.0"], 341.5);
        assert_eq!(by_bus["0000:06:1b.0"], 455.1);
        assert_eq!(
            by_bus["0000:0a:00.0"], FALLBACK_GPU_WATTS,
            "an unmeasured card takes the fallback, NOT another card's reading"
        );
    }

    /// The suite-level figure is the TOTAL over the cards we measured, and `None` when we
    /// measured none — which is what makes a device row fall back to `FALLBACK_GPU_WATTS`
    /// instead of being charged an implausible figure.
    ///
    /// The previous version of this test built a local map, summed it, and asserted
    /// `341.5 + 455.1 ≈ 796.6`. It called no production code at all: it tested `f64` addition
    /// while claiming to pin "the suite figure and the rows can never disagree".
    #[test]
    fn the_suite_total_sums_the_measured_cards() {
        let per_card = BTreeMap::from([
            ("0000:06:10.0".to_string(), 341.5),
            ("0000:06:1b.0".to_string(), 455.1),
        ]);
        let total = super::suite_total_watts(&per_card).expect("two measured cards");
        assert!((total - 796.6).abs() < 0.01, "got {total}");

        // Nothing measured must be None, not 0.0: a 0 W box would make every proof free.
        assert_eq!(super::suite_total_watts(&BTreeMap::new()), None);
    }

    /// Sampling cadence for tests: the production 2s interval would make every one of these
    /// run for seconds, and the cadence is not what they are about.
    const TEST_INTERVAL: Duration = Duration::from_millis(20);

    /// The PEAK fold, through the production function.
    ///
    /// The previous version of this test re-implemented the fold in its own body, so it asserted
    /// a property of code written in the test file: replacing the production fold with
    /// last-sample-wins — which on a sequential multi-slot run records IDLE draw, the exact bug
    /// the sampler exists to fix — left it green. That is the third time this project has shipped
    /// a test that passes with its own bug restored, so the fold now lives in one place and both
    /// the sampler and this test call it.
    #[test]
    fn the_peak_fold_keeps_the_largest_reading_per_card() {
        let mut peak = BTreeMap::new();
        super::fold_peak(
            &mut peak,
            [("a".to_string(), 50.0), ("b".to_string(), 40.0)],
        );
        super::fold_peak(
            &mut peak,
            [("a".to_string(), 400.0), ("b".to_string(), 60.0)],
        );
        super::fold_peak(
            &mut peak,
            [("a".to_string(), 55.0), ("b".to_string(), 380.0)],
        );
        assert_eq!(
            peak["a"], 400.0,
            "a card's peak must survive its idle samples"
        );
        assert_eq!(peak["b"], 380.0);
        // And a single card measured twice (two hwmon nodes) must not be summed.
        let mut one = BTreeMap::new();
        super::fold_peak(
            &mut one,
            [("x".to_string(), 120.0), ("x".to_string(), 90.0)],
        );
        assert_eq!(
            one["x"], 120.0,
            "two readings of one card are not two cards"
        );
    }

    /// An empty proving-card list makes the sampler a genuine NO-OP: no thread, no reads.
    ///
    /// Asserting only that the result is empty was vacuous — the injected reader returns empty, so
    /// deleting the early return spawned a thread that polled three times, hit the give-up cap and
    /// still handed back an empty map. The observable property is that the reader is never called.
    #[test]
    fn a_sampler_with_no_cards_is_a_no_op() {
        static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        fn counting(_: &[String]) -> super::PowerSample {
            CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            super::PowerSample::default()
        }
        CALLS.store(0, std::sync::atomic::Ordering::Relaxed);
        let s = super::PowerSampler::start_with(Vec::new(), counting, TEST_INTERVAL);
        std::thread::sleep(Duration::from_millis(80)); // several TEST_INTERVALs
        assert!(s.finish().is_empty());
        assert_eq!(
            CALLS.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "with no proving cards nothing should be sampled at all"
        );
    }

    /// THE ordering property: a sample must be taken while the load is RUNNING.
    ///
    /// The reader is coupled to TIME, not to call count. The previous version returned 410 W on
    /// its second call whichever side of the load that call fell on, so it passed when `around`
    /// was replaced by the shape its own doc names as the bug — one sample before the load and one
    /// after. That is the sample-around-the-load defect, which measured idle draw and made the
    /// cost model worse than the fallback it displaced. Now 410 W exists only during the load, so
    /// a peak of 410 is proof that a sample landed inside the window.
    #[test]
    fn sampling_happens_during_the_load_and_keeps_the_peak() {
        static LOAD_RUNNING: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        static SAMPLES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

        fn reader(_: &[String]) -> super::PowerSample {
            SAMPLES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let watts = if LOAD_RUNNING.load(std::sync::atomic::Ordering::Relaxed) {
                410.0 // under load
            } else {
                30.0 // idle, before or after
            };
            super::PowerSample {
                per_card: BTreeMap::from([("0000:06:10.0".to_string(), watts)]),
                probe_failed: false,
            }
        }

        LOAD_RUNNING.store(false, std::sync::atomic::Ordering::Relaxed);
        SAMPLES.store(0, std::sync::atomic::Ordering::Relaxed);

        let (out, per_card) = super::PowerSampler::around_with(
            vec!["0000:06:10.0".to_string()],
            reader,
            TEST_INTERVAL,
            || {
                LOAD_RUNNING.store(true, std::sync::atomic::Ordering::Relaxed);
                // Several sample intervals long, so a sampler that runs at all will sample here.
                std::thread::sleep(Duration::from_millis(250));
                LOAD_RUNNING.store(false, std::sync::atomic::Ordering::Relaxed);
                "load-done"
            },
        );

        assert_eq!(out, "load-done", "the load's result must come back");
        assert!(
            SAMPLES.load(std::sync::atomic::Ordering::Relaxed) >= 2,
            "the sampler must have run repeatedly, not once: {} samples",
            SAMPLES.load(std::sync::atomic::Ordering::Relaxed)
        );
        assert_eq!(
            per_card.get("0000:06:10.0").copied(),
            Some(410.0),
            "410W exists only while the load is running, so this is the ordering assertion: a \
             sampler that only reads before and/or after the load can never see it. Got \
             {per_card:?}"
        );
    }

    /// `finish` must observe `stop` promptly, not wait out the sample interval — it is joined, so
    /// a coarse sleep would be added to every benchmark.
    #[test]
    fn finish_does_not_wait_out_the_sample_interval() {
        let s = super::PowerSampler::start_with(
            vec!["0000:06:10.0".to_string()],
            |_| super::PowerSample {
                per_card: BTreeMap::from([("0000:06:10.0".to_string(), 100.0)]),
                probe_failed: false,
            },
            super::POWER_SAMPLE_INTERVAL,
        );
        std::thread::sleep(Duration::from_millis(30));
        let t0 = Instant::now();
        let out = s.finish();
        let dt = t0.elapsed();
        assert_eq!(out.get("0000:06:10.0").copied(), Some(100.0));
        // Must be far below POWER_SAMPLE_INTERVAL. The previous bound was 3s against a 2s
        // interval, so it passed even with the responsiveness slicing removed.
        assert!(
            dt < super::POWER_SAMPLE_INTERVAL / 4,
            "finish() took {dt:?}, which is not prompt against a {:?} interval",
            super::POWER_SAMPLE_INTERVAL
        );
    }

    /// A card that CANNOT report its draw must not stop the sampler.
    ///
    /// This is the distinction the give-up cap got wrong: nvidia-smi prints `[N/A]` for a card
    /// that cannot answer, so that card is absent from EVERY sample with a perfectly healthy
    /// probe. Counting its absence as the leak signal stopped sampling three intervals into a
    /// minutes-long benchmark and recorded the HEALTHY card's warm-up draw as its peak — the
    /// idle-draw bug, reintroduced through the leak cap.
    #[test]
    fn an_unreportable_card_does_not_stop_the_sampler() {
        static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        /// Healthy probe; card B never appears. Card A ramps up after a few samples, so a
        /// sampler that gave up early would miss its peak entirely.
        fn partial(_: &[String]) -> super::PowerSample {
            let i = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let watts = if i >= 3 { 420.0 } else { 25.0 };
            super::PowerSample {
                per_card: BTreeMap::from([("0000:06:10.0".to_string(), watts)]),
                probe_failed: false,
            }
        }
        CALLS.store(0, std::sync::atomic::Ordering::Relaxed);

        let (_, per_card) = super::PowerSampler::around_with(
            // TWO cards; only one ever reports.
            vec!["0000:06:10.0".to_string(), "0000:06:1b.0".to_string()],
            partial,
            TEST_INTERVAL,
            || std::thread::sleep(Duration::from_millis(250)),
        );

        assert!(
            CALLS.load(std::sync::atomic::Ordering::Relaxed) > super::POWER_SAMPLE_GIVE_UP_AFTER,
            "a card that cannot report must not trip the give-up cap: only {} samples taken",
            CALLS.load(std::sync::atomic::Ordering::Relaxed)
        );
        assert_eq!(
            per_card.get("0000:06:10.0").copied(),
            Some(420.0),
            "the healthy card's later peak must still be captured; got {per_card:?}"
        );
        assert!(
            !per_card.contains_key("0000:06:1b.0"),
            "the unreportable card must stay absent, so its row takes the fallback"
        );
    }

    /// A card that never reports must stop being polled. Each bounded sample can abandon a
    /// process and a drainer thread when the driver is wedged, so sampling every 2s for a whole
    /// benchmark window would turn a one-off cost into a leak rate.
    #[test]
    fn the_sampler_gives_up_on_a_card_that_never_reports() {
        static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        // A FAILING PROBE, which is the leak signal the cap counts — not merely a card that
        // cannot report, which is a capability fact true of every sample.
        fn failing(_: &[String]) -> super::PowerSample {
            CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            super::PowerSample {
                per_card: BTreeMap::new(),
                probe_failed: true,
            }
        }
        CALLS.store(0, std::sync::atomic::Ordering::Relaxed);
        let (_, per_card) = super::PowerSampler::around_with(
            vec!["0000:06:10.0".to_string()],
            failing,
            TEST_INTERVAL,
            || std::thread::sleep(Duration::from_millis(300)),
        );
        assert!(per_card.is_empty());
        let calls = CALLS.load(std::sync::atomic::Ordering::Relaxed);
        // An EXACT count against a literal, not against the constant under test: comparing the
        // measurement to `POWER_SAMPLE_GIVE_UP_AFTER` meant raising that constant to 1000 — which
        // is functionally no cap at all over a benchmark window — still satisfied the assertion.
        // The lower bound matters too: `calls == 0` (a sampler thread that never started, e.g.
        // `Builder::spawn` failing and being swallowed by `.ok()`) must not read as success.
        assert_eq!(
            calls, 3,
            "the sampler must poll exactly POWER_SAMPLE_GIVE_UP_AFTER (3) times and then stop: \
             got {calls}"
        );
    }

    // ---- GPU device benchmarks are sized against real VRAM ----

    fn gpu_slot(vram_bytes: Option<u64>) -> crate::dispatcher::SlotBenchmarkResult {
        crate::dispatcher::SlotBenchmarkResult {
            slot_key: "risc0:cuda:0".to_string(),
            gpu_name: Some("Test GPU".to_string()),
            device_index: Some(0),
            pci_bus_id: Some("0000:01:00.0".to_string()),
            gpu_tag: "cuda".to_string(),
            entries: vec![zkminer_prover_protocol::BenchmarkEntry {
                program_name: "fibonacci".to_string(),
                prover_backend: "risc0".to_string(),
                cycles: 1_000_000,
                duration_secs: 1.0,
                throughput: 1_000_000.0,
                weight: 0.10,
                precompile: false,
                wrap_secs: None,
            }],
            vram_bytes,
            host_peak_bytes: None,
        }
    }

    /// Each program's STARK/wrap split must survive the trip from a worker's entries into the device
    /// row the suite persists, with "not measured" kept distinct from zero.
    #[test]
    fn device_rows_carry_the_stark_and_wrap_split_per_program() {
        let mut slot = gpu_slot(Some(24 << 30));
        slot.slot_key = "sp1:cuda:0".to_string();
        let entry = |name: &str, cycles: u64, stark: f64, wrap: Option<f64>| {
            zkminer_prover_protocol::BenchmarkEntry {
                program_name: name.to_string(),
                prover_backend: "sp1".to_string(),
                cycles,
                duration_secs: stark,
                throughput: cycles as f64 / stark,
                weight: 0.10,
                precompile: false,
                wrap_secs: wrap,
            }
        };
        // SP1's shape: the wrap measured on one program per slot, by difference.
        slot.entries = vec![
            entry("fibonacci", 9_966, 1.2, None),
            entry("chacha-mix", 32_484_958, 8.0, Some(55.0)),
        ];
        let rows = build_gpu_device_benchmarks_from_workers(&[slot], &BTreeMap::new());
        let d = &rows[0];
        assert_eq!(d.program_stages.len(), 2);
        let fib = d
            .program_stages
            .iter()
            .find(|p| p.program_name == "fibonacci")
            .unwrap();
        assert_eq!(
            fib.stark_secs, 1.2,
            "duration_secs is the STARK time from v4 on"
        );
        assert_eq!(
            fib.wrap_secs, None,
            "an unmeasured wrap must stay None, never 0.0 — zero would read as a free Groth16 proof"
        );
        assert_eq!(d.wrap_secs(), Some(55.0));
    }

    /// The device-level wrap is the MEDIAN of the measured programs, so the one cold first wrap in a
    /// process does not inflate the per-proof figure, and `None` when nothing was measured — never 0.0.
    #[test]
    fn the_device_wrap_is_the_median_of_what_was_measured() {
        let mut rows =
            build_gpu_device_benchmarks_from_workers(&[gpu_slot(Some(24 << 30))], &BTreeMap::new());
        let d = &mut rows[0];
        let stage = |name: &str, wrap: Option<f64>| ProgramStage {
            program_name: name.to_string(),
            cycles: 1_000_000,
            stark_secs: 1.0,
            wrap_secs: wrap,
        };
        // The measured 4090 shape: one cold wrap, then five warm ones. The median is the warm figure;
        // a mean would read 2.17 s and overstate every proof's wrap by the one-off first-wrap cost.
        d.program_stages = vec![
            stage("fibonacci", Some(2.96)),
            stage("sha256-chain", Some(2.02)),
            stage("ecdsa-verify", Some(2.00)),
            stage("bigint-mul", Some(2.01)),
            stage("memory-merkle", Some(2.02)),
            stage("chacha-mix", Some(2.02)),
        ];
        assert!((d.wrap_secs().unwrap() - 2.02).abs() < 1e-9);
        // Unmeasured programs do not count, and an even count takes the midpoint.
        d.program_stages = vec![
            stage("a", Some(3.0)),
            stage("b", None),
            stage("c", Some(3.4)),
        ];
        assert!((d.wrap_secs().unwrap() - 3.2).abs() < 1e-9);
        d.program_stages = vec![stage("a", None)];
        assert_eq!(d.wrap_secs(), None);
        d.program_stages.clear();
        assert_eq!(d.wrap_secs(), None);
    }

    /// The model's rate must be the one large jobs see. Measured on the 4090 on 2026-10-06: the
    /// unweighted mean of per-program rates is 1.1M c/s because fibonacci runs at 67.8K, while every
    /// real program runs at 1.3-1.4M — and `wrap + cycles / rate` then over-predicts a 46M-cycle job by
    /// ~16%. Weighting by cycles lands within a few percent of what was measured.
    #[test]
    fn the_model_rate_is_weighted_by_cycles() {
        let mut rows =
            build_gpu_device_benchmarks_from_workers(&[gpu_slot(Some(24 << 30))], &BTreeMap::new());
        let d = &mut rows[0];
        let stage = |name: &str, cycles: u64, stark: f64, wrap: f64| ProgramStage {
            program_name: name.to_string(),
            cycles,
            stark_secs: stark,
            wrap_secs: Some(wrap),
        };
        d.program_stages = vec![
            stage("fibonacci", 32_768, 0.48, 2.96),
            stage("sha256-chain", 46_137_344, 35.82, 2.02),
            stage("ecdsa-verify", 65_011_712, 47.65, 2.00),
            stage("bigint-mul", 27_525_120, 19.77, 2.01),
            stage("memory-merkle", 7_340_032, 5.70, 2.02),
            stage("chacha-mix", 8_404_992, 6.67, 2.02),
        ];
        let rate = d.stark_rate().unwrap();
        assert!(
            (1.30e6..1.36e6).contains(&rate),
            "cycle-weighted rate {rate}"
        );
        // Predict sha256-chain end to end and compare with what was measured (35.82 + 2.02 s).
        let predicted = d.wrap_secs().unwrap() + 46_137_344.0 / rate;
        let measured = 35.82 + 2.02;
        assert!(
            (predicted - measured).abs() / measured < 0.05,
            "predicted {predicted:.1}s against {measured:.1}s measured"
        );
        d.program_stages.clear();
        assert_eq!(d.stark_rate(), None);
    }

    /// A benchmarks.json written before `program_stages` existed must still load. The loader treats a
    /// failed parse as a corrupt cache and discards it — hours of po2 calibration — so this field
    /// staying `#[serde(default)]` is load-bearing.
    #[test]
    fn a_cache_written_before_program_stages_still_loads() {
        let rows =
            build_gpu_device_benchmarks_from_workers(&[gpu_slot(Some(24 << 30))], &BTreeMap::new());
        let mut v = serde_json::to_value(&rows[0]).unwrap();
        v.as_object_mut().unwrap().remove("program_stages");
        let back: DeviceBenchmark = serde_json::from_value(v)
            .expect("a pre-v4 device row must deserialize, or the whole cache is thrown away");
        assert!(back.program_stages.is_empty());
        assert_eq!(back.wrap_secs(), None);
    }

    #[test]
    fn gpu_po2_is_sized_from_vram_not_hardcoded() {
        // 32 GB card: budget 28.8 GB, po2=24 needs 16 GB → fits.
        let big =
            build_gpu_device_benchmarks_from_workers(&[gpu_slot(Some(32 << 30))], &BTreeMap::new());
        assert_eq!(big[0].optimal_po2, PO2_MAX);
        assert_eq!(big[0].max_feasible_po2, PO2_MAX);
        assert!(
            big[0].memory_usage_bytes > 0,
            "memory must be derived, got {}",
            big[0].memory_usage_bytes
        );

        // 8 GB card: budget 7.2 GB, po2=23 needs 8 GB → must step DOWN.
        // This is the property that stops a small card being told it can run
        // PO2_MAX once po2 calibration starts consuming max_feasible_po2.
        let small =
            build_gpu_device_benchmarks_from_workers(&[gpu_slot(Some(8 << 30))], &BTreeMap::new());
        assert!(
            small[0].max_feasible_po2 < PO2_MAX,
            "8 GB card must not claim PO2_MAX, got {}",
            small[0].max_feasible_po2
        );
        assert!(small[0].memory_usage_bytes > 0);
        assert!(
            small[0].memory_usage_bytes <= (8u64 << 30),
            "estimated usage must fit the card"
        );
    }

    #[test]
    fn gpu_unknown_vram_keeps_zero_memory_sentinel() {
        // VRAM unknown (e.g. non-CUDA): must NOT invent a size. memory_usage_bytes
        // stays 0 — the documented sentinel meaning "max_feasible_po2 is not
        // memory-derived", which future po2 calibration must gate on.
        let unknown = build_gpu_device_benchmarks_from_workers(&[gpu_slot(None)], &BTreeMap::new());
        assert_eq!(unknown[0].memory_usage_bytes, 0);
        assert_eq!(unknown[0].optimal_po2, PO2_MAX);
    }

    // ---- po2 calibration is only adopted when it carries real signal ----

    fn sample(po2: u8, segment_count: u32, throughput: f64) -> Po2Sample {
        Po2Sample {
            po2,
            total_cycles: 1_000_000,
            segment_count,
            duration_secs: 1.0,
            throughput,
        }
    }

    #[test]
    fn calibration_rejected_when_workload_never_segments() {
        // The real measured shape of the worker's built-in calibration workload on a
        // 5090: one segment at every po2, throughput varying only by warm-up/jitter.
        // argmax over this would pick a po2 at random, so it must be rejected.
        let noise = vec![
            sample(18, 1, 72_198.0),
            sample(19, 1, 570_648.0),
            sample(20, 1, 573_724.0),
            sample(21, 1, 620_184.0),
            sample(22, 1, 624_203.0),
            sample(23, 1, 608_450.0),
            sample(24, 1, 590_307.0),
        ];
        assert!(
            !calibration_is_usable(&noise),
            "single-segment sweep must be rejected"
        );
    }

    #[test]
    fn calibration_accepted_when_segmentation_varies() {
        let real = vec![
            sample(18, 64, 1_000_000.0),
            sample(19, 32, 1_400_000.0),
            sample(20, 16, 1_800_000.0),
            sample(21, 8, 2_100_000.0),
        ];
        assert!(calibration_is_usable(&real));
    }

    #[test]
    fn calibration_rejects_degenerate_input() {
        assert!(!calibration_is_usable(&[]), "empty sweep");
        assert!(
            !calibration_is_usable(&[sample(18, 8, 1.0)]),
            "single sample"
        );
        // A zero-duration/zero-throughput sample would divide badly downstream.
        let mut bad = sample(19, 8, 0.0);
        bad.duration_secs = 0.0;
        assert!(!calibration_is_usable(&[sample(18, 8, 1.0), bad]));
    }

    #[test]
    fn noisy_calibration_does_not_override_the_sdk() {
        // The 4090's REAL sweep: po2=19 leads po2=20 by 0.04%. A plain argmax picks 19,
        // and forcing 19 measured 5% slower than the SDK default on a live 1.05M-cycle
        // job. Below the decision margin we must defer instead.
        let noisy = Po2Profile {
            samples: vec![
                sample(18, 260, 1_971_908.0),
                sample(19, 122, 2_017_940.0),
                sample(20, 59, 2_017_002.0),
                sample(21, 30, 1_989_582.0),
            ],
            max_po2: 21,
            backend: "risc0".to_string(),
        };
        assert_eq!(
            noisy.optimal_po2_for_job(60_000_000),
            19,
            "argmax still picks 19"
        );
        assert_eq!(
            noisy.confident_po2_for_job(60_000_000),
            None,
            "0.04% is noise — must defer to the SDK"
        );
    }

    #[test]
    fn decisive_calibration_does_override_the_sdk() {
        // A real, unambiguous winner (>5% over the runner-up) SHOULD be applied.
        let decisive = Po2Profile {
            samples: vec![
                sample(18, 64, 1_000_000.0),
                sample(19, 32, 1_400_000.0),
                sample(20, 16, 2_500_000.0), // ~79% over runner-up
                sample(21, 8, 1_390_000.0),
            ],
            max_po2: 21,
            backend: "risc0".to_string(),
        };
        assert_eq!(decisive.confident_po2_for_job(60_000_000), Some(20));
        // Zero cycles still means "no opinion" (gates the whole feature off).
        assert_eq!(decisive.confident_po2_for_job(0), None);
    }

    #[test]
    fn failed_po2_cannot_win_argmax_via_clamping() {
        // Regression guard for the real 4090 case: po2=22 OOMed, so it produced no
        // sample. `throughput_at_po2` clamps above the measured range, so an unmeasured
        // (failing) po2 would otherwise inherit the best measured throughput and could
        // be selected. Capping max_po2 at the highest SUCCESSFUL po2 prevents that.
        let samples = vec![
            sample(18, 260, 1_971_908.0),
            sample(19, 122, 2_017_940.0),
            sample(20, 59, 2_017_002.0),
            sample(21, 30, 1_989_582.0),
        ];
        let profile = Po2Profile {
            samples: samples.clone(),
            max_po2: 21, // clamped to highest successful — NOT the heuristic's 24
            backend: "risc0".to_string(),
        };
        let chosen = profile.optimal_po2_for_job(60_000_000);
        assert!(
            chosen <= 21,
            "must never select a po2 that failed to calibrate, got {chosen}"
        );

        // Without the clamp, po2 22..24 clamp to the best measured throughput and can
        // tie/beat it — demonstrating why the cap is load-bearing.
        let unclamped = Po2Profile {
            samples,
            max_po2: 24,
            backend: "risc0".to_string(),
        };
        assert!(
            unclamped.throughput_at_po2(24) >= unclamped.throughput_at_po2(21),
            "clamping above the measured range is what makes the cap necessary"
        );
    }

    #[test]
    fn usable_calibration_drives_po2_selection_end_to_end() {
        // Closes the loop the hardware can't yet demonstrate: once a sweep DOES
        // exercise segmentation, it must flow samples → Po2Profile → chosen po2.
        let samples = vec![
            sample(18, 64, 1_000_000.0),
            sample(19, 32, 1_400_000.0),
            sample(20, 16, 2_500_000.0), // best
            sample(21, 8, 1_900_000.0),
        ];
        assert!(calibration_is_usable(&samples));

        let db = DeviceBenchmark {
            program_stages: Vec::new(),
            device_id: "gpu0".to_string(),
            device_label: "GPU0 Test".to_string(),
            prover_backend: "risc0".to_string(),
            throughput: 2_000_000.0,
            power_watts: 300.0,
            optimal_po2: 21,
            memory_usage_bytes: 8 << 30,
            max_feasible_po2: 21,
            program_throughputs: std::collections::HashMap::new(),
            pci_bus_id: String::new(),
            po2_samples: samples,
            host_peak_bytes: None,
        };

        let profile = Po2Profile::from_device_benchmark(&db).expect("profile from samples");
        assert_eq!(profile.max_po2, 21);
        // total_time = cycles / throughput_at_po2, so selection is argmax(throughput).
        assert_eq!(profile.optimal_po2_for_job(50_000_000), 20);

        // And an empty sweep (what the gate leaves behind today) yields no profile,
        // so `resolve_po2` falls through to letting the SDK choose.
        let mut uncalibrated = db.clone();
        uncalibrated.po2_samples = Vec::new();
        assert!(Po2Profile::from_device_benchmark(&uncalibrated).is_none());
    }

    #[test]
    fn gpu_throughput_is_measured_not_po2_scaled() {
        // avg_throughput is a MEASURED value; applying po2_throughput_factor here
        // would double-count the segment-size effect already baked into it.
        let b =
            build_gpu_device_benchmarks_from_workers(&[gpu_slot(Some(32 << 30))], &BTreeMap::new());
        assert!(
            (b[0].throughput - 1_000_000.0).abs() < 1e-6,
            "throughput must be the measured value, got {}",
            b[0].throughput
        );
    }
}

#[cfg(test)]
mod cache_power_tests {
    use super::{
        floor_implausible_gpu_power, BenchmarkSuite, DeviceBenchmark, CPU_DEVICE_ID,
        FALLBACK_GPU_WATTS, MIN_PLAUSIBLE_GPU_WATTS,
    };

    fn row(id: &str, watts: f64) -> DeviceBenchmark {
        DeviceBenchmark {
            program_stages: Vec::new(),
            device_id: id.to_string(),
            device_label: id.to_string(),
            prover_backend: "risc0".to_string(),
            throughput: 1_000_000.0,
            power_watts: watts,
            optimal_po2: 21,
            memory_usage_bytes: 0,
            max_feasible_po2: 21,
            program_throughputs: std::collections::HashMap::new(),
            pci_bus_id: String::new(),
            po2_samples: Vec::new(),
            host_peak_bytes: None,
        }
    }

    /// The exact contents of this box's cache: 8.5 W on both GPU rows, an idle AMD card's draw
    /// stamped onto every row by the bug the write-time fix removes. A file like this would
    /// otherwise load untouched and price proving at 148 W against ~872 W measured.
    #[test]
    fn an_implausible_cached_gpu_power_is_floored() {
        let mut suite = BenchmarkSuite {
            device_benchmarks: vec![
                row(CPU_DEVICE_ID, 200.0),
                row("gpu0", 8.5),
                row("gpu1", 8.5),
            ],
            gpu_power_watts: Some(8.5),
            ..Default::default()
        };
        floor_implausible_gpu_power(&mut suite);
        assert_eq!(suite.device_benchmarks[1].power_watts, FALLBACK_GPU_WATTS);
        assert_eq!(suite.device_benchmarks[2].power_watts, FALLBACK_GPU_WATTS);
        assert_eq!(
            suite.gpu_power_watts, None,
            "the suite total came from the same bogus readings"
        );
        // The CPU row is a different question and must not be touched: 200 W is plausible for a
        // package, and the cost model reads `cpu_power_watts`, not this row.
        assert_eq!(suite.device_benchmarks[0].power_watts, 200.0);
    }

    /// The WIRING, not the helper: a cache file on disk must come back with its implausible
    /// power already floored. Deleting the `floor_implausible_gpu_power` call from
    /// `load_cached_benchmark_from` makes this fail; the two helper tests above do not.
    #[test]
    fn a_loaded_cache_has_its_implausible_power_floored() {
        let dir = std::env::temp_dir().join(format!(
            "zkbench-load-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("benchmarks.json");

        // The real shape of this box's cache: an idle AMD card's draw stamped on every GPU row by
        // the bug the write-time fix removed.
        let json = serde_json::json!({
            "suite_version": "v-test",
            "hardware_fingerprint": "fp-test",
            "suite": {
                "results": [],
                "device_benchmarks": [
                    {
                        "device_id": "gpu0", "device_label": "GPU0", "prover_backend": "risc0",
                        "throughput": 1000000.0, "power_watts": 8.5, "optimal_po2": 21,
                        "memory_usage_bytes": 0, "max_feasible_po2": 21,
                        "program_throughputs": {}, "pci_bus_id": "", "po2_samples": []
                    }
                ],
                "cpu_info": "test", "timestamp": "now", "zkops": 0.0,
                "precompile_score": 0.0, "compute_score": 0.0,
                "cpu_power_watts": null, "gpu_power_watts": 8.5
            }
        });
        std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        let loaded = super::load_cached_benchmark_from(&path, "v-test", "fp-test")
            .expect("version and fingerprint match, so it must load");
        assert_eq!(
            loaded.device_benchmarks[0].power_watts, FALLBACK_GPU_WATTS,
            "a cache written by the old power bug must not reach the cost model as measured"
        );
        assert_eq!(
            loaded.gpu_power_watts, None,
            "the derived total is bogus too"
        );

        // And the guards still work: a version or fingerprint mismatch is not a load.
        assert!(super::load_cached_benchmark_from(&path, "v-other", "fp-test").is_none());
        assert!(super::load_cached_benchmark_from(&path, "v-test", "fp-other").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A real measurement must pass through untouched — including the fallback itself, and a
    /// genuinely low-power card above the floor.
    #[test]
    fn plausible_cached_power_is_left_alone() {
        let mut suite = BenchmarkSuite {
            device_benchmarks: vec![
                row("gpu0", 341.5),
                row("gpu1", FALLBACK_GPU_WATTS),
                row("gpu2", MIN_PLAUSIBLE_GPU_WATTS + 0.1),
            ],
            gpu_power_watts: Some(700.0),
            ..Default::default()
        };
        floor_implausible_gpu_power(&mut suite);
        assert_eq!(suite.device_benchmarks[0].power_watts, 341.5);
        assert_eq!(suite.device_benchmarks[1].power_watts, FALLBACK_GPU_WATTS);
        assert!(
            (suite.device_benchmarks[2].power_watts - (MIN_PLAUSIBLE_GPU_WATTS + 0.1)).abs() < 1e-9
        );
        assert_eq!(suite.gpu_power_watts, Some(700.0));
    }
}

#[cfg(test)]
mod host_peak_tests {
    use super::*;

    fn row(backend: &str, peak: Option<u64>) -> DeviceBenchmark {
        DeviceBenchmark {
            program_stages: Vec::new(),
            device_id: "gpu0".to_string(),
            device_label: "gpu0".to_string(),
            prover_backend: backend.to_string(),
            throughput: 1_000_000.0,
            power_watts: 300.0,
            optimal_po2: 21,
            memory_usage_bytes: 0,
            max_feasible_po2: 21,
            program_throughputs: std::collections::HashMap::new(),
            pci_bus_id: String::new(),
            po2_samples: Vec::new(),
            host_peak_bytes: peak,
        }
    }

    /// Budget for the WORST card, not the average: admission has to hold for whichever card the
    /// dispatcher picks, and it does not pick the cheapest.
    #[test]
    fn the_expected_peak_is_the_largest_measured_for_that_backend() {
        let gib = 1024 * 1024 * 1024;
        let suite = BenchmarkSuite {
            device_benchmarks: vec![
                row("risc0", Some(4 * gib)),
                row("risc0", Some(11 * gib)),
                row("sp1", Some(18 * gib)),
            ],
            ..Default::default()
        };
        // Scaled by `MEASUREMENT_SAFETY_FACTOR`: a benchmark measurement is a LOWER bound on the
        // production cost (composite receipt, smaller segment), so the budget is the worst
        // measured card's figure times that factor — not the raw reading.
        // Clamped to what the measuring host can realistically admit, so the expectation is written
        // against that ceiling rather than a raw multiple — a budget larger than the machine is a
        // permanent refusal, not a safe one. See `max_admissible_budget`.
        let factor = crate::memory::MEASUREMENT_SAFETY_FACTOR;
        let ceiling = crate::memory::max_admissible_budget(
            crate::memory::mem_total_bytes().unwrap_or(u64::MAX),
        );
        assert_eq!(
            suite.expected_host_peak_bytes("risc0"),
            (11 * gib * factor).min(ceiling)
        );
        assert_eq!(
            suite.expected_host_peak_bytes("sp1"),
            (18 * gib * factor).min(ceiling)
        );
        // The worst card, not the average: 4 and 11 GiB were measured for risc0 and the budget must
        // come from the 11, since the dispatcher does not pick the cheapest card.
        assert!(suite.expected_host_peak_bytes("risc0") > 4 * gib * factor || ceiling <= 8 * gib);
    }

    /// The budget must be obtainable for a backend that has NO GPU device row at all.
    ///
    /// This is the case that mattered and the case the old test could not see. SP1 is permanently
    /// tagged `generic` (it ships without a `-cuda` suffix and re-tagging it breaks SP1 proving), and
    /// `build_gpu_device_benchmarks_from_workers` skips every `generic` slot — so no amount of
    /// benchmarking produced an SP1 device row, and `expected_host_peak_bytes("sp1")` was pinned to
    /// the 18 GiB blind default for the life of the install. The previous test here asserted a
    /// measured SP1 budget by hand-building a `prover_backend: "sp1"` GPU row, which the real
    /// pipeline cannot emit, so it passed throughout.
    #[test]
    fn a_generic_tagged_backend_can_still_be_measured() {
        let gib = 1024 * 1024 * 1024;
        let ceiling = crate::memory::max_admissible_budget(
            crate::memory::mem_total_bytes().unwrap_or(u64::MAX),
        );
        // Exactly what the pipeline produces for SP1: no device row, a backend-keyed peak.
        let suite = BenchmarkSuite {
            device_benchmarks: vec![row("risc0", Some(5 * gib))],
            host_peaks: std::collections::HashMap::from([("sp1".to_string(), 10 * gib)]),
            ..Default::default()
        };
        let sp1 = suite.expected_host_peak_bytes("sp1");
        assert_eq!(
            sp1,
            (10 * gib * crate::memory::MEASUREMENT_SAFETY_FACTOR).min(ceiling),
            "a measured SP1 peak must reach the budget even with no SP1 device row"
        );
        assert_ne!(
            sp1,
            crate::memory::unmeasured_peak_for("sp1"),
            "the blind default must no longer be the only answer available to SP1"
        );
        // And the map must not leak across backends.
        assert_eq!(
            suite.expected_host_peak_bytes("openvm"),
            crate::memory::unmeasured_peak_for("openvm")
        );
    }

    /// An UNMEASURED backend must look expensive. Treating it as free is what allows unlimited
    /// concurrency on a fresh install — the configuration that froze this host.
    #[test]
    fn an_unmeasured_backend_is_charged_the_conservative_default() {
        let suite = BenchmarkSuite {
            device_benchmarks: vec![row("risc0", None), row("risc0", None)],
            ..Default::default()
        };
        assert_eq!(
            suite.expected_host_peak_bytes("risc0"),
            crate::memory::unmeasured_peak_for("risc0")
        );
        // And a backend with no rows at all behaves the same way, rather than reading as 0.
        assert_eq!(
            suite.expected_host_peak_bytes("openvm"),
            crate::memory::unmeasured_peak_for("openvm")
        );
        // The default is PER-BACKEND. One blunt figure for all of them is its own outage: charging
        // risc0 the SP1 default needs ~21 GiB free before anything is admitted, and an
        // unbenchmarked 2-GPU box would mine nothing while reporting only that it cannot fit.
        assert!(
            crate::memory::unmeasured_peak_for("risc0") < crate::memory::unmeasured_peak_for("sp1"),
            "risc0 must not be charged SP1's default"
        );
        // A PARTIALLY measured backend falls back for the whole backend. Taking the max of only
        // the measured rows charged the unmeasured card the measured card's figure — and on a
        // mixed rig the unmeasured card is as likely as not the expensive one. "Budget for the
        // worst card" cannot be satisfied by a card that was never budgeted.
        let mixed = BenchmarkSuite {
            device_benchmarks: vec![
                row("risc0", None),
                row("risc0", Some(2 * 1024 * 1024 * 1024)),
            ],
            ..Default::default()
        };
        assert_eq!(
            mixed.expected_host_peak_bytes("risc0"),
            crate::memory::unmeasured_peak_for("risc0"),
            "one unmeasured card must not inherit another card's measurement"
        );
    }
}
