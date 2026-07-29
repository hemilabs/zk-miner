//! Benchmarking for zkVM proving performance.
//!
//! Provides 6 diverse benchmark programs with a blended **zkOP/s** metric
//! normalized so that an AMD Threadripper 3970X baseline = 100,000 zkOP/s.

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
    /// Average GPU power draw during benchmarks (watts), via hwmon.
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
    BackendProfile { name: "risc0", cpu_factor: 1.00, gpu_acceleration: Some(12.0), memory_multiplier: 1.0 },
    BackendProfile { name: "sp1",   cpu_factor: 0.85, gpu_acceleration: Some(8.0),  memory_multiplier: 1.1 },
    BackendProfile { name: "openvm", cpu_factor: 0.70, gpu_acceleration: None,      memory_multiplier: 1.2 },
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
        !self.results.is_empty()
            && self.results.iter().all(|r| r.prover_backend == "simulated")
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
            let Some(accel) = profile.gpu_acceleration else { continue };

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
                device_id: device_id.clone(),
                device_label: device_label.clone(),
                prover_backend: profile.name.to_string(),
                throughput,
                power_watts: gpu.power_watts,
                optimal_po2,
                memory_usage_bytes,
                max_feasible_po2: optimal_po2,
                program_throughputs: std::collections::HashMap::new(),
                po2_samples: Vec::new(),
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
        let result = results.iter().find(|r| r.program_name.starts_with(program.name));
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
        let result = results.iter().find(|r| r.program_name.starts_with(program.name));
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

    let precompile = if precompile_count > 0 { precompile_sum / precompile_count as f64 } else { 0.0 };
    let compute = if compute_count > 0 { compute_sum / compute_count as f64 } else { 0.0 };
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

/// Read instantaneous GPU power draw from hwmon (watts).
///
/// Scans for AMD GPU hwmon devices and reads `power1_average` (microwatts → watts).
/// Returns the sum across all detected GPUs, or `None` if no GPU power data is available.
fn read_gpu_power_watts() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let mut total_watts = 0.0;
        let mut found = false;

        for card_idx in 0..16u32 {
            let device_path = format!("/sys/class/drm/card{}/device", card_idx);

            // Check vendor — 0x1002 = AMD
            let vendor_path = format!("{device_path}/vendor");
            match std::fs::read_to_string(&vendor_path) {
                Ok(v) if v.trim() == "0x1002" => {}
                _ => continue,
            }

            // Find hwmon directory and read power1_average
            let hwmon_dir = format!("{device_path}/hwmon");
            if let Ok(entries) = std::fs::read_dir(&hwmon_dir) {
                for entry in entries.flatten() {
                    let power_path = entry.path().join("power1_average");
                    if let Ok(contents) = std::fs::read_to_string(&power_path) {
                        if let Ok(microwatts) = contents.trim().parse::<u64>() {
                            total_watts += microwatts as f64 / 1_000_000.0;
                            found = true;
                        }
                    }
                }
            }
        }

        if found {
            return Some(total_watts);
        }
    }
    None
}

/// Run benchmarks using whichever prover backends are compiled in.
///
/// When no prover feature is enabled, falls back to simulated benchmarks.
/// Measures CPU and GPU power consumption during the benchmark window.
pub fn run_benchmark() -> BenchmarkSuite {
    let cpu_info = get_cpu_info();
    let cores = get_cpu_cores();
    let timestamp = chrono::Utc::now().to_rfc3339();

    tracing::info!(
        "Running benchmarks on {} ({} cores)",
        cpu_info,
        cores
    );

    // Snapshot power counters before benchmarks
    let rapl_before = read_rapl_energy_uj();
    if rapl_before.is_none() {
        tracing::warn!(
            "CPU power monitoring unavailable. \
             To enable, run: sudo chmod o+r /dev/cpu/0/msr"
        );
    }
    let gpu_power_before = read_gpu_power_watts();
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
    let rapl_after = read_rapl_energy_uj();
    let gpu_power_after = read_gpu_power_watts();

    // Compute average CPU power from RAPL energy delta
    let cpu_power_watts = match (rapl_before, rapl_after) {
        (Some(before), Some(after)) if power_elapsed.as_secs_f64() > 0.0 => {
            let delta_uj = after.saturating_sub(before);
            let watts = delta_uj as f64 / 1_000_000.0 / power_elapsed.as_secs_f64();
            tracing::info!("CPU power: {watts:.1}W (avg over benchmark window)");
            Some(watts)
        }
        _ => None,
    };

    // Average the before/after GPU power readings
    let gpu_power_watts = match (gpu_power_before, gpu_power_after) {
        (Some(before), Some(after)) => {
            let avg = (before + after) / 2.0;
            tracing::info!("GPU power: {avg:.1}W (avg over benchmark window)");
            Some(avg)
        }
        (Some(v), None) | (None, Some(v)) => Some(v),
        _ => None,
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
                device_id: "cpu".to_string(),
                device_label: cpu_info.clone(),
                prover_backend: profile.name.to_string(),
                throughput: cpu_avg * profile.cpu_factor * po2_factor,
                power_watts: cpu_power,
                optimal_po2,
                memory_usage_bytes,
                max_feasible_po2: optimal_po2,
                program_throughputs: std::collections::HashMap::new(),
                po2_samples: Vec::new(),
            }
        })
        .collect();

    // Build GPU device benchmarks from real worker results.
    // Workers are keyed like "risc0:cuda:0", "risc0:rocm:1", etc.
    // Each worker ran the full benchmark suite on its assigned GPU — use
    // the measured average throughput directly.
    let mut gpu_device_benchmarks = build_gpu_device_benchmarks_from_workers(
        &worker_device_results,
        gpu_power_watts.unwrap_or(300.0),
    );
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

    // Read GPU power
    let gpu_power_watts = read_gpu_power_watts();

    // Run GPU worker benchmarks only
    let worker_device_results = if let Some(pool) = crate::engine::worker_pool() {
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
    };

    // Build GPU device benchmarks from worker results
    let device_benchmarks = build_gpu_device_benchmarks_from_workers(
        &worker_device_results,
        gpu_power_watts.unwrap_or(300.0),
    );

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
        cpu_power_watts: None,
        gpu_power_watts,
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
    let gpu_power_watts = read_gpu_power_watts();

    let worker_device_results = if let Some(pool) = crate::engine::worker_pool() {
        pool.benchmark_all_streaming(on_progress)
    } else {
        Vec::new()
    };

    let device_benchmarks = build_gpu_device_benchmarks_from_workers(
        &worker_device_results,
        gpu_power_watts.unwrap_or(300.0),
    );

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
        cpu_power_watts: None,
        gpu_power_watts,
    }
}

/// Convert a protocol `BenchmarkEntry` (from subprocess) to our `BenchmarkResult`.
///
/// Looks up the matching `BenchmarkProgram` by exact canonical name to copy
/// weight and precompile fields. If no match found, logs a warning and assigns weight 0.0.
fn benchmark_entry_to_result(
    entry: &zkminer_prover_protocol::BenchmarkEntry,
) -> BenchmarkResult {
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
fn build_gpu_device_benchmarks_from_workers(
    worker_results: &[crate::dispatcher::SlotBenchmarkResult],
    gpu_power_watts: f64,
) -> Vec<DeviceBenchmark> {
    let mut benchmarks = Vec::new();

    for r in worker_results {
        if r.entries.is_empty() || r.gpu_tag == "generic" {
            continue;
        }

        let idx = r.device_index.unwrap_or(0);
        let device_id = format!("gpu{idx}");
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
        let backend = entries.first().map(|e| e.prover_backend.as_str()).unwrap_or("risc0");

        // Build per-program throughput map for workload-specific predictions
        let mut program_throughputs = std::collections::HashMap::new();
        for entry in entries {
            program_throughputs.insert(entry.program_name.clone(), entry.throughput);
        }

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

        benchmarks.push(DeviceBenchmark {
            device_id,
            device_label,
            prover_backend: backend.to_string(),
            throughput: avg_throughput,
            power_watts: gpu_power_watts,
            optimal_po2,
            memory_usage_bytes,
            max_feasible_po2: optimal_po2,
            program_throughputs,
            po2_samples: Vec::new(),
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

    for key in pool.registered_backends() {
        // Slot keys look like "risc0:cuda:0" — backend:gpu_tag:device_index.
        let mut parts = key.split(':');
        let (Some(backend), Some(gpu_tag), Some(idx)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if backend != "risc0" || gpu_tag == "generic" {
            continue;
        }
        let device_id = format!("gpu{idx}");

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

        let max_po2 = db.max_feasible_po2.min(PO2_MAX);
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
                        s.po2, s.segment_count, s.total_cycles, s.duration_secs, s.throughput
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
            if program.precompile { " [precompile]" } else { "" },
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
    let mut state = [0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
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
                let ch = (s[(i + 5) % 8] & s[(i + 6) % 8])
                    ^ (!s[(i + 5) % 8] & s[(i + 7) % 8]);
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
        a[i] = (i as u64).wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(0x6A09E667F3BCC908);
        b[i] = (i as u64).wrapping_mul(0x517CC1B727220A95).wrapping_add(0xBB67AE8584CAA73B);
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
    let ram = get_total_memory_bytes();
    let gpu = gpu_fingerprint();
    format!("{cpu}|{cores}|{ram}|{gpu}")
}

/// Build the GPU portion of the hardware fingerprint.
///
/// Detects GPUs via nvidia-smi and sysfs (same sources as discovery.rs)
/// and includes model names, count, and driver version.
fn gpu_fingerprint() -> String {
    let mut parts: Vec<String> = Vec::new();

    // NVIDIA: query model names and driver version
    if let Ok(output) = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=name,driver_version", "--format=csv,noheader,nounits"])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
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
                                let gpu_name = std::fs::read_to_string(device_dir.join("product_name"))
                                    .or_else(|_| std::fs::read_to_string(device_dir.join("device"))
                                        .map(|d| format!("AMD({})", d.trim())))
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
                    if let Some(kb_str) = rest.strip_suffix("kB").or_else(|| rest.strip_suffix("KB")) {
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
    let path = benchmark_cache_path();
    let data = match std::fs::read_to_string(&path) {
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

    let current_version = suite_version();
    if saved.suite_version != current_version {
        tracing::info!(
            "Benchmark suite version changed ({:?} -> {current_version}), re-benchmarking needed",
            if saved.suite_version.is_empty() { "none" } else { &saved.suite_version },
        );
        return None;
    }

    let current_fp = hardware_fingerprint();
    if saved.hardware_fingerprint != current_fp {
        tracing::info!(
            "Hardware changed (saved: {}, current: {}), re-benchmarking needed",
            saved.hardware_fingerprint,
            current_fp
        );
        return None;
    }

    Some(saved.suite)
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

    match serde_json::to_string_pretty(&saved) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                tracing::error!("Failed to write benchmark cache: {e}");
            } else {
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
    fn weights_sum_to_one() {
        let sum: f64 = BENCHMARK_PROGRAMS.iter().map(|p| p.weight).sum();
        assert!((sum - 1.0).abs() < 1e-9, "weights sum to {sum}, expected 1.0");
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
            assert!(db.throughput > 0.0, "throughput for {} should be > 0", db.prover_backend);
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
        let gpus = [
            GpuDesc {
                index: 0,
                name: "RX 7900 XTX".to_string(),
                vram_bytes: 24 * 1024 * 1024 * 1024,
                power_watts: 355.0,
            },
        ];
        add_gpu_device_benchmarks(&mut suite, &gpus);

        // Should now have 3 CPU + 2 GPU entries (risc0+sp1, no openvm GPU)
        assert_eq!(suite.device_benchmarks.len(), 5);

        let gpu_entries: Vec<_> = suite.device_benchmarks.iter()
            .filter(|d| d.device_id == "gpu0")
            .collect();
        assert_eq!(gpu_entries.len(), 2);

        // GPU entries should be faster than CPU entries for backends with GPU support
        for profile in &BACKEND_PROFILES {
            let Some(_) = profile.gpu_acceleration else { continue };
            let cpu_tp = suite.throughput_for("cpu", profile.name).unwrap();
            let gpu_tp = suite.throughput_for("gpu0", profile.name).unwrap();
            assert!(
                gpu_tp > cpu_tp,
                "GPU should be faster than CPU for {}: gpu={:.0} cpu={:.0}",
                profile.name, gpu_tp, cpu_tp
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
            risc0_tp, sp1_tp
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
            GpuDesc { index: 0, name: "GPU A".to_string(), vram_bytes: 8 * 1024 * 1024 * 1024, power_watts: 200.0 },
            GpuDesc { index: 1, name: "GPU B".to_string(), vram_bytes: 16 * 1024 * 1024 * 1024, power_watts: 300.0 },
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
            assert!(f2 > f1, "throughput should increase from po2={po2} to {}", po2 + 1);
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
        assert!(po2 == 22 || po2 == 23, "8 GB GPU risc0 should get po2=22 or 23, got {po2}");
    }

    #[test]
    fn device_benchmarks_have_po2_fields() {
        let suite = run_benchmark();
        for db in &suite.device_benchmarks {
            assert!(
                db.optimal_po2 >= PO2_MIN && db.optimal_po2 <= PO2_MAX,
                "optimal_po2 {} out of range for {}",
                db.optimal_po2, db.prover_backend
            );
            assert!(db.memory_usage_bytes > 0, "memory_usage_bytes should be > 0");
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
        assert!(!suite.is_simulated(), "mixed results should not be considered simulated");
    }

    #[test]
    fn is_simulated_empty() {
        let suite = BenchmarkSuite::default();
        assert!(!suite.is_simulated(), "empty results should not be considered simulated");
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
            results: vec![
                BenchmarkResult {
                    program_name: "chacha-mix".to_string(),
                    prover_backend: "risc0".to_string(),
                    cycles: 34_000_000,
                    duration: Duration::from_secs(5),
                    throughput: 6_800_000.0,
                    weight: 0.0,
                    precompile: false,
                },
            ],
            ..Default::default()
        };
        assert_eq!(suite.average_throughput(), 0.0);
    }

    // ---- memory-merkle precompile flag ----

    #[test]
    fn memory_merkle_is_precompile() {
        let mm = BENCHMARK_PROGRAMS.iter().find(|p| p.name == "memory-merkle").unwrap();
        assert!(mm.precompile, "memory-merkle uses sha2 crate which triggers SHA-256 precompile");
    }

    // ---- suite_version is content-addressable ----

    #[test]
    fn suite_version_deterministic() {
        let v1 = suite_version();
        let v2 = suite_version();
        assert_eq!(v1, v2, "suite_version should be deterministic");
        assert!(v1.starts_with("v2-"), "suite_version should start with 'v2-'");
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
        assert!((pre - 1.0).abs() < 0.01, "precompile at baseline should be 1.0, got {pre}");
        assert!((comp - 1.0).abs() < 0.01, "compute at baseline should be 1.0, got {comp}");
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
        assert!((pre - 2.0).abs() < 0.01, "precompile should be 2.0x, got {pre}");
        assert!((comp - 1.0).abs() < 0.01, "compute should be 1.0x, got {comp}");
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
            device_id: "test".into(),
            device_label: "test".into(),
            prover_backend: "risc0".into(),
            throughput: 0.0,
            power_watts: 0.0,
            optimal_po2: 18,
            memory_usage_bytes: 0,
            max_feasible_po2: 18,
            program_throughputs: std::collections::HashMap::new(),
            po2_samples: Vec::new(),
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
            device_id: "test".into(),
            device_label: "test".into(),
            prover_backend: "risc0".into(),
            throughput: 1000.0,
            power_watts: 0.0,
            optimal_po2: 18,
            memory_usage_bytes: 0,
            max_feasible_po2: 18,
            program_throughputs: tp,
            po2_samples: Vec::new(),
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
            device_id: "test".into(),
            device_label: "test".into(),
            prover_backend: "risc0".into(),
            throughput: 150.0,
            power_watts: 0.0,
            optimal_po2: 18,
            memory_usage_bytes: 0,
            max_feasible_po2: 18,
            program_throughputs: tp,
            po2_samples: Vec::new(),
        };
        let cov = db.throughput_cov();
        assert!((cov - 0.333).abs() < 0.01, "expected ~0.333, got {cov}");
    }

    // ---- GPU device benchmarks are sized against real VRAM ----

    fn gpu_slot(vram_bytes: Option<u64>) -> crate::dispatcher::SlotBenchmarkResult {
        crate::dispatcher::SlotBenchmarkResult {
            slot_key: "risc0:cuda:0".to_string(),
            gpu_name: Some("Test GPU".to_string()),
            device_index: Some(0),
            gpu_tag: "cuda".to_string(),
            entries: vec![zkminer_prover_protocol::BenchmarkEntry {
                program_name: "fibonacci".to_string(),
                prover_backend: "risc0".to_string(),
                cycles: 1_000_000,
                duration_secs: 1.0,
                throughput: 1_000_000.0,
                weight: 0.10,
                precompile: false,
            }],
            vram_bytes,
        }
    }

    #[test]
    fn gpu_po2_is_sized_from_vram_not_hardcoded() {
        // 32 GB card: budget 28.8 GB, po2=24 needs 16 GB → fits.
        let big = build_gpu_device_benchmarks_from_workers(&[gpu_slot(Some(32 << 30))], 300.0);
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
        let small = build_gpu_device_benchmarks_from_workers(&[gpu_slot(Some(8 << 30))], 300.0);
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
        let unknown = build_gpu_device_benchmarks_from_workers(&[gpu_slot(None)], 300.0);
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
        assert!(!calibration_is_usable(&[sample(18, 8, 1.0)]), "single sample");
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
        assert_eq!(noisy.optimal_po2_for_job(60_000_000), 19, "argmax still picks 19");
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
        let unclamped = Po2Profile { samples, max_po2: 24, backend: "risc0".to_string() };
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
            device_id: "gpu0".to_string(),
            device_label: "GPU0 Test".to_string(),
            prover_backend: "risc0".to_string(),
            throughput: 2_000_000.0,
            power_watts: 300.0,
            optimal_po2: 21,
            memory_usage_bytes: 8 << 30,
            max_feasible_po2: 21,
            program_throughputs: std::collections::HashMap::new(),
            po2_samples: samples,
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
        let b = build_gpu_device_benchmarks_from_workers(&[gpu_slot(Some(32 << 30))], 300.0);
        assert!(
            (b[0].throughput - 1_000_000.0).abs() < 1e-6,
            "throughput must be the measured value, got {}",
            b[0].throughput
        );
    }
}
