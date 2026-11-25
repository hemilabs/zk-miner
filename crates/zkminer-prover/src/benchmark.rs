//! Benchmarking for zkVM proving performance.
//!
//! Measures GPUs on the benchmark suite (`BENCHMARK_PROGRAMS`), which sizes and prices jobs, and
//! for the **zkOP/s** score: SP1 cycles per second on one fixed 50M-cycle program. See
//! `zkminer_prover_protocol::zkops_from_stark_secs`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// The suite is the protocol crate's: the miner sends it to the workers, which prove what they are
/// sent. See `zkminer_prover_protocol::suite`.
pub use zkminer_prover_protocol::{BenchmarkProgram, BENCHMARK_PROGRAMS};

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
    /// W7-M11: why this program was measured below the host's full speed (Low Power Mode, battery,
    /// a throttling thermal state; `BenchmarkEntry::power_state`, protocol v12 of the macOS line, v17 since W11-ON37), or `None` when it
    /// was measured at full power or the worker reports no power state. A suite holding a Low Power
    /// Mode or battery row stays in use as measured, and the miner advises a re-benchmark once the
    /// host is at full power again ([`power_redo_reason`]).
    ///
    /// JSON only (benchmarks.json, never bincode), so it may skip `None`; `#[serde(default)]` keeps
    /// every older cache loading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_reduced: Option<String>,
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
    /// The segment size (po2) a risc0 row's suite was proved at (`risc0_benchmark_po2`), which
    /// `throughput` is the rate at. `None` on other backends, and on a row written before the size
    /// was the card's own: those were all proved at [`RISC0_DEFAULT_JOB_PO2`].
    ///
    /// `#[serde(default)]` for the reason given on `pci_bus_id`.
    ///
    /// [`RISC0_DEFAULT_JOB_PO2`]: zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2
    #[serde(default)]
    pub benchmark_po2: Option<u8>,
    /// The largest segment size a risc0 calibration proved on this card, which its kept samples
    /// (all at or below `max_feasible_po2`) may not show: a sweep that saw a larger size fail keeps
    /// none above its ceiling. `None` on a row calibrated before this was recorded, or never
    /// calibrated.
    ///
    /// `#[serde(default)]` for the reason given on `pci_bus_id`.
    #[serde(default)]
    pub highest_proved_po2: Option<u8>,
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
    /// margin this yields `None` — which is also what protects against adopting a noisy
    /// sweep on hardware where po2 simply does not matter much. (Jobs do not use it: a
    /// card proves every job at one size, see `risc0_job_po2`.)
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

/// What a card must have beyond a segment size's measured peak ([`RISC0_GPU_MEASURED_PEAK_MIB`]) to
/// prove at that size by default: the driver's reservation (272-455 MiB on the cards here) and room
/// for a desktop session. 1,900 MiB keeps the size these cards
/// were given before the smaller sizes were measured — 20 from 14 GiB — and gives a 12 GB card 19
/// and an 8 GB one 18.
pub const RISC0_JOB_VRAM_MARGIN: u64 = 1_900 * 1024 * 1024;

/// The smallest CUDA card that proves risc0 jobs by default: [`RISC0_GPU_MEASURED_PEAK_MIB`]'s
/// smallest size plus [`RISC0_JOB_VRAM_MARGIN`]. A smaller one needs a size set for it, or a
/// calibration.
pub const RISC0_JOB_MIN_VRAM_BYTES: u64 =
    RISC0_GPU_MEASURED_PEAK_MIB[0].1 * 1024 * 1024 + RISC0_JOB_VRAM_MARGIN;

/// The smallest AMD or Intel card that proves risc0 jobs by default, at the default size: nothing
/// has measured those vendors' cards per size, so a smaller one needs a size set for it or a
/// calibration, as every card under this did before the CUDA sizes were measured.
pub const RISC0_JOB_MIN_VRAM_BYTES_UNMEASURED: u64 = 14 * 1024 * 1024 * 1024;

/// The smallest card of vendor `gpu_tag` that proves risc0 jobs by default.
pub fn risc0_job_min_vram_bytes(gpu_tag: &str) -> u64 {
    if gpu_tag == "cuda" {
        RISC0_JOB_MIN_VRAM_BYTES
    } else {
        RISC0_JOB_MIN_VRAM_BYTES_UNMEASURED
    }
}

/// The default segment size for a CUDA card of `vram` bytes: the largest MEASURED size, up to
/// [`RISC0_DEFAULT_JOB_PO2`], whose peak plus [`RISC0_JOB_VRAM_MARGIN`] fits, or `None` when even the
/// smallest does not. Never an extrapolated size: a card is only given what something has proved.
///
/// [`RISC0_DEFAULT_JOB_PO2`]: zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2
pub fn risc0_default_job_po2_for_vram(vram: u64) -> Option<u8> {
    RISC0_GPU_MEASURED_PEAK_MIB
        .iter()
        .rev()
        .filter(|(po2, _)| *po2 <= zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2)
        .find(|(_, mib)| (mib * 1024 * 1024).saturating_add(RISC0_JOB_VRAM_MARGIN) <= vram)
        .map(|(po2, _)| *po2)
}

/// The segment size (po2) a risc0 card's benchmark proves the suite at: the size it proves jobs at
/// before any calibration or operator's size, so the rate it records is the one its jobs run at.
///
/// On a CUDA card of known VRAM, the largest measured size that fits
/// (`risc0_default_job_po2_for_vram`) or, on a card too small for any, the smallest measured one:
/// its rate still says what the card would do. Anywhere else [`RISC0_DEFAULT_JOB_PO2`], which every
/// card was benchmarked at before: no AMD or Intel card has been measured per size, and a 12 GB Arc
/// B580 proves 20. An Apple GPU: the Metal table's size for its idle budget ([`metal_job_po2`]),
/// which is what its worker proves jobs at by default (the CUDA rule says 20 on every Mac, beyond
/// the working set of a 16 or 18 GB one).
///
/// [`RISC0_DEFAULT_JOB_PO2`]: zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2
pub fn risc0_benchmark_po2(vram_bytes: Option<u64>, gpu_tag: &str) -> u8 {
    if gpu_tag == "metal" {
        return metal_job_po2(vram_bytes);
    }
    match vram_bytes {
        Some(v) if gpu_tag == "cuda" => {
            risc0_default_job_po2_for_vram(v).unwrap_or(RISC0_GPU_MEASURED_PEAK_MIB[0].0)
        }
        _ => zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2,
    }
}

/// The segment size (po2) a risc0 card measures and proves jobs at, or `None` for a card that proves
/// none.
///
/// In order: the operator's size for the card (config or Settings); else, by default,
/// [`RISC0_DEFAULT_JOB_PO2`] on a card whose VRAM is unknown (what every card proved at before), or the
/// largest measured size that fits on a CUDA card (`risc0_default_job_po2_for_vram`: 20 from 14
/// GiB, 19 on a 12 GB card, 18 on an 8 GB one), 20 on an AMD or Intel card from
/// [`RISC0_JOB_MIN_VRAM_BYTES_UNMEASURED`], or nothing on a card too small; a calibration (real
/// Groth16 proofs at each size, see `calibrate_po2_for_suite`) can raise that default to its
/// measured-fastest size or give a smaller card one, but never lowers it below a size it proved: its
/// ceiling keeps a step of headroom below the highest size that succeeded, which on the 16 GB 5080 is
/// 19 where 20 proves. A calibration that saw the default size fail stands.
/// Always within [`RISC0_JOB_PO2_MIN`]..=[`RISC0_JOB_PO2_MAX`]. The size is the card's, not the
/// job's: a guest can tell the size it runs at, so every job is measured at the size of each card that
/// may prove it.
///
/// [`RISC0_DEFAULT_JOB_PO2`]: zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2
/// [`RISC0_JOB_PO2_MIN`]: zkminer_prover_protocol::RISC0_JOB_PO2_MIN
/// [`RISC0_JOB_PO2_MAX`]: zkminer_prover_protocol::RISC0_JOB_PO2_MAX
pub fn risc0_job_po2(
    override_po2: Option<u8>,
    row: Option<&DeviceBenchmark>,
    vram_bytes: Option<u64>,
    gpu_tag: &str,
) -> Option<u8> {
    use zkminer_prover_protocol::{RISC0_DEFAULT_JOB_PO2, RISC0_JOB_PO2_MAX, RISC0_JOB_PO2_MIN};
    let in_range = |p: u8| p.clamp(RISC0_JOB_PO2_MIN, RISC0_JOB_PO2_MAX);
    if let Some(p) = override_po2 {
        return Some(in_range(p));
    }
    // A card whose VRAM could not be read this time proves at the size its benchmark ran at, which
    // was its default when it was read: its rate is that size's, and 20 may not fit it.
    let benchmarked = row
        .filter(|db| db.prover_backend == "risc0")
        .and_then(|db| db.benchmark_po2);
    let default = match vram_bytes {
        Some(v) if gpu_tag == "cuda" => risc0_default_job_po2_for_vram(v),
        Some(v) if v < RISC0_JOB_MIN_VRAM_BYTES_UNMEASURED => None,
        Some(_) => Some(RISC0_DEFAULT_JOB_PO2),
        None => Some(benchmarked.map_or(RISC0_DEFAULT_JOB_PO2, in_range)),
    };
    match row.filter(|db| db.prover_backend == "risc0" && !db.po2_samples.is_empty()) {
        Some(db) => {
            let calibrated = in_range(db.optimal_po2.min(db.max_feasible_po2));
            // Raised to the default only when the calibration proved the default size: its ceiling
            // is a step below the highest size that proved when a larger one failed, so one at or
            // above the default less one. A lower ceiling means the default size failed there (a
            // display holding VRAM, or a card whose VRAM read failed), and the calibration stands.
            //
            // A ceiling the card's free VRAM set is the highest size that proved, not one below it,
            // so the default proved only if `highest_proved_po2` reaches it; a row calibrated
            // before that was recorded keeps the ceiling rule.
            let proved_default = default.filter(|d| match db.highest_proved_po2 {
                Some(highest) => highest >= *d,
                None => db.max_feasible_po2.saturating_add(1) >= *d,
            });
            Some(proved_default.map_or(calibrated, |d| calibrated.max(d)))
        }
        None => default,
    }
}

/// [`risc0_job_po2`] for one risc0 slot, by its benchmark device id (`WorkerPool::risc0_slots`).
///
/// An Apple GPU (`gpu-metal<N>`) is sized from the shared Metal table
/// ([`crate::metal_sizing::job_po2_for_limit`]), the same one the Metal worker uses for its own
/// default and ceiling, rather than from the discrete-card rule: that rule gave NO job size to a
/// 16 GB Mac's 8 GiB (M6), where the table says 19 (M8; `ZKMINER_METAL_PO2_TABLE=m1` restores M1's
/// 18), and 20 to any figure of at least [`RISC0_JOB_MIN_VRAM_BYTES`], which only agrees with the
/// table since M8. A calibrated Metal row is honoured as for any card, and
/// raised only to the table's size. An operator override still wins. Every other device: unchanged.
/// `gpu_tag` is the slot's GPU backend (`cuda`, `rocm`, `intel`, `metal`), as [`risc0_job_po2`]
/// takes it.
pub fn risc0_slot_job_po2(
    device_id: &str,
    gpu_tag: &str,
    override_po2: Option<u8>,
    row: Option<&DeviceBenchmark>,
    vram_bytes: Option<u64>,
) -> Option<u8> {
    use zkminer_prover_protocol::{RISC0_JOB_PO2_MAX, RISC0_JOB_PO2_MIN};
    if !is_metal_device_id(device_id) {
        return risc0_job_po2(override_po2, row, vram_bytes, gpu_tag);
    }
    let in_range = |p: u8| p.clamp(RISC0_JOB_PO2_MIN, RISC0_JOB_PO2_MAX);
    if let Some(p) = override_po2 {
        return Some(in_range(p));
    }
    let default = metal_job_po2(vram_bytes);
    match row.filter(|db| db.prover_backend == "risc0" && !db.po2_samples.is_empty()) {
        Some(db) => {
            let calibrated = in_range(db.optimal_po2.min(db.max_feasible_po2));
            let proved_default = db.max_feasible_po2.saturating_add(1) >= default;
            Some(if proved_default {
                calibrated.max(default)
            } else {
                calibrated
            })
        }
        None => Some(default),
    }
}

/// Whether a benchmark device id names an Apple GPU (`WorkerPool::gpu_device_id("metal", ..)`).
pub fn is_metal_device_id(device_id: &str) -> bool {
    device_id.starts_with("gpu-metal")
}

/// The Metal table's segment size for the host's figure for an Apple GPU (`hw.memsize` less the host
/// reserve) and `RISC0_METAL_MAX_WORKING_SET_BYTES`. With neither known, the protocol default: the
/// worker then sizes itself, and refuses what does not fit.
pub fn metal_job_po2(vram_bytes: Option<u64>) -> u8 {
    match crate::metal_sizing::host_working_set_limit(vram_bytes) {
        Some(limit) => crate::metal_sizing::job_po2_for_limit(limit),
        None => zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2,
    }
}

/// The largest job size whose peak (`risc0_gpu_peak`: measured to 20, extrapolated above) plus
/// [`RISC0_JOB_VRAM_MARGIN`] fits a CUDA card of `vram` bytes (0 on one too small for any), or
/// `None` when that is unknown (VRAM not read, or another vendor's card, whose peaks nothing has
/// measured). For pricing a size above it (`risc0_job_throughput`), never for choosing one: above
/// 20 the figures are an extrapolation.
pub fn risc0_largest_fitting_po2(vram: Option<u64>, gpu_tag: &str) -> Option<u8> {
    use zkminer_prover_protocol::{RISC0_JOB_PO2_MAX, RISC0_JOB_PO2_MIN};
    let vram = vram.filter(|_| gpu_tag == "cuda")?;
    let fits = (RISC0_JOB_PO2_MIN..=RISC0_JOB_PO2_MAX)
        .rev()
        .find(|p| risc0_gpu_peak(*p).saturating_add(RISC0_JOB_VRAM_MARGIN) <= vram);
    Some(fits.unwrap_or(0))
}

/// Throughput factor per segment-size step below the smallest size a row was measured at.
///
/// Recursion (lift/join) costs per segment, so it doubles per step down while the segments themselves
/// barely change: a 62M-cycle proof on the 4090 took 44.0 / 57.6 / 87.2 s at po2 20 / 19 / 18 (×0.76,
/// then ×0.66 per step). A step down therefore costs less than twice the time, so halving the rate is
/// a bound, however far down.
pub const RISC0_PO2_STEP_DOWN_FACTOR: f64 = 0.5;

/// Throughput factor per segment-size step above the largest size a row was measured at, when that
/// size is below [`RISC0_DEFAULT_JOB_PO2`]: a card benchmarked or calibrated below it is one its
/// measured peaks say the next size does not fit (`risc0_benchmark_po2`), so a size set above that
/// spills into system memory under Windows, or fails. On the 12 GB RTX 4070, measured at 19, the
/// suite took ~14 minutes at 20 against 4 at 19, and po2 21 ran at 0.24M c/s against 1.22M: a
/// quarter per step.
///
/// [`RISC0_DEFAULT_JOB_PO2`]: zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2
pub const RISC0_PO2_STEP_UP_UNFIT_FACTOR: f64 = 0.25;

/// The throughput (cycles/s) to plan a risc0 job on this card at `po2`, the card's job size.
///
/// The row's throughput was measured at its `benchmark_po2` ([`RISC0_DEFAULT_JOB_PO2`] on a row
/// without one). A calibrated card is held to the lower of that and its measured rate at `po2`
/// (which includes the Groth16 wrap). Below the smallest size either was measured at, each step
/// down is charged [`RISC0_PO2_STEP_DOWN_FACTOR`]. Above the largest, nothing is credited, and each
/// step above a size the card is not known to hold is charged [`RISC0_PO2_STEP_UP_UNFIT_FACTOR`]:
/// above the largest measured size on a card measured only below [`RISC0_DEFAULT_JOB_PO2`] (one too
/// small for it), else above `largest_fit` (`risc0_largest_fitting_po2`, the card's VRAM against
/// the peaks), or the largest size measured if that is higher. An operator's size, or the default
/// on a card whose VRAM could not be read, may not fit the card.
///
/// [`RISC0_DEFAULT_JOB_PO2`]: zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2
pub fn risc0_job_throughput(row: &DeviceBenchmark, po2: u8, largest_fit: Option<u8>) -> f64 {
    let benchmarked = row
        .benchmark_po2
        .unwrap_or(zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2);
    let (rate, lowest, highest) = match Po2Profile::from_device_benchmark(row) {
        Some(profile) => {
            let lowest = profile.samples.iter().map(|s| s.po2).min().unwrap_or(po2);
            let highest = profile.samples.iter().map(|s| s.po2).max().unwrap_or(po2);
            (
                row.throughput.min(profile.throughput_at_po2(po2)),
                lowest,
                highest.max(benchmarked),
            )
        }
        None => (row.throughput, benchmarked, benchmarked),
    };
    let held = if highest < zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2 {
        highest
    } else {
        largest_fit.map_or(u8::MAX, |fit| fit.max(highest))
    };
    let up = RISC0_PO2_STEP_UP_UNFIT_FACTOR.powi(i32::from(po2.saturating_sub(held)));
    rate * up * RISC0_PO2_STEP_DOWN_FACTOR.powi(i32::from(lowest.saturating_sub(po2)))
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
        // The scoring program has its own use (`zkops`) and does not take part in job sizing.
        let priced = || {
            self.program_stages
                .iter()
                .filter(|p| p.program_name != zkminer_prover_protocol::BENCH_ZKOP_MIX)
        };
        let cycles: u64 = priced().map(|p| p.cycles).sum();
        let secs: f64 = priced().map(|p| p.stark_secs).sum();
        (cycles > 0 && secs > 0.0).then(|| cycles as f64 / secs)
    }

    /// The scoring program's proof on this backend, if it ran.
    fn scoring_stage(&self) -> Option<&ProgramStage> {
        self.program_stages
            .iter()
            .find(|p| p.program_name == zkminer_prover_protocol::BENCH_ZKOP_MIX)
            .filter(|p| p.stark_secs > 0.0)
    }

    /// The scoring program's rate in this zkVM's own cycles per second. This zkVM's score as shown;
    /// cycles of different zkVMs are not comparable, so it is no part of a GPU's MzkOP/s as such.
    pub fn scoring_cycles_per_sec(&self) -> Option<f64> {
        self.scoring_stage().map(|p| p.cycles as f64 / p.stark_secs)
    }

    /// The scoring proof's speed in zkOP/s (SP1 cycles of the program per second), what
    /// `gpu_zkops` blends.
    pub fn zkop_mix_rate(&self) -> Option<f64> {
        self.scoring_stage()
            .map(|p| zkminer_prover_protocol::zkops_from_stark_secs(p.stark_secs))
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

    /// W7-M11: why any program of this row was measured in reduced power (the reasons of
    /// [`ProgramStage::power_reduced`], once each), or `None` when none was.
    pub fn power_reduced(&self) -> Option<String> {
        let mut why: Vec<&str> = Vec::new();
        for r in self
            .program_stages
            .iter()
            .filter_map(|p| p.power_reduced.as_deref())
        {
            for part in r.split(", ") {
                if !why.contains(&part) {
                    why.push(part);
                }
            }
        }
        (!why.is_empty()).then(|| why.join(", "))
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
    /// zkOP/s of the whole machine; see [`machine_zkops`]. 0 when no GPU has a score.
    pub zkops: f64,
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
    /// The worker slots whose benchmark failed in THIS run (W10-BENCH). Never written to or read from
    /// the cache (`serde(skip)`): a suite with any is a failed run, which `save_benchmark` refuses, and
    /// every caller must report it as a failure rather than show or price its rows.
    #[serde(skip)]
    pub failures: Vec<crate::dispatcher::SlotBenchmarkFailure>,
    /// Slots that were down when this run started (declined at startup, or could not be started) in
    /// a run where another slot measured: reported to the operator, but they do not fail the run
    /// (`dispatcher::BenchmarkRun::not_benchmarked`). Never cached.
    #[serde(skip)]
    pub not_benchmarked: Vec<crate::dispatcher::SlotBenchmarkFailure>,
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

/// Peak VRAM, in MiB, of a risc0 Groth16 proof on a CUDA card at each MEASURED segment size (po2).
/// The largest is the last a card's free VRAM can cap it at (`find_optimal_gpu_po2`).
///
/// 18 and 19: a 62M-cycle job on a 12,282 MiB RTX 4070 under Windows, driving no display, from
/// `zkminer benchmark --calibrate` (2026-11-16): 4,709 MiB in 75 s and 8,179 MiB in 52 s, neither
/// touching system memory. 20: 12,436 MiB on the 16 GB RTX 5080 with the Groth16 cache released
/// between proofs (`tests/risc0_groth16_vram.rs`); on the 4070 it filled the card and spilled about
/// 1.9 GiB into system memory.
///
/// Not a doubling, which is what the estimate this replaced assumed (256 MB at 18, so 4 GB at 22):
/// about 1.2 GiB is fixed, and what grows grew 3.4 then 4.2 GiB a step.
pub const RISC0_GPU_MEASURED_PEAK_MIB: &[(u8, u64)] = &[(18, 4_709), (19, 8_179), (20, 12_436)];

/// [`RISC0_GPU_MEASURED_PEAK_MIB`] at `po2`, in bytes, for a CUDA card: measured where it was, the 18 figure below that
/// (a smaller segment needs no more), and above 20 each step's growth doubled from the last measured
/// one — 20,950 MiB at 21 and 37,978 at 22, which agrees with what is known there: a 24 GB RTX 4090
/// proved 21 and failed 22 on a single 13.2 GiB allocation, and a 16 GB card spilled at 21.
fn risc0_gpu_peak(po2: u8) -> u64 {
    const MIB: u64 = 1024 * 1024;
    let table = RISC0_GPU_MEASURED_PEAK_MIB;
    let (first, last) = (table[0], table[table.len() - 1]);
    if po2 <= first.0 {
        return first.1 * MIB;
    }
    if let Some((_, mib)) = table.iter().find(|(p, _)| *p == po2) {
        return mib * MIB;
    }
    let mut step = last.1 - table[table.len() - 2].1;
    let mut peak = last.1;
    for _ in last.0..po2 {
        step = step.saturating_mul(2);
        peak = peak.saturating_add(step);
    }
    peak.saturating_mul(MIB)
}

/// Estimate memory usage on a GPU of vendor `gpu_tag` for a given po2 and backend.
///
/// risc0 on a CUDA card: [`RISC0_GPU_MEASURED_PEAK_MIB`]. Anything else: [`estimate_po2_memory`]'s
/// guess, which is far below a risc0 CUDA card's real figures — AMD and Intel cards keep it because
/// nothing has measured them per size, and their memory use differs (a 12 GB Arc B580 proved po2 20
/// without spilling, which a 12 GB RTX 4070 cannot), so their calibration still sweeps as high as it
/// did and finds out.
pub fn estimate_gpu_po2_memory(po2: u8, backend: &str, gpu_tag: &str) -> u64 {
    if backend == "risc0" && gpu_tag == "cuda" {
        return risc0_gpu_peak(po2);
    }
    estimate_po2_memory(po2, backend, true)
}

/// The largest po2 a GPU of vendor `gpu_tag` with `device_memory_bytes` is expected to hold, and
/// that size's estimate: the cap on a card's sizes (`max_feasible_po2`) and on a calibration sweep.
///
/// risc0 on a CUDA card is capped only by a MEASURED size: the largest of
/// [`RISC0_GPU_MEASURED_PEAK_MIB`] that fits 90% of the memory, and when even the largest measured
/// size fits, no cap at all ([`PO2_MAX`]) — sizes past the measured ones are found by proving them,
/// whose failure is what sets a card's ceiling, with a step of headroom (`sweep_po2`). An
/// extrapolated figure never caps: a cap is no observed limit, so a sweep that stops at one keeps
/// its top, and a 4090 capped at 21 by an extrapolation would then have proved jobs at 21, where
/// a real one ran out of memory. Anything else: [`estimate_po2_memory`]'s guess, as before.
pub fn find_optimal_gpu_po2(device_memory_bytes: u64, backend: &str, gpu_tag: &str) -> (u8, u64) {
    if backend == "risc0" && gpu_tag == "cuda" {
        let table = RISC0_GPU_MEASURED_PEAK_MIB;
        let (largest, _) = table[table.len() - 1];
        let (po2, _) = largest_po2_within(device_memory_bytes, |po2| {
            if po2 <= largest {
                risc0_gpu_peak(po2)
            } else {
                u64::MAX
            }
        });
        let po2 = if po2 >= largest { PO2_MAX } else { po2 };
        return (po2, risc0_gpu_peak(po2));
    }
    largest_po2_within(device_memory_bytes, |po2| {
        estimate_gpu_po2_memory(po2, backend, gpu_tag)
    })
}

/// Estimate memory usage for a given po2, backend, and device type: a guess, base memory at po2=18
/// of 512 MB on a CPU and 256 MB on a GPU, doubling each po2 step, with the backend's multiplier on
/// top. For a GPU, [`estimate_gpu_po2_memory`] is the better figure.
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
    largest_po2_within(device_memory_bytes, |po2| {
        estimate_po2_memory(po2, backend, is_gpu)
    })
}

/// The largest po2 whose `estimate` fits 90% of `device_memory_bytes`, and that estimate; `PO2_MIN`
/// when none does.
fn largest_po2_within(device_memory_bytes: u64, estimate: impl Fn(u8) -> u64) -> (u8, u64) {
    let budget = (device_memory_bytes as f64 * 0.90) as u64;
    let mut best_po2 = PO2_MIN;
    let mut best_mem = estimate(PO2_MIN);

    for po2 in PO2_MIN..=PO2_MAX {
        let mem = estimate(po2);
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
    /// True when a worker slot's benchmark failed in this run (W10-BENCH): the run is a failure, even
    /// if other slots measured.
    pub fn failed(&self) -> bool {
        !self.failures.is_empty()
    }

    /// Why this suite must not be saved to the benchmark cache, or `None` when it may be (W10-BENCH).
    /// The cache prices every job `zkminer run` claims, so only a complete, measured run belongs there.
    pub fn not_cacheable(&self) -> Option<String> {
        if self.failed() {
            let slots: Vec<&str> = self.failures.iter().map(|f| f.slot_key.as_str()).collect();
            return Some(format!("the benchmark failed on {}", slots.join(", ")));
        }
        if self.is_simulated() {
            return Some("its results are simulated, not measured".to_string());
        }
        if self.results.is_empty()
            && self.device_benchmarks.is_empty()
            && self.host_peaks.is_empty()
        {
            return Some("it measured nothing".to_string());
        }
        None
    }

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
                find_optimal_gpu_po2(gpu.vram_bytes, profile.name, "cuda");
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
                benchmark_po2: None,
                highest_proved_po2: None,
            });
        }
    }
}

/// The GPU `device_id`'s score in zkOP/s: its SP1 and RISC Zero scoring proofs blended
/// (`zkminer_prover_protocol::blended_zkops`), over whichever it ran. `None` when it ran neither.
pub fn gpu_zkops(devices: &[DeviceBenchmark], device_id: &str) -> Option<f64> {
    let rate = |backend: &str| {
        devices
            .iter()
            .filter(|d| d.device_id == device_id && d.prover_backend == backend)
            .find_map(DeviceBenchmark::zkop_mix_rate)
    };
    zkminer_prover_protocol::blended_zkops(rate("sp1"), rate("risc0"))
}

/// The machine's zkOP/s: every GPU's score, added up, as they prove side by side.
pub fn machine_zkops(devices: &[DeviceBenchmark]) -> f64 {
    let mut ids: Vec<&str> = Vec::new();
    for d in devices {
        if !ids.contains(&d.device_id.as_str()) {
            ids.push(&d.device_id);
        }
    }
    ids.into_iter()
        .filter_map(|id| gpu_zkops(devices, id))
        .sum()
}

/// A GPU's or machine's score for display, e.g. "13.83 MzkOP/s".
pub fn format_mzkops(zkops: f64) -> String {
    // `+ 0.0` turns a -0.0 (no score) into 0.00, not "-0.00".
    format!("{:.2} MzkOP/s", zkops / 1e6 + 0.0)
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
    // macOS has no `/proc/cpuinfo`; the kernel's own brand string ("Apple M5 Max") is the same
    // fact. It feeds `hardware_fingerprint`, so it must be stable across runs, which it is.
    #[cfg(target_os = "macos")]
    {
        if let Some(name) = crate::memory::sysctl_string("machdep.cpu.brand_string") {
            return name;
        }
    }
    #[cfg(windows)]
    if let Some(name) = windows_cpu::processor_name() {
        return name;
    }
    "Unknown CPU".to_string()
}

/// Physical CPU cores, on Windows. (On Linux the TUI counts them from `/proc/cpuinfo`.)
#[cfg(windows)]
pub fn physical_core_count() -> Option<u32> {
    windows_cpu::physical_cores()
}

/// Physical CPU cores, on macOS (`hw.physicalcpu`), which has no `/proc/cpuinfo` either.
#[cfg(target_os = "macos")]
pub fn physical_core_count() -> Option<u32> {
    crate::memory::sysctl_u64("hw.physicalcpu")
        .filter(|&n| n > 0)
        .and_then(|n| u32::try_from(n).ok())
}

/// The CPU's name and core count from Windows, which has no `/proc/cpuinfo`.
#[cfg(windows)]
mod windows_cpu {
    use std::ffi::c_void;

    const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
    const RRF_RT_REG_SZ: u32 = 0x2;
    const RELATION_PROCESSOR_CORE: u32 = 0;

    /// SYSTEM_LOGICAL_PROCESSOR_INFORMATION: mask, relationship, then a 16-byte union.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct LogicalProcessorInfo {
        mask: usize,
        relationship: u32,
        _union: [u64; 2],
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn RegGetValueW(
            key: isize,
            sub_key: *const u16,
            value: *const u16,
            flags: u32,
            kind: *mut u32,
            data: *mut c_void,
            len: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetLogicalProcessorInformation(buf: *mut LogicalProcessorInfo, len: *mut u32) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The marketing name Windows shows (as `/proc/cpuinfo`'s `model name` is on Linux).
    pub fn processor_name() -> Option<String> {
        let key = wide(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
        let value = wide("ProcessorNameString");
        let mut buf = [0u16; 256];
        let mut len = std::mem::size_of_val(&buf) as u32;
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if status != 0 {
            return None;
        }
        let chars = (len as usize / 2).min(buf.len());
        let name = String::from_utf16_lossy(&buf[..chars]);
        let name = name.trim_end_matches('\0').trim();
        (!name.is_empty()).then(|| name.to_string())
    }

    pub fn physical_cores() -> Option<u32> {
        let mut len = 0u32;
        unsafe { GetLogicalProcessorInformation(std::ptr::null_mut(), &mut len) };
        let count = len as usize / std::mem::size_of::<LogicalProcessorInfo>();
        if count == 0 {
            return None;
        }
        let mut infos = vec![
            LogicalProcessorInfo {
                mask: 0,
                relationship: 0,
                _union: [0; 2]
            };
            count
        ];
        if unsafe { GetLogicalProcessorInformation(infos.as_mut_ptr(), &mut len) } == 0 {
            return None;
        }
        let cores = infos
            .iter()
            .take(len as usize / std::mem::size_of::<LogicalProcessorInfo>())
            .filter(|info| info.relationship == RELATION_PROCESSOR_CORE)
            .count() as u32;
        (cores > 0).then_some(cores)
    }
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
/// Every vendor is read:
///
/// * AMD through hwmon `power1_average` on Linux.
/// * Intel and AMD on Windows through their drivers' libraries (`windows_telemetry`). Without
///   them those cards were never measured, so their rows took `FALLBACK_GPU_WATTS`.
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
    // AMD's reader is sysfs hwmon, so Linux only; nvidia-smi answers the same query on
    // Windows, where leaving it out made every card take FALLBACK_GPU_WATTS.
    #[cfg(target_os = "linux")]
    read_amd_power_by_card(proving_bus_ids, &mut out);
    #[cfg(windows)]
    read_windows_power_by_card(proving_bus_ids, &mut out);
    // Asked only for cards the others did not read: on a machine without NVIDIA cards the query
    // fails every time, and the sampler gives up after a few failures in a row, which would end
    // the Intel and AMD readings with it.
    let unread = proving_bus_ids.iter().any(|bus| !out.contains_key(bus));
    let probe_failed = unread && !read_nvidia_power_by_card(proving_bus_ids, &mut out);
    PowerSample {
        per_card: out,
        probe_failed,
    }
}

/// NVIDIA per-card draw via nvidia-smi.
/// Returns false when the QUERY itself did not answer — which is the leak signal the sampler's
/// give-up cap counts. A successful query that reports no usable row for some card returns true:
/// that is a fact about the card, not a failure of the probe.
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

/// Intel and AMD per-card draw on Windows, through their drivers' libraries. Intel's comes from an
/// energy counter, so a card has no reading until its second sample.
#[cfg(windows)]
fn read_windows_power_by_card(proving_bus_ids: &[String], out: &mut BTreeMap<String, f64>) {
    use crate::windows_telemetry::{GpuTelemetry, WindowsTelemetry};
    use std::sync::{Mutex, OnceLock};
    // One for the process: the counters' previous readings live in it.
    static TELEMETRY: OnceLock<Mutex<WindowsTelemetry>> = OnceLock::new();
    let telemetry = TELEMETRY.get_or_init(|| {
        let (intel, amd) = telemetry_vendors(
            crate::windows_gpu_memory::adapter_vendors().as_deref(),
            proving_bus_ids,
        );
        Mutex::new(WindowsTelemetry::new(intel, amd))
    });
    let Ok(mut telemetry) = telemetry.lock() else {
        return;
    };
    for bus in proving_bus_ids {
        let mut reading = GpuTelemetry {
            pci_bus_id: bus.clone(),
            ..Default::default()
        };
        telemetry.refresh(&mut reading);
        if reading.power_watts.is_finite() && reading.power_watts > 0.0 {
            fold_peak(out, [(bus.clone(), reading.power_watts)]);
        }
    }
}

/// Which vendors' libraries the power readings need, `(intel, amd)`: those of the proving cards, by
/// the PCI vendor ids in `adapters` (`(pci address, vendor)`). A library is loaded only for a vendor
/// whose card proves here: a vendor library loaded on a machine without its GPU does nothing but
/// leave its own threads and event registrations behind (Intel's crashed the miner that way). A
/// proving card whose vendor is unknown (the adapters could not be listed) asks for both, as before.
#[cfg(any(windows, test))]
fn telemetry_vendors(
    adapters: Option<&[(String, u32)]>,
    proving_bus_ids: &[String],
) -> (bool, bool) {
    const INTEL: u32 = 0x8086;
    const AMD: u32 = 0x1002;
    let (mut intel, mut amd) = (false, false);
    for bus in proving_bus_ids {
        match adapters.and_then(|a| a.iter().find(|(pci, _)| pci == bus)) {
            Some((_, INTEL)) => intel = true,
            Some((_, AMD)) => amd = true,
            Some(_) => {}
            None => return (true, true),
        }
    }
    (intel, amd)
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
        log_cpu_power_unavailable();
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
        results.push(crate::risc0::benchmark_sha256_chain(10_000));
    }

    #[cfg(feature = "sp1")]
    {
        results.push(crate::sp1::benchmark_sha256_chain(10_000));
    }

    // Subprocess worker benchmarks (always try — captures GPU provers).
    // Use benchmark_all_with_device_info to get GPU metadata alongside results.
    let pool = crate::engine::worker_pool();
    // W10-BENCH: a worker that was started but produced nothing is a FAILED benchmark, never a
    // reason to show simulated numbers.
    let workers_present = pool.is_some_and(|p| p.has_any_worker());
    let crate::dispatcher::BenchmarkRun {
        results: worker_device_results,
        mut failures,
        not_benchmarked,
        ..
    } = if let Some(pool) = pool {
        let run = pool.benchmark_all_with_device_info();
        if !run.results.is_empty() {
            let total: usize = run.results.iter().map(|r| r.entries.len()).sum();
            tracing::info!(
                "Got {} benchmark results from {} subprocess workers",
                total,
                run.results.len()
            );
        }
        run
    } else {
        crate::dispatcher::BenchmarkRun::default()
    };

    // Flatten worker entries for main results (if no compile-time backend)
    if results.is_empty() {
        for slot_result in &worker_device_results {
            for entry in &slot_result.entries {
                results.push(benchmark_entry_to_result(entry));
            }
        }
    }

    // Simulated only when there is no prover at all: no compiled-in backend and no worker
    // (W10-BENCH). With a worker present, an empty result is that worker's failure.
    let mut simulated = false;
    if results.is_empty() {
        if workers_present {
            note_unexplained_empty_run(&mut failures);
        } else {
            results = run_simulated_benchmarks();
            simulated = true;
        }
    }

    // Snapshot power counters after benchmarks
    let power_elapsed = power_start.elapsed();
    let per_card = power_sampler.finish();

    // Compute average CPU power from the RAPL energy delta (shared with the GPU-only paths, so
    // all three record the same quantity the same way).
    let cpu_power_watts = cpu_power_over(rapl_before, power_elapsed);

    let gpu_power_watts = match suite_total_watts(&per_card) {
        // Nothing proved on a card (a failed or simulated run): there are no rows to carry a figure.
        None if worker_device_results.is_empty() => None,
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

    // Device rows are the GPU workers' own measurements only. A CPU row used to be made up here
    // from the GPU results (their mean throughput times a per-backend factor), which showed the CPU
    // proving faster than the cards without a single CPU proof behind it; the cost model already
    // skipped it. Cached suites drop theirs on load (`drop_cpu_device_rows`).
    //
    // Workers are keyed like "risc0:cuda:0", "risc0:rocm:1", etc.
    // Each worker ran the full benchmark suite on its assigned GPU — use
    // the measured average throughput directly.
    let device_benchmarks =
        build_gpu_device_benchmarks_from_workers(&worker_device_results, &per_card);

    // No score from a simulated run: nothing was proved.
    let zkops = if simulated {
        0.0
    } else {
        machine_zkops(&device_benchmarks)
    };
    BenchmarkSuite {
        results,
        device_benchmarks,
        cpu_info,
        timestamp,
        zkops,
        cpu_power_watts,
        gpu_power_watts,
        host_peaks: host_peaks_from_workers(&worker_device_results),
        failures,
        not_benchmarked,
    }
}

/// The CPU-power line of a benchmark whose host cannot read the CPU's draw. The `/dev/cpu/0/msr`
/// advice is Linux's (RAPL); macOS has no such counter for an unprivileged process, so it is told what
/// the cost model uses instead (W10-BENCH).
fn log_cpu_power_unavailable() {
    #[cfg(target_os = "linux")]
    tracing::warn!(
        "CPU power monitoring unavailable. \
         To enable, run: sudo chmod o+r /dev/cpu/0/msr"
    );
    #[cfg(target_os = "macos")]
    tracing::info!(
        "CPU power is not measured on macOS; the cost model uses the configured system_power_watts \
         and its default CPU draw"
    );
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    tracing::info!("CPU power is not measured on this platform");
}

/// A run with workers present that measured nothing and reported no slot failure (only measure
/// workers started, or every slot was skipped) is still a failure, with a reason (W10-BENCH).
fn note_unexplained_empty_run(failures: &mut Vec<crate::dispatcher::SlotBenchmarkFailure>) {
    if failures.is_empty() {
        tracing::error!("{NO_PROVING_WORKER}");
        failures.push(crate::dispatcher::SlotBenchmarkFailure {
            slot_key: "workers".to_string(),
            gpu_name: None,
            // The advice follows the tag: on a Mac the prover is the Metal worker, whose advice is
            // macos-smoke.sh and the kit README, not a generic `--benchmark` line.
            gpu_tag: if cfg!(target_os = "macos") {
                "metal"
            } else {
                "generic"
            }
            .to_string(),
            error: NO_PROVING_WORKER.to_string(),
        });
    }
}

/// The failure of a run whose workers started but none of which could benchmark.
const NO_PROVING_WORKER: &str = "prover workers started, but none of them could run the benchmark \
     (no proving worker is up; see the log above for why it did not start)";

/// What to try after a slot's benchmark failed, for the operator (W10-BENCH).
pub fn benchmark_failure_advice(gpu_tag: &str) -> &'static str {
    match gpu_tag {
        "metal" => {
            "Run tools/macos-smoke.sh from the macOS kit folder: it proves and verifies one small \
             proof and says what failed. See Troubleshooting in the kit's README.md."
        }
        _ => {
            "Check the worker's log lines above, then run the worker's own benchmark by hand \
             (`<worker binary> --benchmark`) to see the error on its own."
        }
    }
}

/// What to try when a Metal worker could not start (W10-BFIX).
pub const METAL_START_ADVICE: &str =
    "The prover could not start. If it was copied out of the kit by hand, or macOS blocked it, run \
     ./install.sh from the kit folder again: the installed copies have no com.apple.quarantine \
     mark (see Gatekeeper in the kit's README.md; check with `xattr -l \
     ~/.zkminer/provers/zkminer-prove-risc0-metal`).";

/// The failures of a run, one line each, with what to try: for the CLI and the TUI (W10-BENCH).
pub fn describe_failures(failures: &[crate::dispatcher::SlotBenchmarkFailure]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut advice: Vec<&'static str> = Vec::new();
    for f in failures {
        let on = f
            .gpu_name
            .as_deref()
            .map(|g| format!(" ({g})"))
            .unwrap_or_default();
        lines.push(format!("{}{on}: {}", f.slot_key, f.error));
        let a = benchmark_failure_advice(&f.gpu_tag);
        if !advice.contains(&a) {
            advice.push(a);
        }
        // A Metal worker that never started: the likeliest cause on an unsigned beta is a copy that
        // still carries the browser's quarantine mark, which Gatekeeper kills at exec (W10-BFIX).
        if f.gpu_tag == "metal"
            && f.error.starts_with(crate::dispatcher::COULD_NOT_START)
            && !advice.contains(&METAL_START_ADVICE)
        {
            advice.push(METAL_START_ADVICE);
        }
    }
    lines.extend(advice.into_iter().map(str::to_string));
    lines
}

/// The slots a successful run could not benchmark, one line each, for the CLI and the TUI: declined
/// at startup, down beside a measured GPU of their own backend, or a worker that only simulates
/// (W10-BENCH rounds 1 and 2; see `dispatcher::BenchmarkRun::not_benchmarked`).
pub fn describe_not_benchmarked(slots: &[crate::dispatcher::SlotBenchmarkFailure]) -> Vec<String> {
    slots
        .iter()
        .map(|f| {
            let on = f
                .gpu_name
                .as_deref()
                .map(|g| format!(" ({g})"))
                .unwrap_or_default();
            format!("{}{on} was not benchmarked: {}", f.slot_key, f.error)
        })
        .collect()
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
    let (run, per_card) = PowerSampler::around(proving_bus_ids_from_pool(), || {
        if let Some(pool) = crate::engine::worker_pool() {
            let run = pool.benchmark_all_with_device_info();
            if !run.results.is_empty() {
                let total: usize = run.results.iter().map(|r| r.entries.len()).sum();
                tracing::info!(
                    "Got {} benchmark results from {} GPU workers (CPU benchmarks skipped)",
                    total,
                    run.results.len()
                );
            }
            run
        } else {
            crate::dispatcher::BenchmarkRun::default()
        }
    });
    let worker_device_results = run.results;
    let mut failures = run.failures;
    let not_benchmarked = run.not_benchmarked;
    if worker_device_results.is_empty()
        && crate::engine::worker_pool().is_some_and(|p| p.has_any_worker())
    {
        note_unexplained_empty_run(&mut failures);
    }
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
    let zkops = machine_zkops(&device_benchmarks);
    BenchmarkSuite {
        results,
        device_benchmarks,
        cpu_info,
        timestamp,
        zkops,
        cpu_power_watts: None, // see the note in the streaming path below
        gpu_power_watts,
        host_peaks: host_peaks_from_workers(&worker_device_results),
        failures,
        not_benchmarked,
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
    let (run, per_card) = PowerSampler::around(proving_bus_ids_from_pool(), || {
        if let Some(pool) = crate::engine::worker_pool() {
            pool.benchmark_all_streaming(on_progress)
        } else {
            crate::dispatcher::BenchmarkRun::default()
        }
    });
    let worker_device_results = run.results;
    let mut failures = run.failures;
    let not_benchmarked = run.not_benchmarked;
    if worker_device_results.is_empty()
        && crate::engine::worker_pool().is_some_and(|p| p.has_any_worker())
    {
        note_unexplained_empty_run(&mut failures);
    }
    let gpu_power_watts = suite_total_watts(&per_card);

    let device_benchmarks =
        build_gpu_device_benchmarks_from_workers(&worker_device_results, &per_card);

    let mut results = Vec::new();
    for slot_result in &worker_device_results {
        for entry in &slot_result.entries {
            results.push(benchmark_entry_to_result(entry));
        }
    }
    let zkops = machine_zkops(&device_benchmarks);
    BenchmarkSuite {
        results,
        device_benchmarks,
        cpu_info,
        timestamp,
        zkops,
        cpu_power_watts: cpu_power_over(rapl_before, cpu_window.elapsed()),
        gpu_power_watts,
        host_peaks: host_peaks_from_workers(&worker_device_results),
        failures,
        not_benchmarked,
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

/// W7-M11: the reduced-power reason a worker's entry carries (protocol v12 of the macOS line, v17 since W11-ON37), unless
/// `ZKMINER_POWER_STATE_IN_BENCH=0` (`knob_off`) says to use every entry as measured.
fn entry_power_reduced(
    entry: &zkminer_prover_protocol::BenchmarkEntry,
    knob_off: bool,
) -> Option<String> {
    if knob_off {
        return None;
    }
    entry.power_state.and_then(|p| p.reduced())
}

/// W7-M11: the part of a suite's reduced-power marks that a redo can clear: Low Power Mode and
/// battery, the host states a benchmark cannot cause itself. `None` when no row carries either.
///
/// A thermal mark ("thermal serious"/"critical") never asks for a redo. The worker reads the power
/// state before AND after each program and keeps the worse, and the after-reading comes at the end
/// of minutes of GPU load: on a fanless or small Mac the benchmark heats the Mac to `serious`
/// itself, which is the speed it really mines at. A redo at the next (cool) start would heat it
/// again and be marked again, without end (fix round 1 of W7-M11). So thermal stays an
/// informational mark and the row is priced as measured.
pub fn power_redo_cause(suite: &BenchmarkSuite) -> Option<String> {
    let mut parts: Vec<&'static str> = Vec::new();
    for row in &suite.device_benchmarks {
        let Some(why) = row.power_reduced() else {
            continue;
        };
        for part in why.split(", ") {
            for known in ["Low Power Mode", "on battery"] {
                if part == known && !parts.contains(&known) {
                    parts.push(known);
                }
            }
        }
    }
    parts.sort_by_key(|p| if *p == "Low Power Mode" { 0 } else { 1 });
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// W7-M11's pricing rule for a benchmark taken in reduced power: **price as measured, redo on the
/// operator's command, not discount**. A row measured in Low Power Mode or on battery stays in use
/// as measured: it is what the Mac proves at in that state, so it only claims less and never
/// over-promises. When the host is at full power again the miner advises a re-benchmark (the
/// TUI's `[b]` or `zkminer benchmark`), and the full-power result replaces the suite when saved.
/// A discount would need a slowdown factor per state, which nothing here measured (no laptop; Low
/// Power Mode needs sudo).
///
/// The miner does not re-benchmark by itself: auto-benchmark at startup is disabled in
/// `zkminer run` (GPU proving in passthrough VMs freezes the host), and no caller benchmarks when
/// the cache is missing. So the cached suite is never dropped for its power marks (W7-M11 fix
/// round 2: dropping it left the miner on placeholder prices with no measurement running).
///
/// Returns the advice, or `None` when there is nothing to advise:
/// - no row carries a redo cause ([`power_redo_cause`]: a thermal mark alone never asks);
/// - `knob_off` (`ZKMINER_POWER_STATE_IN_BENCH=0`);
/// - `now` (the host's power state at load) is unknown or still in Low Power Mode or on battery.
///   A hot Mac at load also gets no advice yet: a benchmark now would measure the heat.
pub fn power_redo_reason(
    suite: &BenchmarkSuite,
    now: Option<zkminer_prover_protocol::BenchPowerState>,
    knob_off: bool,
) -> Option<String> {
    if knob_off {
        return None;
    }
    let cause = power_redo_cause(suite)?;
    let now = now?;
    let known = now.low_power_mode.is_some() || now.on_battery.is_some() || now.thermal.is_some();
    if !known || now.reduced().is_some() {
        return None;
    }
    let row = suite
        .device_benchmarks
        .iter()
        .find(|d| d.power_reduced().is_some())
        .map(|d| format!("{} / {}", d.device_id, d.prover_backend))
        .unwrap_or_default();
    Some(format!(
        "{row} was benchmarked in reduced power ({cause}) and this host is at full power now: \
         re-benchmark (press [b] on the Benchmark screen, or run `zkminer benchmark`) to price at \
         full speed; until then it is priced as measured"
    ))
}

fn build_gpu_device_benchmarks_from_workers(
    worker_results: &[crate::dispatcher::SlotBenchmarkResult],
    per_card_watts: &BTreeMap<String, f64>,
) -> Vec<DeviceBenchmark> {
    build_gpu_device_benchmarks_with(
        worker_results,
        per_card_watts,
        zkminer_prover_protocol::power_state_in_bench_off(),
    )
}

/// [`build_gpu_device_benchmarks_from_workers`] with `ZKMINER_POWER_STATE_IN_BENCH=0` passed in
/// (`power_in_bench_off`), for tests that must not depend on the environment.
fn build_gpu_device_benchmarks_with(
    worker_results: &[crate::dispatcher::SlotBenchmarkResult],
    per_card_watts: &BTreeMap<String, f64>,
    power_in_bench_off: bool,
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
        for entry in entries
            .iter()
            .filter(|e| e.program_name != zkminer_prover_protocol::BENCH_ZKOP_MIX)
        {
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
                power_reduced: entry_power_reduced(e, power_in_bench_off),
            })
            .collect();
        if let Some(why) = program_stages
            .iter()
            .find_map(|p| p.power_reduced.as_deref())
        {
            tracing::warn!(
                "{slot_key}: benchmarked in reduced power ({why}): the row is priced as measured; \
                 for a Low Power Mode or battery row the miner advises a re-benchmark once the \
                 host is at full power; a thermal mark is the sustained-load speed ({} = 0 \
                 ignores the power state)",
                zkminer_prover_protocol::POWER_STATE_IN_BENCH_ENV
            );
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
            // An Apple GPU: the Metal worker's own table, not the discrete-card estimate, which
            // showed "po2 24 / 16.0 GB" for an uncalibrated Mac whose worker proves at 20 (M6).
            _ if r.gpu_tag == "metal" && backend == "risc0" => {
                let po2 = metal_job_po2(vram_bytes);
                (po2, crate::metal_sizing::stark_peak_bytes(po2))
            }
            Some(vram) if vram > 0 => find_optimal_gpu_po2(vram, backend, &r.gpu_tag),
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
            benchmark_po2: r.benchmark_po2,
            highest_proved_po2: None,
        });
    }

    benchmarks
}

/// True when a calibration sweep can say which size is FASTEST: at least two samples, one of them
/// split into segments.
///
/// The fastest is `argmax(throughput)`, so a sweep whose workload fit in a SINGLE segment at every
/// po2 carries no po2 signal at all — the throughput differences are warm-up and timer noise.
/// Adopting its argmax would pick a card's job size essentially at random. Such a sweep, or one
/// sample, still says what FITS: `calibrate_po2_for_suite` then takes its ceiling as the size.
///
/// This is not hypothetical: measured on an RTX 5090, the risc0 worker's built-in
/// calibration workload is 32,768 cycles and reports `segment_count == 1` for every po2
/// in 18..=24, with throughput varying 72K→624K purely from warm-up.
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
            tracing::warn!(
                "{key}: skipping po2 calibration — no risc0 benchmark row for this card (its \
                 benchmark failed); give it a size in the config (`prover.risc0_job_po2`)"
            );
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
        // a full proof attempt per step, each one failing, and the failure then ends the sweep
        // and CLAMPS `max_feasible_po2` down — recording the display's footprint as a permanent
        // property of the card, in a suite that persists to disk and prices every later job on it.
        //
        // `calibrate_slot_po2` clamps each individual run as well, so a sample taken here can still
        // come back at a lower po2 than requested; stopping the range early just avoids asking.
        //
        // Read only once the card has settled: `shutdown_all` above returns as the workers die, not
        // as their memory comes back, and memory on its way back still counts as held (`draining`),
        // so the sweep would be capped too low.
        pool.settle_vram(&key);
        let free_po2 = match pool.vram_budget_for_slot(&key) {
            Some(budget) if budget.total > 0 => {
                // What physically fits: calibration's own 10% is its headroom, not the Windows
                // growth margin, which would cap a display card a size down for good.
                let (fits, _) = find_optimal_gpu_po2(
                    budget.available.saturating_add(budget.growth_margin),
                    "risc0",
                    gpu_tag,
                );
                Some(fits)
            }
            _ => None,
        };
        let max_po2 = match free_po2 {
            Some(fits) if fits < db.max_feasible_po2.min(PO2_MAX) => {
                tracing::info!(
                    "{key}: capping the po2 sweep at {fits} rather than {} — part of this card's \
                     VRAM is held by another process or another of our workers",
                    db.max_feasible_po2.min(PO2_MAX),
                );
                fits
            }
            _ => db.max_feasible_po2.min(PO2_MAX),
        };
        let max_po2 = max_po2.min(zkminer_prover_protocol::RISC0_JOB_PO2_MAX);
        if max_po2 < zkminer_prover_protocol::RISC0_JOB_PO2_MIN {
            tracing::warn!(
                "{key}: skipping po2 calibration — not enough free VRAM for even po2={}",
                zkminer_prover_protocol::RISC0_JOB_PO2_MIN
            );
            continue;
        }
        let start = PO2_MIN.min(max_po2);
        tracing::info!("{key}: calibrating po2 from {start}, up to {max_po2}");
        // The quickest run so far, which bounds the next (`calibration_run_limit`).
        let mut fastest_secs: Option<f64> = None;
        let (samples, ceiling, highest) = sweep_po2(start, max_po2, |po2| {
            let limit = calibration_run_limit(fastest_secs);
            // Retry once on failure. A worker can be SIGKILLed out from under us
            // between `ensure_alive`'s liveness check and the response — the worker
            // inherits PR_SET_PDEATHSIG, which is THREAD-scoped, so a retired tokio
            // blocking thread takes its worker with it (observed here as
            // "Worker risc0 process died (EOF)" on the first sample). The retry goes
            // back through `ensure_alive`, which respawns.
            let mut attempt = 0;
            let sample = loop {
                attempt += 1;
                match pool.calibrate_slot_po2_within(&key, po2, limit) {
                    Ok(s) => break Some(s),
                    // Not retried: the size does not fit the card (see `calibration_run_limit`).
                    Err(e) if e.is::<crate::dispatcher::CalibrationTooSlow>() => {
                        tracing::warn!("{e}");
                        break None;
                    }
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
            if let Some(s) = &sample {
                if s.duration_secs > 0.0 {
                    fastest_secs =
                        Some(fastest_secs.map_or(s.duration_secs, |f| f.min(s.duration_secs)));
                }
                tracing::info!(
                    "{key}: po2={} segments={} cycles={} {:.2}s → {:.0} c/s",
                    s.po2,
                    s.segment_count,
                    s.total_cycles,
                    s.duration_secs,
                    s.throughput
                );
            }
            sample
        });
        let Some(ceiling) = ceiling else {
            tracing::warn!(
                "{key}: DISCARDING po2 calibration — no size from {} up proved with a step of \
                 headroom, so this card keeps its default size (none under {:.1} GiB of VRAM) \
                 unless it is given one",
                zkminer_prover_protocol::RISC0_JOB_PO2_MIN,
                risc0_job_min_vram_bytes(gpu_tag) as f64 / (1u64 << 30) as f64,
            );
            continue;
        };
        // The ceiling is MEASURED, and replaces the heuristic: `estimate_po2_memory` predicts 4 GB for
        // po2=22 against a real ~14 GB (on a 4090, po2=22 died with "allocation of 14159970304 bytes
        // for evaluated failed"). No size above it may win the argmax; the samples above it are kept
        // only as the rates of the sizes they measured (see `sweep_po2`).
        if ceiling != db.max_feasible_po2 {
            tracing::info!(
                "{key}: max_feasible_po2 {} → {ceiling} (measured)",
                db.max_feasible_po2
            );
            db.max_feasible_po2 = ceiling;
        }
        db.highest_proved_po2 = highest;
        // The MEASURED fastest size within it is the card's job size (see `risc0_job_po2`, which
        // never lets it lower a default size the calibration proved) and what the TUI shows — when
        // the samples can say which is fastest (`calibration_is_usable`). One sample, or samples that
        // never split into segments, say only what fits: the ceiling is the size.
        let within: Vec<Po2Sample> = samples
            .iter()
            .filter(|s| s.po2 <= ceiling)
            .cloned()
            .collect();
        let usable = calibration_is_usable(&within);
        let best = if usable {
            within
                .iter()
                .max_by(|a, b| a.throughput.total_cmp(&b.throughput))
                .map(|s| s.po2)
        } else {
            Some(ceiling)
        };
        if let Some(best) = best {
            if db.optimal_po2 != best {
                tracing::info!(
                    "{key}: optimal_po2 {} → {best} ({})",
                    db.optimal_po2,
                    if usable {
                        "measured fastest"
                    } else {
                        "its ceiling"
                    }
                );
                db.optimal_po2 = best;
            }
            db.memory_usage_bytes = estimate_gpu_po2_memory(best, backend, gpu_tag);
        }
        if usable {
            tracing::info!("{key}: adopting {} po2 calibration samples", samples.len());
        } else {
            tracing::info!("{key}: adopting po2 {ceiling} as this card's ceiling");
        }
        db.po2_samples = samples;
    }
}

/// How many times the quickest size so far a calibration run may take before it is stopped as a size
/// the card cannot hold (`calibration_run_limit`).
pub const CALIBRATION_SLOW_FACTOR: f64 = 3.0;

/// The least a calibration run is given, whatever the quickest size so far took
/// (`calibration_run_limit`).
pub const CALIBRATION_MIN_RUN: Duration = Duration::from_secs(60);

/// How long a calibration run may take before it is stopped (`WorkerPool::calibrate_slot_po2_within`),
/// given the quickest size the sweep has proved so far: [`CALIBRATION_SLOW_FACTOR`] times it, at
/// least [`CALIBRATION_MIN_RUN`]; no limit before any size has proved.
///
/// Every size proves the same workload, so a larger one takes about as long as a smaller one, or
/// less: fewer segments to fold. One that takes several times longer does not fit the card. Under
/// Windows a CUDA card does not refuse such a size: the driver puts what does not fit in system
/// memory, the proof runs on, and nothing is evicted, so the spill watch sees no spill. On a 16 GB
/// RTX 5080 po2 20 proved in 19 s; 21 took 259 s with 7-15 GB of the worker's memory in system
/// memory, and 22 ran 9 minutes twice, both times to a proof that failed its own verification. Such
/// a size can never be the fastest, and the larger ones after it would spill more, so the sweep ends
/// there, as at a size that failed.
pub fn calibration_run_limit(fastest_secs: Option<f64>) -> Option<Duration> {
    let fastest = fastest_secs.filter(|s| s.is_finite() && *s > 0.0)?;
    let limit = Duration::try_from_secs_f64(fastest * CALIBRATION_SLOW_FACTOR).ok()?;
    Some(limit.max(CALIBRATION_MIN_RUN))
}

/// A card's po2 sweep for `calibrate_po2_for_suite`: every size that proved, in order, and the ceiling,
/// or no ceiling (and no samples) when no size in the job range proved with headroom.
///
/// A size above the ceiling is kept: the ceiling limits which size a calibration may choose, but a card
/// may still prove at a size above it (its default size, which `risc0_job_po2` never lowers below a
/// size the card proved), and is then planned at the rate measured there (`risc0_job_throughput`).
/// Dropping it planned such a card at its slower rate one size down: an Arc A770 measured 116K c/s at
/// po2 20, its job size, and 77K at 19, its ceiling, and was planned at 77K, which refused jobs it
/// proves inside the watchdog.
///
/// Upward from `start` to the first failure (or to `top`, or to a sample at a smaller size than asked,
/// which `calibrate_slot_po2` returns when the card's free VRAM is short); if `start` itself failed,
/// downward to the first size that proves, so a card too small for `start` still gets a size.
///
/// The ceiling is ONE STEP below the highest size that proved, when a larger one failed. "Highest po2
/// that calibrated once" is NOT "reliably safe". Measured on a 4090: po2=22 OOMed so the ceiling was
/// clamped to 21, calibration at 21 then SUCCEEDED (38.5s on a 62M-cycle sweep) — yet a real
/// 15.7M-cycle proof at po2=21 died with
///   "failed to run groth16 prove operation: cudaMallocAsync ... out of memory".
/// The calibration sweep and a live job do not see the same memory state (fragmentation, buffer pools,
/// a second worker on the card), so the very top of the measured range is marginal. Each po2 step
/// doubles the segment, so backing off one step buys ~2x headroom. A sweep that ran clean to a top set
/// by the card's memory needs no backoff (that top is a measured size with 10% to spare, see
/// `find_optimal_gpu_po2`); one that reached `RISC0_JOB_PO2_MAX`, which no failure could show the
/// card's limit at, does. When no sample lies at or below the ceiling, the ceiling itself is proved
/// too.
///
/// `prove(p)` proves the calibration workload at `p` and returns its sample. Also returns the
/// highest size that proved, which the kept samples may not include.
fn sweep_po2(
    start: u8,
    top: u8,
    mut prove: impl FnMut(u8) -> Option<Po2Sample>,
) -> (Vec<Po2Sample>, Option<u8>, Option<u8>) {
    use zkminer_prover_protocol::RISC0_JOB_PO2_MIN;
    fn keep(samples: &mut Vec<Po2Sample>, s: Po2Sample) {
        if !samples.iter().any(|k| k.po2 == s.po2) {
            samples.push(s);
        }
    }
    let mut samples = Vec::new();
    let mut failed = false;
    for po2 in start..=top {
        match prove(po2) {
            Some(s) => {
                let short = s.po2 < po2;
                keep(&mut samples, s);
                if short {
                    break;
                }
            }
            None => {
                failed = true;
                break;
            }
        }
    }
    if samples.is_empty() {
        for po2 in (RISC0_JOB_PO2_MIN..start).rev() {
            if let Some(s) = prove(po2) {
                keep(&mut samples, s);
                break;
            }
        }
    }
    let Some(highest) = samples.iter().map(|s| s.po2).max() else {
        return (Vec::new(), None, None);
    };
    // Reaching the job range's top proves nothing about headroom: the prover refuses anything larger,
    // so no failure above it could be seen. A top set by the card's memory is a MEASURED size that fit
    // with 10% to spare (`find_optimal_gpu_po2` never caps at an extrapolated one), so it keeps.
    let ceiling = if failed || highest >= zkminer_prover_protocol::RISC0_JOB_PO2_MAX {
        highest.saturating_sub(1)
    } else {
        highest
    };
    if ceiling < RISC0_JOB_PO2_MIN {
        return (Vec::new(), None, Some(highest));
    }
    if !samples.iter().any(|s| s.po2 <= ceiling) {
        match prove(ceiling) {
            Some(s) if s.po2 <= ceiling => keep(&mut samples, s),
            _ => return (Vec::new(), None, Some(highest)),
        }
    }
    samples.sort_by_key(|s| s.po2);
    (samples, Some(ceiling), Some(highest))
}

/// Run simulated benchmarks for all canonical programs.
fn run_simulated_benchmarks() -> Vec<BenchmarkResult> {
    tracing::warn!(
        "No prover worker found — running SIMULATED benchmarks: CPU stand-ins, not proofs; nothing \
         is measured, scored or saved"
    );

    let mut results = Vec::new();

    for program in &BENCHMARK_PROGRAMS {
        let start = Instant::now();

        match program.name {
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
            "  SIMULATED {}: {} cycles in {:?} ({:.0} cycles/sec, not a proof){}",
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
/// Automatically invalidates cached results when programs, weights or
/// inputs change — no manual version bumps needed.
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
        let pre = if p.precompile { 1u8 } else { 0u8 };
        h ^= pre as u64;
        h = h.wrapping_mul(FNV_PRIME);
        for b in p.simulated_cycles.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        // A different input is a different measurement.
        for b in p
            .input
            .to_le_bytes()
            .into_iter()
            .chain(p.sp1_input.to_le_bytes())
        {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
    }
    // The zkOP/s definition: a change to it makes every saved score incomparable.
    for b in zkminer_prover_protocol::ZKOP_MIX_SP1_CYCLES.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    format!("v3-{h:016x}")
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

/// Total physical memory in bytes (`memory::mem_total_bytes`: `/proc/meminfo` on Linux, `sysctl
/// hw.memsize` on macOS, the system's memory status on Windows), 0 where it cannot be read. Read
/// from `/proc/meminfo` only, it was 0 on Windows, and every Windows fingerprint said "0GiB".
pub fn get_total_memory_bytes() -> u64 {
    crate::memory::mem_total_bytes().unwrap_or(0)
}

/// Whether a saved hardware fingerprint names this machine (`current`): the same, or the same but
/// for a RAM field of "0GiB", which every Windows build wrote before it could read the RAM size
/// (`get_total_memory_bytes`). Without that, the fix would have discarded every Windows benchmark.
fn same_hardware(saved: &str, current: &str) -> bool {
    if saved == current {
        return true;
    }
    let (s, c): (Vec<&str>, Vec<&str>) = (saved.split('|').collect(), current.split('|').collect());
    s.len() == c.len()
        && s.len() > 2
        && s[2] == "0GiB"
        && s.iter()
            .zip(&c)
            .enumerate()
            .all(|(i, (a, b))| i == 2 || a == b)
}

#[cfg(test)]
mod fingerprint_ram_tests {
    use super::same_hardware;

    /// A fingerprint saved with the "0GiB" RAM field matches this machine's but for the RAM; any
    /// other difference does not.
    #[test]
    fn a_fingerprint_without_its_ram_size_still_matches() {
        let now = "Ryzen|16|64GiB|RTX 5090,RTX 4070|580.1";
        assert!(same_hardware(now, now));
        assert!(same_hardware("Ryzen|16|0GiB|RTX 5090,RTX 4070|580.1", now));
        assert!(!same_hardware("Ryzen|16|0GiB|RTX 5090|580.1", now));
        assert!(!same_hardware(
            "Ryzen|16|32GiB|RTX 5090,RTX 4070|580.1",
            now
        ));
    }
}

/// Returns the path to the benchmark cache file: `~/.zkminer/benchmarks.json`.
pub fn benchmark_cache_path() -> PathBuf {
    zkminer_config::ZkMinerConfig::default_dir().join("benchmarks.json")
}

/// The (device id, backend) pairs in `targets` that `suite` has no measured throughput for.
pub fn missing_device_benchmarks(
    suite: Option<&BenchmarkSuite>,
    targets: &[(String, String)],
) -> Vec<(String, String)> {
    targets
        .iter()
        .filter(|(device, backend)| {
            !suite
                .and_then(|s| s.throughput_for(device, backend))
                .is_some_and(|throughput| throughput > 0.0)
        })
        .cloned()
        .collect()
}

/// Load cached benchmarks from disk, verifying the hardware fingerprint.
///
/// Returns `None` if the file is missing, corrupt, or the hardware has changed.
///
/// W7-M11: a suite's power marks never make it `None` (the callers do not benchmark on `None`);
/// see [`load_cached_benchmark_with_advice`] for the re-benchmark advice.
pub fn load_cached_benchmark() -> Option<BenchmarkSuite> {
    load_cached_benchmark_with_advice().map(|(suite, _)| suite)
}

/// [`load_cached_benchmark`], also returning the re-benchmark advice of [`power_redo_reason`]
/// (logged here as a WARN too), for a caller that shows it to the operator or starts a benchmark.
pub fn load_cached_benchmark_with_advice() -> Option<(BenchmarkSuite, Option<String>)> {
    load_cached_benchmark_with_power(
        &benchmark_cache_path(),
        &suite_version(),
        &hardware_fingerprint(),
        crate::discovery::host_power_state,
        zkminer_prover_protocol::power_state_in_bench_off(),
    )
}

/// [`load_cached_benchmark_with_advice`] with its environment injected: the cache file, the host's
/// power state at load (`now`, read only when a row carries a redo cause) and the knob.
///
/// Read-only: it never writes the cache, and it returns the cached suite whatever its marks.
pub(crate) fn load_cached_benchmark_with_power(
    path: &std::path::Path,
    current_version: &str,
    current_fp: &str,
    now: impl FnOnce() -> zkminer_prover_protocol::BenchPowerState,
    knob_off: bool,
) -> Option<(BenchmarkSuite, Option<String>)> {
    let suite = load_cached_benchmark_from(path, current_version, current_fp)?;
    if knob_off {
        return Some((suite, None));
    }
    let marked = suite
        .device_benchmarks
        .iter()
        .find_map(|d| d.power_reduced().map(|w| (d.device_id.clone(), w)));
    let Some((device, why)) = marked else {
        return Some((suite, None));
    };
    if power_redo_cause(&suite).is_none() {
        tracing::info!(
            "The cached benchmark of {device} was taken hot ({why}); used as measured (the \
             sustained-load speed of this Mac)"
        );
        return Some((suite, None));
    }
    let now = now();
    let advice = power_redo_reason(&suite, Some(now), false);
    match &advice {
        Some(advice) => tracing::warn!("{advice}"),
        None => tracing::warn!(
            "The cached benchmark of {device} was taken in reduced power ({why}); it is priced as \
             measured, and this host is not at full power either ({})",
            now.reduced()
                .unwrap_or_else(|| "power state unknown".to_string())
        ),
    }
    Some((suite, advice))
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

    if !same_hardware(&saved.hardware_fingerprint, current_fp) {
        tracing::info!(
            "Hardware changed (saved: {}, current: {current_fp}), re-benchmarking needed",
            saved.hardware_fingerprint,
        );
        return None;
    }

    let mut suite = saved.suite;
    // W10-BENCH: a simulated suite cached before that was refused (the TUI's full benchmark saved
    // one when no worker answered) prices nothing.
    if suite.is_simulated() {
        tracing::warn!(
            "The cached benchmark at {} is simulated, not measured; ignoring it (re-benchmark)",
            path.display()
        );
        return None;
    }
    migrate_device_identity(&mut suite);
    floor_implausible_gpu_power(&mut suite);
    drop_cpu_device_rows(&mut suite);
    // From the saved proofs, so a change to how GPUs are scored needs no new benchmark.
    suite.zkops = machine_zkops(&suite.device_benchmarks);
    Some(suite)
}

/// Removes the CPU device rows a suite cached before they were dropped: they were derived from the
/// GPU results, not measured (see `run_benchmark`).
fn drop_cpu_device_rows(suite: &mut BenchmarkSuite) {
    suite
        .device_benchmarks
        .retain(|d| d.device_id != CPU_DEVICE_ID);
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
    let path = benchmark_cache_path();
    match save_benchmark_to(&path, &suite_version(), &hardware_fingerprint(), suite) {
        Ok(()) => tracing::info!("Saved benchmarks to {}", path.display()),
        Err(e) if suite.not_cacheable().is_some() => tracing::warn!("{e}"),
        Err(e) => tracing::error!("{e}"),
    }
}

/// The body of [`save_benchmark`], with the path and identity injected (W7-M11, for the power-state
/// tests).
pub(crate) fn save_benchmark_to(
    path: &std::path::Path,
    current_version: &str,
    current_fp: &str,
    suite: &BenchmarkSuite,
) -> Result<(), String> {
    // W10-BENCH: only a complete, measured run is priced from. Callers check too; this is the gate.
    if let Some(why) = suite.not_cacheable() {
        return Err(format!(
            "Not saving the benchmark to {}: {why}",
            path.display()
        ));
    }
    let saved = SavedBenchmark {
        suite_version: current_version.to_string(),
        hardware_fingerprint: current_fp.to_string(),
        suite: suite.clone(),
    };
    write_saved_benchmark(path, &saved)
}

/// [`save_benchmark_to`] for the integration tests (W10-BENCH), with a fixed version and fingerprint.
#[cfg(any(test, feature = "testing"))]
pub fn save_benchmark_to_for_test(
    path: &std::path::Path,
    suite: &BenchmarkSuite,
) -> Result<(), String> {
    save_benchmark_to(path, "v-test", "fp-test", suite)
}

/// Writes `saved` to `path` atomically (temp file, fsync, rename, fsync of the directory).
fn write_saved_benchmark(path: &std::path::Path, saved: &SavedBenchmark) -> Result<(), String> {
    // Ensure the directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create benchmark cache directory: {e}"))?;
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
    let json = serde_json::to_string_pretty(saved)
        .map_err(|e| format!("Failed to serialize benchmark cache: {e}"))?;
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
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Failed to write benchmark cache temp file: {e}"));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Failed to install benchmark cache: {e}"));
    }
    // And the DIRECTORY, so the rename itself survives a power loss rather than only the
    // bytes it points at.
    if let Some(parent) = path.parent() {
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod zkop_score_tests {
    use super::*;
    use crate::dispatcher::SlotBenchmarkResult;
    use zkminer_prover_protocol::{BenchmarkEntry, BENCH_CHACHA_MIX, BENCH_ZKOP_MIX, ZKOP_MIX_SP1_CYCLES};

    fn entry(name: &str, cycles: u64, secs: f64, weight: f64) -> BenchmarkEntry {
        BenchmarkEntry {
            program_name: name.to_string(),
            prover_backend: "sp1".to_string(),
            cycles,
            duration_secs: secs,
            throughput: cycles as f64 / secs,
            weight,
            precompile: false,
            wrap_secs: None,
            power_state: None,
        }
    }

    fn slot(key: &str, index: u32, backend: &str, score_secs: f64) -> SlotBenchmarkResult {
        let mut entries = vec![
            entry(BENCH_CHACHA_MIX, 8_000_000, 2.0, 0.2),
            entry(BENCH_ZKOP_MIX, ZKOP_MIX_SP1_CYCLES, score_secs, 0.0),
        ];
        for e in &mut entries {
            e.prover_backend = backend.to_string();
        }
        SlotBenchmarkResult {
            slot_key: key.to_string(),
            gpu_name: Some("Test".to_string()),
            device_index: Some(index),
            pci_bus_id: Some(format!("0000:0{index}:00.0")),
            gpu_tag: "cuda".to_string(),
            entries,
            vram_bytes: None,
            host_peak_bytes: None,
            benchmark_po2: None,
        }
    }

    #[test]
    fn the_machine_score_adds_up_each_gpus_blended_score() {
        let devices = build_gpu_device_benchmarks_from_workers(
            &[
                slot("sp1:cuda:0", 0, "sp1", 5.0),
                slot("sp1:cuda:1", 1, "sp1", 10.0),
                slot("risc0:cuda:0", 0, "risc0", 20.0),
            ],
            &Default::default(),
        );
        let c = ZKOP_MIX_SP1_CYCLES as f64;
        let id = |i: usize| devices[i].device_id.clone();
        assert_eq!(devices[0].zkop_mix_rate(), Some(c / 5.0));
        assert_eq!(
            devices[2].zkop_mix_rate(),
            Some(c / 20.0),
            "RISC Zero in the same unit"
        );
        // Card 0 ran both zkVMs; card 1 only SP1, which is all it is scored on.
        let card0 = zkminer_prover_protocol::blended_zkops(Some(c / 5.0), Some(c / 20.0)).unwrap();
        let gpu = |device_id: String| gpu_zkops(&devices, &device_id).unwrap();
        assert_eq!(gpu(id(0)), card0);
        assert_eq!(gpu(id(1)), c / 10.0);
        assert_eq!(machine_zkops(&devices), card0 + c / 10.0);
        // Shown per zkVM in its own cycles per second.
        assert_eq!(devices[0].scoring_cycles_per_sec(), Some(c / 5.0));
        assert_eq!(format_mzkops(13_830_000.0), "13.83 MzkOP/s");
        assert_eq!(
            format_mzkops(-0.0),
            "0.00 MzkOP/s",
            "no score is not \"-0.00\""
        );
    }

    #[test]
    fn the_scoring_program_stays_out_of_job_pricing() {
        let devices =
            build_gpu_device_benchmarks_from_workers(&[slot("sp1:cuda:0", 0, "sp1", 5.0)], &Default::default());
        let device = &devices[0];
        assert_eq!(device.throughput, 4_000_000.0);
        assert_eq!(device.stark_rate(), Some(4_000_000.0));
        assert!(!device.program_throughputs.contains_key(BENCH_ZKOP_MIX));
    }

    #[test]
    fn a_device_without_the_scoring_program_has_no_score() {
        let mut only_suite = slot("sp1:cuda:0", 0, "sp1", 5.0);
        only_suite.entries.pop();
        let devices = build_gpu_device_benchmarks_from_workers(&[only_suite], &Default::default());
        assert_eq!(devices[0].zkop_mix_rate(), None);
        assert_eq!(gpu_zkops(&devices, &devices[0].device_id), None);
        assert_eq!(machine_zkops(&devices), 0.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vendor's library is asked for only when one of its cards proves here; a proving card of
    /// unknown vendor asks for both.
    #[test]
    fn only_the_proving_cards_vendors_libraries_are_loaded() {
        let adapters = [
            ("0000:03:00.0".to_string(), 0x10de),
            ("0000:07:00.0".to_string(), 0x1002),
            ("0000:0a:00.0".to_string(), 0x8086),
        ];
        let ids = |ids: &[&str]| ids.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            telemetry_vendors(Some(&adapters), &ids(&["0000:03:00.0"])),
            (false, false)
        );
        assert_eq!(
            telemetry_vendors(Some(&adapters), &ids(&["0000:03:00.0", "0000:07:00.0"])),
            (false, true)
        );
        assert_eq!(
            telemetry_vendors(Some(&adapters), &ids(&["0000:0a:00.0"])),
            (true, false)
        );
        assert_eq!(telemetry_vendors(Some(&adapters), &[]), (false, false));
        assert_eq!(
            telemetry_vendors(Some(&adapters), &ids(&["0000:21:00.0"])),
            (true, true)
        );
        assert_eq!(
            telemetry_vendors(None, &ids(&["0000:03:00.0"])),
            (true, true)
        );
    }

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
    fn missing_device_benchmarks_finds_what_the_suite_lacks() {
        let row = |device: &str, backend: &str, throughput: f64| DeviceBenchmark {
            program_stages: Vec::new(),
            device_id: device.to_string(),
            device_label: device.to_string(),
            prover_backend: backend.to_string(),
            throughput,
            power_watts: 300.0,
            optimal_po2: 21,
            memory_usage_bytes: 0,
            max_feasible_po2: 21,
            program_throughputs: std::collections::HashMap::new(),
            pci_bus_id: String::new(),
            po2_samples: Vec::new(),
            host_peak_bytes: None,
            benchmark_po2: None,
            highest_proved_po2: None,
        };
        let target = |device: &str, backend: &str| (device.to_string(), backend.to_string());
        let targets = [
            target("gpu0", "risc0"),
            target("gpu0", "sp1"),
            target("gpu-rocm0", "sp1"),
        ];

        assert_eq!(missing_device_benchmarks(None, &targets), targets.to_vec());

        let suite = BenchmarkSuite {
            device_benchmarks: vec![
                row("gpu0", "risc0", 1e6),
                row("gpu0", "sp1", 0.0),
                row("gpu1", "sp1", 1e6),
            ],
            ..Default::default()
        };
        assert_eq!(
            missing_device_benchmarks(Some(&suite), &targets),
            vec![target("gpu0", "sp1"), target("gpu-rocm0", "sp1")],
            "a zero row and another card's row are not coverage"
        );

        let full = BenchmarkSuite {
            device_benchmarks: targets.iter().map(|(d, b)| row(d, b, 1e6)).collect(),
            ..Default::default()
        };
        assert!(missing_device_benchmarks(Some(&full), &targets).is_empty());
        assert!(
            missing_device_benchmarks(None, &[]).is_empty(),
            "no GPU workers: nothing to run"
        );
    }

    #[test]
    fn five_programs_defined() {
        assert_eq!(BENCHMARK_PROGRAMS.len(), 5);
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
    fn run_benchmark_makes_no_device_rows_without_gpu_workers() {
        // Device rows come only from GPU workers' measurements; there are none here. It used to
        // add a CPU row per backend, derived from the GPU results rather than measured.
        let suite = run_benchmark();
        assert!(
            suite.device_benchmarks.is_empty(),
            "expected no device rows, got {:?}",
            suite
                .device_benchmarks
                .iter()
                .map(|d| (&d.device_id, &d.prover_backend))
                .collect::<Vec<_>>()
        );
        assert!(
            !suite
                .device_benchmarks
                .iter()
                .any(|d| d.device_id == CPU_DEVICE_ID),
            "no CPU row, ever"
        );
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

        // 2 GPU entries (risc0+sp1, no openvm GPU), and no CPU rows
        assert_eq!(suite.device_benchmarks.len(), 2);

        let gpu_entries: Vec<_> = suite
            .device_benchmarks
            .iter()
            .filter(|d| d.device_id == "gpu0")
            .collect();
        assert_eq!(gpu_entries.len(), 2);

        // GPU estimates should beat the baseline they scale, for backends with GPU support
        let base = suite.average_throughput();
        for profile in &BACKEND_PROFILES {
            let Some(_) = profile.gpu_acceleration else {
                continue;
            };
            let gpu_tp = suite.throughput_for("gpu0", profile.name).unwrap();
            assert!(
                gpu_tp > base,
                "GPU estimate should beat the baseline for {}: gpu={:.0} base={:.0}",
                profile.name,
                gpu_tp,
                base
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
        assert_eq!(risc0_devices.len(), 2); // gpu0 + gpu1

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
        // The guessed figures, for everything but risc0 on a GPU (which is measured).
        let cpu = estimate_po2_memory(18, "risc0", false);
        let gpu = estimate_po2_memory(18, "openvm", true);
        assert_eq!(cpu, 512 * 1024 * 1024);
        assert_eq!(gpu, (256.0 * 1024.0 * 1024.0 * 1.2) as u64);
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
    fn find_optimal_po2_gpu_follows_the_measured_peaks() {
        const MIB: u64 = 1024 * 1024;
        let find_optimal_po2 =
            |vram, backend, _gpu: bool| find_optimal_gpu_po2(vram, backend, "cuda");
        // 90% of what is available must hold the size's measured peak.
        // An 8 GB card: 7.2 GiB holds 18 (4,709 MiB), not 19 (8,179).
        assert_eq!(find_optimal_po2(8 * 1024 * MIB, "risc0", true).0, 18);
        // An idle RTX 4070 (12,010 MiB free to us): 19, the size measured fastest there; 20 spilled.
        assert_eq!(find_optimal_po2(12_010 * MIB, "risc0", true).0, 19);
        // An idle RTX 5080 (15,880) holds the largest measured size, 20 (12,436 MiB): uncapped.
        assert_eq!(find_optimal_po2(15_880 * MIB, "risc0", true).0, PO2_MAX);
        // Nor does a 5080 with a desktop on it (12 GiB free) reach 20.
        assert_eq!(find_optimal_po2(12 * 1024 * MIB, "risc0", true).0, 19);
        // An idle RTX 4090 (24,109): the largest measured size fits, so no cap — never one from an
        // extrapolated figure, which a sweep would keep as its ceiling.
        assert_eq!(find_optimal_po2(24_109 * MIB, "risc0", true).0, PO2_MAX);
        // Below the smallest size there is nothing smaller to offer.
        assert_eq!(find_optimal_po2(2 * 1024 * MIB, "risc0", true).0, PO2_MIN);
        // An AMD or Intel card keeps the old estimate, so its calibration still sweeps high: a 12 GB
        // Arc B580 proves po2 20.
        assert!(find_optimal_gpu_po2(12 * 1024 * MIB, "risc0", "intel").0 >= 20);
    }

    #[test]
    fn the_risc0_gpu_estimate_is_the_measured_peak() {
        const MIB: u64 = 1024 * 1024;
        let estimate_po2_memory =
            |po2, backend, _gpu: bool| estimate_gpu_po2_memory(po2, backend, "cuda");
        for (po2, mib) in RISC0_GPU_MEASURED_PEAK_MIB {
            assert_eq!(estimate_po2_memory(*po2, "risc0", true), mib * MIB);
        }
        // Above the table each step grows twice as much as the one before.
        assert_eq!(estimate_po2_memory(21, "risc0", true), 20_950 * MIB);
        assert_eq!(estimate_po2_memory(22, "risc0", true), 37_978 * MIB);
        // And it only ever grows.
        for po2 in PO2_MIN..PO2_MAX {
            assert!(
                estimate_po2_memory(po2 + 1, "risc0", true)
                    > estimate_po2_memory(po2, "risc0", true)
            );
        }
        // The default sizes come from the measured rows only.
        assert_eq!(risc0_default_job_po2_for_vram(u64::MAX), Some(20));
        assert_eq!(
            risc0_default_job_po2_for_vram(RISC0_JOB_MIN_VRAM_BYTES - 1),
            None
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
            v1.starts_with("v3-"),
            "suite_version should start with 'v3-'"
        );
        assert!(v1.len() > 10, "suite_version should include a hash");
    }

    // ---- category sub-scores ----

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
            benchmark_po2: None,
            highest_proved_po2: None,
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
            benchmark_po2: None,
            highest_proved_po2: None,
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
            benchmark_po2: None,
            highest_proved_po2: None,
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
                power_state: None,
            }],
            vram_bytes,
            host_peak_bytes: None,
            benchmark_po2: None,
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
                power_state: None,
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
            power_reduced: None,
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
            power_reduced: None,
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
        // 32 GB card: the largest measured size fits, so nothing caps it; calibration finds its
        // limit by proving.
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
            benchmark_po2: None,
            highest_proved_po2: None,
        };

        let profile = Po2Profile::from_device_benchmark(&db).expect("profile from samples");
        assert_eq!(profile.max_po2, 21);
        // total_time = cycles / throughput_at_po2, so selection is argmax(throughput).
        assert_eq!(profile.optimal_po2_for_job(50_000_000), 20);

        // And an empty sweep yields no profile: the card's job size comes from its VRAM
        // (`risc0_job_po2`).
        let mut uncalibrated = db.clone();
        uncalibrated.po2_samples = Vec::new();
        assert!(Po2Profile::from_device_benchmark(&uncalibrated).is_none());
    }

    fn risc0_row(samples: Vec<Po2Sample>, optimal: u8, max: u8) -> DeviceBenchmark {
        DeviceBenchmark {
            program_stages: Vec::new(),
            device_id: "gpu0".to_string(),
            device_label: "GPU0 Test".to_string(),
            prover_backend: "risc0".to_string(),
            throughput: 2_000_000.0,
            power_watts: 300.0,
            optimal_po2: optimal,
            memory_usage_bytes: 8 << 30,
            max_feasible_po2: max,
            program_throughputs: std::collections::HashMap::new(),
            pci_bus_id: String::new(),
            po2_samples: samples,
            host_peak_bytes: None,
            benchmark_po2: None,
            highest_proved_po2: None,
        }
    }

    /// M6: an Apple GPU is sized from the Metal worker's own table, not the discrete-card rule that
    /// gave a 24 GB Mac po2 20 (M1's table said 19) and a 16 GB Mac no job size at all. M8: the
    /// table now gives a 16 GB Mac 19 and a 24 GB Mac 20.
    #[test]
    fn a_mac_proves_risc0_jobs_at_the_metal_tables_size() {
        use crate::metal_sizing::{job_po2_for_limit_in, working_set_limit_of, Po2Table::*};
        const GIB: u64 = 1 << 30;
        let mac16 = Some(8 * GIB); // hw.memsize less the 8 GiB reserve
        let mac24 = Some(16 * GIB);
        let mac36 = Some(28 * GIB);
        // The rule the host used before: wrong for both small Macs.
        assert_eq!(risc0_job_po2(None, None, mac24, "metal"), Some(20));
        assert_eq!(risc0_job_po2(None, None, mac16, "metal"), None);
        // Per slot: what the table says for the host figure and this process's budget, if any
        // (the budget runs set RISC0_METAL_MAX_WORKING_SET_BYTES for the whole process).
        for vram in [mac16, mac24, mac36] {
            assert_eq!(
                risc0_slot_job_po2("gpu-metal0", "metal", None, None, vram),
                Some(metal_job_po2(vram))
            );
        }
        // Without a budget: 19 / 20 / 20 (M8; M1's table said 18 / 19 / 20).
        let table =
            |v: Option<u64>, t| job_po2_for_limit_in(working_set_limit_of(v, None).unwrap(), t);
        assert_eq!(
            (table(mac16, M8), table(mac24, M8), table(mac36, M8)),
            (19, 20, 20)
        );
        assert_eq!(
            (table(mac16, M1), table(mac24, M1), table(mac36, M1)),
            (18, 19, 20)
        );
        // An override still wins; a discrete card is unchanged.
        assert_eq!(
            risc0_slot_job_po2("gpu-metal0", "metal", Some(17), None, mac36),
            Some(17)
        );
        assert_eq!(
            risc0_slot_job_po2("gpu0", "cuda", None, None, mac24),
            Some(20)
        );
        assert_eq!(
            risc0_slot_job_po2("gpu-rocm0", "rocm", None, None, mac16),
            None
        );
        // A calibrated Mac: its measured size stands below the table's (the table's size failed
        // there), and is raised to the table's when the calibration proved it.
        let calibrated = |ceiling: u8| {
            let samples = (16..=ceiling)
                .map(|p| sample(p, 64 >> (p - 16), 1e6))
                .collect();
            risc0_row(samples, ceiling, ceiling)
        };
        // A ceiling two below the table's size must stay inside the job range (16..): true for the
        // M8 table under every budget run (18 at 4 GiB), not for M1's (17 at 4 GiB).
        let d = metal_job_po2(mac36);
        if d < 18 {
            return;
        }
        assert_eq!(
            risc0_slot_job_po2("gpu-metal0", "metal", None, Some(&calibrated(d - 2)), mac36),
            Some(d - 2)
        );
        assert_eq!(
            risc0_slot_job_po2("gpu-metal0", "metal", None, Some(&calibrated(d - 1)), mac36),
            Some(d)
        );
    }

    /// M6: the device row of a Mac shows the Metal worker's size and peak, not the discrete-card
    /// estimate ("po2 24 / 16M rows / 16.0 GB" for an uncalibrated M5 Max).
    #[test]
    fn a_macs_device_row_shows_the_metal_size() {
        let mut r = gpu_slot(Some(28 << 30));
        r.slot_key = "risc0:metal:0".to_string();
        r.gpu_tag = "metal".to_string();
        r.gpu_name = Some("Apple M5 Max".to_string());
        r.pci_bus_id = Some("apple-gpu0".to_string());
        let rows = build_gpu_device_benchmarks_from_workers(&[r], &BTreeMap::new());
        assert_eq!(rows.len(), 1);
        let po2 = metal_job_po2(Some(28 << 30));
        assert_eq!(rows[0].device_id, "gpu-metal0");
        assert_eq!(rows[0].optimal_po2, po2);
        assert!(rows[0].optimal_po2 <= 20, "{}", rows[0].optimal_po2);
        assert_eq!(rows[0].max_feasible_po2, po2);
        assert_eq!(
            rows[0].memory_usage_bytes,
            crate::metal_sizing::stark_peak_bytes(po2)
        );
    }

    #[test]
    fn a_card_proves_risc0_jobs_at_its_override_else_its_default_raised_by_calibration() {
        fn cuda_job_po2(o: Option<u8>, r: Option<&DeviceBenchmark>, v: Option<u64>) -> Option<u8> {
            risc0_job_po2(o, r, v, "cuda")
        }
        use zkminer_prover_protocol::{RISC0_JOB_PO2_MAX, RISC0_JOB_PO2_MIN};
        const GIB: u64 = 1 << 30;
        let calibrated = |ceiling: u8| {
            let samples = (18..=ceiling)
                .map(|p| sample(p, 64 >> (p - 18), 1e6))
                .collect();
            risc0_row(samples, ceiling, ceiling)
        };
        // Its heuristic sizes say nothing about a card: never read without samples.
        let heuristic = risc0_row(Vec::new(), 23, 24);

        // By default: 20, unless the card is known too small for it, which gets the largest measured
        // size that fits.
        assert_eq!(cuda_job_po2(None, None, None), Some(20));
        assert_eq!(cuda_job_po2(None, None, Some(16 * GIB)), Some(20));
        assert_eq!(cuda_job_po2(None, None, Some(14 * GIB)), Some(20));
        assert_eq!(cuda_job_po2(None, None, Some(14 * GIB - 1)), Some(19));
        assert_eq!(cuda_job_po2(None, None, Some(12_282 << 20)), Some(19));
        assert_eq!(cuda_job_po2(None, None, Some(8 * GIB)), Some(18));
        assert_eq!(
            cuda_job_po2(None, None, Some(RISC0_JOB_MIN_VRAM_BYTES)),
            Some(18)
        );
        assert_eq!(
            cuda_job_po2(None, None, Some(RISC0_JOB_MIN_VRAM_BYTES - 1)),
            None
        );
        assert_eq!(cuda_job_po2(None, None, Some(4 * GIB)), None);
        assert_eq!(
            cuda_job_po2(None, Some(&heuristic), Some(80 * GIB)),
            Some(20)
        );
        assert_eq!(cuda_job_po2(None, Some(&heuristic), Some(4 * GIB)), None);
        // A calibration gives a card too small for any default its measured size...
        assert_eq!(
            cuda_job_po2(None, Some(&calibrated(18)), Some(6 * GIB)),
            Some(18)
        );
        // ...and a 12 GB card keeps its default 19 when the calibration proved 19 (a ceiling of 18).
        assert_eq!(
            cuda_job_po2(None, Some(&calibrated(18)), Some(12 * GIB)),
            Some(19)
        );
        // ...raises a big one above the default...
        assert_eq!(
            cuda_job_po2(None, Some(&calibrated(21)), Some(32 * GIB)),
            Some(21)
        );
        // ...but never lowers it (its ceiling keeps a step below the highest size that proved).
        assert_eq!(
            cuda_job_po2(None, Some(&calibrated(19)), Some(16 * GIB)),
            Some(20)
        );
        assert_eq!(cuda_job_po2(None, Some(&calibrated(19)), None), Some(20));
        // A calibration that saw the default size fail (a ceiling of 18: 19 was its highest
        // success) stands, whatever the card's VRAM (a display held some; the read failed).
        assert_eq!(
            cuda_job_po2(None, Some(&calibrated(18)), Some(16 * GIB)),
            Some(18)
        );
        assert_eq!(cuda_job_po2(None, Some(&calibrated(18)), None), Some(18));
        // A sweep capped at 19 by a 16 GB card's free VRAM proved 19 and never tried 20: it stands.
        let capped = DeviceBenchmark {
            highest_proved_po2: Some(19),
            ..calibrated(19)
        };
        assert_eq!(cuda_job_po2(None, Some(&capped), Some(16 * GIB)), Some(19));
        // One that proved 20 and saw 21 fail (ceiling 19) is raised to its default 20.
        let proved_20 = DeviceBenchmark {
            highest_proved_po2: Some(20),
            ..calibrated(19)
        };
        assert_eq!(
            cuda_job_po2(None, Some(&proved_20), Some(16 * GIB)),
            Some(20)
        );
        // A card whose VRAM could not be read proves at the size it was benchmarked at.
        let benchmarked_19 = DeviceBenchmark {
            benchmark_po2: Some(19),
            ..risc0_row(Vec::new(), 19, 19)
        };
        assert_eq!(cuda_job_po2(None, Some(&benchmarked_19), None), Some(19));
        assert_eq!(
            cuda_job_po2(None, Some(&benchmarked_19), Some(12 * GIB)),
            Some(19)
        );
        // Never above its ceiling, and within the job range (a cache from before the range).
        let mut over = calibrated(19);
        over.optimal_po2 = 21;
        assert_eq!(cuda_job_po2(None, Some(&over), Some(12 * GIB)), Some(19));
        let mut huge = calibrated(21);
        (huge.optimal_po2, huge.max_feasible_po2) = (24, 24);
        assert_eq!(
            cuda_job_po2(None, Some(&huge), None),
            Some(RISC0_JOB_PO2_MAX)
        );
        // Another backend's row is not this card's risc0 calibration.
        let mut sp1 = calibrated(19);
        sp1.prover_backend = "sp1".to_string();
        assert_eq!(cuda_job_po2(None, Some(&sp1), Some(4 * GIB)), None);
        // An override wins, held to the job range.
        assert_eq!(
            cuda_job_po2(Some(18), Some(&calibrated(21)), Some(8 * GIB)),
            Some(18)
        );
        assert_eq!(cuda_job_po2(Some(23), None, None), Some(RISC0_JOB_PO2_MAX));
        assert_eq!(cuda_job_po2(Some(14), None, None), Some(RISC0_JOB_PO2_MIN));
        // An AMD or Intel card keeps the rule from before the CUDA sizes were measured: 20 from 14 GiB,
        // nothing under it unless calibrated or set.
        assert_eq!(risc0_job_po2(None, None, Some(16 * GIB), "rocm"), Some(20));
        assert_eq!(risc0_job_po2(None, None, Some(12 * GIB), "intel"), None);
        assert_eq!(
            risc0_job_po2(None, Some(&calibrated(20)), Some(12 * GIB), "intel"),
            Some(20)
        );
    }

    #[test]
    fn a_card_is_planned_at_the_rate_of_its_job_size() {
        let uncalibrated = risc0_row(Vec::new(), 18, 18);
        assert_eq!(risc0_job_throughput(&uncalibrated, 20, None), 2_000_000.0);
        assert_eq!(
            risc0_job_throughput(&uncalibrated, 21, None),
            2_000_000.0,
            "nothing credited"
        );
        assert_eq!(
            risc0_job_throughput(&uncalibrated, 18, None),
            2_000_000.0 * 0.25
        );
        // Calibrated: the lower of the row and its rate at the size; halved per step below its
        // samples.
        let calibrated = risc0_row(vec![sample(19, 32, 1.5e6), sample(20, 16, 2.5e6)], 20, 20);
        assert_eq!(risc0_job_throughput(&calibrated, 20, None), 2_000_000.0);
        assert_eq!(risc0_job_throughput(&calibrated, 19, None), 1_500_000.0);
        assert_eq!(
            risc0_job_throughput(&calibrated, 17, None),
            1_500_000.0 * 0.25
        );
        // A 12 GB card benchmarked at its own 19: that rate is its jobs' rate, with nothing
        // credited above it and the same charge per step below.
        let at_19 = DeviceBenchmark {
            benchmark_po2: Some(19),
            highest_proved_po2: None,
            ..risc0_row(Vec::new(), 19, 19)
        };
        assert_eq!(risc0_job_throughput(&at_19, 19, None), 2_000_000.0);
        assert_eq!(risc0_job_throughput(&at_19, 18, None), 2_000_000.0 * 0.5);
        // Above it is a size its measurements say does not fit (an operator's 20, or 20 when its
        // VRAM could not be read): charged a quarter per step, not credited the rate of the size
        // that fits.
        assert_eq!(risc0_job_throughput(&at_19, 20, None), 2_000_000.0 * 0.25);
        assert_eq!(
            risc0_job_throughput(&at_19, 21, None),
            2_000_000.0 * 0.25 * 0.25
        );
        // Calibrated only up to 19 (its free VRAM capped the sweep): the same.
        let capped = DeviceBenchmark {
            benchmark_po2: Some(19),
            ..risc0_row(vec![sample(18, 32, 1.0e6), sample(19, 16, 1.5e6)], 19, 19)
        };
        assert_eq!(risc0_job_throughput(&capped, 20, None), 1_500_000.0 * 0.25);
        // A card measured at 20 whose VRAM is unknown is not charged above it, as before...
        assert_eq!(risc0_job_throughput(&uncalibrated, 22, None), 2_000_000.0);
        // ...but one whose VRAM says the size does not fit is: an RTX 5080 (16 GB) set to 21, a
        // 4090 (24 GB) set to 22. A 4090 at 21 and a 5090 (32 GB) at 21 are held.
        const MIB: u64 = 1 << 20;
        let fit = |mib: u64| risc0_largest_fitting_po2(Some(mib * MIB), "cuda");
        assert_eq!(fit(16_303), Some(20));
        assert_eq!(fit(24_564), Some(21));
        assert_eq!(fit(32_607), Some(21));
        assert_eq!(fit(12_282), Some(19));
        // A card too small for any holds none, which is not "unknown": a 6 GB card benchmarked at
        // 20 by an earlier version and set to 21 is charged above 20.
        assert_eq!(fit(6_144), Some(0));
        assert_eq!(
            risc0_job_throughput(&uncalibrated, 21, fit(6_144)),
            2_000_000.0 * 0.25
        );
        assert_eq!(risc0_largest_fitting_po2(Some(16_303 * MIB), "rocm"), None);
        assert_eq!(risc0_largest_fitting_po2(None, "cuda"), None);
        assert_eq!(
            risc0_job_throughput(&uncalibrated, 21, fit(16_303)),
            2_000_000.0 * 0.25
        );
        assert_eq!(
            risc0_job_throughput(&uncalibrated, 22, fit(24_564)),
            2_000_000.0 * 0.25
        );
        assert_eq!(
            risc0_job_throughput(&uncalibrated, 21, fit(24_564)),
            2_000_000.0
        );
        // A calibration that proved 22 on a card the estimate says cannot hold it is believed.
        let proved_22 = risc0_row(vec![sample(21, 8, 2.0e6), sample(22, 4, 2.2e6)], 22, 22);
        assert_eq!(
            risc0_job_throughput(&proved_22, 22, fit(32_607)),
            2_000_000.0
        );
        // An Arc A770: 20 proved, 21 did not, so its ceiling is 19, but it proves at its default 20, at
        // the rate measured there, not at 19's.
        let (samples, ceiling, _) = sweep_po2(18, 22, |p| match p {
            18 => Some(sample(18, 260, 46_289.0)),
            19 => Some(sample(19, 122, 77_113.0)),
            20 => Some(sample(20, 59, 116_003.0)),
            _ => None,
        });
        assert_eq!(ceiling, Some(19));
        let a770 = risc0_row(samples, 19, 19);
        assert_eq!(risc0_job_throughput(&a770, 20, None), 116_003.0);
        assert_eq!(risc0_job_throughput(&a770, 19, None), 77_113.0);
    }

    #[test]
    fn a_card_is_benchmarked_at_its_own_default_size() {
        const GIB: u64 = 1024 * 1024 * 1024;
        // The 4070's 12 GB: 19, where a 20 proof spills. 16 GB and up: 20, as before.
        assert_eq!(risc0_benchmark_po2(Some(12 * GIB), "cuda"), 19);
        assert_eq!(risc0_benchmark_po2(Some(16 * GIB), "cuda"), 20);
        assert_eq!(risc0_benchmark_po2(Some(32 * GIB), "cuda"), 20);
        assert_eq!(risc0_benchmark_po2(Some(8 * GIB), "cuda"), 18);
        // Too small to prove jobs by default: still the smallest measured size, not an unmeasured
        // one.
        assert_eq!(risc0_benchmark_po2(Some(4 * GIB), "cuda"), 18);
        // Unknown VRAM, or AMD and Intel: 20, as every card was benchmarked before.
        assert_eq!(risc0_benchmark_po2(None, "cuda"), 20);
        assert_eq!(risc0_benchmark_po2(Some(12 * GIB), "intel"), 20);
        assert_eq!(risc0_benchmark_po2(Some(16 * GIB), "rocm"), 20);
        // A card is benchmarked at the size it proves jobs at by default.
        for gib in [6, 8, 12, 16, 24, 32] {
            let v = Some(gib * GIB);
            if let Some(job) = risc0_job_po2(None, None, v, "cuda") {
                assert_eq!(risc0_benchmark_po2(v, "cuda"), job, "{gib} GiB");
            }
        }
    }

    /// An Apple GPU is benchmarked at the Metal table's size for its idle budget (`hw.memsize` less
    /// the 8 GiB host reserve), the size its jobs prove at, never the CUDA rule's 20 (a rebase
    /// regression once benchmarked every Mac at 20).
    #[test]
    fn a_mac_is_benchmarked_at_the_metal_tables_size() {
        const GIB: u64 = 1024 * 1024 * 1024;
        for vram in [
            Some(4 * GIB),
            Some(8 * GIB),
            Some(10 * GIB),
            Some(16 * GIB),
            None,
        ] {
            assert_eq!(
                risc0_benchmark_po2(vram, "metal"),
                metal_job_po2(vram),
                "{vram:?}"
            );
            assert_eq!(
                Some(risc0_benchmark_po2(vram, "metal")),
                risc0_slot_job_po2("gpu-metal0", "metal", None, None, vram),
                "the size its jobs prove at, {vram:?}"
            );
        }
        // Without a budget: what the Metal table says for the idle budget, which keeps a 16 or
        // 18 GB Mac (8 or 10 GiB idle) at 19 and a 12 GB one (4 GiB) at 18 (M8's rows, which W7
        // and R2 only ever lower), and a 24 GB one (16 GiB) at 20.
        if std::env::var_os(crate::metal_sizing::MAX_WORKING_SET_ENV).is_none() {
            use crate::metal_sizing::{job_po2_for_limit, job_po2_for_limit_in, Po2Table::M8};
            for gib in [4, 8, 10, 16] {
                assert_eq!(
                    risc0_benchmark_po2(Some(gib * GIB), "metal"),
                    job_po2_for_limit(gib * GIB),
                    "{gib} GiB"
                );
            }
            assert_eq!(job_po2_for_limit_in(8 * GIB, M8), 19);
            assert_eq!(job_po2_for_limit_in(10 * GIB, M8), 19);
            assert_eq!(job_po2_for_limit_in(4 * GIB, M8), 18);
            assert_eq!(job_po2_for_limit_in(16 * GIB, M8), 20);
            // The default table on the Macs these budgets belong to (16, 18 and 12 GB of RAM), not
            // on this host's: on a Mac with 21 GB or more W7's footprint rule admits 20 at 10 GiB.
            use crate::metal_sizing::{job_po2_in, Po2Table::W7};
            assert_eq!(job_po2_in(8 * GIB, W7, Some(16 * GIB)), 19);
            assert_eq!(job_po2_in(10 * GIB, W7, Some(18 * GIB)), 19);
            assert_eq!(job_po2_in(4 * GIB, W7, Some(12 * GIB)), 18);
        }
        // Unknown budget (an explicitly configured worker): the protocol default, which the host
        // then sends; the worker refuses it where it does not fit (`po2_refusal`, as for a job).
        if std::env::var_os(crate::metal_sizing::MAX_WORKING_SET_ENV).is_none() {
            assert_eq!(
                risc0_benchmark_po2(None, "metal"),
                zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2
            );
        }
    }

    /// A sweep proving at each size per `fits` (the largest that fits; None fails all), recording what
    /// it asked for.
    fn sweep(start: u8, top: u8, fits: Option<u8>) -> (Vec<u8>, Option<u8>, Vec<u8>) {
        let mut asked = Vec::new();
        let (samples, ceiling, _) = sweep_po2(start, top, |p| {
            asked.push(p);
            fits.filter(|f| p <= *f).map(|_| sample(p, 4, 1e6))
        });
        (samples.iter().map(|s| s.po2).collect(), ceiling, asked)
    }

    #[test]
    fn a_sweep_finds_each_cards_ceiling_with_a_step_of_headroom() {
        // A 4090/5080-like card: 20 proves, 21 fails, so 19 (one step below the highest success);
        // 20's sample is kept as the rate of a card that proves at 20.
        assert_eq!(
            sweep(18, 22, Some(20)),
            (vec![18, 19, 20], Some(19), vec![18, 19, 20, 21])
        );
        // A 12 GB card (20 fails): 18.
        assert_eq!(
            sweep(18, 22, Some(19)),
            (vec![18, 19], Some(18), vec![18, 19, 20])
        );
        // A card that fails at the start: down to the first size that proves, then its headroom
        // step, proved too.
        assert_eq!(
            sweep(18, 22, Some(17)),
            (vec![16, 17], Some(16), vec![18, 17, 16])
        );
        assert_eq!(
            sweep(18, 22, Some(18)),
            (vec![17, 18], Some(17), vec![18, 19, 17])
        );
        // Nothing in the job range with headroom: no size.
        assert_eq!(sweep(18, 22, Some(16)).1, None);
        assert_eq!(sweep(18, 22, None), (vec![], None, vec![18, 17, 16]));
        // Clean to a top set by the card's memory (a measured size): no step back...
        assert_eq!(
            sweep(18, 20, Some(22)),
            (vec![18, 19, 20], Some(20), vec![18, 19, 20])
        );
        // ...but clean to the job range's top, beyond which the prover refuses: one.
        assert_eq!(
            sweep(18, 22, Some(22)),
            (vec![18, 19, 20, 21, 22], Some(21), vec![18, 19, 20, 21, 22])
        );
        // A sample at a smaller size than asked (free VRAM short) ends the sweep without a failure.
        let mut asked = Vec::new();
        let (samples, ceiling, highest) = sweep_po2(18, 22, |p| {
            asked.push(p);
            Some(sample(p.min(19), 4, 1e6))
        });
        assert_eq!(highest, Some(19));
        assert_eq!(
            samples.iter().map(|s| s.po2).collect::<Vec<_>>(),
            vec![18, 19]
        );
        assert_eq!((ceiling, asked), (Some(19), vec![18, 19, 20]));
    }

    #[test]
    fn a_sweep_reports_the_highest_size_that_proved() {
        let highest = |start, top, fits: Option<u8>| {
            sweep_po2(start, top, |p| {
                fits.filter(|f| p <= *f).map(|_| sample(p, 4, 1e6))
            })
            .2
        };
        // 20 proved and 21 failed: the ceiling is 19, but 20 proved.
        assert_eq!(highest(18, 22, Some(20)), Some(20));
        // Capped at 19 by free VRAM: 19 is the highest, and 20 never ran.
        assert_eq!(highest(18, 19, Some(22)), Some(19));
        assert_eq!(highest(18, 22, None), None);
    }

    #[test]
    fn a_calibration_run_is_limited_by_the_quickest_size_so_far() {
        assert_eq!(calibration_run_limit(None), None);
        assert_eq!(calibration_run_limit(Some(0.0)), None);
        assert_eq!(calibration_run_limit(Some(f64::NAN)), None);
        assert_eq!(calibration_run_limit(Some(f64::MAX)), None);
        // Never under a minute...
        assert_eq!(calibration_run_limit(Some(1.0)), Some(CALIBRATION_MIN_RUN));
        assert_eq!(
            calibration_run_limit(Some(18.86)),
            Some(CALIBRATION_MIN_RUN)
        );
        // ...and otherwise three times the quickest.
        assert_eq!(
            calibration_run_limit(Some(41.15)),
            Some(Duration::from_secs_f64(41.15 * 3.0))
        );
    }

    /// The sweep `calibrate_po2_for_suite` runs, with each size taking `secs[po2 - 18]` and stopped
    /// at the limit as the pool stops it: the sizes asked for, the ceiling, the highest that proved,
    /// and the limit each run was given.
    fn timed_sweep(secs: &[f64]) -> (Vec<u8>, Option<u8>, Option<u8>, Vec<Option<Duration>>) {
        let mut fastest: Option<f64> = None;
        let (mut asked, mut limits) = (Vec::new(), Vec::new());
        let (_, ceiling, highest) = sweep_po2(18, 22, |p| {
            let limit = calibration_run_limit(fastest);
            asked.push(p);
            limits.push(limit);
            let took = secs[usize::from(p - 18)];
            if limit.is_some_and(|l| took >= l.as_secs_f64()) {
                return None;
            }
            fastest = Some(fastest.map_or(took, |f| f.min(took)));
            Some(Po2Sample {
                duration_secs: took,
                ..sample(p, 4, 1e6 / took)
            })
        });
        (asked, ceiling, highest, limits)
    }

    #[test]
    fn a_size_that_spills_ends_the_sweep_at_its_limit() {
        // RTX 5080 (Windows, 16 GB, driving a display), 2026-11-25: 18-20 fit; 21 spilled to system
        // memory and took 259 s; 22 spilled more (9+ minutes, and an invalid proof). 21 is now
        // stopped at a minute, 22 never runs, and 20 still proved: ceiling 19, highest 20, so the
        // card keeps its default size, 20 (`risc0_job_po2`).
        let (asked, ceiling, highest, limits) = timed_sweep(&[38.91, 25.23, 18.86, 259.16, 540.0]);
        assert_eq!(asked, vec![18, 19, 20, 21]);
        assert_eq!((ceiling, highest), (Some(19), Some(20)));
        assert_eq!(limits[3], Some(CALIBRATION_MIN_RUN));
        // RX 9070 XT, same run: 21 (77 s, under three times 20's 41 s) still proves; 22 (328 s) is
        // stopped at 123 s.
        let (asked, ceiling, highest, limits) = timed_sweep(&[79.58, 52.29, 41.15, 77.34, 328.13]);
        assert_eq!(asked, vec![18, 19, 20, 21, 22]);
        assert_eq!((ceiling, highest), (Some(20), Some(21)));
        assert_eq!(limits[4], Some(Duration::from_secs_f64(41.15 * 3.0)));
        // A card on which every size fits runs to the job range's top as before.
        let (asked, ceiling, _, _) = timed_sweep(&[40.0, 30.0, 22.0, 20.0, 21.0]);
        assert_eq!((asked.len(), ceiling), (5, Some(21)));
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
            benchmark_po2: None,
            highest_proved_po2: None,
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
    /// power already floored, and without the CPU row older versions derived from the GPU results.
    /// Deleting the `floor_implausible_gpu_power` or `drop_cpu_device_rows` call from
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
                        "device_id": "cpu", "device_label": "CPU", "prover_backend": "risc0",
                        "throughput": 9000000.0, "power_watts": 200.0, "optimal_po2": 21,
                        "memory_usage_bytes": 0, "max_feasible_po2": 21,
                        "program_throughputs": {}, "pci_bus_id": "", "po2_samples": []
                    },
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
        let ids: Vec<&str> = loaded
            .device_benchmarks
            .iter()
            .map(|d| d.device_id.as_str())
            .collect();
        assert_eq!(ids, ["gpu0"], "the derived CPU row must not survive a load");
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
            benchmark_po2: None,
            highest_proved_po2: None,
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
        // Never below the backend's blind default (`budget_from_measurement`), which on Windows,
        // charging commit, is above these readings doubled.
        let floor = crate::memory::unmeasured_peak_for;
        assert_eq!(
            suite.expected_host_peak_bytes("risc0"),
            (11 * gib * factor).max(floor("risc0")).min(ceiling)
        );
        assert_eq!(
            suite.expected_host_peak_bytes("sp1"),
            (18 * gib * factor).max(floor("sp1")).min(ceiling)
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
        // Exactly what the pipeline produces for SP1: no device row, a backend-keyed peak. Large
        // enough, doubled, to stand above the blind default it must be told apart from (Windows'
        // is larger, charging commit).
        let measured = if cfg!(windows) { 34 * gib } else { 10 * gib };
        let suite = BenchmarkSuite {
            device_benchmarks: vec![row("risc0", Some(5 * gib))],
            host_peaks: std::collections::HashMap::from([("sp1".to_string(), measured)]),
            ..Default::default()
        };
        let sp1 = suite.expected_host_peak_bytes("sp1");
        assert_eq!(
            sp1,
            (measured * crate::memory::MEASUREMENT_SAFETY_FACTOR).min(ceiling),
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

    /// macOS has no `/proc`: the CPU name and RAM size, both part of the hardware fingerprint, come
    /// from `sysctl` instead of reading as "Unknown CPU" and 0 bytes.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_cpu_and_memory_are_known() {
        let cpu = get_cpu_info();
        assert_ne!(cpu, "Unknown CPU");
        assert_eq!(
            Some(cpu),
            crate::memory::sysctl_string("machdep.cpu.brand_string")
        );
        let total = get_total_memory_bytes();
        assert!(total > 1 << 30, "{total}");
        assert_eq!(Some(total), crate::memory::mem_total_bytes());
        assert!(!hardware_fingerprint().contains("|0GiB|"));
    }
}

/// W7-M11: a benchmark taken in reduced power is marked on its row, survives the cache, and stays
/// in use as measured, with re-benchmark advice at full power (the pricing rule,
/// [`power_redo_reason`]).
#[cfg(test)]
mod power_state_tests {
    use super::*;
    use zkminer_prover_protocol::{BenchPowerState, BenchmarkEntry};

    const FULL: BenchPowerState = BenchPowerState {
        low_power_mode: Some(false),
        on_battery: Some(false),
        thermal: Some(0),
    };
    const LPM: BenchPowerState = BenchPowerState {
        low_power_mode: Some(true),
        on_battery: Some(false),
        thermal: Some(0),
    };
    const HOT_BATTERY: BenchPowerState = BenchPowerState {
        low_power_mode: Some(false),
        on_battery: Some(true),
        thermal: Some(2),
    };

    fn entry(name: &str, power: Option<BenchPowerState>) -> BenchmarkEntry {
        BenchmarkEntry {
            program_name: name.to_string(),
            prover_backend: "risc0".to_string(),
            cycles: 4_000_000,
            duration_secs: 4.0,
            throughput: 1_000_000.0,
            weight: 0.15,
            precompile: false,
            wrap_secs: Some(1.5),
            power_state: power,
        }
    }

    fn metal_slot(entries: Vec<BenchmarkEntry>) -> crate::dispatcher::SlotBenchmarkResult {
        crate::dispatcher::SlotBenchmarkResult {
            slot_key: "risc0:metal:0".to_string(),
            gpu_name: Some("Apple M5 Max".to_string()),
            device_index: Some(0),
            pci_bus_id: None,
            gpu_tag: "metal".to_string(),
            entries,
            vram_bytes: Some(28 << 30),
            host_peak_bytes: None,
            benchmark_po2: None,
        }
    }

    /// The device rows, with the power knob as unset (independent of this process's environment).
    fn rows_of(
        slots: &[crate::dispatcher::SlotBenchmarkResult],
        watts: &BTreeMap<String, f64>,
    ) -> Vec<DeviceBenchmark> {
        build_gpu_device_benchmarks_with(slots, watts, false)
    }

    fn suite_of(rows: Vec<DeviceBenchmark>) -> BenchmarkSuite {
        BenchmarkSuite {
            device_benchmarks: rows,
            ..Default::default()
        }
    }

    #[test]
    fn a_program_measured_in_reduced_power_marks_its_row() {
        let slot = metal_slot(vec![
            entry("fibonacci", Some(FULL)),
            entry("memory-merkle", Some(LPM)),
            entry("chacha-mix", Some(HOT_BATTERY)),
            entry("sha256-chain", None),
        ]);
        let rows = rows_of(&[slot], &BTreeMap::new());
        let marks: Vec<Option<&str>> = rows[0]
            .program_stages
            .iter()
            .map(|p| p.power_reduced.as_deref())
            .collect();
        assert_eq!(
            marks,
            [
                None,
                Some("Low Power Mode"),
                Some("on battery, thermal serious"),
                None
            ]
        );
        assert_eq!(
            rows[0].power_reduced().as_deref(),
            Some("Low Power Mode, on battery, thermal serious")
        );
        // A full-power suite carries no mark.
        let rows = rows_of(
            &[metal_slot(vec![entry("fibonacci", Some(FULL))])],
            &BTreeMap::new(),
        );
        assert_eq!(rows[0].power_reduced(), None);
        // The knob uses every entry as measured.
        assert_eq!(entry_power_reduced(&entry("x", Some(LPM)), true), None);
        assert!(entry_power_reduced(&entry("x", Some(LPM)), false).is_some());
    }

    #[test]
    fn a_reduced_benchmark_gets_advice_once_the_host_is_at_full_power() {
        let marked = suite_of(rows_of(
            &[metal_slot(vec![entry("memory-merkle", Some(LPM))])],
            &BTreeMap::new(),
        ));
        let clean = suite_of(rows_of(
            &[metal_slot(vec![entry("memory-merkle", Some(FULL))])],
            &BTreeMap::new(),
        ));
        // Back at full power: advise a re-benchmark, naming the operator's command.
        let why = power_redo_reason(&marked, Some(FULL), false).expect("advice");
        assert!(why.contains("Low Power Mode"), "{why}");
        assert!(
            why.contains("[b]") && why.contains("zkminer benchmark"),
            "{why}"
        );
        // A desktop Mac (no battery reading) at full power: advice too.
        let desktop = BenchPowerState {
            on_battery: None,
            ..FULL
        };
        assert!(power_redo_reason(&marked, Some(desktop), false).is_some());
        // Still reduced (any cause), or nothing readable: no advice yet.
        assert_eq!(power_redo_reason(&marked, Some(LPM), false), None);
        assert_eq!(power_redo_reason(&marked, Some(HOT_BATTERY), false), None);
        assert_eq!(
            power_redo_reason(&marked, Some(BenchPowerState::default()), false),
            None
        );
        assert_eq!(power_redo_reason(&marked, None, false), None);
        // The knob, and an unmarked suite: never.
        assert_eq!(power_redo_reason(&marked, Some(FULL), true), None);
        assert_eq!(power_redo_reason(&clean, Some(FULL), false), None);
        assert_eq!(
            power_redo_reason(&BenchmarkSuite::default(), Some(FULL), false),
            None
        );
    }

    /// The mark is JSON-only and optional: a cache written before it loads, a marked one keeps its
    /// mark through save and load, and an unmarked stage writes no key. A cache carrying fix round
    /// 1's `power_redo_attempted` key (never released) also loads: the key is ignored.
    #[test]
    fn the_mark_survives_the_cache_and_older_caches_still_load() {
        let old = r#"{"program_name":"fibonacci","cycles":10,"stark_secs":1.0,"wrap_secs":null}"#;
        let stage: ProgramStage = serde_json::from_str(old).unwrap();
        assert_eq!(stage.power_reduced, None);
        assert!(!serde_json::to_string(&stage)
            .unwrap()
            .contains("power_reduced"));

        let suite = suite_of(rows_of(
            &[metal_slot(vec![entry("memory-merkle", Some(LPM))])],
            &BTreeMap::new(),
        ));
        let (dir, path) = scratch_cache("mark");
        let saved = SavedBenchmark {
            suite_version: "v-test".to_string(),
            hardware_fingerprint: "fp-test".to_string(),
            suite,
        };
        std::fs::write(&path, serde_json::to_string(&saved).unwrap()).unwrap();
        let loaded = load_cached_benchmark_from(&path, "v-test", "fp-test").expect("loads");
        assert_eq!(
            loaded.device_benchmarks[0].power_reduced().as_deref(),
            Some("Low Power Mode")
        );
        assert!(power_redo_reason(&loaded, Some(FULL), false).is_some());

        let mut v: serde_json::Value = serde_json::to_value(&saved).unwrap();
        v["power_redo_attempted"] = serde_json::json!("an earlier redo");
        std::fs::write(&path, v.to_string()).unwrap();
        assert!(load_cached_benchmark_from(&path, "v-test", "fp-test").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    const HOT: BenchPowerState = BenchPowerState {
        low_power_mode: Some(false),
        on_battery: Some(false),
        thermal: Some(2),
    };
    const BATTERY: BenchPowerState = BenchPowerState {
        low_power_mode: Some(false),
        on_battery: Some(true),
        thermal: Some(0),
    };

    fn scratch_cache(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "zkbench-w7m11-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("benchmarks.json");
        (dir, path)
    }

    fn suite_measured_in(state: BenchPowerState) -> BenchmarkSuite {
        suite_of(rows_of(
            &[metal_slot(vec![
                entry("fibonacci", Some(FULL)),
                entry("memory-merkle", Some(state)),
            ])],
            &BTreeMap::new(),
        ))
    }

    /// One miner start, shaped like the real callers (`zkminer run` run.rs, `zkminer mock`): load
    /// the cache with the host in `now` and price from what comes back. They never benchmark on
    /// `None` (auto-benchmark at startup is disabled); `None` means placeholder prices. Returns the
    /// suite in use and the advice, if any.
    fn start(
        path: &std::path::Path,
        now: BenchPowerState,
    ) -> (Option<BenchmarkSuite>, Option<String>) {
        match load_cached_benchmark_with_power(path, "v-test", "fp-test", || now, false) {
            Some((suite, advice)) => (Some(suite), advice),
            None => (None, None),
        }
    }

    /// The marked row of the suite in use, to tell which measurement prices the miner.
    fn in_use_mark(suite: &Option<BenchmarkSuite>) -> Option<String> {
        suite
            .as_ref()
            .expect("a measured suite in use")
            .device_benchmarks[0]
            .power_reduced()
    }

    /// The fix-round-1 finding: a benchmark that heats the Mac to `serious` itself is marked, and
    /// the next start is cool. It stays in use as measured and never asks for a redo.
    #[test]
    fn a_self_heated_benchmark_is_never_redone() {
        let (dir, path) = scratch_cache("heat");
        save_benchmark_to(&path, "v-test", "fp-test", &suite_measured_in(HOT)).unwrap();
        let cached = load_cached_benchmark_from(&path, "v-test", "fp-test").unwrap();
        assert_eq!(
            cached.device_benchmarks[0].power_reduced().as_deref(),
            Some("thermal serious")
        );
        assert_eq!(power_redo_cause(&cached), None);
        for now in [FULL, FULL, FULL, FULL, FULL, HOT] {
            let (suite, advice) = start(&path, now);
            assert_eq!(in_use_mark(&suite).as_deref(), Some("thermal serious"));
            assert_eq!(advice, None);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The fix-round-2 finding, caller-shaped: a battery suite at a full-power start used to be
    /// dropped (and a one-shot record written) while no caller benchmarked, so that start priced
    /// from placeholders and the next one kept the battery suite for good. Now every start keeps
    /// the measured suite, never writes the cache, and advises a re-benchmark while the host is at
    /// full power; once the operator's full-power benchmark is saved, that suite is in use and the
    /// advice stops.
    #[test]
    fn a_reduced_suite_stays_in_use_until_the_operator_rebenchmarks() {
        let (dir, path) = scratch_cache("caller");
        save_benchmark_to(&path, "v-test", "fp-test", &suite_measured_in(BATTERY)).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        // Still on battery: in use, no advice.
        let (suite, advice) = start(&path, BATTERY);
        assert_eq!(in_use_mark(&suite).as_deref(), Some("on battery"));
        assert_eq!(advice, None);
        // Full power, on every one of many starts: still in use, advice every time.
        for _ in 0..5 {
            let (suite, advice) = start(&path, FULL);
            assert_eq!(in_use_mark(&suite).as_deref(), Some("on battery"));
            assert!(advice.expect("advice").contains("on battery"));
        }
        // Hot at load: in use, no advice (a benchmark now would measure the heat).
        let (suite, advice) = start(&path, HOT);
        assert!(suite.is_some());
        assert_eq!(advice, None);
        // A load never writes the cache.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        // The operator presses [b] at full power: the clean suite is in use, no advice.
        save_benchmark_to(&path, "v-test", "fp-test", &suite_measured_in(FULL)).unwrap();
        for _ in 0..3 {
            let (suite, advice) = start(&path, FULL);
            assert_eq!(in_use_mark(&suite), None);
            assert_eq!(advice, None);
        }
        // A [b] that is itself marked again (unplugged during it) is simply in use, with advice.
        save_benchmark_to(&path, "v-test", "fp-test", &suite_measured_in(LPM)).unwrap();
        let (suite, advice) = start(&path, FULL);
        assert_eq!(in_use_mark(&suite).as_deref(), Some("Low Power Mode"));
        assert!(advice.is_some());
        // The knob: in use, no advice.
        let (suite, advice) =
            load_cached_benchmark_with_power(&path, "v-test", "fp-test", || FULL, true).unwrap();
        assert!(suite.device_benchmarks[0].power_reduced().is_some());
        assert_eq!(advice, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A read-only cache directory changes nothing: the load needs no write.
    /// Unix only: it sets the directory's mode bits.
    #[cfg(unix)]
    #[test]
    fn a_read_only_cache_still_loads_with_advice() {
        let (dir, path) = scratch_cache("ro");
        save_benchmark_to(&path, "v-test", "fp-test", &suite_measured_in(LPM)).unwrap();
        let mut perm = std::fs::metadata(&dir).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perm.set_mode(0o500);
        std::fs::set_permissions(&dir, perm.clone()).unwrap();
        let kept = load_cached_benchmark_with_power(&path, "v-test", "fp-test", || FULL, false);
        perm.set_mode(0o700);
        std::fs::set_permissions(&dir, perm).unwrap();
        let (_, advice) = kept.expect("in use");
        assert!(advice.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// W10-BENCH: a failed, simulated or empty run is never cached, and a simulated cache is never used.
#[cfg(test)]
mod failure_cache_tests {
    use super::*;
    use crate::dispatcher::SlotBenchmarkFailure;

    fn scratch(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "zkbench-w10-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("benchmarks.json");
        (dir, path)
    }

    fn measured() -> BenchmarkSuite {
        BenchmarkSuite {
            results: vec![BenchmarkResult {
                program_name: "memory-merkle".to_string(),
                prover_backend: "risc0".to_string(),
                cycles: 7_340_032,
                duration: Duration::from_secs_f64(8.4),
                throughput: 873_813.0,
                weight: 0.15,
                precompile: true,
            }],
            ..Default::default()
        }
    }

    fn failure(tag: &str) -> SlotBenchmarkFailure {
        SlotBenchmarkFailure {
            slot_key: format!("risc0:{tag}:0"),
            gpu_name: Some("Apple M5 Max".to_string()),
            gpu_tag: tag.to_string(),
            error: "warm-up of risc0:metal:0 failed: warm-up failed: stepAccumA".to_string(),
        }
    }

    #[test]
    fn only_a_complete_measured_run_is_saved() {
        let (dir, path) = scratch("save");
        assert_eq!(measured().not_cacheable(), None);

        let mut failed = measured();
        failed.failures.push(failure("metal"));
        assert!(failed.failed());
        let simulated = BenchmarkSuite {
            results: run_simulated_benchmarks(),
            ..Default::default()
        };
        for (what, suite) in [
            ("a failed run", failed),
            ("a simulated run", simulated),
            ("an empty run", BenchmarkSuite::default()),
        ] {
            let err = save_benchmark_to(&path, "v-test", "fp-test", &suite).expect_err(what);
            assert!(err.starts_with("Not saving"), "{what}: {err}");
            assert!(!path.exists(), "{what} was written");
        }

        save_benchmark_to(&path, "v-test", "fp-test", &measured()).expect("a measured run");
        let loaded = load_cached_benchmark_from(&path, "v-test", "fp-test").expect("loads");
        assert!(!loaded.failed(), "failures are never cached");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A simulated suite saved before W10-BENCH (the TUI's full benchmark did, with no worker) is
    /// ignored on load, so `zkminer run` never prices from it.
    #[test]
    fn a_simulated_cache_is_not_loaded() {
        let (dir, path) = scratch("load");
        let saved = SavedBenchmark {
            suite_version: "v-test".to_string(),
            hardware_fingerprint: "fp-test".to_string(),
            suite: BenchmarkSuite {
                results: run_simulated_benchmarks(),
                zkops: 3_022_602.0,
                ..Default::default()
            },
        };
        std::fs::write(&path, serde_json::to_string(&saved).unwrap()).unwrap();
        assert!(load_cached_benchmark_from(&path, "v-test", "fp-test").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failures_name_the_worker_the_error_and_what_to_try() {
        let lines = describe_failures(&[failure("metal"), failure("cuda"), failure("metal")]);
        assert!(
            lines[0].starts_with("risc0:metal:0 (Apple M5 Max): warm-up of"),
            "{lines:?}"
        );
        assert!(lines[0].contains("stepAccumA"));
        // Each piece of advice once, after the failures.
        assert_eq!(lines.len(), 5, "{lines:?}");
        assert!(lines[3].contains("tools/macos-smoke.sh") && lines[3].contains("Troubleshooting"));
        assert!(lines[4].contains("--benchmark"));
    }

    /// The simulated stand-ins never carry a score, and a run with no worker at all is the only one
    /// that is simulated (`run_benchmark` with no pool).
    #[test]
    fn a_simulated_run_has_no_score() {
        if crate::engine::worker_pool().is_some() {
            return; // another test in this binary set the pool up
        }
        let suite = run_benchmark();
        assert!(suite.is_simulated());
        assert!(!suite.failed());
        assert_eq!(suite.zkops, 0.0);
        assert!(suite.not_cacheable().is_some());
    }
}
