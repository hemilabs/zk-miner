//! Cost modeling for electricity and hardware amortization.

use std::time::Duration;

/// Cost parameters for the proving operation.
#[derive(Debug, Clone)]
pub struct CostParams {
    /// Electricity cost in USD per kWh.
    pub electricity_cost_kwh: f64,
    /// FIXED overhead in watts: motherboard, fans, drives, PSU losses — everything EXCEPT the
    /// CPU package and the GPUs, which are measured and added by `system_watts_for_suite`.
    ///
    /// Named `base_overhead_watts`, not `system_power_watts`, because the old name is what
    /// produced the bug: config documents the value as a component to be ADDED to measured
    /// power, and the production path read the field's name and passed it through as the whole
    /// machine's draw — costing a two-GPU box's electricity at 75 W against ~872 W at the wall.
    /// A name that cannot be misread is worth more than the comment explaining the misreading.
    pub base_overhead_watts: f64,
    /// Hardware amortization cost in USD per hour.
    pub hardware_cost_per_hour: f64,
    /// Estimated gas cost in USD for the on-chain transactions (claim + fulfill).
    pub gas_cost_usd: f64,
}

impl Default for CostParams {
    fn default() -> Self {
        Self {
            electricity_cost_kwh: 0.12,
            // The config default for the overhead term, not a whole-machine figure. It was
            // 200.0 — a total — which after the composition moved into `evaluate_job` would
            // have been added ON TOP of the measured CPU and GPU.
            base_overhead_watts: 75.0,
            hardware_cost_per_hour: 0.0,
            gas_cost_usd: 0.01, // ~0.0005 ETH at ~$20/ETH (Hemi gas is cheap)
        }
    }
}

/// Estimate the cost of proving for a given duration.
pub fn estimate_proving_cost(params: &CostParams, duration: Duration) -> f64 {
    let hours = duration.as_secs_f64() / 3600.0;

    // Electricity cost: watts * hours / 1000 * $/kWh
    // `base_overhead_watts` is the composed total by the time it reaches here: `evaluate_job`
    // replaces it with CPU + card + overhead. The field keeps its name because that is what the
    // caller supplies; see `system_watts_for_suite`.
    let electricity = params.base_overhead_watts * hours / 1000.0 * params.electricity_cost_kwh;

    // Hardware amortization
    let hardware = params.hardware_cost_per_hour * hours;

    // Gas cost is fixed per job (claim + fulfill transactions)
    electricity + hardware + params.gas_cost_usd
}

/// Fallback CPU package draw when RAPL is unreadable.
///
/// RAPL needs `/dev/cpu/*/msr` or an accessible powercap tree, and on this host neither is
/// present, so `cpu_power_watts` is `None` in practice rather than in theory. 65 W is a
/// desktop package under load.
///
/// This is now the ONLY CPU fallback in the cost path: the mock path used to carry its own `65.0`
/// literal, and the composition moving into `evaluate_job` deleted that code rather than linking
/// it. Two earlier versions of this comment claimed a cross-module link that did not exist; there
/// is no link because there is no second consumer.
///
/// One other `200.0` lives in `benchmark.rs`, stamped on the stored CPU device ROW. That answers a
/// different question (what to display for an unmeasured CPU) and this model never reads it.
///
/// Known limitation: 65 W is a desktop package figure, and on a many-core workstation (this box
/// is a 32-core Threadripper) the CPU draws more than that while feeding the GPUs. It is the one
/// term still unmeasured where RAPL is unreadable, and it is small beside the card term — but it
/// errs low, like everything else here.
pub const DEFAULT_CPU_WATTS: f64 = 65.0;

/// Fallback per-card draw for an unmeasured card.
///
/// Re-exported rather than restated so there is one such number in the workspace. This model
/// never applies it itself — the fallback is stamped onto a device row when the row is written
/// (`benchmark.rs`, and `synthetic_conservative_benchmark` for a suite with no measurements) —
/// so by the time a suite reaches here, an unmeasured card already carries it.
pub use zkminer_prover::benchmark::FALLBACK_GPU_WATTS as DEFAULT_GPU_WATTS;

/// The total watts to charge a proof against on this machine.
///
/// `base_overhead_watts` is config's `prover.system_power_watts`, which its own doc defines as
/// "base system power overhead (motherboard, fans, drives, PSU losses), ADDED to measured CPU
/// and GPU power". Nothing added it: production passed it straight into `CostParams` as the
/// TOTAL, so every profitability estimate on this two-GPU box charged 75 W of electricity
/// against ~872 W measured at the wall — an order of magnitude under, in the one term that
/// decides whether a job is worth claiming.
///
/// `device_watts` is the card this evaluation assumes, when the caller named one. That pairing
/// matters: `evaluate_job` derives the proof's DURATION from either a device-specific
/// throughput or the suite average, and the power charged has to describe the same card as the
/// duration, or the product P·t is a figure about no machine in particular.
///
/// With no card named, the term is the mean over distinct proving cards. Two honest caveats,
/// recorded because the previous version of this comment claimed a correspondence that does
/// not exist:
///
///  * The suite-average throughput is a mean over `suite.results` — per (slot, program), not
///    per card, and not de-duplicated — while this is a mean per distinct card. The two
///    weightings differ whenever backend support is uneven across cards.
///  * For energy the mean is still defensible, because cost is P·t and both scale with card
///    speed: on this box (5080 at ~1.0e6 c/s and 341 W, 4090 at ~1.4e6 c/s and 455 W) the
///    mean-based charge is within ~2% of charging the card actually used. It degrades when the
///    box is heterogeneous in EFFICIENCY rather than speed — a 4090 beside a 1080 Ti over-costs
///    by ~40% — which is an argument for naming the device, not for a different mean.
///
/// This is also not "what the machine draws": the CPU and overhead terms are charged in full
/// to each concurrent job, so with one job per GPU a two-GPU box bills the fixed terms twice.
/// It is a per-job charge that deliberately errs high on the fixed part and low on the GPU
/// part, and the two roughly cancel at this scale.
pub fn system_watts_for_suite(
    suite: &zkminer_prover::benchmark::BenchmarkSuite,
    base_overhead_watts: f64,
    device_watts: Option<f64>,
) -> f64 {
    let cpu = suite.cpu_power_watts.unwrap_or(DEFAULT_CPU_WATTS);
    let gpu = match device_watts {
        // The caller named the device; charge what it said — INCLUDING zero, which is how a
        // CPU-only choice says "no GPU is involved". Treating `Some(0.0)` as "unknown" and
        // substituting the mean card charged a CPU job for a GPU it never touched.
        Some(w) => w,
        None => mean_proving_card_watts(suite),
    };
    cpu + gpu + base_overhead_watts
}

/// Throughput of the card whose power `system_watts_for_suite` would charge, for the same suite.
///
/// Exists so the cost term can be self-consistent. `evaluate_job` derives a job's DURATION from
/// `BenchmarkSuite::average_throughput()` when no device is named — a flat mean over
/// `suite.results`, which is one row per (slot, program) and includes CPU rows — while the power
/// comes from the mean of distinct CARDS. On this rig those differ by 1.6x (3.03M c/s against a
/// 1.90M card mean), so the energy term was being computed as "the mean card's watts for the time
/// the fastest-ish mix would take". The brain already distrusts `average_throughput` for exactly
/// this reason: it refuses to feed it to the queue planner, 300 lines from where the cost model
/// used it unguarded.
///
/// `None` when the suite lists no card, in which case the caller keeps the suite average (a
/// CPU-only box has nothing else to offer).
///
/// One asymmetry worth knowing: this skips rows with `throughput <= 0.0` while
/// `mean_proving_card_watts` does not, so for a suite containing a card with a power figure but no
/// measured throughput the two means cover different card sets. That suite shape is tolerated
/// elsewhere ("A GPU with no benchmark row still appears, with 0.0"), and charging such a card's
/// watts while excluding its zero throughput errs high, which is the safe direction.
pub fn mean_proving_card_throughput(
    suite: &zkminer_prover::benchmark::BenchmarkSuite,
) -> Option<f64> {
    let mut seen: Vec<(&str, f64)> = Vec::new();
    for d in &suite.device_benchmarks {
        if d.device_id == zkminer_prover::benchmark::CPU_DEVICE_ID || d.throughput <= 0.0 {
            continue;
        }
        let key = if d.pci_bus_id.is_empty() {
            d.device_id.as_str()
        } else {
            d.pci_bus_id.as_str()
        };
        // Same card, several backends: keep the fastest, which is what the dispatcher would pick.
        if let Some((_, t)) = seen.iter_mut().find(|(k, _)| *k == key) {
            *t = t.max(d.throughput);
        } else {
            seen.push((key, d.throughput));
        }
    }
    if seen.is_empty() {
        return None;
    }
    Some(seen.iter().map(|(_, t)| *t).sum::<f64>() / seen.len() as f64)
}

/// Mean draw of the DISTINCT GPUs that can prove, or 0.0 if none can.
///
/// Deduplicated by PCI bus id (falling back to device id) because a card appears once per
/// backend it supports — counting `gpu0` three times for risc0/sp1/openvm would weight one
/// card triple in the mean and quietly mis-price a heterogeneous box.
///
/// 0.0 when the suite lists no GPU at all. That is correct for a genuinely CPU-only machine
/// — `cpu_power_watts` already covers the only thing doing work — but it is NOT a safe reading
/// of "no device rows were recorded", which on a GPU box would price every job as if the cards
/// were switched off. Nothing here can tell those two apart, so the suite must not arrive
/// empty: `synthetic_conservative_benchmark` gives every detected card a `FALLBACK_GPU_WATTS`
/// row precisely so an unbenchmarked card looks expensive rather than free.
fn mean_proving_card_watts(suite: &zkminer_prover::benchmark::BenchmarkSuite) -> f64 {
    let mut seen: Vec<(&str, f64)> = Vec::new();
    for d in &suite.device_benchmarks {
        if d.device_id == zkminer_prover::benchmark::CPU_DEVICE_ID {
            continue;
        }
        let key = if d.pci_bus_id.is_empty() {
            d.device_id.as_str()
        } else {
            d.pci_bus_id.as_str()
        };
        if let Some((_, w)) = seen.iter_mut().find(|(k, _)| *k == key) {
            // Same card, different backend: keep the larger reading rather than averaging
            // two samples of one card taken at different moments.
            *w = w.max(d.power_watts);
        } else {
            seen.push((key, d.power_watts));
        }
    }
    if seen.is_empty() {
        return 0.0;
    }
    seen.iter().map(|(_, w)| *w).sum::<f64>() / seen.len() as f64
}

#[cfg(test)]
mod power_tests {
    use super::{system_watts_for_suite, CostParams, DEFAULT_CPU_WATTS};
    use crate::evaluator::{evaluate_job, JobParams};
    use zkminer_prover::benchmark::{BenchmarkResult, BenchmarkSuite, DeviceBenchmark};

    fn device(id: &str, bus: &str, backend: &str, watts: f64) -> DeviceBenchmark {
        DeviceBenchmark {
            program_stages: Vec::new(),
            device_id: id.to_string(),
            device_label: id.to_string(),
            prover_backend: backend.to_string(),
            throughput: 1_000_000.0,
            power_watts: watts,
            optimal_po2: 21,
            memory_usage_bytes: 0,
            max_feasible_po2: 21,
            program_throughputs: std::collections::HashMap::new(),
            pci_bus_id: bus.to_string(),
            po2_samples: Vec::new(),
            host_peak_bytes: None,
        }
    }

    fn suite(cpu: Option<f64>, devices: Vec<DeviceBenchmark>) -> BenchmarkSuite {
        BenchmarkSuite {
            // One result so `average_throughput()` is non-zero and the evaluator can derive a
            // duration; without it every job is infeasible and the cost term never matters.
            results: vec![BenchmarkResult {
                program_name: "fibonacci".to_string(),
                prover_backend: "risc0".to_string(),
                cycles: 1_000_000,
                duration: std::time::Duration::from_secs(1),
                throughput: 1_000_000.0,
                weight: 1.0,
                precompile: false,
            }],
            device_benchmarks: devices,
            cpu_power_watts: cpu,
            ..Default::default()
        }
    }

    /// Electricity is linear in watts, so pick an absurd price per kWh and a long job: the
    /// cost term then dominates the reward and shows up in the evaluation.
    fn costly() -> CostParams {
        CostParams {
            electricity_cost_kwh: 1_000.0,
            base_overhead_watts: 75.0, // the overhead term, as config defines it
            hardware_cost_per_hour: 0.0,
            gas_cost_usd: 0.0,
        }
    }

    fn job() -> JobParams {
        JobParams {
            estimated_cycles: 3_600_000_000, // ~1h at 1e6 c/s
            time_remaining: 86_400,
            fulfillment_timeout: 86_400,
            available_collateral: u128::MAX,
            required_collateral: 0,
            throughput: 0.0,
            device_watts: None,
            ..Default::default()
        }
    }

    /// THE production-path test. The composition lives inside `evaluate_job`, so this fails if
    /// it is removed there — which is exactly what could not be detected before: every test
    /// composed the figure itself in the test body, so deleting the production call site left
    /// the whole suite green while restoring a ~9x under-cost on every claim decision.
    #[test]
    fn evaluate_job_composes_the_power_itself() {
        let cheap_card = suite(
            Some(100.0),
            vec![device("gpu0", "0000:06:10.0", "risc0", 10.0)],
        );
        let hungry_card = suite(
            Some(100.0),
            vec![device("gpu0", "0000:06:10.0", "risc0", 900.0)],
        );

        let a = evaluate_job(&cheap_card, &costly(), &job(), 0.0, 0.2);
        let b = evaluate_job(&hungry_card, &costly(), &job(), 0.0, 0.2);

        assert!(
            a.estimated_profit_hemi_per_day > b.estimated_profit_hemi_per_day,
            "a 900 W card must cost more to run than a 10 W one: {} vs {}. If these are equal, \
             the evaluator is charging `cost_params.base_overhead_watts` as the total and \
             ignoring the measured hardware entirely.",
            a.estimated_profit_hemi_per_day,
            b.estimated_profit_hemi_per_day
        );
    }

    /// And the named card must be what is charged, not the suite mean — otherwise the duration
    /// (derived from that card's throughput) and the power describe different machines.
    #[test]
    fn a_named_device_is_charged_instead_of_the_mean() {
        let s = suite(
            Some(100.0),
            vec![
                device("gpu0", "0000:06:10.0", "risc0", 10.0),
                device("gpu1", "0000:06:1b.0", "risc0", 900.0),
            ],
        );
        let mut on_hungry = job();
        on_hungry.device_watts = Some(900.0);
        on_hungry.throughput = 1_000_000.0;
        let mut on_cheap = job();
        on_cheap.device_watts = Some(10.0);
        on_cheap.throughput = 1_000_000.0;

        let hungry = evaluate_job(&s, &costly(), &on_hungry, 0.0, 0.2);
        let cheap = evaluate_job(&s, &costly(), &on_cheap, 0.0, 0.2);
        assert!(
            cheap.estimated_profit_hemi_per_day > hungry.estimated_profit_hemi_per_day,
            "naming a card must change the charge; got {} vs {}",
            cheap.estimated_profit_hemi_per_day,
            hungry.estimated_profit_hemi_per_day
        );
    }

    /// THE bug, at the unit level: the overhead term alone is not the machine's draw.
    #[test]
    fn the_overhead_alone_is_not_the_machine_power() {
        let s = suite(
            Some(200.0),
            vec![
                device("gpu0", "0000:06:10.0", "risc0", 341.5),
                device("gpu1", "0000:06:1b.0", "risc0", 455.1),
            ],
        );
        // 200 CPU + mean(341.5, 455.1) + 75
        let got = system_watts_for_suite(&s, 75.0, None);
        assert!((got - 673.3).abs() < 0.1, "got {got}");
    }

    /// A named card wins over the mean.
    #[test]
    fn a_named_card_overrides_the_mean() {
        let s = suite(
            Some(0.0),
            vec![
                device("gpu0", "0000:06:10.0", "risc0", 100.0),
                device("gpu1", "0000:06:1b.0", "risc0", 900.0),
            ],
        );
        assert!((system_watts_for_suite(&s, 0.0, Some(900.0)) - 900.0).abs() < 0.001);
        // mean(100, 900) = 500
        assert!((system_watts_for_suite(&s, 0.0, None) - 500.0).abs() < 0.001);
        // `Some(0.0)` is how a CPU-only choice says "no GPU is involved", and it must be
        // honoured: substituting the mean card there charged a CPU job for a card it never
        // touched. An unmeasured GPU cannot arrive as 0.0 — its row carries the fallback.
        assert!((system_watts_for_suite(&s, 0.0, Some(0.0)) - 0.0).abs() < 0.001);
    }

    /// One card appears once per backend it supports. Counting `gpu0` three times would weight
    /// it triple in the mean and mis-price a heterogeneous box.
    #[test]
    fn a_card_is_counted_once_across_its_backends() {
        let s = suite(
            Some(100.0),
            vec![
                device("gpu0", "0000:06:10.0", "risc0", 300.0),
                device("gpu0", "0000:06:10.0", "sp1", 300.0),
                device("gpu0", "0000:06:10.0", "openvm", 300.0),
                device("gpu1", "0000:06:1b.0", "risc0", 500.0),
            ],
        );
        // mean(300, 500) = 400, not mean(300,300,300,500) = 350.
        assert!((system_watts_for_suite(&s, 0.0, None) - 500.0).abs() < 0.001);
    }

    /// With no bus id to join on, the device id is the identity — a suite written before bus ids
    /// were recorded must still not count one card twice. The condition is live, via
    /// `build_gpu_device_benchmarks_from_workers`'s `pci_bus_id.unwrap_or_default()`: a card whose
    /// bus id the dispatcher could not determine produces exactly this row.
    #[test]
    fn a_missing_bus_id_falls_back_to_the_device_id() {
        let s = suite(
            Some(0.0),
            vec![
                device("gpu0", "", "risc0", 200.0),
                device("gpu0", "", "sp1", 200.0),
                device("gpu1", "", "risc0", 400.0),
            ],
        );
        assert!((system_watts_for_suite(&s, 0.0, None) - 300.0).abs() < 0.001);
    }

    /// CPU-only: the GPU term is 0, not a fallback. `cpu_power_watts` already covers the only
    /// thing doing work, and inventing 300 W of GPU would make every job look unprofitable.
    ///
    /// Note what this does NOT license: an empty device list on a GPU box reads the same way
    /// here, which is why the synthetic suite supplies a conservative row per detected card
    /// rather than leaving the list empty.
    #[test]
    fn a_cpu_only_suite_charges_no_gpu() {
        let s = suite(
            Some(90.0),
            vec![device(
                zkminer_prover::benchmark::CPU_DEVICE_ID,
                "",
                "risc0",
                90.0,
            )],
        );
        assert!((system_watts_for_suite(&s, 10.0, None) - 100.0).abs() < 0.001);
    }

    /// Energy is P·t, so the duration the cost is computed over must describe the same machine
    /// as the watts. When no device is named the duration came from `average_throughput()` — a
    /// flat mean over per-(slot, program) rows — while the power came from the mean of distinct
    /// CARDS. On this rig those differ by ~1.6x, so the energy term was systematically short.
    #[test]
    fn the_cost_duration_matches_the_card_whose_power_is_charged() {
        // A suite whose per-program results average much FASTER than its cards do, which is the
        // real shape: `results` carries one row per (slot, program) and the mean is dominated by
        // the quickest programs.
        let mut s = suite(
            Some(0.0),
            vec![device("gpu0", "0000:06:10.0", "risc0", 100.0)],
        );
        s.results[0].throughput = 10_000_000.0; // suite average: 10M c/s
        s.device_benchmarks[0].throughput = 1_000_000.0; // the card: 1M c/s

        let mut j = job();
        j.estimated_cycles = 10_000_000; // 1s at the suite average, 10s on the card
        j.time_remaining = 86_400;
        let params = CostParams {
            electricity_cost_kwh: 1_000.0,
            base_overhead_watts: 0.0,
            hardware_cost_per_hour: 0.0,
            gas_cost_usd: 0.0,
        };

        let eval = evaluate_job(&s, &params, &j, 0.0, 0.2);
        // 100 W for 10s (the card), not for 1s (the suite average): 100 * (10/3600) / 1000 * 1000
        // = 0.2778 USD rather than 0.0278.
        let cost = 100.0 * (10.0 / 3600.0) / 1000.0 * 1_000.0;
        let implied = eval.estimated_cost_usd;
        assert!(
            (implied - cost).abs() < cost * 0.05,
            "cost {implied} should reflect the card's 10s, not the suite average's 1s (expected \
             ~{cost})"
        );
    }

    /// And when the caller DOES name a device, the duration it already computed from that
    /// device's throughput must be left alone.
    #[test]
    fn a_named_device_keeps_its_own_duration() {
        let mut s = suite(
            Some(0.0),
            vec![device("gpu0", "0000:06:10.0", "risc0", 100.0)],
        );
        s.results[0].throughput = 10_000_000.0;
        s.device_benchmarks[0].throughput = 1_000_000.0;

        let mut j = job();
        j.estimated_cycles = 10_000_000;
        j.throughput = 5_000_000.0; // the caller names a 5M c/s device → 2s
        j.device_watts = Some(100.0);
        let params = CostParams {
            electricity_cost_kwh: 1_000.0,
            base_overhead_watts: 0.0,
            hardware_cost_per_hour: 0.0,
            gas_cost_usd: 0.0,
        };
        let eval = evaluate_job(&s, &params, &j, 0.0, 0.2);
        let cost = 100.0 * (2.0 / 3600.0) / 1000.0 * 1_000.0;
        assert!(
            (eval.estimated_cost_usd - cost).abs() < cost * 0.05,
            "a named device's own duration must be used: got {}, expected ~{cost}",
            eval.estimated_cost_usd
        );
    }

    /// An unreadable RAPL (this host: no `/dev/cpu/*/msr`, no powercap tree) must not drop the
    /// CPU term to zero.
    #[test]
    fn an_unmeasured_cpu_uses_the_documented_default() {
        let s = suite(None, vec![device("gpu0", "0000:06:10.0", "risc0", 300.0)]);
        let got = system_watts_for_suite(&s, 0.0, None);
        assert!(
            (got - (DEFAULT_CPU_WATTS + 300.0)).abs() < 0.001,
            "got {got}"
        );
    }
}

#[cfg(test)]
mod rate_tests {
    use super::{CostParams, DEFAULT_CPU_WATTS};
    use crate::evaluator::{evaluate_job, JobParams};
    use zkminer_prover::benchmark::{BenchmarkResult, BenchmarkSuite, DeviceBenchmark};

    /// `profit_hemi_per_day` is what `min_profit_threshold` gates on, so an optimistic denominator
    /// claims jobs that are not worth it. It must use the same duration the cost was computed
    /// over — the card that will run the job — not the suite average.
    #[test]
    fn the_reported_rate_uses_the_card_not_the_suite_average() {
        let suite = BenchmarkSuite {
            // The suite average is 10x the card: `results` is per (slot, program) and is dominated
            // by the quickest programs, which is the real shape on this rig.
            results: vec![BenchmarkResult {
                program_name: "fibonacci".to_string(),
                prover_backend: "risc0".to_string(),
                cycles: 1_000_000,
                duration: std::time::Duration::from_millis(100),
                throughput: 10_000_000.0,
                weight: 1.0,
                precompile: false,
            }],
            device_benchmarks: vec![DeviceBenchmark {
                program_stages: Vec::new(),
                device_id: "gpu0".to_string(),
                device_label: "gpu0".to_string(),
                prover_backend: "risc0".to_string(),
                throughput: 1_000_000.0,
                power_watts: 300.0,
                optimal_po2: 21,
                memory_usage_bytes: 0,
                max_feasible_po2: 21,
                program_throughputs: std::collections::HashMap::new(),
                pci_bus_id: "0000:06:10.0".to_string(),
                po2_samples: Vec::new(),
                host_peak_bytes: None,
            }],
            cpu_power_watts: Some(0.0),
            ..Default::default()
        };

        let params = CostParams {
            electricity_cost_kwh: 0.0, // isolate the denominator: no cost term at all
            base_overhead_watts: 0.0,
            hardware_cost_per_hour: 0.0,
            gas_cost_usd: 0.0,
        };
        let job = JobParams {
            estimated_cycles: 10_000_000, // 1s at the suite average, 10s on the card
            time_remaining: 86_400,
            fulfillment_timeout: 86_400,
            available_collateral: u128::MAX,
            required_collateral: 0,
            throughput: 0.0,
            device_watts: None,
            current_price: 1_000_000_000_000_000_000, // 1 HEMI
            bonus_amount: 0,
            speed_premium: 0,
            token_price_usd: 1.0,
            fee_rate_bps: 0,
            max_price: 1_000_000_000_000_000_000,
        };

        let eval = evaluate_job(&suite, &params, &job, 0.0, 0.2);
        // 1 HEMI over 10s on the card = 8640 HEMI/day. Over the suite average's 1s it would be
        // 86400 — ten times too good, and that is the figure `min_profit_threshold` gated on.
        let per_day = eval.estimated_profit_hemi_per_day;
        assert!(
            (per_day - 8_640.0).abs() < 8_640.0 * 0.05,
            "rate should reflect the card's 10s (~8640/day), got {per_day}; ~86400 means the \
             denominator is still the optimistic suite average"
        );
    }

    /// Sanity: the constant the CPU term falls back to is the one the doc names.
    #[test]
    fn the_cpu_fallback_is_the_documented_constant() {
        assert!((DEFAULT_CPU_WATTS - 65.0).abs() < f64::EPSILON);
    }
}
