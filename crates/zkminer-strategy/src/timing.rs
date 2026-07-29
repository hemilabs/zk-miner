//! Proving time estimation from benchmark results.

use std::time::Duration;
pub use zkminer_prover::benchmark::BenchmarkSuite;

/// Sentinel duration representing "infeasible" — 100 years.
/// Small enough to never overflow when multiplied by safety_margin,
/// large enough to always exceed any real proving deadline.
const INFEASIBLE: Duration = Duration::from_secs(100 * 365 * 24 * 3600); // ~3.15 billion seconds

/// Predict proving duration for a given cycle count based on benchmark results.
pub fn estimate_proving_time(benchmarks: &BenchmarkSuite, estimated_cycles: u64) -> Duration {
    let throughput = benchmarks.average_throughput();
    if throughput <= 0.0 || estimated_cycles == 0 {
        return INFEASIBLE;
    }

    let seconds = estimated_cycles as f64 / throughput;
    Duration::from_secs_f64(seconds)
}

/// Check if proving can finish before a deadline with safety margin.
pub fn can_finish_before_deadline(
    benchmarks: &BenchmarkSuite,
    estimated_cycles: u64,
    deadline_secs_remaining: u64,
    safety_margin: f64,
) -> (bool, Duration) {
    let estimated_duration = estimate_proving_time(benchmarks, estimated_cycles);
    if estimated_duration >= INFEASIBLE {
        return (false, estimated_duration);
    }
    let safe_duration = Duration::from_secs_f64(
        estimated_duration.as_secs_f64() * safety_margin,
    );
    let deadline = Duration::from_secs(deadline_secs_remaining);

    (safe_duration < deadline, estimated_duration)
}

/// Predict proving duration for a given cycle count at a specific throughput.
///
/// Use this when you already know the device-specific throughput (e.g. from
/// [`BenchmarkSuite::throughput_for`]).
pub fn estimate_proving_time_at_throughput(throughput: f64, estimated_cycles: u64) -> Duration {
    if throughput <= 0.0 || estimated_cycles == 0 {
        return INFEASIBLE;
    }
    Duration::from_secs_f64(estimated_cycles as f64 / throughput)
}

/// Check if proving can finish before a deadline at a specific throughput.
pub fn can_finish_at_throughput(
    throughput: f64,
    estimated_cycles: u64,
    deadline_secs_remaining: u64,
    safety_margin: f64,
) -> (bool, Duration) {
    let estimated = estimate_proving_time_at_throughput(throughput, estimated_cycles);
    if estimated >= INFEASIBLE {
        return (false, estimated);
    }
    let safe = Duration::from_secs_f64(estimated.as_secs_f64() * safety_margin);
    let deadline = Duration::from_secs(deadline_secs_remaining);
    (safe < deadline, estimated)
}

/// Predict proving duration using po2 calibration data.
///
/// When a `Po2Profile` is available, uses the measured throughput at the
/// optimal po2 for the given cycle count. Falls back to flat throughput
/// estimation when no calibration data exists.
pub fn estimate_proving_time_with_po2(
    profile: &zkminer_prover::benchmark::Po2Profile,
    estimated_cycles: u64,
) -> Duration {
    if estimated_cycles == 0 {
        return INFEASIBLE;
    }
    let optimal_po2 = profile.optimal_po2_for_job(estimated_cycles);
    let secs = profile.total_time_at_po2(estimated_cycles, optimal_po2);
    if secs <= 0.0 || secs >= INFEASIBLE.as_secs_f64() {
        return INFEASIBLE;
    }
    Duration::from_secs_f64(secs)
}
