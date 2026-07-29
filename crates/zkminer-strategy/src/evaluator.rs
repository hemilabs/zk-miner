//! Job profitability evaluation and strategy.

use crate::cost_model::{CostParams, estimate_proving_cost};
use crate::timing::{BenchmarkSuite, can_finish_at_throughput, can_finish_before_deadline};

/// Recommendation for how to handle a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recommendation {
    /// Claim the job (profitable and feasible).
    Claim,
    /// Skip (not profitable or too risky).
    Skip { reason: String },
    /// Watch the job and claim later when price is higher.
    WatchAndWait,
    /// Use atomic claimAndFulfill if proof is already available.
    AtomicFastPath,
}

/// Full evaluation of a job's profitability and feasibility.
#[derive(Debug, Clone)]
pub struct JobEvaluation {
    pub recommendation: Recommendation,
    pub estimated_reward_usd: f64,
    pub estimated_cost_usd: f64,
    pub estimated_profit_usd: f64,
    /// Net profit rate in HEMI/day (profit_hemi / proving_days).
    pub estimated_profit_hemi_per_day: f64,
    pub estimated_proving_time_secs: f64,
    pub deadline_feasible: bool,
    pub collateral_sufficient: bool,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// Parameters for evaluating a specific job.
#[derive(Debug, Clone)]
pub struct JobParams {
    /// Current auction price in token units.
    pub current_price: u128,
    /// Bonus amount accumulated.
    pub bonus_amount: u128,
    /// Speed premium available.
    pub speed_premium: u128,
    /// Fulfillment timeout in seconds.
    pub fulfillment_timeout: u64,
    /// Seconds remaining until deadline (after claim).
    pub time_remaining: u64,
    /// Estimated cycle count for this job.
    pub estimated_cycles: u64,
    /// Collateral required for this job.
    pub required_collateral: u128,
    /// Available free collateral for the prover.
    pub available_collateral: u128,
    /// Token price in USD (for reward estimation).
    pub token_price_usd: f64,
    /// Protocol fee rate in bps.
    pub fee_rate_bps: u16,
    /// Device-specific throughput in cycles/sec.
    ///
    /// When > 0 the evaluator uses this instead of the benchmark suite average.
    /// Set to 0.0 to fall back to `BenchmarkSuite::average_throughput()`.
    pub throughput: f64,
    /// Maximum auction price for this job (for WatchAndWait decisions).
    pub max_price: u128,
}

/// Default job params for testing.
#[cfg(test)]
impl Default for JobParams {
    fn default() -> Self {
        Self {
            current_price: 10_000_000_000_000_000_000, // 10 HEMI (1e19)
            bonus_amount: 0,
            speed_premium: 0,
            fulfillment_timeout: 3600,
            time_remaining: 3600, // 1 hour
            estimated_cycles: 10_000_000, // 10M cycles
            required_collateral: 1_000_000_000_000_000_000, // 1 HEMI
            available_collateral: 100_000_000_000_000_000_000, // 100 HEMI
            token_price_usd: 0.80,
            fee_rate_bps: 500, // 5%
            throughput: 0.0,
            max_price: 20_000_000_000_000_000_000, // 20 HEMI
        }
    }
}

/// Evaluate a job for profitability and feasibility.
///
/// When `job.throughput > 0.0`, the evaluator uses that device-specific throughput
/// instead of the benchmark suite's average.  This lets callers evaluate the same
/// job on different devices (CPU vs GPU) and pick the best one.
pub fn evaluate_job(
    benchmarks: &BenchmarkSuite,
    cost_params: &CostParams,
    job: &JobParams,
    min_profit_threshold: f64,
    safety_margin: f64,
) -> JobEvaluation {
    // Check collateral sufficiency
    let collateral_sufficient = job.available_collateral >= job.required_collateral;

    // Check deadline feasibility — use device-specific throughput when available
    let (deadline_feasible, estimated_duration) = if job.throughput > 0.0 {
        can_finish_at_throughput(
            job.throughput,
            job.estimated_cycles,
            job.time_remaining,
            safety_margin,
        )
    } else {
        can_finish_before_deadline(
            benchmarks,
            job.estimated_cycles,
            job.time_remaining,
            safety_margin,
        )
    };

    // Estimate proving cost
    let cost_usd = estimate_proving_cost(cost_params, estimated_duration);

    // Estimate reward
    let gross_reward = job.current_price + job.bonus_amount;
    let speed_bonus = if job.speed_premium > 0 && job.fulfillment_timeout > 0 {
        // Estimate speed bonus based on estimated proving time
        let time_left_after_proving = job.time_remaining.saturating_sub(
            estimated_duration.as_secs()
        );
        // Use checked_mul to prevent u128 overflow
        job.speed_premium
            .checked_mul(time_left_after_proving as u128)
            .map(|v| v / job.fulfillment_timeout as u128)
            .unwrap_or(0)
    } else {
        0
    };

    let total_gross = gross_reward + speed_bonus;
    // Protocol fee is on current_price only (matching Solidity contract)
    let protocol_fee = job.current_price * job.fee_rate_bps as u128 / 10000;
    let net_reward_tokens = total_gross - protocol_fee;

    // Convert to USD
    let reward_usd = net_reward_tokens as f64 * job.token_price_usd / 1e18;
    let profit_usd = reward_usd - cost_usd;

    // Compute profit rate in HEMI/day:
    // profit_hemi = net_reward_hemi - cost_in_hemi
    // A proof taking T hours must net at least (threshold × T/24) HEMI.
    let net_reward_hemi = net_reward_tokens as f64 / 1e18;
    let cost_hemi = if job.token_price_usd > 0.0 {
        cost_usd / job.token_price_usd
    } else {
        0.0
    };
    let profit_hemi = net_reward_hemi - cost_hemi;
    let proving_days = estimated_duration.as_secs_f64() / 86400.0;
    let profit_hemi_per_day = if proving_days > 0.0 {
        profit_hemi / proving_days
    } else {
        0.0
    };

    // Risk assessment — guard against time_remaining == 0 (would divide-by-zero
    // and produce NaN/Inf). A job with zero time remaining is always High risk.
    let time_ratio = if job.time_remaining > 0 {
        estimated_duration.as_secs_f64() / job.time_remaining as f64
    } else {
        f64::INFINITY
    };
    let risk_level = if time_ratio < 0.3 {
        RiskLevel::Low
    } else if time_ratio < 0.6 {
        RiskLevel::Medium
    } else {
        RiskLevel::High
    };

    // Decision — min_profit_threshold is in HEMI/day
    //
    // Simulated benchmarks produce fictional throughput numbers that do not
    // reflect real proving performance. Never auto-claim based on simulated data.
    let recommendation = if benchmarks.is_simulated() && job.throughput <= 0.0 {
        Recommendation::Skip {
            reason: "Benchmarks are simulated — cannot reliably estimate proving time".to_string(),
        }
    } else if !collateral_sufficient {
        Recommendation::Skip {
            reason: "Insufficient collateral".to_string(),
        }
    } else if !deadline_feasible {
        Recommendation::Skip {
            reason: "Cannot finish before deadline".to_string(),
        }
    } else if risk_level == RiskLevel::High {
        Recommendation::Skip {
            reason: "Risk level too high".to_string(),
        }
    } else if profit_hemi_per_day < min_profit_threshold {
        if job.current_price < job.max_price {
            Recommendation::WatchAndWait
        } else {
            Recommendation::Skip {
                reason: format!(
                    "Profit rate {:.1} HEMI/day below threshold {:.1} HEMI/day",
                    profit_hemi_per_day, min_profit_threshold
                ),
            }
        }
    } else {
        Recommendation::Claim
    };

    JobEvaluation {
        recommendation,
        estimated_reward_usd: reward_usd,
        estimated_cost_usd: cost_usd,
        estimated_profit_usd: profit_usd,
        estimated_profit_hemi_per_day: profit_hemi_per_day,
        estimated_proving_time_secs: estimated_duration.as_secs_f64(),
        deadline_feasible,
        collateral_sufficient,
        risk_level,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use zkminer_prover::benchmark::{BenchmarkResult, BenchmarkSuite};

    fn make_result(backend: &str, throughput: f64) -> BenchmarkResult {
        BenchmarkResult {
            program_name: "test".to_string(),
            prover_backend: backend.to_string(),
            cycles: 1_000_000,
            duration: Duration::from_secs_f64(1_000_000.0 / throughput),
            throughput,
            weight: 0.20,
            precompile: false,
        }
    }

    fn simulated_suite() -> BenchmarkSuite {
        BenchmarkSuite {
            results: vec![
                make_result("simulated", 500_000.0),
                make_result("simulated", 300_000.0),
            ],
            ..Default::default()
        }
    }

    fn real_suite(throughput: f64) -> BenchmarkSuite {
        BenchmarkSuite {
            results: vec![
                make_result("risc0", throughput),
                make_result("risc0", throughput),
            ],
            ..Default::default()
        }
    }

    // ---- Simulated benchmark guard ----

    #[test]
    fn skips_on_simulated_benchmarks() {
        let suite = simulated_suite();
        let cost = CostParams::default();
        let job = JobParams {
            throughput: 0.0,
            ..Default::default()
        };

        let eval = evaluate_job(&suite, &cost, &job, 10.0, 1.5);
        assert!(
            matches!(&eval.recommendation, Recommendation::Skip { reason } if reason.contains("simulated")),
            "expected Skip(simulated), got {:?}", eval.recommendation
        );
    }

    #[test]
    fn allows_simulated_when_device_throughput_set() {
        let suite = simulated_suite();
        let cost = CostParams::default();
        let job = JobParams {
            throughput: 1_000_000.0,
            ..Default::default()
        };

        let eval = evaluate_job(&suite, &cost, &job, 10.0, 1.5);
        if let Recommendation::Skip { ref reason } = eval.recommendation {
            assert!(
                !reason.contains("simulated"),
                "should not skip for simulated when device throughput is set: {reason}"
            );
        }
    }

    // ---- Core evaluation ----

    #[test]
    fn claims_profitable_job() {
        let suite = real_suite(10_000_000.0);
        let cost = CostParams::default();
        let job = JobParams {
            throughput: 10_000_000.0,
            estimated_cycles: 10_000_000,
            time_remaining: 3600,
            current_price: 50_000_000_000_000_000_000, // 50 HEMI
            ..Default::default()
        };

        let eval = evaluate_job(&suite, &cost, &job, 0.1, 1.5);
        assert_eq!(eval.recommendation, Recommendation::Claim);
        assert!(eval.deadline_feasible);
        assert!(eval.collateral_sufficient);
        assert_eq!(eval.risk_level, RiskLevel::Low);
    }

    #[test]
    fn skips_insufficient_collateral() {
        let suite = real_suite(10_000_000.0);
        let cost = CostParams::default();
        let job = JobParams {
            throughput: 10_000_000.0,
            required_collateral: 1000_000_000_000_000_000_000,
            available_collateral: 1_000_000_000_000_000_000,
            ..Default::default()
        };

        let eval = evaluate_job(&suite, &cost, &job, 10.0, 1.5);
        assert!(
            matches!(&eval.recommendation, Recommendation::Skip { reason } if reason.contains("collateral")),
            "expected Skip(collateral), got {:?}", eval.recommendation
        );
        assert!(!eval.collateral_sufficient);
    }

    #[test]
    fn skips_infeasible_deadline() {
        let suite = real_suite(100.0);
        let cost = CostParams::default();
        let job = JobParams {
            throughput: 100.0,
            estimated_cycles: 1_000_000_000,
            time_remaining: 60,
            ..Default::default()
        };

        let eval = evaluate_job(&suite, &cost, &job, 10.0, 1.5);
        assert!(!eval.deadline_feasible);
    }

    #[test]
    fn watch_and_wait_when_price_can_rise() {
        // Very low current price but high max price = WatchAndWait
        // Use slow throughput so proving cost is high relative to reward
        let suite = real_suite(100_000.0);
        let cost = CostParams::default();
        let job = JobParams {
            throughput: 100_000.0,                          // 100K c/s = 100s proving
            estimated_cycles: 10_000_000,
            current_price: 10_000_000_000_000_000,          // 0.01 HEMI (very cheap)
            max_price: 50_000_000_000_000_000_000,          // 50 HEMI (room to grow)
            time_remaining: 3600,
            ..Default::default()
        };

        let eval = evaluate_job(&suite, &cost, &job, 100.0, 1.5);
        assert_eq!(eval.recommendation, Recommendation::WatchAndWait,
            "expected WatchAndWait, got {:?} (profit_hemi_per_day={:.2})",
            eval.recommendation, eval.estimated_profit_hemi_per_day);
    }

    #[test]
    fn skips_unprofitable_at_max_price() {
        let suite = real_suite(100_000.0);
        let cost = CostParams::default();
        let job = JobParams {
            throughput: 100_000.0,
            estimated_cycles: 10_000_000,
            current_price: 10_000_000_000_000_000,          // 0.01 HEMI
            max_price: 10_000_000_000_000_000,              // already at max
            time_remaining: 3600,
            ..Default::default()
        };

        let eval = evaluate_job(&suite, &cost, &job, 100.0, 1.5);
        assert!(
            matches!(&eval.recommendation, Recommendation::Skip { reason } if reason.contains("Profit rate")),
            "expected Skip(profit), got {:?}", eval.recommendation
        );
    }

    #[test]
    fn empty_benchmarks_not_simulated() {
        let suite = BenchmarkSuite::default();
        assert!(!suite.is_simulated());
    }
}
