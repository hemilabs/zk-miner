//! How far a proof is, from the stages its worker reports (`ProveStage`) weighed by what the host
//! knows of the job and the card: the job's measured cycles over the card's benchmarked STARK rate,
//! and the card's measured wrap time. No stage has a fixed share of the bar: a 30M-cycle SP1 proof
//! spends over half its time in the Groth16 wrap, a 1.5B-cycle risc0 proof well under 1%.

use std::time::Instant;

use zkminer_prover::benchmark::DeviceBenchmark;
use zkminer_prover_protocol::{ProveStage, StageReport, BACKEND_RISC0, BACKEND_SP1};

/// What the host knows of one proof attempt. A retry starts a new one.
#[derive(Debug, Clone)]
pub struct AttemptProgress {
    pub started: Instant,
    /// The slot proving it, e.g. `risc0:cuda:1`.
    pub slot: String,
    /// The worker's latest stage report; `None` before the first.
    pub report: Option<StageReport>,
    /// When `report`'s stage began (the attempt's start before the first report).
    pub stage_started: Instant,
    /// The highest fraction shown for this attempt, so the bar never moves back.
    pub floor: f64,
    /// How long the `Prove` stage took, once it has ended.
    pub prove_secs: Option<f64>,
}

impl AttemptProgress {
    pub fn new(slot: &str, now: Instant) -> Self {
        Self {
            started: now,
            slot: slot.to_string(),
            report: None,
            stage_started: now,
            floor: 0.0,
            prove_secs: None,
        }
    }

    /// Takes a stage report; a new stage restarts the stage clock.
    pub fn record(&mut self, report: StageReport, now: Instant) {
        if self.report.map(|r| r.stage) != Some(report.stage) {
            if self.stage() == Some(ProveStage::Prove) {
                self.prove_secs = Some(
                    now.saturating_duration_since(self.stage_started)
                        .as_secs_f64(),
                );
            }
            self.stage_started = now;
        }
        self.report = Some(report);
    }

    pub fn stage(&self) -> Option<ProveStage> {
        self.report.map(|r| r.stage)
    }
}

/// Expected seconds of each stage of one job on one card.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StageSecs {
    pub setup: f64,
    pub execute: f64,
    /// `None` without a measurement of the job: then only the stage's own observed rate tells.
    pub prove: Option<f64>,
    /// The wrap: the card's measured time, whatever the job's size.
    pub finish: f64,
    /// The part of the finish that grows with the STARK (risc0's lift/join tail), as a share of the
    /// `Prove` stage's time: the time it actually took, or will take at its observed rate, so a card
    /// faster or slower than its benchmark shortens or stretches it too.
    pub finish_share_of_prove: f64,
}

impl StageSecs {
    /// `prove` is the `Prove` stage's time as best known (see `attempt_fraction`).
    fn of(&self, stage: ProveStage, prove: f64) -> f64 {
        match stage {
            ProveStage::Setup => self.setup,
            ProveStage::Execute => self.execute,
            ProveStage::Prove => prove,
            ProveStage::Finish => self.finish + self.finish_share_of_prove * prove,
        }
    }
}

/// SP1's start of a proof before its first shard: the proving key for a program it has not set up,
/// the server's first tasks. Not in the benchmark (its timing leaves setup out); measured ~9 s on an
/// RTX 4070 for a program it had not seen.
const SP1_SETUP_SECS: f64 = 10.0;

/// risc0's lift/join and keccak tail after the last segment, as a share of the segments' time: no
/// hook reports it, and the benchmark folds it into its STARK time (measured ~7% on an RTX 4070).
const RISC0_TAIL_SHARE: f64 = 0.08;

/// Wrap seconds for a card whose benchmark has none: the slowest measured (RTX 4070).
fn default_wrap_secs(backend: &str) -> f64 {
    if backend == BACKEND_SP1 {
        17.0
    } else {
        2.6
    }
}

/// The expected seconds of each stage of a job of `cycles` on the card of `row`. `execute_secs` is
/// how long measuring the job took (risc0 executes it again before proving). Without `cycles` (a lock
/// recovered from a breadcrumb that did not record them) the `Prove` stage's time is left to its
/// observed rate. `None` when the row has no STARK rate.
pub fn expected_stage_secs(
    backend: &str,
    cycles: Option<u64>,
    execute_secs: Option<f64>,
    row: &DeviceBenchmark,
) -> Option<StageSecs> {
    let rate = row.stark_rate().filter(|r| r.is_finite() && *r > 0.0)?;
    let wrap = row
        .wrap_secs()
        .filter(|w| w.is_finite() && *w >= 0.0)
        .unwrap_or_else(|| default_wrap_secs(backend));
    let prove = cycles.map(|c| c as f64 / rate);
    Some(if backend == BACKEND_RISC0 {
        StageSecs {
            setup: 0.0,
            execute: execute_secs.unwrap_or(0.0).max(0.0),
            prove,
            finish: wrap,
            finish_share_of_prove: RISC0_TAIL_SHARE,
        }
    } else {
        StageSecs {
            setup: SP1_SETUP_SECS,
            execute: 0.0,
            prove,
            finish: wrap,
            finish_share_of_prove: 0.0,
        }
    })
}

/// Units done in a counted stage before its own rate is trusted over the benchmark's.
const MIN_UNITS_FOR_RATE: u32 = 3;

/// How far the attempt is at `now`, in [0, 0.99]: elapsed over elapsed plus what remains, which is
/// the current stage's remainder (from its own observed rate once it has counted a few units, else
/// its expected time less what it has run) plus every later stage's expected time. A card faster or
/// slower than its benchmark moves the estimate with it. Never below `p.floor`; never 1.0 until the
/// proof is in. `None` while the `Prove` stage's time is unknown: no measured cycles, and too few
/// units counted (or their total not yet final) to go by its own rate.
pub fn attempt_fraction(p: &AttemptProgress, exp: &StageSecs, now: Instant) -> Option<f64> {
    let stage = p.stage().unwrap_or(ProveStage::Setup);
    let in_stage = now.saturating_duration_since(p.stage_started).as_secs_f64();
    // The `Prove` stage's time as best known: what it took once it has ended; while it runs, its
    // total at the rate observed so far once a few units are done; else the benchmark's.
    let observed = match p.report {
        Some(r)
            if r.stage == ProveStage::Prove
                && r.total_final
                && r.total > 0
                && r.done >= MIN_UNITS_FOR_RATE.min(r.total) =>
        {
            let per_unit = in_stage / f64::from(r.done.min(r.total));
            Some((
                per_unit * f64::from(r.total),
                per_unit * f64::from(r.total - r.done.min(r.total)),
            ))
        }
        _ => None,
    };
    let prove = p
        .prove_secs
        .or(observed.map(|(total, _)| total))
        .or(exp.prove)?;
    let expected = exp.of(stage, prove);
    let remaining_here = match p.report {
        Some(_) if observed.is_some() => observed.map(|(_, left)| left).unwrap_or(0.0),
        // Not final (SP1 still executing): what the counts say so far, at most the benchmark's.
        Some(r) if r.stage == ProveStage::Prove && r.total > 0 => {
            let share_left = 1.0 - f64::from(r.done.min(r.total)) / f64::from(r.total);
            (expected - in_stage).max(expected * share_left * 0.5)
        }
        _ => expected - in_stage,
    };
    // A stage running past its expected time still has some left; a small floor keeps the bar moving
    // toward, but short of, the next stage.
    let remaining_here = remaining_here.max(0.05 * expected).max(0.2);
    let later: f64 = [
        ProveStage::Setup,
        ProveStage::Execute,
        ProveStage::Prove,
        ProveStage::Finish,
    ]
    .into_iter()
    .filter(|s| *s > stage)
    .map(|s| exp.of(s, prove))
    .sum();
    let elapsed = now.saturating_duration_since(p.started).as_secs_f64();
    let total = elapsed + remaining_here + later;
    let f = if total > 0.0 { elapsed / total } else { 0.0 };
    Some(f.clamp(0.0, 0.99).max(p.floor))
}

/// A short label for the stage, with its counts.
pub fn stage_label(backend: &str, report: Option<StageReport>) -> String {
    match report {
        None if backend == BACKEND_SP1 => "starting".to_string(),
        None => "starting".to_string(),
        Some(r) => match r.stage {
            ProveStage::Setup => "setting up".to_string(),
            ProveStage::Execute => "executing".to_string(),
            ProveStage::Prove => {
                let unit = if backend == BACKEND_SP1 {
                    "shard"
                } else {
                    "segment"
                };
                if r.total == 0 {
                    format!("proving {unit}s")
                } else if r.total_final {
                    format!("{unit} {}/{}", r.done.min(r.total), r.total)
                } else {
                    format!("{unit} {}/{}+", r.done.min(r.total), r.total)
                }
            }
            ProveStage::Finish => "wrapping".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn row(stark_cycles: u64, stark_secs: f64, wrap_secs: Option<f64>) -> DeviceBenchmark {
        DeviceBenchmark {
            program_stages: vec![zkminer_prover::benchmark::ProgramStage {
                program_name: "sha256-chain".to_string(),
                cycles: stark_cycles,
                stark_secs,
                wrap_secs,
            }],
            device_id: "gpu1".to_string(),
            device_label: "GPU1".to_string(),
            prover_backend: "sp1".to_string(),
            throughput: 1.0,
            power_watts: 0.0,
            optimal_po2: 20,
            memory_usage_bytes: 0,
            max_feasible_po2: 20,
            program_throughputs: Default::default(),
            po2_samples: Vec::new(),
            pci_bus_id: String::new(),
            host_peak_bytes: None,
            benchmark_po2: None,
            highest_proved_po2: None,
        }
    }

    fn report(stage: ProveStage, done: u32, total: u32, total_final: bool) -> StageReport {
        StageReport {
            stage,
            done,
            total,
            total_final,
        }
    }

    /// The wrap's share follows the job's size: most of a small SP1 proof, little of a large one.
    #[test]
    fn the_wrap_share_follows_the_job_size() {
        let r = row(100_000_000, 10.0, Some(16.0)); // 10M cycles/s, 16 s wrap
        let small = expected_stage_secs(BACKEND_SP1, Some(30_000_000), None, &r).unwrap();
        let large = expected_stage_secs(BACKEND_SP1, Some(1_500_000_000), None, &r).unwrap();
        let share = |s: &StageSecs| {
            let finish = s.finish + s.finish_share_of_prove * s.prove.unwrap();
            finish / (s.setup + s.execute + s.prove.unwrap() + finish)
        };
        assert!((small.prove.unwrap() - 3.0).abs() < 1e-9);
        assert!(share(&small) > 0.5, "{}", share(&small));
        assert!(share(&large) < 0.11, "{}", share(&large));
    }

    #[test]
    fn a_row_without_a_stark_rate_gives_no_estimate() {
        let mut r = row(100, 1.0, None);
        r.program_stages.clear();
        assert!(expected_stage_secs(BACKEND_RISC0, Some(1_000), None, &r).is_none());
    }

    /// Midway through the segments the fraction is the elapsed share of the expected total, and it
    /// follows the observed rate: faster segments, further along.
    #[test]
    fn the_fraction_follows_the_stages_and_the_observed_rate() {
        let exp = StageSecs {
            setup: 0.0,
            execute: 10.0,
            prove: Some(80.0),
            finish: 10.0,
            finish_share_of_prove: 0.0,
        };
        let t0 = Instant::now();
        let mut p = AttemptProgress::new("risc0:cuda:0", t0);
        p.record(report(ProveStage::Execute, 0, 0, false), t0);
        // Half the execution: 5 of 100 expected seconds.
        let f = attempt_fraction(&p, &exp, t0 + Duration::from_secs(5)).unwrap();
        assert!((f - 0.05).abs() < 0.01, "{f}");
        // Segments start at 10 s; at 50 s, half of them done at the expected rate: 50 of 100 s.
        p.record(
            report(ProveStage::Prove, 0, 100, true),
            t0 + Duration::from_secs(10),
        );
        p.record(
            report(ProveStage::Prove, 50, 100, true),
            t0 + Duration::from_secs(50),
        );
        let on_rate = attempt_fraction(&p, &exp, t0 + Duration::from_secs(50)).unwrap();
        assert!((on_rate - 0.5).abs() < 0.01, "{on_rate}");
        // Twice as fast: 50 done after 20 s, 20 s left, then the finish: 30 / 60.
        let mut q = AttemptProgress::new("risc0:cuda:0", t0);
        q.record(
            report(ProveStage::Prove, 0, 100, true),
            t0 + Duration::from_secs(10),
        );
        q.record(
            report(ProveStage::Prove, 50, 100, true),
            t0 + Duration::from_secs(30),
        );
        let fast = attempt_fraction(&q, &exp, t0 + Duration::from_secs(30)).unwrap();
        assert!((fast - 0.5).abs() < 0.01, "{fast}");
        // In the finish, past its expected time: close to, never at, the end.
        p.record(
            report(ProveStage::Finish, 0, 0, false),
            t0 + Duration::from_secs(90),
        );
        let late = attempt_fraction(&p, &exp, t0 + Duration::from_secs(150)).unwrap();
        assert!(late > 0.95 && late <= 0.99, "{late}");
    }

    /// risc0's tail scales with the segments' observed time: a card three times faster than the
    /// benchmark row it was sized on finishes its tail three times sooner too.
    #[test]
    fn the_tail_follows_the_observed_segment_time() {
        let exp = StageSecs {
            setup: 0.0,
            execute: 0.0,
            prove: Some(90.0),
            finish: 0.0,
            finish_share_of_prove: 0.1,
        };
        let t0 = Instant::now();
        let mut p = AttemptProgress::new("risc0:cuda:0", t0);
        p.record(report(ProveStage::Prove, 0, 90, true), t0);
        p.record(
            report(ProveStage::Prove, 90, 90, true),
            t0 + Duration::from_secs(30),
        );
        p.record(
            report(ProveStage::Finish, 0, 0, true),
            t0 + Duration::from_secs(30),
        );
        assert_eq!(p.prove_secs, Some(30.0));
        // 30 s of segments, a 3 s tail: at 31.5 s, half the tail is left of 33 s.
        let f = attempt_fraction(&p, &exp, t0 + Duration::from_millis(31_500)).unwrap();
        assert!((f - 31.5 / 33.0).abs() < 0.01, "{f}");
    }

    #[test]
    fn the_fraction_never_falls_below_what_was_shown() {
        let exp = StageSecs {
            setup: 10.0,
            execute: 0.0,
            prove: Some(10.0),
            finish: 10.0,
            finish_share_of_prove: 0.0,
        };
        let t0 = Instant::now();
        let mut p = AttemptProgress::new("sp1:cuda:0", t0);
        p.floor = 0.6;
        assert_eq!(attempt_fraction(&p, &exp, t0), Some(0.6));
    }

    /// A lock recovered without its measurement has no bar until its own segments give a rate,
    /// then it goes by that rate.
    #[test]
    fn without_cycles_the_bar_waits_for_the_observed_rate() {
        let exp = StageSecs {
            setup: 0.0,
            execute: 0.0,
            prove: None,
            finish: 10.0,
            finish_share_of_prove: 0.0,
        };
        let t0 = Instant::now();
        let mut p = AttemptProgress::new("risc0:cuda:0", t0);
        assert_eq!(
            attempt_fraction(&p, &exp, t0 + Duration::from_secs(1)),
            None
        );
        p.record(report(ProveStage::Prove, 0, 100, true), t0);
        p.record(
            report(ProveStage::Prove, 1, 100, true),
            t0 + Duration::from_secs(1),
        );
        assert_eq!(
            attempt_fraction(&p, &exp, t0 + Duration::from_secs(1)),
            None
        );
        // 50 of 100 segments in 45 s: 45 s left, then the 10 s finish: 45 / 100.
        p.record(
            report(ProveStage::Prove, 50, 100, true),
            t0 + Duration::from_secs(45),
        );
        let f = attempt_fraction(&p, &exp, t0 + Duration::from_secs(45)).unwrap();
        assert!((f - 0.45).abs() < 0.01, "{f}");
        // SP1 still executing: its shard total is not final, so no rate to go by yet.
        let mut q = AttemptProgress::new("sp1:cuda:0", t0);
        q.record(report(ProveStage::Prove, 0, 40, false), t0);
        q.record(
            report(ProveStage::Prove, 20, 40, false),
            t0 + Duration::from_secs(20),
        );
        assert_eq!(
            attempt_fraction(&q, &exp, t0 + Duration::from_secs(20)),
            None
        );
    }

    #[test]
    fn labels_name_the_stage_and_its_counts() {
        assert_eq!(
            stage_label(BACKEND_RISC0, Some(report(ProveStage::Prove, 40, 91, true))),
            "segment 40/91"
        );
        assert_eq!(
            stage_label(BACKEND_SP1, Some(report(ProveStage::Prove, 12, 40, false))),
            "shard 12/40+"
        );
        assert_eq!(
            stage_label(BACKEND_SP1, Some(report(ProveStage::Finish, 0, 0, false))),
            "wrapping"
        );
    }
}
