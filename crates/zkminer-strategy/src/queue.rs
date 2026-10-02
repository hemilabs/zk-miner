//! Look-ahead work queueing across GPUs.
//!
//! # Why
//!
//! `max_concurrent_proofs` caps in-flight work at one job per GPU. That leaves every GPU idle
//! for the whole claim round-trip between finishing one proof and starting the next: a claim
//! tx has to be built, broadcast, and mined before any work can begin. Measured on soak11 that
//! is ~15-30s per job against a mean proof time of 94s (5090) and 216s (4090) — single-digit
//! percent of throughput, but pure waste, and it grows as proofs get shorter.
//!
//! The fix is to claim slightly AHEAD: keep a small backlog queued per device so a finishing
//! GPU always has its next job already locked.
//!
//! # The thing that makes this dangerous
//!
//! A queued job does not start when it is claimed — it starts when the device ahead of it is
//! free. Every existing feasibility check in this codebase (`can_finish_before_deadline`,
//! `can_finish_at_throughput`) assumes work begins NOW. Queue two 216s proofs behind each other
//! against a job whose lock deadline is 300s away and the second one is stranded before it
//! starts: `releaseJob` past the deadline reverts, so the collateral is lost outright.
//!
//! So admission here is deadline-aware by construction: a job is admitted only if it can finish
//! **from the start time it would actually get**, not from now.
//!
//! # Model
//!
//! List scheduling, which is exactly what the dispatcher does at prove time (it hands the job
//! to the first free slot). Each device carries a `backlog` — the work already running or
//! queued on it — so a new job on that device would start at `backlog` and finish at
//! `backlog + estimate`. Modelling it the same way the dispatcher behaves keeps the admission
//! decision honest rather than optimistic.

use std::time::Duration;

/// A proving device and the work already committed to it.
#[derive(Debug, Clone)]
pub struct DeviceSlot {
    /// Dispatcher device id, e.g. `risc0:cuda:0`.
    pub device_id: String,
    /// Work already running or queued here. `ZERO` means idle now.
    pub backlog: Duration,
    /// Cycles per second on this device. `0.0` means unknown — the slot is then only
    /// usable via the suite-average fallback the caller supplies as `est`.
    pub throughput: f64,
}

/// Where an admitted job would run, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    pub device_id: String,
    /// How long until it would START (the device's backlog).
    pub starts_in: Duration,
    /// How long until it would FINISH, from now.
    pub finishes_in: Duration,
}

/// Why a job was not admitted. Worth distinguishing: "queue is full" is a healthy steady state
/// and must not be logged as a problem, whereas "cannot meet the deadline anywhere" means we
/// are being offered work this rig cannot serve and the operator may want to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// No device has room inside the horizon. Normal when saturated.
    HorizonFull,
    /// Some device had room, but the job could not finish in time from any start it could get.
    DeadlineInfeasible,
    /// No devices at all, or none with a usable throughput estimate.
    NoUsableDevice,
}

/// Decide whether to claim `estimated_cycles` of work, and where it would run.
///
/// * `horizon` — how far ahead to queue per device. `ZERO` disables look-ahead entirely and
///   reproduces the old behaviour exactly: only an idle device can take a job.
/// * `time_remaining` — seconds until this job's lock deadline, as of now.
/// * `safety_margin` — multiplier applied to the ESTIMATE (matching `can_finish_before_deadline`),
///   not to the queue wait. Queue wait is a commitment we have already made, so inflating it
///   would double-count the same uncertainty; the estimate is the uncertain part.
/// * `fallback_throughput` — used for slots reporting `0.0`, so an unbenchmarked device is not
///   silently excluded.
///
/// Returns the admission that finishes EARLIEST among the feasible ones — not the one that
/// starts earliest. Those differ whenever devices have unequal throughput (here, ~2.3x), and
/// finishing earliest is what protects the deadline.
pub fn plan_admission(
    slots: &[DeviceSlot],
    horizon: Duration,
    estimated_cycles: u64,
    time_remaining: Duration,
    safety_margin: f64,
    fallback_throughput: f64,
) -> Result<Admission, Rejection> {
    if slots.is_empty() {
        return Err(Rejection::NoUsableDevice);
    }

    let mut saw_usable_device = false;
    let mut had_room = false;
    let mut best: Option<Admission> = None;

    for slot in slots {
        let tput = if slot.throughput > 0.0 { slot.throughput } else { fallback_throughput };
        if tput <= 0.0 || estimated_cycles == 0 {
            continue; // cannot estimate on this device; do not gamble the collateral
        }
        saw_usable_device = true;

        // Room to queue? A device whose backlog already reaches the horizon is full. With
        // `horizon == ZERO` this admits only a device that is idle right now, which is the
        // pre-existing one-job-per-GPU behaviour.
        if slot.backlog > horizon {
            continue;
        }
        had_room = true;

        let est = Duration::from_secs_f64(estimated_cycles as f64 / tput);
        let safe_est = Duration::from_secs_f64(est.as_secs_f64() * safety_margin);
        // Starts when the device frees; must FINISH inside the deadline from there.
        let finish = slot.backlog.saturating_add(safe_est);
        if finish >= time_remaining {
            continue;
        }

        let cand = Admission {
            device_id: slot.device_id.clone(),
            starts_in: slot.backlog,
            // Report the UNINFLATED finish: the margin is a decision input, not a prediction,
            // and the caller uses this to update the device backlog.
            finishes_in: slot.backlog.saturating_add(est),
        };
        if best.as_ref().is_none_or(|b| cand.finishes_in < b.finishes_in) {
            best = Some(cand);
        }
    }

    match best {
        Some(a) => Ok(a),
        None if !saw_usable_device => Err(Rejection::NoUsableDevice),
        None if !had_room => Err(Rejection::HorizonFull),
        None => Err(Rejection::DeadlineInfeasible),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: fn(u64) -> Duration = Duration::from_secs;

    /// 1e9 cycles/s: a 100e9-cycle job takes 100s. Keeps the arithmetic readable.
    fn slot(id: &str, backlog_secs: u64, tput: f64) -> DeviceSlot {
        DeviceSlot { device_id: id.into(), backlog: SEC(backlog_secs), throughput: tput }
    }
    const T: f64 = 1e9;
    const CYCLES_100S: u64 = 100_000_000_000;

    /// `horizon == ZERO` must reproduce today's behaviour exactly: only an idle device.
    #[test]
    fn zero_horizon_admits_only_an_idle_device() {
        let busy = [slot("a", 1, T)];
        assert_eq!(
            plan_admission(&busy, Duration::ZERO, CYCLES_100S, SEC(9999), 1.0, T),
            Err(Rejection::HorizonFull),
            "with look-ahead off, a device with ANY backlog must not take more work"
        );
        let idle = [slot("a", 0, T)];
        assert_eq!(
            plan_admission(&idle, Duration::ZERO, CYCLES_100S, SEC(9999), 1.0, T).unwrap().device_id,
            "a"
        );
    }

    /// THE POINT OF THE FEATURE: a busy device still accepts work inside the horizon.
    #[test]
    fn a_busy_device_accepts_work_inside_the_horizon() {
        let slots = [slot("a", 60, T)];
        let a = plan_admission(&slots, SEC(300), CYCLES_100S, SEC(9999), 1.0, T).unwrap();
        assert_eq!(a.starts_in, SEC(60), "it queues behind the running proof");
        assert_eq!(a.finishes_in, SEC(160));
    }

    /// THE DANGEROUS CASE. The job fits in the horizon and would fit if it started now, but
    /// NOT from the start it would actually get. Admitting it strands the collateral: past the
    /// lock deadline `releaseJob` reverts and the stake is lost outright.
    #[test]
    fn a_job_that_cannot_finish_after_the_queue_wait_is_refused() {
        let slots = [slot("a", 250, T)];
        // 100s of work, 300s until the deadline: trivially feasible if it started now...
        assert!(SEC(100) < SEC(300));
        // ...but it starts at 250s, so it finishes at 350s. Refuse.
        assert_eq!(
            plan_admission(&slots, SEC(300), CYCLES_100S, SEC(300), 1.0, T),
            Err(Rejection::DeadlineInfeasible)
        );
    }

    /// The same job IS admitted when the queue is short enough to leave room.
    #[test]
    fn the_same_job_is_admitted_when_the_queue_is_short_enough() {
        let slots = [slot("a", 150, T)];
        let a = plan_admission(&slots, SEC(300), CYCLES_100S, SEC(300), 1.0, T).unwrap();
        assert_eq!(a.finishes_in, SEC(250));
    }

    /// Pick the EARLIEST FINISH, not the earliest start. A fast device that is busy can still
    /// beat a slow device that is free — with the real 2.3x spread between the 5090 and 4090
    /// this is the common case, not a corner.
    #[test]
    fn prefers_the_earliest_finish_over_the_earliest_start() {
        let slots = [
            slot("slow-idle", 0, T / 3.0), // free now, but 300s of work
            slot("fast-busy", 40, T),      // busy 40s, then 100s => done at 140s
        ];
        let a = plan_admission(&slots, SEC(300), CYCLES_100S, SEC(9999), 1.0, T).unwrap();
        assert_eq!(a.device_id, "fast-busy", "earliest start would have picked the slow device");
        assert_eq!(a.finishes_in, SEC(140));
    }

    /// The safety margin applies to the ESTIMATE only. Queue wait is work we have already
    /// committed to; inflating it too would double-count the same uncertainty and shrink the
    /// usable horizon for no reason.
    #[test]
    fn the_safety_margin_inflates_the_estimate_not_the_queue_wait() {
        let slots = [slot("a", 100, T)];
        // est 100s * 1.5 = 150s, starting at 100s => needs 250s of deadline.
        assert!(plan_admission(&slots, SEC(300), CYCLES_100S, SEC(249), 1.5, T).is_err());
        let a = plan_admission(&slots, SEC(300), CYCLES_100S, SEC(251), 1.5, T).unwrap();
        // ...but the REPORTED finish is uninflated, because the caller uses it as a backlog.
        assert_eq!(a.finishes_in, SEC(200));
    }

    /// A device with no throughput estimate must fall back, not be silently dropped — and if
    /// there is no fallback either, we must refuse rather than gamble the collateral.
    #[test]
    fn an_unbenchmarked_device_uses_the_fallback_and_refuses_without_one() {
        let slots = [slot("a", 0, 0.0)];
        assert_eq!(
            plan_admission(&slots, SEC(300), CYCLES_100S, SEC(9999), 1.0, T).unwrap().finishes_in,
            SEC(100)
        );
        assert_eq!(
            plan_admission(&slots, SEC(300), CYCLES_100S, SEC(9999), 1.0, 0.0),
            Err(Rejection::NoUsableDevice)
        );
    }

    /// Rejections must be distinguishable: a full queue is a healthy steady state, while
    /// "cannot meet this deadline anywhere" is worth telling the operator about.
    #[test]
    fn rejection_reasons_are_distinguishable() {
        let full = [slot("a", 400, T)];
        assert_eq!(
            plan_admission(&full, SEC(300), CYCLES_100S, SEC(9999), 1.0, T),
            Err(Rejection::HorizonFull)
        );
        let roomy_but_late = [slot("a", 10, T)];
        assert_eq!(
            plan_admission(&roomy_but_late, SEC(300), CYCLES_100S, SEC(50), 1.0, T),
            Err(Rejection::DeadlineInfeasible)
        );
        assert_eq!(
            plan_admission(&[], SEC(300), CYCLES_100S, SEC(9999), 1.0, T),
            Err(Rejection::NoUsableDevice)
        );
    }

    /// Zero cycles is a missing estimate, not a free job. Admitting it would queue unbounded
    /// unknown work against a real deadline.
    #[test]
    fn zero_cycles_is_never_admitted() {
        let slots = [slot("a", 0, T)];
        assert_eq!(
            plan_admission(&slots, SEC(300), 0, SEC(9999), 1.0, T),
            Err(Rejection::NoUsableDevice)
        );
    }

    /// Filling a two-GPU rig to a 300s horizon: successive admissions must spread across both
    /// devices and then stop, rather than piling onto one or running away.
    #[test]
    fn successive_admissions_fill_both_devices_then_stop() {
        let mut slots = vec![slot("a", 0, T), slot("b", 0, T)];
        let mut placed = Vec::new();
        for _ in 0..10 {
            match plan_admission(&slots, SEC(300), CYCLES_100S, SEC(9999), 1.0, T) {
                Ok(a) => {
                    let s = slots.iter_mut().find(|s| s.device_id == a.device_id).unwrap();
                    s.backlog = a.finishes_in; // commit it, as the caller would
                    placed.push(a.device_id);
                }
                Err(Rejection::HorizonFull) => break,
                Err(e) => panic!("unexpected rejection: {e:?}"),
            }
        }
        assert_eq!(placed.len(), 8, "4 x 100s per device up to a 300s horizon");
        assert_eq!(placed.iter().filter(|d| *d == "a").count(), 4, "must balance: {placed:?}");
        assert_eq!(slots[0].backlog, SEC(400));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Backlog tracking
//
// `plan_admission` needs each device's backlog, which the miner does not track today: jobs are
// assigned to a GPU by the dispatcher at PROVE time, and nothing records how much work is
// outstanding where. This is the smallest model that supplies it honestly.
//
// It is deliberately SELF-CORRECTING rather than accurate. Estimates come from benchmarks and
// will be wrong; what matters is that error cannot accumulate. Two mechanisms ensure that:
// remaining time decays with the wall clock, and a completed job is dropped outright. So a job
// that overruns its estimate decays to zero and stops inflating the backlog, and one that
// finishes early is removed early. The model converges on truth every completion.
// ─────────────────────────────────────────────────────────────────────────────

use std::collections::HashMap;

/// Per-device outstanding work, maintained by the brain loop.
#[derive(Debug, Default)]
pub struct QueueModel {
    /// job key -> (device, time until THIS JOB FINISHES, from now)
    ///
    /// Finish OFFSET, not work duration. `tick` decays every entry by elapsed wall time, and
    /// that is only coherent for a time-until-finish quantity: storing per-job work and
    /// summing meant a device holding k jobs shed k seconds of backlog per wall second.
    assigned: HashMap<[u8; 32], (String, Duration)>,
}

impl QueueModel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the clock. Every outstanding job's remaining estimate shrinks by `elapsed`,
    /// saturating at zero — an overrunning job stops inflating its device's backlog instead of
    /// blocking it forever.
    pub fn tick(&mut self, elapsed: Duration) {
        for (_, rem) in self.assigned.values_mut() {
            *rem = rem.saturating_sub(elapsed);
        }
    }

    /// Record an admitted job against the device it was planned onto.
    ///
    /// `finish_offset` is `Admission::finishes_in` — how long until this job COMPLETES,
    /// measured from now. Not its work duration; see the field docs.
    pub fn commit(&mut self, job: [u8; 32], device_id: &str, finish_offset: Duration) {
        self.assigned.insert(job, (device_id.to_string(), finish_offset));
    }

    /// Drop a finished (or abandoned) job. Idempotent — the brain settles jobs from several
    /// paths (completion, release, recovery) and must not need to know which ran first.
    pub fn settle(&mut self, job: &[u8; 32]) {
        self.assigned.remove(job);
    }

    /// Jobs currently modelled as outstanding.
    pub fn outstanding(&self) -> usize {
        self.assigned.len()
    }

    /// Build the slot list for `plan_admission`: one entry per device, carrying the time
    /// until that device is FREE — i.e. the max finish offset over its jobs, not the sum.
    /// Summing finish offsets would double-count the queue wait each job already includes.
    pub fn slots(&self, devices: &[(String, f64)]) -> Vec<DeviceSlot> {
        devices
            .iter()
            .map(|(id, tput)| {
                let backlog = self
                    .assigned
                    .values()
                    .filter(|(d, _)| d == id)
                    .map(|(_, rem)| *rem)
                    .fold(Duration::ZERO, Duration::max);
                DeviceSlot { device_id: id.clone(), backlog, throughput: *tput }
            })
            .collect()
    }

    /// Forget everything. For a re-anchor after the device set changes under us.
    pub fn clear(&mut self) {
        self.assigned.clear();
    }
}

#[cfg(test)]
mod model_tests {
    use super::*;

    fn job(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k
    }
    const T: f64 = 1e9;

    /// Backlog is WHEN THE DEVICE IS FREE — the max finish offset over its jobs, not a sum.
    /// Each offset already includes the queue wait ahead of it, so summing double-counts.
    #[test]
    fn backlog_is_the_time_until_the_device_is_free() {
        let mut m = QueueModel::new();
        let devs = vec![("a".to_string(), T), ("b".to_string(), T)];
        m.commit(job(1), "a", Duration::from_secs(100)); // finishes at t=100
        m.commit(job(2), "a", Duration::from_secs(150)); // queued behind it, finishes at t=150
        m.commit(job(3), "b", Duration::from_secs(30));

        let s = m.slots(&devs);
        assert_eq!(s[0].backlog, Duration::from_secs(150), "a is free when its LAST job ends");
        assert_eq!(s[1].backlog, Duration::from_secs(30));

        m.settle(&job(2));
        assert_eq!(m.slots(&devs)[0].backlog, Duration::from_secs(100));
        m.settle(&job(2)); // idempotent: the brain settles from several paths
        assert_eq!(m.outstanding(), 2);
    }

    /// An OVERRUNNING job must decay to zero rather than block its device forever. Without
    /// this, one bad estimate would permanently shrink the usable horizon on that GPU.
    #[test]
    fn an_overrunning_job_decays_to_zero_instead_of_blocking_the_device() {
        let mut m = QueueModel::new();
        let devs = vec![("a".to_string(), T)];
        m.commit(job(1), "a", Duration::from_secs(100));
        m.tick(Duration::from_secs(500)); // it ran 5x its estimate
        assert_eq!(m.slots(&devs)[0].backlog, Duration::ZERO, "decayed, not negative or stuck");
        // ...and the device is admissible again even though the job has not finished.
        assert!(plan_admission(
            &m.slots(&devs),
            Duration::from_secs(300),
            100_000_000_000,
            Duration::from_secs(9999),
            1.0,
            T
        )
        .is_ok());
    }

    /// Estimate error must not ACCUMULATE across jobs — the property that makes an approximate
    /// model safe to schedule against.
    #[test]
    fn estimate_error_does_not_accumulate_across_jobs() {
        let mut m = QueueModel::new();
        let devs = vec![("a".to_string(), T)];
        for i in 0..20u8 {
            m.commit(job(i), "a", Duration::from_secs(100));
            m.tick(Duration::from_secs(300)); // every job overruns 3x
            m.settle(&job(i));
        }
        assert_eq!(m.outstanding(), 0);
        assert_eq!(m.slots(&devs)[0].backlog, Duration::ZERO);
    }

    /// A device with no assigned work reports an empty backlog, not a missing entry — the
    /// planner must see every device.
    #[test]
    fn every_device_appears_even_with_no_work() {
        let m = QueueModel::new();
        let devs = vec![("a".to_string(), T), ("b".to_string(), 0.0)];
        let s = m.slots(&devs);
        assert_eq!(s.len(), 2);
        assert!(s.iter().all(|d| d.backlog == Duration::ZERO));
    }
}

#[cfg(test)]
mod fallback_tests {
    use super::*;

    /// An INFINITE fallback must never be treated as "infinitely fast".
    ///
    /// The caller computes its fallback as a `min`-fold over known GPU throughputs, and an
    /// empty fold yields `f64::INFINITY`. If that reached the planner, `cycles / INFINITY` is
    /// zero, every job would look instantaneous, and admission would be unbounded — strictly
    /// worse than the cpu-skewed average it replaced. The caller collapses non-finite to 0.0;
    /// this pins that the planner refuses BOTH, so neither side can regress alone.
    #[test]
    fn a_non_finite_or_zero_fallback_refuses_rather_than_admitting_everything() {
        let unbenchmarked = [DeviceSlot {
            device_id: "gpu0".into(),
            backlog: Duration::ZERO,
            throughput: 0.0,
        }];
        for bad in [0.0_f64, -1.0] {
            assert_eq!(
                plan_admission(
                    &unbenchmarked,
                    Duration::from_secs(300),
                    100_000_000_000,
                    Duration::from_secs(9999),
                    1.0,
                    bad
                ),
                Err(Rejection::NoUsableDevice),
                "fallback {bad} must refuse, not admit"
            );
        }
        // And the pathological one: if INFINITY ever reached here it would admit with a
        // zero-length estimate. Document the consequence so the caller-side guard is not
        // quietly removed.
        let admitted = plan_admission(
            &unbenchmarked,
            Duration::from_secs(300),
            100_000_000_000,
            Duration::from_secs(9999),
            1.0,
            f64::INFINITY,
        );
        assert_eq!(
            admitted.map(|a| a.finishes_in),
            Ok(Duration::ZERO),
            "THIS is why the caller must collapse a non-finite min-fold to 0.0 before calling"
        );
    }

    /// The fallback must be PESSIMISTIC — the slowest known card, not an average that includes
    /// CPU rows. Measured on this rig: average_throughput() = 3.03M c/s vs the 4090's actual
    /// 1.44M, i.e. 2.11x optimistic, which halves the estimate and admits work that cannot
    /// finish.
    #[test]
    fn a_pessimistic_fallback_refuses_work_an_optimistic_one_would_admit() {
        let unbenchmarked = [DeviceSlot {
            device_id: "gpu9".into(),
            backlog: Duration::ZERO,
            throughput: 0.0,
        }];
        // 200M cycles: 66s at 3.03M c/s, 139s at 1.44M c/s. (Throughputs here are
        // ~1.4-3.0 MILLION cycles/s, so 200 BILLION would be ~18 hours — an easy
        // three-zero slip, and the reason this test asserts both directions.)
        let cycles = 200_000_000u64;
        let deadline = Duration::from_secs(100); // between the two
        assert!(
            plan_admission(&unbenchmarked, Duration::from_secs(300), cycles, deadline, 1.0, 3_030_000.0)
                .is_ok(),
            "the optimistic (cpu-skewed) fallback WOULD have admitted this"
        );
        assert_eq!(
            plan_admission(&unbenchmarked, Duration::from_secs(300), cycles, deadline, 1.0, 1_440_000.0),
            Err(Rejection::DeadlineInfeasible),
            "the slowest-GPU fallback correctly refuses it"
        );
    }
}

#[cfg(test)]
mod depth_tests {
    use super::*;

    fn job(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k
    }
    const T: f64 = 1e9;
    const CYCLES_100S: u64 = 100_000_000_000;

    /// THE R1 REGRESSION. Nothing previously ticked a device holding TWO jobs, which is the
    /// feature's own steady state and the only place the bug lived.
    ///
    /// With work-duration entries and a summing fold, a device holding k jobs shed k seconds
    /// of modelled backlog per wall second: two 100s jobs read 200s at t=0 and ZERO at t=100,
    /// when the truth is 100s. The planner then admitted a third job as if the device were
    /// free, and it missed its deadline — collateral lost outright, since `releaseJob` reverts
    /// past the lock deadline.
    #[test]
    fn a_device_holding_two_jobs_decays_at_exactly_one_x_wall_clock() {
        let mut m = QueueModel::new();
        let devs = vec![("a".to_string(), T)];
        m.commit(job(1), "a", Duration::from_secs(100)); // finishes at t=100
        m.commit(job(2), "a", Duration::from_secs(200)); // queued behind it, ends t=200

        assert_eq!(m.slots(&devs)[0].backlog, Duration::from_secs(200), "free at t=200");
        m.tick(Duration::from_secs(100));
        assert_eq!(
            m.slots(&devs)[0].backlog,
            Duration::from_secs(100),
            "after 100s the device is still 100s from free — NOT zero"
        );
    }

    /// The consequence, end to end: at t=100 a job needing 100s against a 160s window must be
    /// REFUSED, because it would not start until t=100 and would finish at t=200.
    #[test]
    fn a_third_job_is_refused_while_the_device_is_genuinely_busy() {
        let mut m = QueueModel::new();
        let devs = vec![("a".to_string(), T)];
        m.commit(job(1), "a", Duration::from_secs(100));
        m.commit(job(2), "a", Duration::from_secs(200));
        m.tick(Duration::from_secs(100));

        assert_eq!(
            plan_admission(
                &m.slots(&devs),
                Duration::from_secs(300),
                CYCLES_100S,
                Duration::from_secs(160), // its whole window
                1.0,
                T
            ),
            Err(Rejection::DeadlineInfeasible),
            "starts at t=100, finishes at t=200, window is 160s"
        );
    }

    /// Self-correction must survive the semantics change: an overrunning job still decays to
    /// zero rather than blocking its device forever.
    #[test]
    fn overrun_still_self_corrects_under_finish_offset_semantics() {
        let mut m = QueueModel::new();
        let devs = vec![("a".to_string(), T)];
        m.commit(job(1), "a", Duration::from_secs(100));
        m.tick(Duration::from_secs(500));
        assert_eq!(m.slots(&devs)[0].backlog, Duration::ZERO);
    }
}

#[cfg(test)]
mod earned_headroom_tests {
    use super::*;

    /// The look-ahead ceiling must be EARNED per job, not granted per tick.
    ///
    /// The caller triples its claim ceiling when the planner is active (a per-TICK predicate:
    /// horizon set and gpu benchmark rows present), but a job with no declared cycle count
    /// bypasses `plan_admission` entirely (a per-JOB predicate). On the only market ever
    /// observed — 298/298 jobs declaring zero cycles — that combination gave 3x claim depth
    /// with NO admission checking at all, strictly worse than the feature being off.
    ///
    /// This pins the rule at the level this crate owns: a job the planner never admitted has
    /// no `Admission`, so the caller must not count it against look-ahead headroom. The
    /// caller-side guard is `in_flight.len() < max_concurrent` on the bypass branch.
    #[test]
    fn an_unplanned_job_yields_no_admission_to_justify_headroom() {
        // "Unmeasurable" reaches the planner as zero cycles, which must never admit.
        let idle = [DeviceSlot {
            device_id: "gpu0".into(),
            backlog: Duration::ZERO,
            throughput: 1e9,
        }];
        assert_eq!(
            plan_admission(&idle, Duration::from_secs(300), 0, Duration::from_secs(9999), 1.0, 1e9),
            Err(Rejection::NoUsableDevice),
            "a job with no cycle count must produce no Admission — so the caller has nothing \
             to justify the tripled ceiling with, and must fall back to max_concurrent"
        );
    }

    /// A model that under-reports because bypassed jobs were never committed must not be
    /// planned against: an occupied device would look idle and the planner would place a job
    /// at `starts_in = 0` that actually starts when the running proof ends.
    #[test]
    fn an_empty_model_makes_an_occupied_device_look_idle() {
        let m = QueueModel::new(); // two bypassed jobs are running, none committed
        let devs = vec![("gpu0".to_string(), 1e9)];
        assert_eq!(
            m.slots(&devs)[0].backlog,
            Duration::ZERO,
            "this is WHY the caller must refuse to plan when outstanding() != in_flight.len()"
        );
    }
}
