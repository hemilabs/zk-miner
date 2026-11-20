//! The collateral cap: how much of the stake one job may lock, and how much the jobs of one program,
//! or of one submitter, may lock together while they are not proven here.
//!
//! A forced release burns a share of what its job locked, and a job's collateral is its submitter's
//! choice (a rate up to 500% of a maximum price it also chose). Without a cap one job could lock most
//! of the stake; without the aggregate, one program or one submitter could do the same with many jobs
//! each under the cap. The cap is `max(fraction × total stake, MIN_COLLATERAL_AMOUNT)`:
//! - the fraction is [`FRACTION_ENV`] ([`DEFAULT_FRACTION`] unset; `0` turns the cap off), read once
//!   and warned about when it is not a number from 0 up;
//! - the floor is the deployment's per-job minimum, which every claim locks whatever its price, so a
//!   stake that can lock one job at all (100–199 HEMI on 743111) can still claim one.
//!
//! The same cap bounds the jobs of one program, and of one submitter, that this miner holds and has
//! not proven yet ([`decide`]): inline claims ([`record`] at the brain's commit), witness claims
//! ([`admit`] right before their claim) and recovered locks. A job leaves the count once its proof is
//! done or it is no longer held ([`forget`], [`retain`]).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use alloy::primitives::{Address, B256};

/// The variable naming the share of the total stake one job (and the unproven jobs of one program
/// or submitter together) may lock.
pub(crate) const FRACTION_ENV: &str = "ZKMINER_MAX_JOB_COLLATERAL_FRACTION";

/// The share when [`FRACTION_ENV`] is unset or unreadable.
///
/// The cap is checked against a job's collateral at its maximum price, the most its claim could
/// lock, so it must clear an honest job on a rig staked for only a couple of concurrent ones, and
/// still stop one job from locking most of the stake, where a forced release then burns a share of
/// all of it.
pub(crate) const DEFAULT_FRACTION: f64 = 0.5;

/// The share `raw` (the variable's value) names: unset is the default; a finite number from 0 up is
/// itself; anything else is `Err` with the text, and the caller falls back to the default after
/// saying so.
pub(crate) fn parse_fraction(raw: Option<&str>) -> Result<f64, String> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_FRACTION);
    };
    raw.trim()
        .parse::<f64>()
        .ok()
        .filter(|f| f.is_finite() && *f >= 0.0)
        .ok_or_else(|| raw.to_string())
}

/// What the cap is made of.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CapPolicy {
    /// The share of the total stake ([`FRACTION_ENV`]); 0 turns the cap off.
    pub fraction: f64,
    /// The deployment's `MIN_COLLATERAL_AMOUNT` in wei, once read (0 until then).
    pub floor: u128,
}

impl CapPolicy {
    /// The most one job, and the unproven jobs of one program or submitter together, may lock, in
    /// wei: `max(fraction × total_staked, floor)`. `None` when the cap is off or the stake is not
    /// known (0). A threshold, so f64 rounding at wei magnitudes does not matter.
    pub(crate) fn cap(&self, total_staked: u128) -> Option<u128> {
        if self.fraction <= 0.0 || total_staked == 0 {
            return None;
        }
        Some((((total_staked as f64) * self.fraction) as u128).max(self.floor))
    }

    /// Whether the floor, not the fraction, sets the cap at this stake.
    pub(crate) fn floor_sets_cap(&self, total_staked: u128) -> bool {
        self.fraction > 0.0
            && total_staked > 0
            && (((total_staked as f64) * self.fraction) as u128) < self.floor
    }
}

/// The fraction, read once.
static FRACTION: OnceLock<f64> = OnceLock::new();
/// The deployment's per-job floor, once read (`set_floor`).
static FLOOR: Mutex<Option<u128>> = Mutex::new(None);
/// Whether the floor-sets-the-cap notice was logged.
static FLOOR_NOTED: AtomicBool = AtomicBool::new(false);

fn fraction() -> f64 {
    *FRACTION.get_or_init(|| {
        match parse_fraction(std::env::var(FRACTION_ENV).ok().as_deref()) {
            Ok(f) => f,
            Err(raw) => {
                tracing::warn!(
                    "{FRACTION_ENV}={raw:?} is not a number from 0 up: one job may lock at most {:.0}% \
                     of the stake (the default)",
                    DEFAULT_FRACTION * 100.0
                );
                DEFAULT_FRACTION
            }
        }
    })
}

/// The cap's settings now: the fraction (read, and warned about, on first use) and the floor as far
/// as it is known.
pub(crate) fn policy() -> CapPolicy {
    CapPolicy {
        fraction: fraction(),
        floor: floor().unwrap_or(0),
    }
}

/// The deployment's per-job floor, if read yet.
pub(crate) fn floor() -> Option<u128> {
    *FLOOR.lock().unwrap_or_else(|p| p.into_inner())
}

/// Records the deployment's `MIN_COLLATERAL_AMOUNT` (constant for a deployment).
pub(crate) fn set_floor(wei: u128) {
    *FLOOR.lock().unwrap_or_else(|p| p.into_inner()) = Some(wei);
}

/// Says once, at the first stake read where it is so, that the floor sets the cap: the fraction of
/// this stake is less than every job locks.
pub(crate) fn note_stake(total_staked: u128) {
    let p = policy();
    if p.floor_sets_cap(total_staked) && !FLOOR_NOTED.swap(true, Ordering::SeqCst) {
        tracing::info!(
            "{:.0}% of the {} HEMI stake ({FRACTION_ENV}) is under the {} HEMI every job locks: one job \
             (and the unproven jobs of one program or submitter) may lock up to {} HEMI",
            p.fraction * 100.0,
            super::fmt_hemi(total_staked),
            super::fmt_hemi(p.floor),
            super::fmt_hemi(p.floor),
        );
    }
}

/// A job held here (or about to be claimed) and not yet proven: whose it is and what it locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exposure {
    pub program: B256,
    pub submitter: Address,
    /// Wei: what its claim locks, or at most locks (at its maximum price) before it is claimed.
    pub collateral: u128,
}

/// The cap's answer for one job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapVerdict {
    Admit,
    /// The job alone would lock more than the cap. Its terms are fixed while it is Open: set aside.
    OverJob {
        required: u128,
        cap: u128,
    },
    /// With the unproven jobs of its program held here (`held`), it would lock more than the cap:
    /// not now, while they are.
    OverProgram {
        held: u128,
        required: u128,
        cap: u128,
    },
    /// The same for its submitter's.
    OverSubmitter {
        held: u128,
        required: u128,
        cap: u128,
    },
}

impl CapVerdict {
    /// Whether the job stays over the cap for as long as it is Open (not only while others are held).
    pub(crate) fn is_final(&self) -> bool {
        matches!(self, CapVerdict::OverJob { .. })
    }

    /// The reason, for a log line.
    pub(crate) fn describe(&self) -> Option<String> {
        use super::fmt_hemi;
        match *self {
            CapVerdict::Admit => None,
            CapVerdict::OverJob { required, cap } => Some(format!(
                "it would lock up to {} HEMI of collateral, over the {} HEMI one job may lock ({FRACTION_ENV})",
                fmt_hemi(required),
                fmt_hemi(cap)
            )),
            CapVerdict::OverProgram { held, required, cap } => Some(format!(
                "its program's unproven jobs here lock {} HEMI: with its {} HEMI that is over the {} HEMI \
                 one program may lock ({FRACTION_ENV})",
                fmt_hemi(held),
                fmt_hemi(required),
                fmt_hemi(cap)
            )),
            CapVerdict::OverSubmitter { held, required, cap } => Some(format!(
                "its submitter's unproven jobs here lock {} HEMI: with its {} HEMI that is over the {} HEMI \
                 one submitter may lock ({FRACTION_ENV})",
                fmt_hemi(held),
                fmt_hemi(required),
                fmt_hemi(cap)
            )),
        }
    }
}

/// The decision: whether `job` (with id `jid`) may be claimed under `cap`, beside the unproven jobs
/// `held` here (its own entry, if any, is not counted twice). No cap: admitted.
pub(crate) fn decide(
    jid: B256,
    job: &Exposure,
    cap: Option<u128>,
    held: &HashMap<B256, Exposure>,
) -> CapVerdict {
    let Some(cap) = cap else {
        return CapVerdict::Admit;
    };
    let required = job.collateral;
    if required > cap {
        return CapVerdict::OverJob { required, cap };
    }
    let others = || held.iter().filter(|(j, _)| **j != jid).map(|(_, e)| e);
    let program: u128 = others()
        .filter(|e| e.program == job.program)
        .fold(0u128, |s, e| s.saturating_add(e.collateral));
    if program.saturating_add(required) > cap {
        return CapVerdict::OverProgram {
            held: program,
            required,
            cap,
        };
    }
    let submitter: u128 = others()
        .filter(|e| e.submitter == job.submitter)
        .fold(0u128, |s, e| s.saturating_add(e.collateral));
    if submitter.saturating_add(required) > cap {
        return CapVerdict::OverSubmitter {
            held: submitter,
            required,
            cap,
        };
    }
    CapVerdict::Admit
}

/// The unproven jobs held here (or being claimed), by job id.
static UNPROVEN: Mutex<Option<HashMap<B256, Exposure>>> = Mutex::new(None);

fn with_unproven<T>(f: impl FnOnce(&mut HashMap<B256, Exposure>) -> T) -> T {
    let mut g = UNPROVEN.lock().unwrap_or_else(|p| p.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

/// [`decide`] against the unproven jobs held now.
pub(crate) fn check(jid: B256, job: &Exposure, cap: Option<u128>) -> CapVerdict {
    with_unproven(|held| decide(jid, job, cap, held))
}

/// [`decide`] and, when admitted, [`record`] in one step: two claims deciding at once never both
/// take the last of a program's room.
pub(crate) fn admit(jid: B256, job: Exposure, cap: Option<u128>) -> CapVerdict {
    with_unproven(|held| {
        let v = decide(jid, &job, cap, held);
        if v == CapVerdict::Admit {
            held.insert(jid, job);
        }
        v
    })
}

/// Counts `jid` as held and unproven (a claim the brain commits, a lock recovered).
pub(crate) fn record(jid: B256, job: Exposure) {
    with_unproven(|held| {
        held.insert(jid, job);
    });
}

/// `jid` is proven, or no longer held.
pub(crate) fn forget(jid: B256) {
    with_unproven(|held| {
        held.remove(&jid);
    });
}

/// Keeps only the jobs `keep` says are still held and unproven.
pub(crate) fn retain(keep: impl Fn(&B256) -> bool) {
    with_unproven(|held| held.retain(|j, _| keep(j)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::run::ONE_HEMI_WEI;
    use zkminer_chain::auction::compute_collateral;

    const HEMI: u128 = ONE_HEMI_WEI;
    /// The deployment's per-job floor on 743111.
    const FLOOR: u128 = 100 * HEMI;

    fn policy(fraction: f64) -> CapPolicy {
        CapPolicy {
            fraction,
            floor: FLOOR,
        }
    }

    fn job(program: u8, submitter: u8, collateral: u128) -> Exposure {
        Exposure {
            program: B256::repeat_byte(program),
            submitter: Address::repeat_byte(submitter),
            collateral,
        }
    }

    #[test]
    fn the_fraction_is_read_from_the_variable_or_defaults_to_half() {
        assert_eq!(parse_fraction(None), Ok(0.5));
        assert_eq!(parse_fraction(Some("0.25")), Ok(0.25));
        assert_eq!(parse_fraction(Some(" 1 ")), Ok(1.0));
        assert_eq!(parse_fraction(Some("0")), Ok(0.0));
        // Unreadable: refused, with the text, for the caller's warning.
        for bad in ["", "half", "-0.5", "NaN", "inf", "50%"] {
            assert_eq!(parse_fraction(Some(bad)), Err(bad.to_string()), "{bad:?}");
        }
    }

    #[test]
    fn no_cap_without_a_stake_or_with_the_cap_off() {
        assert_eq!(policy(0.5).cap(0), None);
        assert_eq!(policy(0.0).cap(1_000 * HEMI), None);
        assert_eq!(policy(0.5).cap(1_000 * HEMI), Some(500 * HEMI));
        assert_eq!(
            decide(B256::ZERO, &job(1, 1, u128::MAX), None, &HashMap::new()),
            CapVerdict::Admit
        );
    }

    /// A rig staked for one job at the deployment's floor: half its stake is under what every job
    /// locks, so without the floor the cap set every job aside, honest ones too.
    #[test]
    fn a_stake_of_one_or_two_floors_can_claim_one_honest_job() {
        // An honest job: a 5 HEMI price at 150%, floored at 100 HEMI.
        let honest = compute_collateral(5 * HEMI, 15_000, FLOOR);
        assert_eq!(honest, FLOOR);
        for stake_hemi in [100u128, 150, 199] {
            let stake = stake_hemi * HEMI;
            let p = policy(0.5);
            assert!(p.floor_sets_cap(stake), "{stake_hemi}");
            let cap = p.cap(stake);
            assert_eq!(cap, Some(FLOOR), "{stake_hemi}");
            assert_eq!(
                decide(B256::ZERO, &job(1, 1, honest), cap, &HashMap::new()),
                CapVerdict::Admit,
                "{stake_hemi}"
            );
            // One at a time: a second job of the same program waits for the first.
            let held = HashMap::from([(B256::repeat_byte(9), job(1, 1, honest))]);
            assert!(matches!(
                decide(B256::ZERO, &job(1, 2, honest), cap, &held),
                CapVerdict::OverProgram { .. }
            ));
        }
        assert!(!policy(0.5).floor_sets_cap(200 * HEMI));
        assert!(!policy(0.0).floor_sets_cap(150 * HEMI));
    }

    /// The case the cap is for, at localnet's stake: a job whose terms its submitter chose (500% at a
    /// 120 HEMI maximum price: 600 HEMI) fits in the free stake, so the stake check alone would claim
    /// it, and a forced release would then burn a share of most of the stake. An honest job is far
    /// under the cap.
    #[test]
    fn a_job_asking_for_most_of_the_stake_is_set_aside_and_an_honest_one_is_not() {
        let stake = 1_000 * HEMI;
        let cap = policy(DEFAULT_FRACTION).cap(stake);
        let decoy = compute_collateral(120 * HEMI, 50_000, FLOOR);
        assert_eq!(decoy, 600 * HEMI);
        assert!(decoy <= stake, "the stake check alone would admit it");
        let v = decide(B256::ZERO, &job(1, 1, decoy), cap, &HashMap::new());
        assert_eq!(
            v,
            CapVerdict::OverJob {
                required: decoy,
                cap: 500 * HEMI
            }
        );
        assert!(v.is_final() && v.describe().unwrap().contains("600.00 HEMI"));
        let honest = compute_collateral(5 * HEMI, 15_000, FLOOR);
        assert_eq!(
            decide(B256::ZERO, &job(2, 2, honest), cap, &HashMap::new()),
            CapVerdict::Admit
        );
    }

    /// What the brain, the witness gate and the watch-only inspector size a job at (`claim_exposure`):
    /// its collateral at its maximum price under its own terms, whatever the current price, so a job
    /// claimed early on its ramp is held to what its claim can come to lock.
    #[test]
    fn a_job_is_sized_at_its_maximum_price_under_its_own_terms() {
        let info = zkminer_chain::jobs::JobInfo {
            program_id: B256::repeat_byte(1),
            caller: Address::repeat_byte(2),
            max_price: 120 * HEMI,
            ..Default::default()
        };
        // 500% of 120 HEMI, early on the ramp (5 HEMI now).
        let e = super::super::claim_exposure(&info, 5 * HEMI, (FLOOR, 50_000));
        assert_eq!(e, job(1, 2, 600 * HEMI));
        // The default rate on a small price: the floor.
        assert_eq!(
            super::super::claim_exposure(&info, 0, (FLOOR, 15_000)).collateral,
            180 * HEMI
        );
        let cheap = zkminer_chain::jobs::JobInfo {
            max_price: 5 * HEMI,
            ..info.clone()
        };
        assert_eq!(
            super::super::claim_exposure(&cheap, 0, (FLOOR, 15_000)).collateral,
            FLOOR
        );
        // A price past the maximum (a stale maximum): the higher one.
        assert_eq!(
            super::super::claim_exposure(&cheap, 10 * HEMI, (FLOOR, 50_000)).collateral,
            FLOOR.max(50 * HEMI)
        );
        // At localnet's 1,000 HEMI stake the 600 HEMI job is set aside.
        assert!(decide(
            B256::ZERO,
            &e,
            policy(DEFAULT_FRACTION).cap(1_000 * HEMI),
            &HashMap::new()
        )
        .is_final());
    }

    /// Many jobs each under the cap: one program, or one submitter, holds at most the cap here until
    /// its jobs are proven; other programs and submitters are not held back by it.
    #[test]
    fn the_unproven_jobs_of_one_program_or_submitter_share_the_cap() {
        let cap = policy(DEFAULT_FRACTION).cap(1_000 * HEMI);
        let id = |b: u8| B256::repeat_byte(b);
        let mut held = HashMap::new();
        // Program 1 from submitter 1: two 200 HEMI jobs fit (400 ≤ 500), a third does not.
        for n in 0..2u8 {
            assert_eq!(
                decide(id(n), &job(1, 1, 200 * HEMI), cap, &held),
                CapVerdict::Admit
            );
            held.insert(id(n), job(1, 1, 200 * HEMI));
        }
        let third = decide(id(2), &job(1, 3, 200 * HEMI), cap, &held);
        assert_eq!(
            third,
            CapVerdict::OverProgram {
                held: 400 * HEMI,
                required: 200 * HEMI,
                cap: 500 * HEMI
            }
        );
        assert!(!third.is_final());
        // Another program from the same submitter: over the submitter's share.
        assert!(matches!(
            decide(id(2), &job(2, 1, 200 * HEMI), cap, &held),
            CapVerdict::OverSubmitter { .. }
        ));
        // Another program and submitter: admitted.
        assert_eq!(
            decide(id(2), &job(2, 2, 200 * HEMI), cap, &held),
            CapVerdict::Admit
        );
        // A job's own entry is not counted against it again.
        assert_eq!(
            decide(id(1), &job(1, 1, 200 * HEMI), cap, &held),
            CapVerdict::Admit
        );
        // Once one is proven (forgotten), the third fits.
        held.remove(&id(0));
        assert_eq!(
            decide(id(2), &job(1, 1, 200 * HEMI), cap, &held),
            CapVerdict::Admit
        );
    }

    /// `admit` decides and records in one step; `forget` and `retain` give the room back.
    #[test]
    fn admit_records_what_it_admits() {
        let cap = Some(500 * HEMI);
        // A program and submitter no other test uses: the registry is process-wide.
        let mine = |c| job(0xa1, 0xa1, c);
        let (a, b, c) = (
            B256::repeat_byte(0xa1),
            B256::repeat_byte(0xa2),
            B256::repeat_byte(0xa3),
        );
        assert_eq!(admit(a, mine(300 * HEMI), cap), CapVerdict::Admit);
        assert!(matches!(
            admit(b, mine(300 * HEMI), cap),
            CapVerdict::OverProgram { .. }
        ));
        assert!(matches!(
            check(b, &mine(300 * HEMI), cap),
            CapVerdict::OverProgram { .. }
        ));
        forget(a);
        assert_eq!(admit(b, mine(300 * HEMI), cap), CapVerdict::Admit);
        record(c, mine(100 * HEMI));
        assert!(matches!(
            check(a, &mine(200 * HEMI), cap),
            CapVerdict::OverProgram { .. }
        ));
        retain(|j| *j != b && *j != c);
        assert_eq!(check(a, &mine(500 * HEMI), cap), CapVerdict::Admit);
    }
}
