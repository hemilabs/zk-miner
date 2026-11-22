//! The collateral cap: how much of the stake one job may lock, how much the jobs of one program, or
//! of one submitter, may lock together while this miner holds them, and how much every lock it holds
//! may come to together.
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
//! not settled yet ([`decide`]): inline claims ([`record`] at the brain's commit), witness claims
//! ([`admit`] right before their claim) and recovered locks. Programs and submitters cost nothing to
//! make, so with those bounds alone a few of them could lock nearly the whole stake together, and a
//! miner then cut off from the chain until their deadlines pass is slashed for all of it. So every
//! lock held here together is bounded too: by `[prover] max_locked_stake_fraction` of the total stake
//! ([`set_stake_fraction`], [`DEFAULT_STAKE_FRACTION`]), with the same floor.
//!
//! A job leaves the count only once its lock is settled (fulfilled, released, slashed, or no longer
//! ours). Not once it is proven: a proof whose fulfil cannot be sent still loses the whole lock. Nor
//! once the task driving it ends: a lock handed back to recovery is still on chain, so it counts for
//! as long as the journal holds it ([`journalled_locks`], [`retain`]), up to an hour past its window.
//!
//! The registry is this process's view. A lock it holds no entry for (one recovery has not found
//! again since a restart, one it forgot) is still on chain, so the stake-wide sum is the larger of the
//! registry's and the chain's own figure (`stake_info.locked_collateral`, when fresh) plus the claims
//! that figure does not include yet ([`Caps::chain`], [`decide_with`]).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use alloy::primitives::{Address, B256};

/// The variable naming the share of the total stake one job (and the unsettled jobs of one program
/// or submitter together) may lock.
pub(crate) const FRACTION_ENV: &str = "ZKMINER_MAX_JOB_COLLATERAL_FRACTION";

/// The share when [`FRACTION_ENV`] is unset or unreadable.
///
/// The cap is checked against a job's collateral at its maximum price, the most its claim could
/// lock, so it must clear an honest job on a rig staked for only a couple of concurrent ones, and
/// still stop one job from locking most of the stake, where a forced release then burns a share of
/// all of it.
pub(crate) const DEFAULT_FRACTION: f64 = 0.5;

/// The share of the total stake every lock held here may come to together when the config does not
/// say (`[prover] max_locked_stake_fraction`, whose default is the same).
pub(crate) const DEFAULT_STAKE_FRACTION: f64 = 0.5;

/// The config key naming the stake-wide share, for log lines.
pub(crate) const STAKE_FRACTION_KEY: &str = "[prover] max_locked_stake_fraction";

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
    /// The most one job, and the unsettled jobs of one program or submitter together, may lock, in
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
/// The stake-wide fraction the config set (`set_stake_fraction`), if it did.
static STAKE_FRACTION: Mutex<Option<f64>> = Mutex::new(None);
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

/// Sets the share of the total stake every lock held here may come to together
/// (`[prover] max_locked_stake_fraction`, which config validation holds to `(0, 1]`).
pub(crate) fn set_stake_fraction(f: f64) {
    *STAKE_FRACTION.lock().unwrap_or_else(|p| p.into_inner()) = Some(f);
}

/// The stake-wide share in force: the config's, or [`DEFAULT_STAKE_FRACTION`].
pub(crate) fn stake_fraction() -> f64 {
    STAKE_FRACTION
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .unwrap_or(DEFAULT_STAKE_FRACTION)
}

/// The cap's settings now: the fraction (read, and warned about, on first use) and the floor as far
/// as it is known.
pub(crate) fn policy() -> CapPolicy {
    CapPolicy {
        fraction: fraction(),
        floor: floor().unwrap_or(0),
    }
}

/// The stake-wide cap's settings now: the config's share, and the same floor, so a stake that can
/// lock one job at all can still hold one.
pub(crate) fn stake_policy() -> CapPolicy {
    CapPolicy {
        fraction: stake_fraction(),
        floor: floor().unwrap_or(0),
    }
}

/// Both caps at `total_staked`.
pub(crate) fn caps(total_staked: u128) -> Caps {
    Caps {
        job: policy().cap(total_staked),
        stake: stake_policy().cap(total_staked),
        chain: None,
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
             (and the unsettled jobs of one program or submitter) may lock up to {} HEMI",
            p.fraction * 100.0,
            super::fmt_hemi(total_staked),
            super::fmt_hemi(p.floor),
            super::fmt_hemi(p.floor),
        );
    }
}

/// A job held here (or about to be claimed) and not yet settled: whose it is and what it locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exposure {
    pub program: B256,
    pub submitter: Address,
    /// Wei: what its claim locks, or at most locks (at its maximum price) before it is claimed.
    pub collateral: u128,
}

/// The two caps a job is held to, in wei: what one job (and one program's or submitter's held jobs)
/// may lock, and what every lock held here may come to together. `None`: that cap is off, or the
/// stake is not known yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Caps {
    pub job: Option<u128>,
    pub stake: Option<u128>,
    /// What every lock of this prover comes to on chain, from a fresh stake read; `None` when the
    /// read is stale or missing, and the stake-wide sum is then the registry's alone.
    pub chain: Option<ChainLocked>,
}

/// The chain's figure for every lock of this prover (`stake_info.locked_collateral`) and the block it
/// was read at, if known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChainLocked {
    pub locked: u128,
    pub read_block: Option<u64>,
}

/// Whether a stake read stamped at `last_refresh` is fresh enough to count locks by: newer than the
/// refresh's staleness ceiling, as the claim freshness hold and the recovery gate read it.
pub(crate) fn fresh_reading(last_refresh: Option<chrono::DateTime<chrono::Utc>>) -> bool {
    last_refresh.is_some_and(|t| {
        (chrono::Utc::now() - t)
            .to_std()
            .is_ok_and(|d| d < super::REFRESH_STALENESS_CEILING)
    })
}

/// Both caps at the stake read `stake`, with that read's locked figure when it is `fresh`.
pub(crate) fn caps_at(stake: Option<&zkminer_chain::staking::StakeInfo>, fresh: bool) -> Caps {
    Caps {
        chain: stake.filter(|_| fresh).map(|s| ChainLocked {
            locked: s.locked_collateral,
            read_block: s.read_block,
        }),
        ..caps(stake.map_or(0, |s| s.total_staked))
    }
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
    /// With the unsettled jobs of its program held here (`held`), it would lock more than the cap:
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
    /// With every lock of this prover not settled (`held`: those held here, or the chain's figure and
    /// the claims it does not show yet, whichever is more), it would take more of the stake than all
    /// of them may lock together: not now, while they are (and never, when it alone is over).
    OverStake {
        held: u128,
        required: u128,
        cap: u128,
    },
}

impl CapVerdict {
    /// Whether the job stays over the cap for as long as it is Open (not only while others are held).
    pub(crate) fn is_final(&self) -> bool {
        match *self {
            CapVerdict::OverJob { .. } => true,
            CapVerdict::OverStake { required, cap, .. } => required > cap,
            _ => false,
        }
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
                "its program's unsettled jobs here lock {} HEMI: with its {} HEMI that is over the {} HEMI \
                 one program may lock ({FRACTION_ENV})",
                fmt_hemi(held),
                fmt_hemi(required),
                fmt_hemi(cap)
            )),
            CapVerdict::OverSubmitter { held, required, cap } => Some(format!(
                "its submitter's unsettled jobs here lock {} HEMI: with its {} HEMI that is over the {} HEMI \
                 one submitter may lock ({FRACTION_ENV})",
                fmt_hemi(held),
                fmt_hemi(required),
                fmt_hemi(cap)
            )),
            CapVerdict::OverStake { held, required, cap } => Some(format!(
                "the locks this prover holds (on chain, and claims in flight) come to {} HEMI: with its {} \
                 HEMI that is over the {} HEMI of the stake they may lock together ({STAKE_FRACTION_KEY})",
                fmt_hemi(held),
                fmt_hemi(required),
                fmt_hemi(cap)
            )),
        }
    }
}

/// The decision: whether `job` (with id `jid`) may be claimed under `caps`, beside the unsettled
/// jobs `held` here (its own entry, if any, is not counted twice). No cap: admitted. No held job's
/// lock block is known ([`decide_with`]).
pub(crate) fn decide(
    jid: B256,
    job: &Exposure,
    caps: Caps,
    held: &HashMap<B256, Exposure>,
) -> CapVerdict {
    decide_with(jid, job, caps, held, &HashMap::new())
}

/// [`decide`], with the block each held job's lock is known at (`lock_at`). The stake-wide sum is the
/// larger of what is held here and, when `caps.chain` has a fresh reading, the chain's locked figure
/// plus the held jobs it does not count yet: those whose lock is not known at or before the block it
/// was read at (a claim still pending counts; one mined by then is in the figure already, the rule
/// the available-collateral gate uses). A reading of no known block adds nothing to its figure.
pub(crate) fn decide_with(
    jid: B256,
    job: &Exposure,
    caps: Caps,
    held: &HashMap<B256, Exposure>,
    lock_at: &HashMap<B256, u64>,
) -> CapVerdict {
    let required = job.collateral;
    let others = || held.iter().filter(|(j, _)| **j != jid).map(|(_, e)| e);
    let sum = |it: &mut dyn Iterator<Item = &Exposure>| {
        it.fold(0u128, |s, e| s.saturating_add(e.collateral))
    };
    if let Some(cap) = caps.job {
        if required > cap {
            return CapVerdict::OverJob { required, cap };
        }
        let program = sum(&mut others().filter(|e| e.program == job.program));
        if program.saturating_add(required) > cap {
            return CapVerdict::OverProgram {
                held: program,
                required,
                cap,
            };
        }
        let submitter = sum(&mut others().filter(|e| e.submitter == job.submitter));
        if submitter.saturating_add(required) > cap {
            return CapVerdict::OverSubmitter {
                held: submitter,
                required,
                cap,
            };
        }
    }
    if let Some(cap) = caps.stake {
        let here = sum(&mut others());
        let all = match caps.chain {
            None => here,
            Some(ChainLocked {
                locked,
                read_block: None,
            }) => here.max(locked),
            Some(ChainLocked {
                locked,
                read_block: Some(read),
            }) => {
                let pending = sum(&mut held
                    .iter()
                    .filter(|(j, _)| {
                        **j != jid
                            && !super::lock_counted_on_chain(Some(read), lock_at.get(*j).copied())
                    })
                    .map(|(_, e)| e));
                here.max(locked.saturating_add(pending))
            }
        };
        if all.saturating_add(required) > cap {
            return CapVerdict::OverStake {
                held: all,
                required,
                cap,
            };
        }
    }
    CapVerdict::Admit
}

/// The unsettled jobs held here (or being claimed), by job id, and the block each one's lock is
/// known at once its claim mined (or a read found it ours).
#[derive(Default)]
struct Registry {
    held: HashMap<B256, Exposure>,
    lock_at: HashMap<B256, u64>,
}

static HELD: Mutex<Option<Registry>> = Mutex::new(None);

fn with_registry<T>(f: impl FnOnce(&mut Registry) -> T) -> T {
    let mut g = HELD.lock().unwrap_or_else(|p| p.into_inner());
    f(g.get_or_insert_with(Registry::default))
}

fn with_held<T>(f: impl FnOnce(&mut HashMap<B256, Exposure>) -> T) -> T {
    with_registry(|r| f(&mut r.held))
}

/// [`decide_with`] against the unsettled jobs held now.
pub(crate) fn check(jid: B256, job: &Exposure, caps: Caps) -> CapVerdict {
    with_registry(|r| decide_with(jid, job, caps, &r.held, &r.lock_at))
}

/// [`decide_with`] and, when admitted, [`record`] in one step: two claims deciding at once never
/// both take the last of a program's (or the stake's) room.
pub(crate) fn admit(jid: B256, job: Exposure, caps: Caps) -> CapVerdict {
    with_registry(|r| {
        let v = decide_with(jid, &job, caps, &r.held, &r.lock_at);
        if v == CapVerdict::Admit {
            r.held.insert(jid, job);
        }
        v
    })
}

/// `jid`'s lock is known at `block` (its claim's receipt, or a read that found it ours): a stake read
/// at or after it already counts it.
pub(crate) fn note_lock_block(jid: B256, block: u64) {
    with_registry(|r| {
        r.lock_at.insert(jid, block);
    });
}

/// Counts `jid` as held and unsettled (a claim the brain commits, a lock recovered).
pub(crate) fn record(jid: B256, job: Exposure) {
    with_held(|held| {
        held.insert(jid, job);
    });
}

/// Counts a recovered lock that is being released, not driven: its program is not read, so it
/// counts only toward the stake-wide sum (`collateral` locked: what it locked when that is known,
/// else the deployment's floor) until its release settles. An entry the lock already has is kept, at
/// the larger of the two.
pub(crate) fn record_settling(jid: B256, collateral: u128) {
    with_held(|held| {
        let e = held.entry(jid).or_insert(Exposure {
            program: B256::ZERO,
            submitter: Address::ZERO,
            collateral,
        });
        e.collateral = e.collateral.max(collateral);
    });
}

/// Raises what `jid` counts at to `collateral`, if it is counted at all and at less (a release
/// recorded at the floor whose real collateral was read after).
pub(crate) fn raise(jid: B256, collateral: u128) {
    with_held(|held| {
        if let Some(e) = held.get_mut(&jid) {
            e.collateral = e.collateral.max(collateral);
        }
    });
}

/// `jid` is settled, or no longer held.
pub(crate) fn forget(jid: B256) {
    with_registry(|r| {
        r.held.remove(&jid);
        r.lock_at.remove(&jid);
    });
}

/// Keeps only the jobs `keep` says are still held and unsettled.
pub(crate) fn retain(keep: impl Fn(&B256) -> bool) {
    with_registry(|r| {
        r.held.retain(|j, _| keep(j));
        let held = &r.held;
        r.lock_at.retain(|j, _| held.contains_key(j));
    });
}

/// How long past its window a journalled lock still counts here: an entry left behind (a bug, a lock
/// no pass has dropped) must not hold cap room for ever. A lock really held that long (through a
/// pause's grace) still counts in the chain's own figure.
pub(crate) const JOURNAL_STALE_AFTER_SECS: u64 = 3600;

/// Whether a journal entry still counts as a held lock at `now` (unix seconds): until an hour past its
/// recorded cutoff and the prover grace or, with no cutoff recorded (a claim not yet seen locked), an
/// hour past the age at which recovery drops a claim intent.
pub(crate) fn journal_entry_counts(lock_deadline: u64, claimed_at: i64, now: u64) -> bool {
    let end = if lock_deadline != 0 {
        lock_deadline.saturating_add(zkminer_chain::auction::PROVER_GRACE_SECS)
    } else {
        u64::try_from(claimed_at)
            .unwrap_or(0)
            .saturating_add(super::CLAIM_INTENT_MAX_AGE_SECS)
    };
    now <= end.saturating_add(JOURNAL_STALE_AFTER_SECS)
}

/// The jobs the journal holds a lock of (or a claim that may have landed) that still count at `now`
/// ([`journal_entry_counts`]). A lock handed back by its task, kept, or not yet found again by
/// recovery is still on chain, so it keeps its place in the registry until the journal drops it
/// (fulfilled, released, found ended).
pub(crate) fn journalled_locks(journal: &crate::journal::JobJournal, now: u64) -> HashSet<B256> {
    journal
        .entries
        .iter()
        .filter(|(_, e)| journal_entry_counts(e.lock_deadline, e.claimed_at, now))
        .map(|(j, _)| *j)
        .collect()
}

/// A job's task ended: it leaves the registry unless the journal still holds its lock (`journalled`,
/// from [`journalled_locks`]), as after a hand-back to recovery.
pub(crate) fn forget_unless_journalled(jid: B256, journalled: &HashSet<B256>) {
    if !journalled.contains(&jid) {
        forget(jid);
    }
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

    /// The per-job cap alone, as before the stake-wide one.
    fn jc(job: Option<u128>) -> Caps {
        Caps {
            job,
            stake: None,
            chain: None,
        }
    }

    /// The registry is process-wide: the tests that use it take turns.
    fn registry_turn() -> std::sync::MutexGuard<'static, ()> {
        static TURN: Mutex<()> = Mutex::new(());
        TURN.lock().unwrap_or_else(|p| p.into_inner())
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
            decide(
                B256::ZERO,
                &job(1, 1, u128::MAX),
                Caps::default(),
                &HashMap::new()
            ),
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
                decide(B256::ZERO, &job(1, 1, honest), jc(cap), &HashMap::new()),
                CapVerdict::Admit,
                "{stake_hemi}"
            );
            // One at a time: a second job of the same program waits for the first.
            let held = HashMap::from([(B256::repeat_byte(9), job(1, 1, honest))]);
            assert!(matches!(
                decide(B256::ZERO, &job(1, 2, honest), jc(cap), &held),
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
        let v = decide(B256::ZERO, &job(1, 1, decoy), jc(cap), &HashMap::new());
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
            decide(B256::ZERO, &job(2, 2, honest), jc(cap), &HashMap::new()),
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
            jc(policy(DEFAULT_FRACTION).cap(1_000 * HEMI)),
            &HashMap::new()
        )
        .is_final());
    }

    /// Many jobs each under the cap: one program, or one submitter, holds at most the cap here until
    /// its locks settle; other programs and submitters are not held back by it.
    #[test]
    fn the_unsettled_jobs_of_one_program_or_submitter_share_the_cap() {
        let cap = policy(DEFAULT_FRACTION).cap(1_000 * HEMI);
        let id = |b: u8| B256::repeat_byte(b);
        let mut held = HashMap::new();
        // Program 1 from submitter 1: two 200 HEMI jobs fit (400 ≤ 500), a third does not.
        for n in 0..2u8 {
            assert_eq!(
                decide(id(n), &job(1, 1, 200 * HEMI), jc(cap), &held),
                CapVerdict::Admit
            );
            held.insert(id(n), job(1, 1, 200 * HEMI));
        }
        let third = decide(id(2), &job(1, 3, 200 * HEMI), jc(cap), &held);
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
            decide(id(2), &job(2, 1, 200 * HEMI), jc(cap), &held),
            CapVerdict::OverSubmitter { .. }
        ));
        // Another program and submitter: admitted.
        assert_eq!(
            decide(id(2), &job(2, 2, 200 * HEMI), jc(cap), &held),
            CapVerdict::Admit
        );
        // A job's own entry is not counted against it again.
        assert_eq!(
            decide(id(1), &job(1, 1, 200 * HEMI), jc(cap), &held),
            CapVerdict::Admit
        );
        // Once one settles (forgotten), the third fits.
        held.remove(&id(0));
        assert_eq!(
            decide(id(2), &job(1, 1, 200 * HEMI), jc(cap), &held),
            CapVerdict::Admit
        );
    }

    /// `admit` decides and records in one step; `forget` and `retain` give the room back.
    #[test]
    fn admit_records_what_it_admits() {
        let _turn = registry_turn();
        let cap = jc(Some(500 * HEMI));
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

    /// X-A: Sybil submitters, each with its own program and a job just under the per-job cap. Each
    /// share alone admits every one, so without the stake-wide cap two of them locked 98% of the
    /// stake; with it, every lock held here together stays within its share of the stake.
    #[test]
    fn sybil_programs_and_submitters_share_the_stake_wide_cap() {
        let stake = 1_000 * HEMI;
        let caps = Caps {
            job: policy(DEFAULT_FRACTION).cap(stake),
            stake: policy(DEFAULT_STAKE_FRACTION).cap(stake),
            chain: None,
        };
        let id = |b: u8| B256::repeat_byte(b);
        let lure = |n: u8| job(0x10 + n, 0x20 + n, 490 * HEMI);
        let mut held = HashMap::from([(id(1), lure(1))]);
        // The per-job, per-program and per-submitter caps alone admit the second lure.
        assert_eq!(
            decide(id(2), &lure(2), jc(caps.job), &held),
            CapVerdict::Admit
        );
        let v = decide(id(2), &lure(2), caps, &held);
        assert_eq!(
            v,
            CapVerdict::OverStake {
                held: 490 * HEMI,
                required: 490 * HEMI,
                cap: 500 * HEMI
            }
        );
        assert!(!v.is_final(), "it may fit once the first lock settles");
        assert!(v.describe().unwrap().contains(STAKE_FRACTION_KEY));
        // Many small jobs from as many programs and submitters: five fit, the sixth does not.
        held.clear();
        for n in 0..5u8 {
            let e = job(0x40 + n, 0x50 + n, 100 * HEMI);
            assert_eq!(
                decide(id(0x40 + n), &e, caps, &held),
                CapVerdict::Admit,
                "{n}"
            );
            held.insert(id(0x40 + n), e);
        }
        assert!(matches!(
            decide(id(0x45), &job(0x45, 0x55, 100 * HEMI), caps, &held),
            CapVerdict::OverStake { .. }
        ));
        // A lock being released after a restart (its program unread) counts toward the stake only.
        held.clear();
        held.insert(
            id(0x60),
            Exposure {
                program: B256::ZERO,
                submitter: Address::ZERO,
                collateral: 450 * HEMI,
            },
        );
        assert!(matches!(
            decide(id(0x61), &job(0x61, 0x61, 100 * HEMI), caps, &held),
            CapVerdict::OverStake { .. }
        ));
        assert_eq!(
            decide(id(0x61), &job(0x61, 0x61, 50 * HEMI), caps, &held),
            CapVerdict::Admit
        );
        // A job alone over a stake-wide share set lower than the per-job one never fits.
        let low = Caps {
            job: caps.job,
            stake: policy(0.25).cap(stake),
            chain: None,
        };
        let v = decide(id(0x70), &job(0x70, 0x70, 300 * HEMI), low, &HashMap::new());
        assert!(matches!(v, CapVerdict::OverStake { held: 0, .. }) && v.is_final());
        // A small stake still holds one job at the deployment's floor.
        let small = Caps {
            job: policy(DEFAULT_FRACTION).cap(150 * HEMI),
            stake: policy(DEFAULT_STAKE_FRACTION).cap(150 * HEMI),
            chain: None,
        };
        assert_eq!(small.stake, Some(FLOOR));
        assert_eq!(
            decide(id(0x71), &job(0x71, 0x71, FLOOR), small, &HashMap::new()),
            CapVerdict::Admit
        );
    }

    /// E8: a lock stays counted after its proof is done, until the task driving it ends (its fulfil
    /// or release settled, a slash, the lock lost): a proof whose fulfil cannot be sent still loses
    /// the whole lock. The brain keeps every job it holds (`in_flight`) and forgets one only when its
    /// task ends.
    #[test]
    fn a_lock_counts_until_it_settles_not_until_it_is_proven() {
        let _turn = registry_turn();
        let caps = Caps {
            job: Some(500 * HEMI),
            stake: Some(500 * HEMI),
            chain: None,
        };
        let (a, b) = (B256::repeat_byte(0xb1), B256::repeat_byte(0xb2));
        let in_flight: HashMap<B256, u128> = HashMap::from([(a, 400 * HEMI)]);
        assert_eq!(
            admit(a, job(0xb1, 0xb1, 400 * HEMI), caps),
            CapVerdict::Admit
        );
        // Proven: its card is freed, and the brain's pass keeps what it still holds.
        retain(|j| in_flight.contains_key(j));
        assert!(matches!(
            check(b, &job(0xb2, 0xb2, 400 * HEMI), caps),
            CapVerdict::OverStake { .. }
        ));
        // Its task ended (fulfilled): the room comes back.
        forget(a);
        assert_eq!(
            admit(b, job(0xb2, 0xb2, 400 * HEMI), caps),
            CapVerdict::Admit
        );
        forget(b);
    }

    /// After a restart the registry starts empty: recovery counts the locks it finds held (from the
    /// journal and the chain) again, those it drives under their program and submitter, those it
    /// releases toward the stake, so a new claim is held to what they already lock.
    #[test]
    fn recovered_locks_are_counted_again_after_a_restart() {
        let _turn = registry_turn();
        let caps = Caps {
            job: Some(500 * HEMI),
            stake: Some(500 * HEMI),
            chain: None,
        };
        let (driven, released, new) = (
            B256::repeat_byte(0xc1),
            B256::repeat_byte(0xc2),
            B256::repeat_byte(0xc3),
        );
        assert_eq!(
            check(new, &job(0xc3, 0xc3, 400 * HEMI), caps),
            CapVerdict::Admit
        );
        record(driven, job(0xc1, 0xc1, 250 * HEMI));
        record_settling(released, 200 * HEMI);
        // A settling entry never replaces what a lock already counts.
        record_settling(driven, 1);
        assert_eq!(
            check(new, &job(0xc3, 0xc3, 100 * HEMI), caps),
            CapVerdict::OverStake {
                held: 450 * HEMI,
                required: 100 * HEMI,
                cap: 500 * HEMI
            }
        );
        assert_eq!(
            check(new, &job(0xc3, 0xc3, 50 * HEMI), caps),
            CapVerdict::Admit
        );
        forget(driven);
        forget(released);
        assert_eq!(
            check(new, &job(0xc3, 0xc3, 400 * HEMI), caps),
            CapVerdict::Admit
        );
    }

    /// The stake-wide caps at localnet's 1,000 HEMI stake, with the chain's figure `chain`.
    fn stake_caps(chain: Option<ChainLocked>) -> Caps {
        Caps {
            job: Some(500 * HEMI),
            stake: Some(500 * HEMI),
            chain,
        }
    }

    fn read(locked: u128, read_block: Option<u64>) -> Option<ChainLocked> {
        Some(ChainLocked { locked, read_block })
    }

    /// CH-1: a lure locks half the stake and its task hands the lock back (or the miner restarts and
    /// recovery has not found it again): the registry holds nothing, but the chain's own figure still
    /// shows the lock, so a second lure is refused, where the registry alone admitted it.
    #[test]
    fn a_lock_the_registry_lost_still_counts_through_the_chain_figure() {
        let id = B256::repeat_byte(0xd1);
        let lure = job(0xd1, 0xd1, 490 * HEMI);
        let empty = HashMap::new();
        // The registry alone: admitted (the hole).
        assert_eq!(
            decide(id, &lure, stake_caps(None), &empty),
            CapVerdict::Admit
        );
        let v = decide(id, &lure, stake_caps(read(500 * HEMI, Some(100))), &empty);
        assert_eq!(
            v,
            CapVerdict::OverStake {
                held: 500 * HEMI,
                required: 490 * HEMI,
                cap: 500 * HEMI
            }
        );
        assert!(!v.is_final());
        assert!(v.describe().unwrap().contains("on chain"));
        // A reading of no known block still counts its figure.
        assert!(matches!(
            decide(id, &lure, stake_caps(read(500 * HEMI, None)), &empty),
            CapVerdict::OverStake { .. }
        ));
        // Room left on chain: admitted.
        assert_eq!(
            decide(id, &lure, stake_caps(read(10 * HEMI, Some(100))), &empty),
            CapVerdict::Admit
        );
    }

    /// A claim sent but not in the chain's figure yet (pending, or mined after the read) counts on top
    /// of it; once the figure is read at or after its lock block it is in the figure, and is not
    /// counted twice.
    #[test]
    fn a_claim_counts_on_top_of_the_chain_figure_until_a_read_includes_it() {
        let (a, b, new) = (
            B256::repeat_byte(0xd2),
            B256::repeat_byte(0xd3),
            B256::repeat_byte(0xd4),
        );
        let held = HashMap::from([(a, job(0xd2, 0xd2, 200 * HEMI))]);
        let other = job(0xd4, 0xd4, 100 * HEMI);
        // The chain shows 300 HEMI of other locks (a hand-back), read at block 110.
        let caps = stake_caps(read(300 * HEMI, Some(110)));
        // Pending (no lock block yet): 300 + 200 = 500, no room.
        let pending = decide_with(new, &other, caps, &held, &HashMap::new());
        assert_eq!(
            pending,
            CapVerdict::OverStake {
                held: 500 * HEMI,
                required: 100 * HEMI,
                cap: 500 * HEMI
            }
        );
        // Mined after the read: still on top.
        let after = HashMap::from([(a, 120u64)]);
        assert_eq!(decide_with(new, &other, caps, &held, &after), pending);
        // Mined by the read: the figure has it (its 300 then holds a's 200): room for 100 more.
        for at in [105u64, 110] {
            let by = HashMap::from([(a, at)]);
            assert_eq!(
                decide_with(new, &other, caps, &held, &by),
                CapVerdict::Admit,
                "{at}"
            );
        }
        // Never under what the registry holds: a low figure does not hide what is held here.
        let more = HashMap::from([
            (a, job(0xd2, 0xd2, 200 * HEMI)),
            (b, job(0xd3, 0xd3, 250 * HEMI)),
        ]);
        let by = HashMap::from([(a, 100u64), (b, 100u64)]);
        assert_eq!(
            decide_with(new, &other, stake_caps(read(0, Some(110))), &more, &by),
            CapVerdict::OverStake {
                held: 450 * HEMI,
                required: 100 * HEMI,
                cap: 500 * HEMI
            }
        );
        // The job's own entry is not counted against it, pending or not.
        let own = HashMap::from([(new, other)]);
        assert_eq!(
            decide_with(
                new,
                &other,
                stake_caps(read(400 * HEMI, Some(110))),
                &own,
                &HashMap::new()
            ),
            CapVerdict::Admit
        );
    }

    /// A stale (or missing) stake read gives the registry-only rule, as before the chain figure.
    #[test]
    fn a_stale_reading_falls_back_to_the_registry_alone() {
        let stake = zkminer_chain::staking::StakeInfo {
            total_staked: 1_000 * HEMI,
            locked_collateral: 500 * HEMI,
            available_collateral: 500 * HEMI,
            unstake_amount: 0,
            unstake_request_time: 0,
            deposit_block: 0,
            read_block: Some(100),
        };
        let fresh = caps_at(Some(&stake), true);
        assert_eq!(fresh.chain, read(500 * HEMI, Some(100)));
        assert_eq!(fresh.job, caps(1_000 * HEMI).job);
        assert_eq!(fresh.stake, caps(1_000 * HEMI).stake);
        assert_eq!(caps_at(Some(&stake), false).chain, None);
        assert_eq!(caps_at(None, true), caps(0));
        let (held_id, id) = (B256::repeat_byte(0xd5), B256::repeat_byte(0xd6));
        let small = job(0xd6, 0xd6, 50 * HEMI);
        let held = |c| HashMap::from([(held_id, job(0xd5, 0xd5, c))]);
        assert_eq!(
            decide(id, &small, stake_caps(None), &held(450 * HEMI)),
            CapVerdict::Admit
        );
        assert!(matches!(
            decide(id, &small, stake_caps(None), &held(451 * HEMI)),
            CapVerdict::OverStake { .. }
        ));
        // Freshness is the refresh's staleness ceiling.
        assert!(fresh_reading(Some(chrono::Utc::now())));
        assert!(!fresh_reading(None));
        assert!(!fresh_reading(Some(
            chrono::Utc::now() - chrono::Duration::seconds(3_600)
        )));
    }

    /// A lock handed back to recovery (its task ended, the journal still holds it) stays in the
    /// registry, with its lock block; it leaves once the journal drops it (fulfilled, released, found
    /// ended).
    #[test]
    fn a_handed_back_lock_counts_while_the_journal_holds_it() {
        let _turn = registry_turn();
        let caps = stake_caps(None);
        let (back, live, new) = (
            B256::repeat_byte(0xe1),
            B256::repeat_byte(0xe2),
            B256::repeat_byte(0xe3),
        );
        let now = chrono::Utc::now().timestamp() as u64;
        let mut journal = crate::journal::JobJournal::default();
        journal.mark_claimed(back, None, now + 600);
        record(back, job(0xe1, 0xe1, 300 * HEMI));
        record(live, job(0xe2, 0xe2, 150 * HEMI));
        note_lock_block(back, 90);
        // `back`'s task handed it back: no longer in flight, but journalled.
        let journalled = journalled_locks(&journal, now);
        assert!(journalled.contains(&back));
        forget_unless_journalled(back, &journalled);
        let in_flight = HashSet::from([live]);
        retain(|j| in_flight.contains(j) || journalled.contains(j));
        assert!(matches!(
            check(new, &job(0xe3, 0xe3, 100 * HEMI), caps),
            CapVerdict::OverStake { held, .. } if held == 450 * HEMI
        ));
        // Its lock block is kept with it: a read after it has it in the figure, not on top of it.
        let with_chain = stake_caps(read(300 * HEMI, Some(95)));
        assert!(matches!(
            check(new, &job(0xe3, 0xe3, 100 * HEMI), with_chain),
            CapVerdict::OverStake { held, .. } if held == 450 * HEMI
        ));
        assert_eq!(
            check(new, &job(0xe3, 0xe3, 50 * HEMI), with_chain),
            CapVerdict::Admit
        );
        // Released by recovery: the journal drops it, and so does the next pass.
        journal.remove(back);
        let journalled = journalled_locks(&journal, now);
        retain(|j| in_flight.contains(j) || journalled.contains(j));
        assert_eq!(
            check(new, &job(0xe3, 0xe3, 300 * HEMI), caps),
            CapVerdict::Admit
        );
        // A task whose lock settled (not journalled) leaves at once.
        forget_unless_journalled(live, &journalled);
        assert_eq!(
            check(new, &job(0xe3, 0xe3, 500 * HEMI), caps),
            CapVerdict::Admit
        );
    }

    /// An entry counts until an hour past its cutoff and the prover grace (or, with no cutoff, past
    /// the claim-intent age), then no longer.
    #[test]
    fn a_journal_entry_long_past_its_window_stops_counting() {
        let grace = zkminer_chain::auction::PROVER_GRACE_SECS;
        let cutoff = 1_000_000u64;
        let last = cutoff + grace + JOURNAL_STALE_AFTER_SECS;
        assert!(journal_entry_counts(cutoff, 0, cutoff));
        assert!(journal_entry_counts(cutoff, 0, last));
        assert!(!journal_entry_counts(cutoff, 0, last + 1));
        // A claim not yet seen locked: by its age.
        let claimed = 2_000_000i64;
        let last =
            claimed as u64 + super::super::CLAIM_INTENT_MAX_AGE_SECS + JOURNAL_STALE_AFTER_SECS;
        assert!(journal_entry_counts(0, claimed, last));
        assert!(!journal_entry_counts(0, claimed, last + 1));
        let mut journal = crate::journal::JobJournal::default();
        let (old, fresh) = (B256::repeat_byte(0xe4), B256::repeat_byte(0xe5));
        journal.mark_claimed(old, None, cutoff);
        journal.mark_claimed(fresh, None, cutoff + 10 * 3600);
        assert_eq!(
            journalled_locks(&journal, cutoff + grace + 2 * 3600),
            HashSet::from([fresh])
        );
    }

    /// A recovered lock being released counts at what it locked when that is known, not the floor,
    /// and a figure read after it was recorded at the floor raises it.
    #[test]
    fn a_recovered_release_counts_at_its_real_collateral() {
        let _turn = registry_turn();
        let caps = stake_caps(None);
        let (rel, raised, new) = (
            B256::repeat_byte(0xe6),
            B256::repeat_byte(0xe7),
            B256::repeat_byte(0xe8),
        );
        record_settling(rel, 300 * HEMI);
        assert!(matches!(
            check(new, &job(0xe8, 0xe8, 250 * HEMI), caps),
            CapVerdict::OverStake { held, .. } if held == 300 * HEMI
        ));
        // Recorded at the floor, then its terms were read: raised, never lowered.
        record_settling(raised, FLOOR);
        raise(raised, 150 * HEMI);
        raise(raised, 1);
        assert!(matches!(
            check(new, &job(0xe8, 0xe8, 100 * HEMI), caps),
            CapVerdict::OverStake { held, .. } if held == 450 * HEMI
        ));
        // A job not counted is not added by a raise.
        raise(new, 400 * HEMI);
        forget(rel);
        forget(raised);
        assert_eq!(
            check(new, &job(0xe8, 0xe8, 500 * HEMI), caps),
            CapVerdict::Admit
        );
    }

    /// Every claim path holds a job to the same stake-wide inputs: the brain's claims and the witness
    /// gate both build their caps with the chain's figure (`caps_at`), and both note lock blocks; a
    /// task that ends keeps its lock counted while the journal holds it.
    #[test]
    fn every_claim_path_counts_the_chain_figure() {
        let run = include_str!("../run.rs");
        let witness = include_str!("witness/runtime.rs");
        assert!(run.contains("collateral::caps_at("));
        assert!(witness.contains("run::collateral::caps_at("));
        assert!(!witness.contains("run::collateral::caps(total"));
        assert!(run.contains("collateral::note_lock_block(job_id, block)"));
        assert!(witness.contains("run::collateral::note_lock_block(jid, l.lock_block)"));
        assert!(run.contains("collateral::forget_unless_journalled(jid, &journalled)"));
        assert!(run.contains("|| journalled.contains(j)"));
    }
}
