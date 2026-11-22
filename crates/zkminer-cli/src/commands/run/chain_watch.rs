//! The chain-loss watch (review r6 D2): a page when the miner has lost the chain while it holds
//! locks, and one per lock whose cutoff comes inside its release margin meanwhile.
//!
//! Fulfils, releases and the state refresh all go through the one `[chain] rpc_url`, so a miner cut
//! off from it (a flooded link, an on-path drop, a dead provider) can neither prove nor give back
//! what it holds, and every lock is slashed at its deadline plus grace. Before this, nothing said so:
//! the refresh failure was a debug line, the claim hold a WARN, and the first page (LOCK-LATE) came
//! after the deadline. The watch keys on the age of the last successful refresh (the same
//! `last_refresh` the claim-freshness hold reads) and on the journal, the record of every lock held:
//! - `PAGE: CHAIN-UNREACHABLE` once no refresh has succeeded for [`UNREACHABLE_AFTER`] while a lock
//!   is held, again every [`UNREACHABLE_REPEAT`] while it lasts;
//! - `PAGE: LOCK-AT-RISK <job>` meanwhile, for each lock whose recorded cutoff is within the release
//!   margin (`DEADLINE_RELEASE_MARGIN_SECS`): the miner would be releasing it now, and cannot. Once,
//!   and once more at half the time that was left. Judged on the host clock's chain-time estimate,
//!   which needs no RPC.
//!
//! Nothing is paged while no lock is held: an idle miner that lost the chain loses nothing.
//!
//! On Windows the watch also recycles workers (review r6 G-1). A Low-integrity worker keeps the
//! network, so one whose guest broke out of its executor can cut the miner off its RPC without
//! ending it (the host's ephemeral ports held open, or the uplink flooded): nothing crashes, so the
//! crash-loop guard never counts it, and every lock runs to a slash. When no chain read has
//! succeeded for [`RECYCLE_AFTER`] while locks are held and workers run, the watch looks for the
//! symptom: the sockets each worker's processes hold (`zkminer_prover::netwatch`; an honest worker
//! holds none while it proves). Only the workers past the limits are stopped, busy or not
//! (`PAGE: WORKERS-RECYCLED`, naming each slot, its pids and its sockets); a proof stopped that way
//! is retried without counting an attempt (`zkminer_prover::dispatcher::WorkerRecycled`). When no
//! worker holds sockets, no proof is stopped: only idle workers, and the page says the link or the
//! endpoint is down. Rate limits do not hold it back: a worker found holding sockets is stopped
//! while the endpoint answers 429s (which such a worker could cause itself).
//!
//! An outage anyone can cause must not churn the cards, so the stops are spaced: at least
//! [`RECYCLE_GAP_FIRST`] after the last one, doubling with each in the last [`RECYCLE_WINDOW`] up
//! to [`RECYCLE_GAP_MAX`], whatever the chain did after each. A stop of workers found holding
//! sockets needs only [`RECYCLE_GAP_FIRST`]: it had evidence, not timing. More than one can come in
//! one outage. On Linux a confined worker has no socket at all, so it is not done there.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::B256;
use zkminer_prover::netwatch::{Limits, SlotSockets};

/// No successful chain read for this long, with a lock held, pages. Well past a refresh's normal
/// period (15 s) and the claim-freshness hold (35 s), so one slow or failed read does not.
pub(crate) const UNREACHABLE_AFTER: Duration = Duration::from_secs(60);

/// How often CHAIN-UNREACHABLE is repeated while the outage lasts.
pub(crate) const UNREACHABLE_REPEAT: Duration = Duration::from_secs(5 * 60);

/// How often the watch looks.
const TICK: Duration = Duration::from_secs(5);

/// Whether an outage recycles the workers: where they can reach the network (see the module docs).
const RECYCLE_ON_OUTAGE: bool = cfg!(windows);

/// No chain read for this long, with locks held and workers running, recycles the workers. Long
/// enough that an honest blip never kills a proof, short of the shortest lock's deadline plus grace
/// (about 35 min) by more than the release margin, so a recycle that frees the link still leaves
/// time to release.
pub(crate) const RECYCLE_AFTER: Duration = Duration::from_secs(10 * 60);

/// The least time between two recycles, and all a stop of workers found holding sockets waits.
pub(crate) const RECYCLE_GAP_FIRST: Duration = Duration::from_secs(30 * 60);

/// The most the gap between two recycles grows to.
pub(crate) const RECYCLE_GAP_MAX: Duration = Duration::from_secs(4 * 3600);

/// The recycles that double the gap: those in the last day.
pub(crate) const RECYCLE_WINDOW: Duration = Duration::from_secs(24 * 3600);

/// A lock on record: its job and its recorded cutoff (unix seconds, 0 unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeldLock {
    pub job: B256,
    pub cutoff: u64,
}

/// What a look at the chain's state calls for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// `PAGE: CHAIN-UNREACHABLE`: no chain read for `secs` with `locks` held, the earliest cutoff
    /// `earliest` (0 unknown).
    Unreachable {
        secs: u64,
        locks: usize,
        earliest: u64,
    },
    /// `PAGE: LOCK-AT-RISK`: `job`'s cutoff is `left` seconds away, inside its release margin.
    AtRisk { job: B256, left: u64, cutoff: u64 },
    /// The chain answers again after an outage that was paged.
    Restored { secs: u64 },
}

/// The watch's memory between looks.
pub(crate) struct Watch {
    /// When the watch started: the age of chain data never read.
    started: Instant,
    /// The outage under way: when it was first seen.
    outage: Option<Instant>,
    /// When CHAIN-UNREACHABLE was last paged in this outage.
    paged: Option<Instant>,
    /// Locks paged at risk in this outage: the time that was left when first paged, and whether the
    /// second page went out.
    at_risk: HashMap<B256, (u64, bool)>,
    /// When the workers were recycled, within the last [`RECYCLE_WINDOW`], oldest first.
    recycles: VecDeque<Instant>,
}

impl Watch {
    pub(crate) fn new(now: Instant) -> Self {
        Watch {
            started: now,
            outage: None,
            paged: None,
            at_risk: HashMap::new(),
            recycles: VecDeque::new(),
        }
    }

    /// Whether the outage calls for a look at the workers' sockets now: no chain read for
    /// [`RECYCLE_AFTER`] (`age`, as in [`Watch::step`]) while a lock is on record (`holding`) and a
    /// prove worker is up (`workers_running`). Rate limits do not veto it (see the module docs).
    pub(crate) fn recycle_look_due(
        &self,
        now: Instant,
        age: Option<Duration>,
        holding: bool,
        workers_running: bool,
    ) -> bool {
        let age = age.unwrap_or_else(|| now.saturating_duration_since(self.started));
        age >= RECYCLE_AFTER && holding && workers_running
    }

    /// The least time after the last recycle before the next: [`RECYCLE_GAP_FIRST`] doubled for each
    /// recycle in the last [`RECYCLE_WINDOW`] after the first, up to [`RECYCLE_GAP_MAX`]; just
    /// [`RECYCLE_GAP_FIRST`] when the look `found` workers holding sockets.
    pub(crate) fn recycle_gap(&mut self, now: Instant, found: bool) -> Duration {
        while self
            .recycles
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= RECYCLE_WINDOW)
        {
            self.recycles.pop_front();
        }
        let n = self.recycles.len() as u32;
        if found || n <= 1 {
            return RECYCLE_GAP_FIRST;
        }
        RECYCLE_GAP_FIRST
            .saturating_mul(1u32 << (n - 1).min(16))
            .min(RECYCLE_GAP_MAX)
    }

    /// Whether a recycle may run now, after a look that `found` (or did not) workers holding
    /// sockets; if so, recorded as done.
    pub(crate) fn recycle_now(&mut self, now: Instant, found: bool) -> bool {
        let gap = self.recycle_gap(now, found);
        let due = self
            .recycles
            .back()
            .is_none_or(|t| now.saturating_duration_since(*t) >= gap);
        if due {
            self.recycles.push_back(now);
        }
        due
    }

    /// One look. `age`: since the last successful refresh (`None`: none yet). `held`: the journal's
    /// locks. `chain_now`: the chain-time estimate. `margin`: the release margin.
    pub(crate) fn step(
        &mut self,
        now: Instant,
        age: Option<Duration>,
        held: &[HeldLock],
        chain_now: u64,
        margin: u64,
    ) -> Vec<Action> {
        let mut out = Vec::new();
        let age = age.unwrap_or_else(|| now.saturating_duration_since(self.started));
        if age < UNREACHABLE_AFTER {
            if let Some(since) = self.outage.take() {
                if self.paged.is_some() {
                    out.push(Action::Restored {
                        secs: now.saturating_duration_since(since).as_secs() + age.as_secs(),
                    });
                }
            }
            self.paged = None;
            self.at_risk.clear();
            return out;
        }
        self.outage.get_or_insert(now);
        self.at_risk
            .retain(|job, _| held.iter().any(|h| h.job == *job));
        if held.is_empty() {
            return out;
        }
        if self
            .paged
            .is_none_or(|t| now.saturating_duration_since(t) >= UNREACHABLE_REPEAT)
        {
            self.paged = Some(now);
            out.push(Action::Unreachable {
                secs: age.as_secs(),
                locks: held.len(),
                earliest: held
                    .iter()
                    .filter(|h| h.cutoff != 0)
                    .map(|h| h.cutoff)
                    .min()
                    .unwrap_or(0),
            });
        }
        for h in held {
            if h.cutoff == 0 || chain_now.saturating_add(margin) < h.cutoff {
                continue;
            }
            let left = h.cutoff.saturating_sub(chain_now);
            let page = match self.at_risk.get_mut(&h.job) {
                None => {
                    self.at_risk.insert(h.job, (left, false));
                    true
                }
                Some((first, again)) if !*again && left <= *first / 2 => {
                    *again = true;
                    true
                }
                Some(_) => false,
            };
            if page {
                out.push(Action::AtRisk {
                    job: h.job,
                    left,
                    cutoff: h.cutoff,
                });
            }
        }
        out
    }
}

/// The page text for `a`.
pub(crate) fn describe(a: &Action, margin: u64) -> String {
    match a {
        Action::Unreachable {
            secs,
            locks,
            earliest,
        } => format!(
            "PAGE: CHAIN-UNREACHABLE — no successful chain read for {secs}s while holding {locks} \
             lock(s) (earliest cutoff {}); they can be neither fulfilled nor released until it \
             returns, and each is slashed in full at its cutoff plus grace. Check this host's link \
             and the RPC endpoint ([chain] rpc_url)",
            if *earliest == 0 {
                "unknown".to_string()
            } else {
                zkminer_chain::exit::fmt_unix(*earliest)
            }
        ),
        Action::AtRisk { job, left, cutoff } => format!(
            "PAGE: LOCK-AT-RISK {} — its cutoff is in {left}s ({}), inside the {margin}s a release \
             needs, and the chain is unreachable: it is slashed in full unless the chain comes back \
             in time",
            super::short_id(*job),
            zkminer_chain::exit::fmt_unix(*cutoff)
        ),
        Action::Restored { secs } => {
            format!("chain reachable again after about {secs}s without a successful read")
        }
    }
}

/// The page for a recycle after `secs` without a chain read, with `locks` held, that stops the
/// workers of `suspects` (each slot with its pids and sockets), found past `limits`.
pub(crate) fn describe_recycle(
    secs: u64,
    locks: usize,
    suspects: &[SlotSockets],
    limits: &Limits,
) -> String {
    let slots: Vec<String> = suspects
        .iter()
        .map(|s| {
            let mut pids: Vec<String> = s.pids.iter().take(8).map(|p| p.to_string()).collect();
            if s.pids.len() > 8 {
                pids.push(format!("+{} more", s.pids.len() - 8));
            }
            format!(
                "{} ({}, pid {}: {})",
                s.slot,
                if s.busy { "busy" } else { "idle" },
                pids.join(" "),
                s.sockets
            )
        })
        .collect();
    format!(
        "PAGE: WORKERS-RECYCLED — no chain read for {secs}s with {locks} lock(s) held, and {} \
         worker(s) held more network sockets than a prover does (over {} TCP or {} UDP; {} and {} \
         set the limits): stopped {}. Each starts again when next needed; a proof stopped this way \
         is retried and not counted against its job or card. A worker holding sockets may be \
         holding this host's network: see which job it was proving",
        suspects.len(),
        limits.tcp,
        limits.udp,
        zkminer_prover::netwatch::TCP_MAX_ENV,
        zkminer_prover::netwatch::UDP_MAX_ENV,
        slots.join("; ")
    )
}

/// The page for a look that found no worker holding sockets (or could not read them: `error`),
/// after `secs` without a chain read with `locks` held; `idle` idle workers were stopped.
pub(crate) fn describe_no_suspects(
    secs: u64,
    locks: usize,
    idle: usize,
    error: Option<&str>,
) -> String {
    let found = match error {
        None => "no worker holds network sockets, so the link or the RPC endpoint ([chain] \
                 rpc_url) is down"
            .to_string(),
        Some(e) => format!("the workers' sockets could not be read ({e})"),
    };
    format!(
        "PAGE: CHAIN-UNREACHABLE — no chain read for {secs}s with {locks} lock(s) held, and \
         {found}. No proof was stopped; {idle} idle worker(s) were (each starts again when next \
         needed)"
    )
}

/// What a recycle stopped: the workers found holding sockets, or (none found) the idle ones; or
/// workers found holding sockets that the gap since the last recycle held back.
enum Stopped {
    Suspects(Vec<SlotSockets>),
    Idle(usize, Option<String>),
    HeldBack(Vec<SlotSockets>),
}

/// The outage recycle, off the runtime (it reads the system's socket tables and ends processes):
/// look at each worker's sockets and, if the gap allows, stop those past the limits, or the idle
/// workers when none is. `None` when nothing was done (and nobody held sockets).
fn recycle(now: Instant, watch: &std::sync::Mutex<Watch>) -> Option<Stopped> {
    let pool = zkminer_prover::engine::worker_pool()?;
    let limits = Limits::from_env();
    let survey = pool.worker_sockets();
    let suspects: Vec<SlotSockets> = match &survey {
        Ok(all) => zkminer_prover::netwatch::suspects(all, &limits)
            .into_iter()
            .cloned()
            .collect(),
        Err(_) => Vec::new(),
    };
    let found = !suspects.is_empty();
    if !watch
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .recycle_now(now, found)
    {
        return found.then_some(Stopped::HeldBack(suspects));
    }
    if found {
        let keys: Vec<String> = suspects.iter().map(|s| s.slot.clone()).collect();
        let stopped = pool.stop_slots(&keys);
        tracing::warn!("outage recycle: stopped {stopped:?}");
        Some(Stopped::Suspects(suspects))
    } else {
        let idle = pool.stop_idle_slots();
        Some(Stopped::Idle(
            idle.len(),
            survey.err().map(|e| e.to_string()),
        ))
    }
}

/// Run the watch until aborted: every few seconds, the age of the last refresh and the journal's
/// locks, and the pages (and, on Windows, the worker recycle) they call for.
pub(crate) fn spawn(
    state: zkminer_tui::state::SharedState,
    journal: super::SharedJournal,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let margin = super::DEADLINE_RELEASE_MARGIN_SECS;
        let watch = Arc::new(std::sync::Mutex::new(Watch::new(Instant::now())));
        // When workers held back by the recycle gap were last logged.
        let mut held_back_noted: Option<Instant> = None;
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            let age = state
                .read()
                .await
                .last_refresh
                .map(|t| (chrono::Utc::now() - t).to_std().unwrap_or(Duration::ZERO));
            let held: Vec<HeldLock> = {
                let j = journal.lock().unwrap_or_else(|p| p.into_inner());
                j.entries
                    .values()
                    .map(|e| HeldLock {
                        job: e.job_id,
                        cutoff: e.lock_deadline,
                    })
                    .collect()
            };
            let chain_now = zkminer_chain::client::chain_now();
            let now = Instant::now();
            let workers_running = zkminer_prover::engine::worker_pool()
                .is_some_and(|p| !p.connected_backends().is_empty());
            // Not while stopping: the shutdown reaps the workers itself.
            let look = RECYCLE_ON_OUTAGE
                && !super::SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst)
                && watch
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .recycle_look_due(now, age, !held.is_empty(), workers_running);
            if look {
                let w = watch.clone();
                let done = tokio::task::spawn_blocking(move || recycle(now, &w))
                    .await
                    .ok()
                    .flatten();
                let secs = age.map_or(0, |a| a.as_secs());
                match done {
                    Some(Stopped::Suspects(s)) => tracing::error!(
                        "{}",
                        describe_recycle(secs, held.len(), &s, &Limits::from_env())
                    ),
                    Some(Stopped::Idle(n, e)) => tracing::error!(
                        "{}",
                        describe_no_suspects(secs, held.len(), n, e.as_deref())
                    ),
                    Some(Stopped::HeldBack(s))
                        if held_back_noted.is_none_or(|t| {
                            now.saturating_duration_since(t) >= UNREACHABLE_REPEAT
                        }) =>
                    {
                        held_back_noted = Some(now);
                        let slots: Vec<String> = s
                            .iter()
                            .map(|s| format!("{} ({})", s.slot, s.sockets))
                            .collect();
                        tracing::warn!(
                            "workers hold network sockets during the outage, not stopped yet (the \
                             last recycle was less than {} min ago): {}",
                            RECYCLE_GAP_FIRST.as_secs() / 60,
                            slots.join("; ")
                        );
                    }
                    Some(Stopped::HeldBack(_)) | None => {}
                }
            }
            let actions = watch
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .step(now, age, &held, chain_now, margin);
            for a in actions {
                let text = describe(&a, margin);
                match a {
                    Action::Restored { .. } => tracing::warn!("{text}"),
                    _ => tracing::error!("{text}"),
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARGIN: u64 = 600;

    fn lock(b: u8, cutoff: u64) -> HeldLock {
        HeldLock {
            job: B256::repeat_byte(b),
            cutoff,
        }
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn unreachable_pages(a: &[Action]) -> usize {
        a.iter()
            .filter(|a| matches!(a, Action::Unreachable { .. }))
            .count()
    }

    #[test]
    fn chain_unreachable_pages_after_a_minute_with_locks_held_then_every_five_minutes() {
        let t0 = Instant::now();
        let mut w = Watch::new(t0);
        let held = [lock(1, 1_000_000)];
        // A refresh 30 s old is normal.
        assert!(w.step(t0, Some(secs(30)), &held, 0, MARGIN).is_empty());
        // 90 s: one page.
        let a = w.step(t0 + secs(5), Some(secs(90)), &held, 0, MARGIN);
        assert_eq!(
            a,
            vec![Action::Unreachable {
                secs: 90,
                locks: 1,
                earliest: 1_000_000
            }]
        );
        // Not again inside five minutes, however often it looks.
        let mut n = 0;
        for i in 1..60 {
            n += unreachable_pages(&w.step(
                t0 + secs(5 + i * 5),
                Some(secs(90 + i * 5)),
                &held,
                0,
                MARGIN,
            ));
        }
        assert_eq!(n, 0);
        // Five minutes after the first: again.
        let a = w.step(t0 + secs(305), Some(secs(390)), &held, 0, MARGIN);
        assert_eq!(unreachable_pages(&a), 1);
        // The chain answers: said once, and a new outage pages anew.
        let a = w.step(t0 + secs(310), Some(secs(3)), &held, 0, MARGIN);
        assert!(matches!(a[..], [Action::Restored { .. }]));
        let a = w.step(t0 + secs(400), Some(secs(70)), &held, 0, MARGIN);
        assert_eq!(unreachable_pages(&a), 1);
    }

    #[test]
    fn nothing_pages_while_no_lock_is_held_or_before_the_first_minute() {
        let t0 = Instant::now();
        let mut w = Watch::new(t0);
        assert!(w.step(t0, Some(secs(600)), &[], 0, MARGIN).is_empty());
        // Never refreshed: counted from the watch's start.
        let mut w = Watch::new(t0);
        assert!(w
            .step(t0 + secs(30), None, &[lock(1, 0)], 0, MARGIN)
            .is_empty());
        assert_eq!(
            unreachable_pages(&w.step(t0 + secs(61), None, &[lock(1, 0)], 0, MARGIN)),
            1
        );
    }

    #[test]
    fn lock_at_risk_pages_inside_the_margin_once_and_again_at_half_the_time_left() {
        let t0 = Instant::now();
        let mut w = Watch::new(t0);
        let now = 10_000;
        // One inside the margin (500 s left), one outside it (an hour).
        let held = [lock(1, now + 500), lock(2, now + 3_600)];
        let a = w.step(t0, Some(secs(120)), &held, now, MARGIN);
        let risks: Vec<_> = a
            .iter()
            .filter(|a| matches!(a, Action::AtRisk { .. }))
            .collect();
        assert_eq!(
            risks,
            vec![&Action::AtRisk {
                job: B256::repeat_byte(1),
                left: 500,
                cutoff: now + 500
            }]
        );
        // Not again until half of the 500 s is gone.
        let a = w.step(t0 + secs(100), Some(secs(220)), &held, now + 100, MARGIN);
        assert!(!a.iter().any(|a| matches!(a, Action::AtRisk { .. })));
        let a = w.step(t0 + secs(260), Some(secs(380)), &held, now + 260, MARGIN);
        assert!(a.contains(&Action::AtRisk {
            job: B256::repeat_byte(1),
            left: 240,
            cutoff: now + 500
        }));
        // And never a third time.
        let a = w.step(t0 + secs(400), Some(secs(520)), &held, now + 400, MARGIN);
        assert!(!a.iter().any(|a| matches!(a, Action::AtRisk { .. })));
    }

    #[test]
    fn a_lock_inside_its_margin_is_not_at_risk_while_the_chain_answers() {
        // The miner is releasing it then; a fulfilled one leaves the journal.
        let t0 = Instant::now();
        let mut w = Watch::new(t0);
        assert!(w
            .step(t0, Some(secs(10)), &[lock(1, 10_100)], 10_000, MARGIN)
            .is_empty());
    }

    #[test]
    fn a_look_is_due_after_ten_minutes_with_locks_held_and_workers_running_rate_limits_or_not() {
        let t0 = Instant::now();
        let w = Watch::new(t0);
        assert!(!w.recycle_look_due(t0, Some(secs(599)), true, true));
        assert!(!w.recycle_look_due(t0, Some(secs(700)), false, true));
        assert!(!w.recycle_look_due(t0, Some(secs(700)), true, false));
        assert!(w.recycle_look_due(t0, Some(secs(700)), true, true));
        // Never read: counted from the watch's start.
        assert!(w.recycle_look_due(t0 + RECYCLE_AFTER, None, true, true));
        // No rate-limit veto: the look takes no such input (review r7 LD-4/C7-7).
        let src = include_str!("chain_watch.rs");
        let body = &src[src.find("    pub(crate) fn recycle_look_due(").unwrap()..];
        let body = &body[..body.find("\n    }\n").unwrap()];
        assert!(!body.contains("rate_limited"));
    }

    #[test]
    fn the_gap_doubles_per_recycle_in_a_day_whatever_the_chain_did_after_each() {
        let t0 = Instant::now();
        let held = [lock(1, 0)];
        let mut w = Watch::new(t0);
        // The first: at once.
        assert!(w.recycle_now(t0, false));
        // The chain is back a minute later (the old "helped" case): the gap does not reset.
        w.step(t0 + secs(60), Some(secs(5)), &held, 0, MARGIN);
        // Within the first gap: no; after it: yes, and more than once in one outage.
        assert!(!w.recycle_now(t0 + RECYCLE_GAP_FIRST - secs(1), false));
        let t1 = t0 + RECYCLE_GAP_FIRST;
        assert!(w.recycle_now(t1, false));
        // Two in the day: the next waits twice the first gap.
        assert_eq!(w.recycle_gap(t1, false), RECYCLE_GAP_FIRST * 2);
        assert!(!w.recycle_now(t1 + RECYCLE_GAP_FIRST * 2 - secs(1), false));
        let t2 = t1 + RECYCLE_GAP_FIRST * 2;
        assert!(w.recycle_now(t2, false));
        assert_eq!(w.recycle_gap(t2, false), RECYCLE_GAP_FIRST * 4);
        // ... up to the ceiling.
        let mut t = t2;
        for _ in 0..6 {
            t += RECYCLE_GAP_MAX;
            assert!(w.recycle_now(t, false));
        }
        assert_eq!(w.recycle_gap(t, false), RECYCLE_GAP_MAX);
        // Workers found holding sockets need only the first gap.
        assert_eq!(w.recycle_gap(t, true), RECYCLE_GAP_FIRST);
        assert!(!w.recycle_now(t + RECYCLE_GAP_FIRST - secs(1), true));
        assert!(w.recycle_now(t + RECYCLE_GAP_FIRST, true));
        // A day without one: back to the first gap.
        let later = t + RECYCLE_GAP_FIRST + RECYCLE_WINDOW;
        assert_eq!(w.recycle_gap(later, false), RECYCLE_GAP_FIRST);
        assert!(w.recycle_now(later, false));
    }

    #[test]
    fn there_is_no_helped_reset() {
        let src = include_str!("chain_watch.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        for gone in [
            "RECYCLE_HELPED_WITHIN",
            "recycled_this_outage",
            "rate_limited",
        ] {
            assert!(!code.contains(gone), "{gone} is back");
        }
    }

    #[test]
    fn the_recycle_is_paged_and_only_where_workers_have_the_network() {
        let suspect = SlotSockets {
            slot: "risc0:cuda:0".to_string(),
            pids: vec![100, 101],
            age: Some(secs(900)),
            sockets: zkminer_prover::netwatch::Sockets {
                tcp_established: 3,
                tcp_other: 4_000,
                udp: 0,
            },
            busy: true,
        };
        let p = describe_recycle(700, 2, &[suspect], &Limits::DEFAULT);
        assert!(p.starts_with("PAGE: WORKERS-RECYCLED — no chain read for 700s with 2 lock(s)"));
        assert!(p.contains("risc0:cuda:0 (busy, pid 100 101: 4003 TCP (3 established), 0 UDP)"));
        assert!(p.contains("not counted against its job or card"));
        assert!(p.contains("ZKMINER_RECYCLE_TCP_MAX"));
        let n = describe_no_suspects(700, 2, 1, None);
        assert!(n.starts_with("PAGE: CHAIN-UNREACHABLE — no chain read for 700s"));
        assert!(
            n.contains("no worker holds network sockets") && n.contains("No proof was stopped")
        );
        assert!(
            describe_no_suspects(700, 2, 0, Some("denied")).contains("could not be read (denied)")
        );
        assert_eq!(RECYCLE_ON_OUTAGE, cfg!(windows));
    }

    #[test]
    fn the_pages_say_what_is_at_stake() {
        let u = describe(
            &Action::Unreachable {
                secs: 90,
                locks: 2,
                earliest: 0,
            },
            MARGIN,
        );
        assert!(u.starts_with("PAGE: CHAIN-UNREACHABLE — no successful chain read for 90s"));
        assert!(u.contains("neither fulfilled nor released"));
        let r = describe(
            &Action::AtRisk {
                job: B256::repeat_byte(1),
                left: 120,
                cutoff: 1_700_000_000,
            },
            MARGIN,
        );
        assert!(r.starts_with("PAGE: LOCK-AT-RISK "));
        assert!(r.contains("in 120s") && r.contains("600s a release needs"));
    }
}
