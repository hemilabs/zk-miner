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

use std::collections::HashMap;
use std::time::{Duration, Instant};

use alloy::primitives::B256;

/// No successful chain read for this long, with a lock held, pages. Well past a refresh's normal
/// period (15 s) and the claim-freshness hold (35 s), so one slow or failed read does not.
pub(crate) const UNREACHABLE_AFTER: Duration = Duration::from_secs(60);

/// How often CHAIN-UNREACHABLE is repeated while the outage lasts.
pub(crate) const UNREACHABLE_REPEAT: Duration = Duration::from_secs(5 * 60);

/// How often the watch looks.
const TICK: Duration = Duration::from_secs(5);

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
}

impl Watch {
    pub(crate) fn new(now: Instant) -> Self {
        Watch {
            started: now,
            outage: None,
            paged: None,
            at_risk: HashMap::new(),
        }
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

/// Run the watch until aborted: every few seconds, the age of the last refresh and the journal's
/// locks, and the pages they call for.
pub(crate) fn spawn(
    state: zkminer_tui::state::SharedState,
    journal: super::SharedJournal,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let margin = super::DEADLINE_RELEASE_MARGIN_SECS;
        let mut watch = Watch::new(Instant::now());
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
            for a in watch.step(Instant::now(), age, &held, chain_now, margin) {
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
