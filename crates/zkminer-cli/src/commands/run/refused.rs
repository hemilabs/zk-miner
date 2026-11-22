//! Windows: what `zkminer run` does when it refuses its account with locks in the journal (review 5
//! X-G, review 6 CR6-1). Proving them would run requesters' guests as that account, and refusing
//! outright strands them until they are slashed. Releasing them all at once (what this did before)
//! cost every lock its release penalty the moment the process started, before a human could see the
//! page and restart the miner as the right account, which would have proved them.
//!
//! So the refused process holds them: it starts no worker and claims nothing, pages every
//! [`PAGE_EVERY`], and releases each lock only once its cutoff comes within the keep horizon (the
//! margin a keep-locks stop releases at, `keep_horizon`). The release penalty is the job's flat
//! snapshot (5% by default), so a release at the horizon costs what one at once does, and every
//! minute before it is a minute to restart the miner correctly. `zkminer stop` is answered: a drain
//! goes on releasing each lock at its horizon and exits once none is left (review 7 WR-5: exiting
//! at once left the locks to a full slash under a service set to stay stopped on 0), a keep-locks
//! stop exits keeping what is held, an abandon releases everything now, and
//! `zkminer run --release-held` releases everything at once from the start.
//!
//! Like the main run, it keeps Windows awake while it holds locks (`keep_awake`, review 7 DI-1): a
//! PC that idles into sleep turns each horizon release (5%) into a full slash. And it keeps the
//! slash latch (review 7 LD-1): its own releases are noted, and the stake baseline stays current,
//! so the next correct start does not read them as an unexplained fall.

use super::*;

/// How often the hold loop looks at the journal and the stop request.
const TICK: std::time::Duration = std::time::Duration::from_secs(5);

/// How often the hold loop pages.
const PAGE_EVERY: std::time::Duration = std::time::Duration::from_secs(300);

/// How often the hold loop reads the stake for the slash latch.
const LATCH_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// A gap of chain time between two ticks longer than this means the loop was not running (the PC
/// slept): `PAGE: SLEPT-WHILE-HOLDING`. Above the longest a tick's own chain reads can take.
const SLEPT_AFTER_SECS: u64 = 180;

/// How long after a release that left its lock held (a pause, a state it could not read) the lock is
/// tried again.
const RETRY_SECS: u64 = 60;

/// What the hold loop weighs of one lock in the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Held {
    pub job_id: B256,
    /// The recorded cutoff (unix seconds), 0 when unknown.
    pub lock_deadline: u64,
    pub claimed_at: i64,
    /// A fulfil gave up with its nonce stashed: only the job's own release displaces it.
    pub abandoned_nonce: bool,
}

impl Held {
    /// The cutoff the schedule counts with: the recorded one, or for an unknown one the contract's
    /// shortest window from the claim (as `keep_too_close` does).
    fn cutoff(&self) -> u64 {
        if self.lock_deadline != 0 {
            self.lock_deadline
        } else {
            (self.claimed_at.max(0) as u64).saturating_add(MIN_JOB_WINDOW_SECS)
        }
    }

    /// Whether its recorded cutoff has passed at `now`: nothing releases it any more, and the
    /// release only cleans the breadcrumb up.
    fn past(&self, now: u64) -> bool {
        self.lock_deadline != 0 && self.lock_deadline <= now
    }
}

/// Which held locks to release, and when: each at its keep horizon, or all at once
/// (`--release-held`, or an abandon stop). Pure, so a test can drive it with a fake clock.
#[derive(Debug, Default)]
pub(super) struct Schedule {
    /// Release every lock now, whatever its cutoff.
    pub release_all: bool,
    /// Releases started and not yet ended.
    in_flight: std::collections::HashSet<B256>,
    /// Locks a release was tried for at least once.
    attempted: std::collections::HashSet<B256>,
    /// A lock whose release ended with it still held, and when to try again.
    retry_at: std::collections::HashMap<B256, u64>,
}

impl Schedule {
    /// The locks of `held` to start releasing at `now` (chain time), whose keep horizon is
    /// `horizon`: those whose cutoff is within it (a past one included) or that have an abandoned
    /// nonce, or every one under `release_all`; none already being released or waiting to be tried
    /// again. Nearest cutoff first: a release's nonce is its on-chain priority.
    pub fn due(&mut self, held: &[Held], now: u64, horizon: u64) -> Vec<B256> {
        let mut due: Vec<&Held> = held
            .iter()
            .filter(|h| !self.in_flight.contains(&h.job_id))
            .filter(|h| self.retry_at.get(&h.job_id).is_none_or(|t| *t <= now))
            .filter(|h| self.release_all || h.abandoned_nonce || h.cutoff() <= horizon)
            .collect();
        due.sort_by_key(|h| h.cutoff());
        due.into_iter()
            .map(|h| {
                self.in_flight.insert(h.job_id);
                self.attempted.insert(h.job_id);
                self.retry_at.remove(&h.job_id);
                h.job_id
            })
            .collect()
    }

    /// The release of `job_id` ended at `now`, leaving its lock `still_held` or not.
    pub fn ended(&mut self, job_id: B256, still_held: bool, now: u64) {
        self.in_flight.remove(&job_id);
        if still_held {
            self.retry_at.insert(job_id, now.saturating_add(RETRY_SECS));
        }
    }

    /// Whether the loop is done with `held` at `now`: nothing is held, or no release is running and
    /// what is left can no longer be helped, each lock tried once and past its cutoff (or, under
    /// `release_all`, tried once: the rest is the next start's, as before).
    pub fn settled(&self, held: &[Held], now: u64) -> bool {
        self.in_flight.is_empty()
            && held
                .iter()
                .all(|h| self.attempted.contains(&h.job_id) && (self.release_all || h.past(now)))
    }

    /// When the first lock not yet being released will be (chain time): its cutoff less the keep
    /// horizon's lead (`lead`, the horizon less now), or `None` when there is none.
    pub fn next_release(&self, held: &[Held], lead: u64) -> Option<u64> {
        held.iter()
            .filter(|h| !self.attempted.contains(&h.job_id))
            .map(|h| h.cutoff().saturating_sub(lead))
            .min()
    }
}

/// Whether the hold loop keeps Windows awake: while it holds a lock, or a release is in flight.
pub(super) fn awake_wanted(held: &[Held], in_flight: bool) -> bool {
    !held.is_empty() || in_flight
}

/// The locks of `held` whose cutoff passed between two ticks at `before` and `now` (chain time),
/// when that gap is too long for the process to have been running: it slept.
pub(super) fn slept_past(held: &[Held], before: u64, now: u64) -> Option<Vec<B256>> {
    if now.saturating_sub(before) <= SLEPT_AFTER_SECS {
        return None;
    }
    Some(
        held.iter()
            .filter(|h| h.lock_deadline > before && h.lock_deadline <= now)
            .map(|h| h.job_id)
            .collect(),
    )
}

/// What the hold loop does with a `zkminer stop` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OnStop {
    /// Go on holding and releasing each lock at its horizon, and exit 0 once none is left (a
    /// drain: nothing is proving, and exiting would leave every lock to its slash).
    Drain,
    /// Exit at once, keeping every lock not yet released, with this exit code: 75 for a keep-locks
    /// stop (a service set to restart on it starts the miner again, which holds them again).
    Keep(i32),
    /// Release every lock now, then exit 0.
    ReleaseAll,
    /// Exit at once, releasing nothing more (as `--force-exit` everywhere).
    Force,
}

/// [`OnStop`] for `mode`, and the answer `zkminer stop` prints.
pub(super) fn on_stop(mode: zkminer_tui::state::StopMode) -> (OnStop, &'static str) {
    use zkminer_tui::state::StopMode;
    match mode {
        StopMode::Drain => (
            OnStop::Drain,
            "refused account: nothing is proving, so it goes on releasing each lock it holds as \
             its cutoff comes near and exits once none is left; `zkminer stop --keep-locks` exits \
             now keeping them (to prove them as the right account), `zkminer stop --abandon` \
             releases them now",
        ),
        StopMode::KeepLocks => (
            OnStop::Keep(75),
            "refused account: it exits now (75) and keeps the locks it holds",
        ),
        StopMode::Abandon => (
            OnStop::ReleaseAll,
            "refused account: releasing every lock it holds now, then exiting",
        ),
        StopMode::Force => (OnStop::Force, "exiting at once, releasing nothing"),
    }
}

/// The journal's locks, as the schedule weighs them.
fn held_of(journal: &SharedJournal, client: &ChainClient) -> Vec<Held> {
    let j = journal.lock().unwrap_or_else(|p| p.into_inner());
    j.iter()
        .map(|e| Held {
            job_id: e.job_id,
            lock_deadline: e.lock_deadline,
            claimed_at: e.claimed_at,
            abandoned_nonce: client.has_abandoned_nonce(e.job_id),
        })
        .collect()
}

/// The page the hold loop repeats: what it holds, when it releases, and what to do.
fn hold_page(refusal: &str, held: &[Held], next: Option<u64>, release_all: bool) -> String {
    let earliest = held
        .iter()
        .map(|h| h.lock_deadline)
        .filter(|d| *d > 0)
        .min()
        .map_or_else(|| "unknown".to_string(), zkminer_chain::exit::fmt_unix);
    let when = match (release_all, next) {
        (true, _) => "releasing each now".to_string(),
        (false, Some(t)) => format!(
            "releasing each only near its cutoff, the first at {}",
            zkminer_chain::exit::fmt_unix(t)
        ),
        (false, None) => "every one is being released".to_string(),
    };
    format!(
        "PAGE: PRIVILEGED-ACCOUNT refused; holding {} lock(s) without proving them (earliest \
         cutoff {earliest}), {when}. This process keeps Windows awake while it holds them; a \
         sleep or shutdown asked for still happens and turns each release into a slash. To prove \
         them instead, stop this process (`zkminer stop --keep-locks`, or stop the service) and \
         start the miner as a dedicated standard user, or from a console that is not elevated; \
         to release them all now, `zkminer stop --abandon` or `zkminer run --release-held`. \
         {refusal}",
        held.len()
    )
}

/// The refusal and, lock by lock, what became of the ones that were held.
fn report(refusal: &str, journal: &SharedJournal, ids: &[B256]) -> String {
    let j = journal.lock().unwrap_or_else(|p| p.into_inner());
    let lines: Vec<String> = ids
        .iter()
        .map(|&jid| match j.entries.contains_key(&jid) {
            false => format!("  {jid}: released"),
            true => format!(
                "  {jid}: NOT released ({}); the next start tries again",
                kept_reason_of(jid).unwrap_or_else(|| "not released yet".into())
            ),
        })
        .collect();
    format!(
        "{refusal}\n\n{} lock(s) were held in {}; no worker was started and none was proven:\n{}",
        ids.len(),
        JobJournal::default_path().display(),
        lines.join("\n")
    )
}

/// The hold loop (see the module docs). `release_held`: release everything at once
/// (`zkminer run --release-held`).
pub(super) async fn hold_and_release(
    config_path: Option<&Path>,
    refusal: &str,
    release_held: bool,
) -> Result<()> {
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_for_chain()?;
    hold_instance_lock("miner")?;
    // Nothing here claims, but every check of it says the same.
    HELD_LOCKS_ONLY.store(true, std::sync::atomic::Ordering::SeqCst);
    let journal = JobJournal::load_checked().map_err(|e| {
        anyhow::anyhow!(
            "{}",
            refused_account_mode(refusal.to_string(), Some(Err(e))).unwrap_err()
        )
    })?;
    let ids: Vec<B256> = journal.iter().map(|e| e.job_id).collect();
    let client = ChainClient::new(&config, load_signer(&config.wallet)?).await?;
    // Its releases are noted and the stake baseline kept, as in the main run (review 7 LD-1).
    slash_latch::init(client.chain_id, client.address, true);
    let state = new_shared_state();
    let journal: SharedJournal = Arc::new(Mutex::new(journal));
    let mut schedule = Schedule {
        release_all: release_held,
        ..Default::default()
    };
    let (ended_tx, mut ended_rx) = tokio::sync::mpsc::unbounded_channel::<B256>();
    let mut last_page: Option<std::time::Instant> = None;
    let mut last_latch: Option<std::time::Instant> = None;
    let mut last_now: Option<u64> = None;
    let mut exit_code = None;
    // A keep-locks stop: exit once the releases already sent end.
    let mut keep_stop = false;
    loop {
        let now = zkminer_chain::client::chain_now_floor();
        let horizon = keep_horizon();
        let mut release_ended = false;
        while let Ok(jid) = ended_rx.try_recv() {
            let still = journal
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entries
                .contains_key(&jid);
            schedule.ended(jid, still, now);
            release_ended = true;
        }
        // The stake for the slash latch: every LATCH_EVERY, and after each release that ended.
        if release_ended || last_latch.is_none_or(|t| t.elapsed() >= LATCH_EVERY) {
            last_latch = Some(std::time::Instant::now());
            if let Ok(data) = client.get_refresh_batch().await {
                slash_latch::observe(data.stats.as_ref(), data.stake.as_ref());
                slash_latch::explain_pending(&client).await;
            }
            slash_latch::page_again_if_due();
        }
        if let Some(request) = take_stop_request_file() {
            let word = request.as_ref().map_or("unknown", |m| stop_mode_word(*m));
            match request {
                Err(why) => write_stop_response(word, &Err(why)),
                Ok(mode) => {
                    let (action, answer) = on_stop(mode);
                    write_stop_response(word, &Ok(answer.to_string()));
                    tracing::warn!("stop requested: {answer}");
                    match action {
                        OnStop::Force => force_exit(),
                        OnStop::Drain => {
                            exit_code = Some(0);
                            keep_stop = false;
                        }
                        OnStop::Keep(code) => {
                            exit_code = Some(code);
                            keep_stop = true;
                            schedule.release_all = false;
                        }
                        OnStop::ReleaseAll => {
                            schedule.release_all = true;
                            keep_stop = false;
                            exit_code = Some(0);
                        }
                    }
                }
            }
        }
        let held = held_of(&journal, &client);
        // Asleep it releases nothing, and a lock whose cutoff passes meanwhile is slashed in full.
        keep_awake(awake_wanted(&held, !schedule.in_flight.is_empty()));
        if let Some(missed) = last_now.and_then(|before| slept_past(&held, before, now)) {
            let ids: Vec<String> = missed.iter().map(|j| short_id(*j)).collect();
            tracing::error!(
                "PAGE: SLEPT-WHILE-HOLDING — this loop did not run for {} s while holding {} \
                 lock(s) (the PC slept, the process was suspended, or its chain reads hung); {} \
                 passed {} cutoff meanwhile and cannot be released any more{}",
                now.saturating_sub(last_now.unwrap_or(now)),
                held.len(),
                missed.len(),
                if missed.len() == 1 { "its" } else { "their" },
                if ids.is_empty() {
                    String::new()
                } else {
                    format!(": {}", ids.join(", "))
                }
            );
        }
        last_now = Some(now);
        // A keep stop waits only for the releases already sent.
        if keep_stop && !schedule.release_all {
            if schedule.in_flight.is_empty() {
                break;
            }
        } else {
            if schedule.settled(&held, now) {
                break;
            }
            for jid in schedule.due(&held, now, horizon) {
                let past = held.iter().any(|h| h.job_id == jid && h.past(now));
                tracing::warn!("releasing job {} (refused account)", short_id(jid));
                // Nonces in cutoff order; one past its recorded cutoff reserves none (most send
                // nothing).
                let pre_nonce = if past {
                    None
                } else {
                    client.reserve_nonce().await.ok()
                };
                let (c, st, jr, tx) = (
                    client.clone(),
                    state.clone(),
                    journal.clone(),
                    ended_tx.clone(),
                );
                tokio::spawn(async move {
                    release_and_clean_with_nonce(&c, &st, &jr, jid, pre_nonce).await;
                    let _ = tx.send(jid);
                });
            }
        }
        if !held.is_empty() && last_page.is_none_or(|t| t.elapsed() >= PAGE_EVERY) {
            last_page = Some(std::time::Instant::now());
            let next = schedule.next_release(&held, horizon.saturating_sub(now));
            tracing::error!("{}", hold_page(refusal, &held, next, schedule.release_all));
        }
        tokio::time::sleep(TICK).await;
    }
    keep_awake(false);
    let text = report(refusal, &journal, &ids);
    match exit_code {
        Some(0) => {
            tracing::warn!("{text}");
            Ok(())
        }
        Some(code) => {
            tracing::warn!("{text}");
            std::process::exit(code);
        }
        None => anyhow::bail!("{text}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(byte: u8, lock_deadline: u64) -> Held {
        Held {
            job_id: B256::repeat_byte(byte),
            lock_deadline,
            claimed_at: 0,
            abandoned_nonce: false,
        }
    }

    /// Review 6 CR6-1: three locks, the nearest inside the keep horizon. Only it is released on the
    /// first tick; the others each once the clock brings their cutoff within the horizon; a release
    /// that left its lock held is tried again after [`RETRY_SECS`]; and the loop is settled only
    /// once nothing is left that a release could still help.
    #[test]
    fn a_refused_account_releases_each_lock_at_its_horizon() {
        let lead = 3_000;
        let t0 = 1_900_000_000;
        let locks = [
            held(1, t0 + 1_000),
            held(2, t0 + 10_000),
            held(3, t0 + 20_000),
        ];
        let mut s = Schedule::default();
        assert_eq!(s.due(&locks, t0, t0 + lead), vec![locks[0].job_id]);
        // Already in flight: not started twice.
        assert!(s.due(&locks, t0 + 5, t0 + 5 + lead).is_empty());
        assert_eq!(s.next_release(&locks, lead), Some(t0 + 10_000 - lead));
        s.ended(locks[0].job_id, false, t0 + 30);
        let left = &locks[1..];
        assert!(!s.settled(left, t0 + 30));
        // Just before the second's horizon: nothing; at it: the second only.
        let at = t0 + 10_000 - lead;
        assert!(s.due(left, at - 1, at - 1 + lead).is_empty());
        assert_eq!(s.due(left, at, at + lead), vec![locks[1].job_id]);
        // A release that kept its lock (a pause) is tried again after RETRY_SECS, not before.
        s.ended(locks[1].job_id, true, at + 10);
        assert!(s
            .due(
                left,
                at + 10 + RETRY_SECS - 1,
                at + 10 + RETRY_SECS - 1 + lead
            )
            .is_empty());
        let retry = at + 10 + RETRY_SECS;
        assert_eq!(s.due(left, retry, retry + lead), vec![locks[1].job_id]);
        s.ended(locks[1].job_id, false, retry);
        let at = t0 + 20_000 - lead;
        assert_eq!(s.due(&locks[2..], at, at + lead), vec![locks[2].job_id]);
        assert!(!s.settled(&locks[2..], at));
        s.ended(locks[2].job_id, true, at + 5);
        // Tried, still held, and its cutoff not yet past: keep at it.
        assert!(!s.settled(&locks[2..], at + 5));
        // Past its cutoff: nothing more to do.
        assert!(s.settled(&locks[2..], t0 + 20_001));
        assert!(s.settled(&[], t0));
    }

    /// `--release-held` (and an abandon stop) release every lock at once, nearest cutoff first,
    /// unknown cutoffs counted from the claim; an abandoned nonce is released at once in any mode.
    #[test]
    fn release_held_and_abandoned_nonces_release_at_once() {
        let t0 = 1_900_000_000;
        let unknown = Held {
            claimed_at: t0 as i64,
            ..held(9, 0)
        };
        let locks = [held(1, t0 + 20_000), unknown, held(2, t0 + 10_000)];
        let mut all = Schedule {
            release_all: true,
            ..Default::default()
        };
        assert_eq!(
            all.due(&locks, t0, t0 + 100),
            vec![unknown.job_id, locks[2].job_id, locks[0].job_id]
        );
        for h in &locks {
            all.ended(h.job_id, true, t0 + 1);
        }
        // Each tried once: the rest is the next start's.
        assert!(all.settled(&locks, t0 + 1));
        let stuck = Held {
            abandoned_nonce: true,
            ..held(3, t0 + 50_000)
        };
        let mut s = Schedule::default();
        assert_eq!(s.due(&[stuck, locks[0]], t0, t0 + 100), vec![stuck.job_id]);
    }

    /// A stop request: a drain goes on holding and releasing (review 7 WR-5: exiting 0 at once left
    /// the locks to a full slash under a service set to stay stopped on 0); a keep-locks stop exits
    /// 75 keeping the rest; an abandon releases everything; a force exit is a force exit.
    #[test]
    fn stop_requests_keep_or_release_what_a_refused_account_holds() {
        use zkminer_tui::state::StopMode;
        let (drain, answer) = on_stop(StopMode::Drain);
        assert_eq!(drain, OnStop::Drain);
        assert!(
            answer.contains("--keep-locks") && answer.contains("--abandon"),
            "{answer}"
        );
        assert_eq!(on_stop(StopMode::KeepLocks).0, OnStop::Keep(75));
        assert_eq!(on_stop(StopMode::Abandon).0, OnStop::ReleaseAll);
        assert_eq!(on_stop(StopMode::Force).0, OnStop::Force);
        let page = hold_page("refusing to run", &[held(1, 0)], Some(1_900_000_000), false);
        assert!(page.starts_with("PAGE: PRIVILEGED-ACCOUNT"), "{page}");
        assert!(
            page.contains("--release-held") && page.contains("not elevated"),
            "{page}"
        );
        assert!(page.contains("keeps Windows awake"), "{page}");
    }

    /// Review 7 DI-1: awake while anything is held or being released, and the loop asks for it on
    /// every tick and lets go on its way out.
    #[test]
    fn the_hold_loop_keeps_windows_awake_while_it_holds_locks() {
        assert!(awake_wanted(&[held(1, 0)], false));
        assert!(awake_wanted(&[], true));
        assert!(!awake_wanted(&[], false));
        let src = include_str!("refused.rs");
        let hold = &src[src.find("pub(super) async fn hold_and_release(").unwrap()..];
        let hold = &hold[..hold.find("\n}\n").unwrap()];
        let ask = hold
            .find("keep_awake(awake_wanted(&held, !schedule.in_flight.is_empty()));")
            .expect("asked on every tick");
        assert!(hold.find("let held = held_of(").unwrap() < ask);
        let release = hold
            .find("keep_awake(false);")
            .expect("let go on the way out");
        assert!(release > hold.rfind("tokio::time::sleep(TICK).await;").unwrap());
        // The main run's two holders ask too.
        let run = include_str!("../run.rs");
        assert!(
            run.matches("keep_awake(").count() >= 3,
            "fn + the run's two calls"
        );
        // And the latch is kept here as in the main run (review 7 LD-1 path 3).
        assert!(hold.contains("slash_latch::init(client.chain_id, client.address, true);"));
    }

    /// A gap of chain time between ticks longer than the loop can take is a sleep; the locks whose
    /// cutoff passed in it are named.
    #[test]
    fn a_long_gap_between_ticks_names_the_cutoffs_slept_through() {
        let t0 = 1_900_000_000;
        let locks = [held(1, t0 + 100), held(2, t0 + 5_000), held(3, 0)];
        assert_eq!(slept_past(&locks, t0, t0 + 10), None);
        assert_eq!(slept_past(&locks, t0, t0 + SLEPT_AFTER_SECS), None);
        assert_eq!(
            slept_past(&locks, t0, t0 + 3_600),
            Some(vec![locks[0].job_id])
        );
        assert_eq!(slept_past(&locks[1..], t0, t0 + 3_600), Some(vec![]));
    }
}
