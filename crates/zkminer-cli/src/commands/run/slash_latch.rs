//! The slash latch (review r6 M6-1): after a slash, no new claims until a human clears it.
//!
//! The collateral cap bounds what ONE isolation costs (one round), not an incident. The cap is
//! recomputed from the stake that is left, so a miner that went on claiming after a slash could be
//! lured and cut off again, round after round, until the stake is gone. This latch stops new claims
//! at the first sign of a slash and keeps them stopped across restarts until the operator clears it
//! with `zkminer resume-claims`. Locks already held are still driven: fulfils, releases, recovery and
//! the shutdown never look at it.
//!
//! It trips on:
//! - the prover's on-chain `jobsSlashed` rising (every slash of its locks, its own included);
//! - a lock of ours that ended past its deadline (`EndedPastDeadline`) unless the router's events say
//!   it was released (a release of ours that landed late), or that it slashed itself
//!   ([`classify_past_deadline`], review 7 LD-3);
//! - a fall in `totalStaked` that the chain's own events do not explain (`STAKE-DROP`, review r6
//!   N6-EM-1), or one they name as a slash (`StakeReduced` with `slashed`).
//!
//! A fall is not judged on the reading that sees it (review 7 LD-1): this miner's own releases,
//! withdrawals and stake commands lower the stake too, and the reading can land before the miner has
//! noted its release. A fall that a withdrawal (`unstakeAmount` falling by as much) does not explain
//! is held as a pending fall, persisted, while new claims wait (a soft hold: no page); the next
//! refresh reads the staking contract's `StakeReduced` and `Withdrawn` events over the fall's blocks
//! ([`explain_pending`]). Events that cover it clear it; a slash among them trips; a fall they still
//! do not cover after a few reads, or whose events cannot be read for [`PENDING_FALL_LIMIT_SECS`],
//! falls back to the release penalties this miner noted itself, and trips if those do not cover it.
//!
//! The record is `~/.zkminer/slash_latch.json`, one entry per chain and prover, written atomically
//! (tmp + rename) and, on Windows, labelled like the journal so a Low-integrity worker cannot clear
//! it. A missing file is a fresh baseline (a fresh install, or an upgrade); an unreadable one counts
//! as tripped, so losing the record never resumes claims. A running miner sees a `resume-claims` from
//! another terminal within seconds (it re-reads the file when it changes).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use alloy::primitives::{Address, B256};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The file, in the miner's home.
pub(crate) const FILE_NAME: &str = "slash_latch.json";

/// The command that clears the latch, for every line that names it.
pub(crate) const RESUME_COMMAND: &str = "zkminer resume-claims";

/// A stake fall smaller than this is not reported: rounding in our own penalty figures, never a slash
/// (the smallest lock is the deployment's floor, 100 HEMI on 743111).
pub(crate) const STAKE_DROP_TOLERANCE: u128 = 1_000_000_000_000_000_000;

/// How long before a pending fall a release penalty of ours noted here can explain it, when the
/// chain's events cannot be read. A release mined but not yet seen by the refresh (a lagging
/// replica) is seen within minutes; one never seen (a penalty rounded to 0) must not explain a slash
/// days later.
pub(crate) const OWN_PENALTY_WINDOW_SECS: u64 = 3_600;

/// How long a pending fall waits for the chain's events before the noted penalties decide it.
pub(crate) const PENDING_FALL_LIMIT_SECS: u64 = 600;

/// How many event reads that came back but do not cover a pending fall it takes to decide it on the
/// noted penalties (a replica a block or two behind on logs is seen again on the next refresh).
const UNEXPLAINED_READS: u32 = 3;

/// The widest block range a fall's events are read over (a miner stopped for months reads them in
/// chunks at its start; wider than this, the noted penalties decide).
const MAX_EVENT_RANGE: u64 = 1_000_000;

/// How far back a lock's exit is looked for when its lock block was never recorded.
const PAST_END_LOOKBACK: u64 = 20_000;

/// The longest any one event read may take.
const EVENT_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Noted penalties older than this are dropped whatever happens (they can no longer explain anything).
const CREDIT_KEEP_SECS: u64 = 24 * 3_600;

/// How often a tripped latch is paged again while the miner runs.
pub(crate) const PAGE_REPEAT: Duration = Duration::from_secs(30 * 60);

/// The least time between two looks at the file for a change (a `resume-claims` from elsewhere).
const RELOAD_EVERY: Duration = Duration::from_secs(2);

/// Amounts are kept as decimal strings: JSON numbers above 2^53 do not survive every reader.
mod dec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<u128>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(n) => s.serialize_some(&n.to_string()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u128>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|t| t.parse::<u128>().map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// The whole file: one [`ProverLatch`] per `<chain id>:<prover>` ([`key`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LatchFile {
    #[serde(default)]
    pub provers: BTreeMap<String, ProverLatch>,
}

/// A release penalty of ours not yet seen leave the stake: the fallback explanation of a fall when
/// the chain's events cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OwnPenalty {
    /// Unix seconds when it was noted (before its release was sent, when the penalty read in time).
    pub at: u64,
    #[serde(with = "dec")]
    pub wei: Option<u128>,
    /// The job whose release it is (absent in files written before review 7).
    #[serde(default)]
    pub job: Option<B256>,
    /// Unix seconds when its release was confirmed; `None` while it is being sent.
    #[serde(default)]
    pub confirmed_at: Option<u64>,
}

/// A stake fall that a withdrawal does not explain, waiting for the chain's events (review 7 LD-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingFall {
    /// The block of the reading before the fall (`None`: not known; one chunk back is read).
    #[serde(default)]
    pub after_block: Option<u64>,
    /// The block of the reading that last saw it fall.
    #[serde(default)]
    pub to_block: Option<u64>,
    /// The stake before and after (for the page).
    #[serde(default, with = "dec")]
    pub before: Option<u128>,
    #[serde(default, with = "dec")]
    pub total: Option<u128>,
    /// What a withdrawal does not explain.
    #[serde(default, with = "dec")]
    pub left: Option<u128>,
    /// Unix seconds when first and last seen.
    #[serde(default)]
    pub first_seen: u64,
    #[serde(default)]
    pub last_seen: u64,
    /// Event reads that came back and did not cover it.
    #[serde(default)]
    pub unexplained_reads: u32,
}

impl PendingFall {
    fn left(&self) -> u128 {
        self.left.unwrap_or(0)
    }
}

/// What tripped the latch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Trip {
    /// Unix seconds.
    pub at_unix: u64,
    /// `SLASHED` or `STAKE-DROP`.
    pub kind: String,
    pub reason: String,
    /// What was seen after it, while it stayed tripped (the last few).
    #[serde(default)]
    pub later: Vec<String>,
}

/// The most later events a trip keeps.
const LATER_KEPT: usize = 8;

/// One prover's baseline and latch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProverLatch {
    /// The on-chain `jobsSlashed` last read.
    #[serde(default)]
    pub jobs_slashed_seen: Option<u64>,
    /// `totalStaked` and `unstakeAmount` last read, and the block they were read at.
    #[serde(default, with = "dec")]
    pub total_staked_seen: Option<u128>,
    #[serde(default, with = "dec")]
    pub unstake_seen: Option<u128>,
    #[serde(default)]
    pub block_seen: Option<u64>,
    /// Release penalties of ours that a stake fall has not yet used up.
    #[serde(default)]
    pub own_penalties: Vec<OwnPenalty>,
    /// A fall waiting for the chain's events; new claims wait while it is set.
    #[serde(default)]
    pub pending_fall: Option<PendingFall>,
    /// Set by a trip; cleared only by [`ProverLatch::clear`] (`zkminer resume-claims`).
    #[serde(default)]
    pub tripped: Option<Trip>,
}

/// One refresh's reading. Each field is `None` when its read failed.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Observation {
    pub jobs_slashed: Option<u64>,
    pub total_staked: Option<u128>,
    pub unstake: Option<u128>,
    pub block: Option<u64>,
}

/// Something that trips the latch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Event {
    /// `SLASHED` or `STAKE-DROP`.
    pub kind: &'static str,
    pub detail: String,
}

fn hemi(wei: u128) -> String {
    super::fmt_hemi(wei)
}

impl ProverLatch {
    /// Take one reading. Returns the event it trips on, if any (the latch is then tripped). The
    /// first reading of a field only records it: a missing baseline is never a slash.
    pub(crate) fn observe(&mut self, obs: &Observation, now: u64) -> Option<Event> {
        let mut event = None;
        if let Some(n) = obs.jobs_slashed {
            if let Some(seen) = self.jobs_slashed_seen {
                if n > seen {
                    event = Some(Event {
                        kind: "SLASHED",
                        detail: format!(
                            "{} lock(s) of this prover slashed on chain (jobsSlashed {seen} -> {n})",
                            n - seen
                        ),
                    });
                }
            }
            self.jobs_slashed_seen = Some(n);
        }
        if let (Some(total), Some(unstake)) = (obs.total_staked, obs.unstake) {
            // A replica behind the last reading would show an older stake, and then the newer one
            // again as a fall.
            let older = matches!((obs.block, self.block_seen), (Some(b), Some(seen)) if b < seen);
            if !older {
                self.own_penalties
                    .retain(|p| now.saturating_sub(p.at) <= CREDIT_KEEP_SECS);
                if let (Some(before), Some(unstake_before)) =
                    (self.total_staked_seen, self.unstake_seen)
                {
                    if total < before {
                        let fall = before - total;
                        // `withdrawUnstaked` takes the pending amount out of the stake. (A slash
                        // that caps a pending unstake lowers it too, but `jobsSlashed` counts that.)
                        let withdrawn = unstake_before.saturating_sub(unstake);
                        let left = fall.saturating_sub(withdrawn);
                        if left > STAKE_DROP_TOLERANCE {
                            // Not judged here: the chain's events say whose it is (`explain_pending`).
                            self.note_fall(before, total, left, obs.block, now);
                        }
                    }
                }
                self.total_staked_seen = Some(total);
                self.unstake_seen = Some(unstake);
                if obs.block.is_some() {
                    self.block_seen = obs.block;
                }
            }
        }
        if let Some(e) = &event {
            self.trip(e, now);
        }
        event
    }

    /// Hold a fall of `left` (the stake `before` -> `total`, seen at `block`) for the chain's events.
    /// A second fall before the first is decided widens it.
    fn note_fall(&mut self, before: u128, total: u128, left: u128, block: Option<u64>, now: u64) {
        match &mut self.pending_fall {
            Some(p) => {
                p.left = Some(p.left().saturating_add(left));
                p.total = Some(total);
                if block.is_some() {
                    p.to_block = block;
                }
                p.last_seen = now;
                p.unexplained_reads = 0;
            }
            None => {
                self.pending_fall = Some(PendingFall {
                    after_block: self.block_seen,
                    to_block: block,
                    before: Some(before),
                    total: Some(total),
                    left: Some(left),
                    first_seen: now,
                    last_seen: now,
                    unexplained_reads: 0,
                })
            }
        }
    }

    /// Record a release penalty of ours (`job`, when known), so the stake fall it causes is not read
    /// as a slash when the chain's events cannot be read. `confirmed`: its release was confirmed.
    /// A second note for the same job replaces the first.
    pub(crate) fn note_own_penalty(
        &mut self,
        job: Option<B256>,
        wei: u128,
        now: u64,
        confirmed: bool,
    ) {
        if job.is_some() {
            self.own_penalties.retain(|p| p.job != job);
        }
        if wei > 0 {
            self.own_penalties.push(OwnPenalty {
                at: now,
                wei: Some(wei),
                job,
                confirmed_at: confirmed.then_some(now),
            });
        }
    }

    /// The release of `job` was confirmed: its noted penalty (if any) is now confirmed. `false` when
    /// none was noted.
    fn confirm_own_penalty(&mut self, job: B256, now: u64) -> bool {
        let mut found = false;
        for p in self.own_penalties.iter_mut().filter(|p| p.job == Some(job)) {
            p.confirmed_at = Some(now);
            found = true;
        }
        found
    }

    /// The release of `job` took nothing (its fulfil landed first): forget its penalty.
    fn withdraw_own_penalty(&mut self, job: B256) {
        self.own_penalties.retain(|p| p.job != Some(job));
    }

    /// The range of blocks whose events explain the pending fall, `(after, to]`, if one is pending
    /// and its block is known.
    fn pending_range(&self) -> Option<(u64, u64)> {
        let p = self.pending_fall.as_ref()?;
        let to = p.to_block?;
        let after = p
            .after_block
            .filter(|a| *a <= to)
            .unwrap_or(to.saturating_sub(zkminer_chain::stake_logs::LOG_CHUNK));
        Some((after, to))
    }

    /// The chain's stake events over the range of `queried` (the pending fall when the read began)
    /// came back as `moves`. A slash among them trips; events that cover the fall clear it (and the
    /// noted penalties of releases confirmed by then); events that still do not
    /// cover it after [`UNEXPLAINED_READS`] reads leave it to the noted penalties.
    pub(crate) fn apply_moves(
        &mut self,
        queried: &PendingFall,
        moves: &zkminer_chain::stake_logs::StakeMoves,
        now: u64,
    ) -> Option<Event> {
        if let Some(&(block, amount)) = moves.slashes.first() {
            let more = moves.slashes.len() - 1;
            let e = Event {
                kind: "SLASHED",
                detail: format!(
                    "the staking contract reduced this prover's stake by {} HEMI as a slash at \
                     block {block}{}",
                    hemi(amount),
                    if more > 0 {
                        format!(" (and {more} more slash(es) in the same range)")
                    } else {
                        String::new()
                    }
                ),
            };
            if self.pending_fall.as_ref() == Some(queried) {
                self.pending_fall = None;
            }
            self.trip(&e, now);
            return Some(e);
        }
        // A fall seen meanwhile widened it: the next read covers the new range.
        if self.pending_fall.as_ref() != Some(queried) {
            return None;
        }
        let explained = moves.explained();
        if explained.saturating_add(STAKE_DROP_TOLERANCE) >= queried.left() {
            self.pending_fall = None;
            // The events explained it, so the noted penalties were not needed: a confirmed one is
            // this fall's or one the events explain next, and one noted long ago and never
            // confirmed is stale. Neither may absorb a later, unrelated fall (review 7 VLA-2). Only a
            // release still being sent keeps its note.
            self.own_penalties.retain(|p| {
                p.confirmed_at.is_none() && now.saturating_sub(p.at) <= PENDING_FALL_LIMIT_SECS
            });
            return None;
        }
        if let Some(p) = &mut self.pending_fall {
            p.unexplained_reads += 1;
            if p.unexplained_reads < UNEXPLAINED_READS {
                return None;
            }
        }
        self.decide_on_credits(Some(explained), now)
    }

    /// The chain's events could not be read for the pending fall: once it has waited
    /// [`PENDING_FALL_LIMIT_SECS`], the noted penalties decide it.
    pub(crate) fn moves_unread(&mut self, now: u64) -> Option<Event> {
        let p = self.pending_fall.as_ref()?;
        if now.saturating_sub(p.first_seen) < PENDING_FALL_LIMIT_SECS {
            return None;
        }
        self.decide_on_credits(None, now)
    }

    /// Decide the pending fall on the release penalties noted here (those noted within
    /// [`OWN_PENALTY_WINDOW_SECS`] before it was first seen, oldest first): trip `STAKE-DROP` on what
    /// they do not cover beyond the tolerance. `by_events`: what the chain's events explained, when
    /// they were read.
    fn decide_on_credits(&mut self, by_events: Option<u128>, now: u64) -> Option<Event> {
        let p = self.pending_fall.take()?;
        let since = p.first_seen.saturating_sub(OWN_PENALTY_WINDOW_SECS);
        let mut left = p.left().saturating_sub(by_events.unwrap_or(0));
        for c in self.own_penalties.iter_mut().filter(|c| c.at >= since) {
            let have = c.wei.unwrap_or(0);
            let take = have.min(left);
            c.wei = Some(have - take);
            left -= take;
        }
        self.own_penalties
            .retain(|c| c.wei.unwrap_or(0) > 0 && c.at >= since);
        if left <= STAKE_DROP_TOLERANCE {
            return None;
        }
        let fall = p.before.unwrap_or(0).saturating_sub(p.total.unwrap_or(0));
        let events = match by_events {
            Some(x) => format!(
                "the chain's release and withdrawal events ({} HEMI)",
                hemi(x)
            ),
            None => "the chain's stake events (unreadable)".to_string(),
        };
        let e = Event {
            kind: "STAKE-DROP",
            detail: format!(
                "the stake fell by {} HEMI ({} -> {}, blocks {}..{}) with no slash counted on \
                 chain; a withdrawal, {events} and this miner's noted release penalties leave {} \
                 HEMI unexplained",
                hemi(fall),
                hemi(p.before.unwrap_or(0)),
                hemi(p.total.unwrap_or(0)),
                p.after_block
                    .map_or_else(|| "?".to_string(), |b| b.to_string()),
                p.to_block
                    .map_or_else(|| "?".to_string(), |b| b.to_string()),
                hemi(left)
            ),
        };
        self.trip(&e, now);
        Some(e)
    }

    /// Trip on `e`. An event while already tripped is kept beside the first.
    pub(crate) fn trip(&mut self, e: &Event, now: u64) {
        match &mut self.tripped {
            None => {
                self.tripped = Some(Trip {
                    at_unix: now,
                    kind: e.kind.to_string(),
                    reason: e.detail.clone(),
                    later: Vec::new(),
                })
            }
            Some(t) => {
                if t.later.len() >= LATER_KEPT {
                    t.later.remove(0);
                }
                t.later.push(format!("{}: {}", e.kind, e.detail));
            }
        }
    }

    /// Clear the latch, keeping the baseline. Returns what it held.
    pub(crate) fn clear(&mut self) -> Option<Trip> {
        self.tripped.take()
    }
}

impl Trip {
    /// One line: what, and when.
    pub(crate) fn summary(&self) -> String {
        let more = if self.later.is_empty() {
            String::new()
        } else {
            format!(" (+{} later)", self.later.len())
        };
        format!(
            "{}: {} at {}{more}",
            self.kind,
            self.reason,
            zkminer_chain::exit::fmt_unix(self.at_unix)
        )
    }
}

/// The key of one chain and prover in [`LatchFile::provers`].
pub(crate) fn key(chain_id: u64, prover: Address) -> String {
    format!("{chain_id}:{prover}")
}

/// `~/.zkminer/slash_latch.json`.
pub(crate) fn path() -> PathBuf {
    super::zkminer_home().join(FILE_NAME)
}

/// Read the file. Missing is an empty file (`Ok`); unreadable or unparsable is `Err`.
pub(crate) fn load(path: &Path) -> Result<LatchFile> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("{} does not parse", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(LatchFile::default()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Write the file atomically (tmp + rename); on Windows labelled from its creation, like the journal,
/// so a Low-integrity worker can neither change nor clear it.
pub(crate) fn save(path: &Path, file: &LatchFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let content = serde_json::to_string_pretty(file).context("serialize the slash latch")?;
    #[cfg(windows)]
    let written = zkminer_prover::windows_sandbox::write_secret_file(&tmp, content.as_bytes());
    #[cfg(not(windows))]
    let written = std::fs::write(&tmp, content);
    written.with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// The trip an unreadable file stands for: claims stay stopped until a human looks.
fn unreadable_trip(e: &anyhow::Error, now: u64) -> Trip {
    Trip {
        at_unix: now,
        kind: "SLASHED".into(),
        reason: format!("the slash latch could not be read ({e:#}); treated as tripped"),
        later: Vec::new(),
    }
}

fn unix_now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// The running miner's latch.
struct Live {
    path: PathBuf,
    key: String,
    latch: ProverLatch,
    /// The rest of the file (other chains and provers), written back as read.
    file: LatchFile,
    /// The file's modification time when last read or written here.
    stamp: Option<SystemTime>,
    checked: Instant,
    /// False for a watch-only run: it never writes the file.
    persist: bool,
    last_page: Option<Instant>,
}

static LIVE: Mutex<Option<Live>> = Mutex::new(None);

impl Live {
    /// Re-read the file if it changed since we last read or wrote it (a `resume-claims` from another
    /// terminal). A file gone or unreadable keeps what is in memory.
    fn reload_if_changed(&mut self, force: bool) {
        if !force && self.checked.elapsed() < RELOAD_EVERY {
            return;
        }
        self.checked = Instant::now();
        let now_stamp = modified(&self.path);
        if now_stamp.is_none() || now_stamp == self.stamp {
            return;
        }
        if let Ok(file) = load(&self.path) {
            let was = self.latch.tripped.is_some();
            self.latch = file.provers.get(&self.key).cloned().unwrap_or_default();
            self.file = file;
            self.stamp = now_stamp;
            if was && self.latch.tripped.is_none() {
                tracing::warn!(
                    "slash latch cleared ({RESUME_COMMAND}): claiming resumes. Each further \
                     isolation can again take up to {} of the stake that is left.",
                    super::collateral::STAKE_FRACTION_KEY
                );
                self.last_page = None;
            }
        }
    }

    /// Write the file. Callers re-read it first (`reload_if_changed(true)`) and change it after, all
    /// under the lock, so a clear written by another process is never written over.
    fn persist(&mut self) {
        if !self.persist {
            return;
        }
        self.file
            .provers
            .insert(self.key.clone(), self.latch.clone());
        match save(&self.path, &self.file) {
            Ok(()) => self.stamp = modified(&self.path),
            Err(e) => tracing::warn!(
                "could not save the slash latch ({e:#}); it holds in memory for this run"
            ),
        }
    }

    fn page(&mut self, e: &Event) {
        page_event(e);
        self.last_page = Some(Instant::now());
    }
}

/// Log the page for `e`.
fn page_event(e: &Event) {
    tracing::error!(
        "PAGE: {} — {}; not claiming new work until `{RESUME_COMMAND}`; held locks are still driven",
        e.kind,
        e.detail
    );
}

impl Live {
    /// The latch for `key` in the file at `path`. An unreadable file is a tripped latch.
    fn open(path: PathBuf, key: String, persist: bool) -> Live {
        let (file, latch) = match load(&path) {
            Ok(file) => {
                let latch = file.provers.get(&key).cloned().unwrap_or_default();
                (file, latch)
            }
            Err(e) => {
                let latch = ProverLatch {
                    tripped: Some(unreadable_trip(&e, unix_now())),
                    ..ProverLatch::default()
                };
                (LatchFile::default(), latch)
            }
        };
        Live {
            stamp: modified(&path),
            path,
            key,
            latch,
            file,
            checked: Instant::now(),
            persist,
            last_page: None,
        }
    }

    /// One refresh's reading: page and persist a trip, persist a changed baseline.
    fn observe(&mut self, obs: &Observation) {
        self.reload_if_changed(true);
        let before = self.latch.clone();
        if let Some(e) = self.latch.observe(obs, unix_now()) {
            self.page(&e);
        }
        // Not for the block alone, which moves on every refresh: that would rewrite the file every
        // 15 s. A restart that reads an older block back loses nothing.
        let moved = ProverLatch {
            block_seen: before.block_seen,
            ..self.latch.clone()
        };
        if moved != before {
            self.persist();
        }
    }

    /// Trip on `e` at once, page it and persist it.
    fn trip_now(&mut self, e: &Event) {
        self.reload_if_changed(true);
        self.latch.trip(e, unix_now());
        self.page(e);
        self.persist();
    }

    /// Change the latch with `f` (after a re-read) and persist it if it changed.
    fn update(&mut self, f: impl FnOnce(&mut ProverLatch, u64)) {
        self.reload_if_changed(true);
        let before = self.latch.clone();
        f(&mut self.latch, unix_now());
        if self.latch != before {
            self.persist();
        }
    }

    /// The events read for `queried` (the pending fall when the read began) came back as `read`.
    fn explained(
        &mut self,
        queried: &PendingFall,
        read: Result<zkminer_chain::stake_logs::StakeMoves>,
    ) {
        self.reload_if_changed(true);
        let before = self.latch.clone();
        let now = unix_now();
        let e = match read {
            Ok(moves) => self.latch.apply_moves(queried, &moves, now),
            Err(err) => {
                tracing::debug!("slash latch: the stake events could not be read ({err:#})");
                self.latch.moves_unread(now)
            }
        };
        if let Some(e) = &e {
            self.page(e);
        } else if before.pending_fall.is_some() && self.latch.pending_fall.is_none() {
            tracing::info!("slash latch: the stake fall is explained by the chain's events");
        }
        if self.latch != before {
            self.persist();
        }
    }
}

/// Load the latch for this chain and prover at the start of a run. `persist` false (a watch-only
/// run) never writes the file. A latch already tripped is paged now.
pub(crate) fn init(chain_id: u64, prover: Address, persist: bool) {
    let mut live = Live::open(path(), key(chain_id, prover), persist);
    if let Some(t) = live.latch.tripped.clone() {
        let e = Event {
            kind: "SLASHED",
            detail: format!("tripped since {}", t.summary()),
        };
        live.page(&e);
    }
    *LIVE.lock().unwrap_or_else(|p| p.into_inner()) = Some(live);
}

fn with_live<R>(f: impl FnOnce(&mut Live) -> R) -> Option<R> {
    let mut g = LIVE.lock().unwrap_or_else(|p| p.into_inner());
    g.as_mut().map(f)
}

/// Feed one state refresh (its prover statistics and stake, each `None` when not read). Pages and
/// persists a trip.
pub(crate) fn observe(
    stats: Option<&zkminer_chain::staking::ProverStatistics>,
    stake: Option<&zkminer_chain::staking::StakeInfo>,
) {
    let obs = Observation {
        jobs_slashed: stats.map(|s| s.jobs_slashed),
        total_staked: stake.map(|s| s.total_staked),
        unstake: stake.map(|s| s.unstake_amount),
        block: stake.and_then(|s| s.read_block),
    };
    with_live(|live| live.observe(&obs));
}

/// The event for a lock of ours lost `how`.
fn lock_lost(job_id: B256, how: &str) -> Event {
    Event {
        kind: "SLASHED",
        detail: format!("lock {} {how}", super::short_id(job_id)),
    }
}

/// A lock of ours ended past its deadline, or this miner slashed it itself: trip at once (the next
/// refresh's `jobsSlashed` would too, if the chain counts it).
pub(crate) fn note_lock_lost(job_id: B256, how: &str) {
    let e = lock_lost(job_id, how);
    with_live(|live| live.trip_now(&e));
}

/// Read the chain's stake events for a pending fall and decide it (review 7 LD-1): a slash among
/// them trips, events that cover it clear it, and one left unexplained falls back to the noted
/// release penalties (see the module docs). Call after [`observe`], outside any lock; it returns at
/// once when nothing is pending, so the common cost is one small `eth_getLogs` per fall.
pub(crate) async fn explain_pending(client: &zkminer_chain::client::ChainClient) {
    let Some((queried, range)) = with_live(|live| {
        live.reload_if_changed(false);
        live.latch
            .pending_fall
            .clone()
            .map(|p| (p, live.latch.pending_range()))
    })
    .flatten() else {
        return;
    };
    let read = match range {
        Some((after, to)) if to.saturating_sub(after) <= MAX_EVENT_RANGE => {
            match tokio::time::timeout(EVENT_READ_TIMEOUT, client.stake_moves_in(after, to)).await {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!("timed out")),
            }
        }
        Some((after, to)) => Err(anyhow::anyhow!(
            "blocks {after}..{to} are too many to read the events of"
        )),
        None => Err(anyhow::anyhow!("the block of the fall is not known")),
    };
    with_live(|live| live.explained(&queried, read));
}

/// A release of ours on `job_id` is about to be sent, at `penalty` wei (its job's snapshotted
/// `releasePenaltyBps` of its locked collateral): noted before the send, so a refresh that sees its
/// fall first can fall back on it.
pub(crate) fn note_release_sending(job_id: B256, penalty: u128) {
    with_live(|live| live.update(|l, now| l.note_own_penalty(Some(job_id), penalty, now, false)));
}

/// A release of ours on `job_id` took nothing (its fulfil landed first): forget its penalty.
pub(crate) fn withdraw_own_release(job_id: B256) {
    with_live(|live| live.update(|l, _| l.withdraw_own_penalty(job_id)));
}

/// What releasing `collateral` costs at `penalty_bps`: the router's `releasePenaltyBps ×
/// lockedCollateral / 10,000`, rounded down as it rounds.
pub(crate) fn penalty_of(collateral: u128, penalty_bps: u128) -> u128 {
    collateral.saturating_mul(penalty_bps) / 10_000
}

/// The release penalty of our lock on `job_id`, read while the lock is still on record (its
/// `lockedCollateral` and its snapshotted `releasePenaltyBps`). `None` when either read fails, the
/// record is not ours any more, or it takes too long. The release waits for it 2 s at most.
pub(crate) async fn release_penalty(
    client: zkminer_chain::client::ChainClient,
    job_id: B256,
) -> Option<u128> {
    let read = async {
        let (rec, _) = client.read_job_record(job_id, None).await.ok()?;
        if rec.prover != client.address || rec.locked_collateral == 0 {
            return None;
        }
        let snaps = client.get_job_snapshots_batch(&[job_id]).await.ok()?;
        let (bps, _, _) = snaps.into_iter().next()?.1?;
        Some(penalty_of(rec.locked_collateral, bps))
    };
    tokio::time::timeout(Duration::from_secs(30), read)
        .await
        .ok()
        .flatten()
}

/// A release of ours on `job_id` was confirmed, at `penalty` (`None`: not read). An unread penalty
/// is not guessed: the chain's events explain the fall it causes; only if they cannot be read either
/// may it trip the latch as `STAKE-DROP`, which says so.
pub(crate) fn note_own_release(job_id: B256, penalty: Option<u128>) {
    let noted = with_live(|live| {
        let mut noted = false;
        live.update(|l, now| {
            noted = l.confirm_own_penalty(job_id, now);
            if let Some(p) = penalty {
                l.note_own_penalty(Some(job_id), p, now, true);
                noted = true;
            }
        });
        noted
    })
    .unwrap_or(false);
    if !noted {
        tracing::warn!(
            "release of {}: its penalty could not be read; the chain's events explain the stake \
             fall it causes, and if they cannot be read and the slash latch trips (STAKE-DROP), \
             that fall is this release",
            super::short_id(job_id)
        );
    }
}

/// How a lock of ours that ended past its recorded deadline really ended, by the router's events
/// (review 7 LD-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PastEnd {
    /// A release (or grace release) of ours landed: no slash.
    Released { penalty: u128 },
    /// It was slashed.
    Slashed,
    /// The events could not be read, or name neither: treated as a slash (fail closed).
    Unknown,
}

/// [`PastEnd`] from a lock's exits ([`zkminer_chain::stake_logs::LockExit`]): a slash wins, then a
/// release of ours, else unknown.
pub(crate) fn past_end_of(exits: &[zkminer_chain::stake_logs::LockExit]) -> PastEnd {
    use zkminer_chain::stake_logs::LockExit;
    if exits.iter().any(|e| matches!(e, LockExit::Slashed { .. })) {
        return PastEnd::Slashed;
    }
    match exits.last() {
        Some(LockExit::Released { penalty }) => PastEnd::Released { penalty: *penalty },
        Some(LockExit::GraceReleased) => PastEnd::Released { penalty: 0 },
        _ => PastEnd::Unknown,
    }
}

/// Classify a lock of ours on `job_id` (read locked at `lock_block`, 0 when not recorded) that ended
/// past its recorded deadline, from the router's events since. One classifier for every
/// `EndedPastDeadline` site (review 7 LD-3, VLA-1).
pub(crate) async fn classify_past_deadline(
    client: &zkminer_chain::client::ChainClient,
    job_id: B256,
    lock_block: u64,
) -> PastEnd {
    let read = async {
        let head = client.get_block_number().await?;
        let from = if lock_block != 0 && lock_block <= head {
            lock_block
        } else {
            head.saturating_sub(PAST_END_LOOKBACK)
        };
        if head - from > MAX_EVENT_RANGE {
            anyhow::bail!("blocks {from}..{head} are too many to read the events of");
        }
        client.lock_exits_in(job_id, from, head).await
    };
    match tokio::time::timeout(EVENT_READ_TIMEOUT, read).await {
        Ok(Ok(exits)) => past_end_of(&exits),
        Ok(Err(e)) => {
            tracing::warn!(
                "{}: how its lock ended could not be read ({e:#}); counted as a slash",
                super::short_id(job_id)
            );
            PastEnd::Unknown
        }
        Err(_) => PastEnd::Unknown,
    }
}

/// After a stake command's own confirmed transaction (`stake`, `requestUnstake`, `cancelUnstake`,
/// `withdrawUnstaked`): move this prover's baseline to `after` (its stake and pending unstake, read
/// after the transaction, at `block`), but only when the baseline is the reading `before` the
/// transaction, it is not tripped and no fall is pending. Anything else moved since the miner last
/// looked, and the miner's next start explains that from the chain's events. The miner is not
/// running (the command holds the miner lock), so nothing else writes the file meanwhile.
pub(crate) fn rebaseline_after_own_tx(
    chain_id: u64,
    prover: Address,
    before: (u128, u128),
    after: (u128, u128),
    block: Option<u64>,
) {
    let path = path();
    let Ok(mut file) = load(&path) else {
        return;
    };
    let Some(l) = file.provers.get_mut(&key(chain_id, prover)) else {
        return;
    };
    if !rebaseline(l, before, after, block) {
        return;
    }
    if let Err(e) = save(&path, &file) {
        tracing::warn!("could not update the slash latch baseline ({e:#})");
    }
}

/// [`rebaseline_after_own_tx`] on one entry; `true` when it moved.
fn rebaseline(
    l: &mut ProverLatch,
    before: (u128, u128),
    after: (u128, u128),
    block: Option<u64>,
) -> bool {
    if l.tripped.is_some()
        || l.pending_fall.is_some()
        || l.total_staked_seen != Some(before.0)
        || l.unstake_seen != Some(before.1)
        || before == after
    {
        return false;
    }
    l.total_staked_seen = Some(after.0);
    l.unstake_seen = Some(after.1);
    if block.is_some() {
        l.block_seen = block;
    }
    true
}

/// The trip holding claims now, if any. Cheap: the file is looked at most every few seconds.
pub(crate) fn tripped() -> Option<Trip> {
    with_live(|live| {
        live.reload_if_changed(false);
        live.latch.tripped.clone()
    })
    .flatten()
}

/// Whether a stake fall is waiting for the chain's events (new claims wait meanwhile).
pub(crate) fn fall_pending() -> bool {
    with_live(|live| {
        live.reload_if_changed(false);
        live.latch.pending_fall.is_some()
    })
    .unwrap_or(false)
}

/// The claim hold's reason while tripped, or while a stake fall is being checked.
pub(crate) fn hold_reason() -> Option<String> {
    if let Some(t) = tripped() {
        return Some(format!(
            "a lock of this prover was slashed ({}): claims stop until `{RESUME_COMMAND}`; held \
             locks continue",
            t.summary()
        ));
    }
    fall_pending().then(|| PENDING_SHORT.to_string())
}

/// The claim hold's reason in a word, for callers that take a static string.
pub(crate) const HOLD_SHORT: &str =
    "a lock of this prover was slashed: claims stop until `zkminer resume-claims`";

/// The soft hold's reason: a stake fall is being checked against the chain's events.
pub(crate) const PENDING_SHORT: &str =
    "a stake fall is being checked against the chain's events: new claims wait for it";

/// [`hold_reason`] for callers that take a static string: tripped, or a fall being checked.
pub(crate) fn hold_short() -> Option<&'static str> {
    if tripped().is_some() {
        Some(HOLD_SHORT)
    } else if fall_pending() {
        Some(PENDING_SHORT)
    } else {
        None
    }
}

/// Page again while tripped, every [`PAGE_REPEAT`].
pub(crate) fn page_again_if_due() {
    with_live(|live| {
        let Some(t) = live.latch.tripped.clone() else {
            return;
        };
        if live.last_page.is_none_or(|p| p.elapsed() >= PAGE_REPEAT) {
            let e = Event {
                kind: "SLASHED",
                detail: format!("still tripped: {}", t.summary()),
            };
            live.page(&e);
        }
    });
}

/// What `status` and `doctor` print for `chain_id` and `prover`: whether it is tripped, and the lines.
pub(crate) fn describe(chain_id: u64, prover: Address) -> (bool, Vec<String>) {
    match load(&path()) {
        Err(e) => (
            true,
            vec![format!(
                "unreadable ({e:#}): `zkminer run` treats it as tripped; `{RESUME_COMMAND}` \
                 rewrites it"
            )],
        ),
        Ok(file) => match file.provers.get(&key(chain_id, prover)) {
            Some(ProverLatch {
                tripped: Some(t), ..
            }) => {
                let mut lines = vec![format!(
                    "TRIPPED, not claiming new work: {}. Clear it with `{RESUME_COMMAND}` once \
                     you know why",
                    t.summary()
                )];
                lines.extend(t.later.iter().map(|l| format!("  later: {l}")));
                (true, lines)
            }
            Some(ProverLatch {
                pending_fall: Some(p),
                ..
            }) => (
                false,
                vec![format!(
                    "clear; a stake fall of {} HEMI seen at {} is being checked against the \
                     chain's events (new claims wait for it)",
                    hemi(p.left()),
                    zkminer_chain::exit::fmt_unix(p.first_seen)
                )],
            ),
            Some(_) => (false, vec!["clear (claims allowed)".into()]),
            None => (
                false,
                vec!["clear (no baseline yet: the next `zkminer run` records one)".into()],
            ),
        },
    }
}

/// `zkminer resume-claims`: show every tripped latch in this home and clear it, keeping the baseline.
pub fn resume(yes: bool) -> Result<()> {
    let path = path();
    let mut file = match load(&path) {
        Ok(f) => f,
        Err(e) => {
            println!(
                "{} is unreadable ({e:#}); it will be rewritten clear.",
                path.display()
            );
            crate::commands::signer_guard::confirm("Rewrite it and allow claims again?", yes)?;
            save(&path, &LatchFile::default())?;
            println!("Rewritten: the next refresh records a new baseline.");
            return Ok(());
        }
    };
    let tripped: Vec<(String, Trip)> = file
        .provers
        .iter()
        .filter_map(|(k, p)| p.tripped.clone().map(|t| (k.clone(), t)))
        .collect();
    if tripped.is_empty() {
        println!(
            "No slash latch is tripped in {}: claims are allowed.",
            path.display()
        );
        return Ok(());
    }
    for (k, t) in &tripped {
        println!("{k}: {}", t.summary());
        for l in &t.later {
            println!("    later: {l}");
        }
    }
    println!(
        "\nClaims stopped because a lock of this prover was slashed or its stake fell unexplained. \
         The collateral cap ({}) bounds what ONE isolation costs, of the stake that is left: \
         every further one can take that share again. Check `zkminer status` (the stake now) and \
         why the lock was lost (the RPC link, the card) before resuming.",
        super::collateral::STAKE_FRACTION_KEY
    );
    crate::commands::signer_guard::confirm("Clear the latch and allow new claims?", yes)?;
    for (k, _) in &tripped {
        if let Some(p) = file.provers.get_mut(k) {
            p.clear();
        }
    }
    save(&path, &file)?;
    println!("Cleared. A running miner resumes claiming within seconds.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u128 = 1_000_000_000_000_000_000;

    fn reading(slashed: u64, total: u128, unstake: u128, block: u64) -> Observation {
        Observation {
            jobs_slashed: Some(slashed),
            total_staked: Some(total),
            unstake: Some(unstake),
            block: Some(block),
        }
    }

    #[test]
    fn the_first_reading_is_a_baseline_not_a_trip() {
        let mut l = ProverLatch::default();
        assert_eq!(l.observe(&reading(3, 1_000 * H, 0, 10), 100), None);
        assert!(l.tripped.is_none());
        assert_eq!(l.jobs_slashed_seen, Some(3));
        assert_eq!(l.total_staked_seen, Some(1_000 * H));
    }

    #[test]
    fn a_rise_in_jobs_slashed_trips() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        let e = l.observe(&reading(1, 500 * H, 0, 11), 115).expect("a trip");
        assert_eq!(e.kind, "SLASHED");
        assert!(l.tripped.is_some());
        // Still tripped on the next quiet reading; only a clear lifts it.
        assert_eq!(l.observe(&reading(1, 500 * H, 0, 12), 130), None);
        assert!(l.tripped.is_some());
    }

    #[test]
    fn a_trip_survives_a_save_and_a_reload_and_a_clear_keeps_the_baseline() {
        let dir = std::env::temp_dir().join(format!("zkminer-latch-{}", std::process::id()));
        let path = dir.join(FILE_NAME);
        let k = key(743111, Address::repeat_byte(0x11));
        let mut l = ProverLatch::default();
        l.observe(&reading(0, u128::MAX - 7, 0, 10), 100);
        l.observe(&reading(2, u128::MAX - 7, 0, 11), 115);
        let mut file = LatchFile::default();
        file.provers.insert(k.clone(), l.clone());
        save(&path, &file).unwrap();
        let back = load(&path).unwrap();
        assert_eq!(back, file);
        let mut again = back.provers[&k].clone();
        assert!(again.tripped.is_some());
        assert!(again.clear().is_some());
        assert_eq!(again.jobs_slashed_seen, Some(2));
        assert_eq!(again.total_staked_seen, Some(u128::MAX - 7));
        // A missing file is an empty baseline; a corrupt one is an error (read as tripped).
        assert_eq!(
            load(&dir.join("absent.json")).unwrap(),
            LatchFile::default()
        );
        std::fs::write(&path, b"{not json").unwrap();
        assert!(load(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_withdrawal_is_not_a_stake_drop() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 400 * H, 10), 100);
        assert_eq!(l.observe(&reading(0, 600 * H, 0, 11), 115), None);
        assert!(l.tripped.is_none());
    }

    use zkminer_chain::stake_logs::{LockExit, StakeMoves};

    fn moves(reduced: u128, withdrawn: u128) -> StakeMoves {
        StakeMoves {
            reduced,
            withdrawn,
            slashes: Vec::new(),
        }
    }

    /// Review 7 LD-1: the refresh sees our release's fall before the release is noted. It is held,
    /// not tripped, and the chain's `StakeReduced{slashed: false}` of the same amount clears it.
    #[test]
    fn a_fall_seen_before_its_credit_is_held_and_the_chain_explains_it() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        assert_eq!(l.observe(&reading(0, 995 * H, 0, 12), 115), None);
        assert!(l.tripped.is_none());
        let p = l.pending_fall.clone().expect("held");
        assert_eq!(l.pending_range(), Some((10, 12)));
        assert_eq!(p.left, Some(5 * H));
        // The credit lands only now, after the reading.
        l.note_own_penalty(Some(B256::repeat_byte(1)), 5 * H, 120, true);
        assert_eq!(l.apply_moves(&p, &moves(5 * H, 0), 125), None);
        assert!(l.pending_fall.is_none() && l.tripped.is_none());
        // The credit it covered is dropped: it must not absorb a later fall (VLA-2).
        assert!(l.own_penalties.is_empty());
    }

    #[test]
    fn a_slash_event_trips_even_without_jobs_slashed() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        // jobsSlashed not read on this refresh.
        let obs = Observation {
            jobs_slashed: None,
            ..reading(0, 900 * H, 0, 11)
        };
        assert_eq!(l.observe(&obs, 115), None);
        let p = l.pending_fall.clone().unwrap();
        let m = StakeMoves {
            reduced: 0,
            withdrawn: 0,
            slashes: vec![(11, 100 * H)],
        };
        let e = l.apply_moves(&p, &m, 120).expect("a trip");
        assert_eq!(e.kind, "SLASHED");
        assert!(e.detail.contains("block 11"), "{}", e.detail);
        assert!(l.tripped.is_some() && l.pending_fall.is_none());
    }

    /// Events that come back and do not cover the fall: a few reads (a replica behind on logs),
    /// then the noted penalties decide, and what they leave trips STAKE-DROP.
    #[test]
    fn an_unexplained_stake_fall_trips_after_a_few_reads() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        l.note_own_penalty(None, 5 * H, 105, true);
        l.observe(&reading(0, 895 * H, 0, 11), 115);
        let p = l.pending_fall.clone().unwrap();
        assert_eq!(l.apply_moves(&p, &moves(0, 0), 120), None);
        let p = l.pending_fall.clone().unwrap();
        assert_eq!(l.apply_moves(&p, &moves(0, 0), 135), None);
        let p = l.pending_fall.clone().unwrap();
        let e = l.apply_moves(&p, &moves(0, 0), 150).expect("a trip");
        assert_eq!(e.kind, "STAKE-DROP");
        assert!(e.detail.contains("105.00"), "{}", e.detail);
        assert!(e.detail.contains("100.00 HEMI unexplained"), "{}", e.detail);
        assert!(l.tripped.is_some() && l.pending_fall.is_none());
    }

    /// Events unreadable: nothing is decided before PENDING_FALL_LIMIT_SECS; then the noted
    /// penalties do. A fall they cover clears; one they do not, trips.
    #[test]
    fn unreadable_events_fall_back_to_the_noted_penalties_after_the_limit() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        l.note_own_penalty(Some(B256::repeat_byte(1)), 10 * H, 105, false);
        l.observe(&reading(0, 990 * H, 0, 11), 115);
        assert_eq!(l.moves_unread(115 + PENDING_FALL_LIMIT_SECS - 1), None);
        assert!(l.pending_fall.is_some(), "still held, not tripped");
        assert_eq!(l.moves_unread(115 + PENDING_FALL_LIMIT_SECS), None);
        assert!(l.pending_fall.is_none() && l.tripped.is_none());
        assert!(l.own_penalties.is_empty(), "used up");
        // A fall no penalty covers trips at the limit.
        l.observe(&reading(0, 900 * H, 0, 12), 2_000);
        assert_eq!(l.moves_unread(2_000 + 60), None);
        let e = l
            .moves_unread(2_000 + PENDING_FALL_LIMIT_SECS)
            .expect("a trip");
        assert_eq!(e.kind, "STAKE-DROP");
        assert!(e.detail.contains("unreadable"), "{}", e.detail);
    }

    #[test]
    fn a_penalty_too_old_explains_nothing_and_rounding_is_tolerated() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        l.note_own_penalty(None, 100 * H, 100, true);
        let later = 100 + OWN_PENALTY_WINDOW_SECS + 1;
        l.observe(&reading(0, 900 * H, 0, 11), later);
        assert!(l.moves_unread(later + PENDING_FALL_LIMIT_SECS).is_some());
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        assert_eq!(l.observe(&reading(0, 1_000 * H - H / 2, 0, 11), 115), None);
        assert!(l.pending_fall.is_none());
    }

    /// EC-1 path 2: an abandon's release confirmed and persisted, then a restart more than an hour
    /// later. The hydration reading sees the fall; the chain's events explain it, so no trip.
    #[test]
    fn a_restart_long_after_an_abandon_is_explained_by_the_events() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        l.note_own_penalty(Some(B256::repeat_byte(7)), 5 * H, 110, true);
        let restart = 100 + 5 * OWN_PENALTY_WINDOW_SECS;
        assert_eq!(l.observe(&reading(0, 995 * H, 0, 900), restart), None);
        let p = l.pending_fall.clone().unwrap();
        assert_eq!(l.pending_range(), Some((10, 900)));
        assert_eq!(l.apply_moves(&p, &moves(5 * H, 0), restart + 15), None);
        assert!(l.tripped.is_none() && l.pending_fall.is_none());
    }

    /// EC-1 path 5: `withdraw` then `unstake` while the miner was stopped. The pending unstake rose
    /// again, so the withdrawal arithmetic does not cover the fall; the `Withdrawn` event does.
    #[test]
    fn a_withdraw_then_request_while_stopped_is_explained_by_withdrawn() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 400 * H, 10), 100);
        assert_eq!(l.observe(&reading(0, 600 * H, 200 * H, 50), 5_000), None);
        let p = l.pending_fall.clone().expect("held");
        assert_eq!(p.left, Some(200 * H));
        assert_eq!(l.apply_moves(&p, &moves(0, 400 * H), 5_015), None);
        assert!(l.tripped.is_none() && l.pending_fall.is_none());
    }

    /// VLA-2: a credit left over after an explained fall is dropped and does not absorb a later,
    /// unrelated fall.
    #[test]
    fn a_leftover_credit_does_not_absorb_a_later_fall() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        l.note_own_penalty(Some(B256::repeat_byte(1)), 50 * H, 101, true);
        l.observe(&reading(0, 995 * H, 0, 11), 115);
        let p = l.pending_fall.clone().unwrap();
        assert_eq!(l.apply_moves(&p, &moves(5 * H, 0), 120), None);
        assert!(l.own_penalties.is_empty());
        // A later fall with the events unreadable: nothing left to explain it.
        l.observe(&reading(0, 950 * H, 0, 12), 130);
        let e = l
            .moves_unread(130 + PENDING_FALL_LIMIT_SECS)
            .expect("a trip");
        assert_eq!(e.kind, "STAKE-DROP");
    }

    /// A second fall before the first is decided widens it; a read for the narrower range does not
    /// clear the wider one.
    #[test]
    fn a_second_fall_widens_the_pending_one() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        l.observe(&reading(0, 995 * H, 0, 11), 115);
        let first = l.pending_fall.clone().unwrap();
        l.observe(&reading(0, 990 * H, 0, 12), 130);
        assert_eq!(l.pending_range(), Some((10, 12)));
        assert_eq!(l.pending_fall.as_ref().unwrap().left, Some(10 * H));
        assert_eq!(l.apply_moves(&first, &moves(5 * H, 0), 131), None);
        assert!(
            l.pending_fall.is_some(),
            "the wider fall waits for its own read"
        );
        let wide = l.pending_fall.clone().unwrap();
        assert_eq!(l.apply_moves(&wide, &moves(10 * H, 0), 145), None);
        assert!(l.pending_fall.is_none() && l.tripped.is_none());
    }

    /// A release whose fulfil landed first takes nothing: its noted penalty is withdrawn; a
    /// confirmed one is marked so.
    #[test]
    fn noted_penalties_are_keyed_by_job() {
        let mut l = ProverLatch::default();
        let a = B256::repeat_byte(1);
        let b = B256::repeat_byte(2);
        l.note_own_penalty(Some(a), 5 * H, 100, false);
        l.note_own_penalty(Some(b), 7 * H, 100, false);
        l.note_own_penalty(Some(a), 6 * H, 101, false);
        assert_eq!(l.own_penalties.len(), 2, "one per job");
        assert!(l.confirm_own_penalty(a, 110));
        l.withdraw_own_penalty(b);
        assert_eq!(l.own_penalties.len(), 1);
        assert_eq!(l.own_penalties[0].wei, Some(6 * H));
        assert_eq!(l.own_penalties[0].confirmed_at, Some(110));
        assert!(!l.confirm_own_penalty(b, 111));
    }

    /// LD-3: a lock that ended past its deadline is a release when the router says one of ours
    /// landed, a slash when it says slashed (whatever else), and unknown (a trip) otherwise.
    #[test]
    fn a_past_deadline_end_is_classified_from_the_lock_exits() {
        assert_eq!(
            past_end_of(&[LockExit::Released { penalty: 5 * H }]),
            PastEnd::Released { penalty: 5 * H }
        );
        assert_eq!(
            past_end_of(&[LockExit::GraceReleased]),
            PastEnd::Released { penalty: 0 }
        );
        assert_eq!(
            past_end_of(&[
                LockExit::Released { penalty: 5 * H },
                LockExit::Slashed { amount: 100 * H }
            ]),
            PastEnd::Slashed
        );
        assert_eq!(past_end_of(&[]), PastEnd::Unknown);
    }

    /// The stake commands move the baseline only from the reading before their own transaction,
    /// never over a trip or a pending fall.
    #[test]
    fn a_stake_command_rebaselines_only_from_its_own_before_reading() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 400 * H, 10), 100);
        // withdrawUnstaked then requestUnstake, each rebaselined.
        assert!(rebaseline(
            &mut l,
            (1_000 * H, 400 * H),
            (600 * H, 0),
            Some(20)
        ));
        assert!(rebaseline(
            &mut l,
            (600 * H, 0),
            (600 * H, 200 * H),
            Some(21)
        ));
        assert_eq!(l.block_seen, Some(21));
        assert_eq!(l.observe(&reading(0, 600 * H, 200 * H, 22), 200), None);
        assert!(l.pending_fall.is_none());
        // A baseline that moved since (a release the miner made after its last reading): left alone.
        assert!(!rebaseline(
            &mut l,
            (590 * H, 200 * H),
            (590 * H, 0),
            Some(30)
        ));
        // Tripped or pending: left alone.
        l.observe(&reading(0, 500 * H, 200 * H, 23), 210);
        assert!(l.pending_fall.is_some());
        assert!(!rebaseline(
            &mut l,
            (500 * H, 200 * H),
            (500 * H, 0),
            Some(31)
        ));
    }

    /// Files written before review 7 (no `pending_fall`, penalties without a job) load; a file with
    /// a pending fall round-trips.
    #[test]
    fn the_latch_file_loads_old_entries_and_round_trips_a_pending_fall() {
        let old = r#"{"provers":{"743111:0x1111111111111111111111111111111111111111":{
            "jobs_slashed_seen":0,"total_staked_seen":"1000","unstake_seen":"0","block_seen":10,
            "own_penalties":[{"at":5,"wei":"7"}],"tripped":null}}}"#;
        let f: LatchFile = serde_json::from_str(old).unwrap();
        let l = f.provers.values().next().unwrap();
        assert!(l.pending_fall.is_none());
        assert_eq!(l.own_penalties[0].job, None);
        assert_eq!(l.own_penalties[0].wei, Some(7));
        let mut l = l.clone();
        l.observe(&reading(0, 500, 0, 11), 100);
        assert!(l.pending_fall.is_none(), "inside the tolerance");
        l.observe(&reading(0, 0, 0, 12), 100);
        let mut l2 = ProverLatch::default();
        l2.observe(&reading(0, 1_000 * H, 0, 10), 100);
        l2.observe(&reading(0, 900 * H, 0, 11), 115);
        l2.note_own_penalty(Some(B256::repeat_byte(3)), 5 * H, 116, true);
        let mut file = LatchFile::default();
        file.provers.insert("k".into(), l2.clone());
        let text = serde_json::to_string(&file).unwrap();
        let back: LatchFile = serde_json::from_str(&text).unwrap();
        assert_eq!(back.provers["k"], l2);
        assert!(back.provers["k"].pending_fall.is_some());
    }

    #[test]
    fn an_older_block_is_not_read_as_a_fall_and_a_stake_rise_rebaselines() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 900 * H, 0, 20), 100);
        // A lagging replica at block 19 still shows the stake before a fall we already saw.
        assert_eq!(l.observe(&reading(0, 1_000 * H, 0, 19), 115), None);
        assert_eq!(l.total_staked_seen, Some(900 * H));
        // A stake added (`zkminer stake` between runs) is the new baseline.
        assert_eq!(l.observe(&reading(0, 1_400 * H, 0, 21), 130), None);
        assert_eq!(l.total_staked_seen, Some(1_400 * H));
    }

    #[test]
    fn a_lost_lock_trips_and_later_events_are_kept_beside_the_first() {
        let mut l = ProverLatch::default();
        let first = Event {
            kind: "SLASHED",
            detail: "lock 0xab ended past its deadline".into(),
        };
        l.trip(&first, 100);
        l.trip(
            &Event {
                kind: "STAKE-DROP",
                detail: "x".into(),
            },
            200,
        );
        let t = l.tripped.clone().unwrap();
        assert_eq!(t.reason, first.detail);
        assert_eq!(t.later, vec!["STAKE-DROP: x".to_string()]);
        assert!(t.summary().contains("(+1 later)"));
    }

    #[test]
    fn a_trip_holds_across_a_restart_until_resume_claims_clears_it() {
        let dir = std::env::temp_dir().join(format!("zkminer-latch-live-{}", std::process::id()));
        let p = dir.join(FILE_NAME);
        let k = key(743111, Address::repeat_byte(0x22));
        let mut live = Live::open(p.clone(), k.clone(), true);
        assert!(live.latch.tripped.is_none());
        live.observe(&reading(0, 1_000 * H, 0, 10));
        live.trip_now(&lock_lost(
            B256::repeat_byte(0xab),
            "ended past its deadline",
        ));
        assert!(live.latch.tripped.is_some());
        // A restart reads it back tripped.
        let mut again = Live::open(p.clone(), k.clone(), true);
        assert!(again.latch.tripped.is_some());
        assert_eq!(again.latch.total_staked_seen, Some(1_000 * H));
        // `zkminer resume-claims` in another terminal: the running miner sees it, baseline kept.
        let mut f = load(&p).unwrap();
        f.provers.get_mut(&k).unwrap().clear();
        std::thread::sleep(Duration::from_millis(20));
        save(&p, &f).unwrap();
        again.reload_if_changed(true);
        assert!(again.latch.tripped.is_none());
        assert_eq!(again.latch.total_staked_seen, Some(1_000 * H));
        // A watch-only run never writes the file.
        let mut watch = Live::open(p.clone(), k.clone(), false);
        watch.trip_now(&lock_lost(B256::repeat_byte(0xcd), "x"));
        assert!(load(&p).unwrap().provers[&k].tripped.is_none());
        // An unreadable file is a tripped latch.
        std::fs::write(&p, b"garbage").unwrap();
        assert!(Live::open(p.clone(), k.clone(), true)
            .latch
            .tripped
            .is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The latch holds every way to a NEW lock (the brain's pass, the per-job last-moment checks,
    /// witness claims) and nothing that drives a held one (fulfil, release, recovery, shutdown).
    #[test]
    fn the_latch_holds_new_claims_and_never_held_locks() {
        let run = include_str!("../run.rs");
        let held_for = &run[run.find("fn claims_held_for(").unwrap()..];
        let held_for = &held_for[..held_for.find("\n}\n").unwrap()];
        assert!(held_for.contains("slash_latch::hold_short().is_some()"));
        let brain = run
            .find("if let Some(why) = slash_latch::hold_reason() {")
            .unwrap();
        let jam = run.find("if client.signer_is_jammed() {").unwrap();
        assert!(jam < brain);
        let witness = include_str!("witness/runtime.rs");
        assert_eq!(
            witness
                .matches("if let Some(why) = run::slash_latch::hold_short() {")
                .count(),
            2
        );
        let release = &run[run
            .find("\nasync fn release_and_clean_with_nonce(")
            .unwrap()..];
        let release = &release[..release.find("\n}\n").unwrap()];
        assert!(
            !release.contains("slash_latch::tripped")
                && !release.contains("hold_reason")
                && !release.contains("hold_short")
        );
        assert_eq!(
            run.matches("slash_latch::tripped()").count(),
            1,
            "the badge"
        );
        assert_eq!(
            run.matches("slash_latch::hold_short()").count(),
            1,
            "the gate"
        );
    }

    /// Review 7 LD-1 path 3, LD-3: both entry points load the latch and keep it current, and every
    /// site that sees a lock end past its deadline asks the one classifier.
    #[test]
    fn both_entry_points_keep_the_latch_and_past_deadline_ends_are_classified() {
        let run = include_str!("../run.rs");
        let refused = include_str!("refused.rs");
        let hold = &refused[refused.find("async fn hold_and_release(").unwrap()..];
        for src in [run, hold] {
            assert!(src.contains("slash_latch::init("));
            assert!(src.contains("slash_latch::observe("));
            assert!(src.contains("slash_latch::explain_pending("));
        }
        assert_eq!(
            run.matches("slash_latch::note_lock_lost(").count(),
            2,
            "the classifier's trip and slash_own_expired_lock's"
        );
        assert_eq!(run.matches("past_deadline_end(").count(), 4, "fn + 3 sites");
    }

    #[test]
    fn the_page_names_the_kind_and_the_way_out() {
        // The page is a `tracing::error!` whose text starts `PAGE: <kind>`, so it reaches the log
        // file, journald, stderr and the dashboard (`PageToDashboard`).
        let src = include_str!("slash_latch.rs");
        assert!(src.contains(
            "\"PAGE: {} — {}; not claiming new work until `{RESUME_COMMAND}`; held locks are still driven\""
        ));
        assert_eq!(RESUME_COMMAND, "zkminer resume-claims");
        assert!(HOLD_SHORT.contains(RESUME_COMMAND));
    }
}
