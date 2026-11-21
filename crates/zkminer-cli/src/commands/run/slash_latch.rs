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
//! - a lock of ours that ended past its deadline (`EndedPastDeadline`: a keeper's slash, or a release
//!   of ours that landed late, which the chain does not tell apart), or that it slashed itself;
//! - a fall in `totalStaked` that neither a withdrawal (`unstakeAmount` falling by as much) nor this
//!   miner's own release penalties explain (`STAKE-DROP`, review r6 N6-EM-1).
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

/// How long a release penalty of ours stays available to explain a stake fall. A release mined but
/// not yet seen by the refresh (a lagging replica) is seen within minutes; one never seen (a penalty
/// rounded to 0) must not explain a slash days later.
pub(crate) const OWN_PENALTY_WINDOW_SECS: u64 = 3_600;

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

/// A release penalty of ours not yet seen leave the stake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OwnPenalty {
    /// Unix seconds when its release was confirmed.
    pub at: u64,
    #[serde(with = "dec")]
    pub wei: Option<u128>,
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
                    .retain(|p| now.saturating_sub(p.at) <= OWN_PENALTY_WINDOW_SECS);
                if let (Some(before), Some(unstake_before)) =
                    (self.total_staked_seen, self.unstake_seen)
                {
                    if total < before {
                        let fall = before - total;
                        // `withdrawUnstaked` takes the pending amount out of the stake. (A slash
                        // that caps a pending unstake lowers it too, but `jobsSlashed` counts that.)
                        let withdrawn = unstake_before.saturating_sub(unstake);
                        let mut left = fall.saturating_sub(withdrawn);
                        for p in &mut self.own_penalties {
                            let have = p.wei.unwrap_or(0);
                            let take = have.min(left);
                            p.wei = Some(have - take);
                            left -= take;
                        }
                        self.own_penalties.retain(|p| p.wei.unwrap_or(0) > 0);
                        if left > STAKE_DROP_TOLERANCE && event.is_none() {
                            event = Some(Event {
                                kind: "STAKE-DROP",
                                detail: format!(
                                    "the stake fell by {} HEMI ({} -> {}) with no slash counted on \
                                     chain; a withdrawal and this miner's release penalties explain \
                                     only {} HEMI of it",
                                    hemi(fall),
                                    hemi(before),
                                    hemi(total),
                                    hemi(fall - left)
                                ),
                            });
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

    /// Record a release penalty of ours, so the stake fall it causes is not read as a slash.
    pub(crate) fn note_own_penalty(&mut self, wei: u128, now: u64) {
        if wei > 0 {
            self.own_penalties.push(OwnPenalty {
                at: now,
                wei: Some(wei),
            });
        }
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

    fn own_penalty(&mut self, wei: u128) {
        self.reload_if_changed(true);
        self.latch.note_own_penalty(wei, unix_now());
        self.persist();
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

/// A release of ours was confirmed, at `penalty` wei (its job's snapshotted `releasePenaltyBps` of
/// its locked collateral).
fn note_own_penalty(penalty: u128) {
    with_live(|live| live.own_penalty(penalty));
}

/// What releasing `collateral` costs at `penalty_bps`: the router's `releasePenaltyBps ×
/// lockedCollateral / 10,000`, rounded down as it rounds.
pub(crate) fn penalty_of(collateral: u128, penalty_bps: u128) -> u128 {
    collateral.saturating_mul(penalty_bps) / 10_000
}

/// The release penalty of our lock on `job_id`, read while the lock is still on record (its
/// `lockedCollateral` and its snapshotted `releasePenaltyBps`). `None` when either read fails, the
/// record is not ours any more, or it takes too long: run beside the release, never before it.
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
/// is not guessed: the stake fall it causes may then trip the latch as `STAKE-DROP`, which says so.
pub(crate) fn note_own_release(job_id: B256, penalty: Option<u128>) {
    match penalty {
        Some(p) => note_own_penalty(p),
        None => tracing::warn!(
            "release of {}: its penalty could not be read; if the stake fall it causes trips the \
             slash latch (STAKE-DROP), that fall is this release",
            super::short_id(job_id)
        ),
    }
}

/// The trip holding claims now, if any. Cheap: the file is looked at most every few seconds.
pub(crate) fn tripped() -> Option<Trip> {
    with_live(|live| {
        live.reload_if_changed(false);
        live.latch.tripped.clone()
    })
    .flatten()
}

/// The claim hold's reason while tripped.
pub(crate) fn hold_reason() -> Option<String> {
    tripped().map(|t| {
        format!(
            "a lock of this prover was slashed ({}): claims stop until `{RESUME_COMMAND}`; held \
             locks continue",
            t.summary()
        )
    })
}

/// The claim hold's reason in a word, for callers that take a static string.
pub(crate) const HOLD_SHORT: &str =
    "a lock of this prover was slashed: claims stop until `zkminer resume-claims`";

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

    #[test]
    fn our_own_release_penalties_explain_a_stake_fall() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        l.note_own_penalty(5 * H, 105);
        l.note_own_penalty(10 * H, 106);
        assert_eq!(l.observe(&reading(0, 985 * H, 0, 11), 115), None);
        assert!(l.own_penalties.is_empty(), "both used up");
        // A penalty seen in two steps (a replica that saw one release first) is used in parts.
        l.note_own_penalty(20 * H, 120);
        assert_eq!(l.observe(&reading(0, 975 * H, 0, 12), 125), None);
        assert_eq!(l.own_penalties[0].wei, Some(10 * H));
        assert_eq!(l.observe(&reading(0, 965 * H, 0, 13), 130), None);
        assert!(l.tripped.is_none());
    }

    #[test]
    fn an_unexplained_stake_fall_trips() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        l.note_own_penalty(5 * H, 105);
        let e = l.observe(&reading(0, 895 * H, 0, 11), 115).expect("a trip");
        assert_eq!(e.kind, "STAKE-DROP");
        assert!(e.detail.contains("105.00"), "{}", e.detail);
        assert!(l.tripped.is_some());
    }

    #[test]
    fn a_penalty_too_old_explains_nothing_and_rounding_is_tolerated() {
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        l.note_own_penalty(100 * H, 100);
        let later = 100 + OWN_PENALTY_WINDOW_SECS + 1;
        assert!(l.observe(&reading(0, 900 * H, 0, 11), later).is_some());
        let mut l = ProverLatch::default();
        l.observe(&reading(0, 1_000 * H, 0, 10), 100);
        assert_eq!(l.observe(&reading(0, 1_000 * H - H / 2, 0, 11), 115), None);
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
        assert!(held_for.contains("slash_latch::tripped().is_some()"));
        let brain = run
            .find("if let Some(why) = slash_latch::hold_reason() {")
            .unwrap();
        let jam = run.find("if client.signer_is_jammed() {").unwrap();
        assert!(jam < brain);
        let witness = include_str!("witness/runtime.rs");
        assert_eq!(
            witness
                .matches("run::slash_latch::tripped().is_some()")
                .count(),
            2
        );
        let release = &run[run
            .find("\nasync fn release_and_clean_with_nonce(")
            .unwrap()..];
        let release = &release[..release.find("\n}\n").unwrap()];
        assert!(!release.contains("slash_latch::tripped") && !release.contains("hold_reason"));
        assert_eq!(
            run.matches("slash_latch::tripped()").count(),
            2,
            "the gate and the badge"
        );
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
