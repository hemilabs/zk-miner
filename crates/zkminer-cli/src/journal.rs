//! Persistent job journal for restart recovery.
//!
//! Records every job we have claimed on-chain, along with the claim tx hash and
//! its current lifecycle state. On restart the brain reads this journal,
//! queries the on-chain state for each entry, and either resumes (re-fulfills,
//! releases before deadline) or garbage-collects entries whose on-chain state
//! has moved past our control (already released by a keeper, fulfilled, etc.).
//!
//! Writes are atomic (tmp + rename) so a crash mid-write cannot leave an
//! unparseable journal.
//!
//! # Format versions
//!
//! - **1**: the original format, with no `format_version` field (a file without one is version 1).
//! - **2** ([`JOURNAL_FORMAT_VERSION`]): adds `format_version` and, per entry, `witness`: the
//!   retention-store bundle a witness-construction lock is proven from (plan §15.2). Version 1 files
//!   load unchanged; they are written back as version 2.
//!
//! Loading never silently drops anything: an entry that does not parse is kept verbatim (and written
//! back) and reported with a `PAGE: JOURNAL-ENTRY-UNREADABLE`, until an authoritative read shows its
//! job terminal ([`JobJournal::drop_unparsed`]); a file that does not parse at all is moved aside,
//! never overwritten, with a `PAGE: JOURNAL-CORRUPT`; a file from a NEWER format, or one that cannot
//! be read, is an error ([`JobJournal::load_checked`]): an older build must not rewrite a newer
//! build's record of the locks it holds. The miner then starts in held-locks-only mode with this
//! run's journal written beside the file ([`JobJournal::write_aside`]), never over it: refusing to
//! start would leave every lock it holds undriven until slashed, while the chain scan (and the
//! retention store, for witness locks) still finds each of them. The journal is not the
//! authoritative index of witness locks (the retention store's pins are).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use alloy::primitives::{Address, B256};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The format this build writes (see the module docs).
pub const JOURNAL_FORMAT_VERSION: u32 = 2;

/// The format of a journal written before versions existed.
fn format_v1() -> u32 {
    1
}

/// Where this process writes the journal instead of the default path, once
/// [`JobJournal::write_aside`] set it.
static SAVE_PATH_OVERRIDE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// The retention-store bundle a witness lock is proven from: the store key and version. Recovery
/// does not depend on it (the store's pins are the authoritative index); it tells the journal's
/// readers, and an operator, that the lock is a witness lock and where its bundle is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessBundleRef {
    pub job_id: B256,
    pub descriptor_hash: B256,
    pub prover: Address,
    pub version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalState {
    /// Claim tx has been sent but we haven't confirmed it landed.
    Claiming,
    /// Claim confirmed on-chain — we hold the lock.
    Claimed,
    /// Proof is currently being generated.
    Proving,
    /// Fulfillment tx has been sent.
    Fulfilling,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JournalEntry {
    pub job_id: B256,
    /// Unix timestamp (seconds) when we first recorded this entry.
    pub claimed_at: i64,
    /// The claim tx hash (populated once the tx is broadcast).
    pub claim_tx: Option<B256>,
    /// The job's submitting tx (from the monitor), so a restart can rebuild the descriptor of a held
    /// lock with one tx read, without depending on a long log scan.
    pub submit_tx: Option<B256>,
    /// On-chain lock deadline (unix seconds) — a hint; authoritative value is
    /// always re-read from chain before acting.
    pub lock_deadline: u64,
    pub state: JournalState,
    /// A block at which the job was read Locked by us (0 = not seen yet). A read pinned at or after
    /// it that shows another prover proves our lock is gone; an unpinned one may come from a replica
    /// still showing the job's previous holder.
    pub lock_block: u64,
    /// The job's `reopenCount` when it read Locked by us. Every way a lock leaves its prover except a
    /// pause's grace release (which only the prover sends) bumps it, so a higher count on ANY read,
    /// pinned or not, proves our lock is gone.
    pub lock_reopens: Option<u8>,
    /// The risc0 segment sizes (po2) the job measured clean at before it was claimed, so a restart
    /// proves it on a card at one of them: a guest can tell the size it runs at. Empty for SP1, and
    /// in a breadcrumb written before sizes were recorded.
    pub measured_po2s: Vec<u8>,
    /// The `sys_rand` rule the risc0 sizes above were measured under, so a restart on a build with
    /// another rule can say that this lock's guest may now commit something else. `None` in a
    /// breadcrumb written before the rule was recorded.
    pub sys_rand_rule: Option<String>,
    /// The cycles the job measured at before it was claimed, and how long that execution took in
    /// seconds, so a restart still shows how far its proof is. `None` in a breadcrumb written before
    /// they were recorded.
    pub measured_cycles: Option<u64>,
    pub measured_execute_secs: Option<u64>,
    /// For a witness-construction lock, the bundle it is proven from (format 2). `None` for an
    /// inline job and in every format-1 entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<WitnessBundleRef>,
    /// Proofs of this job that started and never ended: each start counts one, and the proof's end
    /// in the same run (proved, failed or stopped) takes it back, so what is left counts runs that
    /// ended in the middle of its proof (the miner killed or crashed). A guest that breaks out of
    /// its worker and ends the miner every time the job is proven again leaves one more each time,
    /// and the job is released at a limit rather than proven forever (`run::crash_loop_refusal`).
    /// Absent (0) in an entry written before it was recorded; an older build ignores it.
    #[serde(skip_serializing_if = "is_zero")]
    pub prove_starts: u8,
}

fn is_zero(n: &u8) -> bool {
    *n == 0
}

impl Default for JournalEntry {
    fn default() -> Self {
        Self {
            job_id: B256::ZERO,
            claimed_at: 0,
            claim_tx: None,
            submit_tx: None,
            lock_deadline: 0,
            state: JournalState::Claiming,
            lock_block: 0,
            lock_reopens: None,
            measured_po2s: Vec::new(),
            sys_rand_rule: None,
            measured_cycles: None,
            measured_execute_secs: None,
            witness: None,
            prove_starts: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobJournal {
    /// The format the file was read in (1 when it has no such field); always written as
    /// [`JOURNAL_FORMAT_VERSION`].
    #[serde(default = "format_v1")]
    pub format_version: u32,
    #[serde(default)]
    pub entries: HashMap<B256, JournalEntry>,
    /// Entries that did not parse, by their key as written, kept verbatim and written back so that
    /// nothing is lost (an operator, or a newer build, can still read them).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unparsed: BTreeMap<String, serde_json::Value>,
    /// Jobs released because the miner kept ending in the middle of their proofs (JOB-CRASH-LOOP),
    /// by job id: not claimed again, nor their submitter's jobs of the same program for a while
    /// ([`Self::crash_loop_hold`]). Outlives the job's entry, which its release removes. An older
    /// build ignores it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub crash_looped: BTreeMap<B256, CrashLoopMark>,
    /// The address whose locks these are: the signer of the miner that last saved it
    /// ([`set_owner`]). `None` in a journal written before it was recorded (stamped at its next
    /// save). A miner started with another key refuses to take the journal over while it holds
    /// entries ([`JobJournal::key_changed_refusal`]). An older build ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prover: Option<Address>,
}

/// The signer of this process's miner, stamped into every journal it saves ([`JobJournal::prover`]).
static OWNER: std::sync::OnceLock<Address> = std::sync::OnceLock::new();

/// The address this journal's locks belonged to before a key change the operator accepted
/// (`run --forget-foreign-locks`): recovery pages each lock still held by it.
static PREVIOUS_OWNER: std::sync::OnceLock<Address> = std::sync::OnceLock::new();

/// Record `address` as the owner of every journal this process saves from now on (once per
/// process: a later call is ignored).
pub fn set_owner(address: Address) {
    let _ = OWNER.set(address);
}

/// Record that the journal's locks belonged to `address` before a key change that was accepted.
pub fn set_previous_owner(address: Address) {
    let _ = PREVIOUS_OWNER.set(address);
}

/// See [`set_previous_owner`].
pub fn previous_owner() -> Option<Address> {
    PREVIOUS_OWNER.get().copied()
}

/// A job released as a crash loop ([`JobJournal::crash_looped`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashLoopMark {
    pub program_id: B256,
    pub submitter: Address,
    /// Unix seconds.
    pub at: i64,
}

/// How long a crash-looped job id is not claimed again (a job's window is at most 7 days).
pub const CRASH_LOOP_JOB_HOLD_SECS: i64 = 7 * 24 * 3600;

/// How long a crash-looped job's submitter is not claimed from for the same program.
pub const CRASH_LOOP_PAIR_HOLD_SECS: i64 = 24 * 3600;

/// How many crash-loop marks are kept at most: the oldest go first.
const CRASH_LOOP_MARKS_MAX: usize = 1000;

impl Default for JobJournal {
    fn default() -> Self {
        Self {
            format_version: JOURNAL_FORMAT_VERSION,
            entries: HashMap::new(),
            unparsed: BTreeMap::new(),
            crash_looped: BTreeMap::new(),
            prover: None,
        }
    }
}

/// `<path>.aside-<stamp>`: where a run that could not load `path` writes its journal.
fn aside_path(path: &Path, stamp: i64) -> PathBuf {
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(".aside-{stamp}"));
    PathBuf::from(aside)
}

/// Why a journal refused to load ([`JobJournal::load_checked`]).
#[derive(Debug)]
pub enum JournalLoadError {
    /// Written by a newer build (a later format): this build must not rewrite it.
    NewerFormat { path: PathBuf, found: u32 },
    /// The file exists but could not be read.
    Unreadable { path: PathBuf, error: std::io::Error },
}

impl std::fmt::Display for JournalLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewerFormat { path, found } => write!(
                f,
                "the job journal at {} is format {found}, newer than this build's \
                 {JOURNAL_FORMAT_VERSION}: a newer zkminer wrote it (perhaps holding witness locks this \
                 build cannot prove). Run that release, or move the file aside after settling its locks",
                path.display()
            ),
            Self::Unreadable { path, error } => {
                write!(f, "the job journal at {} cannot be read: {error}", path.display())
            }
        }
    }
}

impl std::error::Error for JournalLoadError {}

/// What a load found, besides the journal.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LoadReport {
    /// The file did not parse and was moved here (never overwritten).
    pub moved_aside: Option<PathBuf>,
    /// Keys of entries that did not parse (kept in [`JobJournal::unparsed`]).
    pub unparsed: Vec<String>,
}

/// Parses journal text. `Err` with the parse error when the text is not a journal at all; an entry
/// that does not parse lands in `unparsed`.
fn parse_journal(content: &str) -> std::result::Result<(JobJournal, Vec<String>), String> {
    let v: serde_json::Value = serde_json::from_str(content).map_err(|e| e.to_string())?;
    let obj = v.as_object().ok_or("not a JSON object")?;
    let format_version = match obj.get("format_version") {
        None => format_v1(),
        Some(f) => f
            .as_u64()
            .and_then(|f| u32::try_from(f).ok())
            .ok_or("format_version is not a number")?,
    };
    let mut j = JobJournal {
        format_version,
        ..JobJournal::default()
    };
    match obj.get("entries") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Object(entries)) => {
            for (k, e) in entries {
                let parsed = k
                    .parse::<B256>()
                    .ok()
                    .zip(serde_json::from_value::<JournalEntry>(e.clone()).ok());
                match parsed {
                    Some((id, e)) => {
                        j.entries.insert(id, e);
                    }
                    None => {
                        j.unparsed.insert(k.clone(), e.clone());
                    }
                }
            }
        }
        Some(_) => return Err("entries is not an object".into()),
    }
    // Entries an earlier load could not parse stay with the file.
    if let Some(serde_json::Value::Object(u)) = obj.get("unparsed") {
        for (k, e) in u {
            j.unparsed.entry(k.clone()).or_insert_with(|| e.clone());
        }
    }
    // A mark that does not parse is dropped: it only holds claims back.
    if let Some(serde_json::Value::Object(marks)) = obj.get("crash_looped") {
        for (k, m) in marks {
            if let (Ok(id), Ok(m)) = (
                k.parse::<B256>(),
                serde_json::from_value::<CrashLoopMark>(m.clone()),
            ) {
                j.crash_looped.insert(id, m);
            }
        }
    }
    // An owner that does not parse is as none: the journal is stamped again at its next save.
    j.prover = obj
        .get("prover")
        .and_then(|p| serde_json::from_value::<Address>(p.clone()).ok());
    let unparsed = j.unparsed.keys().cloned().collect();
    Ok((j, unparsed))
}

impl JobJournal {
    /// Default path: `~/.zkminer/job_journal.json`.
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".zkminer")
            .join("job_journal.json")
    }

    /// Load the journal from disk ([`Self::load_checked_from`] at the default path).
    pub fn load_checked() -> std::result::Result<Self, JournalLoadError> {
        Self::load_checked_from(&Self::default_path())
    }

    /// Load the journal from `path`. A missing file is an empty journal. A file that does not parse
    /// is moved aside (`<path>.corrupt-<unix seconds>`) and paged, and the journal starts empty: the
    /// chain scan still finds every lock this prover holds, and the retention store every witness
    /// lock. Entries that do not parse are kept and paged. A newer format, or a file that cannot be
    /// read, is an error: refuse to start rather than lose or rewrite it.
    pub fn load_checked_from(path: &Path) -> std::result::Result<Self, JournalLoadError> {
        let (j, report) = Self::load_reporting(path)?;
        if let Some(aside) = &report.moved_aside {
            tracing::error!(
                "PAGE: JOURNAL-CORRUPT: the job journal at {} did not parse; it was moved to {} and \
                 the miner starts with an empty journal (recovery still finds every lock on chain)",
                path.display(),
                aside.display()
            );
        }
        for k in &report.unparsed {
            tracing::error!(
                "PAGE: JOURNAL-ENTRY-UNREADABLE: entry {} of the job journal at {} did not parse; it is \
                 kept in the file as written (recovery still finds its lock on chain)",
                zkminer_chain::programs::sanitize_log(k),
                path.display()
            );
        }
        Ok(j)
    }

    /// The journal at the default path as it is, for a report (`zkminer doctor`, `zkminer stop`, a
    /// forced exit): empty when it is missing, unreadable or does not parse, and never moved aside,
    /// which only a run that takes the journal over does ([`Self::load_checked`]).
    pub fn peek() -> Self {
        std::fs::read_to_string(Self::default_path())
            .ok()
            .and_then(|content| parse_journal(&content).ok())
            .map(|(j, _)| j)
            .unwrap_or_default()
    }

    /// As [`Self::peek`], but saying why a journal that is there could not be read (`zkminer
    /// status`): an empty journal must not be reported for one that did not parse.
    pub fn peek_checked() -> std::result::Result<Self, String> {
        match std::fs::read_to_string(Self::default_path()) {
            Ok(content) => parse_journal(&content).map(|(j, _)| j),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// [`Self::load_checked_from`] without the logging, for tests.
    pub fn load_reporting(path: &Path) -> std::result::Result<(Self, LoadReport), JournalLoadError> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((Self::default(), LoadReport::default()))
            }
            Err(error) => {
                return Err(JournalLoadError::Unreadable {
                    path: path.to_path_buf(),
                    error,
                })
            }
        };
        match parse_journal(&content) {
            Ok((j, _)) if j.format_version > JOURNAL_FORMAT_VERSION => Err(JournalLoadError::NewerFormat {
                path: path.to_path_buf(),
                found: j.format_version,
            }),
            Ok((j, unparsed)) => Ok((
                j,
                LoadReport {
                    moved_aside: None,
                    unparsed,
                },
            )),
            Err(_) => {
                let stamp = chrono::Utc::now().timestamp();
                let mut aside = path.as_os_str().to_owned();
                aside.push(format!(".corrupt-{stamp}"));
                let aside = PathBuf::from(aside);
                std::fs::rename(path, &aside).map_err(|error| JournalLoadError::Unreadable {
                    path: path.to_path_buf(),
                    error,
                })?;
                Ok((
                    Self::default(),
                    LoadReport {
                        moved_aside: Some(aside),
                        unparsed: Vec::new(),
                    },
                ))
            }
        }
    }

    /// Write the journal atomically: write to a sibling tmp file then rename. To the default path,
    /// or where [`Self::write_aside`] sent this process's writes.
    pub fn save(&self) -> Result<()> {
        match SAVE_PATH_OVERRIDE.get() {
            Some(p) => self.save_to(p),
            None => self.save_to(&Self::default_path()),
        }
    }

    /// The journal at `path` could not be loaded (unreadable, or a newer format): from now on this
    /// process writes its journal to `<path>.aside-<unix seconds>` and never touches `path`, which
    /// keeps what an operator, or the build that wrote it, needs. Returns the aside path. Once per
    /// process (a later call returns the first path).
    pub fn write_aside(path: &Path) -> PathBuf {
        SAVE_PATH_OVERRIDE
            .get_or_init(|| aside_path(path, chrono::Utc::now().timestamp()))
            .clone()
    }

    /// Review 7 WR-1: why a miner signing as `signer` must not take this journal over: it holds
    /// entries (parsed or not), and they belong to another address. Its recovery would see each of
    /// those locks held by "another prover" and drop it, leaving it to be slashed. `None` for an
    /// empty journal, one of `signer`'s, or one written before the owner was recorded.
    pub fn key_changed_refusal(&self, signer: Address) -> Option<String> {
        let owner = self.prover.filter(|&p| p != signer)?;
        let held = self.entries.len() + self.unparsed.len();
        if held == 0 {
            return None;
        }
        Some(format!(
            "the job journal holds {held} job(s) claimed by {owner:?}, but this config signs as \
             {signer:?}: the key changed. Start with the key of {owner:?} to drive them (put its \
             key file back, or `zkminer init --import-env-key`), or, to give them up and accept \
             they will be slashed, `zkminer run --forget-foreign-locks`"
        ))
    }

    /// Job ids of the entries that did not parse but whose key is a job id: an authoritative read
    /// of each can show it terminal ([`Self::drop_unparsed`]).
    pub fn unparsed_job_ids(&self) -> Vec<B256> {
        self.unparsed.keys().filter_map(|k| k.parse::<B256>().ok()).collect()
    }

    /// Drops the unparsed entries of `terminal` jobs (read Fulfilled, Cancelled, or Open at the
    /// reopen limit: whatever the entry said, no lock of that job is left). Returns how many.
    pub fn drop_unparsed(&mut self, terminal: &[B256]) -> usize {
        let before = self.unparsed.len();
        self.unparsed.retain(|k, _| !matches!(k.parse::<B256>(), Ok(id) if terminal.contains(&id)));
        before - self.unparsed.len()
    }

    /// This journal as it is written: in this build's format, owned by `owner` when known (else
    /// by whoever it was read as owned by).
    fn stamped(&self, owner: Option<Address>) -> Self {
        let mut out = self.clone();
        out.format_version = JOURNAL_FORMAT_VERSION;
        if owner.is_some() {
            out.prover = owner;
        }
        out
    }

    pub fn save_to(&self, path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create journal dir {}", parent.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        let out = self.stamped(OWNER.get().copied());
        let content = serde_json::to_string_pretty(&out).context("Failed to serialize journal")?;
        // Windows, with Low-integrity workers: unreadable to them from its creation.
        #[cfg(windows)]
        let written = zkminer_prover::windows_sandbox::write_secret_file(&tmp, content.as_bytes());
        #[cfg(not(windows))]
        let written = std::fs::write(&tmp, content);
        written.with_context(|| format!("Failed to write journal tmp {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("Failed to rename journal tmp to {}", path.display()))?;
        Ok(())
    }

    /// Record that a claim is about to be sent. An EXISTING entry is kept as is: it may track an
    /// earlier claim tx of ours that is still pending (or mined unseen), and its age is what decides
    /// when that intent is given up.
    pub fn record_claim_intent(&mut self, job_id: B256, lock_deadline: u64, submit_tx: Option<B256>) {
        let now = chrono::Utc::now().timestamp();
        let e = self.entries.entry(job_id).or_insert(JournalEntry {
            job_id,
            claimed_at: now,
            claim_tx: None,
            submit_tx,
            lock_deadline,
            state: JournalState::Claiming,
            lock_block: 0,
            lock_reopens: None,
            measured_po2s: Vec::new(),
            sys_rand_rule: None,
            measured_cycles: None,
            measured_execute_secs: None,
            witness: None,
            prove_starts: 0,
        });
        // A new claim: whatever was seen of an earlier lock on this job says nothing about it (a
        // read showing the new claim pending, at a higher reopen count, would look like proof that
        // the earlier lock is gone).
        e.lock_block = 0;
        e.lock_reopens = None;
    }

    /// A claim whose outcome is unknown went out: an OPEN read is taken as "may still be pending" for
    /// as long after THIS send (a breadcrumb still `Claiming` ages from its latest claim).
    pub fn note_claim_unconfirmed(&mut self, job_id: B256) {
        if let Some(e) = self.entries.get_mut(&job_id) {
            if e.state == JournalState::Claiming {
                e.claimed_at = chrono::Utc::now().timestamp();
            }
        }
    }

    /// Record a block at which the job read Locked by us, if known, and its `reopenCount` there (see
    /// [`JournalEntry::lock_block`], [`JournalEntry::lock_reopens`]).
    pub fn note_lock_seen(&mut self, job_id: B256, block: Option<u64>, reopens: u8) {
        if let Some(e) = self.entries.get_mut(&job_id) {
            if let Some(b) = block {
                e.lock_block = e.lock_block.max(b);
            }
            e.lock_reopens = Some(e.lock_reopens.map_or(reopens, |r| r.max(reopens)));
        }
    }

    pub fn mark_claimed(&mut self, job_id: B256, claim_tx: Option<B256>, lock_deadline: u64) {
        let e = self.entries.entry(job_id).or_insert(JournalEntry {
            job_id,
            claimed_at: chrono::Utc::now().timestamp(),
            claim_tx: None,
            submit_tx: None,
            lock_deadline,
            state: JournalState::Claimed,
            lock_block: 0,
            lock_reopens: None,
            measured_po2s: Vec::new(),
            sys_rand_rule: None,
            measured_cycles: None,
            measured_execute_secs: None,
            witness: None,
            prove_starts: 0,
        });
        if claim_tx.is_some() {
            e.claim_tx = claim_tx;
        }
        e.lock_deadline = lock_deadline;
        e.state = JournalState::Claimed;
    }

    /// Record the sizes a claim about to be sent measured clean at. Added to any already recorded: an
    /// earlier claim of ours still pending measured clean at those, and the lock is the same job's
    /// whichever claim lands.
    pub fn note_measured_po2s(&mut self, job_id: B256, po2s: &[u8]) {
        if let Some(e) = self.entries.get_mut(&job_id) {
            for &p in po2s {
                if !e.measured_po2s.contains(&p) {
                    e.measured_po2s.push(p);
                }
            }
            e.measured_po2s.sort_unstable();
            if !po2s.is_empty() {
                e.sys_rand_rule = Some(zkminer_prover_protocol::sys_rand::SYS_RAND_RULE.to_string());
            }
        }
    }

    /// The jobs held or being proved that were measured at risc0 sizes under a `sys_rand` rule other
    /// than `rule`, or before rules were recorded (see [`JournalEntry::sys_rand_rule`]). SP1 locks
    /// record no sizes and have no host seed, so never appear; nor does a claim that never landed.
    pub fn measured_under_another_sys_rand_rule(&self, rule: &str) -> Vec<B256> {
        let mut ids: Vec<B256> = self
            .entries
            .values()
            .filter(|e| {
                e.state != JournalState::Claiming
                    && !e.measured_po2s.is_empty()
                    && e.sys_rand_rule.as_deref() != Some(rule)
            })
            .map(|e| e.job_id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// The sizes recorded for a job (see [`JournalEntry::measured_po2s`]).
    /// Record the cycles a claim about to be sent measured at, and how long measuring took (see
    /// [`JournalEntry::measured_cycles`]). Kept when there is none to record.
    pub fn note_measured_cycles(
        &mut self,
        job_id: B256,
        cycles: Option<u64>,
        execute_secs: Option<u64>,
    ) {
        if let Some(e) = self.entries.get_mut(&job_id) {
            if cycles.is_some() {
                e.measured_cycles = cycles;
                e.measured_execute_secs = execute_secs;
            }
        }
    }

    pub fn measured_po2s(&self, job_id: B256) -> Vec<u8> {
        self.entries
            .get(&job_id)
            .map(|e| e.measured_po2s.clone())
            .unwrap_or_default()
    }

    pub fn mark_proving(&mut self, job_id: B256) {
        if let Some(e) = self.entries.get_mut(&job_id) {
            e.state = JournalState::Proving;
        }
    }

    /// A proof of `job_id` starts: one more unfinished start ([`JournalEntry::prove_starts`]).
    pub fn note_prove_start(&mut self, job_id: B256) {
        if let Some(e) = self.entries.get_mut(&job_id) {
            e.prove_starts = e.prove_starts.saturating_add(1);
        }
    }

    /// That proof ended in this run, however: its start no longer counts.
    pub fn note_prove_end(&mut self, job_id: B256) {
        if let Some(e) = self.entries.get_mut(&job_id) {
            e.prove_starts = e.prove_starts.saturating_sub(1);
        }
    }

    /// How many proofs of `job_id` started in runs that ended before they did.
    pub fn prove_starts(&self, job_id: B256) -> u8 {
        self.entries.get(&job_id).map_or(0, |e| e.prove_starts)
    }

    /// A proof of `job_id` completed: the runs that ended in the middle of its earlier proofs no
    /// longer count, so the limit counts runs in a row ([`JournalEntry::prove_starts`]).
    pub fn note_prove_completed(&mut self, job_id: B256) {
        if let Some(e) = self.entries.get_mut(&job_id) {
            e.prove_starts = 0;
        }
    }

    /// `job_id`, of `program_id` from `submitter`, is released as a crash loop at `now` (unix
    /// seconds): marked so it is not claimed again ([`Self::crash_loop_hold`]). Marks past their hold
    /// are dropped, and the oldest beyond [`CRASH_LOOP_MARKS_MAX`].
    pub fn mark_crash_looped(
        &mut self,
        job_id: B256,
        program_id: B256,
        submitter: Address,
        now: i64,
    ) {
        self.crash_looped.insert(
            job_id,
            CrashLoopMark {
                program_id,
                submitter,
                at: now,
            },
        );
        self.crash_looped
            .retain(|_, m| now.saturating_sub(m.at) < CRASH_LOOP_JOB_HOLD_SECS);
        while self.crash_looped.len() > CRASH_LOOP_MARKS_MAX {
            let Some(oldest) = self
                .crash_looped
                .iter()
                .min_by_key(|(_, m)| m.at)
                .map(|(id, _)| *id)
            else {
                break;
            };
            self.crash_looped.remove(&oldest);
        }
    }

    /// Why `job_id` (of `program_id`, from `submitter`) is not claimed at `now`, if a crash-loop mark
    /// holds it: the job itself was released as one in the last [`CRASH_LOOP_JOB_HOLD_SECS`], or a job
    /// of the same program from the same submitter in the last [`CRASH_LOOP_PAIR_HOLD_SECS`]. With
    /// the seconds the hold has left.
    pub fn crash_loop_hold(
        &self,
        job_id: B256,
        submitter: Address,
        program_id: B256,
        now: i64,
    ) -> Option<(String, i64)> {
        if let Some(m) = self.crash_looped.get(&job_id) {
            let left =
                m.at.saturating_add(CRASH_LOOP_JOB_HOLD_SECS)
                    .saturating_sub(now);
            if left > 0 {
                return Some((
                    "it was released as a crash loop: the miner kept ending in the middle of its \
                     proof"
                        .to_string(),
                    left,
                ));
            }
        }
        self.crash_looped
            .values()
            .filter(|m| m.submitter == submitter && m.program_id == program_id)
            .map(|m| {
                m.at.saturating_add(CRASH_LOOP_PAIR_HOLD_SECS)
                    .saturating_sub(now)
            })
            .filter(|left| *left > 0)
            .max()
            .map(|left| {
                (
                    "another job of its program from its submitter was released as a crash loop"
                        .to_string(),
                    left,
                )
            })
    }

    pub fn mark_fulfilling(&mut self, job_id: B256) {
        if let Some(e) = self.entries.get_mut(&job_id) {
            e.state = JournalState::Fulfilling;
        }
    }

    /// Record the bundle a witness lock is (about to be) proven from. Only on an existing entry:
    /// written right after the claim intent, and again when a journal divergence re-versions it.
    pub fn record_witness_bundle(&mut self, job_id: B256, bundle: WitnessBundleRef) {
        if let Some(e) = self.entries.get_mut(&job_id) {
            e.witness = Some(bundle);
        }
    }

    /// The bundle a witness lock is proven from, if the entry records one.
    pub fn witness_bundle(&self, job_id: B256) -> Option<WitnessBundleRef> {
        self.entries.get(&job_id).and_then(|e| e.witness)
    }

    pub fn remove(&mut self, job_id: B256) {
        self.entries.remove(&job_id);
    }

    pub fn iter(&self) -> impl Iterator<Item = &JournalEntry> {
        self.entries.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "zkminer_journal_test_{}_{}.json",
            name,
            std::process::id()
        ));
        p
    }

    #[test]
    fn a_lock_measured_under_another_rule_is_named_and_an_sp1_one_never() {
        const RULE: &str = zkminer_prover_protocol::sys_rand::SYS_RAND_RULE;
        let (now, old, unsized_, sp1, unlanded) = (
            B256::repeat_byte(1),
            B256::repeat_byte(2),
            B256::repeat_byte(3),
            B256::repeat_byte(4),
            B256::repeat_byte(5),
        );
        let mut j = JobJournal::default();
        for id in [now, old, unsized_, sp1, unlanded] {
            j.record_claim_intent(id, 1, None);
        }
        for id in [now, old, unsized_, sp1] {
            j.mark_claimed(id, Some(B256::repeat_byte(9)), 1);
        }
        j.note_measured_po2s(now, &[20]);
        j.note_measured_po2s(old, &[20]);
        j.note_measured_po2s(sp1, &[]);
        j.note_measured_po2s(unlanded, &[20]);
        assert_eq!(j.measured_under_another_sys_rand_rule(RULE), Vec::<B256>::new());
        assert_eq!(j.measured_under_another_sys_rand_rule("risc0-public-v4"), vec![now, old]);
        // A breadcrumb from a build before the rule was recorded: sizes, no rule.
        j.entries.get_mut(&old).unwrap().sys_rand_rule = None;
        assert_eq!(j.measured_under_another_sys_rand_rule(RULE), vec![old]);
        // And an old file still loads, the field absent.
        let path = tmp_path("rule");
        j.save_to(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap().replace("\"sys_rand_rule\"", "\"ignored_field\"");
        std::fs::write(&path, text).unwrap();
        let loaded = JobJournal::load_checked_from(&path).unwrap();
        assert_eq!(loaded.entries.len(), 5);
        assert!(loaded.entries.values().all(|e| e.sys_rand_rule.is_none()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn roundtrip_save_load() {
        let path = tmp_path("roundtrip");
        let _ = std::fs::remove_file(&path);
        let mut j = JobJournal::default();
        let jid = B256::repeat_byte(0xAB);
        j.record_claim_intent(jid, 12345, None);
        j.mark_claimed(jid, Some(B256::repeat_byte(0xCD)), 12345);
        j.save_to(&path).unwrap();

        let loaded = JobJournal::load_checked_from(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        let e = loaded.entries.get(&jid).unwrap();
        assert_eq!(e.state, JournalState::Claimed);
        assert_eq!(e.lock_deadline, 12345);
        assert_eq!(e.claim_tx, Some(B256::repeat_byte(0xCD)));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn corrupt_file_is_moved_aside_never_overwritten() {
        let path = tmp_path("corrupt");
        std::fs::write(&path, "not valid json {{{").unwrap();
        let (loaded, report) = JobJournal::load_reporting(&path).unwrap();
        assert!(loaded.entries.is_empty());
        let aside = report.moved_aside.expect("moved aside");
        assert!(!path.exists(), "the corrupt file is no longer where a save would overwrite it");
        assert_eq!(std::fs::read_to_string(&aside).unwrap(), "not valid json {{{");
        std::fs::remove_file(&aside).unwrap();
    }

    /// A format-1 journal (no `format_version`, no `witness`) loads unchanged and is written back as
    /// format 2 with every entry.
    #[test]
    fn a_format_1_journal_loads_and_is_rewritten_as_format_2() {
        let path = tmp_path("v1");
        let jid = B256::repeat_byte(0x11);
        let v1 = format!(
            r#"{{"entries":{{"{jid}":{{"job_id":"{jid}","claimed_at":5,"claim_tx":null,"submit_tx":null,"lock_deadline":77,"state":"Proving","lock_block":3,"lock_reopens":1,"measured_po2s":[20]}}}}}}"#
        );
        std::fs::write(&path, &v1).unwrap();
        let (j, report) = JobJournal::load_reporting(&path).unwrap();
        assert_eq!(report, LoadReport::default());
        assert_eq!(j.format_version, 1);
        let e = &j.entries[&jid];
        assert_eq!((e.state, e.lock_deadline, e.lock_block, e.witness), (JournalState::Proving, 77, 3, None));
        j.save_to(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"format_version\": 2"), "{text}");
        assert!(!text.contains("witness"), "an inline entry writes no witness field: {text}");
        let back = JobJournal::load_checked_from(&path).unwrap();
        assert_eq!(back.format_version, JOURNAL_FORMAT_VERSION);
        assert_eq!(back.entries[&jid].measured_po2s, vec![20]);
        std::fs::remove_file(&path).unwrap();
    }

    /// An entry that does not parse (a state this build does not know) is kept and written back,
    /// never dropped; the rest load.
    #[test]
    fn an_unreadable_entry_is_kept_verbatim() {
        let path = tmp_path("unparsed");
        let (good, bad) = (B256::repeat_byte(0x21), B256::repeat_byte(0x22));
        let text = format!(
            r#"{{"format_version":2,"entries":{{"{good}":{{"job_id":"{good}","state":"Claimed"}},"{bad}":{{"job_id":"{bad}","state":"Teleporting"}},"not-a-job-id":{{"state":"Claimed"}}}}}}"#
        );
        std::fs::write(&path, &text).unwrap();
        let (j, report) = JobJournal::load_reporting(&path).unwrap();
        assert_eq!(j.entries.len(), 1);
        assert!(j.entries.contains_key(&good));
        let mut unparsed = report.unparsed.clone();
        unparsed.sort();
        assert_eq!(unparsed, vec![bad.to_string(), "not-a-job-id".to_string()]);
        j.save_to(&path).unwrap();
        let (again, report) = JobJournal::load_reporting(&path).unwrap();
        assert_eq!(again.unparsed.len(), 2, "written back");
        assert_eq!(again.unparsed[&bad.to_string()]["state"], "Teleporting");
        assert_eq!(report.unparsed.len(), 2);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_newer_format_refuses_to_load() {
        let path = tmp_path("newer");
        std::fs::write(&path, r#"{"format_version":3,"entries":{}}"#).unwrap();
        match JobJournal::load_checked_from(&path) {
            Err(JournalLoadError::NewerFormat { found: 3, .. }) => {}
            other => panic!("{other:?}"),
        }
        assert!(path.exists(), "left in place");
        std::fs::remove_file(&path).unwrap();
        // A missing file is an empty journal of the current format.
        let j = JobJournal::load_checked_from(&path).unwrap();
        assert!(j.entries.is_empty());
        assert_eq!(j.format_version, JOURNAL_FORMAT_VERSION);
    }

    /// A journal this build cannot load is never written over: the run's journal goes beside it.
    #[test]
    fn an_unloadable_journal_is_written_beside_not_over() {
        let path = PathBuf::from("/home/x/.zkminer/job_journal.json");
        assert_eq!(aside_path(&path, 42), PathBuf::from("/home/x/.zkminer/job_journal.json.aside-42"));
    }

    /// Entries that do not parse are kept until an authoritative read shows their job terminal.
    #[test]
    fn unparsed_entries_go_once_their_job_is_terminal() {
        let path = tmp_path("unparsed-gc");
        let (a, b) = (B256::repeat_byte(0x41), B256::repeat_byte(0x42));
        std::fs::write(
            &path,
            format!(r#"{{"format_version":2,"entries":{{"{a}":{{"state":"Teleported"}},"{b}":7,"not-a-job":{{}}}}}}"#),
        )
        .unwrap();
        let mut j = JobJournal::load_checked_from(&path).unwrap();
        let mut ids = j.unparsed_job_ids();
        ids.sort();
        assert_eq!(ids, vec![a, b]);
        assert_eq!(j.drop_unparsed(&[a]), 1);
        assert!(j.unparsed.contains_key(&format!("{b}")) && j.unparsed.contains_key("not-a-job"));
        assert_eq!(j.drop_unparsed(&[]), 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_witness_bundle_reference_round_trips() {
        let path = tmp_path("witness");
        let mut j = JobJournal::default();
        let jid = B256::repeat_byte(0x31);
        let r = WitnessBundleRef {
            job_id: jid,
            descriptor_hash: B256::repeat_byte(0x32),
            prover: Address::repeat_byte(0x33),
            version: 4,
        };
        j.record_witness_bundle(jid, r);
        assert_eq!(j.witness_bundle(jid), None, "no entry, nothing recorded");
        j.record_claim_intent(jid, 0, None);
        j.record_witness_bundle(jid, r);
        j.save_to(&path).unwrap();
        let back = JobJournal::load_checked_from(&path).unwrap();
        assert_eq!(back.witness_bundle(jid), Some(r));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn where_we_saw_our_lock_only_moves_forward() {
        let mut j = JobJournal::default();
        let jid = B256::repeat_byte(0x05);
        j.note_lock_seen(jid, Some(10), 1);
        assert!(!j.entries.contains_key(&jid), "no entry, nothing to note");
        j.record_claim_intent(jid, 100, None);
        assert_eq!(
            (j.entries[&jid].lock_block, j.entries[&jid].lock_reopens),
            (0, None)
        );
        j.note_lock_seen(jid, Some(10), 1);
        j.note_lock_seen(jid, None, 0);
        j.note_lock_seen(jid, Some(5), 0);
        assert_eq!(
            (j.entries[&jid].lock_block, j.entries[&jid].lock_reopens),
            (10, Some(1))
        );
        j.note_lock_seen(jid, Some(20), 2);
        assert_eq!(
            (j.entries[&jid].lock_block, j.entries[&jid].lock_reopens),
            (20, Some(2))
        );
        // An entry written before these fields existed loads with them unknown.
        let old: JournalEntry = serde_json::from_str(r#"{"job_id":"0x0505050505050505050505050505050505050505050505050505050505050505","claimed_at":1,"lock_deadline":9,"state":"Claimed"}"#).unwrap();
        assert_eq!((old.lock_block, old.lock_reopens), (0, None));
    }

    #[test]
    fn state_transitions() {
        let mut j = JobJournal::default();
        let jid = B256::repeat_byte(0x01);
        j.record_claim_intent(jid, 100, Some(B256::repeat_byte(0x02)));
        assert_eq!(j.entries[&jid].state, JournalState::Claiming);
        // A second claim intent never overwrites an existing entry's data or age (it may track an
        // unresolved earlier claim), but drops what was seen of an earlier lock.
        j.entries.get_mut(&jid).unwrap().claimed_at = 1;
        j.note_lock_seen(jid, Some(10), 1);
        j.record_claim_intent(jid, 999, None);
        assert_eq!(j.entries[&jid].claimed_at, 1);
        assert_eq!(
            (j.entries[&jid].lock_block, j.entries[&jid].lock_reopens),
            (0, None)
        );
        assert_eq!(j.entries[&jid].lock_deadline, 100);
        assert_eq!(j.entries[&jid].submit_tx, Some(B256::repeat_byte(0x02)));
        // A claim whose outcome is unknown restarts the age: an OPEN read is "may still be pending"
        // for as long after the LATEST such send.
        j.note_claim_unconfirmed(jid);
        assert!(j.entries[&jid].claimed_at > 1);
        j.mark_claimed(jid, None, 100);
        assert_eq!(j.entries[&jid].state, JournalState::Claimed);
        // Past Claiming, the age is the lock's and stays.
        j.entries.get_mut(&jid).unwrap().claimed_at = 1;
        j.note_claim_unconfirmed(jid);
        assert_eq!(j.entries[&jid].claimed_at, 1);
        j.mark_proving(jid);
        assert_eq!(j.entries[&jid].state, JournalState::Proving);
        j.mark_fulfilling(jid);
        assert_eq!(j.entries[&jid].state, JournalState::Fulfilling);
        j.remove(jid);
        assert!(!j.entries.contains_key(&jid));
    }

    /// A proof that ends in its run takes its start back; one whose run ended first (the miner
    /// killed mid-proof) stays counted across a save and a load, and an entry written before the
    /// count existed (or with none) loads at 0 and writes none.
    #[test]
    fn unfinished_proof_starts_survive_a_restart() {
        let path = tmp_path("prove-starts");
        let mut j = JobJournal::default();
        let jid = B256::repeat_byte(0x07);
        j.mark_claimed(jid, None, 100);
        j.note_prove_start(jid);
        j.note_prove_end(jid);
        assert_eq!(j.prove_starts(jid), 0);
        assert!(!serde_json::to_string(&j).unwrap().contains("prove_starts"));
        for _ in 0..2 {
            j.note_prove_start(jid);
            j.save_to(&path).unwrap();
            j = JobJournal::load_checked_from(&path).unwrap();
        }
        assert_eq!(j.prove_starts(jid), 2);
        j.note_prove_end(jid);
        j.note_prove_end(jid);
        j.note_prove_end(jid);
        assert_eq!(j.prove_starts(jid), 0, "never below 0");
        assert_eq!(j.prove_starts(B256::ZERO), 0);
        let _ = std::fs::remove_file(&path);
    }

    /// A completed proof resets the count (it counts runs in a row); a crash-loop mark survives a
    /// save and a load and the job's own removal, holds the job for its window and its submitter's
    /// jobs of the same program for a day, and is dropped after.
    #[test]
    fn crash_loop_marks_survive_a_restart_and_expire() {
        let path = tmp_path("crash-looped");
        let mut j = JobJournal::default();
        let (jid, other) = (B256::repeat_byte(0x51), B256::repeat_byte(0x52));
        let (program, submitter) = (B256::repeat_byte(0x61), Address::repeat_byte(0x71));
        j.mark_claimed(jid, None, 100);
        j.note_prove_start(jid);
        j.note_prove_start(jid);
        j.note_prove_completed(jid);
        assert_eq!(j.prove_starts(jid), 0);

        let now = 1_800_000_000;
        assert_eq!(j.crash_loop_hold(jid, submitter, program, now), None);
        j.mark_crash_looped(jid, program, submitter, now);
        j.remove(jid);
        j.save_to(&path).unwrap();
        let j = JobJournal::load_checked_from(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(j
            .crash_loop_hold(jid, submitter, program, now + 60)
            .is_some());
        // Its submitter's other job of the same program: a day.
        let (_, left) = j
            .crash_loop_hold(other, submitter, program, now + 60)
            .unwrap();
        assert_eq!(left, CRASH_LOOP_PAIR_HOLD_SECS - 60);
        assert_eq!(
            j.crash_loop_hold(other, submitter, program, now + CRASH_LOOP_PAIR_HOLD_SECS),
            None
        );
        // Another program, or another submitter: not held.
        assert_eq!(j.crash_loop_hold(other, submitter, B256::ZERO, now), None);
        assert_eq!(j.crash_loop_hold(other, Address::ZERO, program, now), None);
        // The job itself: its window, then free.
        assert!(j
            .crash_loop_hold(jid, submitter, program, now + CRASH_LOOP_PAIR_HOLD_SECS)
            .is_some());
        assert_eq!(
            j.crash_loop_hold(jid, submitter, program, now + CRASH_LOOP_JOB_HOLD_SECS),
            None
        );
        // Expired marks are dropped at the next mark.
        let mut j = j;
        j.mark_crash_looped(other, program, submitter, now + CRASH_LOOP_JOB_HOLD_SECS);
        assert_eq!(j.crash_looped.len(), 1);
    }

    #[test]
    fn a_claims_measured_sizes_are_kept_across_a_restart() {
        let path = tmp_path("po2s");
        let _ = std::fs::remove_file(&path);
        let mut j = JobJournal::default();
        let jid = B256::repeat_byte(0x07);
        j.note_measured_po2s(jid, &[20]);
        assert!(j.measured_po2s(jid).is_empty(), "no entry, nothing to note");
        j.record_claim_intent(jid, 100, None);
        j.note_measured_po2s(jid, &[20, 19]);
        // A later claim's sizes are added: either claim's lock measured clean at its own.
        j.record_claim_intent(jid, 100, None);
        j.note_measured_po2s(jid, &[21, 20]);
        assert_eq!(j.measured_po2s(jid), vec![19, 20, 21]);
        j.save_to(&path).unwrap();
        assert_eq!(
            JobJournal::load_checked_from(&path).unwrap().measured_po2s(jid),
            vec![19, 20, 21]
        );
        std::fs::remove_file(&path).unwrap();
        // A breadcrumb written before sizes were recorded loads with none.
        let old: JournalEntry = serde_json::from_str(r#"{"job_id":"0x0505050505050505050505050505050505050505050505050505050505050505","claimed_at":1,"lock_deadline":9,"state":"Claimed"}"#).unwrap();
        assert!(old.measured_po2s.is_empty());
    }

    #[test]
    fn a_claims_measured_cycles_are_kept_across_a_restart() {
        let path = tmp_path("cycles");
        let _ = std::fs::remove_file(&path);
        let mut j = JobJournal::default();
        let jid = B256::repeat_byte(0x08);
        j.record_claim_intent(jid, 100, None);
        j.note_measured_cycles(jid, Some(85_000_000), Some(4));
        // A later claim without a measurement keeps the one recorded.
        j.note_measured_cycles(jid, None, None);
        j.save_to(&path).unwrap();
        let e = JobJournal::load_checked_from(&path).unwrap().entries[&jid].clone();
        assert_eq!(
            (e.measured_cycles, e.measured_execute_secs),
            (Some(85_000_000), Some(4))
        );
        std::fs::remove_file(&path).unwrap();
        // A breadcrumb written before cycles were recorded loads with none.
        let old: JournalEntry = serde_json::from_str(r#"{"job_id":"0x0505050505050505050505050505050505050505050505050505050505050505","claimed_at":1,"lock_deadline":9,"state":"Claimed"}"#).unwrap();
        assert_eq!(old.measured_cycles, None);
    }

    /// Review 7 WR-1: the journal records whose locks it holds. A miner with another key refuses
    /// to take over one with entries; an empty one, its own, or one written before the owner was
    /// recorded (then stamped at its next save) is taken over.
    #[test]
    fn a_journal_of_another_address_is_not_taken_over() {
        let a: Address = "0x00000000000000000000000000000000000000aa"
            .parse()
            .unwrap();
        let b: Address = "0x00000000000000000000000000000000000000bb"
            .parse()
            .unwrap();
        let mut j = JobJournal::default();
        j.record_claim_intent(B256::repeat_byte(1), 1, None);
        // Written before the owner was recorded: accepted, and stamped with the new owner.
        assert_eq!(j.prover, None);
        assert_eq!(j.key_changed_refusal(b), None);
        assert_eq!(j.stamped(Some(b)).prover, Some(b));
        assert_eq!(j.stamped(None).prover, None);
        // Owned by `a`: round-trips through the file, and `b` is refused.
        j.prover = Some(a);
        let path = tmp_path("owner");
        j.save_to(&path).unwrap();
        let loaded = JobJournal::load_checked_from(&path).unwrap();
        assert_eq!(loaded.prover, Some(a));
        let why = loaded
            .key_changed_refusal(b)
            .expect("another key is refused");
        assert!(
            why.contains(&format!("{a:?}"))
                && why.contains(&format!("{b:?}"))
                && why.contains("--forget-foreign-locks"),
            "{why}"
        );
        assert_eq!(loaded.key_changed_refusal(a), None);
        // Empty: nothing to lose.
        let mut empty = loaded.clone();
        empty.entries.clear();
        assert_eq!(empty.key_changed_refusal(b), None);
        // An entry that did not parse counts.
        empty.unparsed.insert("x".into(), serde_json::Value::Null);
        assert!(empty.key_changed_refusal(b).is_some());
        // An old journal without the field, or an owner that does not parse, loads as unowned.
        let text = std::fs::read_to_string(&path).unwrap();
        let text = text.replace(&format!("{a:?}"), "not-an-address");
        std::fs::write(&path, text).unwrap();
        let loaded = JobJournal::load_checked_from(&path).unwrap();
        assert_eq!(loaded.prover, None);
        assert_eq!(loaded.entries.len(), 1);
        let _ = std::fs::remove_file(&path);
    }
}
