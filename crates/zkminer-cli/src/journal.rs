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

use std::collections::HashMap;
use std::path::PathBuf;

use alloy::primitives::B256;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JobJournal {
    pub entries: HashMap<B256, JournalEntry>,
}

impl JobJournal {
    /// Default path: `~/.zkminer/job_journal.json`.
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".zkminer")
            .join("job_journal.json")
    }

    /// Load the journal from disk. Returns an empty journal if the file
    /// does not exist or fails to parse (logs a warning on parse failure).
    pub fn load() -> Self {
        Self::load_from(&Self::default_path())
    }

    pub fn load_from(path: &std::path::Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<Self>(&content) {
                Ok(j) => j,
                Err(e) => {
                    tracing::warn!(
                        "Job journal at {} is corrupt ({}); starting with empty journal",
                        path.display(),
                        e,
                    );
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// Write the journal atomically: write to a sibling tmp file then rename.
    pub fn save(&self) -> Result<()> {
        self.save_to(&Self::default_path())
    }

    pub fn save_to(&self, path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create journal dir {}", parent.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        let content = serde_json::to_string_pretty(self).context("Failed to serialize journal")?;
        std::fs::write(&tmp, content)
            .with_context(|| format!("Failed to write journal tmp {}", tmp.display()))?;
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

    pub fn mark_fulfilling(&mut self, job_id: B256) {
        if let Some(e) = self.entries.get_mut(&job_id) {
            e.state = JournalState::Fulfilling;
        }
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
        let loaded = JobJournal::load_from(&path);
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

        let loaded = JobJournal::load_from(&path);
        assert_eq!(loaded.entries.len(), 1);
        let e = loaded.entries.get(&jid).unwrap();
        assert_eq!(e.state, JournalState::Claimed);
        assert_eq!(e.lock_deadline, 12345);
        assert_eq!(e.claim_tx, Some(B256::repeat_byte(0xCD)));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn corrupt_file_yields_empty_journal() {
        let path = tmp_path("corrupt");
        std::fs::write(&path, "not valid json {{{").unwrap();
        let loaded = JobJournal::load_from(&path);
        assert!(loaded.entries.is_empty());
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
            JobJournal::load_from(&path).measured_po2s(jid),
            vec![19, 20, 21]
        );
        std::fs::remove_file(&path).unwrap();
        // A breadcrumb written before sizes were recorded loads with none.
        let old: JournalEntry = serde_json::from_str(r#"{"job_id":"0x0505050505050505050505050505050505050505050505050505050505050505","claimed_at":1,"lock_deadline":9,"state":"Claimed"}"#).unwrap();
        assert!(old.measured_po2s.is_empty());
    }
}
