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
    /// On-chain lock deadline (unix seconds) — a hint; authoritative value is
    /// always re-read from chain before acting.
    pub lock_deadline: u64,
    pub state: JournalState,
}

impl Default for JournalEntry {
    fn default() -> Self {
        Self {
            job_id: B256::ZERO,
            claimed_at: 0,
            claim_tx: None,
            lock_deadline: 0,
            state: JournalState::Claiming,
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

    pub fn record_claim_intent(&mut self, job_id: B256, lock_deadline: u64) {
        self.entries.insert(
            job_id,
            JournalEntry {
                job_id,
                claimed_at: chrono::Utc::now().timestamp(),
                claim_tx: None,
                lock_deadline,
                state: JournalState::Claiming,
            },
        );
    }

    pub fn mark_claimed(&mut self, job_id: B256, claim_tx: Option<B256>, lock_deadline: u64) {
        let e = self.entries.entry(job_id).or_insert(JournalEntry {
            job_id,
            claimed_at: chrono::Utc::now().timestamp(),
            claim_tx: None,
            lock_deadline,
            state: JournalState::Claimed,
        });
        if claim_tx.is_some() {
            e.claim_tx = claim_tx;
        }
        e.lock_deadline = lock_deadline;
        e.state = JournalState::Claimed;
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
    fn roundtrip_save_load() {
        let path = tmp_path("roundtrip");
        let _ = std::fs::remove_file(&path);
        let mut j = JobJournal::default();
        let jid = B256::repeat_byte(0xAB);
        j.record_claim_intent(jid, 12345);
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
    fn state_transitions() {
        let mut j = JobJournal::default();
        let jid = B256::repeat_byte(0x01);
        j.record_claim_intent(jid, 100);
        assert_eq!(j.entries[&jid].state, JournalState::Claiming);
        j.mark_claimed(jid, None, 100);
        assert_eq!(j.entries[&jid].state, JournalState::Claimed);
        j.mark_proving(jid);
        assert_eq!(j.entries[&jid].state, JournalState::Proving);
        j.mark_fulfilling(jid);
        assert_eq!(j.entries[&jid].state, JournalState::Fulfilling);
        j.remove(jid);
        assert!(!j.entries.contains_key(&jid));
    }
}
