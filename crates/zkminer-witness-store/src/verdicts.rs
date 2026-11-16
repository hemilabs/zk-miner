//! Persisted local verdicts (plan §15.2, §16): one small file per job under `<root>/verdicts/`, the
//! serde encoding of the fixed-shape [`VerdictRecord`] (no attacker strings, bounded size), dropped
//! when the job is deleted as terminal or once it expires.

use std::fs;
use std::io;

use alloy_primitives::B256;
use zkminer_witness::verdict::VerdictRecord;

use crate::error::{Defect, StoreError};
use crate::fsutil::{read_capped, ReadError};
use crate::layout::{parse_verdict_name, verdict_name};
use crate::store::{entries, Inner, State, Store, Usage, MAX_SMALL_RECORD_BYTES};

impl Inner {
    /// Removes a job's verdict if present.
    pub(crate) fn drop_verdict(&self, st: &mut State, job_id: &B256) -> Result<bool, StoreError> {
        let p = self.verdict_path(job_id);
        match fs::symlink_metadata(&p) {
            Ok(_) => {
                self.remove_entry(st, &p)?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StoreError::io(e, &p)),
        }
    }
}

impl Store {
    /// Records (or replaces) a job's verdict, durably. Counted against the quota.
    pub fn put_verdict(&self, v: &VerdictRecord) -> Result<(), StoreError> {
        let inner = &self.inner;
        inner.check_root()?;
        let json = serde_json::to_vec(v).expect("verdict serializes");
        debug_assert!(json.len() as u64 <= MAX_SMALL_RECORD_BYTES);
        let mut st = inner.state();
        let p = inner.verdict_path(&v.job_id);
        let old = fs::symlink_metadata(&p).ok().filter(|m| m.is_file()).map(|m| m.len());
        let add = match old {
            Some(o) => Usage::new((json.len() as u64).saturating_sub(o), 0),
            None => Usage::new(json.len() as u64, 1),
        };
        inner.admit(&st, add)?;
        inner.write_atomic(&mut st, &inner.verdicts_dir(), &verdict_name(&v.job_id), &json, 0o600)
    }

    /// A job's verdict: `None` when there is none, [`StoreError::Corrupt`] when its file does not
    /// read back as a record for this job.
    pub fn verdict(&self, job_id: B256) -> Result<Option<VerdictRecord>, StoreError> {
        let inner = &self.inner;
        inner.check_root()?;
        let p = inner.verdict_path(&job_id);
        let bytes = match read_capped(&p, MAX_SMALL_RECORD_BYTES) {
            Ok(b) => b,
            Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(ReadError::Io(e)) => return Err(StoreError::io(e, &p)),
            Err(ReadError::TooLarge) => return Err(StoreError::corrupt(Defect::TooLarge, &p)),
            Err(ReadError::NotRegular) => return Err(StoreError::corrupt(Defect::NotRegularFile, &p)),
        };
        match serde_json::from_slice::<VerdictRecord>(&bytes) {
            Ok(v) if v.job_id == job_id => Ok(Some(v)),
            Ok(_) => Err(StoreError::corrupt(Defect::KeyMismatch, &p)),
            Err(_) => Err(StoreError::corrupt(Defect::Unparseable, &p)),
        }
    }

    /// Drops every verdict with `expires_at <= now_unix`, and every verdict file that does not read
    /// back as a record for its job (a verdict is advisory; an unreadable one is worth nothing).
    /// Returns how many were dropped.
    pub fn expire_verdicts(&self, now_unix: u64) -> Result<usize, StoreError> {
        let inner = &self.inner;
        inner.check_root()?;
        let mut st = inner.state();
        let mut dropped = 0;
        for (n, p, _) in entries(&inner.verdicts_dir())? {
            let Some(job_id) = n.as_deref().and_then(parse_verdict_name) else { continue };
            let keep = match read_capped(&p, MAX_SMALL_RECORD_BYTES) {
                Ok(b) => serde_json::from_slice::<VerdictRecord>(&b)
                    .is_ok_and(|v| v.job_id == job_id && v.expires_at > now_unix),
                Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(ReadError::Io(e)) => return Err(StoreError::io(e, &p)),
                Err(ReadError::TooLarge | ReadError::NotRegular) => false,
            };
            if !keep {
                inner.remove_entry(&mut st, &p)?;
                dropped += 1;
            }
        }
        Ok(dropped)
    }
}
