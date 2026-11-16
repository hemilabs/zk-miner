//! Persisted local verdicts (plan §15.2, §16): one small file per job under `<root>/verdicts/`, the
//! serde encoding of the fixed-shape [`VerdictRecord`] (no attacker strings, bounded size), dropped
//! when the job is deleted as terminal or once it expires.

use alloy_primitives::B256;
use zkminer_witness::verdict::VerdictRecord;

use crate::error::{Defect, StoreError};
use crate::fsutil::{is_enoent, read_capped, Kind, ReadError};
use crate::layout::{parse_verdict_name, verdict_name};
use crate::store::{Inner, State, Store, Usage, MAX_SMALL_RECORD_BYTES};

impl Inner {
    /// Removes a job's verdict if present.
    pub(crate) fn drop_verdict(&self, st: &mut State, job_id: &B256) -> Result<bool, StoreError> {
        let verdicts = self.verdicts()?;
        Ok(self.remove_entry(st, &verdicts, &verdict_name(job_id), false, &mut |_| {})?.is_some())
    }
}

impl Store {
    /// Records (or replaces) a job's verdict, durably. Counted against the quota.
    pub fn put_verdict(&self, v: &VerdictRecord) -> Result<(), StoreError> {
        let inner = &self.inner;
        inner.check_usable()?;
        let json = serde_json::to_vec(v).expect("verdict serializes");
        debug_assert!(json.len() as u64 <= MAX_SMALL_RECORD_BYTES);
        let verdicts = inner.verdicts()?;
        let name = verdict_name(&v.job_id);
        let mut st = inner.state();
        let add = match verdicts.stat_opt(&name) {
            Ok(Some(s)) if s.kind == Kind::File => Usage::new((json.len() as u64).saturating_sub(s.len), 0),
            Ok(Some(_)) => return Err(StoreError::layout(&verdicts.child(&name))),
            Ok(None) => Usage::new(json.len() as u64, 1),
            Err(e) => return Err(StoreError::io(e, &verdicts.child(&name))),
        };
        inner.admit(&st, add)?;
        inner.write_atomic(&mut st, &verdicts, &name, &json, 0o600)
    }

    /// A job's verdict: `None` when there is none, [`StoreError::Corrupt`] when its file does not
    /// read back as a record for this job.
    pub fn verdict(&self, job_id: B256) -> Result<Option<VerdictRecord>, StoreError> {
        let inner = &self.inner;
        inner.check_usable()?;
        let verdicts = inner.verdicts()?;
        let name = verdict_name(&job_id);
        let p = verdicts.child(&name);
        let bytes = match read_capped(&verdicts, &name, MAX_SMALL_RECORD_BYTES) {
            Ok(b) => b,
            Err(ReadError::Io(e)) if is_enoent(&e) => return Ok(None),
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
        inner.check_usable()?;
        let verdicts = inner.verdicts()?;
        let mut st = inner.state();
        let mut dropped = 0;
        for e in verdicts.entries().map_err(|e| StoreError::io(e, verdicts.path()))? {
            let Some(name) = e.utf8() else { continue };
            let Some(job_id) = parse_verdict_name(name) else { continue };
            let keep = match read_capped(&verdicts, name, MAX_SMALL_RECORD_BYTES) {
                Ok(b) => serde_json::from_slice::<VerdictRecord>(&b)
                    .is_ok_and(|v| v.job_id == job_id && v.expires_at > now_unix),
                Err(ReadError::Io(err)) if is_enoent(&err) => continue,
                Err(ReadError::Io(err)) => return Err(StoreError::io(err, &verdicts.child(name))),
                Err(ReadError::TooLarge | ReadError::NotRegular) => false,
            };
            // A directory planted under a verdict's name is a layout problem, not a verdict.
            if !keep && e.kind != Kind::Dir && inner.remove_entry(&mut st, &verdicts, name, false, &mut |_| {})?.is_some() {
                dropped += 1;
            }
        }
        Ok(dropped)
    }
}
