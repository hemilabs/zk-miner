//! Eviction (plan §15.2: nothing before one full recovery scan; never a pinned bundle; lowest value
//! first) and terminal deletion (only on an authoritative terminal read, with no pin, re-checked
//! under the lock).

use std::collections::HashMap;
use std::io;

use alloy_primitives::{Address, B256};

use crate::error::{Reject, StoreError};
use crate::layout::{b256_name, parse_pin_name};
use crate::store::{entries, BundleKey, BundleMeta, BundleRef, Store, TerminalProof, Usage};

/// What [`Store::evict_to`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvictReport {
    pub evicted: Vec<BundleRef>,
    pub elfs_removed: Vec<B256>,
    pub freed: Usage,
    /// [`Store::headroom`] afterwards.
    pub headroom: u64,
    /// `headroom >= target_free_bytes`.
    pub reached: bool,
}

/// What [`Store::delete_job`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteReport {
    pub versions_removed: usize,
    pub freed: Usage,
    pub elfs_removed: Vec<B256>,
    pub verdict_removed: bool,
}

fn job_range(job_id: B256) -> std::ops::RangeInclusive<BundleRef> {
    let lo = BundleRef { job_id, descriptor_hash: B256::ZERO, prover: Address::ZERO, version: 0 };
    let hi = BundleRef {
        job_id,
        descriptor_hash: B256::repeat_byte(0xff),
        prover: Address::repeat_byte(0xff),
        version: u32::MAX,
    };
    lo..=hi
}

impl Store {
    /// Enables eviction. Call once this process has completed its full recovery scan.
    pub fn mark_recovery_scan_complete(&self) {
        self.inner.state().scan_complete = true;
    }

    pub fn recovery_scan_complete(&self) -> bool {
        self.inner.state().scan_complete
    }

    /// Frees space until [`Store::headroom`] reaches `target_free_bytes`: first ELFs nothing
    /// references or holds, then unprotected versions in ascending `value_fn` order (ties: older
    /// block, then lower version). Never a pinned version, never the latest version of a pinned
    /// key, never any version of a key whose pin is unreadable; protection is re-checked under the
    /// lock before each removal. `value_fn` runs without the store lock held, but must not call
    /// back into the store. [`StoreError::EvictionDisabled`] until
    /// [`Store::mark_recovery_scan_complete`].
    pub fn evict_to(
        &self,
        target_free_bytes: u64,
        value_fn: &dyn Fn(&BundleMeta) -> u64,
    ) -> Result<EvictReport, StoreError> {
        let inner = &self.inner;
        inner.check_root()?;
        let metas = {
            let st = inner.state();
            if !st.scan_complete {
                return Err(StoreError::EvictionDisabled);
            }
            let headroom = inner.headroom(&st)?;
            if headroom >= target_free_bytes {
                return Ok(EvictReport { headroom, reached: true, ..Default::default() });
            }
            st.metas()
        };
        let mut ranked: Vec<(u64, u64, BundleRef)> = metas
            .iter()
            .filter(|m| !m.protected())
            .map(|m| (value_fn(m), m.record.as_ref().map_or(0, |s| s.created_at_block), m.bundle))
            .collect();
        ranked.sort();

        let mut st = inner.state();
        let mut report = EvictReport::default();
        let before = st.total();
        let ids = inner.elf_ids()?;
        report.elfs_removed = inner.collect_elfs(&mut st, &ids)?;
        for (_, _, r) in ranked {
            if inner.headroom(&st)? >= target_free_bytes {
                break;
            }
            let Some(info) = st.versions.get(&r) else { continue };
            if st.meta(&r, info).protected() {
                continue;
            }
            inner.remove_entry(&mut st, &inner.version_dir(&r))?;
            let info = st.index_remove(&r);
            inner.prune_empty(&mut st, &r.key())?;
            report.evicted.push(r);
            if let Some(Ok(s)) = info.map(|i| i.record) {
                report.elfs_removed.extend(inner.collect_elfs(&mut st, &[s.image_id])?);
            }
        }
        let after = st.total();
        report.freed = Usage::new(before.bytes.saturating_sub(after.bytes), before.inodes.saturating_sub(after.inodes));
        report.headroom = inner.headroom(&st)?;
        report.reached = report.headroom >= target_free_bytes;
        Ok(report)
    }

    /// Bytes of retained versions per `BundleV1.caller` (readable versions; the per-caller cap of
    /// plan §15.2 is applied by the miner to the bundles of Open jobs it may lock).
    pub fn bytes_by_caller(&self) -> HashMap<Address, u64> {
        let st = self.inner.state();
        let mut m: HashMap<Address, u64> = HashMap::new();
        for info in st.versions.values() {
            if let Ok(s) = &info.record {
                *m.entry(s.caller).or_default() += info.usage.bytes;
            }
        }
        m
    }

    /// Deletes every version of a job, drops the ELF references they held (collecting ELFs left
    /// unreferenced and unheld), and drops the job's verdict.
    ///
    /// `terminal` is the caller's assertion of an authoritative read showing the job terminal.
    /// Refused with [`StoreError::Pinned`] while any (descriptor, prover) of the job is pinned,
    /// readable or not; the pins are re-checked in memory and on disk under the store's lock, so a
    /// concurrent [`Store::pin`] either lands first (and the delete is refused) or finds the
    /// bundle gone ([`StoreError::Missing`]). A [`crate::BundleWriter`] still streaming for the job
    /// publishes afterwards as a new, unpinned version: a cache entry that eviction or a later
    /// delete removes.
    pub fn delete_job(&self, job_id: B256, terminal: &TerminalProof) -> Result<DeleteReport, StoreError> {
        if terminal.job_id != job_id {
            return Err(StoreError::Rejected(Reject::TerminalJobMismatch));
        }
        let inner = &self.inner;
        inner.check_root()?;
        let mut st = inner.state();
        let mut pinned: Vec<BundleKey> = st.pins.keys().filter(|k| k.job_id == job_id).copied().collect();
        let prefix = format!("{}.", b256_name(&job_id));
        for (n, _, _) in entries(&inner.pins_dir())? {
            let Some(n) = n.filter(|n| n.starts_with(&prefix)) else { continue };
            // A pin file of this job that does not even parse still blocks the delete.
            let k = parse_pin_name(&n).unwrap_or(BundleKey::new(job_id, B256::ZERO, Address::ZERO));
            if !pinned.contains(&k) {
                pinned.push(k);
            }
        }
        if !pinned.is_empty() {
            return Err(StoreError::Pinned(pinned));
        }

        let mut report = DeleteReport::default();
        let jdir = inner.job_dir(&job_id);
        match std::fs::symlink_metadata(&jdir) {
            Ok(_) => report.freed = inner.remove_entry(&mut st, &jdir)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(StoreError::io(e, &jdir)),
        }
        let refs: Vec<BundleRef> = st.versions.range(job_range(job_id)).map(|(r, _)| *r).collect();
        let mut image_ids = Vec::new();
        for r in refs {
            if let Some(info) = st.index_remove(&r) {
                report.versions_removed += 1;
                if let Ok(s) = info.record {
                    image_ids.push(s.image_id);
                }
            }
        }
        report.elfs_removed = inner.collect_elfs(&mut st, &image_ids)?;
        report.verdict_removed = inner.drop_verdict(&mut st, &job_id)?;
        Ok(report)
    }
}
