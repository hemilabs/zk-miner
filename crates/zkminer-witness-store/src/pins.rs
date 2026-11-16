//! Pins (plan §15.2): one fsynced file per (jobId, descriptorHash, prover) under `<root>/pins/`,
//! written before the claim intent is journaled and before the lock transaction is signed.

use std::fs;
use std::io;

use alloy_primitives::{Address, B256};
use zkminer_witness::bundle::PinRecord;

use crate::error::StoreError;
use crate::fsutil::{fsync_dir, tree_usage};
use crate::layout::pin_name;
use crate::store::{BundleKey, PinStatus, Store};

impl Store {
    /// Pins a published version. Durable when it returns `Ok`: the record is written to a fresh
    /// file, fsynced, renamed into `pins/`, and `pins/` is fsynced. The version must exist and read
    /// back (record and `w.bin` size); [`StoreError::Missing`] or [`StoreError::Corrupt`]
    /// otherwise. Re-pinning a key at another version replaces its pin atomically. Pins are never
    /// refused for the store's own quota (they protect locks); only a full filesystem refuses one.
    pub fn pin(&self, rec: &PinRecord) -> Result<(), StoreError> {
        let inner = &self.inner;
        inner.check_root()?;
        let key = BundleKey::of_pin(rec);
        let r = key.at(rec.bundle_version);
        let mut st = inner.state();
        let b = inner.load_record(&r)?;
        inner.check_w_file(&r, b.w_len)?;
        if st.pins.get(&key) == Some(&Some(rec.clone())) {
            return Ok(());
        }
        let json = serde_json::to_vec_pretty(rec).expect("pin record serializes");
        inner.write_atomic(&mut st, &inner.pins_dir(), &pin_name(&key), &json, 0o444)?;
        st.pins.insert(key, Some(rec.clone()));
        Ok(())
    }

    /// Removes a key's pin (readable or not), durably. Returns whether one existed.
    pub fn unpin(&self, job_id: B256, descriptor_hash: B256, prover: Address) -> Result<bool, StoreError> {
        let inner = &self.inner;
        inner.check_root()?;
        let key = BundleKey::new(job_id, descriptor_hash, prover);
        let path = inner.pin_path(&key);
        let mut st = inner.state();
        let u = match tree_usage(&path) {
            Ok(u) => u,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                st.pins.remove(&key);
                return Ok(false);
            }
            Err(e) => return Err(StoreError::io(e, &path)),
        };
        fs::remove_file(&path).map_err(|e| StoreError::io(e, &path))?;
        st.durable.sub(u);
        st.pins.remove(&key);
        let dir = inner.pins_dir();
        fsync_dir(&dir).map_err(|e| StoreError::io(e, &dir))?;
        Ok(true)
    }

    /// Every readable pin.
    pub fn pins(&self) -> Vec<PinRecord> {
        self.inner.state().pins.values().flatten().cloned().collect()
    }

    /// Keys whose pin file exists but cannot be read. Every version of such a key is protected
    /// from eviction, and its job from deletion, until it is unpinned or re-pinned.
    pub fn unreadable_pins(&self) -> Vec<BundleKey> {
        self.inner.state().pins.iter().filter(|(_, p)| p.is_none()).map(|(k, _)| *k).collect()
    }

    pub fn pin_status(&self, key: &BundleKey) -> PinStatus {
        self.inner.state().pin_status(key)
    }
}
