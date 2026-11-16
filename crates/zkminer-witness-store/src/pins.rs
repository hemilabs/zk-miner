//! Pins (plan §15.2): one fsynced file per (jobId, descriptorHash, prover) under `<root>/pins/`,
//! written before the claim intent is journaled and before the lock transaction is signed.

use alloy_primitives::{Address, B256};
use zkminer_witness::bundle::PinRecord;

use crate::error::{Defect, Reject, StoreError};
use crate::fsutil::{is_enoent, Kind};
use crate::layout::pin_name;
use crate::store::{BundleKey, BundleRef, PinState, PinStatus, Store};

impl Store {
    /// The pin record for a version as it is on disk: its `input_sha256` and the sha256 of its
    /// `bundle.json` bytes, which every read through the pin re-checks. The lock evidence
    /// (`reopen_count`, `lock_block`, `pinned_at_unix`) is the caller's to fill in. The version is read as
    /// [`Store::read`] reads it (without the descriptor re-hash). The caller compares
    /// `input_sha256` with the input it executed before pinning.
    pub fn pin_record(&self, r: &BundleRef, pinned_at_block: u64) -> Result<PinRecord, StoreError> {
        let inner = &self.inner;
        inner.check_usable()?;
        let vdir = inner.open_version(r)?;
        let (b, json_sha256) = inner.load_record_in(&vdir, r)?;
        inner.check_w_in(&vdir, r, b.w_len)?;
        Ok(PinRecord {
            job_id: r.job_id,
            descriptor_hash: r.descriptor_hash,
            prover: r.prover,
            bundle_version: r.version,
            pinned_at_block,
            input_sha256: b.input_sha256,
            bundle_json_sha256: json_sha256,
            reopen_count: None,
            lock_block: 0,
            pinned_at_unix: 0,
        })
    }

    /// Pins a published version. Durable when it returns `Ok`: the record is written to a fresh
    /// file, fsynced, renamed into `pins/`, and `pins/` is fsynced. The version must exist and read
    /// back (record and `w.bin` size) — [`StoreError::Missing`] or [`StoreError::Corrupt`] otherwise
    /// — and its `input_sha256` and `bundle.json` must be the ones `rec` names
    /// ([`Defect::PinMismatch`], rejected; see [`Store::pin_record`]). Re-pinning a key at another
    /// version replaces its pin atomically. Pins are never refused for the store's own quota (they
    /// protect locks); only a full filesystem refuses one.
    ///
    /// An identical pin returns without writing only when this `Store` wrote and fsynced it itself;
    /// a pin read back from disk is rewritten, since nothing proves it ever reached the disk. If the
    /// write fails, the key's pin is unknown ([`PinStatus::Unreadable`]: every version protected)
    /// until it is pinned or unpinned successfully, or a scan reads it back; a failure after the
    /// rename also poisons the store.
    pub fn pin(&self, rec: &PinRecord) -> Result<(), StoreError> {
        let inner = &self.inner;
        inner.check_usable()?;
        let key = BundleKey::of_pin(rec);
        let r = key.at(rec.bundle_version);
        let mut st = inner.state();
        let vdir = inner.open_version(&r)?;
        let (b, json_sha256) = inner.load_record_in(&vdir, &r)?;
        inner.check_w_in(&vdir, &r, b.w_len)?;
        if b.input_sha256 != rec.input_sha256 || json_sha256 != rec.bundle_json_sha256 {
            return Err(StoreError::Rejected(Reject::Record(Defect::PinMismatch)));
        }
        if let Some(PinState::Readable { rec: cur, durable_here: true }) = st.pins.get(&key) {
            if cur == rec {
                return Ok(());
            }
        }
        let json = serde_json::to_vec_pretty(rec).expect("pin record serializes");
        let pins = inner.pins_area()?;
        match inner.write_atomic(&mut st, &pins, &pin_name(&key), &json, 0o444) {
            Ok(()) => {
                st.pins.insert(key, PinState::Readable { rec: rec.clone(), durable_here: true });
                Ok(())
            }
            Err(e) => {
                st.pins.insert(key, PinState::Unknown);
                Err(e)
            }
        }
    }

    /// Removes a key's pin (readable or not), durably. Returns whether one existed. A failure
    /// leaves the key's pin unknown (every version protected); a failure after the unlink also
    /// poisons the store.
    pub fn unpin(&self, job_id: B256, descriptor_hash: B256, prover: Address) -> Result<bool, StoreError> {
        let inner = &self.inner;
        inner.check_usable()?;
        let key = BundleKey::new(job_id, descriptor_hash, prover);
        let pins = inner.pins_area()?;
        let name = pin_name(&key);
        let path = pins.child(&name);
        let mut st = inner.state();
        let s = match pins.stat_opt(&name) {
            Ok(Some(s)) if s.kind == Kind::Dir => return Err(StoreError::layout(&path)),
            Ok(Some(s)) => s,
            Ok(None) => {
                st.pins.remove(&key);
                return Ok(false);
            }
            Err(e) => return Err(StoreError::io(e, &path)),
        };
        if let Err(e) = pins.unlink(&name) {
            if is_enoent(&e) {
                st.pins.remove(&key);
                return Ok(false);
            }
            st.pins.insert(key, PinState::Unknown);
            return Err(inner.failed(e, &path, false));
        }
        st.durable.sub(s.usage());
        if let Err(e) = pins.fsync() {
            st.pins.insert(key, PinState::Unknown);
            return Err(inner.failed(e, pins.path(), true));
        }
        st.pins.remove(&key);
        Ok(true)
    }

    /// Every readable pin.
    pub fn pins(&self) -> Vec<PinRecord> {
        self.inner.state().readable_pins()
    }

    /// Keys whose pin file exists but cannot be read, or whose pin write or removal failed. Every
    /// version of such a key is protected from eviction, and its job from deletion, until it is
    /// pinned or unpinned successfully.
    pub fn unreadable_pins(&self) -> Vec<BundleKey> {
        self.inner.state().unknown_pins()
    }

    pub fn pin_status(&self, key: &BundleKey) -> PinStatus {
        self.inner.state().pin_status(key)
    }
}
