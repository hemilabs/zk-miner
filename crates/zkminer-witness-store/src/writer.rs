//! Streaming a new bundle version: `W` into `<root>/tmp/<random>/w.bin` (or a hard link of an
//! existing version's `W`), then `finish` verifies the record against what was written and
//! publishes the directory by one rename.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use alloy_primitives::{Address, B256};
use sha2::{Digest, Sha256};
use zkminer_witness::binding::journal_prefix;
use zkminer_witness::bundle::{BundleV1, BUNDLE_FORMAT_VERSION};

use crate::error::{Defect, Reject, StoreError};
use crate::fsutil::{clear_nonblock, fchmod, fstat, fsync_file, is_enoent, random_name, write_all, Dir, Kind};
use crate::layout::{b256_name, addr_name, elf_name, version_name, BUNDLE_JSON, W_BIN};
use crate::store::{
    check_record, finalize, hash_into, BundleKey, BundleRef, BundleSummary, Inner, Store, Usage, VersionInfo,
    BUNDLE_MAX_INODES, MAX_BUNDLE_JSON_BYTES,
};

/// What [`Store::begin_bundle_evicting`] frees beyond `max_w_bytes`, for `bundle.json`.
pub const BUNDLE_JSON_ALLOWANCE: u64 = 1 << 20;

/// A bundle version being written. Its version number is reserved (durably) when it begins, so the
/// record can carry it ([`BundleWriter::version`]). Dropping it without [`BundleWriter::finish`]
/// (or a failed `finish`) removes its temporary directory: an interrupted write is never visible as
/// a version, and the number is simply never used.
pub struct BundleWriter {
    inner: Arc<Inner>,
    key: BundleKey,
    version: u32,
    tmp: Dir,
    /// The writer's directory's name under `tmp/`.
    name: String,
    dir: Dir,
    /// `w.bin`, open for writing until sealed.
    file: Option<File>,
    max_w_bytes: u64,
    written: u64,
    w_hash: Sha256,
    /// `sha256(abi.encode(jobId, prover) ‖ W)`, used when the record says `prefix`.
    prefixed_hash: Sha256,
    /// What this writer added to the store's usage (all under `tmp/` until published).
    reserved: Usage,
    failed: bool,
    /// `w.bin` is read-only and fsynced; no more writes.
    sealed: bool,
    published: bool,
}

impl std::fmt::Debug for BundleWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleWriter")
            .field("key", &self.key)
            .field("version", &self.version)
            .field("written", &self.written)
            .field("sealed", &self.sealed)
            .finish()
    }
}

impl Inner {
    /// Reserves a version and creates the writer's directory under `tmp/`.
    fn new_writer(self: &Arc<Self>, key: BundleKey, add: Usage, max_w_bytes: u64) -> Result<BundleWriter, StoreError> {
        let tmp = self.tmp()?;
        let name = random_name().map_err(|e| StoreError::io(e, tmp.path()))?;
        let (version, dir) = {
            let mut st = self.state();
            self.admit(&st, add.plus(Usage::new(0, BUNDLE_MAX_INODES)))?;
            let version = self.reserve_version(&mut st)?;
            tmp.mkdir(&name).map_err(|e| self.failed(e, &tmp.child(&name), false))?;
            let dir = match tmp.sub(&name) {
                Ok(d) => d,
                Err(e) => {
                    let _ = tmp.rmdir(&name);
                    return Err(self.failed(e, &tmp.child(&name), false));
                }
            };
            st.transient.add(Usage::new(0, 1));
            (version, dir)
        };
        let mut prefixed_hash = Sha256::new();
        prefixed_hash.update(journal_prefix(key.job_id, key.prover));
        Ok(BundleWriter {
            inner: Arc::clone(self),
            key,
            version,
            tmp,
            name,
            dir,
            file: None,
            max_w_bytes,
            written: 0,
            w_hash: Sha256::new(),
            prefixed_hash,
            reserved: Usage::new(0, 1),
            failed: false,
            sealed: false,
            published: false,
        })
    }
}

impl Store {
    /// Starts a new version of (jobId, descriptorHash, prover) and reserves its number. `W` is then
    /// streamed with [`BundleWriter::write_w`], at most `max_w_bytes` of it, each piece admitted
    /// against the quota and the free-space floor before it is written.
    ///
    /// Unpinned versions are a cache, but they count against the quota until evicted: call
    /// [`Store::evict_to`] first, or use [`Store::begin_bundle_evicting`].
    pub fn begin_bundle(
        &self,
        job_id: B256,
        descriptor_hash: B256,
        prover: Address,
        max_w_bytes: u64,
    ) -> Result<BundleWriter, StoreError> {
        let inner = &self.inner;
        inner.check_usable()?;
        let mut wr = inner.new_writer(BundleKey::new(job_id, descriptor_hash, prover), Usage::default(), max_w_bytes)?;
        let p = wr.dir.child(W_BIN);
        let f = wr.dir.create_new(W_BIN, 0o600).map_err(|e| inner.failed(e, &p, false))?;
        wr.file = Some(f);
        wr.account(Usage::new(0, 1));
        Ok(wr)
    }

    /// [`Store::begin_bundle`], first evicting unpinned versions (lowest `value_fn` first, as
    /// [`Store::evict_to`]) until there is room for `max_w_bytes` plus [`BUNDLE_JSON_ALLOWANCE`],
    /// once eviction is enabled ([`Store::mark_recovery_scan_complete`]); before that it is
    /// `begin_bundle`. Admission is still per piece: a witness or record larger than planned can
    /// still meet [`StoreError::RetentionFull`].
    pub fn begin_bundle_evicting(
        &self,
        job_id: B256,
        descriptor_hash: B256,
        prover: Address,
        max_w_bytes: u64,
        value_fn: &dyn Fn(&crate::BundleMeta) -> u64,
    ) -> Result<BundleWriter, StoreError> {
        if self.recovery_scan_complete() {
            self.evict_to(max_w_bytes.saturating_add(BUNDLE_JSON_ALLOWANCE), value_fn)?;
        }
        self.begin_bundle(job_id, descriptor_hash, prover, max_w_bytes)
    }

    /// Starts a new version of `from`'s key whose `W` is `from`'s, shared by a hard link (never
    /// copied, never rewritten): for executing at a po2 the bundle lacks, or re-versioning after a
    /// journal divergence (plan §15.2, §15.3), always from the retained `W`. `from` is read as
    /// [`Store::read`] reads it, and the linked file is hashed against its record, so the new
    /// version starts from a verified `W`. The writer is sealed: [`BundleWriter::seal_w`] hands out
    /// `W` for execution, and [`BundleWriter::finish`] takes the new record (same `W` fields, the
    /// writer's version). The linked bytes count against the quota once per version.
    pub fn begin_version_from(&self, from: &BundleRef) -> Result<BundleWriter, StoreError> {
        let inner = &self.inner;
        inner.check_usable()?;
        let (src, b) = inner.read_version(from)?;
        inner.check_w_in(&src, from, b.w_len)?;
        let mut wr = inner.new_writer(from.key(), Usage::new(b.w_len, 0), b.w_len)?;
        if let Err(e) = src.link_to(W_BIN, &wr.dir, W_BIN) {
            let p = src.child(W_BIN);
            return Err(if is_enoent(&e) { inner.vanished(from, &src, &p) } else { inner.failed(e, &p, false) });
        }
        wr.account(Usage::new(b.w_len, 1));
        wr.sealed = true;
        // What will be published is exactly what is hashed here: the linked inode.
        let p = src.child(W_BIN);
        let mut f = wr.open_sealed()?;
        let mut w_hash = Sha256::new();
        let mut prefixed = Sha256::new();
        prefixed.update(journal_prefix(b.job_id, b.prover));
        let n = hash_into(&mut f, &mut w_hash, &mut prefixed).map_err(|e| StoreError::io(e, &p))?;
        let w = finalize(w_hash.clone());
        let input = if b.prefix { finalize(prefixed.clone()) } else { w };
        if n != b.w_len {
            return Err(StoreError::corrupt(Defect::WLength, &p));
        }
        if w != b.w_sha256 {
            return Err(StoreError::corrupt(Defect::WHash, &p));
        }
        if input != b.input_sha256 {
            return Err(StoreError::corrupt(Defect::InputHash, &p));
        }
        wr.w_hash = w_hash;
        wr.prefixed_hash = prefixed;
        wr.written = n;
        wr.max_w_bytes = n;
        Ok(wr)
    }
}

impl BundleWriter {
    pub fn key(&self) -> BundleKey {
        self.key
    }

    /// The version this writer publishes as; the record's `version` must say it.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Bytes of `W` written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    fn account(&mut self, u: Usage) {
        self.inner.state().transient.add(u);
        self.reserved.add(u);
    }

    fn fail(&mut self, e: StoreError) -> StoreError {
        self.failed = true;
        e
    }

    /// Appends to `W`. Refuses (and fails the writer) past `max_w_bytes`
    /// ([`Reject::WitnessTooLarge`]), past the quota or the floor ([`StoreError::RetentionFull`]),
    /// after [`BundleWriter::seal_w`] ([`Reject::Sealed`]), or on an I/O error.
    pub fn write_w(&mut self, data: &[u8]) -> Result<(), StoreError> {
        if self.failed {
            return Err(StoreError::Rejected(Reject::WriterFailed));
        }
        if self.sealed {
            return Err(StoreError::Rejected(Reject::Sealed));
        }
        if let Err(e) = self.inner.check_usable() {
            return Err(self.fail(e));
        }
        let n = data.len() as u64;
        if self.written.saturating_add(n) > self.max_w_bytes {
            return Err(self.fail(StoreError::Rejected(Reject::WitnessTooLarge { max: self.max_w_bytes })));
        }
        {
            let mut st = self.inner.state();
            if let Err(e) = self.inner.admit(&st, Usage::new(n, 0)) {
                drop(st);
                return Err(self.fail(e));
            }
            st.transient.add(Usage::new(n, 0));
            st.pending_bytes += n;
            self.reserved.add(Usage::new(n, 0));
        }
        let p = self.dir.child(W_BIN);
        let res = write_all(self.file.as_mut().expect("an unsealed writer has its file"), data, &p);
        self.inner.state().pending_bytes -= n;
        if let Err(e) = res {
            return Err(self.fail(StoreError::io(e, &p)));
        }
        self.written += n;
        self.w_hash.update(data);
        self.prefixed_hash.update(data);
        Ok(())
    }

    /// Makes `W` final for execution before publication (plan §5.1 step 2 executes from the
    /// persisted `W`; step 8 publishes it): `w.bin` is made read-only and fsynced (once), and a
    /// fresh read-only fd of it is returned for the execute worker. Afterwards
    /// [`BundleWriter::write_w`] is refused ([`Reject::Sealed`]) and [`BundleWriter::finish`]
    /// publishes the same file. A failed seal fails the writer (its fsync is never retried).
    pub fn seal_w(&mut self) -> Result<File, StoreError> {
        if self.failed {
            return Err(StoreError::Rejected(Reject::WriterFailed));
        }
        if let Err(e) = self.inner.check_usable() {
            return Err(self.fail(e));
        }
        if let Err(e) = self.seal() {
            return Err(self.fail(e));
        }
        self.open_sealed().map_err(|e| self.fail(e))
    }

    fn seal(&mut self) -> Result<(), StoreError> {
        if self.sealed {
            return Ok(());
        }
        let p = self.dir.child(W_BIN);
        let f = self.file.take().expect("an unsealed writer has its file");
        self.sealed = true;
        fchmod(&f, 0o444, &p).map_err(|e| self.inner.failed(e, &p, false))?;
        fsync_file(&f, &p).map_err(|e| self.inner.failed(e, &p, false))
    }

    fn open_sealed(&self) -> Result<File, StoreError> {
        let p = self.dir.child(W_BIN);
        let f = self.dir.open_ro(W_BIN).map_err(|e| StoreError::io(e, &p))?;
        let m = fstat(f.as_raw_fd()).map_err(|e| StoreError::io(e, &p))?;
        if m.kind != Kind::File {
            return Err(StoreError::corrupt(Defect::NotRegularFile, &p));
        }
        clear_nonblock(&f).map_err(|e| StoreError::io(e, &p))?;
        Ok(f)
    }

    /// Verifies `bundle` against what was written and publishes it as this writer's version.
    ///
    /// Checks: the format version; the record's key is the writer's and its `version` is
    /// [`BundleWriter::version`]; `w_len` and `w_sha256` are what was written; `input_sha256 ==
    /// sha256(prefix ‖ W)` with the prefix `abi.encode(jobId, prover)` when `bundle.prefix`; the
    /// descriptor hashes to `descriptor_hash` under `descriptor_hash_fn`; every po2 journal is unique,
    /// at most 32 KiB and hashes to its `journal_sha256`; the ELF `bundle.image_id` is in the store.
    ///
    /// Then: `w.bin` (unless sealed already) and `bundle.json` are made read-only and fsynced, the
    /// temporary directory is fsynced, missing parent directories are created (each fsynced into its
    /// parent), the directory is renamed to `v<n>`, and the key directory is fsynced. When this
    /// returns `Ok`, the version survives a crash. If that last fsync fails, the version is renamed
    /// back into `tmp/` (best effort), never indexed, and the store is poisoned.
    pub fn finish(
        mut self,
        bundle: &BundleV1,
        descriptor_hash_fn: &dyn Fn(&[u8]) -> Option<B256>,
    ) -> Result<BundleRef, StoreError> {
        let reject = |d| StoreError::Rejected(Reject::Record(d));
        if self.failed {
            return Err(StoreError::Rejected(Reject::WriterFailed));
        }
        if bundle.format_version != BUNDLE_FORMAT_VERSION {
            return Err(reject(Defect::FormatVersion));
        }
        if BundleKey::of_bundle(bundle) != self.key {
            return Err(reject(Defect::KeyMismatch));
        }
        if bundle.version != self.version {
            return Err(reject(Defect::VersionMismatch));
        }
        if bundle.w_len != self.written {
            return Err(reject(Defect::WLength));
        }
        let w_sha256 = finalize(self.w_hash.clone());
        if bundle.w_sha256 != w_sha256 {
            return Err(reject(Defect::WHash));
        }
        let input = if bundle.prefix { finalize(self.prefixed_hash.clone()) } else { w_sha256 };
        if bundle.input_sha256 != input {
            return Err(reject(Defect::InputHash));
        }
        check_record(bundle, descriptor_hash_fn).map_err(reject)?;
        let json = serde_json::to_vec_pretty(bundle).map_err(|_| reject(Defect::Unparseable))?;
        if json.len() as u64 > MAX_BUNDLE_JSON_BYTES {
            return Err(reject(Defect::TooLarge));
        }
        let inner = Arc::clone(&self.inner);
        inner.check_usable()?;

        // Contents durable inside the temporary directory.
        self.seal()?;
        let json_usage = Usage::new(json.len() as u64, 1);
        {
            let mut st = inner.state();
            inner.admit(&st, json_usage)?;
            st.transient.add(json_usage);
            st.pending_bytes += json_usage.bytes;
            self.reserved.add(json_usage);
        }
        let json_path = self.dir.child(BUNDLE_JSON);
        let res = (|| -> std::io::Result<()> {
            let mut f = self.dir.create_new(BUNDLE_JSON, 0o600)?;
            write_all(&mut f, &json, &json_path)?;
            fchmod(&f, 0o444, &json_path)?;
            fsync_file(&f, &json_path)
        })();
        inner.state().pending_bytes -= json_usage.bytes;
        res.map_err(|e| inner.failed(e, &json_path, false))?;
        self.dir.fsync().map_err(|e| inner.failed(e, self.dir.path(), false))?;

        // Publish under the store lock.
        let mut st = inner.state();
        inner.check_usable()?;
        let elfs = inner.elfs()?;
        let elf = elf_name(&bundle.image_id);
        match elfs.stat_opt(&elf) {
            Ok(Some(s)) if s.kind == Kind::File => {}
            Ok(_) => return Err(StoreError::Rejected(Reject::ElfMissing)),
            Err(e) => return Err(StoreError::io(e, &elfs.child(&elf))),
        }
        let bundles = inner.bundles()?;
        let job = inner.ensure_sub(&mut st, &bundles, &b256_name(&self.key.job_id))?;
        let desc = inner.ensure_sub(&mut st, &job, &b256_name(&self.key.descriptor_hash))?;
        let key_dir = inner.ensure_sub(&mut st, &desc, &addr_name(&self.key.prover))?;
        let vname = version_name(self.version);
        let vpath = key_dir.child(&vname);
        self.tmp.rename_to(&self.name, &key_dir, &vname, true).map_err(|e| inner.failed(e, &vpath, false))?;
        // Visible. Its parents' entries were made durable when they were created.
        if let Err(e) = key_dir.fsync() {
            let err = inner.failed(e, key_dir.path(), true);
            // Not durable: take it back out of view (never fsyncing that directory again) and
            // leave it unindexed, so nothing — a pin least of all — builds on it.
            if key_dir.rename_to(&vname, &self.tmp, &self.name, true).is_err() {
                self.published = true;
                st.transient.sub(self.reserved);
                st.durable.add(self.reserved);
            }
            drop(st);
            return Err(err);
        }
        self.published = true;
        st.transient.sub(self.reserved);
        st.durable.add(self.reserved);
        let r = self.key.at(self.version);
        st.index_insert(r, VersionInfo { usage: self.reserved, record: Ok(BundleSummary::of(bundle)) });
        drop(st);
        Ok(r)
    }
}

impl Drop for BundleWriter {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        drop(self.file.take());
        let _ = self.tmp.remove_tree(&self.name);
        let left = self.tmp.tree_usage_opt(&self.name);
        let mut st = self.inner.state();
        st.transient.sub(self.reserved);
        // Anything a failed removal left is still on disk until the next open cleans `tmp/`.
        if let Ok(left) = left {
            st.transient.add(left);
        }
    }
}
