//! Streaming a new bundle version: `W` into `<root>/tmp/<random>/w.bin`, then `finish` verifies the
//! record against what was written and publishes the directory by one rename.

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;

use alloy_primitives::{Address, B256};
use sha2::{Digest, Sha256};
use zkminer_witness::binding::journal_prefix;
use zkminer_witness::bundle::{BundleV1, BUNDLE_FORMAT_VERSION};

use crate::error::{Defect, Reject, StoreError};
use crate::fsutil::{create_new, fsync_dir, random_name, tree_usage_opt};
use crate::layout::{version_name, BUNDLE_JSON, W_BIN};
use crate::store::{
    check_record, finalize, BundleKey, BundleRef, BundleSummary, Inner, Store, Usage, VersionInfo,
    BUNDLE_MAX_INODES, MAX_BUNDLE_JSON_BYTES,
};

/// A bundle version being written. Dropping it without [`BundleWriter::finish`] (or a failed
/// `finish`) removes its temporary directory: an interrupted write is never visible as a version.
pub struct BundleWriter {
    inner: Arc<Inner>,
    key: BundleKey,
    dir: PathBuf,
    file: File,
    max_w_bytes: u64,
    written: u64,
    w_hash: Sha256,
    /// `sha256(abi.encode(jobId, prover) ‖ W)`, used when the record says `prefix`.
    prefixed_hash: Sha256,
    /// What this writer added to the store's usage (all under `tmp/` until published).
    reserved: Usage,
    failed: bool,
    published: bool,
}

impl std::fmt::Debug for BundleWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleWriter").field("key", &self.key).field("written", &self.written).finish()
    }
}

impl Store {
    /// Starts a new version of (jobId, descriptorHash, prover). `W` is then streamed with
    /// [`BundleWriter::write_w`], at most `max_w_bytes` of it, each piece admitted against the
    /// quota and the free-space floor before it is written.
    pub fn begin_bundle(
        &self,
        job_id: B256,
        descriptor_hash: B256,
        prover: Address,
        max_w_bytes: u64,
    ) -> Result<BundleWriter, StoreError> {
        let inner = &self.inner;
        inner.check_root()?;
        let mut st = inner.state();
        inner.admit(&st, Usage::new(0, BUNDLE_MAX_INODES))?;
        let tmp = inner.tmp_dir();
        let dir = tmp.join(random_name().map_err(|e| StoreError::io(e, &tmp))?);
        fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| StoreError::io(e, &dir))?;
        let w_path = dir.join(W_BIN);
        let file = match create_new(&w_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = fs::remove_dir_all(&dir);
                return Err(StoreError::io(e, &w_path));
            }
        };
        let reserved = Usage::new(0, 2);
        st.transient.add(reserved);
        drop(st);
        let mut prefixed_hash = Sha256::new();
        prefixed_hash.update(journal_prefix(job_id, prover));
        Ok(BundleWriter {
            inner: Arc::clone(inner),
            key: BundleKey::new(job_id, descriptor_hash, prover),
            dir,
            file,
            max_w_bytes,
            written: 0,
            w_hash: Sha256::new(),
            prefixed_hash,
            reserved,
            failed: false,
            published: false,
        })
    }
}

impl BundleWriter {
    pub fn key(&self) -> BundleKey {
        self.key
    }

    /// Bytes of `W` written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Appends to `W`. Refuses (and fails the writer) past `max_w_bytes`
    /// ([`Reject::WitnessTooLarge`]), past the quota or the floor ([`StoreError::RetentionFull`]),
    /// or on an I/O error.
    pub fn write_w(&mut self, data: &[u8]) -> Result<(), StoreError> {
        if self.failed {
            return Err(StoreError::Rejected(Reject::WriterFailed));
        }
        let n = data.len() as u64;
        if self.written.saturating_add(n) > self.max_w_bytes {
            self.failed = true;
            return Err(StoreError::Rejected(Reject::WitnessTooLarge { max: self.max_w_bytes }));
        }
        {
            let mut st = self.inner.state();
            if let Err(e) = self.inner.admit(&st, Usage::new(n, 0)) {
                self.failed = true;
                return Err(e);
            }
            st.transient.add(Usage::new(n, 0));
            self.reserved.add(Usage::new(n, 0));
        }
        if let Err(e) = self.file.write_all(data) {
            self.failed = true;
            return Err(StoreError::io(e, &self.dir.join(W_BIN)));
        }
        self.written += n;
        self.w_hash.update(data);
        self.prefixed_hash.update(data);
        Ok(())
    }

    /// Verifies `bundle` against what was written and publishes it as the next version.
    ///
    /// Checks: the format version; the record's key is the writer's; `w_len` and `w_sha256` are what
    /// was written; `input_sha256 == sha256(prefix ‖ W)` with the prefix `abi.encode(jobId, prover)`
    /// when `bundle.prefix`; the descriptor hashes to `descriptor_hash` under `descriptor_hash_fn`;
    /// every po2 journal is unique, at most 32 KiB and hashes to its `journal_sha256`; the ELF
    /// `bundle.image_id` is in the store.
    ///
    /// Then: `w.bin` and `bundle.json` are made read-only and fsynced, the temporary directory is
    /// fsynced, the store-wide version counter is advanced durably, the parent directories are
    /// created (each fsynced into its parent), the directory is renamed to `v<n>`, and every parent
    /// up to `bundles/` is fsynced. When this returns `Ok`, the version survives a crash.
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

        // Contents durable inside the temporary directory.
        let w_path = self.dir.join(W_BIN);
        let io = |e, p: &std::path::Path| StoreError::io(e, p);
        self.file.set_permissions(fs::Permissions::from_mode(0o444)).map_err(|e| io(e, &w_path))?;
        self.file.sync_all().map_err(|e| io(e, &w_path))?;
        let json_usage = Usage::new(json.len() as u64, 1);
        {
            let mut st = self.inner.state();
            self.inner.admit(&st, json_usage)?;
            st.transient.add(json_usage);
            self.reserved.add(json_usage);
        }
        let json_path = self.dir.join(BUNDLE_JSON);
        (|| -> std::io::Result<()> {
            let mut f = create_new(&json_path)?;
            f.write_all(&json)?;
            f.set_permissions(fs::Permissions::from_mode(0o444))?;
            f.sync_all()
        })()
        .map_err(|e| io(e, &json_path))?;
        fsync_dir(&self.dir).map_err(|e| io(e, &self.dir))?;

        // Publish under the store lock.
        let inner = Arc::clone(&self.inner);
        let mut st = inner.state();
        inner.check_root()?;
        let elf = inner.elf_path(&bundle.image_id);
        if !fs::symlink_metadata(&elf).is_ok_and(|m| m.is_file()) {
            return Err(StoreError::Rejected(Reject::ElfMissing));
        }
        let key_dir = inner.key_dir(&self.key);
        let desc_dir = key_dir.parent().expect("descriptor dir").to_path_buf();
        let job_dir = desc_dir.parent().expect("job dir").to_path_buf();
        let parents = [&job_dir, &desc_dir, &key_dir];
        let missing = parents.iter().filter(|d| fs::symlink_metadata(d).is_err()).count() as u64;
        inner.admit(&st, Usage::new(0, missing))?;

        let version = st.next_version;
        let next = version.checked_add(1).ok_or(StoreError::Rejected(Reject::VersionsExhausted))?;
        let root = inner.root.clone();
        inner.write_atomic(&mut st, &root, crate::layout::NEXT_VERSION, next.to_string().as_bytes(), 0o600)?;
        st.next_version = next;
        for d in parents {
            inner.ensure_dir(&mut st, d)?;
        }
        let vdir = key_dir.join(version_name(version));
        fs::rename(&self.dir, &vdir).map_err(|e| io(e, &vdir))?;
        self.published = true;
        st.transient.sub(self.reserved);
        st.durable.add(self.reserved);
        let r = self.key.at(version);
        st.index_insert(r, VersionInfo { usage: self.reserved, record: Ok(BundleSummary::of(bundle)) });
        // Still under the lock, so no eviction can remove the version before its entry is durable.
        for d in [&key_dir, &desc_dir, &job_dir, &inner.bundles_dir()] {
            fsync_dir(d).map_err(|e| io(e, d))?;
        }
        drop(st);
        Ok(r)
    }
}

impl Drop for BundleWriter {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        let _ = fs::remove_dir_all(&self.dir);
        let mut st = self.inner.state();
        st.transient.sub(self.reserved);
        // Anything a failed removal left is still on disk until the next open cleans `tmp/`.
        if let Ok(left) = tree_usage_opt(&self.dir) {
            st.transient.add(left);
        }
    }
}
