//! The store: open (filesystem, identity, lock, `tmp/` cleanup, usage), the in-memory index, quota
//! admission, bundle reads and the recovery scan.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zkminer_witness::binding::{journal_prefix, MAX_JOURNAL_BYTES, STREAM_CHUNK_BYTES};
use zkminer_witness::bundle::{BundleV1, PinRecord, StoreIdentity, BUNDLE_FORMAT_VERSION};

use crate::error::{Defect, FullReason, StoreError, UnavailableKind};
use crate::fsutil::{
    clear_nonblock, create_new, decode_hex, fs_avail_bytes, fs_type, fsync_dir, is_uuid, open_ro, random_name, read_capped,
    refused_fs_type, remove_any, tree_usage, tree_usage_opt, uuid_v4, ReadError,
};
use crate::layout::{
    addr_name, b256_name, elf_name, parse_addr_name, parse_b256_name, parse_pin_name, parse_version_name, pin_name,
    verdict_name, version_name, AREAS, BUNDLES, BUNDLE_JSON, ELFS, IDENTITY, LOCK, LOST_FOUND, NEXT_VERSION, OWNED,
    PINS, TMP, VERDICTS, W_BIN,
};

/// The bound on `bundle.json` (the descriptor plus at most a few 32 KiB journals, hex).
pub const MAX_BUNDLE_JSON_BYTES: u64 = 8 << 20;
/// The bound on identity, pin, verdict and counter files.
pub(crate) const MAX_SMALL_RECORD_BYTES: u64 = 4096;
/// The bound on a retained ELF.
pub const MAX_ELF_BYTES: u64 = 512 << 20;
/// `store_format` in `identity.json`.
pub const STORE_FORMAT_VERSION: u32 = 1;
/// Entries a bundle can add: its directory, `w.bin`, `bundle.json` and three parent directories.
pub(crate) const BUNDLE_MAX_INODES: u64 = 6;

/// Limits and creation policy (plan §19 `[retention] quota`, `free_floor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreOptions {
    /// Bytes of regular files the store may hold.
    pub quota_bytes: u64,
    /// Entries (files and directories) the store may hold.
    pub quota_inodes: u64,
    /// New writes are refused when the filesystem's available bytes (`statvfs`) would fall below
    /// this.
    pub free_space_floor_bytes: u64,
    /// Initialise a root directory that holds nothing yet (only `.lock`, `lost+found` or `tmp`).
    /// The root itself is never created: an absent root is [`UnavailableKind::RootAbsent`], since
    /// it usually means an unmounted filesystem.
    pub create: bool,
}

/// What `identity.json` must say for this miner. With `store_uuid` set (recorded from an earlier
/// open, e.g. in the lock journal), the store must already exist with that UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedIdentity {
    pub chain_id: u64,
    pub router: Address,
    pub prover: Address,
    pub store_uuid: Option<String>,
}

/// `identity.json`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFile {
    store_format: u32,
    store_uuid: String,
    chain_id: u64,
    router: Address,
    prover: Address,
}

/// A bundle's (jobId, descriptorHash, prover): one directory holding its versions, one pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BundleKey {
    pub job_id: B256,
    pub descriptor_hash: B256,
    pub prover: Address,
}

impl BundleKey {
    pub fn new(job_id: B256, descriptor_hash: B256, prover: Address) -> Self {
        BundleKey { job_id, descriptor_hash, prover }
    }

    pub fn of_bundle(b: &BundleV1) -> Self {
        BundleKey::new(b.job_id, b.descriptor_hash, b.prover)
    }

    pub fn of_pin(p: &PinRecord) -> Self {
        BundleKey::new(p.job_id, p.descriptor_hash, p.prover)
    }

    pub fn at(self, version: u32) -> BundleRef {
        BundleRef { job_id: self.job_id, descriptor_hash: self.descriptor_hash, prover: self.prover, version }
    }
}

/// One published, immutable bundle version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BundleRef {
    pub job_id: B256,
    pub descriptor_hash: B256,
    pub prover: Address,
    pub version: u32,
}

impl BundleRef {
    pub fn key(&self) -> BundleKey {
        BundleKey::new(self.job_id, self.descriptor_hash, self.prover)
    }
}

/// Bytes of regular files and entries (inodes) under the store root.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Usage {
    pub bytes: u64,
    pub inodes: u64,
}

impl Usage {
    pub const fn new(bytes: u64, inodes: u64) -> Self {
        Usage { bytes, inodes }
    }

    pub(crate) fn add(&mut self, o: Usage) {
        self.bytes = self.bytes.saturating_add(o.bytes);
        self.inodes = self.inodes.saturating_add(o.inodes);
    }

    pub(crate) fn sub(&mut self, o: Usage) {
        self.bytes = self.bytes.saturating_sub(o.bytes);
        self.inodes = self.inodes.saturating_sub(o.inodes);
    }

    pub fn plus(mut self, o: Usage) -> Usage {
        self.add(o);
        self
    }
}

/// The pin state of a bundle's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinStatus {
    Unpinned,
    /// The key is pinned at `version`.
    Pinned { version: u32 },
    /// A pin file exists for the key but cannot be read: every version of the key is protected.
    Unreadable,
}

/// What a version's `bundle.json` says, as far as eviction and accounting need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSummary {
    pub caller: Address,
    pub image_id: B256,
    pub builder_id: B256,
    pub w_len: u64,
    pub created_at_block: u64,
    pub po2s: Vec<u32>,
}

impl BundleSummary {
    pub(crate) fn of(b: &BundleV1) -> Self {
        BundleSummary {
            caller: b.caller,
            image_id: b.image_id,
            builder_id: b.builder_id,
            w_len: b.w_len,
            created_at_block: b.created_at_block,
            po2s: b.po2_results.iter().map(|r| r.po2).collect(),
        }
    }
}

/// One complete version, as the recovery scan and eviction see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleMeta {
    pub bundle: BundleRef,
    /// The version directory: itself, `w.bin` and `bundle.json`.
    pub usage: Usage,
    pub pin: PinStatus,
    /// The highest version of its key.
    pub latest: bool,
    /// What `bundle.json` says, or why it cannot be read. Unreadable versions are reported, never
    /// skipped.
    pub record: Result<BundleSummary, Defect>,
}

impl BundleMeta {
    /// Never evicted: the pinned version, the latest version of a pinned key, and every version of
    /// a key whose pin is unreadable.
    pub fn protected(&self) -> bool {
        match self.pin {
            PinStatus::Unpinned => false,
            PinStatus::Unreadable => true,
            PinStatus::Pinned { version } => version == self.bundle.version || self.latest,
        }
    }

    pub fn caller(&self) -> Option<Address> {
        self.record.as_ref().ok().map(|s| s.caller)
    }
}

/// An entry under the store that is not part of the layout, or a pin that cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    pub path: PathBuf,
    pub kind: AnomalyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyKind {
    /// A name or file type the layout does not produce.
    UnexpectedEntry,
    /// A pin file whose record does not parse or does not match its name.
    UnreadablePin,
}

/// The recovery scan (plan §15.2): the store, not the lock journal, is the authoritative index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    /// Every complete version, readable or not.
    pub bundles: Vec<BundleMeta>,
    pub pins: Vec<PinRecord>,
    pub unreadable_pins: Vec<BundleKey>,
    pub anomalies: Vec<Anomaly>,
}

/// What `open` found and did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenReport {
    /// The identity record was created by this open.
    pub created: bool,
    /// Leftovers of interrupted writes removed from `tmp/`.
    pub tmp_entries_removed: usize,
    /// `next_version` was absent, unreadable or behind the highest version on disk, and was
    /// rewritten.
    pub version_counter_recovered: bool,
}

/// An authoritative read showing the job terminal (plan §15.2): Fulfilled, Cancelled, or Open with
/// `reopenCount ≥ MAX_REOPEN_COUNT`. The store cannot check it; constructing one is the caller's
/// assertion that it read the job's state from the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalProof {
    pub job_id: B256,
    pub state: TerminalState,
    /// The block the state was read at.
    pub read_at_block: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminalState {
    Fulfilled,
    Cancelled,
    ReopenLimit,
}

#[derive(Debug, Clone)]
pub(crate) struct VersionInfo {
    pub usage: Usage,
    pub record: Result<BundleSummary, Defect>,
}

#[derive(Default)]
pub(crate) struct State {
    /// Everything under the root except the contents of `tmp/`.
    pub durable: Usage,
    /// Contents of `tmp/`: writers in progress and anything a failed removal left.
    pub transient: Usage,
    pub versions: BTreeMap<BundleRef, VersionInfo>,
    /// `None`: the pin file exists but is unreadable.
    pub pins: BTreeMap<BundleKey, Option<PinRecord>>,
    /// Readable versions referencing each ELF.
    pub elf_refs: HashMap<B256, u32>,
    /// In-memory holds ([`crate::ElfHold`]).
    pub elf_holds: HashMap<B256, u32>,
    /// Versions whose `bundle.json` is unreadable: their ELF is unknown, so no ELF is collected.
    pub unknown_refs: usize,
    pub next_version: u32,
    pub scan_complete: bool,
    pub anomalies: Vec<Anomaly>,
}

impl State {
    pub(crate) fn total(&self) -> Usage {
        self.durable.plus(self.transient)
    }

    pub(crate) fn pin_status(&self, k: &BundleKey) -> PinStatus {
        match self.pins.get(k) {
            None => PinStatus::Unpinned,
            Some(Some(p)) => PinStatus::Pinned { version: p.bundle_version },
            Some(None) => PinStatus::Unreadable,
        }
    }

    pub(crate) fn key_versions(&self, k: &BundleKey) -> impl DoubleEndedIterator<Item = (&BundleRef, &VersionInfo)> {
        self.versions.range(k.at(0)..=k.at(u32::MAX))
    }

    pub(crate) fn meta(&self, r: &BundleRef, info: &VersionInfo) -> BundleMeta {
        let latest = self.key_versions(&r.key()).next_back().map(|(l, _)| l.version) == Some(r.version);
        BundleMeta { bundle: *r, usage: info.usage, pin: self.pin_status(&r.key()), latest, record: info.record.clone() }
    }

    pub(crate) fn metas(&self) -> Vec<BundleMeta> {
        self.versions.iter().map(|(r, i)| self.meta(r, i)).collect()
    }

    pub(crate) fn index_insert(&mut self, r: BundleRef, info: VersionInfo) {
        match &info.record {
            Ok(s) => *self.elf_refs.entry(s.image_id).or_default() += 1,
            Err(_) => self.unknown_refs += 1,
        }
        if let Some(old) = self.versions.insert(r, info) {
            self.index_forget(&old);
        }
    }

    pub(crate) fn index_remove(&mut self, r: &BundleRef) -> Option<VersionInfo> {
        let info = self.versions.remove(r)?;
        self.index_forget(&info);
        Some(info)
    }

    fn index_forget(&mut self, info: &VersionInfo) {
        match &info.record {
            Ok(s) => {
                if let Some(n) = self.elf_refs.get_mut(&s.image_id) {
                    *n -= 1;
                    if *n == 0 {
                        self.elf_refs.remove(&s.image_id);
                    }
                }
            }
            Err(_) => self.unknown_refs -= 1,
        }
    }

    fn install(&mut self, l: Loaded) {
        self.durable = l.durable;
        self.pins = l.pins;
        self.anomalies = l.anomalies;
        self.versions.clear();
        self.elf_refs.clear();
        self.unknown_refs = 0;
        for (r, info) in l.versions {
            self.index_insert(r, info);
        }
    }

    /// An ELF may be deleted: no readable version references it, none is held, and no unreadable
    /// version could.
    pub(crate) fn elf_collectable(&self, image_id: &B256) -> bool {
        self.unknown_refs == 0 && !self.elf_refs.contains_key(image_id) && !self.elf_holds.contains_key(image_id)
    }
}

#[derive(Default)]
struct Loaded {
    versions: BTreeMap<BundleRef, VersionInfo>,
    pins: BTreeMap<BundleKey, Option<PinRecord>>,
    anomalies: Vec<Anomaly>,
    durable: Usage,
    max_version: u32,
}

pub(crate) struct Inner {
    pub root: PathBuf,
    root_id: (u64, u64),
    root_dir: File,
    /// Holds the exclusive `flock` on `<root>/.lock` until the last reference is dropped.
    _lock: File,
    pub opts: StoreOptions,
    pub identity: StoreIdentity,
    pub open_report: OpenReport,
    state: Mutex<State>,
}

/// The witness retention store (plan §15). Blocking (`std::fs`), `Send + Sync`, internally locked;
/// call it from `spawn_blocking`. The `flock` on `<root>/.lock` is held until the `Store` and every
/// [`crate::BundleWriter`] and [`crate::ElfHold`] it handed out are dropped.
pub struct Store {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("root", &self.inner.root).field("identity", &self.inner.identity).finish()
    }
}

impl Inner {
    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The root path still names the directory that was opened (not unmounted, not replaced).
    pub(crate) fn check_root(&self) -> Result<(), StoreError> {
        match fs::symlink_metadata(&self.root) {
            Ok(m) if (m.dev(), m.ino()) == self.root_id => Ok(()),
            Ok(_) => Err(StoreError::unavailable(UnavailableKind::RootChanged, &self.root)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Err(StoreError::unavailable(UnavailableKind::RootAbsent, &self.root))
            }
            Err(e) => Err(StoreError::io(e, &self.root)),
        }
    }

    pub(crate) fn tmp_dir(&self) -> PathBuf {
        self.root.join(TMP)
    }

    pub(crate) fn bundles_dir(&self) -> PathBuf {
        self.root.join(BUNDLES)
    }

    pub(crate) fn job_dir(&self, job_id: &B256) -> PathBuf {
        self.bundles_dir().join(b256_name(job_id))
    }

    pub(crate) fn key_dir(&self, k: &BundleKey) -> PathBuf {
        self.job_dir(&k.job_id).join(b256_name(&k.descriptor_hash)).join(addr_name(&k.prover))
    }

    pub(crate) fn version_dir(&self, r: &BundleRef) -> PathBuf {
        self.key_dir(&r.key()).join(version_name(r.version))
    }

    pub(crate) fn pins_dir(&self) -> PathBuf {
        self.root.join(PINS)
    }

    pub(crate) fn pin_path(&self, k: &BundleKey) -> PathBuf {
        self.pins_dir().join(pin_name(k))
    }

    pub(crate) fn elfs_dir(&self) -> PathBuf {
        self.root.join(ELFS)
    }

    pub(crate) fn elf_path(&self, image_id: &B256) -> PathBuf {
        self.elfs_dir().join(elf_name(image_id))
    }

    pub(crate) fn verdicts_dir(&self) -> PathBuf {
        self.root.join(VERDICTS)
    }

    pub(crate) fn verdict_path(&self, job_id: &B256) -> PathBuf {
        self.verdicts_dir().join(verdict_name(job_id))
    }

    fn avail_bytes(&self) -> Result<u64, StoreError> {
        fs_avail_bytes(&self.root_dir).map_err(|e| StoreError::io(e, &self.root))
    }

    /// Refuses a write of `add` that would cross the quota or the free-space floor.
    pub(crate) fn admit(&self, st: &State, add: Usage) -> Result<(), StoreError> {
        let used = st.total();
        if used.bytes.saturating_add(add.bytes) > self.opts.quota_bytes {
            return Err(StoreError::RetentionFull(FullReason::QuotaBytes));
        }
        if used.inodes.saturating_add(add.inodes) > self.opts.quota_inodes {
            return Err(StoreError::RetentionFull(FullReason::QuotaInodes));
        }
        if self.avail_bytes()? < self.opts.free_space_floor_bytes.saturating_add(add.bytes) {
            return Err(StoreError::RetentionFull(FullReason::FreeSpaceFloor));
        }
        Ok(())
    }

    /// Bytes that can still be written before the quota or the floor.
    pub(crate) fn headroom(&self, st: &State) -> Result<u64, StoreError> {
        let quota = self.opts.quota_bytes.saturating_sub(st.total().bytes);
        let fs = self.avail_bytes()?.saturating_sub(self.opts.free_space_floor_bytes);
        Ok(quota.min(fs))
    }

    /// Replaces `dir/name` atomically and durably: the bytes go to a fresh file under `tmp/`, which
    /// is fsynced, renamed over the destination, and the destination directory fsynced.
    pub(crate) fn write_atomic(
        &self,
        st: &mut State,
        dir: &Path,
        name: &str,
        bytes: &[u8],
        mode: u32,
    ) -> Result<(), StoreError> {
        let dest = dir.join(name);
        let old = match fs::symlink_metadata(&dest) {
            Ok(m) if m.is_file() => Some(m.len()),
            Ok(_) => return Err(StoreError::corrupt(Defect::NotRegularFile, &dest)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(StoreError::io(e, &dest)),
        };
        let tmp = self.tmp_dir();
        let part = tmp.join(format!("{}.part", random_name().map_err(|e| StoreError::io(e, &tmp))?));
        let res = (|| -> io::Result<()> {
            let mut f = create_new(&part)?;
            f.write_all(bytes)?;
            f.set_permissions(fs::Permissions::from_mode(mode))?;
            f.sync_all()?;
            fs::rename(&part, &dest)
        })();
        if let Err(e) = res {
            let _ = fs::remove_file(&part);
            return Err(StoreError::io(e, &dest));
        }
        match old {
            Some(o) => {
                st.durable.sub(Usage::new(o, 0));
                st.durable.add(Usage::new(bytes.len() as u64, 0));
            }
            None => st.durable.add(Usage::new(bytes.len() as u64, 1)),
        }
        fsync_dir(dir).map_err(|e| StoreError::io(e, dir))
    }

    /// Creates `dir` if absent and makes its entry durable in its parent.
    pub(crate) fn ensure_dir(&self, st: &mut State, dir: &Path) -> Result<(), StoreError> {
        match fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {
                st.durable.add(Usage::new(0, 1));
                let parent = dir.parent().unwrap_or(&self.root);
                fsync_dir(parent).map_err(|e| StoreError::io(e, parent))
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => match fs::symlink_metadata(dir) {
                Ok(m) if m.is_dir() => Ok(()),
                Ok(_) => Err(StoreError::corrupt(Defect::NotDirectory, dir)),
                Err(e) => Err(StoreError::io(e, dir)),
            },
            Err(e) => Err(StoreError::io(e, dir)),
        }
    }

    /// Removes a file or a tree as one step: it is renamed into `tmp/` (so nothing partial is ever
    /// visible under its name), its old parent fsynced, then deleted.
    pub(crate) fn remove_entry(&self, st: &mut State, path: &Path) -> Result<Usage, StoreError> {
        let u = tree_usage(path).map_err(|e| StoreError::io(e, path))?;
        let tmp = self.tmp_dir();
        let grave = tmp.join(format!("{}.del", random_name().map_err(|e| StoreError::io(e, &tmp))?));
        fs::rename(path, &grave).map_err(|e| StoreError::io(e, path))?;
        st.durable.sub(u);
        if let Err(e) = remove_any(&grave) {
            // What is left is real usage until the next open cleans `tmp/`.
            if let Ok(left) = tree_usage_opt(&grave) {
                st.transient.add(left);
            }
            return Err(StoreError::io(e, &grave));
        }
        let parent = path.parent().unwrap_or(&self.root);
        fsync_dir(parent).map_err(|e| StoreError::io(e, parent))?;
        Ok(u)
    }

    /// Removes the key's directory and its parents while they are empty.
    pub(crate) fn prune_empty(&self, st: &mut State, k: &BundleKey) -> Result<(), StoreError> {
        let prover = self.key_dir(k);
        let desc = prover.parent().expect("descriptor dir").to_path_buf();
        let job = desc.parent().expect("job dir").to_path_buf();
        for d in [prover, desc, job] {
            match fs::remove_dir(&d) {
                Ok(()) => st.durable.sub(Usage::new(0, 1)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY) | Some(libc::EEXIST)) => return Ok(()),
                Err(e) => return Err(StoreError::io(e, &d)),
            }
        }
        Ok(())
    }

    /// Reads and parses a version's `bundle.json`, checking its format and that it belongs where it
    /// is stored. An absent version directory is [`StoreError::Missing`]; a version directory
    /// without a readable record is [`StoreError::Corrupt`].
    pub(crate) fn load_record(&self, r: &BundleRef) -> Result<BundleV1, StoreError> {
        let vdir = self.version_dir(r);
        match fs::symlink_metadata(&vdir) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(StoreError::corrupt(Defect::NotDirectory, &vdir)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // A vanished bundles area is an unavailable store, not a missing bundle.
                let b = self.bundles_dir();
                fs::symlink_metadata(&b).map_err(|e| StoreError::io(e, &b))?;
                return Err(StoreError::Missing { path: vdir });
            }
            Err(e) => return Err(StoreError::io(e, &vdir)),
        }
        let p = vdir.join(BUNDLE_JSON);
        let bytes = read_capped(&p, MAX_BUNDLE_JSON_BYTES).map_err(|e| entry_read_error(e, &p))?;
        let b: BundleV1 = serde_json::from_slice(&bytes).map_err(|_| StoreError::corrupt(Defect::Unparseable, &p))?;
        if b.format_version != BUNDLE_FORMAT_VERSION {
            return Err(StoreError::corrupt(Defect::FormatVersion, &p));
        }
        if BundleKey::of_bundle(&b) != r.key() {
            return Err(StoreError::corrupt(Defect::KeyMismatch, &p));
        }
        Ok(b)
    }

    /// `w.bin` is a regular file of `w_len` bytes (no hashing).
    pub(crate) fn check_w_file(&self, r: &BundleRef, w_len: u64) -> Result<(), StoreError> {
        let p = self.version_dir(r).join(W_BIN);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_file() && m.len() == w_len => Ok(()),
            Ok(m) if m.is_file() => Err(StoreError::corrupt(Defect::WLength, &p)),
            Ok(_) => Err(StoreError::corrupt(Defect::NotRegularFile, &p)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(StoreError::corrupt(Defect::FileMissing, &p)),
            Err(e) => Err(StoreError::io(e, &p)),
        }
    }

    /// The scan's view of one version: its summary, or why it is unreadable. I/O errors other than
    /// corruption make the whole scan fail (the store is unavailable).
    fn summarize(&self, r: &BundleRef) -> Result<Result<BundleSummary, Defect>, StoreError> {
        let res = self.load_record(r).and_then(|b| {
            self.check_w_file(r, b.w_len)?;
            Ok(b)
        });
        match res {
            Ok(b) => Ok(Ok(BundleSummary::of(&b))),
            Err(StoreError::Corrupt { defect, .. }) => Ok(Err(defect)),
            Err(StoreError::Missing { .. }) => Ok(Err(Defect::FileMissing)),
            Err(e) => Err(e),
        }
    }

    /// Walks the store: usage, every version, every pin.
    fn load(&self) -> Result<Loaded, StoreError> {
        let mut l = Loaded::default();
        for name in OWNED {
            let p = self.root.join(name);
            if name == TMP {
                // `tmp/` itself is durable; its contents are transient.
                if fs::symlink_metadata(&p).is_ok() {
                    l.durable.add(Usage::new(0, 1));
                }
                continue;
            }
            l.durable.add(tree_usage_opt(&p).map_err(|e| StoreError::io(e, &p))?);
        }
        self.load_bundles(&mut l)?;
        self.load_pins(&mut l)?;
        Ok(l)
    }

    fn load_bundles(&self, l: &mut Loaded) -> Result<(), StoreError> {
        fn unexpected(l: &mut Loaded, path: PathBuf) {
            l.anomalies.push(Anomaly { path, kind: AnomalyKind::UnexpectedEntry });
        }
        for (jn, jp, jd) in entries(&self.bundles_dir())? {
            let Some(job_id) = jn.as_deref().and_then(parse_b256_name).filter(|_| jd) else {
                unexpected(l, jp);
                continue;
            };
            for (dn, dp, dd) in entries(&jp)? {
                let Some(descriptor_hash) = dn.as_deref().and_then(parse_b256_name).filter(|_| dd) else {
                    unexpected(l, dp);
                    continue;
                };
                for (pn, pp, pd) in entries(&dp)? {
                    let Some(prover) = pn.as_deref().and_then(parse_addr_name).filter(|_| pd) else {
                        unexpected(l, pp);
                        continue;
                    };
                    for (vn, vp, vd) in entries(&pp)? {
                        let Some(version) = vn.as_deref().and_then(parse_version_name).filter(|_| vd) else {
                            unexpected(l, vp);
                            continue;
                        };
                        let r = BundleRef { job_id, descriptor_hash, prover, version };
                        let usage = tree_usage(&vp).map_err(|e| StoreError::io(e, &vp))?;
                        let record = self.summarize(&r)?;
                        l.max_version = l.max_version.max(version);
                        l.versions.insert(r, VersionInfo { usage, record });
                    }
                }
            }
        }
        Ok(())
    }

    fn load_pins(&self, l: &mut Loaded) -> Result<(), StoreError> {
        for (n, p, _) in entries(&self.pins_dir())? {
            let Some(key) = n.as_deref().and_then(parse_pin_name) else {
                l.anomalies.push(Anomaly { path: p, kind: AnomalyKind::UnexpectedEntry });
                continue;
            };
            let rec = match read_capped(&p, MAX_SMALL_RECORD_BYTES) {
                Ok(b) => serde_json::from_slice::<PinRecord>(&b).ok().filter(|r| BundleKey::of_pin(r) == key),
                Err(ReadError::Io(e)) => return Err(StoreError::io(e, &p)),
                Err(ReadError::TooLarge | ReadError::NotRegular) => None,
            };
            if rec.is_none() {
                l.anomalies.push(Anomaly { path: p, kind: AnomalyKind::UnreadablePin });
            }
            l.pins.insert(key, rec);
        }
        Ok(())
    }
}

/// A directory's entries: (UTF-8 name, path, is a directory — symlinks are not followed).
pub(crate) fn entries(p: &Path) -> Result<Vec<(Option<String>, PathBuf, bool)>, StoreError> {
    let rd = fs::read_dir(p).map_err(|e| StoreError::io(e, p))?;
    let mut out = Vec::new();
    for e in rd {
        let e = e.map_err(|e| StoreError::io(e, p))?;
        let path = e.path();
        let is_dir = e.file_type().map_err(|err| StoreError::io(err, &path))?.is_dir();
        out.push((e.file_name().into_string().ok(), path, is_dir));
    }
    Ok(out)
}

/// A read of a file a complete entry must hold: absence is corruption, not a missing entry.
pub(crate) fn entry_read_error(e: ReadError, p: &Path) -> StoreError {
    match e {
        ReadError::TooLarge => StoreError::corrupt(Defect::TooLarge, p),
        ReadError::NotRegular => StoreError::corrupt(Defect::NotRegularFile, p),
        ReadError::Io(e) if e.kind() == io::ErrorKind::NotFound => StoreError::corrupt(Defect::FileMissing, p),
        ReadError::Io(e) => StoreError::io(e, p),
    }
}

/// The record checks shared by `finish` and `read`: the descriptor hashes to `descriptor_hash`
/// (with the caller's hash function), and every po2 result is unique with a journal of at most
/// 32 KiB hashing to its `journal_sha256`.
pub(crate) fn check_record(b: &BundleV1, descriptor_hash_fn: &dyn Fn(&[u8]) -> Option<B256>) -> Result<(), Defect> {
    let d = decode_hex(&b.descriptor_hex).ok_or(Defect::DescriptorHex)?;
    if descriptor_hash_fn(&d) != Some(b.descriptor_hash) {
        return Err(Defect::DescriptorHash);
    }
    let mut seen = BTreeSet::new();
    for r in &b.po2_results {
        if !seen.insert(r.po2) {
            return Err(Defect::Po2Duplicate);
        }
        let j = decode_hex(&r.journal_hex).ok_or(Defect::JournalHex)?;
        if j.len() > MAX_JOURNAL_BYTES {
            return Err(Defect::JournalTooLarge);
        }
        if sha256(&j) != r.journal_sha256 {
            return Err(Defect::JournalHash);
        }
    }
    Ok(())
}

pub(crate) fn sha256(b: &[u8]) -> B256 {
    B256::from(<[u8; 32]>::from(Sha256::digest(b)))
}

pub(crate) fn finalize(h: Sha256) -> B256 {
    B256::from(<[u8; 32]>::from(h.finalize()))
}

fn is_uninitialised(root: &Path) -> Result<bool, StoreError> {
    for (n, _, _) in entries(root)? {
        if !matches!(n.as_deref(), Some(LOCK | LOST_FOUND | TMP)) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Verifies `identity.json`, or creates it in an uninitialised root when `create` allows.
fn identity(root: &Path, want: &ExpectedIdentity, create: bool) -> Result<(StoreIdentity, bool), StoreError> {
    let p = root.join(IDENTITY);
    let unavailable = |kind| StoreError::unavailable(kind, &p);
    match read_capped(&p, MAX_SMALL_RECORD_BYTES) {
        Ok(bytes) => {
            let f: IdentityFile =
                serde_json::from_slice(&bytes).map_err(|_| unavailable(UnavailableKind::IdentityInvalid))?;
            if f.store_format != STORE_FORMAT_VERSION || !is_uuid(&f.store_uuid) {
                return Err(unavailable(UnavailableKind::IdentityInvalid));
            }
            let mismatch = f.chain_id != want.chain_id
                || f.router != want.router
                || f.prover != want.prover
                || want.store_uuid.as_ref().is_some_and(|u| *u != f.store_uuid);
            if mismatch {
                return Err(unavailable(UnavailableKind::IdentityMismatch));
            }
            let id = StoreIdentity { store_uuid: f.store_uuid, chain_id: f.chain_id, router: f.router, prover: f.prover };
            Ok((id, false))
        }
        Err(ReadError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
            if !create || want.store_uuid.is_some() || !is_uninitialised(root)? {
                return Err(unavailable(UnavailableKind::IdentityMissing));
            }
            let f = IdentityFile {
                store_format: STORE_FORMAT_VERSION,
                store_uuid: uuid_v4().map_err(|e| StoreError::io(e, root))?,
                chain_id: want.chain_id,
                router: want.router,
                prover: want.prover,
            };
            let json = serde_json::to_vec_pretty(&f).expect("identity serializes");
            let tmp = root.join(TMP);
            let res = (|| -> io::Result<()> {
                match fs::DirBuilder::new().mode(0o700).create(&tmp) {
                    Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
                    _ => {}
                }
                let part = tmp.join(format!("{}.part", random_name()?));
                let mut w = create_new(&part)?;
                w.write_all(&json)?;
                w.set_permissions(fs::Permissions::from_mode(0o444))?;
                w.sync_all()?;
                fs::rename(&part, &p)?;
                fsync_dir(root)
            })();
            res.map_err(|e| StoreError::io(e, &p))?;
            let id = StoreIdentity { store_uuid: f.store_uuid, chain_id: f.chain_id, router: f.router, prover: f.prover };
            Ok((id, true))
        }
        Err(ReadError::Io(e)) => Err(StoreError::io(e, &p)),
        Err(ReadError::TooLarge | ReadError::NotRegular) => Err(unavailable(UnavailableKind::IdentityInvalid)),
    }
}

impl Store {
    /// Opens (or, with `opts.create`, initialises) the store at `root`.
    ///
    /// Refuses a symlinked root and tmpfs, ramfs and overlayfs; takes the exclusive `flock` on
    /// `<root>/.lock` (a second open fails with [`UnavailableKind::LockHeld`]); verifies or creates
    /// `identity.json`; removes leftovers of interrupted writes from `tmp/`; and scans usage, every
    /// version and every pin. Eviction stays disabled until
    /// [`Store::mark_recovery_scan_complete`].
    pub fn open(root: impl AsRef<Path>, identity_want: &ExpectedIdentity, opts: StoreOptions) -> Result<Store, StoreError> {
        let root = root.as_ref().to_path_buf();
        let unavailable = |kind| StoreError::unavailable(kind, &root);
        match fs::symlink_metadata(&root) {
            Ok(m) if m.file_type().is_symlink() => return Err(unavailable(UnavailableKind::SymlinkRoot)),
            Ok(m) if !m.is_dir() => return Err(unavailable(UnavailableKind::NotADirectory)),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(unavailable(UnavailableKind::RootAbsent)),
            Err(e) => return Err(StoreError::io(e, &root)),
        }
        let root_dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&root)
            .map_err(|e| match e.raw_os_error() {
                Some(libc::ELOOP) => unavailable(UnavailableKind::SymlinkRoot),
                Some(libc::ENOTDIR) => unavailable(UnavailableKind::NotADirectory),
                Some(libc::ENOENT) => unavailable(UnavailableKind::RootAbsent),
                _ => StoreError::io(e, &root),
            })?;
        let f_type = fs_type(&root_dir).map_err(|e| StoreError::io(e, &root))?;
        if refused_fs_type(f_type) {
            return Err(unavailable(UnavailableKind::UnsupportedFilesystem { f_type }));
        }
        let m = root_dir.metadata().map_err(|e| StoreError::io(e, &root))?;
        let root_id = (m.dev(), m.ino());

        let lock_path = root.join(LOCK);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|e| StoreError::io(e, &lock_path))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(unavailable(UnavailableKind::LockHeld)),
            Err(TryLockError::Error(e)) => return Err(StoreError::io(e, &lock_path)),
        }

        let (ident, created) = identity(&root, identity_want, opts.create)?;

        let mut made = false;
        for a in AREAS {
            let p = root.join(a);
            match fs::DirBuilder::new().mode(0o700).create(&p) {
                Ok(()) => made = true,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    if !fs::symlink_metadata(&p).map_err(|e| StoreError::io(e, &p))?.is_dir() {
                        return Err(StoreError::unavailable(UnavailableKind::BadLayout, &p));
                    }
                }
                Err(e) => return Err(StoreError::io(e, &p)),
            }
        }
        if made {
            fsync_dir(&root).map_err(|e| StoreError::io(e, &root))?;
        }

        // Interrupted writes never became versions: drop them.
        let tmp = root.join(TMP);
        let mut tmp_entries_removed = 0;
        for (_, p, _) in entries(&tmp)? {
            remove_any(&p).map_err(|e| StoreError::io(e, &p))?;
            tmp_entries_removed += 1;
        }

        let mut inner = Inner {
            root,
            root_id,
            root_dir,
            _lock: lock,
            opts,
            identity: ident,
            open_report: OpenReport::default(),
            state: Mutex::new(State::default()),
        };
        let loaded = inner.load()?;
        let max_version = loaded.max_version;
        let mut st = State::default();
        st.install(loaded);

        // Versions come from one store-wide counter, persisted before each publish, so a version
        // number is never reused even after its bundle is evicted or deleted.
        let floor = max_version.checked_add(1).ok_or(StoreError::Rejected(crate::Reject::VersionsExhausted))?;
        let counter_path = inner.root.join(NEXT_VERSION);
        let counter = match read_capped(&counter_path, MAX_SMALL_RECORD_BYTES) {
            Ok(b) => std::str::from_utf8(&b).ok().and_then(|s| s.trim().parse::<u32>().ok()),
            Err(ReadError::Io(e)) if e.kind() != io::ErrorKind::NotFound => {
                return Err(StoreError::io(e, &counter_path))
            }
            Err(_) => None,
        };
        let (next, recovered) = match counter {
            Some(c) if c >= floor => (c, false),
            _ => (floor, true),
        };
        st.next_version = next;
        if recovered {
            let root = inner.root.clone();
            inner.write_atomic(&mut st, &root, NEXT_VERSION, next.to_string().as_bytes(), 0o600)?;
        }
        inner.open_report = OpenReport {
            created,
            tmp_entries_removed,
            version_counter_recovered: recovered && !created,
        };
        *inner.state.get_mut().unwrap_or_else(|e| e.into_inner()) = st;
        Ok(Store { inner: Arc::new(inner) })
    }

    pub fn identity(&self) -> &StoreIdentity {
        &self.inner.identity
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    pub fn options(&self) -> StoreOptions {
        self.inner.opts
    }

    pub fn open_report(&self) -> OpenReport {
        self.inner.open_report
    }

    /// Usage as accounted in memory (every write and removal updates it).
    pub fn usage(&self) -> Usage {
        self.inner.state().total()
    }

    /// Usage re-counted from disk under the store's lock. Equals [`Store::usage`] whenever no
    /// writer is streaming at the same moment.
    pub fn recount_usage(&self) -> Result<Usage, StoreError> {
        let _st = self.inner.state();
        let mut u = Usage::default();
        for name in OWNED {
            let p = self.inner.root.join(name);
            u.add(tree_usage_opt(&p).map_err(|e| StoreError::io(e, &p))?);
        }
        Ok(u)
    }

    /// Bytes that can be written before the quota or the free-space floor is crossed.
    pub fn headroom(&self) -> Result<u64, StoreError> {
        self.inner.check_root()?;
        let st = self.inner.state();
        self.inner.headroom(&st)
    }

    /// Every complete version of a key, ascending, from disk.
    pub fn versions(&self, job_id: B256, descriptor_hash: B256, prover: Address) -> Result<Vec<u32>, StoreError> {
        self.inner.check_root()?;
        let dir = self.inner.key_dir(&BundleKey::new(job_id, descriptor_hash, prover));
        let mut v = match entries(&dir) {
            Ok(es) => es.into_iter().filter(|e| e.2).filter_map(|e| e.0.as_deref().and_then(parse_version_name)).collect(),
            Err(StoreError::Unavailable { kind: UnavailableKind::NotFound, .. }) => {
                let b = self.inner.bundles_dir();
                fs::symlink_metadata(&b).map_err(|e| StoreError::io(e, &b))?;
                Vec::new()
            }
            Err(e) => return Err(e),
        };
        v.sort_unstable();
        Ok(v)
    }

    /// The highest complete version of a key; [`StoreError::Missing`] when there is none. A
    /// version is complete once its directory exists (it appears by one rename); whether it reads
    /// back cleanly is [`Store::read`]'s question.
    pub fn latest(&self, job_id: B256, descriptor_hash: B256, prover: Address) -> Result<BundleRef, StoreError> {
        let k = BundleKey::new(job_id, descriptor_hash, prover);
        match self.versions(job_id, descriptor_hash, prover)?.last() {
            Some(&v) => Ok(k.at(v)),
            None => Err(StoreError::Missing { path: self.inner.key_dir(&k) }),
        }
    }

    /// Reads a version's record, re-verifying its descriptor against `descriptor_hash` with
    /// `descriptor_hash_fn` (decoding and hashing a descriptor is the chain crate's job), its po2
    /// results, and that `w.bin` has `w_len` bytes. `sha256(W)` is verified by [`Store::open_w`].
    pub fn read(
        &self,
        r: &BundleRef,
        descriptor_hash_fn: &dyn Fn(&[u8]) -> Option<B256>,
    ) -> Result<BundleV1, StoreError> {
        self.inner.check_root()?;
        let b = self.inner.load_record(r)?;
        let p = self.inner.version_dir(r).join(BUNDLE_JSON);
        check_record(&b, descriptor_hash_fn).map_err(|d| StoreError::corrupt(d, &p))?;
        self.inner.check_w_file(r, b.w_len)?;
        Ok(b)
    }

    /// Opens `w.bin` read-only, verifies `|W|`, `sha256(W)` and `sha256(prefix ‖ W)` against the
    /// record by streaming it, rewinds, and hands out the verified fd (plan §15.3: the worker
    /// receives `W` as a read-only fd).
    pub fn open_w(&self, r: &BundleRef) -> Result<File, StoreError> {
        self.inner.check_root()?;
        let b = self.inner.load_record(r)?;
        let p = self.inner.version_dir(r).join(W_BIN);
        let mut f = open_ro(&p).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => StoreError::corrupt(Defect::FileMissing, &p),
            _ => StoreError::io(e, &p),
        })?;
        let m = f.metadata().map_err(|e| StoreError::io(e, &p))?;
        if !m.is_file() {
            return Err(StoreError::corrupt(Defect::NotRegularFile, &p));
        }
        if m.len() != b.w_len {
            return Err(StoreError::corrupt(Defect::WLength, &p));
        }
        clear_nonblock(&f).map_err(|e| StoreError::io(e, &p))?;
        let mut w_hash = Sha256::new();
        let mut input_hash = Sha256::new();
        if b.prefix {
            input_hash.update(journal_prefix(b.job_id, b.prover));
        }
        let mut buf = vec![0u8; STREAM_CHUNK_BYTES];
        let mut total = 0u64;
        loop {
            let n = match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(StoreError::io(e, &p)),
            };
            w_hash.update(&buf[..n]);
            input_hash.update(&buf[..n]);
            total += n as u64;
        }
        if total != b.w_len {
            return Err(StoreError::corrupt(Defect::WLength, &p));
        }
        if finalize(w_hash) != b.w_sha256 {
            return Err(StoreError::corrupt(Defect::WHash, &p));
        }
        if finalize(input_hash) != b.input_sha256 {
            return Err(StoreError::corrupt(Defect::InputHash, &p));
        }
        f.seek(SeekFrom::Start(0)).map_err(|e| StoreError::io(e, &p))?;
        Ok(f)
    }

    /// [`Store::read`] and [`Store::open_w`] together: the record, its descriptor, and every byte
    /// of `W`. For revalidation and recovery, where the fd itself is not needed.
    pub fn verify(
        &self,
        r: &BundleRef,
        descriptor_hash_fn: &dyn Fn(&[u8]) -> Option<B256>,
    ) -> Result<BundleV1, StoreError> {
        let b = self.read(r, descriptor_hash_fn)?;
        self.open_w(r)?;
        Ok(b)
    }

    /// The recovery scan: re-reads every version and pin from disk, refreshes the index and the
    /// durable usage, and reports every complete version with its pin status, size and caller.
    /// Unreadable versions and pins are reported, never skipped.
    pub fn scan(&self) -> Result<ScanReport, StoreError> {
        self.inner.check_root()?;
        let mut st = self.inner.state();
        let loaded = self.inner.load()?;
        st.install(loaded);
        Ok(ScanReport {
            bundles: st.metas(),
            pins: st.pins.values().flatten().cloned().collect(),
            unreadable_pins: st.pins.iter().filter(|(_, p)| p.is_none()).map(|(k, _)| *k).collect(),
            anomalies: st.anomalies.clone(),
        })
    }
}
