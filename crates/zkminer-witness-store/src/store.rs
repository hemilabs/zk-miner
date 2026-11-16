//! The store: init and open (filesystem, mount, lock, identity, `tmp/` cleanup, usage), the
//! in-memory index, quota admission, poisoning, bundle reads and the recovery scan.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{File, TryLockError};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zkminer_witness::binding::{journal_prefix, MAX_JOURNAL_BYTES, STREAM_CHUNK_BYTES};
use zkminer_witness::bundle::{BundleV1, PinRecord, StoreIdentity, BUNDLE_FORMAT_VERSION};

use crate::error::{Defect, FullReason, Reject, StoreError, UnavailableKind};
use crate::fsutil::{
    clear_nonblock, decode_hex, errno, fstat, is_enoent, is_not_a_real_dir, is_uuid, read_capped, supported_fs_type,
    uuid_v4, write_file_atomic, Dir, Entry, Kind, ReadError, Staged,
};
use crate::layout::{
    addr_name, b256_name, parse_addr_name, parse_b256_name, parse_pin_name, parse_version_name, version_name, AREAS,
    BUNDLES, BUNDLE_JSON, ELFS, IDENTITY, LOCK, LOST_FOUND, NEXT_VERSION, OWNED, PINS, TMP, VERDICTS, W_BIN,
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

/// Limits and root checks (plan §19 `[retention] quota`, `free_floor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreOptions {
    /// Bytes of regular files the store may hold. Evictable (unpinned) versions count until they
    /// are evicted: call [`Store::evict_to`] before [`Store::begin_bundle`], or use
    /// [`Store::begin_bundle_evicting`].
    pub quota_bytes: u64,
    /// Entries (files and directories) the store may hold.
    pub quota_inodes: u64,
    /// New writes are refused when the filesystem's available bytes (`statvfs`), less what
    /// concurrent writers have been admitted for but not yet written, would fall below this.
    pub free_space_floor_bytes: u64,
    /// Refuse a root that is not itself a mount point (its `st_dev` equals its parent's):
    /// [`UnavailableKind::NotMounted`]. Set it when the store has its own filesystem (plan §15.1's
    /// recommendation), so a disk that failed to mount is never taken for the store. A bind mount of
    /// a directory on the same filesystem has its parent's `st_dev` and is refused too.
    pub require_dedicated_mount: bool,
    /// Accept any filesystem. Off, only ext2/3/4, xfs, btrfs, zfs and f2fs are accepted; NFS, CIFS,
    /// FUSE, virtiofs, 9p, aufs, tmpfs, ramfs, overlay and every other type are
    /// [`UnavailableKind::UnsupportedFilesystem`].
    pub allow_any_filesystem: bool,
}

/// What `identity.json` must say for this miner. `store_uuid` is the UUID [`Store::init`] returned,
/// kept durably in the miner's configuration (never taken from the lock journal or from the store
/// itself), so an empty or foreign directory at the configured path is never accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedIdentity {
    pub chain_id: u64,
    pub router: Address,
    pub prover: Address,
    pub store_uuid: String,
}

/// What [`Store::init`] writes, and the root checks it applies (as [`StoreOptions`]' fields of the
/// same names do for `open`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreIdentityInit {
    pub chain_id: u64,
    pub router: Address,
    pub prover: Address,
    pub require_dedicated_mount: bool,
    pub allow_any_filesystem: bool,
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
    /// A pin file exists but cannot be read, or a write or removal of the key's pin failed in this
    /// process (so its state on disk is unknown): every version of the key is protected.
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
    /// A name or file type the layout does not produce (a symlink anywhere is one, never followed).
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

/// A key's pin as the store knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PinState {
    /// A readable pin: read back from disk at open or a scan, or (`durable_here`) written and
    /// fsynced by this `Store`. Only the latter lets an identical `pin` return without writing.
    Readable { rec: PinRecord, durable_here: bool },
    /// The file does not parse, or a write or removal of it failed: protects every version.
    Unknown,
}

#[derive(Default)]
pub(crate) struct State {
    /// Everything under the root except the contents of `tmp/`.
    pub durable: Usage,
    /// Contents of `tmp/`: writers in progress and anything a failed removal left.
    pub transient: Usage,
    /// Bytes admitted to writers that are being written outside the lock: the free-space floor
    /// counts them before `statvfs` can.
    pub pending_bytes: u64,
    pub versions: BTreeMap<BundleRef, VersionInfo>,
    pub pins: BTreeMap<BundleKey, PinState>,
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
            Some(PinState::Readable { rec, .. }) => PinStatus::Pinned { version: rec.bundle_version },
            Some(PinState::Unknown) => PinStatus::Unreadable,
        }
    }

    pub(crate) fn readable_pins(&self) -> Vec<PinRecord> {
        self.pins
            .values()
            .filter_map(|p| match p {
                PinState::Readable { rec, .. } => Some(rec.clone()),
                PinState::Unknown => None,
            })
            .collect()
    }

    pub(crate) fn unknown_pins(&self) -> Vec<BundleKey> {
        self.pins.iter().filter(|(_, p)| **p == PinState::Unknown).map(|(k, _)| *k).collect()
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
    pins: BTreeMap<BundleKey, PinState>,
    anomalies: Vec<Anomaly>,
    durable: Usage,
    max_version: u32,
}

pub(crate) struct Inner {
    pub root: PathBuf,
    root_id: (u64, u64),
    /// The root, opened once: every path is walked from this fd.
    pub root_dir: Dir,
    /// Holds the exclusive `flock` on `<root>/.lock` until the last reference is dropped.
    _lock: File,
    pub opts: StoreOptions,
    pub identity: StoreIdentity,
    pub open_report: OpenReport,
    poisoned: AtomicBool,
    state: Mutex<State>,
}

/// The witness retention store (plan §15). Blocking, `Send + Sync`, internally locked; call it
/// from `spawn_blocking`. The `flock` on `<root>/.lock` is held until the `Store` and every
/// [`crate::BundleWriter`] and [`crate::ElfHold`] it handed out are dropped.
pub struct Store {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("root", &self.inner.root).field("identity", &self.inner.identity).finish()
    }
}

/// A failure to open a directory the layout requires: a symlink or a non-directory is a bad
/// layout; anything else is an I/O error.
pub(crate) fn dir_error(e: io::Error, path: &Path) -> StoreError {
    if is_not_a_real_dir(&e) {
        StoreError::layout(path)
    } else {
        StoreError::io(e, path)
    }
}

/// A failure walking below `bundles/`: an absent directory is a missing entry (`missing`).
fn below_bundles(e: io::Error, path: &Path, missing: &Path) -> StoreError {
    if is_enoent(&e) {
        StoreError::Missing { path: missing.to_path_buf() }
    } else {
        dir_error(e, path)
    }
}

impl Inner {
    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// The store can be used: not poisoned, and the root path still names the directory that was
    /// opened (not unmounted, not replaced).
    pub(crate) fn check_usable(&self) -> Result<(), StoreError> {
        if self.is_poisoned() {
            return Err(StoreError::unavailable(UnavailableKind::Poisoned, &self.root));
        }
        match std::fs::symlink_metadata(&self.root) {
            Ok(m) if (m.dev(), m.ino()) == self.root_id => Ok(()),
            Ok(_) => Err(StoreError::unavailable(UnavailableKind::RootChanged, &self.root)),
            Err(e) if is_enoent(&e) => Err(StoreError::unavailable(UnavailableKind::RootAbsent, &self.root)),
            Err(e) => Err(StoreError::io(e, &self.root)),
        }
    }

    /// Maps a failed mutating call. A failure after an earlier step of the same change had made it
    /// visible, or an EIO (whose outcome is unknown), poisons the store: what is on disk may no
    /// longer be what the store promised, and nothing will be fsynced again (fsyncgate).
    pub(crate) fn failed(&self, e: io::Error, path: &Path, after_visible: bool) -> StoreError {
        if after_visible || errno(&e) == Some(libc::EIO) {
            self.poisoned.store(true, Ordering::Release);
        }
        StoreError::io(e, path)
    }

    fn staged(&self, s: Staged) -> StoreError {
        self.failed(s.err, &s.path, s.visible)
    }

    /// A top-level area: absent is `Unavailable(NotFound)`, a symlink or file `BadLayout`.
    pub(crate) fn area(&self, name: &str) -> Result<Dir, StoreError> {
        self.root_dir.sub(name).map_err(|e| {
            let p = self.root.join(name);
            if is_enoent(&e) {
                StoreError::unavailable(UnavailableKind::NotFound, &p)
            } else {
                dir_error(e, &p)
            }
        })
    }

    pub(crate) fn tmp(&self) -> Result<Dir, StoreError> {
        self.area(TMP)
    }

    pub(crate) fn bundles(&self) -> Result<Dir, StoreError> {
        self.area(BUNDLES)
    }

    pub(crate) fn pins_area(&self) -> Result<Dir, StoreError> {
        self.area(PINS)
    }

    pub(crate) fn elfs(&self) -> Result<Dir, StoreError> {
        self.area(ELFS)
    }

    pub(crate) fn verdicts(&self) -> Result<Dir, StoreError> {
        self.area(VERDICTS)
    }

    pub(crate) fn key_path(&self, k: &BundleKey) -> PathBuf {
        self.root
            .join(BUNDLES)
            .join(b256_name(&k.job_id))
            .join(b256_name(&k.descriptor_hash))
            .join(addr_name(&k.prover))
    }

    pub(crate) fn version_path(&self, r: &BundleRef) -> PathBuf {
        self.key_path(&r.key()).join(version_name(r.version))
    }

    fn walk(&self, names: &[String], missing: &Path) -> Result<Dir, StoreError> {
        let mut d = self.bundles()?;
        for name in names {
            d = d.sub(name).map_err(|e| below_bundles(e, &d.child(name), missing))?;
        }
        Ok(d)
    }

    /// A key's directory, walked from the root without following any symlink: `Missing` when it
    /// (or its job or descriptor directory) is absent, `Unavailable` when `bundles/` is, `BadLayout`
    /// when any level is a symlink or not a directory.
    pub(crate) fn open_key(&self, k: &BundleKey) -> Result<Dir, StoreError> {
        let names = [b256_name(&k.job_id), b256_name(&k.descriptor_hash), addr_name(&k.prover)];
        self.walk(&names, &self.key_path(k))
    }

    /// A version's directory, as [`Inner::open_key`].
    pub(crate) fn open_version(&self, r: &BundleRef) -> Result<Dir, StoreError> {
        let names =
            [b256_name(&r.job_id), b256_name(&r.descriptor_hash), addr_name(&r.prover), version_name(r.version)];
        self.walk(&names, &self.version_path(r))
    }

    /// A file of a version was absent: `Missing` when the version itself is gone meanwhile (evicted
    /// or deleted while it was read), `Unavailable` when `bundles/` is, `Corrupt` only when the same
    /// version directory is still there without the file.
    pub(crate) fn vanished(&self, r: &BundleRef, vdir: &Dir, file: &Path) -> StoreError {
        let now = match self.open_version(r) {
            Ok(d) => d,
            Err(e) => return e,
        };
        match (now.fstat(), vdir.fstat()) {
            (Ok(a), Ok(b)) if (a.dev, a.ino) == (b.dev, b.ino) => StoreError::corrupt(Defect::FileMissing, file),
            // Another directory took the version's name meanwhile: never a verdict on this bundle.
            (Ok(_), Ok(_)) => StoreError::unavailable(UnavailableKind::NotFound, file),
            (Err(e), _) | (_, Err(e)) => StoreError::io(e, file),
        }
    }

    /// Reads and parses a version's `bundle.json` through its directory fd, checking its format and
    /// that it belongs where it is stored (key and version). Returns it with the sha256 of its bytes.
    pub(crate) fn load_record_in(&self, vdir: &Dir, r: &BundleRef) -> Result<(BundleV1, B256), StoreError> {
        let p = vdir.child(BUNDLE_JSON);
        let bytes = match read_capped(vdir, BUNDLE_JSON, MAX_BUNDLE_JSON_BYTES) {
            Ok(b) => b,
            Err(ReadError::Io(e)) if is_enoent(&e) => return Err(self.vanished(r, vdir, &p)),
            Err(e) => return Err(entry_read_error(e, &p)),
        };
        let b: BundleV1 = serde_json::from_slice(&bytes).map_err(|_| StoreError::corrupt(Defect::Unparseable, &p))?;
        if b.format_version != BUNDLE_FORMAT_VERSION {
            return Err(StoreError::corrupt(Defect::FormatVersion, &p));
        }
        if BundleKey::of_bundle(&b) != r.key() {
            return Err(StoreError::corrupt(Defect::KeyMismatch, &p));
        }
        if b.version != r.version {
            return Err(StoreError::corrupt(Defect::VersionMismatch, &p));
        }
        Ok((b, sha256(&bytes)))
    }

    /// `w.bin` is a regular file of `w_len` bytes (no hashing).
    pub(crate) fn check_w_in(&self, vdir: &Dir, r: &BundleRef, w_len: u64) -> Result<(), StoreError> {
        let p = vdir.child(W_BIN);
        match vdir.stat(W_BIN) {
            Ok(s) if s.kind == Kind::File && s.len == w_len => Ok(()),
            Ok(s) if s.kind == Kind::File => Err(StoreError::corrupt(Defect::WLength, &p)),
            Ok(_) => Err(StoreError::corrupt(Defect::NotRegularFile, &p)),
            Err(e) if is_enoent(&e) => Err(self.vanished(r, vdir, &p)),
            Err(e) => Err(StoreError::io(e, &p)),
        }
    }

    /// A read through a pin: the pinned version must still be the bundle the pin was taken on.
    pub(crate) fn check_pin(
        pins: &BTreeMap<BundleKey, PinState>,
        r: &BundleRef,
        b: &BundleV1,
        json_sha256: B256,
        path: &Path,
    ) -> Result<(), StoreError> {
        if let Some(PinState::Readable { rec, .. }) = pins.get(&r.key()) {
            if rec.bundle_version == r.version
                && (rec.input_sha256 != b.input_sha256 || rec.bundle_json_sha256 != json_sha256)
            {
                return Err(StoreError::corrupt(Defect::PinMismatch, path));
            }
        }
        Ok(())
    }

    /// A version's directory and record, checked for reading: location, key, version, and its pin
    /// when it is the pinned version. Takes the state lock briefly.
    pub(crate) fn read_version(&self, r: &BundleRef) -> Result<(Dir, BundleV1), StoreError> {
        let vdir = self.open_version(r)?;
        let (b, js) = self.load_record_in(&vdir, r)?;
        Inner::check_pin(&self.state().pins, r, &b, js, &vdir.child(BUNDLE_JSON))?;
        Ok((vdir, b))
    }

    fn avail_bytes(&self) -> Result<u64, StoreError> {
        self.root_dir.avail_bytes().map_err(|e| StoreError::io(e, &self.root))
    }

    /// Refuses a write of `add` that would cross the quota or the free-space floor. The floor
    /// counts bytes already admitted to concurrent writers but not yet on disk.
    pub(crate) fn admit(&self, st: &State, add: Usage) -> Result<(), StoreError> {
        let used = st.total();
        if used.bytes.saturating_add(add.bytes) > self.opts.quota_bytes {
            return Err(StoreError::RetentionFull(FullReason::QuotaBytes));
        }
        if used.inodes.saturating_add(add.inodes) > self.opts.quota_inodes {
            return Err(StoreError::RetentionFull(FullReason::QuotaInodes));
        }
        let avail = self.avail_bytes()?.saturating_sub(st.pending_bytes);
        if avail < self.opts.free_space_floor_bytes.saturating_add(add.bytes) {
            return Err(StoreError::RetentionFull(FullReason::FreeSpaceFloor));
        }
        Ok(())
    }

    /// Bytes that can still be written before the quota or the floor.
    pub(crate) fn headroom(&self, st: &State) -> Result<u64, StoreError> {
        let quota = self.opts.quota_bytes.saturating_sub(st.total().bytes);
        let fs = self
            .avail_bytes()?
            .saturating_sub(st.pending_bytes)
            .saturating_sub(self.opts.free_space_floor_bytes);
        Ok(quota.min(fs))
    }

    /// Replaces `dir/name` atomically and durably: the bytes go to a fresh file under `tmp/`, which
    /// is fsynced, renamed over the destination, and the destination directory fsynced. A failure
    /// after the rename poisons the store.
    pub(crate) fn write_atomic(
        &self,
        st: &mut State,
        dir: &Dir,
        name: &str,
        bytes: &[u8],
        mode: u32,
    ) -> Result<(), StoreError> {
        let dest = dir.child(name);
        let old = match dir.stat_opt(name) {
            Ok(Some(s)) if s.kind == Kind::File => Some(s.len),
            Ok(Some(_)) => return Err(StoreError::layout(&dest)),
            Ok(None) => None,
            Err(e) => return Err(StoreError::io(e, &dest)),
        };
        let tmp = self.tmp()?;
        let res = write_file_atomic(&tmp, dir, name, bytes, mode);
        if res.as_ref().map_or_else(|s| s.visible, |()| true) {
            match old {
                Some(o) => {
                    st.durable.sub(Usage::new(o, 0));
                    st.durable.add(Usage::new(bytes.len() as u64, 0));
                }
                None => st.durable.add(Usage::new(bytes.len() as u64, 1)),
            }
        }
        res.map_err(|s| self.staged(s))
    }

    /// Opens `parent/name`, creating it if absent; a new directory's entry is fsynced into its
    /// parent before it is used.
    pub(crate) fn ensure_sub(&self, st: &mut State, parent: &Dir, name: &str) -> Result<Dir, StoreError> {
        let path = parent.child(name);
        match parent.sub(name) {
            Ok(d) => return Ok(d),
            Err(e) if is_enoent(&e) => {}
            Err(e) => return Err(dir_error(e, &path)),
        }
        self.admit(st, Usage::new(0, 1))?;
        parent.mkdir(name).map_err(|e| self.failed(e, &path, false))?;
        st.durable.add(Usage::new(0, 1));
        parent.fsync().map_err(|e| self.failed(e, parent.path(), true))?;
        parent.sub(name).map_err(|e| dir_error(e, &path))
    }

    /// The next store-wide version number, durably reserved: the counter is written (temp file,
    /// fsync, rename, fsync of the root) before the number is used, so no number is ever reused.
    pub(crate) fn reserve_version(&self, st: &mut State) -> Result<u32, StoreError> {
        let v = st.next_version;
        let next = v.checked_add(1).ok_or(StoreError::Rejected(Reject::VersionsExhausted))?;
        self.write_atomic(st, &self.root_dir, NEXT_VERSION, next.to_string().as_bytes(), 0o600)?;
        st.next_version = next;
        Ok(v)
    }

    /// Removes `parent/name` (with `dir`, a directory tree) as one step: it is renamed into `tmp/`
    /// (nothing partial is ever visible under its name), `on_renamed` updates the index at once, the
    /// old parent is fsynced, and only then are the contents deleted. `Ok(None)` when it is already
    /// gone. A directory entry must be a real directory, a file entry must not be a directory
    /// (`BadLayout` otherwise); a symlink is removed as itself, never followed.
    pub(crate) fn remove_entry(
        &self,
        st: &mut State,
        parent: &Dir,
        name: &str,
        dir: bool,
        on_renamed: &mut dyn FnMut(&mut State),
    ) -> Result<Option<Usage>, StoreError> {
        let path = parent.child(name);
        let s = match parent.stat_opt(name) {
            Ok(Some(s)) => s,
            Ok(None) => return Ok(None),
            Err(e) => return Err(StoreError::io(e, &path)),
        };
        if (s.kind == Kind::Dir) != dir {
            return Err(StoreError::layout(&path));
        }
        let u = match parent.tree_usage(name) {
            Ok(u) => u,
            Err(e) if is_enoent(&e) => return Ok(None),
            Err(e) => return Err(StoreError::io(e, &path)),
        };
        let tmp = self.tmp()?;
        let grave = format!("{}.del", crate::fsutil::random_name().map_err(|e| StoreError::io(e, tmp.path()))?);
        match parent.rename_to(name, &tmp, &grave, true) {
            Ok(()) => {}
            Err(e) if is_enoent(&e) => return Ok(None),
            Err(e) => return Err(self.failed(e, &path, false)),
        }
        st.durable.sub(u);
        st.transient.add(u);
        on_renamed(st);
        parent.fsync().map_err(|e| self.failed(e, parent.path(), true))?;
        let res = tmp.remove_tree(&grave);
        st.transient.sub(u);
        // What a failed removal left is real usage until the next open empties `tmp/`.
        if let Ok(left) = tmp.tree_usage_opt(&grave) {
            st.transient.add(left);
        }
        res.map_err(|e| self.failed(e, &tmp.child(&grave), false))?;
        Ok(Some(u))
    }

    /// Removes the key's directory and its parents while they are empty, never through a symlink.
    pub(crate) fn prune_empty(&self, st: &mut State, k: &BundleKey) -> Result<(), StoreError> {
        let bundles = self.bundles()?;
        let (jn, dn, pn) = (b256_name(&k.job_id), b256_name(&k.descriptor_hash), addr_name(&k.prover));
        let Some(job) = self.real_sub(&bundles, &jn)? else { return Ok(()) };
        if let Some(desc) = self.real_sub(&job, &dn)? {
            if !self.rmdir_if_empty(st, &desc, &pn)? {
                return Ok(());
            }
        }
        if self.rmdir_if_empty(st, &job, &dn)? {
            self.rmdir_if_empty(st, &bundles, &jn)?;
        }
        Ok(())
    }

    /// `parent/name` when it is a real directory; `None` when absent or not one.
    fn real_sub(&self, parent: &Dir, name: &str) -> Result<Option<Dir>, StoreError> {
        match parent.sub(name) {
            Ok(d) => Ok(Some(d)),
            Err(e) if is_enoent(&e) || is_not_a_real_dir(&e) => Ok(None),
            Err(e) => Err(StoreError::io(e, &parent.child(name))),
        }
    }

    /// Removes an empty directory: `true` when it is gone, `false` when it is not empty or not a
    /// directory.
    fn rmdir_if_empty(&self, st: &mut State, parent: &Dir, name: &str) -> Result<bool, StoreError> {
        match parent.rmdir(name) {
            Ok(()) => {
                st.durable.sub(Usage::new(0, 1));
                Ok(true)
            }
            Err(e) if is_enoent(&e) => Ok(true),
            Err(e) if matches!(errno(&e), Some(libc::ENOTEMPTY | libc::EEXIST | libc::ENOTDIR)) => Ok(false),
            Err(e) => Err(self.failed(e, &parent.child(name), false)),
        }
    }

    /// The scan's view of one version: its summary, or why it is unreadable. I/O errors (the store
    /// is unavailable) fail the whole scan.
    fn summarize(
        &self,
        vdir: &Dir,
        r: &BundleRef,
        pins: &BTreeMap<BundleKey, PinState>,
    ) -> Result<Result<BundleSummary, Defect>, StoreError> {
        let res = self.load_record_in(vdir, r).and_then(|(b, js)| {
            self.check_w_in(vdir, r, b.w_len)?;
            Inner::check_pin(pins, r, &b, js, &vdir.child(BUNDLE_JSON))?;
            Ok(b)
        });
        match res {
            Ok(b) => Ok(Ok(BundleSummary::of(&b))),
            Err(StoreError::Corrupt { defect, .. }) => Ok(Err(defect)),
            Err(StoreError::Missing { .. }) => Ok(Err(Defect::FileMissing)),
            Err(e) => Err(e),
        }
    }

    /// Walks the store: usage, every pin, every version.
    fn load(&self) -> Result<Loaded, StoreError> {
        let mut l = Loaded::default();
        for name in OWNED {
            let io = |e| StoreError::io(e, &self.root.join(name));
            if name == TMP {
                // `tmp/` itself is durable; its contents are transient.
                if self.root_dir.stat_opt(TMP).map_err(io)?.is_some() {
                    l.durable.add(Usage::new(0, 1));
                }
                continue;
            }
            l.durable.add(self.root_dir.tree_usage_opt(name).map_err(io)?);
        }
        self.load_pins(&mut l)?;
        self.load_bundles(&mut l)?;
        Ok(l)
    }

    fn load_bundles(&self, l: &mut Loaded) -> Result<(), StoreError> {
        fn unexpected(l: &mut Loaded, path: PathBuf) {
            l.anomalies.push(Anomaly { path, kind: AnomalyKind::UnexpectedEntry });
        }
        /// The subdirectory for an entry whose name parses; an anomaly otherwise (a symlink is one).
        fn descend<T>(
            l: &mut Loaded,
            parent: &Dir,
            e: &Entry,
            parse: impl Fn(&str) -> Option<T>,
        ) -> Result<Option<(T, Dir)>, StoreError> {
            let p = parent.child(&e.name);
            let Some(v) = e.utf8().and_then(parse).filter(|_| e.kind == Kind::Dir) else {
                unexpected(l, p);
                return Ok(None);
            };
            match parent.sub(&e.name) {
                Ok(d) => Ok(Some((v, d))),
                Err(err) if is_enoent(&err) => Ok(None),
                Err(err) if is_not_a_real_dir(&err) => {
                    unexpected(l, p);
                    Ok(None)
                }
                Err(err) => Err(StoreError::io(err, &p)),
            }
        }
        let list = |d: &Dir| d.entries().map_err(|e| StoreError::io(e, d.path()));
        let bundles = self.bundles()?;
        for je in list(&bundles)? {
            let Some((job_id, job)) = descend(l, &bundles, &je, parse_b256_name)? else { continue };
            for de in list(&job)? {
                let Some((descriptor_hash, desc)) = descend(l, &job, &de, parse_b256_name)? else { continue };
                for pe in list(&desc)? {
                    let Some((prover, key_dir)) = descend(l, &desc, &pe, parse_addr_name)? else { continue };
                    for ve in list(&key_dir)? {
                        let Some((version, vdir)) = descend(l, &key_dir, &ve, parse_version_name)? else {
                            continue;
                        };
                        let r = BundleRef { job_id, descriptor_hash, prover, version };
                        let usage = key_dir.tree_usage(&ve.name).map_err(|e| StoreError::io(e, vdir.path()))?;
                        let record = self.summarize(&vdir, &r, &l.pins)?;
                        l.max_version = l.max_version.max(version);
                        l.versions.insert(r, VersionInfo { usage, record });
                    }
                }
            }
        }
        Ok(())
    }

    fn load_pins(&self, l: &mut Loaded) -> Result<(), StoreError> {
        let pins = self.pins_area()?;
        for e in pins.entries().map_err(|e| StoreError::io(e, pins.path()))? {
            let p = pins.child(&e.name);
            let Some(key) = e.utf8().and_then(parse_pin_name) else {
                l.anomalies.push(Anomaly { path: p, kind: AnomalyKind::UnexpectedEntry });
                continue;
            };
            let rec = match read_capped(&pins, &e.name, MAX_SMALL_RECORD_BYTES) {
                Ok(b) => serde_json::from_slice::<PinRecord>(&b).ok().filter(|r| BundleKey::of_pin(r) == key),
                Err(ReadError::Io(err)) if is_enoent(&err) => continue,
                Err(ReadError::Io(err)) => return Err(StoreError::io(err, &p)),
                Err(ReadError::TooLarge | ReadError::NotRegular) => None,
            };
            let state = match rec {
                Some(rec) => PinState::Readable { rec, durable_here: false },
                None => {
                    l.anomalies.push(Anomaly { path: p, kind: AnomalyKind::UnreadablePin });
                    PinState::Unknown
                }
            };
            l.pins.insert(key, state);
        }
        Ok(())
    }
}

/// A read of a file a complete entry must hold: absence is corruption, not a missing entry (the
/// caller has already ruled out the entry itself being gone).
pub(crate) fn entry_read_error(e: ReadError, p: &Path) -> StoreError {
    match e {
        ReadError::TooLarge => StoreError::corrupt(Defect::TooLarge, p),
        ReadError::NotRegular => StoreError::corrupt(Defect::NotRegularFile, p),
        ReadError::Io(e) if is_enoent(&e) => StoreError::corrupt(Defect::FileMissing, p),
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

/// Streams `f` to its end into both hashers; returns the bytes read.
pub(crate) fn hash_into(f: &mut File, w_hash: &mut Sha256, input_hash: &mut Sha256) -> io::Result<u64> {
    let mut buf = vec![0u8; STREAM_CHUNK_BYTES];
    let mut total = 0u64;
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        w_hash.update(&buf[..n]);
        input_hash.update(&buf[..n]);
        total += n as u64;
    }
}

/// The root checks shared by `open` and `init`: a real directory (never a symlink) on an accepted
/// filesystem and, when required, a mount point. Writes nothing.
fn open_root(root: &Path, require_dedicated_mount: bool, allow_any_filesystem: bool) -> Result<(Dir, (u64, u64)), StoreError> {
    let unavailable = |kind| StoreError::unavailable(kind, root);
    match std::fs::symlink_metadata(root) {
        Ok(m) if m.file_type().is_symlink() => return Err(unavailable(UnavailableKind::SymlinkRoot)),
        Ok(m) if !m.is_dir() => return Err(unavailable(UnavailableKind::NotADirectory)),
        Ok(_) => {}
        Err(e) if is_enoent(&e) => return Err(unavailable(UnavailableKind::RootAbsent)),
        Err(e) => return Err(StoreError::io(e, root)),
    }
    let dir = Dir::open_path(root).map_err(|e| match errno(&e) {
        Some(libc::ELOOP) => unavailable(UnavailableKind::SymlinkRoot),
        Some(libc::ENOTDIR) => unavailable(UnavailableKind::NotADirectory),
        Some(libc::ENOENT) => unavailable(UnavailableKind::RootAbsent),
        _ => StoreError::io(e, root),
    })?;
    let f_type = dir.fs_type().map_err(|e| StoreError::io(e, root))?;
    if !allow_any_filesystem && !supported_fs_type(f_type) {
        return Err(unavailable(UnavailableKind::UnsupportedFilesystem { f_type }));
    }
    let st = dir.fstat().map_err(|e| StoreError::io(e, root))?;
    if require_dedicated_mount && !is_mount_root(&dir).map_err(|e| StoreError::io(e, root))? {
        return Err(unavailable(UnavailableKind::NotMounted));
    }
    Ok((dir, (st.dev, st.ino)))
}

/// The directory is the root of a mounted filesystem: its `st_dev` differs from its parent's.
pub(crate) fn is_mount_root(dir: &Dir) -> io::Result<bool> {
    Ok(dir.fstat()?.dev != dir.parent_stat()?.dev)
}

/// Takes the exclusive `flock` on `.lock`, opened (with `create`, created) without following a
/// symlink; anything but a regular file there is a bad layout.
fn take_lock(root: &Path, dir: &Dir, create: bool) -> Result<File, StoreError> {
    let lock_path = root.join(LOCK);
    let lock = match dir.open_lock(LOCK, create) {
        Ok(f) => f,
        Err(e) if is_enoent(&e) => {
            // Not an initialised store (an unmounted mount point looks like this): never written to.
            let has_identity = dir.stat_opt(IDENTITY).map_err(|e| StoreError::io(e, root))?.is_some();
            let kind = if has_identity { UnavailableKind::BadLayout } else { UnavailableKind::IdentityMissing };
            return Err(StoreError::unavailable(kind, if has_identity { &lock_path } else { root }));
        }
        Err(e) if matches!(errno(&e), Some(libc::ELOOP | libc::EISDIR | libc::ENXIO | libc::ENOTDIR)) => {
            return Err(StoreError::layout(&lock_path))
        }
        Err(e) => return Err(StoreError::io(e, &lock_path)),
    };
    if fstat(lock.as_raw_fd()).map_err(|e| StoreError::io(e, &lock_path))?.kind != Kind::File {
        return Err(StoreError::layout(&lock_path));
    }
    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(TryLockError::WouldBlock) => Err(StoreError::unavailable(UnavailableKind::LockHeld, root)),
        Err(TryLockError::Error(e)) => Err(StoreError::io(e, &lock_path)),
    }
}

/// Reads and checks `identity.json` against what this miner expects.
fn read_identity(root: &Path, dir: &Dir, want: &ExpectedIdentity) -> Result<StoreIdentity, StoreError> {
    let p = root.join(IDENTITY);
    let unavailable = |kind| StoreError::unavailable(kind, &p);
    let bytes = match read_capped(dir, IDENTITY, MAX_SMALL_RECORD_BYTES) {
        Ok(b) => b,
        Err(ReadError::Io(e)) if is_enoent(&e) => return Err(unavailable(UnavailableKind::IdentityMissing)),
        Err(ReadError::Io(e)) => return Err(StoreError::io(e, &p)),
        Err(ReadError::TooLarge | ReadError::NotRegular) => return Err(unavailable(UnavailableKind::IdentityInvalid)),
    };
    let f: IdentityFile = serde_json::from_slice(&bytes).map_err(|_| unavailable(UnavailableKind::IdentityInvalid))?;
    if f.store_format != STORE_FORMAT_VERSION || !is_uuid(&f.store_uuid) {
        return Err(unavailable(UnavailableKind::IdentityInvalid));
    }
    if f.chain_id != want.chain_id || f.router != want.router || f.prover != want.prover || f.store_uuid != want.store_uuid
    {
        return Err(unavailable(UnavailableKind::IdentityMismatch));
    }
    Ok(StoreIdentity { store_uuid: f.store_uuid, chain_id: f.chain_id, router: f.router, prover: f.prover })
}

/// `init` may run here: no identity yet, and nothing but `.lock`, `lost+found` and what an
/// interrupted `init` leaves (empty areas, any `tmp/`, `next_version`).
fn initialisable(root: &Path, dir: &Dir) -> Result<(), StoreError> {
    let io = |e, p: &Path| StoreError::io(e, p);
    for e in dir.entries().map_err(|e| io(e, root))? {
        let empty_area = |a: &str| -> Result<bool, StoreError> {
            let d = dir.sub(a).map_err(|e| dir_error(e, &root.join(a)))?;
            Ok(a == TMP || d.entries().map_err(|e| io(e, d.path()))?.is_empty())
        };
        match (e.utf8(), e.kind) {
            (Some(LOCK | LOST_FOUND), _) => {}
            (Some(IDENTITY), _) => return Err(StoreError::Rejected(Reject::AlreadyInitialised)),
            (Some(NEXT_VERSION), Kind::File) => {}
            (Some(a), Kind::Dir) if AREAS.contains(&a) && empty_area(a)? => {}
            _ => return Err(StoreError::Rejected(Reject::NotEmpty)),
        }
    }
    Ok(())
}

impl Store {
    /// Initialises a store in an existing, empty directory: the explicit operator step that
    /// [`Store::open`] never takes. Returns the new identity; its `store_uuid` belongs in the miner's
    /// configuration ([`ExpectedIdentity::store_uuid`]).
    ///
    /// Applies `open`'s root checks (`identity`'s `require_dedicated_mount` and
    /// `allow_any_filesystem`) and, before writing anything, refuses a root that already has an
    /// identity ([`Reject::AlreadyInitialised`]) or holds anything but `lost+found` and what an
    /// interrupted `init` leaves (`.lock`, empty areas, `next_version`, `tmp/`)
    /// ([`Reject::NotEmpty`]). Then creates and locks `.lock`, checks again, creates the areas,
    /// writes `next_version` and, last, `identity.json`, each durably: an interrupted `init` leaves
    /// no identity, and running it again finishes it. Every other failure is
    /// [`StoreError::Unavailable`].
    pub fn init(root: impl AsRef<Path>, identity: &StoreIdentityInit) -> Result<StoreIdentity, StoreError> {
        let root = root.as_ref();
        Store::init_inner(root, identity).map_err(|e| e.only_unavailable(root))
    }

    fn init_inner(root: &Path, want: &StoreIdentityInit) -> Result<StoreIdentity, StoreError> {
        let (dir, _) = open_root(root, want.require_dedicated_mount, want.allow_any_filesystem)?;
        // Refused before anything is written (not even `.lock`), and checked again under the lock.
        initialisable(root, &dir)?;
        let _lock = take_lock(root, &dir, true)?;
        initialisable(root, &dir)?;
        let io = |e, p: &Path| StoreError::io(e, p);
        let mut made = false;
        for a in AREAS {
            match dir.sub(a) {
                Ok(_) => {}
                Err(e) if is_enoent(&e) => {
                    dir.mkdir(a).map_err(|e| io(e, &root.join(a)))?;
                    made = true;
                }
                Err(e) => return Err(dir_error(e, &root.join(a))),
            }
        }
        if made {
            dir.fsync().map_err(|e| io(e, root))?;
        }
        let tmp = dir.sub(TMP).map_err(|e| dir_error(e, &root.join(TMP)))?;
        for e in tmp.entries().map_err(|e| io(e, tmp.path()))? {
            tmp.remove_tree(&e.name).map_err(|err| io(err, &tmp.child(&e.name)))?;
        }
        let staged = |s: Staged| io(s.err, &s.path);
        write_file_atomic(&tmp, &dir, NEXT_VERSION, b"1", 0o600).map_err(staged)?;
        let f = IdentityFile {
            store_format: STORE_FORMAT_VERSION,
            store_uuid: uuid_v4().map_err(|e| io(e, root))?,
            chain_id: want.chain_id,
            router: want.router,
            prover: want.prover,
        };
        let json = serde_json::to_vec_pretty(&f).expect("identity serializes");
        write_file_atomic(&tmp, &dir, IDENTITY, &json, 0o444).map_err(staged)?;
        Ok(StoreIdentity { store_uuid: f.store_uuid, chain_id: f.chain_id, router: f.router, prover: f.prover })
    }

    /// Opens the store at `root`. Never creates or initialises anything: a directory that is not
    /// an initialised store ([`Store::init`]) is [`UnavailableKind::IdentityMissing`] and is left
    /// untouched, so a disk that failed to mount is never taken for an empty store.
    ///
    /// Refuses a symlinked root, an unsupported filesystem and (with `require_dedicated_mount`) a
    /// root that is not a mount point, before writing anything; takes the exclusive `flock` on
    /// `<root>/.lock` (a second open fails with [`UnavailableKind::LockHeld`]); verifies
    /// `identity.json` (its UUID included) and the areas; removes leftovers of interrupted writes
    /// from `tmp/`; scans usage, every version and every pin; and repairs a lost or stale
    /// `next_version`. Every error is [`StoreError::Unavailable`]. Eviction stays disabled until
    /// [`Store::mark_recovery_scan_complete`].
    pub fn open(root: impl AsRef<Path>, identity: &ExpectedIdentity, opts: StoreOptions) -> Result<Store, StoreError> {
        let root = root.as_ref();
        Store::open_inner(root, identity, opts).map_err(|e| e.only_unavailable(root))
    }

    fn open_inner(root: &Path, want: &ExpectedIdentity, opts: StoreOptions) -> Result<Store, StoreError> {
        let (root_dir, root_id) = open_root(root, opts.require_dedicated_mount, opts.allow_any_filesystem)?;
        let lock = take_lock(root, &root_dir, false)?;
        let ident = read_identity(root, &root_dir, want)?;
        for a in AREAS {
            let p = root.join(a);
            match root_dir.sub(a) {
                Ok(_) => {}
                Err(e) if is_enoent(&e) || is_not_a_real_dir(&e) => return Err(StoreError::layout(&p)),
                Err(e) => return Err(StoreError::io(e, &p)),
            }
        }

        // Interrupted writes never became versions: drop them.
        let tmp = root_dir.sub(TMP).map_err(|e| dir_error(e, &root.join(TMP)))?;
        let mut tmp_entries_removed = 0;
        for e in tmp.entries().map_err(|e| StoreError::io(e, tmp.path()))? {
            tmp.remove_tree(&e.name).map_err(|err| StoreError::io(err, &tmp.child(&e.name)))?;
            tmp_entries_removed += 1;
        }

        let mut inner = Inner {
            root: root.to_path_buf(),
            root_id,
            root_dir,
            _lock: lock,
            opts,
            identity: ident,
            open_report: OpenReport::default(),
            poisoned: AtomicBool::new(false),
            state: Mutex::new(State::default()),
        };
        let loaded = inner.load()?;
        let max_version = loaded.max_version;
        let mut st = State::default();
        st.install(loaded);

        // Versions come from one store-wide counter, persisted before each version is begun, so a
        // number is never reused even after its bundle is evicted or deleted.
        let floor = max_version.checked_add(1).ok_or_else(|| StoreError::layout(&root.join(BUNDLES)))?;
        let counter_path = root.join(NEXT_VERSION);
        let counter = match read_capped(&inner.root_dir, NEXT_VERSION, MAX_SMALL_RECORD_BYTES) {
            Ok(b) => std::str::from_utf8(&b).ok().and_then(|s| s.trim().parse::<u32>().ok()),
            Err(ReadError::Io(e)) if is_enoent(&e) => None,
            Err(ReadError::Io(e)) => return Err(StoreError::io(e, &counter_path)),
            Err(ReadError::NotRegular) => return Err(StoreError::layout(&counter_path)),
            Err(ReadError::TooLarge) => None,
        };
        let (next, recovered) = match counter {
            Some(c) if c >= floor => (c, false),
            _ => (floor, true),
        };
        st.next_version = next;
        if recovered {
            inner.write_atomic(&mut st, &inner.root_dir, NEXT_VERSION, next.to_string().as_bytes(), 0o600)?;
        }
        inner.open_report = OpenReport { tmp_entries_removed, version_counter_recovered: recovered };
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

    /// An earlier change failed after it had become visible: every call is
    /// [`UnavailableKind::Poisoned`] until the store is reopened.
    pub fn is_poisoned(&self) -> bool {
        self.inner.is_poisoned()
    }

    /// Usage as accounted in memory (every write and removal updates it).
    pub fn usage(&self) -> Usage {
        self.inner.state().total()
    }

    /// Usage re-counted from disk under the store's lock. Equals [`Store::usage`] whenever no
    /// writer is streaming at the same moment.
    pub fn recount_usage(&self) -> Result<Usage, StoreError> {
        self.inner.check_usable()?;
        let _st = self.inner.state();
        let mut u = Usage::default();
        for name in OWNED {
            u.add(self.inner.root_dir.tree_usage_opt(name).map_err(|e| StoreError::io(e, &self.inner.root.join(name)))?);
        }
        Ok(u)
    }

    /// Bytes that can be written before the quota or the free-space floor is crossed.
    pub fn headroom(&self) -> Result<u64, StoreError> {
        self.inner.check_usable()?;
        let st = self.inner.state();
        self.inner.headroom(&st)
    }

    /// Every complete version of a key, ascending, from disk. A version name that is not a real
    /// directory (a planted symlink) is [`UnavailableKind::BadLayout`].
    pub fn versions(&self, job_id: B256, descriptor_hash: B256, prover: Address) -> Result<Vec<u32>, StoreError> {
        self.inner.check_usable()?;
        let k = BundleKey::new(job_id, descriptor_hash, prover);
        let dir = match self.inner.open_key(&k) {
            Ok(d) => d,
            Err(StoreError::Missing { .. }) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut v = Vec::new();
        for e in dir.entries().map_err(|e| StoreError::io(e, dir.path()))? {
            let Some(n) = e.utf8().and_then(parse_version_name) else { continue };
            if e.kind != Kind::Dir {
                return Err(StoreError::layout(&dir.child(&e.name)));
            }
            v.push(n);
        }
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
            None => Err(StoreError::Missing { path: self.inner.key_path(&k) }),
        }
    }

    /// Reads a version's record: it must say the key and version it is stored under, and match the
    /// key's pin when it is the pinned version; its descriptor is re-verified against
    /// `descriptor_hash` with `descriptor_hash_fn` (decoding and hashing a descriptor is the chain
    /// crate's job), its po2 results re-checked, and `w.bin` must have `w_len` bytes. `sha256(W)` is
    /// verified by [`Store::open_w`], the ELF by [`Store::verify`].
    pub fn read(
        &self,
        r: &BundleRef,
        descriptor_hash_fn: &dyn Fn(&[u8]) -> Option<B256>,
    ) -> Result<BundleV1, StoreError> {
        self.inner.check_usable()?;
        let (vdir, b) = self.inner.read_version(r)?;
        check_record(&b, descriptor_hash_fn).map_err(|d| StoreError::corrupt(d, &vdir.child(BUNDLE_JSON)))?;
        self.inner.check_w_in(&vdir, r, b.w_len)?;
        Ok(b)
    }

    /// Opens `w.bin` read-only, verifies `|W|`, `sha256(W)` and `sha256(prefix ‖ W)` against the
    /// record (checked as [`Store::read`] checks it) by streaming it, rewinds, and hands out the
    /// verified fd (plan §15.3: the worker receives `W` as a read-only fd).
    pub fn open_w(&self, r: &BundleRef) -> Result<File, StoreError> {
        self.inner.check_usable()?;
        let (vdir, b) = self.inner.read_version(r)?;
        let p = vdir.child(W_BIN);
        let mut f = match vdir.open_ro(W_BIN) {
            Ok(f) => f,
            Err(e) if is_enoent(&e) => return Err(self.inner.vanished(r, &vdir, &p)),
            Err(e) if errno(&e) == Some(libc::ELOOP) => return Err(StoreError::corrupt(Defect::NotRegularFile, &p)),
            Err(e) => return Err(StoreError::io(e, &p)),
        };
        let m = fstat(f.as_raw_fd()).map_err(|e| StoreError::io(e, &p))?;
        if m.kind != Kind::File {
            return Err(StoreError::corrupt(Defect::NotRegularFile, &p));
        }
        if m.len != b.w_len {
            return Err(StoreError::corrupt(Defect::WLength, &p));
        }
        clear_nonblock(&f).map_err(|e| StoreError::io(e, &p))?;
        let mut w_hash = Sha256::new();
        let mut input_hash = Sha256::new();
        if b.prefix {
            input_hash.update(journal_prefix(b.job_id, b.prover));
        }
        let total = hash_into(&mut f, &mut w_hash, &mut input_hash).map_err(|e| StoreError::io(e, &p))?;
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

    /// The path of a version's `w.bin`, for a prove worker that opens `W` itself (plan §15.3: the
    /// prove command carries a path, so host RAM is not charged for a copy). `W` is verified first,
    /// as [`Store::open_w`] verifies it (every byte against the record), so a version whose `W` is
    /// missing or corrupt is reported here, before a proof is dispatched. The worker hashes what it
    /// reads against the bundle's `sha256(prefix ‖ W)` again, so a file changed after this check is
    /// refused there. Published files are read-only and a pinned version is never evicted.
    pub fn w_path(&self, r: &BundleRef) -> Result<PathBuf, StoreError> {
        drop(self.open_w(r)?);
        Ok(self.inner.version_path(r).join(W_BIN))
    }

    /// Everything a proof from this version needs, verified (plan §15.1: "every read verifies
    /// `sha256(W)` and the ELF's image id"): [`Store::read`], [`Store::open_w`] (every byte of `W`),
    /// and the ELF `image_id` re-verified with `image_id_fn`. An ELF absent from an available store
    /// is [`Defect::ElfMissing`]. For revalidation and recovery, where the fd itself is not needed.
    pub fn verify(
        &self,
        r: &BundleRef,
        descriptor_hash_fn: &dyn Fn(&[u8]) -> Option<B256>,
        image_id_fn: &dyn Fn(&[u8]) -> Option<B256>,
    ) -> Result<BundleV1, StoreError> {
        let b = self.read(r, descriptor_hash_fn)?;
        self.open_w(r)?;
        match self.inner.read_elf(&b.image_id, image_id_fn) {
            Ok(_) => Ok(b),
            Err(StoreError::Missing { path }) => Err(StoreError::corrupt(Defect::ElfMissing, &path)),
            Err(e) => Err(e),
        }
    }

    /// The recovery scan: re-reads every version and pin from disk, refreshes the index and the
    /// durable usage, and reports every complete version with its pin status, size and caller.
    /// Unreadable versions and pins are reported, never skipped; a symlink anywhere is an anomaly,
    /// never followed.
    pub fn scan(&self) -> Result<ScanReport, StoreError> {
        self.inner.check_usable()?;
        let mut st = self.inner.state();
        let loaded = self.inner.load()?;
        st.install(loaded);
        Ok(ScanReport {
            bundles: st.metas(),
            pins: st.readable_pins(),
            unreadable_pins: st.unknown_pins(),
            anomalies: st.anomalies.clone(),
        })
    }
}
