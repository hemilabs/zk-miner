//! The store's error states (plan §15.2). Every reason is a fixed enum: no attacker-controlled
//! string is ever carried, and the miner maps each state to its page without parsing text.

use std::io;
use std::path::{Path, PathBuf};

use crate::store::BundleKey;

/// What the miner sees from the store. The four states of §15.2 are [`StoreError::Unavailable`]
/// (keep every lock, `PAGE: RETENTION-UNAVAILABLE`), [`StoreError::Missing`] and
/// [`StoreError::Corrupt`] (`PAGE: BUNDLE-MISSING` on an available store), and
/// [`StoreError::RetentionFull`] (skip new work). The rest refuse a caller's request.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The store cannot be used: absent or wrong root, wrong identity, lock held, or an I/O error
    /// such as EIO, EROFS or ENOENT.
    #[error("retention store unavailable ({kind}): {}", .path.display())]
    Unavailable { kind: UnavailableKind, path: PathBuf },
    /// A new write would cross the store's quota or the free-space floor, or the filesystem itself
    /// is full (ENOSPC, EDQUOT).
    #[error("retention store full: {0}")]
    RetentionFull(FullReason),
    /// A complete entry exists but fails verification when re-read.
    #[error("corrupt ({defect}): {}", .path.display())]
    Corrupt { defect: Defect, path: PathBuf },
    /// No complete entry exists on an available store.
    #[error("missing: {}", .path.display())]
    Missing { path: PathBuf },
    /// The caller's request is refused: a record that does not match what was written, a witness
    /// over its limit, and the like. Nothing was published.
    #[error("rejected: {0}")]
    Rejected(Reject),
    /// [`crate::Store::delete_job`] refused: the job still has pins (re-checked under the lock).
    #[error("refused: the job has {} pin(s)", .0.len())]
    Pinned(Vec<BundleKey>),
    /// [`crate::Store::evict_to`] before [`crate::Store::mark_recovery_scan_complete`].
    #[error("eviction is disabled until the recovery scan completes")]
    EvictionDisabled,
}

impl StoreError {
    /// Maps an I/O error on `path` to a store state. ENOSPC and EDQUOT are a full filesystem; ELOOP
    /// (an `O_NOFOLLOW` open met a symlink the store never creates) is a corrupt entry; the rest make
    /// the store unavailable.
    pub(crate) fn io(e: io::Error, path: &Path) -> StoreError {
        let kind = match e.raw_os_error() {
            Some(libc::ENOSPC) | Some(libc::EDQUOT) => return StoreError::RetentionFull(FullReason::Filesystem),
            Some(libc::ELOOP) => {
                return StoreError::Corrupt { defect: Defect::NotRegularFile, path: path.to_path_buf() }
            }
            Some(libc::EIO) => UnavailableKind::Eio,
            Some(libc::EROFS) => UnavailableKind::ReadOnly,
            Some(libc::ENOENT) => UnavailableKind::NotFound,
            errno => UnavailableKind::Io { errno },
        };
        StoreError::Unavailable { kind, path: path.to_path_buf() }
    }

    pub(crate) fn unavailable(kind: UnavailableKind, path: &Path) -> StoreError {
        StoreError::Unavailable { kind, path: path.to_path_buf() }
    }

    pub(crate) fn corrupt(defect: Defect, path: &Path) -> StoreError {
        StoreError::Corrupt { defect, path: path.to_path_buf() }
    }

    pub fn is_unavailable(&self) -> bool {
        matches!(self, StoreError::Unavailable { .. })
    }

    pub fn is_missing(&self) -> bool {
        matches!(self, StoreError::Missing { .. })
    }

    pub fn is_corrupt(&self) -> bool {
        matches!(self, StoreError::Corrupt { .. })
    }

    pub fn is_full(&self) -> bool {
        matches!(self, StoreError::RetentionFull(_))
    }
}

/// Why the store is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum UnavailableKind {
    #[error("the root does not exist")]
    RootAbsent,
    #[error("the root is not a directory")]
    NotADirectory,
    #[error("the root is a symlink")]
    SymlinkRoot,
    /// tmpfs, ramfs or overlayfs (`statfs` magic).
    #[error("the root is on an unsupported filesystem (f_type {f_type:#x})")]
    UnsupportedFilesystem { f_type: u32 },
    /// An area the layout requires (`bundles/`, `pins/`, …) is not a directory.
    #[error("a store area is not a directory")]
    BadLayout,
    /// The root path no longer names the directory that was opened (unmounted or replaced).
    #[error("the root changed since it was opened")]
    RootChanged,
    /// No identity record, and the root is not an empty directory this open may initialise.
    #[error("the identity record is missing")]
    IdentityMissing,
    #[error("the identity record is unreadable")]
    IdentityInvalid,
    #[error("the identity record does not match this miner")]
    IdentityMismatch,
    /// Another `Store` (this process or another) holds `<root>/.lock`.
    #[error("the store lock is held by another opener")]
    LockHeld,
    #[error("I/O error (EIO)")]
    Eio,
    #[error("read-only filesystem (EROFS)")]
    ReadOnly,
    /// A path the store relies on is gone (ENOENT).
    #[error("not found (ENOENT)")]
    NotFound,
    #[error("I/O error (errno {errno:?})")]
    Io { errno: Option<i32> },
}

/// Which limit a refused write would cross.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum FullReason {
    #[error("byte quota")]
    QuotaBytes,
    #[error("inode quota")]
    QuotaInodes,
    #[error("free-space floor")]
    FreeSpaceFloor,
    #[error("filesystem full (ENOSPC/EDQUOT)")]
    Filesystem,
}

/// What is wrong with a record or a file: a [`StoreError::Corrupt`] on re-read, or a
/// [`Reject::Record`] when the caller hands it to the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum Defect {
    #[error("unknown bundle format version")]
    FormatVersion,
    /// The record's (jobId, descriptorHash, prover) is not the one it is stored or written under.
    #[error("the record's key does not match its location")]
    KeyMismatch,
    #[error("the descriptor is not hex")]
    DescriptorHex,
    #[error("the descriptor does not hash to descriptorHash")]
    DescriptorHash,
    #[error("a po2 appears twice")]
    Po2Duplicate,
    #[error("a journal is not hex")]
    JournalHex,
    #[error("a journal exceeds 32 KiB")]
    JournalTooLarge,
    #[error("a journal does not hash to its journal_sha256")]
    JournalHash,
    #[error("|W| does not match w_len")]
    WLength,
    #[error("sha256(W) does not match w_sha256")]
    WHash,
    #[error("sha256(prefix ‖ W) does not match input_sha256")]
    InputHash,
    #[error("the ELF does not have its image id")]
    ImageId,
    #[error("the record does not parse")]
    Unparseable,
    #[error("the file exceeds its size bound")]
    TooLarge,
    #[error("not a regular file")]
    NotRegularFile,
    #[error("not a directory")]
    NotDirectory,
    /// A file a complete entry must hold (`w.bin`, `bundle.json`) is absent.
    #[error("a file of a complete entry is absent")]
    FileMissing,
}

/// Why a caller's request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum Reject {
    #[error("{0}")]
    Record(Defect),
    /// The witness passed the writer's `max_w_bytes` (the job's `maxWitnessBytes`, clamped).
    #[error("the witness exceeds {max} bytes")]
    WitnessTooLarge { max: u64 },
    /// `finish` needs the bundle's ELF in the store first ([`crate::Store::put_elf`]).
    #[error("the bundle's ELF is not in the store")]
    ElfMissing,
    /// A previous write on this writer failed; it can only be dropped.
    #[error("the writer failed earlier")]
    WriterFailed,
    #[error("the terminal proof names another job")]
    TerminalJobMismatch,
    #[error("bundle versions exhausted")]
    VersionsExhausted,
}
