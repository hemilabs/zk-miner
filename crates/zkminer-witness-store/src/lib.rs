//! The witness retention store (docs/witness-construction-jobs.md §15.1, §15.2): the bundles a
//! witness lock is proven from, their pins, the shared ELF area, and persisted verdicts.
//!
//! A miner takes a witness lock only after `W` is persisted here, the bundle published and pinned
//! (§5.1, §5.7); after the lock it proves the bundle and never rebuilds (invariant 2). So the store
//! must never show a partial bundle, must keep what a lock depends on, and must say precisely
//! whether it is *unavailable* (keep every lock), or a bundle *missing* or *corrupt* on an available
//! store (page, wait, salvage or release) — see [`StoreError`]. When it cannot be sure, it says
//! unavailable: a wrong *missing* or *corrupt* can cost a lock's collateral.
//!
//! # Lifecycle
//!
//! [`Store::init`] creates a store in an empty directory: an explicit operator step returning the
//! store UUID, which the miner keeps in its configuration. [`Store::open`] never creates anything:
//! it requires that UUID ([`ExpectedIdentity::store_uuid`]), so an unmounted disk's bare mount
//! point (or any other empty or foreign directory) is [`UnavailableKind::IdentityMissing`] or
//! [`UnavailableKind::IdentityMismatch`], never an empty store whose locks look missing. With
//! [`StoreOptions::require_dedicated_mount`], a root that is not a mount point is refused before
//! anything is read.
//!
//! # On-disk layout
//!
//! ```text
//! <root>/                                  ext4/xfs/btrfs/zfs/f2fs (or allow_any_filesystem); never a symlink
//!   .lock                                  exclusive flock, held for the Store's lifetime
//!   identity.json                          {store_format, store_uuid, chain_id, router, prover}
//!   next_version                           store-wide version counter (decimal)
//!   tmp/                                   writes in progress; emptied at every open
//!   bundles/<jobId>/<descriptorHash>/<prover>/v<n>/
//!       w.bin                              W (0444; may be a hard link shared with other versions)
//!       bundle.json                        BundleV1 (0444), whose `version` is n
//!   pins/<jobId>.<descriptorHash>.<prover>.json   PinRecord (0444)
//!   elfs/<imageId>                         guest ELF, content-addressed (0444); a bundle records
//!                                          its sha256, checked on reads through the bundle
//!   verdicts/<jobId>.json                  VerdictRecord
//! ```
//!
//! Hashes and addresses are lowercase hex without `0x`. Every path is walked from the root's
//! directory fd one component at a time with `O_NOFOLLOW`, and every change is an `*at` syscall
//! inside such a directory: a symlink anywhere is never followed (a read through one is
//! [`UnavailableKind::BadLayout`], the scan reports it as an anomaly), so nothing outside the root
//! is ever read, changed or deleted.
//!
//! # Durability
//!
//! - **Version numbers** come from the store-wide counter, advanced durably (temp file, fsync,
//!   rename, fsync of the root) when a writer begins ([`BundleWriter::version`]), so a number is
//!   never reused, even after its bundle is evicted or deleted, and the record can carry it.
//! - **Bundle publish** ([`BundleWriter::finish`]): `w.bin` and `bundle.json` are written in
//!   `tmp/<random>/`, made read-only and fsynced ([`BundleWriter::seal_w`] can do `w.bin` early, to
//!   execute from it before publishing); `tmp/<random>/` is fsynced; each missing parent is created
//!   and its parent fsynced; `tmp/<random>/` is renamed to `v<n>` and the key directory fsynced. A
//!   crash before the rename leaves only `tmp/` debris, removed at the next open; the rename is
//!   atomic and its contents were durable before it, so a `v<n>` that exists is complete. Published
//!   files are never modified: a new execution result is a new version
//!   ([`Store::begin_version_from`] shares the old `W` by hard link).
//! - **Pins** ([`Store::pin`]) go to a temp file, fsync, rename into `pins/`, fsync of `pins/`:
//!   durable when `pin` returns. `pin` requires the version to exist and match the record's hashes,
//!   and versions are durable before `finish` returns, so a durable pin never names a version that
//!   a crash could lose.
//! - **Removal** (eviction, deletion) renames the entry into `tmp/` first (so no half-deleted
//!   version is ever visible under its name), drops it from the index, fsyncs the old parent, and
//!   only then deletes it.
//! - **Poisoning.** When a change fails after it became visible (an fsync after a rename, a rename
//!   after a mkdir), or a metadata call fails with EIO, the store no longer knows that the disk
//!   holds what it promised, and a retried fsync can falsely succeed (fsyncgate). The store is then
//!   *poisoned*: every later call is [`UnavailableKind::Poisoned`] until it is reopened, except the
//!   verified reads of a version a readable pin names (or the last readable pin of a key whose
//!   re-pin failed) ([`Store::read`], [`Store::open_w`],
//!   [`Store::w_path`], [`Store::verify`]) and of a bundle's ELF ([`Store::open_bundle_elf`]),
//!   which re-check every byte they return, so a held lock is still proven. A publish whose final fsync fails is renamed back
//!   into `tmp/` and never indexed; a pin whose write fails leaves its key's pin unknown, protecting
//!   every version of the key, while the pin it had stays readable.
//!
//! # Admission
//!
//! Quotas cover bytes and inodes of everything under the root, unpinned versions included: they
//! are a cache, evicted lowest-value-first, but only when asked. Call [`Store::evict_to`] before
//! [`Store::begin_bundle`], or use [`Store::begin_bundle_evicting`]. The free-space floor also
//! counts bytes admitted to concurrent writers but not yet written.
//!
//! # Concurrency
//!
//! [`Store`] is `Send + Sync` with one internal mutex. Streaming `W`, hashing on read and caller
//! closures run outside it; every change to the index, pins, counters and usage runs under it.

// The crate's unit tests share the integration tests' helpers, which name the crate.
#[cfg(test)]
extern crate self as zkminer_witness_store;

mod elf;
mod error;
mod evict;
mod faults;
mod fsutil;
mod layout;
mod pins;
mod revalidate;
mod store;
mod verdicts;
mod writer;

#[cfg(test)]
mod tests;

pub use elf::ElfHold;
pub use error::{Defect, FullReason, Reject, StoreError, UnavailableKind};
pub use evict::{DeleteReport, EvictReport};
pub use revalidate::{missing_po2s, revalidate, unprovable_po2s, HostProfile, Revalidation};
pub use store::{
    Anomaly, AnomalyKind, BundleKey, BundleMeta, BundleRef, BundleSummary, ExpectedIdentity, OpenReport, PinStatus,
    ScanReport, Store, StoreIdentityInit, StoreOptions, TerminalProof, TerminalState, Usage, MAX_BUNDLE_JSON_BYTES,
    MAX_ELF_BYTES, STORE_FORMAT_VERSION,
};
pub use writer::{BundleWriter, BUNDLE_JSON_ALLOWANCE};
