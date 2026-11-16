//! The witness retention store (docs/witness-construction-jobs.md §15.1, §15.2): the bundles a
//! witness lock is proven from, their pins, the shared ELF area, and persisted verdicts.
//!
//! A miner takes a witness lock only after `W` is persisted here, the bundle published and pinned
//! (§5.1, §5.7); after the lock it proves the bundle and never rebuilds (invariant 2). So the store
//! must never show a partial bundle, must keep what a lock depends on, and must say precisely
//! whether it is *unavailable* (keep every lock), or a bundle *missing* or *corrupt* on an available
//! store (page, wait, salvage or release) — see [`StoreError`].
//!
//! # On-disk layout
//!
//! ```text
//! <root>/                                  never tmpfs, ramfs or overlayfs; never a symlink
//!   .lock                                  exclusive flock, held for the Store's lifetime
//!   identity.json                          {store_format, store_uuid, chain_id, router, prover}
//!   next_version                           store-wide version counter (decimal)
//!   tmp/                                   writes in progress; emptied at every open
//!   bundles/<jobId>/<descriptorHash>/<prover>/v<n>/
//!       w.bin                              W (0444)
//!       bundle.json                        BundleV1 (0444)
//!   pins/<jobId>.<descriptorHash>.<prover>.json   PinRecord (0444)
//!   elfs/<imageId>                         guest ELF, content-addressed (0444)
//!   verdicts/<jobId>.json                  VerdictRecord
//! ```
//!
//! Hashes and addresses are lowercase hex without `0x`.
//!
//! # Durability
//!
//! - **Bundle publish** ([`BundleWriter::finish`]): `w.bin` and `bundle.json` are written in
//!   `tmp/<random>/`, made read-only and fsynced; `tmp/<random>/` is fsynced; `next_version` is
//!   advanced (temp file, fsync, rename, fsync of the root); each missing parent is created and its
//!   parent fsynced; `tmp/<random>/` is renamed to `v<n>`; and every parent up to `bundles/` is
//!   fsynced. A crash before the rename leaves only `tmp/` debris, removed at the next open; the
//!   rename is atomic and its contents were durable before it, so a `v<n>` that exists is complete.
//!   Published files are never modified: a new execution result is a new version.
//! - **Version numbers** come from the counter, which is durable before the rename that uses it, so
//!   a number is never reused, even after its bundle is evicted or deleted.
//! - **Pins** ([`Store::pin`]) go to a temp file, fsync, rename into `pins/`, fsync of `pins/`:
//!   durable when `pin` returns. `pin` requires the version to exist, and versions are durable
//!   before `finish` returns, so a durable pin never names a version that a crash could lose.
//! - **Removal** (eviction, deletion) renames the entry into `tmp/` first, so no half-deleted
//!   version is ever visible under its name, then deletes it.
//!
//! # Concurrency
//!
//! [`Store`] is `Send + Sync` with one internal mutex. Streaming `W`, hashing on read and caller
//! closures run outside it; every change to the index, pins, counters and usage runs under it.

mod elf;
mod error;
mod evict;
mod fsutil;
mod layout;
mod pins;
mod revalidate;
mod store;
mod verdicts;
mod writer;

pub use elf::ElfHold;
pub use error::{Defect, FullReason, Reject, StoreError, UnavailableKind};
pub use evict::{DeleteReport, EvictReport};
pub use revalidate::{missing_po2s, revalidate, unprovable_po2s, HostProfile, Revalidation};
pub use store::{
    Anomaly, AnomalyKind, BundleKey, BundleMeta, BundleRef, BundleSummary, ExpectedIdentity, OpenReport, PinStatus,
    ScanReport, Store, StoreOptions, TerminalProof, TerminalState, Usage, MAX_BUNDLE_JSON_BYTES, MAX_ELF_BYTES,
    STORE_FORMAT_VERSION,
};
pub use writer::BundleWriter;
