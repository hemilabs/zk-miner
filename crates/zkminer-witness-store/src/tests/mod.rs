//! Unit tests that drive the fault seam ([`crate::faults`]), which exists only in this build: the
//! fsync/rename failure sequences (F1, F5, F8), `open`/`init` classification under injected
//! errors (F3), crash-at-step-k sweeps, and deterministic interleavings with eviction.

#[path = "../../tests/common/mod.rs"]
mod common;

mod classify;
mod crash;
mod durability;
mod races;

use crate::{Defect, StoreError, UnavailableKind};

pub(crate) fn unavailable(e: StoreError) -> UnavailableKind {
    match e {
        StoreError::Unavailable { kind, .. } => kind,
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[allow(dead_code)]
pub(crate) fn defect(e: StoreError) -> Defect {
    match e {
        StoreError::Corrupt { defect, .. } => defect,
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

pub(crate) fn poisoned<T: std::fmt::Debug>(r: Result<T, StoreError>) {
    match r {
        Err(StoreError::Unavailable { kind: UnavailableKind::Poisoned, .. }) => {}
        other => panic!("expected Unavailable(Poisoned), got {other:?}"),
    }
}
