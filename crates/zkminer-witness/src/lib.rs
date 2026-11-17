//! Shared formats for witness-construction jobs (docs/witness-construction-jobs.md):
//! the `inputData` envelope (§7.1), the builder context (§9.2), `hemi-code` locators and artifact
//! manifests (§13), journal-binding helpers (§7.2), the guest-cycle unit (§7.1), local verdicts
//! (§16), IPC frames between the miner, the broker and builders (§10.1), and the retention bundle
//! schema (§15.1).

pub mod abi;
pub mod binding;
pub mod bundle;
pub mod context;
pub mod cycles;
pub mod envelope;
pub mod ipc;
pub mod locator;
pub mod manifest;
pub mod requester;
pub mod verdict;

pub use envelope::{
    classify, decode, encode_envelope, BuilderSource, BuilderType, Capability, CapabilityKind, Envelope,
    EnvelopeError, HostMaxima, Limits, MethodSet, WitnessJobV1, WITNESS_JOB_TAG_V1,
};
pub use locator::HemiCodeLocator;
