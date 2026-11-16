//! The retention bundle schema (plan §15.1). The store crate owns the on-disk layout; this module
//! owns the record types so the miner, the store and tooling agree on them.

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

pub const BUNDLE_FORMAT_VERSION: u32 = 1;

/// Per-po2 execution results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Po2Result {
    pub po2: u32,
    /// The journal, hex (at most 32 KiB).
    pub journal_hex: String,
    pub journal_sha256: B256,
    /// Sized cycles in the `maxGuestCycles` unit.
    pub cycles: u64,
    pub exit: GuestExit,
    pub segment_bytes: u64,
}

/// How a guest execution ended (risc0 `ExitCode`); only `Halted(0)` is provable for a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "code", rename_all = "snake_case")]
pub enum GuestExit {
    Halted(u32),
    Paused(u32),
    SystemSplit,
    SessionLimit,
}

/// Everything a lock is proven from (plan §15.1). `W` itself is a separate file (`w.bin`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleV1 {
    pub format_version: u32,
    pub job_id: B256,
    pub descriptor_hash: B256,
    pub prover: Address,
    /// The full descriptor, ABI-encoded, hex; verified against `descriptor_hash` on read.
    pub descriptor_hex: String,
    pub submit_tx_hash: B256,
    pub prefix: bool,
    pub image_id: B256,
    pub po2_results: Vec<Po2Result>,
    /// `sha256(prefix ‖ W)`: what the prove worker checks its input against.
    pub input_sha256: B256,
    /// `sha256(W)`: what reads of `w.bin` are verified against.
    pub w_sha256: B256,
    pub w_len: u64,
    pub sys_rand_key_fingerprint: B256,
    pub keccak_po2: u32,
    /// Build ids of every worker binary that may prove this bundle.
    pub worker_builds: Vec<String>,
    pub created_at_block: u64,
    pub builder_id: B256,
    pub caller: Address,
}

impl BundleV1 {
    /// The po2 result for `po2`, if executed.
    pub fn at(&self, po2: u32) -> Option<&Po2Result> {
        self.po2_results.iter().find(|r| r.po2 == po2)
    }
}

/// The store's identity record (plan §15.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreIdentity {
    pub store_uuid: String,
    pub chain_id: u64,
    pub router: Address,
    pub prover: Address,
}

/// A pin: fsynced before the claim intent is journaled and before the lock transaction is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinRecord {
    pub job_id: B256,
    pub descriptor_hash: B256,
    pub prover: Address,
    /// The bundle version the lock will prove.
    pub bundle_version: u32,
    pub pinned_at_block: u64,
}
