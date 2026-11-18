//! The retention bundle schema (plan §15.1). The store crate owns the on-disk layout; this module
//! owns the record types so the miner, the store and tooling agree on them.

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

/// The record format this build writes and reads. 2: `sys_rand_rule` replaced version 1's key
/// fingerprint when the risc0 `sys_rand` seed became a public rule; a version-1 record does not
/// load.
pub const BUNDLE_FORMAT_VERSION: u32 = 2;

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
    /// The store version this record is published as (`v<version>/`); checked against the
    /// directory on every read, so a record never passes for another version's.
    pub version: u32,
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
    /// The `sys_rand` rule the executions were seeded by (`sys_rand::rule_id()` of
    /// zkminer-prover-protocol, `SHA-256(SYS_RAND_DOMAIN)`): revalidation executes a bundle
    /// recorded under another rule again rather than prove it as if its journals still held.
    pub sys_rand_rule: B256,
    pub keccak_po2: u32,
    /// Build ids of every worker binary that may prove this bundle.
    pub worker_builds: Vec<String>,
    pub created_at_block: u64,
    pub builder_id: B256,
    pub caller: Address,
    /// Milliseconds one po2's execute took when the bundle was simulated (the execute step's wall
    /// time over its po2s): the prove executes the guest again and replays its segments, so a lock
    /// taken on a retained bundle budgets that time as a fresh simulation would. `None` in a record
    /// written before it was kept; such a bundle is not reused for a new lock.
    #[serde(default)]
    pub execute_ms_per_po2: Option<u64>,
    /// `sha256` of the retained ELF's bytes as the store holds them under `image_id` (verified
    /// against `image_id` when it was retained). A read through the bundle checks the ELF against it,
    /// so proving a held lock needs no image-id derivation. `None` in a record written before it was
    /// kept: the ELF's image id is derived again.
    #[serde(default)]
    pub elf_sha256: Option<B256>,
}

impl BundleV1 {
    /// The po2 result for `po2`, if executed.
    pub fn at(&self, po2: u32) -> Option<&Po2Result> {
        self.po2_results.iter().find(|r| r.po2 == po2)
    }

    /// The prefix the bundle's guest input starts with (`abi.encode(jobId, prover)` for a prefix
    /// job): the one derivation the store's `W` check, the prove dispatch and recovery share.
    pub fn input_prefix(&self) -> Option<[u8; crate::binding::PREFIX_BYTES]> {
        self.prefix.then(|| crate::binding::journal_prefix(self.job_id, self.prover))
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
    /// The pinned version's `input_sha256` (`sha256(prefix ‖ W)`), checked on every read through
    /// the pin.
    pub input_sha256: B256,
    /// `sha256` of the pinned version's `bundle.json` bytes, checked on every read through the pin.
    pub bundle_json_sha256: B256,
    /// The job's `reopenCount` when the pin was taken (the lock instance the claim is for). A read
    /// showing a higher count proves that instance ended, whoever held it. `None` in a pin written
    /// before it was kept.
    #[serde(default)]
    pub reopen_count: Option<u8>,
    /// A block at which the job read Locked by this prover (0 until the claim is confirmed): a read
    /// pinned at or after it that shows another prover proves our lock is gone.
    #[serde(default)]
    pub lock_block: u64,
    /// Chain time (unix seconds) when the pin was taken, for the claim-intent age rule (§15.2: a
    /// claim that provably never landed is judged by chain time). 0 in a pin written before it was
    /// kept.
    #[serde(default)]
    pub pinned_at_unix: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record or pin written before the newer fields existed still reads, with them unset.
    #[test]
    fn older_records_read_with_the_newer_fields_unset() {
        let pin = PinRecord {
            job_id: B256::repeat_byte(1),
            descriptor_hash: B256::repeat_byte(2),
            prover: Address::repeat_byte(3),
            bundle_version: 4,
            pinned_at_block: 5,
            input_sha256: B256::repeat_byte(6),
            bundle_json_sha256: B256::repeat_byte(7),
            reopen_count: Some(1),
            lock_block: 9,
            pinned_at_unix: 10,
        };
        let mut v = serde_json::to_value(&pin).unwrap();
        for k in ["reopen_count", "lock_block", "pinned_at_unix"] {
            v.as_object_mut().unwrap().remove(k);
        }
        let old: PinRecord = serde_json::from_value(v).unwrap();
        assert_eq!(old, PinRecord { reopen_count: None, lock_block: 0, pinned_at_unix: 0, ..pin });
    }

    #[test]
    fn the_input_prefix_is_the_journal_prefix_of_a_prefix_job() {
        let b = BundleV1 {
            format_version: BUNDLE_FORMAT_VERSION,
            job_id: B256::repeat_byte(0xaa),
            descriptor_hash: B256::ZERO,
            prover: Address::repeat_byte(0xbb),
            version: 1,
            descriptor_hex: String::new(),
            submit_tx_hash: B256::ZERO,
            prefix: true,
            image_id: B256::ZERO,
            po2_results: Vec::new(),
            input_sha256: B256::ZERO,
            w_sha256: B256::ZERO,
            w_len: 0,
            sys_rand_rule: B256::ZERO,
            keccak_po2: 17,
            worker_builds: Vec::new(),
            created_at_block: 0,
            builder_id: B256::ZERO,
            caller: Address::ZERO,
            execute_ms_per_po2: None,
            elf_sha256: None,
        };
        assert_eq!(b.input_prefix(), Some(crate::binding::journal_prefix(b.job_id, b.prover)));
        assert_eq!(BundleV1 { prefix: false, ..b.clone() }.input_prefix(), None);
        let mut v = serde_json::to_value(&b).unwrap();
        v.as_object_mut().unwrap().remove("execute_ms_per_po2");
        v.as_object_mut().unwrap().remove("elf_sha256");
        assert_eq!(serde_json::from_value::<BundleV1>(v).unwrap(), b);
    }
}
