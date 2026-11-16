//! The router's journal binding (handoff §8), mirrored so a job is checked BEFORE it is claimed.
//!
//! `HemiProveFulfill._checkBinding` runs on every fulfil path before the verifier: a journal that
//! does not satisfy the job's `expectedJournalHash` / `journalFields` reverts `JournalMismatch` (or
//! `JournalPrefixMismatch`) after we have locked collateral, and the lock then ends in a release
//! penalty. The binding is a pure function of the descriptor and the journal, and the journal is a
//! deterministic function of (ELF, input), so the pre-claim measurement decides it exactly.
//!
//! This mirrors the Solidity line for line (hemiprove-contracts 3bc441d, the deployed 8e1808b,
//! `src/core/HemiProveFulfill.sol` `_checkBinding`):
//! - slot 0 of `journalFields` may hold a marker. `0xffffffff` (journal prefix) requires
//!   `journal[0:64] == jobId ‖ uint256(prover)` and moves the statement check to `journal[64:]`;
//!   `0xfffffffe` (SP1 proof nonce) is a check on the SEAL, which this module does not see, so a job
//!   carrying it is refused here (`NonceUnchecked`) rather than passed. Slot 0 is then cleared
//!   before the mode is chosen.
//! - `expectedJournalHash == 0` is NONE: nothing to check.
//! - the remaining `journalFields == 0` is FULL: `keccak256(abi.encode(JOURNAL_PREDICATE_DOMAIN_V1,
//!   proofSystemId, programId, journal))`.
//! - otherwise FIELDS: plain `keccak256` of the used slots' ranges in slot order, or 0 when a used
//!   range ends past the journal (a mismatch, never a truncation).

use alloy::primitives::{b256, keccak256, Address, B256};
use zkminer_contracts::bindings::JobDescriptor;

/// `keccak256("HemiProve.JournalPredicate.v1")`.
pub const JOURNAL_PREDICATE_DOMAIN_V1: B256 =
    b256!("8fc1eec9ac3fed1ebf9116804d90a1da182248d5fcdc1edcc673416bf4231898");
/// `journalFields` slot 0: the journal must begin with `abi.encode(jobId, prover)`.
pub const JOURNAL_PREFIX_MARKER: u32 = 0xffff_ffff;
/// `journalFields` slot 0: the SP1 seal's nonce word must equal `getProofNonce(jobId, prover)`.
pub const PROOF_NONCE_MARKER: u32 = 0xffff_fffe;
/// Length of the journal prefix, `abi.encode(bytes32 jobId, address prover)`.
pub const JOURNAL_PREFIX_BYTES: usize = 64;

/// Why a journal does not satisfy a job's binding, as the router would revert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingMismatch {
    /// `JournalPrefixMismatch(jobId, prover)`: the journal does not begin with `jobId ‖ prover`.
    Prefix,
    /// `JournalMismatch(expected, computed)`.
    Journal { expected: B256, computed: B256 },
    /// The SP1 proof-nonce marker binds the seal (`ProofNonceMismatch`), which this check does not
    /// see: not satisfied as far as it can tell.
    NonceUnchecked,
}

impl std::fmt::Display for BindingMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingMismatch::Prefix => write!(f, "JournalPrefixMismatch"),
            BindingMismatch::NonceUnchecked => write!(f, "the SP1 proof nonce is not checked here"),
            BindingMismatch::Journal { expected, computed } => {
                write!(
                    f,
                    "JournalMismatch(expected {expected}, computed {computed})"
                )
            }
        }
    }
}

/// The marker in slot 0 of `journalFields`, if any.
pub fn marker(journal_fields: B256) -> Option<u32> {
    let slot0 = u32::from_be_bytes(journal_fields.0[..4].try_into().unwrap());
    (slot0 >= PROOF_NONCE_MARKER).then_some(slot0)
}

/// The FULL statement hash: `keccak256(abi.encode(JOURNAL_PREDICATE_DOMAIN_V1, proofSystemId,
/// programId, journal))`, `journal` encoded as dynamic `bytes`.
pub fn full_hash(proof_system_id: B256, program_id: B256, journal: &[u8]) -> B256 {
    let padded = journal.len().div_ceil(32) * 32;
    let mut enc = Vec::with_capacity(5 * 32 + padded);
    enc.extend_from_slice(JOURNAL_PREDICATE_DOMAIN_V1.as_slice());
    enc.extend_from_slice(proof_system_id.as_slice());
    enc.extend_from_slice(program_id.as_slice());
    // Head word of the dynamic argument: its offset, after the four head words.
    enc.extend_from_slice(B256::left_padding_from(&[0x80]).as_slice());
    enc.extend_from_slice(
        B256::left_padding_from(&(journal.len() as u64).to_be_bytes()).as_slice(),
    );
    enc.extend_from_slice(journal);
    enc.resize(5 * 32 + padded, 0);
    keccak256(&enc)
}

/// The FIELDS hash of `journal` under `fields` (`_journalFieldsHash`): the plain `keccak256` of the
/// used slots' ranges concatenated in slot order, or `B256::ZERO` when a used range ends past the
/// journal. A slot is `(uint16 offset << 16) | uint16 length`, slot 0 the top 32 bits; length 0 is
/// unused.
pub fn fields_hash(journal: &[u8], fields: B256) -> B256 {
    let mut buf = Vec::new();
    for slot in fields.0.chunks_exact(4) {
        let off = u16::from_be_bytes([slot[0], slot[1]]) as usize;
        let len = u16::from_be_bytes([slot[2], slot[3]]) as usize;
        if len == 0 {
            continue;
        }
        if off + len > journal.len() {
            return B256::ZERO;
        }
        buf.extend_from_slice(&journal[off..off + len]);
    }
    keccak256(&buf)
}

/// Does `journal` satisfy `d`'s binding for job `job_id` locked by `prover`? Mirrors the router's
/// `_checkBinding`. The SP1 proof-nonce marker binds the seal, not the journal, so a job carrying it
/// is never reported satisfied (`NonceUnchecked`).
pub fn check_journal_binding(
    d: &JobDescriptor,
    journal: &[u8],
    job_id: B256,
    prover: Address,
) -> Result<(), BindingMismatch> {
    let mut fields = d.journalFields;
    let mut statement = journal;
    if let Some(m) = marker(fields) {
        fields.0[..4].fill(0);
        if m == PROOF_NONCE_MARKER {
            return Err(BindingMismatch::NonceUnchecked);
        }
        if m == JOURNAL_PREFIX_MARKER {
            if journal.len() < JOURNAL_PREFIX_BYTES
                || journal[..32] != job_id.0
                || journal[32..64] != B256::left_padding_from(prover.as_slice()).0
            {
                return Err(BindingMismatch::Prefix);
            }
            statement = &journal[JOURNAL_PREFIX_BYTES..];
        }
    }
    let expected = d.expectedJournalHash;
    if expected == B256::ZERO {
        return Ok(());
    }
    let computed = if fields == B256::ZERO {
        full_hash(d.proofSystemId, d.programId, statement)
    } else {
        fields_hash(statement, fields)
    };
    if computed == expected {
        Ok(())
    } else {
        Err(BindingMismatch::Journal { expected, computed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    // The contract suite's real RISC Zero receipt (test/fixtures/RiscZeroTestReceipt.sol): journal
    // "zkpool e2e test" under its image id.
    const JOURNAL: &[u8] = b"zkpool e2e test";
    const IMAGE_ID: B256 =
        b256!("bc93ea63d7adda6b4e2f0f930c2c9fe53d57e8f4add5aa81af2373949517edfe");

    fn slots(s: &[u32]) -> B256 {
        let mut w = B256::ZERO;
        for (i, v) in s.iter().enumerate() {
            w.0[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
        }
        w
    }

    fn desc(expected: B256, fields: B256) -> JobDescriptor {
        JobDescriptor {
            programId: IMAGE_ID,
            proofSystemId: crate::auction::risc_zero_groth16_v1_id(),
            callbackContract: Address::ZERO,
            assignedProver: Address::ZERO,
            tag: B256::ZERO,
            inputData: Default::default(),
            callbackExtraData: Default::default(),
            extraVerifierData: Default::default(),
            expectedJournalHash: expected,
            journalFields: fields,
        }
    }

    const JOB: B256 = b256!("2222222222222222222222222222222222222222222222222222222222222222");
    const PROVER: Address = address!("3333333333333333333333333333333333333333");

    fn prefixed(statement: &[u8]) -> Vec<u8> {
        let mut j = JOB.to_vec();
        j.extend_from_slice(&B256::left_padding_from(PROVER.as_slice()).0);
        j.extend_from_slice(statement);
        j
    }

    #[test]
    fn domain_is_the_keccak_of_its_tag() {
        assert_eq!(
            JOURNAL_PREDICATE_DOMAIN_V1,
            keccak256("HemiProve.JournalPredicate.v1")
        );
    }

    // Expected values from `cast keccak $(cast abi-encode "f(bytes32,bytes32,bytes32,bytes)" ...)`.
    #[test]
    fn full_hash_matches_solidity_abi_encode() {
        let ps = crate::auction::risc_zero_groth16_v1_id();
        assert_eq!(
            ps,
            b256!("f8fe527fde36a1f428dcd6b89b775a345a829f12ff8f54ba488149a8dc3960c5")
        );
        assert_eq!(
            full_hash(ps, IMAGE_ID, JOURNAL),
            b256!("9ae65eff5da6fdb352555713541992128e277bf5312518474d899fe2effe13b8")
        );
        assert_eq!(
            full_hash(ps, IMAGE_ID, &[]),
            b256!("3e46812c126ac848216cfb28de779bf0d54c51a9d137d622dff4fec92c733a0a")
        );
        let j33: Vec<u8> = (0u8..33).collect();
        assert_eq!(
            full_hash(ps, IMAGE_ID, &j33),
            b256!("686cc68d740711aa83aa9c7f5952c7c4e92c779668080770f1492b88af44a21f")
        );
    }

    #[test]
    fn full_hash_agrees_with_alloy_abi_encode_params() {
        use alloy::sol_types::SolValue;
        let ps = crate::auction::risc_zero_groth16_v1_id();
        for len in [0usize, 1, 31, 32, 33, 64, 100] {
            let j: Vec<u8> = (0..len).map(|i| i as u8 ^ 0x5a).collect();
            let enc = (
                JOURNAL_PREDICATE_DOMAIN_V1,
                ps,
                IMAGE_ID,
                alloy::primitives::Bytes::from(j.clone()),
            )
                .abi_encode_params();
            assert_eq!(full_hash(ps, IMAGE_ID, &j), keccak256(&enc), "len {len}");
        }
    }

    #[test]
    fn fields_hash_follows_slot_order_and_allows_overlap() {
        // "zkpool " = bytes 0..7.
        assert_eq!(
            fields_hash(JOURNAL, slots(&[7])),
            b256!("84773cd7dcc845cbacc63f7800da89ac53d6c63725f155d2ac301f3b63adf84f")
        );
        // "e2e test" (7..15) then "pool" (2..6): out of order, overlapping, an unused slot between.
        assert_eq!(
            fields_hash(JOURNAL, slots(&[(7 << 16) | 8, 0x1234_0000, (2 << 16) | 4])),
            b256!("97f1540fc026c8e5464ad9bbafc0c371fad1c39a8e69815a294b5af8cfd73983")
        );
    }

    #[test]
    fn a_field_past_the_journal_is_zero_not_a_truncation() {
        assert_eq!(fields_hash(JOURNAL, slots(&[(8 << 16) | 8])), B256::ZERO);
        assert_ne!(fields_hash(JOURNAL, slots(&[(7 << 16) | 8])), B256::ZERO);
        assert_eq!(fields_hash(JOURNAL, slots(&[0xffff_ffff])), B256::ZERO);
    }

    #[test]
    fn full_and_fields_jobs_are_checked() {
        let full = full_hash(crate::auction::risc_zero_groth16_v1_id(), IMAGE_ID, JOURNAL);
        assert_eq!(
            check_journal_binding(&desc(full, B256::ZERO), JOURNAL, JOB, PROVER),
            Ok(())
        );
        let err = check_journal_binding(&desc(full, B256::ZERO), b"zkpool e2e tesT", JOB, PROVER);
        assert!(matches!(err, Err(BindingMismatch::Journal { expected, .. }) if expected == full));

        let f = slots(&[7]);
        let h = fields_hash(JOURNAL, f);
        assert_eq!(
            check_journal_binding(&desc(h, f), JOURNAL, JOB, PROVER),
            Ok(())
        );
        // The result bytes are free under FIELDS.
        assert_eq!(
            check_journal_binding(&desc(h, f), b"zkpool other", JOB, PROVER),
            Ok(())
        );
        assert_eq!(
            check_journal_binding(&desc(h, f), b"zkpo", JOB, PROVER),
            Err(BindingMismatch::Journal {
                expected: h,
                computed: B256::ZERO
            })
        );
    }

    #[test]
    fn the_full_hash_binds_the_proof_system_and_program() {
        let full = full_hash(crate::auction::risc_zero_groth16_v1_id(), IMAGE_ID, JOURNAL);
        let mut d = desc(full, B256::ZERO);
        d.proofSystemId = crate::auction::sp1_groth16_v1_id();
        assert!(check_journal_binding(&d, JOURNAL, JOB, PROVER).is_err());
        let mut d = desc(full, B256::ZERO);
        d.programId = B256::repeat_byte(1);
        assert!(check_journal_binding(&d, JOURNAL, JOB, PROVER).is_err());
    }

    #[test]
    fn none_checks_nothing() {
        assert_eq!(
            check_journal_binding(&desc(B256::ZERO, B256::ZERO), b"", JOB, PROVER),
            Ok(())
        );
    }

    #[test]
    fn the_prefix_marker_binds_job_and_prover_and_shifts_the_statement() {
        let statement = JOURNAL;
        let full = full_hash(
            crate::auction::risc_zero_groth16_v1_id(),
            IMAGE_ID,
            statement,
        );
        let d = desc(full, slots(&[JOURNAL_PREFIX_MARKER]));
        assert_eq!(
            check_journal_binding(&d, &prefixed(statement), JOB, PROVER),
            Ok(())
        );
        // Another prover, another job, a short journal, or dirty high bytes in the prover word.
        let other = address!("4444444444444444444444444444444444444444");
        assert_eq!(
            check_journal_binding(&d, &prefixed(statement), JOB, other),
            Err(BindingMismatch::Prefix)
        );
        assert_eq!(
            check_journal_binding(&d, &prefixed(statement), B256::repeat_byte(9), PROVER),
            Err(BindingMismatch::Prefix)
        );
        assert_eq!(
            check_journal_binding(&d, &prefixed(statement)[..63], JOB, PROVER),
            Err(BindingMismatch::Prefix)
        );
        let mut dirty = prefixed(statement);
        dirty[32] = 1;
        assert_eq!(
            check_journal_binding(&d, &dirty, JOB, PROVER),
            Err(BindingMismatch::Prefix)
        );
        // The bare statement (no prefix) is refused.
        assert!(check_journal_binding(&d, statement, JOB, PROVER).is_err());

        // FIELDS under the marker: ranges in slots 1..7, offsets counted from byte 64.
        let f = slots(&[JOURNAL_PREFIX_MARKER, 7]);
        let h = fields_hash(statement, slots(&[7]));
        assert_eq!(
            check_journal_binding(&desc(h, f), &prefixed(statement), JOB, PROVER),
            Ok(())
        );
    }

    #[test]
    fn the_nonce_marker_is_never_reported_satisfied() {
        // The journal would satisfy the statement binding, but the nonce lives in the seal.
        let full = full_hash(crate::auction::risc_zero_groth16_v1_id(), IMAGE_ID, JOURNAL);
        let d = desc(full, slots(&[PROOF_NONCE_MARKER]));
        assert_eq!(
            check_journal_binding(&d, JOURNAL, JOB, PROVER),
            Err(BindingMismatch::NonceUnchecked)
        );
        let none = desc(B256::ZERO, slots(&[PROOF_NONCE_MARKER]));
        assert_eq!(
            check_journal_binding(&none, JOURNAL, JOB, PROVER),
            Err(BindingMismatch::NonceUnchecked)
        );
    }

    #[test]
    fn a_field_under_the_prefix_is_bounded_by_the_narrowed_journal() {
        // 15 statement bytes after the prefix: offset 8 + length 8 ends at 16, past the statement,
        // although it is well inside the whole 79-byte journal.
        let f = slots(&[JOURNAL_PREFIX_MARKER, (8 << 16) | 8]);
        let d = desc(B256::repeat_byte(1), f);
        assert_eq!(
            check_journal_binding(&d, &prefixed(JOURNAL), JOB, PROVER),
            Err(BindingMismatch::Journal {
                expected: B256::repeat_byte(1),
                computed: B256::ZERO
            })
        );
    }

    #[test]
    fn markers_are_only_the_two_top_values() {
        assert_eq!(marker(slots(&[0xffff_ffff])), Some(JOURNAL_PREFIX_MARKER));
        assert_eq!(marker(slots(&[0xffff_fffe])), Some(PROOF_NONCE_MARKER));
        assert_eq!(marker(slots(&[0xffff_fffd])), None);
        assert_eq!(marker(B256::ZERO), None);
    }
}
