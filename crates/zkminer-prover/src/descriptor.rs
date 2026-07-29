//! Descriptor hash computation — must match `_computeDescriptorHash` in Solidity exactly.
//!
//! ```solidity
//! keccak256(abi.encode(
//!     programId,
//!     proofSystemId,
//!     callback,
//!     assignedProver,
//!     tag,
//!     keccak256(inputData),
//!     keccak256(callbackExtraData),
//!     keccak256(extraVerifierData),
//!     expectedJournalHash               // [Phase 2, 2026-07-10] 9th slot, raw
//! ))
//! ```

use alloy_primitives::{Address, B256, keccak256};

/// Compute the descriptor hash matching the on-chain `_computeDescriptorHash`.
///
/// `expected_journal_hash` is the Phase-2 predicate commitment (raw `bytes32`,
/// NOT pre-hashed). Pass `B256::ZERO` for opt-out (predicate-free) jobs.
pub fn compute_descriptor_hash(
    program_id: B256,
    proof_system_id: B256,
    callback_contract: Address,
    assigned_prover: Address,
    tag: B256,
    input_data: &[u8],
    callback_extra_data: &[u8],
    extra_verifier_data: &[u8],
    expected_journal_hash: B256,
) -> B256 {
    let input_data_hash = keccak256(input_data);
    let callback_extra_data_hash = keccak256(callback_extra_data);
    let extra_verifier_data_hash = keccak256(extra_verifier_data);

    // abi.encode packs each value into a 32-byte word
    let mut encoded = Vec::with_capacity(288); // 9 * 32 = 288 bytes

    // bytes32 programId
    encoded.extend_from_slice(program_id.as_slice());
    // bytes32 proofSystemId
    encoded.extend_from_slice(proof_system_id.as_slice());
    // address callback — left-padded to 32 bytes
    encoded.extend_from_slice(&address_to_word(callback_contract));
    // address assignedProver — left-padded to 32 bytes
    encoded.extend_from_slice(&address_to_word(assigned_prover));
    // bytes32 tag
    encoded.extend_from_slice(tag.as_slice());
    // bytes32 keccak256(inputData)
    encoded.extend_from_slice(input_data_hash.as_slice());
    // bytes32 keccak256(callbackExtraData)
    encoded.extend_from_slice(callback_extra_data_hash.as_slice());
    // bytes32 keccak256(extraVerifierData)
    encoded.extend_from_slice(extra_verifier_data_hash.as_slice());
    // bytes32 expectedJournalHash (raw, NOT pre-hashed)
    encoded.extend_from_slice(expected_journal_hash.as_slice());

    keccak256(&encoded)
}

/// Compute descriptor hash from pre-hashed input data (for fulfillJobHashed).
///
/// NOTE: the on-chain `fulfillJobHashed` fast-path hard-codes
/// `expectedJournalHash = 0` (opt-out only), so predicate jobs cannot be
/// fulfilled through the hashed path. This helper takes `expected_journal_hash`
/// for completeness; pass `B256::ZERO` to match the hashed entrypoint.
pub fn compute_descriptor_hash_from_hashed(
    program_id: B256,
    proof_system_id: B256,
    callback_contract: Address,
    assigned_prover: Address,
    tag: B256,
    input_data_hash: B256,
    callback_extra_data: &[u8],
    extra_verifier_data: &[u8],
    expected_journal_hash: B256,
) -> B256 {
    let callback_extra_data_hash = keccak256(callback_extra_data);
    let extra_verifier_data_hash = keccak256(extra_verifier_data);

    let mut encoded = Vec::with_capacity(288);
    encoded.extend_from_slice(program_id.as_slice());
    encoded.extend_from_slice(proof_system_id.as_slice());
    encoded.extend_from_slice(&address_to_word(callback_contract));
    encoded.extend_from_slice(&address_to_word(assigned_prover));
    encoded.extend_from_slice(tag.as_slice());
    encoded.extend_from_slice(input_data_hash.as_slice());
    encoded.extend_from_slice(callback_extra_data_hash.as_slice());
    encoded.extend_from_slice(extra_verifier_data_hash.as_slice());
    encoded.extend_from_slice(expected_journal_hash.as_slice());

    keccak256(&encoded)
}

/// Convert an address to a left-padded 32-byte word (abi.encode format).
fn address_to_word(addr: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(addr.as_slice());
    word
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn test_descriptor_hash_deterministic() {
        let program_id = B256::ZERO;
        let proof_system_id = keccak256("risczero.v1");
        let callback = address!("0000000000000000000000000000000000000001");
        let assigned_prover = Address::ZERO;
        let tag = B256::ZERO;
        let input_data = b"test input";
        let callback_extra = b"";
        let extra_verifier = b"";
        let expected_journal = B256::repeat_byte(0x99); // non-zero: exercise the 9th field

        let hash1 = compute_descriptor_hash(
            program_id,
            proof_system_id,
            callback,
            assigned_prover,
            tag,
            input_data,
            callback_extra,
            extra_verifier,
            expected_journal,
        );

        let hash2 = compute_descriptor_hash(
            program_id,
            proof_system_id,
            callback,
            assigned_prover,
            tag,
            input_data,
            callback_extra,
            extra_verifier,
            expected_journal,
        );

        assert_eq!(hash1, hash2);

        // A different expectedJournalHash must change the hash.
        let hash3 = compute_descriptor_hash(
            program_id,
            proof_system_id,
            callback,
            assigned_prover,
            tag,
            input_data,
            callback_extra,
            extra_verifier,
            B256::ZERO,
        );
        assert_ne!(hash1, hash3, "expectedJournalHash must affect the descriptor hash");
    }

    #[test]
    fn test_hashed_descriptor_matches() {
        let program_id = B256::ZERO;
        let proof_system_id = keccak256("risczero.v1");
        let callback = address!("0000000000000000000000000000000000000001");
        let assigned_prover = Address::ZERO;
        let tag = B256::ZERO;
        let input_data = b"test input";
        let callback_extra = b"";
        let extra_verifier = b"";
        let expected_journal = B256::ZERO;

        let hash_full = compute_descriptor_hash(
            program_id,
            proof_system_id,
            callback,
            assigned_prover,
            tag,
            input_data,
            callback_extra,
            extra_verifier,
            expected_journal,
        );

        let hash_hashed = compute_descriptor_hash_from_hashed(
            program_id,
            proof_system_id,
            callback,
            assigned_prover,
            tag,
            keccak256(input_data),
            callback_extra,
            extra_verifier,
            expected_journal,
        );

        assert_eq!(hash_full, hash_hashed);
    }
}
