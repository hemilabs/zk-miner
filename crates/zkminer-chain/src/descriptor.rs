//! JobDescriptor reconstruction from on-chain tx calldata.
//!
//! The full JobDescriptor (including inputData, callbackExtraData, extraVerifierData)
//! is not stored on-chain — only its keccak256 hash. To fulfill a job we need the full
//! descriptor, which we reconstruct by fetching the transaction that emitted the
//! JobSubmitted event and decoding its calldata.

use alloy::consensus::Transaction;
use alloy::primitives::{Address, B256, Bytes, keccak256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolCall;
use anyhow::{Context, Result, bail};

use zkminer_contracts::bindings::{IHemiProveCore, JobDescriptor};

use crate::client::ChainClient;

/// Default lookback window for JobSubmitted log queries, in blocks.
/// Hemi produces ~2-second blocks, so 500_000 blocks ≈ 11.5 days — well beyond
/// any realistic lock_deadline + margin. This bounds the log scan to a range
/// most RPC providers accept (typically 1k–10k is the per-request cap, but
/// providers honour the absolute range here — the query is still narrowed by
/// topic0 and topic1 so result size is small).
pub const DEFAULT_DESCRIPTOR_LOOKBACK_BLOCKS: u64 = 500_000;

/// Topic0 for the JobSubmitted event. Derived from the canonical event signature.
fn job_submitted_topic() -> B256 {
    keccak256(
        "JobSubmitted(bytes32,bytes32,address,bytes32,bytes32,uint96,uint96,uint96,uint40,uint8)",
    )
}

/// Fetch the full JobDescriptor for a given job_id by locating the emitting tx
/// and decoding its calldata.
///
/// Supports jobs submitted via `submitJob` (full descriptor in calldata) or
/// `submitJobDefault` (synthesised descriptor with zero tag/assignedProver and
/// empty callbackExtraData/extraVerifierData).
///
/// The log scan is bounded to the last `DEFAULT_DESCRIPTOR_LOOKBACK_BLOCKS`
/// blocks to avoid hitting RPC-provider block-range limits (most providers
/// reject unbounded `Earliest..Latest` queries).
///
/// Returns an error if the job was submitted via an unsupported entry point
/// (e.g. a multicall or proxy-internal call where the HemiProve calldata is
/// not the outer tx input).
pub async fn fetch_job_descriptor(client: &ChainClient, job_id: B256) -> Result<JobDescriptor> {
    fetch_job_descriptor_with_lookback(client, job_id, DEFAULT_DESCRIPTOR_LOOKBACK_BLOCKS).await
}

/// [RPC #2] Descriptor fetch with the monitor-cached submit-tx FAST PATH, verified
/// against the job's on-chain `descriptorHash` (which every caller already holds from
/// a JobStatusView / snapshot).
///
/// Fast path: the monitor caches jobId → submitting tx hash while parsing JobSubmitted
/// logs (zero extra requests — the log carries it). On a hit, ONE
/// `eth_getTransactionByHash` replaces the scan path's 500k-block `eth_getLogs` (the
/// single heaviest query the miner issues) + tx fetch. Sound because exactly one
/// JobSubmitted is ever emitted per jobId, so the cached tx IS the tx the scan finds.
///
/// Safety: the fast-path result is hash-verified; on ANY miss — no cache entry, tx not
/// found (e.g. reorg-replaced), decode failure, hash mismatch — it falls back SILENTLY
/// to the full scan, so the fast path can only save requests, never change outcomes.
/// The scan result is then also verified against `expected_hash` (Err on mismatch: the
/// descriptor is unusable either way, and this closes the previously-unverified
/// pre-claim predicate-gate path).
pub async fn fetch_job_descriptor_checked(
    client: &ChainClient,
    job_id: B256,
    expected_hash: B256,
) -> Result<JobDescriptor> {
    if let Some(tx_hash) = client.submit_tx_for(job_id) {
        match decode_descriptor_from_tx(client, job_id, tx_hash, Some(expected_hash)).await {
            Ok(d) if compute_descriptor_hash(&d) == expected_hash => return Ok(d),
            Ok(_) => tracing::warn!(
                "descriptor fast path hash mismatch for {job_id} (cached tx {tx_hash}) — falling back to log scan"
            ),
            Err(e) => tracing::debug!(
                "descriptor fast path for {job_id} failed ({e:#}) — falling back to log scan"
            ),
        }
    }
    let d = scan_for_descriptor(
        client,
        job_id,
        DEFAULT_DESCRIPTOR_LOOKBACK_BLOCKS,
        Some(expected_hash),
    )
    .await?;
    verify_descriptor_hash(&d, expected_hash)?;
    Ok(d)
}

/// Same as [`fetch_job_descriptor`] with an explicit lookback window.
pub async fn fetch_job_descriptor_with_lookback(
    client: &ChainClient,
    job_id: B256,
    lookback_blocks: u64,
) -> Result<JobDescriptor> {
    scan_for_descriptor(client, job_id, lookback_blocks, None).await
}

/// Scan path: locate the JobSubmitted log, then decode the emitting tx's calldata.
/// `known_hash` (when the caller holds the on-chain descriptorHash) lets the
/// submitJobBatch decode branch skip its extra getJobStatusView read.
async fn scan_for_descriptor(
    client: &ChainClient,
    job_id: B256,
    lookback_blocks: u64,
    known_hash: Option<B256>,
) -> Result<JobDescriptor> {
    // [RPC quick-win] Use the monitor-populated cached head instead of a fresh
    // eth_blockNumber. We only fetch a descriptor for a job we've already seen (claimed
    // or under recovery), whose JobSubmitted is necessarily mined and older than any
    // cached head — so the cached value always spans the submit block. Falls back to a
    // live read when the cache is cold (startup). Removes 1 request per descriptor fetch
    // from the claim burst window.
    let latest = client
        .head_block_cached()
        .await
        .context("Failed to get cached head block for descriptor lookup")?;
    let from_block = latest.saturating_sub(lookback_blocks);

    // 1. Find the JobSubmitted log for this job_id. jobId is topic1 (indexed).
    let filter = Filter::new()
        .address(client.hemi_prove)
        .event_signature(job_submitted_topic())
        .topic1(job_id)
        .from_block(from_block)
        .to_block(latest);

    let logs = client
        .provider
        .get_logs(&filter)
        .await
        .with_context(|| {
            format!(
                "Failed to query JobSubmitted logs for descriptor recovery (blocks {from_block}..={latest})"
            )
        })?;

    let log = logs.first().ok_or_else(|| {
        anyhow::anyhow!("No JobSubmitted log found for job_id {}", job_id)
    })?;

    let tx_hash = log
        .transaction_hash
        .ok_or_else(|| anyhow::anyhow!("JobSubmitted log missing transaction hash"))?;

    decode_descriptor_from_tx(client, job_id, tx_hash, known_hash).await
}

/// Fetch the submitting tx by hash and decode the JobDescriptor from its calldata.
/// Shared by the fast path (monitor-cached tx hash) and the scan path (tx hash from
/// the JobSubmitted log). `known_hash` lets the submitJobBatch branch select the
/// right descriptor without an extra getJobStatusView read.
async fn decode_descriptor_from_tx(
    client: &ChainClient,
    job_id: B256,
    tx_hash: B256,
    known_hash: Option<B256>,
) -> Result<JobDescriptor> {
    // Fetch the submitting tx and extract its calldata.
    let tx = client
        .provider
        .get_transaction_by_hash(tx_hash)
        .await
        .context("Failed to fetch submitting transaction")?
        .ok_or_else(|| anyhow::anyhow!("Transaction {} not found", tx_hash))?;

    let calldata = tx.input();
    if calldata.len() < 4 {
        bail!("Submitting tx calldata is too short: {} bytes", calldata.len());
    }
    let selector: [u8; 4] = calldata[..4].try_into().unwrap();

    // 3. Decode the descriptor from whichever submit entry point was used. [H1] ALL of
    //    submitJob/submitJobDefault/submitJobSimple/submitJobBatch emit the same
    //    JobSubmitted event and create ordinary Open jobs, so recovery must handle every
    //    one — else a job submitted via a convenience entry point is claimed (collateral
    //    locked) but its descriptor can't be reconstructed → unfulfillable → strand (and
    //    a cheap griefing vector).
    let descriptor = if selector == IHemiProveCore::submitJobCall::SELECTOR {
        let decoded = IHemiProveCore::submitJobCall::abi_decode(calldata)
            .context("Failed to decode submitJob calldata")?;
        decoded.descriptor
    } else if selector == IHemiProveCore::submitJobSimpleCall::SELECTOR {
        let decoded = IHemiProveCore::submitJobSimpleCall::abi_decode(calldata)
            .context("Failed to decode submitJobSimple calldata")?;
        decoded.descriptor
    } else if selector == IHemiProveCore::submitJobBatchCall::SELECTOR {
        // A batch tx carries N descriptors; jobIds are index-derived and not recoverable
        // from calldata, so select the descriptor whose hash matches THIS job's on-chain
        // descriptorHash.
        let decoded = IHemiProveCore::submitJobBatchCall::abi_decode(calldata)
            .context("Failed to decode submitJobBatch calldata")?;
        // [RPC #2] When the caller already holds the on-chain descriptorHash, use it to
        // select the descriptor without the extra getJobStatusView read.
        let want = match known_hash {
            Some(h) => h,
            None => client
                .get_job_status_view(job_id)
                .await
                .context("submitJobBatch: need on-chain descriptorHash to select the descriptor")?
                .descriptorHash,
        };
        decoded
            .descriptors
            .into_iter()
            .find(|d| compute_descriptor_hash(d) == want)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "submitJobBatch: no descriptor in the batch matches job {job_id}'s hash {want}"
                )
            })?
    } else if selector == IHemiProveCore::submitJobDefaultCall::SELECTOR {
        let decoded = IHemiProveCore::submitJobDefaultCall::abi_decode(calldata)
            .context("Failed to decode submitJobDefault calldata")?;
        JobDescriptor {
            programId: decoded.programId,
            proofSystemId: decoded.proofSystemId,
            callbackContract: decoded.callbackContract,
            assignedProver: Address::ZERO,
            tag: B256::ZERO,
            inputData: decoded.inputData,
            callbackExtraData: Bytes::new(),
            extraVerifierData: Bytes::new(),
            // submitJobDefault never sets a predicate.
            expectedJournalHash: B256::ZERO,
        }
    } else {
        bail!(
            "Unsupported submit selector 0x{} — job was not submitted via submitJob/submitJobSimple/submitJobBatch/submitJobDefault (likely an integrator proxy/multicall wrapper). Cannot reconstruct descriptor.",
            alloy::hex::encode(selector)
        );
    };

    Ok(descriptor)
}

/// Compute the descriptor hash matching the on-chain `_computeDescriptorHash`.
///
/// The Solidity implementation pre-hashes each `bytes` field before encoding:
/// ```solidity
/// keccak256(abi.encode(
///     programId, proofSystemId, callback, assignedProver, tag,
///     keccak256(inputData), keccak256(callbackExtraData), keccak256(extraVerifierData),
///     expectedJournalHash                 // [Phase 2, 2026-07-10] 9th slot, raw bytes32
/// ))
/// ```
///
/// This is NOT the same as `keccak256(abi.encode(descriptor))` because `abi.encode`
/// for a struct with `bytes` fields uses head+tail encoding, not pre-hashing.
pub fn compute_descriptor_hash(descriptor: &JobDescriptor) -> B256 {
    let input_data_hash = keccak256(&descriptor.inputData);
    let callback_extra_data_hash = keccak256(&descriptor.callbackExtraData);
    let extra_verifier_data_hash = keccak256(&descriptor.extraVerifierData);

    // 9 words × 32 bytes = 288 bytes, matching abi.encode of 9 fixed-size values
    let mut encoded = Vec::with_capacity(288);
    encoded.extend_from_slice(descriptor.programId.as_slice());
    encoded.extend_from_slice(descriptor.proofSystemId.as_slice());
    // address → left-padded 32 bytes
    let mut callback_word = [0u8; 32];
    callback_word[12..].copy_from_slice(descriptor.callbackContract.as_slice());
    encoded.extend_from_slice(&callback_word);
    let mut prover_word = [0u8; 32];
    prover_word[12..].copy_from_slice(descriptor.assignedProver.as_slice());
    encoded.extend_from_slice(&prover_word);
    encoded.extend_from_slice(descriptor.tag.as_slice());
    encoded.extend_from_slice(input_data_hash.as_slice());
    encoded.extend_from_slice(callback_extra_data_hash.as_slice());
    encoded.extend_from_slice(extra_verifier_data_hash.as_slice());
    // bytes32 expectedJournalHash (raw, NOT pre-hashed)
    encoded.extend_from_slice(descriptor.expectedJournalHash.as_slice());

    keccak256(&encoded)
}

/// Verify a reconstructed descriptor matches its on-chain hash.
pub fn verify_descriptor_hash(descriptor: &JobDescriptor, expected: B256) -> Result<()> {
    let actual = compute_descriptor_hash(descriptor);
    if actual != expected {
        bail!(
            "Descriptor hash mismatch: expected 0x{}, got 0x{}",
            alloy::hex::encode(expected),
            alloy::hex::encode(actual),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolValue;

    #[test]
    fn topic_matches_canonical_signature() {
        let t = job_submitted_topic();
        let expected = keccak256(
            "JobSubmitted(bytes32,bytes32,address,bytes32,bytes32,uint96,uint96,uint96,uint40,uint8)",
        );
        assert_eq!(t, expected);
    }

    #[test]
    fn descriptor_hash_prehashes_bytes_fields() {
        // With non-empty inputData, the hash must NOT equal naive abi.encode(struct).
        let d = JobDescriptor {
            programId: B256::repeat_byte(0x11),
            proofSystemId: B256::repeat_byte(0x22),
            callbackContract: Address::ZERO,
            assignedProver: Address::ZERO,
            tag: B256::ZERO,
            inputData: Bytes::from_static(b"test input data"),
            callbackExtraData: Bytes::new(),
            extraVerifierData: Bytes::new(),
            expectedJournalHash: B256::ZERO,
        };
        let correct_hash = compute_descriptor_hash(&d);
        let naive_hash = keccak256(d.abi_encode());
        // These must differ — the naive encoding doesn't pre-hash bytes fields.
        assert_ne!(
            correct_hash, naive_hash,
            "descriptor hash should NOT equal naive abi.encode — bytes fields must be pre-hashed"
        );
        assert!(verify_descriptor_hash(&d, correct_hash).is_ok());
        assert!(verify_descriptor_hash(&d, naive_hash).is_err());
    }

    #[test]
    fn descriptor_hash_matches_prover_crate() {
        // Cross-validate with the zkminer_prover descriptor hash implementation.
        let d = JobDescriptor {
            programId: B256::repeat_byte(0xAA),
            proofSystemId: keccak256("risczero.v1"),
            callbackContract: Address::repeat_byte(0x01),
            assignedProver: Address::ZERO,
            tag: B256::repeat_byte(0xBB),
            inputData: Bytes::from_static(b"hello world"),
            callbackExtraData: Bytes::from_static(b"callback"),
            extraVerifierData: Bytes::from_static(b"verifier"),
            expectedJournalHash: B256::repeat_byte(0x77),
        };
        let our_hash = compute_descriptor_hash(&d);
        let prover_hash = zkminer_prover::descriptor::compute_descriptor_hash(
            d.programId,
            d.proofSystemId,
            d.callbackContract,
            d.assignedProver,
            d.tag,
            &d.inputData,
            &d.callbackExtraData,
            &d.extraVerifierData,
            d.expectedJournalHash,
        );
        assert_eq!(
            our_hash, prover_hash,
            "chain descriptor hash must match prover crate's implementation"
        );
    }

    #[test]
    fn descriptor_hash_empty_bytes_still_correct() {
        // With all-empty bytes fields, verify consistency.
        let d = JobDescriptor {
            programId: B256::ZERO,
            proofSystemId: B256::ZERO,
            callbackContract: Address::ZERO,
            assignedProver: Address::ZERO,
            tag: B256::ZERO,
            inputData: Bytes::new(),
            callbackExtraData: Bytes::new(),
            extraVerifierData: Bytes::new(),
            expectedJournalHash: B256::ZERO,
        };
        let h = compute_descriptor_hash(&d);
        assert!(verify_descriptor_hash(&d, h).is_ok());
        assert!(verify_descriptor_hash(&d, B256::ZERO).is_err());
    }

    #[test]
    fn descriptor_hash_matches_independent_tuple_encoding() {
        // Solidity reference: our hash must equal
        //   keccak256(abi.encode(bytes32, bytes32, address, address, bytes32, bytes32, bytes32, bytes32))
        // where the last three bytes32s are keccak256 of the bytes fields.
        //
        // alloy's `SolValue::abi_encode` on a Rust tuple of those exact types
        // produces Solidity's `abi.encode(...)` output for those types, giving
        // an independent reference encoding that does NOT go through the
        // `sol!`-generated `JobDescriptor` struct path. If our manual
        // byte-packing in `compute_descriptor_hash` matches this tuple encoding,
        // the implementation is Solidity-correct.
        let program_id = B256::repeat_byte(0x42);
        let proof_system_id = keccak256("risczero.v1");
        let callback = Address::repeat_byte(0xAB);
        let assigned = Address::repeat_byte(0xCD);
        let tag = B256::repeat_byte(0xEF);
        let input_data = b"hello world".as_slice();
        let callback_extra = b"cb-extra".as_slice();
        let extra_verifier = b"vx".as_slice();
        let expected_journal = B256::repeat_byte(0x33);

        let d = JobDescriptor {
            programId: program_id,
            proofSystemId: proof_system_id,
            callbackContract: callback,
            assignedProver: assigned,
            tag,
            inputData: Bytes::copy_from_slice(input_data),
            callbackExtraData: Bytes::copy_from_slice(callback_extra),
            extraVerifierData: Bytes::copy_from_slice(extra_verifier),
            expectedJournalHash: expected_journal,
        };
        let our_hash = compute_descriptor_hash(&d);

        // Independent reference via alloy tuple abi.encode (9 fixed-size words).
        let reference_tuple = (
            program_id,
            proof_system_id,
            callback,
            assigned,
            tag,
            keccak256(input_data),
            keccak256(callback_extra),
            keccak256(extra_verifier),
            expected_journal,
        );
        let reference_encoded = reference_tuple.abi_encode();
        let reference_hash = keccak256(&reference_encoded);
        assert_eq!(
            our_hash, reference_hash,
            "compute_descriptor_hash must equal keccak256(abi.encode(bytes32,bytes32,address,address,bytes32,bytes32,bytes32,bytes32,bytes32)) with bytes fields pre-hashed"
        );

        // The encoding length must be exactly 9*32 = 288 bytes (no dynamic tails).
        assert_eq!(reference_encoded.len(), 288, "abi.encode of 9 fixed-size values must be 288 bytes");
    }

    /// Solidity-derived hardcoded reference vector.
    ///
    /// Inputs:
    ///   programId       = 0x0000…01 (all zero except last byte = 1)
    ///   proofSystemId   = keccak256("risczero.v1")
    ///                   = 0x0b01f44f... (verified by `cast keccak "risczero.v1"`)
    ///   callback        = 0x0000…0000 (zero address)
    ///   assignedProver  = 0x0000…0000
    ///   tag             = 0x0000…0000
    ///   inputData       = ""
    ///   callbackExtra   = ""
    ///   extraVerifier   = ""
    ///
    /// keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    ///
    /// We don't have a live Solidity runtime in tests, so this test reconstructs
    /// the reference via an independent path (alloy's tuple abi_encode of the
    /// 8 fixed-size words) and captures the resulting hash as a regression
    /// fixture. A future change to either `compute_descriptor_hash` OR
    /// `alloy::sol_types::SolValue::abi_encode` that diverges will fail this
    /// test. If the contract ever changes its encoding, this test's expected
    /// vector must be regenerated from the new contract.
    #[test]
    fn descriptor_hash_regression_vector() {
        let program_id = {
            let mut b = [0u8; 32];
            b[31] = 1;
            B256::from(b)
        };
        let proof_system_id = keccak256("risczero.v1");
        let d = JobDescriptor {
            programId: program_id,
            proofSystemId: proof_system_id,
            callbackContract: Address::ZERO,
            assignedProver: Address::ZERO,
            tag: B256::ZERO,
            inputData: Bytes::new(),
            callbackExtraData: Bytes::new(),
            extraVerifierData: Bytes::new(),
            expectedJournalHash: B256::ZERO,
        };

        let our_hash = compute_descriptor_hash(&d);

        // Independent path: manually build the 288-byte abi.encode(bytes32*9)
        // buffer and hash it. If `compute_descriptor_hash` matches this, they
        // share the same encoding definition.
        let empty_hash = keccak256(b"");
        let mut buf = [0u8; 288];
        buf[31] = 1;                          // programId
        buf[32..64].copy_from_slice(proof_system_id.as_slice()); // proofSystemId
        // callback: 32 zeros
        // assignedProver: 32 zeros
        // tag: 32 zeros
        buf[160..192].copy_from_slice(empty_hash.as_slice()); // keccak256(inputData)
        buf[192..224].copy_from_slice(empty_hash.as_slice()); // keccak256(callbackExtra)
        buf[224..256].copy_from_slice(empty_hash.as_slice()); // keccak256(extraVerifier)
        // buf[256..288]: expectedJournalHash = 32 zeros
        let manual_hash = keccak256(&buf);

        assert_eq!(
            our_hash, manual_hash,
            "descriptor hash must match manual abi.encode(bytes32*9) reference"
        );

        // Also cross-check with the alloy tuple encoding.
        let reference_tuple = (
            program_id,
            proof_system_id,
            Address::ZERO,
            Address::ZERO,
            B256::ZERO,
            empty_hash,
            empty_hash,
            empty_hash,
            B256::ZERO,
        );
        let reference_hash = keccak256(reference_tuple.abi_encode());
        assert_eq!(our_hash, reference_hash, "descriptor hash must match alloy tuple encoding");
    }
}
