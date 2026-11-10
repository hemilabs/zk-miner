//! JobDescriptor reconstruction from on-chain tx calldata.
//!
//! The full JobDescriptor (including inputData, callbackExtraData, extraVerifierData)
//! is not stored on-chain — only its keccak256 hash. To fulfill a job we need the full
//! descriptor, which we reconstruct by fetching the transaction that emitted the
//! JobSubmitted event and decoding its calldata.

use alloy::primitives::{keccak256, Address, Bytes, B256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolCall;
use anyhow::{bail, Context, Result};

use zkminer_contracts::bindings::{IHemiProveCore, JobDescriptor};

use crate::client::ChainClient;

/// A PERMANENT, deterministic reason a job's descriptor can never be reconstructed from its submit
/// transaction: the calldata's selector is not a known submit entry point (an integrator proxy /
/// multicall wrapper), or the calldata is too short to carry one. Unlike a transient fetch / RPC /
/// log-scan miss — which can heal on a later tick — this cannot change for a given job, because the
/// submit tx's calldata is immutable. Callers should NEGATIVE-CACHE the job on this error instead of
/// re-running the (up to `DEFAULT_DESCRIPTOR_LOOKBACK_BLOCKS`) descriptor scan + re-occupying a measure
/// slot for it every tick (a measure-budget + RPC DoS). It is produced only from decoding an
/// AUTHORITATIVE tx (the one the JobSubmitted-log scan locates, or a hash-verified fast-path tx), so a
/// stale cached tx cannot yield a false permanent verdict — a wrong-selector fast-path decode is
/// swallowed and retried via the scan.
#[derive(Debug, Clone)]
pub struct UndecodableDescriptor(pub String);

impl std::fmt::Display for UndecodableDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for UndecodableDescriptor {}

/// Default lookback window for JobSubmitted log queries, in blocks (floored at the deployment's
/// first block, `ChainClient::scan_from_block`). Hemi testnet produces 12-second blocks, so
/// 500_000 blocks ≈ 69 days — well beyond
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

/// Descriptor fetch with the monitor-cached submit-tx FAST PATH, verified
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
/// descriptor is unusable either way), so the descriptor the pre-claim predicate gate
/// relies on is always hash-checked.
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
    // The scan decoded the AUTHORITATIVE tx (the one whose JobSubmitted log names this jobId) and
    // the hash is a pure function of it, so a mismatch can never heal: type it permanent so the
    // caller negative-caches this jobId instead of re-scanning it every tick.
    verify_descriptor_hash(&d, expected_hash).map_err(|e| undecodable(format!("{e:#}")))?;
    Ok(d)
}

/// The descriptor of `job_id` from `tx_hash`, a transaction a caller names as the job's submit tx
/// (an indexer that saw the job's `JobSubmitted` log), checked first: the tx's receipt must hold the
/// router's `JobSubmitted` for `job_id`. One JobSubmitted is ever emitted per jobId, so that tx IS the
/// submit tx, and the descriptor is its calldata or nothing: calldata that does not decode, or whose
/// descriptor does not hash to `expected_hash`, is final ([`UndecodableDescriptor`]), with no log
/// scan behind it (the scan would find this same tx, after up to 500k blocks of `eth_getLogs`).
///
/// `Ok(None)`: the node knows no such tx, or its receipt holds no such log, so the hint says nothing
/// and the caller scans as usual. Any other `Err` is the RPC's.
pub async fn fetch_job_descriptor_from_submit_tx(
    client: &ChainClient,
    job_id: B256,
    tx_hash: B256,
    expected_hash: B256,
) -> Result<Option<JobDescriptor>> {
    // Raw JSON, as `decode_descriptor_from_tx` reads the tx: an L1 deposit (type 0x7E) does not
    // deserialize as an Ethereum receipt.
    let receipt: Option<serde_json::Value> = client
        .provider
        .raw_request("eth_getTransactionReceipt".into(), (tx_hash,))
        .await
        .context("Failed to fetch the submit tx's receipt")?;
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    if !receipt_emits_job_submitted(&receipt, client.hemi_prove, job_id) {
        return Ok(None);
    }
    let d = decode_descriptor_from_tx(client, job_id, tx_hash, Some(expected_hash)).await?;
    verify_descriptor_hash(&d, expected_hash).map_err(|e| undecodable(format!("{e:#}")))?;
    Ok(Some(d))
}

/// Whether a receipt (as the node's JSON) holds `router`'s `JobSubmitted` log for `job_id`.
fn receipt_emits_job_submitted(receipt: &serde_json::Value, router: Address, job_id: B256) -> bool {
    let topic0 = job_submitted_topic();
    receipt
        .get("logs")
        .and_then(|l| l.as_array())
        .is_some_and(|logs| {
            logs.iter().any(|log| {
                let from_router = log
                    .get("address")
                    .and_then(|a| a.as_str())
                    .and_then(|a| a.parse::<Address>().ok())
                    == Some(router);
                let removed = log.get("removed").and_then(|r| r.as_bool()) == Some(true);
                let topic = |i: usize| {
                    log.get("topics")
                        .and_then(|t| t.as_array())
                        .and_then(|t| t.get(i))
                        .and_then(|t| t.as_str())
                        .and_then(|t| t.parse::<B256>().ok())
                };
                from_router && !removed && topic(0) == Some(topic0) && topic(1) == Some(job_id)
            })
        })
}

/// A permanent decode verdict (see [`UndecodableDescriptor`]) as an `anyhow::Error`.
fn undecodable(msg: String) -> anyhow::Error {
    UndecodableDescriptor(msg).into()
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
    // Use the monitor-populated cached head instead of a fresh
    // eth_blockNumber. We only fetch a descriptor for a job we've already seen (claimed
    // or under recovery), whose JobSubmitted is necessarily mined and older than any
    // cached head — so the cached value always spans the submit block. Falls back to a
    // live read when the cache is cold (startup). Removes 1 request per descriptor fetch
    // from the claim burst window.
    let latest = client
        .head_block_cached()
        .await
        .context("Failed to get cached head block for descriptor lookup")?;
    // Floor at the deployment's first block: no HemiProve log exists below it, and a 500k-block
    // window at Hemi's 12-s blocks (~69 days) would otherwise reach far before the deployment.
    let from_block = latest
        .saturating_sub(lookback_blocks)
        .max(client.scan_from_block.min(latest));

    // 1. Find the JobSubmitted log for this job_id. jobId is topic1 (indexed).
    let filter = Filter::new()
        .address(client.hemi_prove)
        .event_signature(job_submitted_topic())
        .topic1(job_id)
        .from_block(from_block)
        .to_block(latest);

    // One query over the whole window first (the common case, cheap where the RPC allows it). An RPC
    // that caps the block range refuses it every time, so fall back to a chunked scan BACKWARDS from
    // the head, stopping at the first hit — otherwise a held lock's descriptor could never be rebuilt
    // there, and the lock could only be released.
    let logs = match client.provider.get_logs(&filter).await {
        Ok(l) => l,
        Err(e) => {
            tracing::debug!(
                "JobSubmitted scan {from_block}..={latest} refused ({e:#}) — retrying in chunks"
            );
            const CHUNK: u64 = 9000;
            let mut end = latest;
            loop {
                let start = end.saturating_sub(CHUNK - 1).max(from_block);
                let chunk = filter.clone().from_block(start).to_block(end);
                let l = client.provider.get_logs(&chunk).await.with_context(|| {
                    format!("Failed to query JobSubmitted logs for descriptor recovery (blocks {start}..={end})")
                })?;
                if !l.is_empty() || start == from_block {
                    break l;
                }
                end = start - 1;
            }
        }
    };

    let log = logs
        .first()
        .ok_or_else(|| anyhow::anyhow!("No JobSubmitted log found for job_id {}", job_id))?;

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
    // Fetch the submitting tx and extract its calldata — as RAW JSON, not through the typed
    // Ethereum-network response. Hemi is an OP Stack chain: a job can be submitted from L1 through a
    // deposit transaction (type 0x7E), which alloy's Ethereum `TxEnvelope` cannot deserialize. The
    // typed fetch then fails like a transport error, the job looks "transient" forever, and a few
    // such jobs priced above honest work hold every measure slot on every tick. Only `input` is
    // needed, and every tx type carries it.
    let raw: Option<serde_json::Value> = client
        .provider
        .raw_request("eth_getTransactionByHash".into(), (tx_hash,))
        .await
        .context("Failed to fetch submitting transaction")?;
    let raw = raw.ok_or_else(|| anyhow::anyhow!("Transaction {} not found", tx_hash))?;
    // The tx EXISTS (the node returned it); a missing or unparsable `input` cannot heal.
    let calldata: Bytes = raw
        .get("input")
        .and_then(|v: &serde_json::Value| v.as_str())
        .ok_or_else(|| undecodable(format!("submitting tx {tx_hash} carries no `input` field")))?
        .parse()
        .map_err(|e| undecodable(format!("submitting tx {tx_hash} has unparsable `input`: {e}")))?;
    let calldata = &calldata[..];
    if calldata.len() < 4 {
        // Deterministic & permanent: the authoritative submit tx's calldata cannot carry a selector,
        // so the descriptor can never be reconstructed. Typed so the caller negative-caches it.
        return Err(UndecodableDescriptor(format!(
            "Submitting tx calldata is too short: {} bytes",
            calldata.len()
        ))
        .into());
    }
    let selector: [u8; 4] = calldata[..4].try_into().unwrap();

    // 3. Decode the descriptor from whichever submit entry point was used. ALL of
    //    submitJob/submitJobDefault/submitJobSimple/submitJobBatch emit the same
    //    JobSubmitted event and create ordinary Open jobs, so recovery must handle every
    //    one — else a job submitted via a convenience entry point is claimed (collateral
    //    locked) but its descriptor can't be reconstructed → unfulfillable → strand. That
    //    is also a cheap griefing vector: a submitter can lock up a prover's collateral on
    //    a job it can never fulfill.
    // A recognised selector whose calldata does not decode is as permanent as an unknown one: the
    // calldata is immutable (typically a non-router contract exposing a same-selector function).
    let descriptor = if selector == IHemiProveCore::submitJobCall::SELECTOR {
        let decoded = IHemiProveCore::submitJobCall::abi_decode(calldata)
            .map_err(|e| undecodable(format!("submitJob calldata does not decode: {e}")))?;
        decoded.descriptor
    } else if selector == IHemiProveCore::submitJobSimpleCall::SELECTOR {
        let decoded = IHemiProveCore::submitJobSimpleCall::abi_decode(calldata)
            .map_err(|e| undecodable(format!("submitJobSimple calldata does not decode: {e}")))?;
        decoded.descriptor
    } else if selector == IHemiProveCore::submitJobBatchCall::SELECTOR {
        // A batch tx carries N descriptors; jobIds are index-derived and not recoverable
        // from calldata, so select the descriptor whose hash matches THIS job's on-chain
        // descriptorHash.
        let decoded = IHemiProveCore::submitJobBatchCall::abi_decode(calldata)
            .map_err(|e| undecodable(format!("submitJobBatch calldata does not decode: {e}")))?;
        // When the caller already holds the on-chain descriptorHash, use it to
        // select the descriptor without the extra getJobStatusView read.
        let want = match known_hash {
            Some(h) => h,
            None => {
                client
                    .get_job_status_view(job_id)
                    .await
                    .context(
                        "submitJobBatch: need on-chain descriptorHash to select the descriptor",
                    )?
                    .descriptorHash
            }
        };
        // `want` is the on-chain descriptorHash (caller-held or read from the chain), so no match in
        // this immutable calldata is permanent.
        decoded
            .descriptors
            .into_iter()
            .find(|d| compute_descriptor_hash(d) == want)
            .ok_or_else(|| {
                undecodable(format!(
                    "submitJobBatch: no descriptor in the batch matches job {job_id}'s hash {want}"
                ))
            })?
    } else if selector == IHemiProveCore::submitJobDefaultCall::SELECTOR {
        let decoded = IHemiProveCore::submitJobDefaultCall::abi_decode(calldata)
            .map_err(|e| undecodable(format!("submitJobDefault calldata does not decode: {e}")))?;
        // Mirrors HemiProveCore.submitJobDefault: zero assignedProver/tag, empty extra-data fields,
        // and the CALLER-SUPPLIED journal binding (both words). Every open-market job is FULL or
        // FIELDS bound, so the binding words are never implicitly zero here.
        JobDescriptor {
            programId: decoded.programId,
            proofSystemId: decoded.proofSystemId,
            callbackContract: decoded.callbackContract,
            assignedProver: Address::ZERO,
            tag: B256::ZERO,
            inputData: decoded.inputData,
            callbackExtraData: Bytes::new(),
            extraVerifierData: Bytes::new(),
            expectedJournalHash: decoded.expectedJournalHash,
            journalFields: decoded.journalFields,
        }
    } else {
        // Deterministic & permanent: the authoritative submit tx used an entry point we cannot decode
        // (an integrator proxy/multicall wrapper), so the descriptor can never be reconstructed for this
        // job. Typed (not a generic `bail!`) so the measure path negative-caches it instead of re-running
        // the block scan every tick. The selector is a property of the immutable submit tx calldata.
        return Err(UndecodableDescriptor(format!(
            "Unsupported submit selector 0x{} — job was not submitted via submitJob/submitJobSimple/submitJobBatch/submitJobDefault (likely an integrator proxy/multicall wrapper). Cannot reconstruct descriptor.",
            alloy::hex::encode(selector)
        ))
        .into());
    };

    Ok(descriptor)
}

/// Compute the descriptor hash matching the on-chain `_hashDescriptorFields` (HemiProveBase).
///
/// The Solidity implementation pre-hashes each `bytes` field before encoding:
/// ```solidity
/// keccak256(abi.encode(
///     programId, proofSystemId, callback, assignedProver, tag,
///     keccak256(inputData), keccak256(callbackExtraData), keccak256(extraVerifierData),
///     expectedJournalHash, journalFields  // slots 9 and 10, raw bytes32
/// ))
/// ```
///
/// This is NOT the same as `keccak256(abi.encode(descriptor))` because `abi.encode`
/// for a struct with `bytes` fields uses head+tail encoding, not pre-hashing.
pub fn compute_descriptor_hash(descriptor: &JobDescriptor) -> B256 {
    let input_data_hash = keccak256(&descriptor.inputData);
    let callback_extra_data_hash = keccak256(&descriptor.callbackExtraData);
    let extra_verifier_data_hash = keccak256(&descriptor.extraVerifierData);

    // 10 words × 32 bytes = 320 bytes, matching abi.encode of 10 fixed-size values
    let mut encoded = Vec::with_capacity(320);
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
    // bytes32 expectedJournalHash and bytes32 journalFields (raw, NOT pre-hashed)
    encoded.extend_from_slice(descriptor.expectedJournalHash.as_slice());
    encoded.extend_from_slice(descriptor.journalFields.as_slice());

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
    fn undecodable_descriptor_is_downcastable_through_anyhow() {
        // The measure path (run.rs) distinguishes a PERMANENT undecodable-selector decode failure
        // from a transient fetch error by `downcast_ref::<UndecodableDescriptor>()` on the propagated
        // anyhow::Error, and negative-caches only on the permanent one. Guard that contract: the typed
        // error must survive the `.into()` + `?` propagation used on the authoritative scan path.
        let err: anyhow::Error = UndecodableDescriptor("Unsupported submit selector 0xdeadbeef".into()).into();
        let got = err.downcast_ref::<UndecodableDescriptor>();
        assert!(got.is_some(), "UndecodableDescriptor must downcast through anyhow");
        assert!(
            format!("{err:#}").contains("Unsupported submit selector"),
            "the message must be preserved for the sanitized log"
        );
        // A generic transient error must NOT masquerade as the permanent verdict.
        let transient: anyhow::Error = anyhow::anyhow!("Failed to fetch submitting transaction");
        assert!(
            transient.downcast_ref::<UndecodableDescriptor>().is_none(),
            "a transient fetch error must not be treated as permanently undecodable"
        );
    }

    /// A submit-tx hint is taken as the submit tx only when its receipt holds the router's
    /// JobSubmitted for this very job: another job's, another contract's, another event's, or a
    /// removed log says nothing.
    #[test]
    fn only_the_routers_job_submitted_for_the_job_makes_a_hint_the_submit_tx() {
        let router: Address = "0x00000000000000000000000000000000000000a1".parse().unwrap();
        let job = B256::repeat_byte(0x22);
        let log = |address: Address, topic0: B256, topic1: B256, removed: bool| {
            serde_json::json!({
                "address": address.to_string(),
                "topics": [topic0.to_string(), topic1.to_string(), B256::ZERO.to_string()],
                "removed": removed,
            })
        };
        let receipt = |logs: Vec<serde_json::Value>| serde_json::json!({ "status": "0x1", "logs": logs });
        let t = job_submitted_topic();
        let other: Address = "0x00000000000000000000000000000000000000b2".parse().unwrap();
        assert!(receipt_emits_job_submitted(&receipt(vec![log(router, t, job, false)]), router, job));
        // Beside other logs, in any position.
        assert!(receipt_emits_job_submitted(
            &receipt(vec![log(other, t, job, false), log(router, t, job, false)]),
            router,
            job
        ));
        for wrong in [
            log(other, t, job, false),
            log(router, keccak256("Other()"), job, false),
            log(router, t, B256::repeat_byte(0x33), false),
            log(router, t, job, true),
        ] {
            assert!(!receipt_emits_job_submitted(&receipt(vec![wrong.clone()]), router, job), "{wrong}");
        }
        assert!(!receipt_emits_job_submitted(&receipt(vec![]), router, job));
        assert!(!receipt_emits_job_submitted(&serde_json::json!({}), router, job));
        // Address case does not matter (nodes answer lower case; a checksum parses the same).
        let mut upper = log(router, t, job, false);
        upper["address"] = serde_json::json!("0x00000000000000000000000000000000000000A1");
        assert!(receipt_emits_job_submitted(&receipt(vec![upper]), router, job));
    }

    #[test]
    fn topic_matches_canonical_signature() {
        let t = job_submitted_topic();
        let expected = keccak256(
            "JobSubmitted(bytes32,bytes32,address,bytes32,bytes32,uint96,uint96,uint96,uint40,uint8)",
        );
        assert_eq!(t, expected);
    }

    /// Descriptor with every field set to a distinct value (journalFields included).
    fn full_descriptor() -> JobDescriptor {
        JobDescriptor {
            programId: B256::repeat_byte(0x42),
            proofSystemId: keccak256("risczero.groth16.v1"),
            callbackContract: Address::repeat_byte(0xAB),
            assignedProver: Address::repeat_byte(0xCD),
            tag: B256::repeat_byte(0xEF),
            inputData: Bytes::from_static(b"hello world"),
            callbackExtraData: Bytes::from_static(b"cb-extra"),
            extraVerifierData: Bytes::from_static(b"vx"),
            expectedJournalHash: B256::repeat_byte(0x33),
            journalFields: B256::repeat_byte(0x55),
        }
    }

    #[test]
    fn descriptor_hash_prehashes_bytes_fields() {
        // With non-empty inputData, the hash must NOT equal naive abi.encode(struct).
        let d = full_descriptor();
        let correct_hash = compute_descriptor_hash(&d);
        let naive_hash = keccak256(d.abi_encode());
        assert_ne!(
            correct_hash, naive_hash,
            "descriptor hash should NOT equal naive abi.encode — bytes fields must be pre-hashed"
        );
        assert!(verify_descriptor_hash(&d, correct_hash).is_ok());
        assert!(verify_descriptor_hash(&d, naive_hash).is_err());
    }

    #[test]
    fn descriptor_hash_covers_both_binding_words() {
        // journalFields is the 10th hashed word: a job differing ONLY in it (or only in
        // expectedJournalHash) has a different descriptorHash, so the binding is pinned by the hash.
        let d = full_descriptor();
        let mut other_fields = d.clone();
        other_fields.journalFields = B256::repeat_byte(0x56);
        assert_ne!(compute_descriptor_hash(&d), compute_descriptor_hash(&other_fields));
        let mut other_ejh = d.clone();
        other_ejh.expectedJournalHash = B256::repeat_byte(0x34);
        assert_ne!(compute_descriptor_hash(&d), compute_descriptor_hash(&other_ejh));
    }

    #[test]
    fn descriptor_hash_matches_prover_crate() {
        // Cross-validate with the zkminer_prover descriptor hash implementation.
        let d = full_descriptor();
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
            d.journalFields,
        );
        assert_eq!(
            our_hash, prover_hash,
            "chain descriptor hash must match prover crate's implementation"
        );
    }

    #[test]
    fn descriptor_hash_matches_independent_tuple_encoding() {
        // Independent reference: alloy's tuple `abi_encode` of the 10 fixed-size words (Solidity's
        // `abi.encode(...)` for those types), NOT going through the sol!-generated struct path.
        let d = full_descriptor();
        let reference_tuple = (
            d.programId,
            d.proofSystemId,
            d.callbackContract,
            d.assignedProver,
            d.tag,
            keccak256(&d.inputData),
            keccak256(&d.callbackExtraData),
            keccak256(&d.extraVerifierData),
            d.expectedJournalHash,
            d.journalFields,
        );
        let reference_encoded = reference_tuple.abi_encode();
        assert_eq!(reference_encoded.len(), 320, "abi.encode of 10 fixed-size values is 320 bytes");
        assert_eq!(compute_descriptor_hash(&d), keccak256(&reference_encoded));
    }

    /// The c8333aa Solidity test suite's pinned vector (test/utils/SP1PlonkNonceScenario.sol, asserted
    /// in test/integration/SP1PlonkProofs.t.sol `test_scenario_pinnedDerivations`): an SP1 PLONK job
    /// with a FULL expectedJournalHash AND the proof-nonce marker in journalFields slot 0. The
    /// expected values were produced by the deployed contracts' own code (and re-derived independently
    /// with Foundry's `cast abi-encode`), so this anchors zkminer to the CONTRACT, not to itself.
    #[test]
    fn descriptor_hash_matches_the_contract_suites_pinned_vector() {
        let vkey: B256 = "0x00122a038d1d9663aa5bd7cbd78d74f71c5e878ed253458363d8cb3ea9dafe7f"
            .parse()
            .unwrap();
        let journal = alloy::hex::decode(
            "48656d6950726f766520535031206e6f6e636520666978747572652076310000",
        )
        .unwrap();
        let sp1_plonk_v1 = keccak256("sp1.plonk.v1");
        let domain = keccak256("HemiProve.JournalPredicate.v1");
        assert_eq!(
            format!("{domain:x}"),
            "8fc1eec9ac3fed1ebf9116804d90a1da182248d5fcdc1edcc673416bf4231898"
        );
        // FULL hash = keccak256(abi.encode(DOMAIN, proofSystemId, programId, bytes publicValues)):
        // Solidity's abi.encode of a parameter LIST (abi_encode_params), not a wrapped tuple.
        let ejh = keccak256(
            (domain, sp1_plonk_v1, vkey, Bytes::from(journal.clone())).abi_encode_params(),
        );
        assert_eq!(
            format!("{ejh:x}"),
            "e677a15afce77fc76392d113eec364ff86ff836617a5c6da8f79aec1163bd6b5",
            "FULL expectedJournalHash (cast-derived)"
        );
        let mut nonce_marker = [0u8; 32];
        nonce_marker[..4].copy_from_slice(&[0xff, 0xff, 0xff, 0xfe]);
        let d = JobDescriptor {
            programId: vkey,
            proofSystemId: sp1_plonk_v1,
            callbackContract: Address::ZERO,
            assignedProver: Address::ZERO,
            tag: B256::ZERO,
            inputData: Bytes::from(journal),
            callbackExtraData: Bytes::new(),
            extraVerifierData: Bytes::new(),
            expectedJournalHash: ejh,
            journalFields: B256::from(nonce_marker),
        };
        let h = compute_descriptor_hash(&d);
        assert_eq!(
            format!("{h:x}"),
            "fac3c0e8c040b047fb89ef5ac44c4a760a3a5806f8150e46b08f74f74b160fd0",
            "descriptorHash pinned by the contract test suite"
        );
        // jobId = keccak256(abi.encode(chainid, router, uint48 jobIndex, descriptorHash)).
        let router: Address = "0xC353289ef20D8846Fd7cf3c50111a16f06C3CbC7".parse().unwrap();
        let job_id = keccak256(
            (
                alloy::primitives::U256::from(743111u64),
                router,
                alloy::primitives::aliases::U48::from(0u64),
                h,
            )
                .abi_encode(),
        );
        assert_eq!(
            format!("{job_id:x}"),
            "d7410d92ac26dbf8270be9f4d856510a7ca693de9cb94fec10fa6ccffa101ca8",
            "jobId pinned by the contract test suite"
        );
    }
}
