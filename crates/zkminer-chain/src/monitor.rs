use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use anyhow::Result;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};

use crate::client::ChainClient;

/// Events emitted by the job monitor.
#[derive(Debug, Clone)]
pub enum MonitorEvent {
    /// A new job was submitted targeting RISC Zero.
    JobSubmitted {
        job_id: B256,
        proof_system_id: B256,
        caller: Address,
        program_id: B256,
        descriptor_hash: B256,
        deposited_amount: u128,
        min_price: u128,
        max_price: u128,
        fulfillment_timeout: u64,
    },
    /// A job was claimed.
    JobClaimed {
        job_id: B256,
        prover: Address,
        settled_price: u128,
        lock_deadline: u64,
    },
    /// A job was fulfilled.
    JobFulfilled {
        job_id: B256,
        prover: Address,
        payout: u128,
    },
    /// A job was released.
    JobReleased {
        job_id: B256,
        prover: Address,
        penalty: u128,
    },
    /// A job was reopened (prover slashed).
    JobReopened {
        job_id: B256,
        slashed_prover: Address,
        slashed_amount: u128,
    },
    /// A job was cancelled by its submitter (terminal — prover stays ZERO, so a
    /// per-tick prover check alone never evicts it from the candidate set).
    JobCancelled { job_id: B256, caller: Address },
    /// Monitor error (non-fatal).
    Error(String),
}

// Canonical topic0 hashes (see HemiProveBase.sol; VerifierTrust enum = uint8). Computed
// once — parse_monitor_log compares against these for every log. Test-pinned against the
// bindings' SolEvent::SIGNATURE_HASH so signature drift fails CI instead of silently
// ignoring the event class.
static JOB_SUBMITTED_TOPIC0: std::sync::LazyLock<B256> = std::sync::LazyLock::new(|| {
    alloy::primitives::keccak256(
        "JobSubmitted(bytes32,bytes32,address,bytes32,bytes32,uint96,uint96,uint96,uint40,uint8)",
    )
});
static JOB_CLAIMED_TOPIC0: std::sync::LazyLock<B256> = std::sync::LazyLock::new(|| {
    alloy::primitives::keccak256("JobClaimed(bytes32,address,address,uint96,uint96,uint40)")
});
static JOB_CANCELLED_TOPIC0: std::sync::LazyLock<B256> = std::sync::LazyLock::new(|| {
    alloy::primitives::keccak256("JobCancelled(bytes32,address,uint256,bool)")
});

/// Canonical topic0 for JobSubmitted.
pub(crate) fn job_submitted_topic0() -> B256 {
    *JOB_SUBMITTED_TOPIC0
}

/// Canonical topic0 for JobClaimed.
pub(crate) fn job_claimed_topic0() -> B256 {
    *JOB_CLAIMED_TOPIC0
}

/// Canonical topic0 for JobCancelled.
pub(crate) fn job_cancelled_topic0() -> B256 {
    *JOB_CANCELLED_TOPIC0
}

/// Job monitor that watches for new RISC Zero jobs via polling eth_getLogs.
pub struct JobMonitor {
    client: ChainClient,
    poll_interval: Duration,
    /// Only watch for this proof system.
    /// If `Some`, the monitor only surfaces jobs for this proof system.
    /// If `None`, the monitor surfaces ALL JobSubmitted events regardless of
    /// backend; the brain filters by looking up `resolve_backend` later.
    proof_system_filter: Option<B256>,
    /// Blocks to rewind the initial start block by, so the first poll backfills
    /// jobs that were already Open when the miner started (it otherwise only sees
    /// jobs submitted after it began polling). 0 = forward-only.
    backfill_blocks: u64,
}

impl JobMonitor {
    /// Rewind the monitor's start block by `blocks` so it backfills already-open
    /// jobs on the first poll.
    pub fn with_backfill(mut self, blocks: u64) -> Self {
        self.backfill_blocks = blocks;
        self
    }

    /// Watch jobs for every proof system our workers support (risc0, sp1, openvm).
    /// The brain drops events whose proof system doesn't map to a known backend.
    pub fn new(client: ChainClient) -> Self {
        Self {
            client,
            poll_interval: Duration::from_secs(5),
            proof_system_filter: None,
            backfill_blocks: 0,
        }
    }

    /// Watch only a specific proof system.
    pub fn for_proof_system(client: ChainClient, proof_system_id: B256) -> Self {
        Self {
            client,
            poll_interval: Duration::from_secs(5),
            proof_system_filter: Some(proof_system_id),
            backfill_blocks: 0,
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Start monitoring, sending events to the provided channel.
    /// Runs until the sender is dropped or an unrecoverable error occurs.
    pub async fn run(self, tx: mpsc::Sender<MonitorEvent>) -> Result<()> {
        let mut poll_timer = interval(self.poll_interval);
        // [H4 #52] Do NOT seed last_block from a failed head fetch. `unwrap_or(0)` would
        // make last_block ≈ 0, so the first get_logs queries a genesis..head range that
        // every provider rejects on size — immediate, permanent blindness. Retry the
        // head read until it succeeds so backfill anchors to the real head.
        let head = loop {
            match self.client.get_block_number().await {
                Ok(b) => break b,
                Err(e) => {
                    tracing::warn!("monitor: startup get_block_number failed ({e:#}); retrying");
                    poll_timer.tick().await;
                }
            }
        };
        // Rewind so the first poll backfills jobs already Open at startup.
        let mut last_block = head.saturating_sub(self.backfill_blocks);
        // [review must-fix] The head at startup: JobClaimed events at or below this block
        // are HISTORICAL and must not prune (see the suppression in the log loop).
        let startup_head = head;

        tracing::info!(
            "Job monitor started, polling every {:?} from block {} (head {}, backfill {} blocks)",
            self.poll_interval,
            last_block,
            head,
            self.backfill_blocks,
        );

        // Event signatures. [RPC #3] The filter watches JobClaimed/JobCancelled too (one
        // widened topic0 array — same single get_logs request) so the brain can prune
        // foreign-claimed/cancelled jobs from the candidate set purely from log data.
        let job_submitted_topic = job_submitted_topic0();
        let job_claimed_topic = job_claimed_topic0();
        let job_cancelled_topic = job_cancelled_topic0();

        // [#10b] 429 circuit-breaker for the monitor: while the endpoint is rate-limiting,
        // stretch the effective poll cadence (get_block_number + get_logs are among the
        // heavier requests) to MONITOR_RATE_LIMITED_POLL, but query IMMEDIATELY on the clear
        // edge so a job that arrived during the storm is picked up promptly. New-job
        // detection is slower during a storm — acceptable, since the brain pauses claims then
        // anyway. The chunk ratchet / last_block advancement are unchanged.
        const MONITOR_RATE_LIMITED_POLL: Duration = Duration::from_secs(30);
        const MONITOR_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(30);
        let mut last_query = tokio::time::Instant::now();

        loop {
            poll_timer.tick().await;

            // Skip this tick's query only while STILL rate-limited AND we polled recently.
            // The clear edge needs no special case: the instant `rate_limited` goes false the
            // guard short-circuits, so the very next tick queries immediately (a job that
            // arrived during the storm is picked up right after it clears).
            let rate_limited = self
                .client
                .rpc_meter()
                .rate_limited_within(MONITOR_RATE_LIMIT_WINDOW);
            if rate_limited && last_query.elapsed() < MONITOR_RATE_LIMITED_POLL {
                continue;
            }
            last_query = tokio::time::Instant::now();

            let current_block = match self.client.get_block_number().await {
                Ok(b) => b,
                Err(e) => {
                    let _ = tx
                        .send(MonitorEvent::Error(format!("Failed to get block number: {}", e)))
                        .await;
                    continue;
                }
            };
            // Share the head with other tasks so they don't each poll block number.
            self.client.set_head_block(current_block);

            if current_block <= last_block {
                continue;
            }
            tracing::debug!(
                "monitor: new blocks {}..={current_block}, querying {} on {}",
                last_block + 1,
                if self.proof_system_filter.is_some() {
                    "JobSubmitted"
                } else {
                    "JobSubmitted/JobClaimed/JobCancelled"
                },
                self.client.hemi_prove
            );

            // [H4 #28] Query in bounded CHUNKs, advancing last_block per SUCCESSFUL chunk.
            // The old single unchunked get_logs never advanced last_block on error, so
            // during any outage the [last_block+1, current] range ratcheted upward until it
            // permanently exceeded the provider's block-range/result cap — then every poll
            // failed on size FOREVER, even after the RPC recovered. Chunking caps each
            // request at CHUNK blocks (always under the cap) and, on a mid-range failure,
            // keeps the progress from the chunks that DID succeed so the range can't grow.
            // Matches find_locked_jobs.
            const CHUNK: u64 = 9000;
            let mut start = last_block + 1;
            while start <= current_block {
                let end = (start + CHUNK - 1).min(current_block);
                let mut filter = Filter::new()
                    .address(self.client.hemi_prove)
                    .from_block(start)
                    .to_block(end);
                // [RPC #3] Widen topic0 to {JobSubmitted, JobClaimed, JobCancelled} ONLY
                // when no proof-system filter is set (the run path — the brain filters by
                // resolve_backend at ingest). With a proof-system filter, topic2 means
                // proofSystemId ONLY for JobSubmitted (it is prover/caller for the other
                // events), so combining them in one query would silently mis-filter —
                // keep the legacy single-event query in that mode.
                if let Some(ps) = self.proof_system_filter {
                    filter = filter.event_signature(job_submitted_topic).topic2(ps);
                } else {
                    filter = filter.event_signature(vec![
                        job_submitted_topic,
                        job_claimed_topic,
                        job_cancelled_topic,
                    ]);
                }

                match self.client.provider.get_logs(&filter).await {
                    Ok(logs) => {
                        tracing::debug!("monitor: get_logs {start}..={end} returned {} logs", logs.len());
                        for log in logs {
                            let topic0 = log.topics().first().copied();
                            // [RPC #2] Cache jobId → submitting tx hash for the descriptor
                            // fast path. Free: the log already carries both (topic1 = jobId).
                            // Populated for BOTH the live poll and the startup backfill.
                            // [RPC #3] GATED on topic0 == JobSubmitted: with the widened
                            // filter, a JobClaimed/JobCancelled log's tx is the claim/cancel
                            // tx, NOT the submit tx — caching it would poison the fast path
                            // (the hash-verify fallback would catch it, but every lookup for
                            // that job would then waste the fast path).
                            if topic0 == Some(job_submitted_topic) {
                                if let Some(txh) = log.transaction_hash {
                                    if let Some(jid) = log.topics().get(1) {
                                        self.client.note_submit_tx(*jid, txh);
                                    }
                                }
                            }
                            if let Some(event) = parse_monitor_log(&log) {
                                // [review must-fix] Claims are NON-terminal: releaseJob and
                                // slashAndReopen reset a job to Open (with a boosted bonus).
                                // A historical JobClaimed replayed through the startup
                                // backfill says NOTHING about current state — pruning on it
                                // would permanently drop a claimed-then-reopened job on
                                // every restart (the pre-event build re-discovered such jobs
                                // via the first tick's live Multicall3 view). Suppress
                                // backfill-range JobClaimed (block <= startup head; missing
                                // block number → suppress, fail-safe = don't prune). LIVE
                                // claims prune as designed. JobCancelled stays unconditional:
                                // Cancelled is terminal — no contract path resets it.
                                if matches!(event, MonitorEvent::JobClaimed { .. })
                                    && log.block_number.map_or(true, |b| b <= startup_head)
                                {
                                    continue;
                                }
                                if tx.send(event).await.is_err() {
                                    tracing::info!("Monitor channel closed, stopping");
                                    return Ok(());
                                }
                            }
                        }
                        last_block = end; // advance per successful chunk
                        start = end + 1;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(MonitorEvent::Error(format!("Failed to get logs {start}..={end}: {}", e)))
                            .await;
                        // Stop this poll; retry the FAILED chunk next poll. last_block has
                        // already advanced past the successful chunks, so the range never grows.
                        break;
                    }
                }
            }
        }
    }
}

/// [RPC #3] Dispatch a raw log to the right per-event parser, keyed STRICTLY on
/// topic0. Unknown/other event topics (e.g. JobReopened, JobFulfilled) return None
/// and are ignored — they must never be misparsed as one of the handled events.
fn parse_monitor_log(log: &Log) -> Option<MonitorEvent> {
    let t0 = log.topics().first()?;
    if *t0 == job_submitted_topic0() {
        parse_job_submitted_log(log)
    } else if *t0 == job_claimed_topic0() {
        parse_job_claimed_log(log)
    } else if *t0 == job_cancelled_topic0() {
        parse_job_cancelled_log(log)
    } else {
        None
    }
}

/// Parse a JobClaimed log.
/// `JobClaimed(bytes32 indexed jobId, address indexed prover, address indexed operator,
///             uint96 settledPrice, uint96 bonusAmount, uint40 lockDeadline)`
fn parse_job_claimed_log(log: &Log) -> Option<MonitorEvent> {
    let topics = log.topics();
    // topic0 + jobId + prover (operator topic unused; tolerate its absence).
    if topics.len() < 3 {
        return None;
    }
    let job_id = topics[1];
    let prover = Address::from_slice(&topics[2][12..]);
    let data = log.data().data.as_ref();
    // 3 non-indexed words: settledPrice, bonusAmount, lockDeadline.
    if data.len() < 96 {
        return None;
    }
    // uint96 right-aligned in word 0 → low 16 bytes fit u128 (top 4 are zero).
    let settled_price = u128::from_be_bytes(data[16..32].try_into().ok()?);
    // uint40 right-aligned in word 2 ([64..96]) → low 5 bytes at [91..96].
    let lock_deadline = u64::from_be_bytes({
        let mut buf = [0u8; 8];
        buf[3..8].copy_from_slice(&data[91..96]);
        buf
    });
    Some(MonitorEvent::JobClaimed { job_id, prover, settled_price, lock_deadline })
}

/// Parse a JobCancelled log.
/// `JobCancelled(bytes32 indexed jobId, address indexed caller, uint256 refundAmount,
///               bool bonusIncluded)`
fn parse_job_cancelled_log(log: &Log) -> Option<MonitorEvent> {
    let topics = log.topics();
    // topic0 + jobId + caller.
    if topics.len() < 3 {
        return None;
    }
    let job_id = topics[1];
    let caller = Address::from_slice(&topics[2][12..]);
    Some(MonitorEvent::JobCancelled { job_id, caller })
}

/// Parse a raw log into a MonitorEvent for JobSubmitted.
fn parse_job_submitted_log(log: &Log) -> Option<MonitorEvent> {
    let topics = &log.topics();
    if topics.len() < 4 {
        return None;
    }

    let job_id = topics[1];
    let proof_system_id = topics[2];
    let caller_topic = topics[3];
    let caller = Address::from_slice(&caller_topic[12..]);

    // Decode non-indexed data from log.data
    let data = log.data().data.as_ref();
    if data.len() < 192 {
        // 6 * 32 bytes minimum for the non-indexed params
        return None;
    }

    let program_id = B256::from_slice(&data[0..32]);
    let descriptor_hash = B256::from_slice(&data[32..64]);

    // uint96 fields are right-aligned in 32-byte words
    let deposited_amount = u128::from_be_bytes(data[80..96].try_into().ok()?);
    let min_price = u128::from_be_bytes(data[112..128].try_into().ok()?);
    let max_price = u128::from_be_bytes(data[144..160].try_into().ok()?);

    // uint40 fulfillmentTimeout
    let timeout_bytes = &data[160..192];
    let fulfillment_timeout = u64::from_be_bytes({
        let mut buf = [0u8; 8];
        buf[3..8].copy_from_slice(&timeout_bytes[27..32]);
        buf
    });

    Some(MonitorEvent::JobSubmitted {
        job_id,
        proof_system_id,
        caller,
        program_id,
        descriptor_hash,
        deposited_amount,
        min_price,
        max_price,
        fulfillment_timeout,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{keccak256, Bytes, LogData};

    fn mk_log(topics: Vec<B256>, data: Vec<u8>) -> Log {
        Log {
            inner: alloy::primitives::Log {
                address: Address::ZERO,
                data: LogData::new_unchecked(topics, Bytes::from(data)),
            },
            ..Default::default()
        }
    }

    /// Right-align `bytes` into a fresh 32-byte word.
    fn word(bytes: &[u8]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[32 - bytes.len()..].copy_from_slice(bytes);
        w
    }

    #[test]
    fn topic0s_match_bindings_signature_hashes() {
        // [review] Independent pin against the sol!-generated event signatures. Without
        // this, a typo in the hand-written signature strings (or contracts/bindings
        // drift — a documented failure mode in this repo) silently kills the whole
        // event class: every log is ignored with green CI.
        use alloy::sol_types::SolEvent;
        use zkminer_contracts::bindings::{IHemiProveCore, IHemiProveFulfill};
        assert_eq!(
            job_submitted_topic0(),
            IHemiProveCore::JobSubmitted::SIGNATURE_HASH,
            "JobSubmitted topic0 drifted from the bindings"
        );
        assert_eq!(
            job_claimed_topic0(),
            IHemiProveCore::JobClaimed::SIGNATURE_HASH,
            "JobClaimed topic0 drifted from the bindings"
        );
        assert_eq!(
            job_cancelled_topic0(),
            IHemiProveFulfill::JobCancelled::SIGNATURE_HASH,
            "JobCancelled topic0 drifted from the bindings"
        );
    }

    #[test]
    fn job_submitted_log_parses_through_dispatch() {
        // [review] Positive coverage for the revenue-critical event through the NEW
        // dispatch path (mutation testing showed total loss of job discovery previously
        // passed every test).
        let jid = B256::repeat_byte(0x01);
        let ps = B256::repeat_byte(0x02);
        let caller = Address::repeat_byte(0x03);
        let program = B256::repeat_byte(0x04);
        let dhash = B256::repeat_byte(0x05);
        let mut data = Vec::new();
        data.extend_from_slice(program.as_slice()); // programId
        data.extend_from_slice(dhash.as_slice()); // descriptorHash
        data.extend_from_slice(&word(&100_000_000_000_000_000_000u128.to_be_bytes()[4..])); // depositedAmount uint96
        data.extend_from_slice(&word(&50_000_000_000_000_000_000u128.to_be_bytes()[4..])); // minPrice
        data.extend_from_slice(&word(&100_000_000_000_000_000_000u128.to_be_bytes()[4..])); // maxPrice
        data.extend_from_slice(&word(&7200u64.to_be_bytes()[3..])); // fulfillmentTimeout uint40
        data.extend_from_slice(&word(&[0])); // trust uint8
        let log = mk_log(
            vec![job_submitted_topic0(), jid, ps, B256::from(word(caller.as_slice()))],
            data,
        );
        match parse_monitor_log(&log) {
            Some(MonitorEvent::JobSubmitted {
                job_id,
                proof_system_id,
                caller: c,
                program_id,
                descriptor_hash,
                min_price,
                max_price,
                fulfillment_timeout,
                ..
            }) => {
                assert_eq!(job_id, jid);
                assert_eq!(proof_system_id, ps);
                assert_eq!(c, caller);
                assert_eq!(program_id, program);
                assert_eq!(descriptor_hash, dhash);
                assert_eq!(min_price, 50_000_000_000_000_000_000u128);
                assert_eq!(max_price, 100_000_000_000_000_000_000u128);
                assert_eq!(fulfillment_timeout, 7200);
            }
            other => panic!("expected JobSubmitted, got {other:?}"),
        }
    }

    #[test]
    fn topic0s_are_distinct_and_canonical() {
        let s = job_submitted_topic0();
        let c = job_claimed_topic0();
        let x = job_cancelled_topic0();
        assert_ne!(s, c);
        assert_ne!(s, x);
        assert_ne!(c, x);
        // Regression-pin JobSubmitted's canonical signature (shared with descriptor.rs).
        assert_eq!(
            s,
            keccak256(
                "JobSubmitted(bytes32,bytes32,address,bytes32,bytes32,uint96,uint96,uint96,uint40,uint8)"
            )
        );
    }

    #[test]
    fn job_claimed_log_parses_and_is_not_misparsed_as_submitted() {
        let jid = B256::repeat_byte(0xAB);
        let prover = Address::repeat_byte(0x11);
        let operator = Address::repeat_byte(0x22);
        // data: settledPrice=50e18 (uint96), bonusAmount=0, lockDeadline=1_784_000_000 (uint40)
        let mut data = Vec::new();
        data.extend_from_slice(&word(&50_000_000_000_000_000_000u128.to_be_bytes()[4..])); // low 12 bytes = uint96
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(&word(&1_784_000_000u64.to_be_bytes()[3..])); // low 5 bytes = uint40
        let log = mk_log(
            vec![
                job_claimed_topic0(),
                jid,
                B256::from(word(prover.as_slice())),
                B256::from(word(operator.as_slice())),
            ],
            data,
        );
        match parse_monitor_log(&log) {
            Some(MonitorEvent::JobClaimed { job_id, prover: p, settled_price, lock_deadline }) => {
                assert_eq!(job_id, jid);
                assert_eq!(p, prover);
                assert_eq!(settled_price, 50_000_000_000_000_000_000u128);
                assert_eq!(lock_deadline, 1_784_000_000u64);
            }
            other => panic!("expected JobClaimed, got {other:?}"),
        }
        // And the dedicated submitted-parser must never be reached for this topic0 —
        // parse_monitor_log dispatches on topic0, so a claimed log with data long enough
        // to satisfy the submitted layout still must NOT come back as JobSubmitted.
        let mut long_data = log.data().data.to_vec();
        long_data.resize(224, 0);
        let padded = mk_log(log.topics().to_vec(), long_data);
        assert!(matches!(
            parse_monitor_log(&padded),
            Some(MonitorEvent::JobClaimed { .. })
        ));
    }

    #[test]
    fn job_cancelled_log_parses() {
        let jid = B256::repeat_byte(0xCD);
        let caller = Address::repeat_byte(0x33);
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 32]); // refundAmount
        data.extend_from_slice(&word(&[1])); // bonusIncluded = true
        let log = mk_log(
            vec![job_cancelled_topic0(), jid, B256::from(word(caller.as_slice()))],
            data,
        );
        match parse_monitor_log(&log) {
            Some(MonitorEvent::JobCancelled { job_id, caller: c }) => {
                assert_eq!(job_id, jid);
                assert_eq!(c, caller);
            }
            other => panic!("expected JobCancelled, got {other:?}"),
        }
    }

    #[test]
    fn job_reopened_log_is_ignored_not_misparsed() {
        // [review guard] A JobReopened log has 4 topics and a wide data section (8
        // non-indexed params ≥ 256 bytes) — enough to satisfy JobSubmitted's length
        // checks if dispatch were length-based. It must be IGNORED (None), never
        // misparsed as JobSubmitted.
        let reopened_topic = keccak256(
            "JobReopened(bytes32,address,address,uint128,uint256,uint256,uint96,uint8,uint40,uint40,address)",
        );
        let log = mk_log(
            vec![
                reopened_topic,
                B256::repeat_byte(0xEF),
                B256::from(word(Address::repeat_byte(0x44).as_slice())),
                B256::from(word(Address::repeat_byte(0x55).as_slice())),
            ],
            vec![0u8; 256],
        );
        assert!(parse_monitor_log(&log).is_none(), "JobReopened must be ignored");
    }

    #[test]
    fn short_or_malformed_logs_return_none() {
        // Claimed log with too few topics.
        assert!(parse_monitor_log(&mk_log(vec![job_claimed_topic0(), B256::ZERO], vec![0u8; 96])).is_none());
        // Claimed log with short data.
        assert!(parse_monitor_log(&mk_log(
            vec![job_claimed_topic0(), B256::ZERO, B256::ZERO],
            vec![0u8; 64]
        ))
        .is_none());
        // Cancelled log with too few topics.
        assert!(parse_monitor_log(&mk_log(vec![job_cancelled_topic0(), B256::ZERO], vec![])).is_none());
        // Empty-topic log.
        assert!(parse_monitor_log(&mk_log(vec![], vec![])).is_none());
    }
}
