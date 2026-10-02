use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::Provider;
use anyhow::{Context, Result, bail};
use std::time::Duration;

use crate::tx::TX_RECEIPT_TIMEOUT;
use zkminer_contracts::bindings::{
    HashedDescriptor, IHemiProveAux, IHemiProveCore, IHemiProveFulfill, JobDescriptor,
    JobStatusView,
};

/// Per-job gas budget for `claimJobBatch`, and the batch's fixed overhead.
///
/// **Why an explicit limit instead of `eth_estimateGas`.** `claimJobBatch`
/// isolates each job in a self-`call` and SWALLOWS per-job failures
/// (`results[i] = ok`), so the OUTER tx never reverts no matter how many inner
/// claims fail. `eth_estimateGas` binary-searches for the least gas at which the
/// outer tx *succeeds* — and, because inner failures are swallowed, it happily
/// settles on a value where the LAST sub-call is starved by EIP-150's 63/64 rule
/// and returns `false`, while the tx still "succeeds" returning `[true, …, false]`.
/// The estimate therefore SILENTLY DROPS the tail job(s): a batch of 3 mined with
/// ~314k gas locked only 2 (the 3rd sub-call got ~13k of the ~144k it needed).
///
/// A single `claimJob` executes in ~144k gas; the self-call wrapper and adapter
/// staticcall are included in that. 250k/job (~1.7×) leaves enough headroom that
/// even the 10th sub-call in a MAX_BATCH_SIZE batch clears the 63/64 haircut. The
/// unused portion is refunded, so over-provisioning is free beyond block-limit
/// headroom (2.6M for n=10 is trivial against Hemi's block gas limit).
const CLAIM_BATCH_PER_JOB_GAS: u64 = 250_000;
const CLAIM_BATCH_BASE_GAS: u64 = 80_000;
// [RPC quick-win] Explicit gas on the single claimJob so GasFiller sees a limit and both
// fee fields set → it skips the eth_estimateGas that otherwise fires back-to-back with the
// send (up to 5x under retry, and a 429-fragile abort point) in the claim burst window.
// claimJob is a fixed, loop-free path measured at ~144k; 300k is >2x headroom, refunded if
// unused. (claimJobBatch already sets an explicit limit; releaseJob deliberately does NOT —
// it is heavier and an under-provisioned OOG revert is treated as terminal → stranded.)
const CLAIM_JOB_GAS_LIMIT: u64 = 300_000;

/// Marker in the error text for "we cannot outbid the transaction resident at this
/// nonce within the ratchet cap".
///
/// Diagnostic only — nothing matches on it. The claim gate keys off
/// `ChainClient::signer_is_jammed`, which is set by the same bail arms; this string
/// exists so the give-up is greppable in an operator log.
pub const FEE_CAP_EXHAUSTED: &str = "fee cap exhausted";

/// Log an exhausted-cap give-up uniformly across the four tx paths.
///
/// The bid is logged because the 2026-08-14 wedge was diagnosable only by re-deriving
/// the arithmetic from the cap: 327 rejected sends over 4h24m and not one fee value in
/// the log. Never make an operator infer the number that was actually on the wire.
fn log_fee_cap_exhausted(what: &str, nonce: u64, state: &crate::nonce::FeeFloorState) {
    tracing::error!(
        "{what} at nonce {nonce}: fee cap EXHAUSTED — already broadcast \
         max_fee={} tip={} against cap={}; no strictly-higher replacement is possible, \
         so giving up instead of re-bidding a fee the node will reject forever. \
         The resident tx must mine or be evicted before this nonce frees.",
        state.broadcast.1, state.broadcast.0, state.cap,
    );
}

/// Escalating EIP-1559 fees for re-broadcast `attempt` (1-based) given base fees.
///
/// Bumps BOTH the priority fee and the max fee enough to clear a node's same-nonce
/// replacement threshold (geth default 10%, some nodes 12.5%), so a re-broadcast
/// reliably DISPLACES a stuck predecessor (a claim/fulfill/release we're retrying, or
/// a release over a stuck fulfill). Without this, a re-send at unchanged fees is
/// rejected "replacement underpriced" forever.
///
/// The escalation is MULTIPLICATIVE — attempt N is ~15% over attempt N-1 on BOTH
/// fields — so *every* re-broadcast (not just the first) clears the floor even after
/// integer truncation. An earlier additive-percentage-point schedule decayed as the
/// base grew (13% → 11.5% → 10.3% → 9.35% by attempt 4→5), dropping under geth's 10%
/// floor on the final attempt — which is exactly `release_job`'s same-nonce collateral
/// rescue, and the decay is the *normal* case on low-priority-fee L2s where max_fee
/// dominates the tip. attempt 1 == base fees (the initial send is not a replacement);
/// each further attempt multiplies by 1.15, with a strict +1 floor so a sub-100-wei
/// base still moves.
/// [H2/M5] `release_job` continues the fee escalation from HERE (past `fulfill_job`'s
/// MAX_ATTEMPTS ceiling) so a release can out-bid — and thus displace at the same
/// nonce — a fulfill tx parked at its top escalation. Equal to fulfill's MAX_ATTEMPTS.
const FULFILL_ESCALATION_HEADROOM: u32 = 5;

/// Raise `(tip, max_fee)` so it can DISPLACE whatever we last broadcast at `nonce`.
///
/// The escalation ladder is seeded per INVOCATION (`base_fees()` is fetched once per
/// `claim_job`/`fulfill_job` call and `attempt` restarts at 1), so a fresh invocation that
/// recycles a nonce through `freed` restarts at the UNBUMPED base and cannot clear the
/// node's replacement threshold against a resident tx left at a previous invocation's top
/// attempt. That made the retry loop arithmetically non-terminating and wedged the signer
/// for ~10 minutes on 2026-08-01. Anchoring the floor to the NONCE fixes it: every send at
/// that nonce is strictly above the last one, whoever sends it.
///
/// `REPLACEMENT_BUMP_NUM/DEN` is the margin over the recorded high-water. geth's default
/// replacement rule needs +10%; 12.5% (= `+ v/8`) clears it with room for rounding, and
/// matches the floor already used inside `escalated_fees`.
/// Lift `(tip, max_fee)` over the recorded per-nonce floor so a re-broadcast can
/// displace whatever we last put at this nonce.
///
/// Returns `None` when the ratchet cap is EXHAUSTED — no strictly-higher bid is
/// possible, so any send would be rejected `replacement transaction underpriced`
/// every time. Callers must stop rather than spin: re-bidding a losing fee is what
/// wedged nonce 11589 for 4h24m on 2026-08-14 and stranded three jobs' collateral.
fn fees_over_floor(
    client: &ChainClient,
    nonce: u64,
    tip: u128,
    max_fee: u128,
) -> Option<(u128, u128)> {
    fees_over_floor_state(client.nonce_fee_floor_state(nonce), tip, max_fee)
}

/// The pure core of [`fees_over_floor`], split out so it can be unit-tested without a
/// chain client. It had zero test coverage while being the function that decides whether
/// a money-path transaction is sent at all.
fn fees_over_floor_state(
    state: Option<crate::nonce::FeeFloorState>,
    tip: u128,
    max_fee: u128,
) -> Option<(u128, u128)> {
    let Some(state) = state else {
        return Some((tip, max_fee));
    };
    if state.exhausted {
        return None;
    }
    let (floor_tip, floor_max) = state.floor;
    let over = |v: u128| v.saturating_add((v / 8).max(1));
    let bid = (tip.max(over(floor_tip)), max_fee.max(over(floor_max)));
    // A bid at or below what we already broadcast cannot displace it. Treat that as
    // exhaustion too -- this is the exact shape the cap used to produce silently.
    if bid.1 <= state.broadcast.1 && state.broadcast.1 > 0 {
        return None;
    }
    Some(bid)
}

fn escalated_fees(base_tip: u128, base_max_fee: u128, attempt: u32) -> (u128, u128) {
    let steps = attempt.saturating_sub(1);
    let bump = |mut v: u128| -> u128 {
        for _ in 0..steps {
            // Increment = max(15% of v, ceil(v/8) = 12.5% of v, 1). The 15% term is the
            // normal bump for realistic (gwei-scale) fees; the ceil(v/8) term is a hard
            // floor that guarantees ≥12.5% even where `*15/100` would truncate below the
            // replacement threshold for tiny (sub-~40-wei) fees on a zero-priority-fee
            // chain; the final `.max(1)` guarantees strict increase from a zero base.
            // So EVERY attempt clears a node's replacement floor (geth default 10%).
            let inc = (v.saturating_mul(15) / 100)
                .max(v.saturating_add(7) / 8)
                .max(1);
            v = v.saturating_add(inc);
        }
        v
    };
    let tip = bump(base_tip);
    // Guarantee max_fee >= tip: an EIP-1559 tx with maxPriorityFeePerGas > maxFeePerGas
    // is rejected by the node. base_max_fee >= base_tip from estimate_eip1559_fees, and
    // both escalate by the same factor, but clamp defensively.
    let max_fee = bump(base_max_fee).max(tip);
    (tip, max_fee)
}

/// [H2] A tx is already PENDING at the nonce we're using — a stuck predecessor at
/// this nonce (a fulfill we're releasing over, or our own prior re-broadcast). The
/// correct response is to KEEP the same nonce and ESCALATE the fee so the next
/// attempt DISPLACES it. Re-syncing the nonce forward here (the old is_nonce_error
/// path) instead queues the new tx BEHIND the stuck one → it can never mine before
/// the deadline → strand. This must be checked BEFORE is_nonce_error.
fn is_same_nonce_pending(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("replacement transaction underpriced")
        || m.contains("already known")
        || m.contains("tx already in mempool")
}

/// True if a tx-send error means our nonce is genuinely WRONG (consumed or ahead of
/// chain) and a re-fetch of the on-chain nonce will fix it. NOTE: "replacement
/// underpriced"/"already known"/"mempool" are NOT here — those mean the nonce is
/// correct but a tx is pending at it (see is_same_nonce_pending); walking the nonce
/// forward on those breaks the fulfill→release same-nonce displacement (H2).
fn is_nonce_error(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("nonce too low") || m.contains("nonce too high")
}

/// [#4] Whether an error string is a rate-limit (429) response. Matches the HTTP 429
/// status and the JSON-RPC "rate limit exceeded" body the endpoint returns (code -32005).
fn is_rate_limit_error(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("429") || m.contains("rate limit") || m.contains("-32005")
}

use crate::client::ChainClient;

/// Outcome of an idempotent claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// We now hold the lock on this job.
    Claimed,
    /// Someone else already owns (or has released/fulfilled) this job.
    LostRace,
}

/// Parsed job data from chain (derived from JobStatusView + events).
#[derive(Debug, Clone)]
pub struct JobInfo {
    pub job_id: B256,
    /// The programId (imageId/vKey) from the JobSubmitted event.
    pub program_id: B256,
    pub caller: Address,
    pub status: u8,
    pub reopen_count: u8,
    pub descriptor_hash: B256,
    pub deposited_amount: u128,
    pub bonus_amount: u128,
    pub lock_deadline: u64,
    pub prover: Address,
    pub locked_collateral: u128,
    pub ramp_up_start: u64,
    pub elapsed_at_lock: u64,
    pub settled_price: u128,
    pub min_price: u128,
    pub max_price: u128,
    pub ramp_up_period: u64,
    pub curve_type: u8,
    pub fulfillment_timeout: u64,
    pub lock_collateral_bps: u128,
    pub speed_premium: u128,
    pub exclusivity_duration: u64,
}

impl ChainClient {
    /// Read a job's status view (rich view with computed fields).
    pub async fn get_job_status_view(&self, job_id: B256) -> Result<JobStatusView> {
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        let view = aux.getJobStatusView(job_id).call().await
            .context("Failed to get job status view")?;
        Ok(view)
    }

    /// Fetch `getJobStatusView` for many jobs in ONE RPC request via Multicall3.
    /// Returns `(job_id, Some(view))` for each, or `(job_id, None)` if that
    /// sub-call reverted (e.g. an unknown job) — the whole batch shares one
    /// consistent block snapshot. Falls back to per-job calls if the batch RPC
    /// itself errors, so a Multicall3-less chain still works.
    pub async fn get_job_status_views_batch(
        &self,
        job_ids: &[B256],
    ) -> Result<Vec<(B256, Option<JobStatusView>)>> {
        if job_ids.is_empty() {
            return Ok(Vec::new());
        }
        // [M9] CHUNK the multicall. A single aggregate3 over a large set (recovery can pass
        // 100+ historically-claimed jobs) can exceed the node's response/gas cap and fail
        // WHOLESALE, dropping us into the per-job fallback below for EVERY job — an RPC
        // storm that 429s the endpoint. Bounded chunks keep each multicall well within
        // limits, so only a genuinely broken chunk falls back per-job.
        use alloy::providers::MulticallItem;
        const MC_CHUNK: usize = 25;
        let mut out = Vec::with_capacity(job_ids.len());
        let mut i = 0;
        while i < job_ids.len() {
            let chunk = &job_ids[i..(i + MC_CHUNK).min(job_ids.len())];
            let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
            let mut mc = self
                .provider
                .multicall()
                .dynamic::<IHemiProveAux::getJobStatusViewCall>();
            for jid in chunk {
                // [review must-fix] allowFailure=TRUE per sub-call. alloy's `add_dynamic`
                // defaults to allow_failure=FALSE, and aggregate3 reverts wholesale on any
                // allowFailure=false sub-call revert — so a single unknown/reverting jobId
                // would sink the entire 25-job chunk into the expensive per-job fallback
                // (or, under a storm, defer all 25). With allowFailure=true a reverting job
                // yields None for THAT job only, exactly as the `.ok()` below assumes.
                mc = mc.add_call_dynamic(aux.getJobStatusView(*jid).into_call(true));
            }
            match mc.aggregate3().await {
                Ok(results) => {
                    for (jid, r) in chunk.iter().zip(results) {
                        // aggregate3 = allowFailure per sub-call: a single reverting
                        // getJobStatusView yields None for THAT job, not the whole chunk.
                        out.push((*jid, r.ok()));
                    }
                    i += chunk.len();
                }
                // [#4] Classify the chunk failure. Under a rate-limit storm the OLD code
                // fanned out one get_job_status_view PER job in the failed chunk — the exact
                // per-job storm that AMPLIFIES the 429s.
                //
                // Classify PRIMARILY on THIS chunk's error being a 429 (not just the global
                // recent-429 meter): a stray unrelated 429 within the window must not
                // reclassify a genuine one-chunk error. [review must-fix] Mark ONLY the
                // current chunk unreadable (None) and CONTINUE — do NOT discard the later,
                // possibly-healthy chunks. Each remaining chunk still costs exactly one
                // paced multicall (N/25 total, never per-job), so the amplifier is gone,
                // while readable later chunks still return real deadlines so the recovery
                // loop can prioritise/release an urgent job THIS pass. None always means
                // "keep the breadcrumb, retry" to every caller — never "not ours" — so this
                // can only defer, never strand.
                Err(e) if is_rate_limit_error(&format!("{e:#}")) || self.rate_limited_now() => {
                    tracing::warn!(
                        "getJobStatusView chunk rate-limited ({e:#}); marking chunk unreadable, continuing to next chunk"
                    );
                    for jid in chunk {
                        out.push((*jid, None));
                    }
                    i += chunk.len();
                }
                Err(e) => {
                    tracing::debug!("getJobStatusView multicall chunk failed ({e:#}); per-job fallback for this chunk");
                    for jid in chunk {
                        out.push((*jid, self.get_job_status_view(*jid).await.ok()));
                    }
                    i += chunk.len();
                }
            }
        }
        Ok(out)
    }

    /// [#4] True if the endpoint rate-limited us within the recent-classify window — a
    /// secondary storm signal used alongside the per-error 429 check.
    fn rate_limited_now(&self) -> bool {
        self.rpc_meter()
            .rate_limited_within(std::time::Duration::from_secs(5))
    }

    /// Get current auction price for a job.
    pub async fn get_current_price(&self, job_id: B256) -> Result<u128> {
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        let price = aux.getCurrentPrice(job_id).call().await
            .context("Failed to get current price")?;
        Ok(price.to::<u128>())
    }

    /// The governance-set per-job collateral floor (`MIN_COLLATERAL_AMOUNT`). The
    /// on-chain claim floors `computeCollateral()` with this value, so the miner's
    /// collateral gate must use the SAME floor (not an adapter's `minStake`, which is
    /// the unrelated prover-eligibility total-stake threshold — [D6]). Constant across
    /// a deployment, so callers fetch it once at startup and cache it.
    pub async fn get_min_collateral_amount(&self) -> Result<u128> {
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        let v = aux.MIN_COLLATERAL_AMOUNT().call().await
            .context("Failed to get MIN_COLLATERAL_AMOUNT")?;
        Ok(v.to::<u128>())
    }

    /// Get current job index (total jobs submitted).
    pub async fn get_job_index(&self) -> Result<u64> {
        let core = IHemiProveCore::new(self.hemi_prove, &*self.provider);
        let index = core.jobIndex().call().await
            .context("Failed to get job index")?;
        Ok(index.to::<u64>())
    }

    /// Scan `JobClaimed` events for jobs this miner locked on-chain (topic2 =
    /// prover == our address), within `lookback_blocks` of the chain head. Used on
    /// startup to discover locked positions that never made it into the journal
    /// (crash before write, cleared journal, another machine). Chunked to stay
    /// under RPC log-range limits; per-chunk errors are logged, not fatal. The
    /// returned ids still need a per-job status check (the recovery loop confirms
    /// each is currently Locked-by-us before re-driving it).
    pub async fn find_locked_jobs(&self, lookback_blocks: u64) -> Result<Vec<B256>> {
        use alloy::rpc::types::Filter;
        let head = self
            .head_block_cached()
            .await
            .context("find_locked_jobs: head block")?;
        let from = head.saturating_sub(lookback_blocks);
        let topic = alloy::primitives::keccak256(
            "JobClaimed(bytes32,address,address,uint96,uint96,uint40)",
        );
        let prover_topic = self.address.into_word();
        const CHUNK: u64 = 9000;

        let mut job_ids: Vec<B256> = Vec::new();
        let mut start = from;
        while start <= head {
            let end = (start + CHUNK).min(head);
            let filter = Filter::new()
                .address(self.hemi_prove)
                .event_signature(topic)
                .topic2(prover_topic)
                .from_block(start)
                .to_block(end);
            match self.provider.get_logs(&filter).await {
                Ok(logs) => {
                    for log in logs {
                        // topics: [sig, jobId, prover, operator]
                        if let Some(jid) = log.topics().get(1).copied() {
                            if !job_ids.contains(&jid) {
                                job_ids.push(jid);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("find_locked_jobs: get_logs {start}..={end} failed: {e:#}");
                }
            }
            start = end.saturating_add(1);
        }
        Ok(job_ids)
    }

    /// Claim an open job.
    pub async fn claim_job(&self, job_id: B256) -> Result<()> {
        const MAX_ATTEMPTS: u32 = 5;
        let core = IHemiProveCore::new(self.hemi_prove, &*self.provider);

        // Reserve the nonce once from the local cache (fetching only if unset) and
        // reuse it across re-broadcasts, so a timed-out tx is *replaced* at the same
        // nonce rather than leaving a gap. Committed on success; on any error/give-up the
        // nonce is ABORTED (recycled as a gap for the next reservation) — not "invalidated":
        // `invalidate` re-anchors the whole allocator and has no callers.
        let mut nonce = self.reserve_nonce().await?;
        // Seed fee escalation once; each attempt bumps fees so a re-broadcast can
        // displace a stuck same-nonce tx even under default (auto-gas) config.
        let (base_tip, base_max_fee) = self.base_fees().await;

        for attempt in 1..=MAX_ATTEMPTS {
            // Send under the nonce lock. The local nonce cache bypasses a per-send
            // eth_getTransactionCount; the provider's own cached nonce is unreliable
            // when the flaky RPC drops then later mines a tx.
            let send_result = {
                let _guard = self.tx_lock.lock().await;
                let mut tx = core.claimJob(job_id).nonce(nonce).gas(CLAIM_JOB_GAS_LIMIT);
                let mut bid = None;
                if base_max_fee > 0 {
                    let (tip, seed_max_fee) = escalated_fees(base_tip, base_max_fee, attempt);
                    // Must exceed anything WE already put at this nonce, even if that came
                    // from an earlier invocation with its own fresh ladder.
                    let max_fee = seed_max_fee;
                    let Some((tip, max_fee)) = fees_over_floor(self, nonce, tip, max_fee)
                    else {
                        // Cap exhausted: no strictly-higher bid exists, so every send from
                        // here is rejected "replacement underpriced". Stop now rather than
                        // burning the attempt ladder against a wall.
                        if let Some(st) = self.nonce_fee_floor_state(nonce) {
                            log_fee_cap_exhausted("claimJob", nonce, &st);
                        }
                        self.note_nonce_undisplaceable(nonce);
                        // Leave abort EVIDENCE but do NOT offer the nonce back to
                        // reservers. `abort` would push it to the HEAD of `freed`, and
                        // `reserve_locked` hands the lowest freed nonce out first -- so the
                        // next reserver (preferentially a deadline-critical release) would
                        // draw this same poisoned nonce and bail again, in a loop.
                        // `note_unresolved` writes `aborted_at` only: the gap detector's
                        // branch (B) still nominates the nonce via `recently_aborted`, so
                        // it stays visible and healable, while nothing is handed it.
                        //
                        // BEWARE: the healer this arms is the LIVE watchdog branch (B),
                        // which is consumed UNGATED (client.rs `hole_we_own` and its
                        // `frontier_has_executable_tx` gate are on the SHUTDOWN path only).
                        // So roughly WEDGE_CHECK_TICKS + WEDGE_MIN_PERSIST after this, the
                        // healer will try to evict the resident tx with a self-transfer --
                        // and since that bid now lifts over the uncapped high-water, it
                        // will SUCCEED. That is the intended unwedge, but it does mean a
                        // live tx of ours at this nonce is deliberately displaced.
                        self.note_nonce_unresolved(nonce);
                        bail!("{FEE_CAP_EXHAUSTED} at nonce {nonce} (claimJob)");
                    };
                    bid = Some((tip, max_fee, seed_max_fee));
                    tx = tx.max_priority_fee_per_gas(tip).max_fee_per_gas(max_fee);
                }
                let r = tx.send().await;
                // Ratchet ONLY on an accepted broadcast: a rejected send (429, balance
                // pre-check) never reached the mempool, and inflating the floor for it
                // would raise later bids for nothing.
                if r.is_ok() {
                    if let Some((tip, max_fee, seed)) = bid {
                        self.note_broadcast_fee(nonce, tip, max_fee, seed);
                    }
                }
                r
            };

            let pending = match send_result {
                Ok(p) => p,
                Err(e) => {
                    let msg = format!("{e:#}");
                    // [H2] A tx is pending at this nonce → keep it and let the next
                    // attempt's escalated fee displace it; do NOT walk the shared nonce
                    // forward (that orphans the pending tx and poisons the cache for
                    // concurrent lifecycle tasks).
                    if is_same_nonce_pending(&msg) {
                        tracing::warn!(
                            "claimJob replacement at nonce {nonce} (attempt {attempt}/{MAX_ATTEMPTS}): {msg} — bumping fee, keeping nonce"
                        );
// Give the node a moment before re-bidding. Without this the
                        // whole attempt ladder burns in well under a second, which learns
                        // nothing (the resident tx has not moved) and, during the
                        // 2026-08-14 wedge, produced 327 rejected sends in 4h24m. Linear in
                        // the attempt so a transient collision still clears quickly.
                        tokio::time::sleep(Duration::from_millis(
                            250u64.saturating_mul(attempt as u64),
                        ))
                        .await;
                        continue;
                    }
                    // Genuine nonce mismatch (our nonce was consumed by an external tx):
                    // re-sync and take a FRESH distinct nonce. The stale nonce is consumed
                    // on-chain, so it is NOT recycled.
                    if is_nonce_error(&msg) {
                        tracing::warn!(
                            "claimJob nonce error (attempt {attempt}/{MAX_ATTEMPTS}): {msg} — re-syncing nonce"
                        );
                        // [nonce-review] Recycle the abandoned nonce so a "nonce too high"
                        // (a gap below us) doesn't leak it; resync then prunes it from the
                        // gap set if it was actually consumed ("nonce too low").
                        self.abort_nonce(nonce);
                        self.resync_nonce().await.ok();
                        match self.reserve_nonce().await {
                            Ok(n) => nonce = n,
                            Err(e) => tracing::warn!("claimJob nonce re-reserve failed: {e:#} — retrying"),
                        }
                        continue;
                    }
                    // Send failed for a non-nonce reason and the tx did not land → recycle
                    // the nonce as a gap so it doesn't wedge higher nonces.
                    self.abort_nonce(nonce);
                    return Err(anyhow::anyhow!("Failed to send claimJob tx: {msg}"));
                }
            };
            let tx_hash = *pending.tx_hash();
            tracing::info!(
                "claimJob tx sent (attempt {attempt}/{MAX_ATTEMPTS}): {tx_hash:?}, waiting for receipt..."
            );

            // [RPC #1] Poll for the receipt instead of registering alloy's heartbeat
            // watcher. Some(receipt) = mined (same status handling); None folds the old
            // timeout AND RPC-error arms into the on-chain STATE poll (a transient 429 no
            // longer blind-rebroadcasts at the same nonce — the storm amplifier).
            match crate::tx::await_receipt(&*self.provider, tx_hash, TX_RECEIPT_TIMEOUT).await {
                Some(receipt) => {
                    if receipt.status() {
                        self.commit_nonce(nonce);
                        tracing::info!("Job claimed: {} tx: {:?}", job_id, receipt.transaction_hash);
                        return Ok(());
                    }
                    // Mined revert consumed the nonce on-chain → commit it.
                    self.commit_nonce(nonce);
                    anyhow::bail!("claimJob transaction reverted (tx {tx_hash:?})");
                }
                None => {
                    // No receipt within budget: the tx may still land. Poll on-chain state
                    // before re-broadcasting (never re-send blindly).
                    tracing::warn!(
                        "claimJob receipt not confirmed (attempt {attempt}/{MAX_ATTEMPTS}, tx {tx_hash:?}); \
                         polling state before re-broadcast"
                    );
                    let deadline = std::time::Instant::now() + Duration::from_secs(20);
                    while std::time::Instant::now() < deadline {
                        if let Ok(view) = self.get_job_status_view(job_id).await {
                            if view.prover == self.address {
                                // [nonce-review] State signal = SOME claim of ours landed, not
                                // necessarily THIS nonce (an is_nonce_error re-reserve may have
                                // moved us off it). abort self-heals; commit could advance past
                                // an unmined nonce → permanent gap/wedge.
                                self.abort_nonce(nonce);
                                tracing::info!("Job {} claimed (confirmed via poll)", job_id);
                                return Ok(());
                            }
                            if view.prover != Address::ZERO {
                                self.abort_nonce(nonce); // our claim didn't land → recycle the gap
                                anyhow::bail!("claimJob lost race — job {} taken by {}", job_id, view.prover);
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(4)).await;
                    }
                }
            }
        }

        // Final on-chain check before declaring failure.
        if let Ok(view) = self.get_job_status_view(job_id).await {
            if view.prover == self.address {
                self.abort_nonce(nonce); // [nonce-review] state signal, not a receipt for THIS nonce
                return Ok(());
            }
            if view.prover != Address::ZERO {
                self.abort_nonce(nonce); // our claim didn't land → recycle the gap
                anyhow::bail!("claimJob lost race — job {} taken by {}", job_id, view.prover);
            }
        }
        self.abort_nonce(nonce); // gave up; tx didn't land → recycle the gap
        anyhow::bail!("claimJob failed after {MAX_ATTEMPTS} attempts (RPC may be dropping txs)")
    }

    /// Batch-lock up to MAX_BATCH_SIZE (10) jobs in ONE tx via `claimJobBatch`.
    ///
    /// Partial-completion: the outer tx SUCCEEDS even if some sub-claims fail (lost
    /// race, adapter disabled, insufficient collateral) — each is isolated per-job on
    /// chain. The per-job `bool[]` result is not visible from a tx receipt, so this
    /// returns `Ok(())` once the batch tx has EXECUTED on-chain and leaves the caller
    /// to reconcile which jobs actually locked (via `get_job_status_views_batch`).
    ///
    /// Mirrors `claim_job`'s single-nonce / escalating-fee / re-broadcast machinery
    /// (the whole batch is one tx = one nonce). The "executed" signal for the poll/
    /// final paths is "≥1 job in the set is now locked by us"; a batch where every
    /// sub-claim lost the race also executes but locks nothing — that surfaces as a
    /// (false) Err here, which is safe because the caller treats unclaimed jobs as
    /// not-locked either way and keeps its claim-intent breadcrumbs for reconciliation.
    pub async fn claim_job_batch(&self, job_ids: &[B256]) -> Result<()> {
        if job_ids.is_empty() {
            return Ok(());
        }
        const MAX_ATTEMPTS: u32 = 5;
        // [D5] A batch claim is SPECULATIVE (it locks MORE work). It must not
        // monopolize the single shared nonce lane for the full ~11 min worst case
        // (5 × (TX_RECEIPT_TIMEOUT + 20s poll)): while it holds/reuses nonce N and
        // keeps escalating fees, a deadline-critical fulfill/release reserving the
        // same N is out-bid → walked to N+1 behind the stuck batch → its already-
        // locked job misses the deadline → keeper slash. Cap total wall time well
        // under any fulfillment deadline; on give-up the nonce is ABORTED — recycled as a
        // gap so the next reservation refills it and an urgent tx takes the lane. (Not
        // "invalidated": that re-anchors the whole allocator and has no callers.) The batch's last tx may still mine —
        // the background caller reconciles on-chain regardless, so cutting the retry
        // loop short never loses a lock we actually won.
        const WALL_CAP: Duration = Duration::from_secs(90);
        let started = std::time::Instant::now();
        let core = IHemiProveCore::new(self.hemi_prove, &*self.provider);
        let ids: Vec<B256> = job_ids.to_vec();
        let mut nonce = self.reserve_nonce().await?;
        let (base_tip, base_max_fee) = self.base_fees().await;

        let any_ours = |views: &[(B256, Option<JobStatusView>)]| -> bool {
            views
                .iter()
                .any(|(_, v)| v.as_ref().map_or(false, |view| view.prover == self.address))
        };

        for attempt in 1..=MAX_ATTEMPTS {
            if started.elapsed() >= WALL_CAP {
                // Speculative batch has held the lane long enough — yield. Recycle the
                // nonce as a gap: with the distinct-nonce allocator, a deadline-critical
                // fulfill/release gets its OWN nonce (it no longer needs to displace this
                // one), and recycling keeps this nonce from wedging higher ones. If the
                // batch tx actually mines, a reuser hits "nonce too low" and re-syncs.
                tracing::warn!(
                    "claimJobBatch wall-time cap ({}s) reached after {} attempt(s) — yielding the nonce lane to deadline-critical txs",
                    WALL_CAP.as_secs(), attempt - 1
                );
                self.abort_nonce(nonce);
                return Ok(());
            }
            // Explicit gas limit — DO NOT rely on eth_estimateGas here (it under-
            // provisions and silently drops the tail job; see CLAIM_BATCH_PER_JOB_GAS).
            let gas_limit =
                CLAIM_BATCH_BASE_GAS + CLAIM_BATCH_PER_JOB_GAS * ids.len() as u64;
            let mut bid: Option<(u128, u128, u128)> = None;
            let send_result = {
                let _guard = self.tx_lock.lock().await;
                let mut tx = core.claimJobBatch(ids.clone()).nonce(nonce).gas(gas_limit);
                if base_max_fee > 0 {
                    let (tip, seed_max_fee) = escalated_fees(base_tip, base_max_fee, attempt);
                    // Must exceed anything WE already put at this nonce. A recycled nonce
                    // can carry a give-up claim/release floor, or a heal's >=4x self-transfer,
                    // and this open-loop ladder can never clear those on its own.
                    let max_fee = seed_max_fee;
                    let Some((tip, max_fee)) = fees_over_floor(self, nonce, tip, max_fee)
                    else {
                        // Cap exhausted: no strictly-higher bid exists, so every send from
                        // here is rejected "replacement underpriced". Stop now rather than
                        // burning the attempt ladder against a wall.
                        if let Some(st) = self.nonce_fee_floor_state(nonce) {
                            log_fee_cap_exhausted("claimJobBatch", nonce, &st);
                        }
                        self.note_nonce_undisplaceable(nonce);
                        // Leave abort EVIDENCE but do NOT offer the nonce back to
                        // reservers. `abort` would push it to the HEAD of `freed`, and
                        // `reserve_locked` hands the lowest freed nonce out first -- so the
                        // next reserver (preferentially a deadline-critical release) would
                        // draw this same poisoned nonce and bail again, in a loop.
                        // `note_unresolved` writes `aborted_at` only: the gap detector's
                        // branch (B) still nominates the nonce via `recently_aborted`, so
                        // it stays visible and healable, while nothing is handed it.
                        //
                        // BEWARE: the healer this arms is the LIVE watchdog branch (B),
                        // which is consumed UNGATED (client.rs `hole_we_own` and its
                        // `frontier_has_executable_tx` gate are on the SHUTDOWN path only).
                        // So roughly WEDGE_CHECK_TICKS + WEDGE_MIN_PERSIST after this, the
                        // healer will try to evict the resident tx with a self-transfer --
                        // and since that bid now lifts over the uncapped high-water, it
                        // will SUCCEED. That is the intended unwedge, but it does mean a
                        // live tx of ours at this nonce is deliberately displaced.
                        self.note_nonce_unresolved(nonce);
                        bail!("{FEE_CAP_EXHAUSTED} at nonce {nonce} (claimJobBatch)");
                    };
                    bid = Some((tip, max_fee, seed_max_fee));
                    tx = tx.max_priority_fee_per_gas(tip).max_fee_per_gas(max_fee);
                }
                tx.send().await
            };

            let pending = match send_result {
                Ok(p) => {
                    // Ratchet on an ACCEPTED send only, so the read above cannot flatten the
                    // ladder (with a floor present, max() would pin every rung to one bid and
                    // a self-displacing re-broadcast would be rejected forever).
                    if let Some((t, m, seed)) = bid {
                        self.note_broadcast_fee(nonce, t, m, seed);
                    }
                    p
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    // [H2] tx pending at this nonce → keep it, escalate; don't walk forward.
                    if is_same_nonce_pending(&msg) {
                        tracing::warn!(
                            "claimJobBatch replacement at nonce {nonce} (attempt {attempt}/{MAX_ATTEMPTS}): {msg} — bumping fee, keeping nonce"
                        );
// Give the node a moment before re-bidding. Without this the
                        // whole attempt ladder burns in well under a second, which learns
                        // nothing (the resident tx has not moved) and, during the
                        // 2026-08-14 wedge, produced 327 rejected sends in 4h24m. Linear in
                        // the attempt so a transient collision still clears quickly.
                        tokio::time::sleep(Duration::from_millis(
                            250u64.saturating_mul(attempt as u64),
                        ))
                        .await;
                        continue;
                    }
                    if is_nonce_error(&msg) {
                        tracing::warn!(
                            "claimJobBatch nonce error (attempt {attempt}/{MAX_ATTEMPTS}): {msg} — re-syncing nonce"
                        );
                        // [nonce-review] Recycle the abandoned nonce so a "nonce too high"
                        // (a gap below us) doesn't leak it; resync then prunes it from the
                        // gap set if it was actually consumed ("nonce too low").
                        self.abort_nonce(nonce);
                        self.resync_nonce().await.ok();
                        match self.reserve_nonce().await {
                            Ok(n) => nonce = n,
                            Err(e) => tracing::warn!("claimJobBatch nonce re-reserve failed: {e:#} — retrying"),
                        }
                        continue;
                    }
                    self.abort_nonce(nonce); // send failed, tx didn't land → recycle gap
                    return Err(anyhow::anyhow!("Failed to send claimJobBatch tx: {msg}"));
                }
            };
            let tx_hash = *pending.tx_hash();
            tracing::info!(
                "claimJobBatch({} jobs) tx sent (attempt {attempt}/{MAX_ATTEMPTS}): {tx_hash:?}, waiting for receipt..."
            , ids.len());

            // Bound the receipt wait by the remaining wall budget so one attempt can't
            // blow past the cap (TX_RECEIPT_TIMEOUT alone is 120s > WALL_CAP).
            let recv_budget = WALL_CAP
                .saturating_sub(started.elapsed())
                .min(TX_RECEIPT_TIMEOUT);
            // [RPC #1] Poll for the receipt (no heartbeat watcher). None folds the old
            // timeout + RPC-error arms into the on-chain state poll below.
            match crate::tx::await_receipt(&*self.provider, tx_hash, recv_budget).await {
                Some(receipt) => {
                    if receipt.status() {
                        self.commit_nonce(nonce);
                        tracing::info!(
                            "claimJobBatch mined: {} job(s) submitted, tx {:?}",
                            ids.len(), receipt.transaction_hash
                        );
                        return Ok(());
                    }
                    // Whole-batch revert (EmptyBatch, or an outer-level failure — NOT a
                    // per-job sub-claim, which is isolated and doesn't revert the tx).
                    self.commit_nonce(nonce); // mined revert consumed the nonce
                    anyhow::bail!("claimJobBatch transaction reverted (tx {tx_hash:?})");
                }
                None => {
                    tracing::warn!(
                        "claimJobBatch receipt not confirmed (attempt {attempt}/{MAX_ATTEMPTS}, tx {tx_hash:?}); \
                         polling state before re-broadcast"
                    );
                    // Poll, but never past the wall cap (yield the nonce lane on time).
                    let deadline = (std::time::Instant::now() + Duration::from_secs(20))
                        .min(started + WALL_CAP);
                    while std::time::Instant::now() < deadline {
                        if let Ok(views) = self.get_job_status_views_batch(&ids).await {
                            if any_ours(&views) {
                                // [nonce-review] state signal (≥1 locked), not a receipt for
                                // THIS nonce → abort self-heals; commit could wedge the signer.
                                self.abort_nonce(nonce);
                                tracing::info!("claimJobBatch confirmed via poll (≥1 job locked)");
                                return Ok(());
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(4)).await;
                    }
                }
            }
        }

        // Final on-chain check before declaring failure.
        if let Ok(views) = self.get_job_status_views_batch(&ids).await {
            if any_ours(&views) {
                self.abort_nonce(nonce); // [nonce-review] state signal, not a receipt for THIS nonce
                return Ok(());
            }
        }
        // Gave up; the batch tx didn't confirm as ours → recycle the nonce as a gap so it
        // doesn't wedge higher nonces. (With the distinct-nonce allocator a fulfill/release
        // gets its OWN nonce, so we no longer need to leave this one parked for displacement.)
        self.abort_nonce(nonce);
        anyhow::bail!("claimJobBatch failed after {MAX_ATTEMPTS} attempts (RPC may be dropping txs)")
    }

    /// Idempotent claim: pre-checks on-chain state, re-checks after receipt timeout.
    ///
    /// - Pre-flight: if `prover == self`, treat as already-claimed success.
    /// - Pre-flight: if `prover != ZERO && != self`, return `LostRace` without sending a tx.
    /// - Post-flight: on receipt timeout, poll chain for up to `timeout_check` to
    ///   see if the claim landed. If `prover == self`, treat as success.
    ///
    /// This prevents both double-claim (wasted gas / potential over-commit) and
    /// false-negative "claim failed" on transient RPC timeouts that actually
    /// mined successfully.
    pub async fn claim_job_idempotent(&self, job_id: B256) -> Result<ClaimOutcome> {
        // Pre-flight: check current state.
        if let Ok(view) = self.get_job_status_view(job_id).await {
            if view.prover == self.address {
                tracing::info!("Job {} already held by us — skipping claim tx", job_id);
                return Ok(ClaimOutcome::Claimed);
            }
            if view.prover != Address::ZERO {
                tracing::info!(
                    "Job {} already claimed by {} — skipping claim tx",
                    job_id, view.prover
                );
                return Ok(ClaimOutcome::LostRace);
            }
        }

        // claim_job self-heals nonce errors, re-broadcasts dropped txs, and polls
        // state on timeout. On error, do a final on-chain reconciliation so a claim
        // that actually landed (or a lost race) is reported correctly.
        match self.claim_job(job_id).await {
            Ok(()) => Ok(ClaimOutcome::Claimed),
            Err(e) => {
                if let Ok(view) = self.get_job_status_view(job_id).await {
                    if view.prover == self.address {
                        return Ok(ClaimOutcome::Claimed);
                    }
                    if view.prover != Address::ZERO {
                        return Ok(ClaimOutcome::LostRace);
                    }
                }
                Err(e)
            }
        }
    }

    /// Fulfill a locked job. Robust to a flaky/inconsistent RPC that drops or
    /// hides txs: on a receipt timeout it polls on-chain state, and if the job is
    /// not yet Fulfilled it re-broadcasts with a freshly-fetched nonce and an
    /// escalating tip (so a re-send can replace a stuck tx), up to a few attempts.
    /// A job already Fulfilled on-chain (from a prior attempt that landed but whose
    /// receipt we never saw) is treated as success.
    /// `budget`, if set, caps the total wall time. [#45] The deadline is enforced HERE
    /// (not by an external `tokio::time::timeout` that would DROP this future mid-flight)
    /// so the give-up path always runs and STASHES the pending nonce for `release_job` —
    /// a dropped future would orphan the nonce (permanent gap) and break the handoff.
    pub async fn fulfill_job(
        &self,
        job_id: B256,
        descriptor: JobDescriptor,
        public_values: Bytes,
        proof_bytes: Bytes,
        budget: Option<Duration>,
    ) -> Result<()> {
        const MAX_ATTEMPTS: u32 = 5;
        let fulfill = IHemiProveFulfill::new(self.hemi_prove, &*self.provider);
        let started = std::time::Instant::now();
        // Reserve one DISTINCT nonce and own it across re-broadcasts. Committed on
        // success; recycled (abort) or stashed for release (give-up) at the end.
        let mut nonce = self.reserve_nonce().await?;
        let (base_tip, base_max_fee) = self.base_fees().await;

        for attempt in 1..=MAX_ATTEMPTS {
            // [#45] Enforce the deadline budget in-loop so the give-up/stash path runs.
            if budget.map_or(false, |b| started.elapsed() >= b) {
                tracing::warn!(
                    "fulfillJob budget reached for {} after {} attempt(s) — giving up to release",
                    job_id, attempt - 1
                );
                break;
            }
            // Already Fulfilled? (a prior attempt may have landed on a node whose
            // receipt was invisible to the one we polled.)
            if let Ok(view) = self.get_job_status_view(job_id).await {
                if view.status == 2 {
                    // Already fulfilled. Our reserved nonce may be unused (job fulfilled
                    // before we sent) or consumed (our own tx landed) — recycle it as a
                    // gap either way; if it was actually consumed a reuser hits "nonce too
                    // low" and re-syncs.
                    self.abort_nonce(nonce);
                    tracing::info!("Job {} already Fulfilled on-chain", job_id);
                    return Ok(());
                }
            }

            // Build + send under the nonce lock at the reserved nonce (escalating tip
            // lets a re-broadcast replace a stuck tx at the same nonce).
            let mut bid: Option<(u128, u128, u128)> = None;
            let send_result = {
                let _guard = self.tx_lock.lock().await;
                let mut tx = fulfill
                    .fulfillJob(
                        job_id,
                        descriptor.clone(),
                        public_values.clone(),
                        proof_bytes.clone(),
                    )
                    .nonce(nonce)
                    // Explicit gas limit: the router's settlement preflight (~4.6M)
                    // reverts InsufficientGasForFullSettlement() if eth_estimateGas
                    // under-provisions it (INTERACTION_GUIDE §9).
                    .gas(self.fulfill_gas_limit);
                if base_max_fee > 0 {
                    let (tip, seed_max_fee) = escalated_fees(base_tip, base_max_fee, attempt);
                    // Must exceed anything WE already put at this nonce. A recycled nonce
                    // can carry a give-up claim/release floor, or a heal's >=4x self-transfer,
                    // and this open-loop ladder can never clear those on its own.
                    let max_fee = seed_max_fee;
                    let Some((tip, max_fee)) = fees_over_floor(self, nonce, tip, max_fee)
                    else {
                        // Cap exhausted: no strictly-higher bid exists, so every send from
                        // here is rejected "replacement underpriced". Stop now rather than
                        // burning the attempt ladder against a wall.
                        if let Some(st) = self.nonce_fee_floor_state(nonce) {
                            log_fee_cap_exhausted("fulfillJob", nonce, &st);
                        }
                        self.note_nonce_undisplaceable(nonce);
                        // Leave abort EVIDENCE but do NOT offer the nonce back to
                        // reservers. `abort` would push it to the HEAD of `freed`, and
                        // `reserve_locked` hands the lowest freed nonce out first -- so the
                        // next reserver (preferentially a deadline-critical release) would
                        // draw this same poisoned nonce and bail again, in a loop.
                        // `note_unresolved` writes `aborted_at` only: the gap detector's
                        // branch (B) still nominates the nonce via `recently_aborted`, so
                        // it stays visible and healable, while nothing is handed it.
                        //
                        // BEWARE: the healer this arms is the LIVE watchdog branch (B),
                        // which is consumed UNGATED (client.rs `hole_we_own` and its
                        // `frontier_has_executable_tx` gate are on the SHUTDOWN path only).
                        // So roughly WEDGE_CHECK_TICKS + WEDGE_MIN_PERSIST after this, the
                        // healer will try to evict the resident tx with a self-transfer --
                        // and since that bid now lifts over the uncapped high-water, it
                        // will SUCCEED. That is the intended unwedge, but it does mean a
                        // live tx of ours at this nonce is deliberately displaced.
                        self.note_nonce_unresolved(nonce);
                        bail!("{FEE_CAP_EXHAUSTED} at nonce {nonce} (fulfillJob)");
                    };
                    bid = Some((tip, max_fee, seed_max_fee));
                    tx = tx.max_priority_fee_per_gas(tip).max_fee_per_gas(max_fee);
                }
                tx.send().await
            };

            let pending = match send_result {
                Ok(p) => {
                    // Ratchet on an ACCEPTED send only, so the read above cannot flatten the
                    // ladder (with a floor present, max() would pin every rung to one bid and
                    // a self-displacing re-broadcast would be rejected forever).
                    if let Some((t, m, seed)) = bid {
                        self.note_broadcast_fee(nonce, t, m, seed);
                    }
                    p
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    // [H2] A tx is pending at our nonce (our own re-broadcast, or a stuck
                    // predecessor) → KEEP the nonce so the next attempt's escalated fee
                    // displaces it. Walking forward here orphans the pending fulfill and,
                    // worse, breaks the fulfill→release same-nonce displacement the error
                    // path relies on. The top-of-loop status check confirms if it landed.
                    if is_same_nonce_pending(&msg) {
                        tracing::warn!("fulfillJob replacement at nonce {nonce} (attempt {attempt}/{MAX_ATTEMPTS}): {msg} — bumping fee, keeping nonce");
                        // Give the node a moment before re-bidding. Without this the
                        // whole attempt ladder burns in well under a second, which learns
                        // nothing (the resident tx has not moved) and, during the
                        // 2026-08-14 wedge, produced 327 rejected sends in 4h24m. Linear in
                        // the attempt so a transient collision still clears quickly.
                        tokio::time::sleep(Duration::from_millis(
                            250u64.saturating_mul(attempt as u64),
                        ))
                        .await;
                        continue;
                    }
                    // Genuine nonce mismatch ⇒ re-fetch and retry fast.
                    if is_nonce_error(&msg) {
                        tracing::warn!("fulfillJob nonce error (attempt {attempt}/{MAX_ATTEMPTS}): {msg} — re-syncing");
                        // [nonce-review] Recycle the abandoned nonce so a "nonce too high"
                        // (a gap below us) doesn't leak it; resync then prunes it from the
                        // gap set if it was actually consumed ("nonce too low").
                        self.abort_nonce(nonce);
                        self.resync_nonce().await.ok();
                        // [M3] Don't abort the deadline-critical fulfill on a single
                        // transient re-sync failure; keep the attempt budget and retry.
                        match self.reserve_nonce().await {
                            Ok(n) => nonce = n,
                            Err(e) => tracing::warn!("fulfillJob nonce re-sync failed (attempt {attempt}/{MAX_ATTEMPTS}): {e:#} — retrying"),
                        }
                    } else {
                        tracing::warn!("fulfillJob send failed (attempt {attempt}/{MAX_ATTEMPTS}): {msg}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    continue;
                }
            };
            let tx_hash = *pending.tx_hash();
            tracing::info!(
                "fulfillJob tx sent (attempt {attempt}/{MAX_ATTEMPTS}): {tx_hash:?}, waiting for receipt..."
            );

            // [nonce-review] Bound the receipt wait by the remaining budget so a single
            // 120s TX_RECEIPT_TIMEOUT + 30s poll can't overrun the deadline (the top-of-loop
            // budget check alone would let one iteration run ~150s past it, starting release
            // too late to beat the lock deadline).
            let recv_budget = match budget {
                Some(b) => b.saturating_sub(started.elapsed()).min(TX_RECEIPT_TIMEOUT),
                None => TX_RECEIPT_TIMEOUT,
            };
            // [RPC #1] Poll for the receipt (no heartbeat watcher). None folds the old
            // timeout + RPC-error arms into the on-chain state poll below — a transient 429
            // no longer blind-rebroadcasts a fulfill (which, on a mined revert, is a proof
            // the verifier rejected — only receipt.status() distinguishes that, so we still
            // read it whenever a receipt IS returned).
            match crate::tx::await_receipt(&*self.provider, tx_hash, recv_budget).await {
                Some(receipt) => {
                    if receipt.status() {
                        self.commit_nonce(nonce);
                        tracing::info!("Job fulfilled: {} tx: {:?}", job_id, receipt.transaction_hash);
                        return Ok(());
                    }
                    // A genuine revert (e.g. verifier rejected the proof) — retrying
                    // the same proof won't help. The reverted tx consumed the nonce
                    // on-chain → commit it.
                    self.commit_nonce(nonce);
                    anyhow::bail!("fulfillJob transaction reverted (tx {tx_hash:?})");
                }
                None => {
                    tracing::warn!(
                        "fulfillJob receipt not confirmed (attempt {attempt}/{MAX_ATTEMPTS}, tx {tx_hash:?}); \
                         polling on-chain state before re-broadcast"
                    );
                    // Poll, but never past the budget (start release on time).
                    let mut poll_end = std::time::Instant::now() + Duration::from_secs(30);
                    if let Some(b) = budget {
                        poll_end = poll_end.min(started + b);
                    }
                    while std::time::Instant::now() < poll_end {
                        // [nonce-review r6] Bound the read itself by the remaining poll window
                        // (already budget-clamped) so a slow RPC can't run ~45s past the deadline
                        // budget and start release too late.
                        let call_budget = poll_end.saturating_duration_since(std::time::Instant::now());
                        if let Ok(Ok(view)) =
                            tokio::time::timeout(call_budget, self.get_job_status_view(job_id)).await
                        {
                            if view.status == 2 {
                                // [nonce-review] status==2 = SOME fulfill of ours landed, not
                                // necessarily THIS nonce (an is_nonce_error re-reserve may have
                                // moved us off it). abort self-heals; commit could advance past
                                // an unmined nonce → permanent gap/wedge. (Matches the top-of-loop
                                // already-fulfilled arm.)
                                self.abort_nonce(nonce);
                                tracing::info!("Job {} Fulfilled (confirmed via state poll)", job_id);
                                return Ok(());
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }

        // Final state check before declaring failure — [nonce-review r6] skip it once the
        // budget is spent (go straight to stash+release), and otherwise bound the read by the
        // remaining budget so it can't run ~45s past the deadline.
        let final_budget = budget.map(|b| b.saturating_sub(started.elapsed()));
        if final_budget.map_or(true, |r| !r.is_zero()) {
            let view = match final_budget {
                Some(r) => tokio::time::timeout(r, self.get_job_status_view(job_id)).await.ok().and_then(|x| x.ok()),
                None => self.get_job_status_view(job_id).await.ok(),
            };
            if let Some(view) = view {
                if view.status == 2 {
                    self.abort_nonce(nonce); // [nonce-review] state signal, not a receipt for THIS nonce
                    return Ok(());
                }
            }
        }
        // [#45] Our fulfill tx may still be pending at this nonce. STASH it so the
        // lifecycle error path's release_job for this job re-broadcasts releaseJob at the
        // SAME nonce (with a higher fee) to DISPLACE the stuck fulfill. With the distinct-
        // nonce allocator, release would otherwise reserve a FRESH nonce and queue BEHIND
        // the stuck fulfill → strand. Do NOT abort/commit here (that would recycle or
        // advance past a nonce we still need to displace). If the fulfill actually mined,
        // release's send at N gets "nonce too low" → re-syncs → sees the job Fulfilled.
        self.stash_abandoned_nonce(job_id, nonce);
        anyhow::bail!("fulfillJob failed after {MAX_ATTEMPTS} attempts (RPC may be dropping txs)")
    }

    /// Fulfill a locked job with hashed descriptor (gas efficient).
    ///
    /// UNUSED as of this writing — the lifecycle uses [`Self::fulfill_job`]. Unlike that
    /// path, this does NOT reserve/commit through the shared `next_nonce` cache and does
    /// NOT apply `escalated_fees`, so wiring it into a concurrent lifecycle would let the
    /// gas filler pick a nonce that collides with an in-flight cached one. Before using
    /// it, port over the `reserve_nonce`/`commit_nonce`/`invalidate_nonce` + `base_fees`/
    /// `escalated_fees` treatment from `fulfill_job`.
    pub async fn fulfill_job_hashed(
        &self,
        job_id: B256,
        hashed_descriptor: HashedDescriptor,
        callback_extra_data: Bytes,
        extra_verifier_data: Bytes,
        public_values: Bytes,
        proof_bytes: Bytes,
    ) -> Result<()> {
        let fulfill = IHemiProveFulfill::new(self.hemi_prove, &*self.provider);
        let tx = fulfill.fulfillJobHashed(
            job_id,
            hashed_descriptor,
            callback_extra_data,
            extra_verifier_data,
            public_values,
            proof_bytes,
        );
        let pending = tx.send().await.context("Failed to send fulfillJobHashed tx")?;
        let tx_hash = *pending.tx_hash();
        tracing::info!("fulfillJobHashed tx sent: {:?}, waiting for receipt...", tx_hash);
        let receipt = tokio::time::timeout(TX_RECEIPT_TIMEOUT, pending.get_receipt())
            .await
            .with_context(|| format!("fulfillJobHashed receipt timed out after {TX_RECEIPT_TIMEOUT:?} (tx {tx_hash:?} may still be pending)"))?
            .context("Failed to get fulfillJobHashed receipt")?;

        if !receipt.status() {
            anyhow::bail!("fulfillJobHashed transaction reverted");
        }

        tracing::info!(
            "Job fulfilled (hashed): {} tx: {:?}",
            job_id,
            receipt.transaction_hash
        );
        Ok(())
    }

    /// Release a claimed job (voluntary release, incurs penalty).
    ///
    /// Robust to a flaky/inconsistent RPC in the same way as `fulfill_job`: on a
    /// receipt timeout it polls on-chain state, and if the job is still locked by
    /// us it re-broadcasts at the same nonce with an escalating tip (to displace a
    /// stuck tx), up to a few attempts. Because releasing frees collateral before a
    /// missed deadline strands it permanently, giving up after a single receipt
    /// timeout (the old behaviour) was the exact failure that leaves collateral
    /// locked — mirroring fulfill_job's rebroadcast/poll closes that gap.
    ///
    /// Success is defined as "our lock is gone" (`view.prover != self.address`):
    /// after a release the job reopens (prover cleared) or is reclaimed by another
    /// prover — in every case our collateral is no longer tied to a lock we hold.
    pub async fn release_job(&self, job_id: B256) -> Result<()> {
        self.release_job_with_nonce(job_id, None).await
    }

    /// As [`Self::release_job`], but starts from a nonce the CALLER already reserved.
    ///
    /// The shutdown abandon path releases several jobs concurrently. A single signer's txs
    /// mine in strict NONCE order, so the nonce — not the spawn or send order — is a
    /// release's on-chain priority; reserving inside each task instead orders them by
    /// scheduling and RPC latency, which can put a job with hours of headroom ahead of one
    /// about to strand. Reserving in deadline order and handing the nonce in fixes that.
    /// The caller must recycle (`abort_nonce`) a pre-reserved nonce it never passes here.
    pub async fn release_job_with_nonce(&self, job_id: B256, preassigned: Option<u64>) -> Result<()> {
        const MAX_ATTEMPTS: u32 = 5;
        let fulfill = IHemiProveFulfill::new(self.hemi_prove, &*self.provider);
        // [#45] If a fulfill for THIS job gave up with its tx likely still pending, reuse
        // that EXACT nonce so releaseJob displaces the stuck fulfill (a fresh distinct
        // nonce would queue BEHIND it and strand). Displacing from the start seeds the fee
        // headroom below.
        // [M7] Otherwise reserve a fresh nonce and apply the fulfill-ceiling fee HEADROOM
        // only after we actually observe a stuck same-nonce tx — applying it
        // unconditionally ~doubles the fee on every release and can trip the wallet
        // "insufficient funds" precheck during a base-fee spike → release never lands.
        let (mut nonce, mut displacing) = match self.take_abandoned_nonce(job_id) {
            Some(n) => {
                // The stash WINS (it must displace the stuck fulfill at that exact nonce);
                // recycle the caller's unused pre-reservation so it can't become a gap.
                if let Some(p) = preassigned {
                    self.abort_nonce(p);
                }
                (n, true)
            }
            // [M7] A pre-assigned nonce is a plain reservation, so `displacing` stays false
            // and the fulfill-ceiling fee headroom is still only applied once we observe a
            // stuck same-nonce tx.
            None => match preassigned {
                Some(p) => (p, false),
                None => (self.reserve_nonce().await?, false),
            },
        };
        let (base_tip, base_max_fee) = self.base_fees().await;
        // [D1] Have we actually put a releaseJob on the wire yet? Before that, a
        // `prover == ZERO` read (the job reads OPEN) is NOT proof our lock is gone — a claim
        // still pending and a lagging replica are indistinguishable from a real reopen. That
        // is the rule every other reader applies (`release_and_clean`'s own guard,
        // `classify_reconcile`, recovery), and they all RETAIN the journal breadcrumb on it.
        // This path is the one that DELETES it: our `Ok(())` makes `release_and_clean` drop
        // the breadcrumb, which is the only record that collateral is locked — after which
        // the drain union, the abandon list and the EX_TEMPFAIL exit gate (all
        // `active_jobs ∪ journal`) can never see the lock again. Positive evidence (prover
        // set to a DIFFERENT address) is still accepted immediately.
        let mut broadcast = false;

        for attempt in 1..=MAX_ATTEMPTS {
            // Already released? (a prior attempt landed on a node whose receipt we
            // never saw, or the job was reopened/slashed out from under us). Our lock
            // being gone means our collateral is free — treat as success.
            if let Ok(view) = self.get_job_status_view(job_id).await {
                if view.prover != self.address && (broadcast || view.prover != Address::ZERO) {
                    // Our lock is gone (release landed, or the fulfill we were displacing
                    // actually mined) → success. Recycle the nonce; self-heals if consumed.
                    self.abort_nonce(nonce);
                    tracing::info!("Job {} no longer locked by us (released/reopened)", job_id);
                    return Ok(());
                }
            }

            // Recorded on an ACCEPTED send only (see below).
            let mut bid: Option<(u128, u128, u128)> = None;
            let send_result = {
                let _guard = self.tx_lock.lock().await;
                let mut tx = fulfill.releaseJob(job_id).nonce(nonce);
                if base_max_fee > 0 {
                    // [H2/M5] Once we're displacing a stuck same-nonce tx, seed escalation
                    // ABOVE fulfill's ceiling (it can only be evicted by a strictly higher
                    // fee). Otherwise escalate normally [M7].
                    let headroom = if displacing { FULFILL_ESCALATION_HEADROOM } else { 0 };
                    let (tip, seed_max_fee) =
                        escalated_fees(base_tip, base_max_fee, attempt + headroom);
                    // Lift over anything WE already broadcast at this nonce — mirroring
                    // claim_job. Without it this ladder is OPEN LOOP: it tops out at
                    // attempt 5 + headroom 5 => 1.15^9 ~= 3.52x base, while a nonce-gap heal
                    // bids >= 4x, and 4 / 1.125 = 3.556 > 3.52 — so a release racing a heal
                    // at the same nonce could NEVER clear the replacement threshold. All five
                    // attempts were rejected "replacement underpriced" and the releaseJob
                    // never reached the wire, silently, losing the collateral at the lock
                    // deadline. This is what made every heal-vs-release collision terminal
                    // rather than recoverable.
                    let max_fee = seed_max_fee;
                    let Some((tip, max_fee)) = fees_over_floor(self, nonce, tip, max_fee)
                    else {
                        // Cap exhausted: no strictly-higher bid exists, so every send from
                        // here is rejected "replacement underpriced". Stop now rather than
                        // burning the attempt ladder against a wall.
                        if let Some(st) = self.nonce_fee_floor_state(nonce) {
                            log_fee_cap_exhausted("releaseJob", nonce, &st);
                        }
                        self.note_nonce_undisplaceable(nonce);
                        // Leave abort EVIDENCE but do NOT offer the nonce back to
                        // reservers. `abort` would push it to the HEAD of `freed`, and
                        // `reserve_locked` hands the lowest freed nonce out first -- so the
                        // next reserver (preferentially a deadline-critical release) would
                        // draw this same poisoned nonce and bail again, in a loop.
                        // `note_unresolved` writes `aborted_at` only: the gap detector's
                        // branch (B) still nominates the nonce via `recently_aborted`, so
                        // it stays visible and healable, while nothing is handed it.
                        //
                        // NOTE: unlike the other three arms, this does NOT hand the
                        // nonce to the watchdog as an intended unwedge. This is the
                        // collateral rescue; we move to a fresh nonce and keep driving it.
                        self.note_nonce_unresolved(nonce);
                        // release is the COLLATERAL RESCUE, so a give-up here is not the
                        // same trade as on the other three paths. Unless we are
                        // deliberately displacing a stashed fulfill at this exact nonce,
                        // move to a FRESH nonce and keep going -- mirroring the
                        // `is_nonce_error` arm below, which already handles the same
                        // predicament correctly. A release at M > N is accepted
                        // immediately and cascades the moment the heal at N mines;
                        // bailing instead hands the retry to `recover_claimed_jobs` on a
                        // ~5 min cadence and lets the watchdog evict our own valid,
                        // pre-deadline releaseJob -- which, now that the heal bid wins,
                        // actually succeeds.
                        if !displacing {
                            match self.reserve_nonce().await {
                                Ok(n) => {
                                    nonce = n;
                                    displacing = false;
                                    continue;
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "releaseJob: cap exhausted at {nonce} and no fresh \
                                         nonce available ({e:#})"
                                    );
                                }
                            }
                        }
                        bail!("{FEE_CAP_EXHAUSTED} at nonce {nonce} (releaseJob)");
                    };
                    bid = Some((tip, max_fee, seed_max_fee));
                    tx = tx.max_priority_fee_per_gas(tip).max_fee_per_gas(max_fee);
                }
                tx.send().await
            };

            let pending = match send_result {
                Ok(p) => {
                    broadcast = true; // [D1] a ZERO read may now legitimately be our release
                    // The read above is HALF the mechanism; without this write it is a
                    // regression. With a floor present, `max()` pins every attempt to the
                    // same bid, so a self-displacing re-broadcast after a receipt timeout is
                    // rejected `is_same_nonce_pending` and all five rungs burn identically.
                    // Writing on success restores strict monotonicity — exactly how claim_job
                    // pairs its `fees_over_floor` read with `note_broadcast_fee`.
                    //
                    // Ratchet ONLY on an accepted send: recording a rejected bid would
                    // inflate the floor for a tx that never reached the mempool.
                    if let Some((t, m, seed)) = bid {
                        self.note_broadcast_fee(nonce, t, m, seed);
                    }
                    p
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    // A tx is already pending at THIS nonce (e.g. a stuck fulfill we're
                    // releasing over, or our own re-broadcast). Keep the SAME nonce so
                    // the next attempt's escalated tip DISPLACES it. Re-syncing the nonce
                    // forward here would instead queue the release behind that pending tx,
                    // so it could never mine before the deadline — the exact stranding we
                    // are trying to avoid.
                    if is_same_nonce_pending(&msg) {
                        displacing = true; // [M7] now escalate above fulfill's ceiling
                        tracing::warn!(
                            "releaseJob replacement at nonce {nonce} (attempt {attempt}/{MAX_ATTEMPTS}): {msg} \
                             — bumping tip, keeping nonce"
                        );
                        // Shorter backoff than the other three paths on purpose: this is
                        // the deadline-critical collateral rescue, so the ladder must not
                        // burn instantly (it learns nothing) but also must not dawdle.
                        // ~1.5s total across five attempts, against a lock deadline
                        // measured in hours.
                        tokio::time::sleep(Duration::from_millis(
                            100u64.saturating_mul(attempt as u64),
                        ))
                        .await;
                        continue;
                    }
                    if is_nonce_error(&msg) {
                        tracing::warn!("releaseJob nonce error (attempt {attempt}/{MAX_ATTEMPTS}): {msg} — re-syncing");
                        // [nonce-review] Recycle the abandoned nonce so a "nonce too high"
                        // (a gap below us) doesn't leak it; resync then prunes it from the
                        // gap set if it was actually consumed ("nonce too low").
                        self.abort_nonce(nonce);
                        self.resync_nonce().await.ok();
                        // [M3] Don't abort the whole deadline-critical release on a single
                        // transient re-sync failure; keep the attempt budget and retry.
                        match self.reserve_nonce().await {
                            Ok(n) => {
                                nonce = n;
                                // [M7] A FRESH nonce has nothing of ours to displace, so the
                                // fulfill-ceiling headroom must not carry over. Leaving it set
                                // made attempt 2 bid `escalated_fees(base, 2 + 5)` ~= 2.31x
                                // base against an empty nonce — overpaying on a
                                // deadline-critical tx for no reason, and exactly what the
                                // [M7] note at the top of this function forbids. `displacing`
                                // is re-armed by the `is_same_nonce_pending` arm above if the
                                // new nonce turns out to be occupied too.
                                displacing = false;
                            }
                            Err(e) => {
                                tracing::warn!("releaseJob nonce re-sync failed (attempt {attempt}/{MAX_ATTEMPTS}): {e:#} — retrying");
                            }
                        }
                    } else {
                        tracing::warn!("releaseJob send failed (attempt {attempt}/{MAX_ATTEMPTS}): {msg}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    continue;
                }
            };
            let tx_hash = *pending.tx_hash();
            tracing::info!(
                "releaseJob tx sent (attempt {attempt}/{MAX_ATTEMPTS}): {tx_hash:?}, waiting for receipt..."
            );

            // [RPC #1] Poll for the receipt (no heartbeat watcher). None folds the old
            // timeout + RPC-error arms into the on-chain state poll below.
            match crate::tx::await_receipt(&*self.provider, tx_hash, TX_RECEIPT_TIMEOUT).await {
                Some(receipt) => {
                    if receipt.status() {
                        self.commit_nonce(nonce);
                        tracing::info!("Job released: {} tx: {:?}", job_id, receipt.transaction_hash);
                        return Ok(());
                    }
                    // Genuine revert. releaseJob reverts "At or past deadline" once the
                    // lock deadline passes — retrying won't help, and the reverted tx
                    // consumed the nonce on-chain, so re-sync and bail.
                    self.commit_nonce(nonce); // mined revert consumed the nonce
                    anyhow::bail!("releaseJob transaction reverted (tx {tx_hash:?})");
                }
                None => {
                    tracing::warn!(
                        "releaseJob receipt not confirmed (attempt {attempt}/{MAX_ATTEMPTS}, tx {tx_hash:?}); \
                         polling on-chain state before re-broadcast"
                    );
                    let deadline = std::time::Instant::now() + Duration::from_secs(30);
                    while std::time::Instant::now() < deadline {
                        if let Ok(view) = self.get_job_status_view(job_id).await {
                            if view.prover != self.address {
                                // ABORT, not commit: "our lock is gone" is NOT uniquely our
                                // doing — a keeper's slashAndReopen or another prover's
                                // reclaim clears it too, in which case our releaseJob at
                                // `nonce` never mined and it's a gap to recycle. If our tx
                                // DID land, recycling self-heals (a reuser hits "nonce too
                                // low" → re-syncs). Either way, abort is correct and — unlike
                                // a blunt invalidate — doesn't discard other gaps.
                                self.abort_nonce(nonce);
                                tracing::info!("Job {} released (confirmed via state poll)", job_id);
                                return Ok(());
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }

        // Final state check before declaring failure — our lock may have cleared
        // on the very last broadcast whose receipt we didn't catch. Same [D1] rule: if every
        // attempt failed at `send` (persistent 429s) nothing was broadcast, so a ZERO read
        // here is UNKNOWN, not success.
        if let Ok(view) = self.get_job_status_view(job_id).await {
            if view.prover != self.address && (broadcast || view.prover != Address::ZERO) {
                self.abort_nonce(nonce);
                tracing::info!("Job {} released (confirmed on final check)", job_id);
                return Ok(());
            }
        }
        self.abort_nonce(nonce); // gave up; release didn't confirm → recycle the gap
        anyhow::bail!("releaseJob failed after {MAX_ATTEMPTS} attempts (RPC may be dropping txs)")
    }

    /// Atomic claim-and-fulfill with EIP-712 signature.
    ///
    /// UNUSED as of this writing (the lifecycle claims and fulfills as separate steps).
    /// Same caveat as [`Self::fulfill_job_hashed`]: it bypasses the shared `next_nonce`
    /// cache and the `escalated_fees` re-broadcast logic, so harden it (reserve/commit/
    /// invalidate + escalated fees) before wiring it into the concurrent lifecycle.
    pub async fn claim_and_fulfill_job(
        &self,
        job_id: B256,
        descriptor: JobDescriptor,
        public_values: Bytes,
        proof_bytes: Bytes,
        prover: Address,
        prover_signature: Bytes,
        deadline: U256,
    ) -> Result<()> {
        let fulfill = IHemiProveFulfill::new(self.hemi_prove, &*self.provider);
        let tx = fulfill.claimAndFulfillJob(
            job_id,
            descriptor,
            public_values,
            proof_bytes,
            prover,
            prover_signature,
            deadline,
        );
        let pending = tx.send().await.context("Failed to send claimAndFulfillJob tx")?;
        let tx_hash = *pending.tx_hash();
        tracing::info!("claimAndFulfillJob tx sent: {:?}, waiting for receipt...", tx_hash);
        let receipt = tokio::time::timeout(TX_RECEIPT_TIMEOUT, pending.get_receipt())
            .await
            .with_context(|| format!("claimAndFulfillJob receipt timed out after {TX_RECEIPT_TIMEOUT:?} (tx {tx_hash:?} may still be pending)"))?
            .context("Failed to get claimAndFulfillJob receipt")?;

        if !receipt.status() {
            anyhow::bail!("claimAndFulfillJob transaction reverted");
        }

        tracing::info!(
            "Job claim+fulfill: {} tx: {:?}",
            job_id,
            receipt.transaction_hash
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{escalated_fees, is_nonce_error, is_rate_limit_error, is_same_nonce_pending};

    /// [cheap-1] A FRESH nonce has nothing of ours to displace, so the fulfill-ceiling
    /// headroom must not carry over from a previous nonce. Leaving `displacing` set made
    /// attempt 2 bid `escalated_fees(base, 2 + FULFILL_ESCALATION_HEADROOM)` against an empty
    /// nonce — the overpay [M7] forbids. This pins the arithmetic that made it visible.
    #[test]
    fn headroom_must_not_apply_to_a_fresh_nonce() {
        let (base_tip, base_max) = (1_000u128, 10_000u128);
        // attempt 2 on a nonce we ARE displacing: 5 rungs of headroom on top.
        let (_, displacing_bid) =
            escalated_fees(base_tip, base_max, 2 + super::FULFILL_ESCALATION_HEADROOM);
        // attempt 2 on a fresh nonce: no headroom.
        let (_, fresh_bid) = escalated_fees(base_tip, base_max, 2);
        // Pin the VALUES, not an inequality. `escalated_fees` increments by at least 1 per
        // step, so `displacing_bid > fresh_bid` is a theorem of the function under test — it
        // would hold no matter what FIX 1 did, which is the definition of a tautological
        // assertion. (The previous `> fresh_bid * 2` was worse still: it passed by 0.56% and
        // went red at HEADROOM = 4, hard-pinning a constant this test does not own.)
        assert_eq!(fresh_bid, 11_500, "attempt 2, no headroom: exactly one 15% rung");
        assert_eq!(
            displacing_bid, 23_128,
            "attempt 2 + 5 rungs of headroom — this is what a fresh nonce would have been \
             overcharged before `displacing` was reset"
        );
    }

    /// attempt 1 is the initial send (not a replacement) → base fees unchanged.
    #[test]
    fn escalated_fees_first_attempt_is_base() {
        assert_eq!(escalated_fees(2, 200, 1), (2, 200));
        assert_eq!(escalated_fees(0, 1_000_000_000, 1), (0, 1_000_000_000));
    }

    /// Every re-broadcast must clear geth's 12.5% same-nonce replacement floor on BOTH
    /// fields — including the LAST attempt (the additive schedule failed here at 9.35%).
    #[test]
    fn escalated_fees_clears_replacement_floor_every_attempt() {
        // Large base so integer truncation is negligible; low tip vs high max_fee is
        // the normal L2 case that broke the old additive schedule.
        let base_tip = 1_000_000u128; // 0.001 gwei
        let base_max_fee = 200_000_000_000u128; // 200 gwei
        for attempt in 1..5u32 {
            let (tip_a, max_a) = escalated_fees(base_tip, base_max_fee, attempt);
            let (tip_b, max_b) = escalated_fees(base_tip, base_max_fee, attempt + 1);
            // >= 12.5% higher: new * 1000 >= prev * 1125.
            assert!(
                max_b.saturating_mul(1000) >= max_a.saturating_mul(1125),
                "max_fee attempt {attempt}->{}: {max_a} -> {max_b} under 12.5%",
                attempt + 1
            );
            assert!(
                tip_b.saturating_mul(1000) >= tip_a.saturating_mul(1125),
                "tip attempt {attempt}->{}: {tip_a} -> {tip_b} under 12.5%",
                attempt + 1
            );
        }
    }

    /// Hard floor: even for tiny fees (the integer-truncation band that a naive
    /// `*115/100` under-bumped below the replacement threshold), every attempt is
    /// ≥12.5% over the previous on both fields.
    #[test]
    fn escalated_fees_tiny_fees_still_clear_floor() {
        for base in [8u128, 9, 10, 11, 13, 15, 17, 19, 33, 40, 100] {
            for attempt in 1..=4u32 {
                let (t_a, m_a) = escalated_fees(base, base, attempt);
                let (t_b, m_b) = escalated_fees(base, base, attempt + 1);
                assert!(
                    m_b.saturating_mul(1000) >= m_a.saturating_mul(1125),
                    "base {base} attempt {attempt}->{}: max {m_a}->{m_b} under 12.5%",
                    attempt + 1
                );
                assert!(t_b.saturating_mul(1000) >= t_a.saturating_mul(1125));
            }
        }
    }

    /// A zero-priority-fee chain (tip == 0) still escalates: tip moves strictly up (so
    /// it's never stuck), and max_fee bumps ≥12.5% per attempt.
    #[test]
    fn escalated_fees_zero_tip_still_escalates() {
        let base_max_fee = 50_000_000_000u128;
        let (t1, m1) = escalated_fees(0, base_max_fee, 1);
        let (t2, m2) = escalated_fees(0, base_max_fee, 2);
        assert_eq!(t1, 0);
        assert!(t2 > t1, "tip must strictly increase even from 0");
        assert!(m2.saturating_mul(1000) >= m1.saturating_mul(1125));
    }

    /// Invariant: maxFeePerGas >= maxPriorityFeePerGas for ALL inputs, incl. pathological
    /// base_tip > base_max_fee — a violating tx is rejected by the node.
    #[test]
    fn escalated_fees_max_fee_never_below_tip() {
        for &(t, m) in &[(0u128, 0u128), (5, 3), (100, 100), (u128::MAX, 1), (1, u128::MAX)] {
            for attempt in 1..=5u32 {
                let (tip, max_fee) = escalated_fees(t, m, attempt);
                assert!(max_fee >= tip, "max_fee {max_fee} < tip {tip} at ({t},{m},{attempt})");
            }
        }
    }

    /// Saturating math: no panic at the u128 ceiling.
    #[test]
    fn escalated_fees_saturates_no_panic() {
        let (tip, max_fee) = escalated_fees(u128::MAX, u128::MAX, 5);
        assert_eq!(tip, u128::MAX);
        assert_eq!(max_fee, u128::MAX);
    }

    #[test]
    fn is_rate_limit_error_classification() {
        // [#4] The recovery chunk classifier must recognize the endpoint's 429s so it
        // defers (marks the chunk None) instead of fanning out per-job.
        for msg in [
            "HTTP error 429 with body: ...",
            "server returned an error response: error code -32005: rate limit exceeded",
            "Rate Limit Exceeded",
        ] {
            assert!(is_rate_limit_error(msg), "should be a rate-limit error: {msg:?}");
        }
        // A genuine (non-429) chunk error must NOT be classified as rate-limit (else it
        // skips the per-job fallback that reconciles the one broken chunk).
        for msg in [
            "execution reverted",
            "response size exceeded the limit",
            "connection reset by peer",
        ] {
            assert!(!is_rate_limit_error(msg), "must NOT be a rate-limit error: {msg:?}");
        }
    }

    #[test]
    fn is_nonce_error_classification() {
        // [H2] Only genuine nonce mismatch → is_nonce_error (re-sync). Pending-at-nonce
        // errors are is_same_nonce_pending (keep nonce + escalate), NOT is_nonce_error.
        for msg in [
            "nonce too low",
            "Nonce too high",
            "server error: nonce too low: address 0x..",
        ] {
            assert!(is_nonce_error(msg), "should be a nonce error: {msg:?}");
            assert!(!is_same_nonce_pending(msg), "not a pending error: {msg:?}");
        }
        for msg in [
            "replacement transaction underpriced",
            "ALREADY KNOWN",
            "tx already in mempool",
        ] {
            assert!(is_same_nonce_pending(msg), "should be same-nonce-pending: {msg:?}");
            assert!(!is_nonce_error(msg), "pending is NOT a nonce error (would walk forward): {msg:?}");
        }
        for msg in [
            "execution reverted",
            "insufficient funds for gas * price + value",
            "At or past deadline",
            "",
        ] {
            assert!(!is_nonce_error(msg), "should NOT be a nonce error: {msg:?}");
            assert!(!is_same_nonce_pending(msg), "should NOT be pending: {msg:?}");
        }
    }
}

#[cfg(test)]
mod fees_over_floor_tests {
    use super::*;
    use crate::nonce::FeeFloorState;

    fn st(broadcast_max: u128, cap: u128) -> Option<FeeFloorState> {
        let capped = broadcast_max.min(cap);
        Some(FeeFloorState {
            floor: (0, capped),
            broadcast: (0, broadcast_max),
            cap,
            exhausted: broadcast_max >= cap,
        })
    }

    /// No floor recorded: the caller's own escalated bid passes through untouched.
    #[test]
    fn no_floor_passes_the_bid_through() {
        assert_eq!(fees_over_floor_state(None, 5, 100), Some((5, 100)));
    }

    /// Below the cap: lift over the recorded high-water so the replacement can win.
    #[test]
    fn below_the_cap_lifts_over_the_high_water() {
        // broadcast 1000, cap 8000 -> floor 1000 -> over() = 1125.
        let got = fees_over_floor_state(st(1_000, 8_000), 0, 500).unwrap();
        assert!(got.1 > 1_000, "must strictly exceed what we already broadcast, got {}", got.1);
        assert_eq!(got.1, 1_125);
    }

    /// A caller bid already above the floor wins over the lift.
    #[test]
    fn a_higher_caller_bid_is_preserved() {
        let got = fees_over_floor_state(st(1_000, 8_000), 0, 9_999).unwrap();
        assert_eq!(got.1, 9_999);
    }

    /// AT the cap: exhausted. This is the boundary the livelock sat on.
    #[test]
    fn exactly_at_the_cap_is_exhausted() {
        assert_eq!(fees_over_floor_state(st(8_000, 8_000), 0, 100), None);
    }

    /// Past the cap — the real steady state (~1.04x cap) — is exhausted.
    #[test]
    fn past_the_cap_is_exhausted() {
        assert_eq!(fees_over_floor_state(st(8_332, 8_000), 0, 100), None);
    }

    /// THE LIVELOCK, stated as a property: whatever this returns must be strictly
    /// greater than what is already on the wire. Returning an equal bid is precisely
    /// what produced 327 rejected sends over 4h24m on 2026-08-14.
    #[test]
    fn a_returned_bid_always_strictly_exceeds_the_resident() {
        for broadcast in [1u128, 999, 1_000, 4_000, 7_999, 8_000, 8_332, 100_000] {
            for caller in [0u128, 1, 500, 9_999] {
                if let Some((_, bid)) = fees_over_floor_state(st(broadcast, 8_000), 0, caller) {
                    assert!(
                        bid > broadcast,
                        "bid {bid} does not exceed resident {broadcast} — that is the \
                         rejected-forever fixed point"
                    );
                }
            }
        }
    }
}
