use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionReceipt;
use anyhow::{bail, Context, Result};
use std::time::Duration;

use crate::revert::{ClaimClass, ClaimFailure, ClaimNotSent, FulfilClass, FulfilFailure};
use alloy::eips::BlockId;
use alloy::primitives::aliases::U96;
use alloy::sol_types::SolCall;

/// `JobStatus` values (Types.sol; enums are append-only — compare as integers, tolerate unknowns).
pub const JOB_STATUS_OPEN: u8 = 0;
pub const JOB_STATUS_LOCKED: u8 = 1;
pub const JOB_STATUS_FULFILLED: u8 = 2;
/// `MAX_REOPEN_COUNT` (Constants.sol): a job reopened this many times can no longer be claimed.
pub const MAX_REOPEN_COUNT: u8 = 10;
/// `MAX_JOURNAL_BYTES` (Constants.sol): a fulfil with a longer journal reverts `JournalTooLarge`.
pub const MAX_JOURNAL_BYTES: usize = 32_768;
/// Extra gas per resend after an `InsufficientGasFor*Settlement` revert (the reference daemons'
/// step).
pub const FULFIL_GAS_BUMP: u64 = 1_000_000;
/// Per-attempt receipt wait on the fulfil path: ~1 Hemi block (12 s). An unmined fulfil is
/// re-published, fee-bumped >= 12.5% at the same nonce, about once per missed block (handoff §10) —
/// a slower climb makes holding it out of blocks several times cheaper.
const FULFIL_RECEIPT_WAIT: Duration = Duration::from_secs(14);
/// After an unconfirmed fulfil attempt, how long to poll job state before re-publishing (the next
/// attempt's lock read is a state check too).
const FULFIL_STATE_POLL: Duration = Duration::from_secs(4);
/// A fulfil pending at its fee ceiling can't be bumped: wait this long for it between re-publishes
/// (each re-publish also re-broadcasts it, should a node have dropped it), reading once a block.
const FULFIL_HELD_WAIT: Duration = Duration::from_secs(60);
const FULFIL_HELD_POLL: Duration = Duration::from_secs(12);
/// Wait between reads while a lagging replica's head is still below a block we hold a receipt for.
const LAG_RETRY_WAIT: Duration = Duration::from_secs(2);
/// Per-rung receipt wait and state poll on the RELEASE ladder (~3 blocks + 1). The release window
/// closes at D+G and only the lifecycle's reserved margin is left for it, so each rung must be short
/// enough that several fee-bumped same-nonce rungs fit (see `RELEASE_LADDER_SECS`).
pub(crate) const RELEASE_RECEIPT_WAIT: Duration = Duration::from_secs(36);
/// Per-rung receipt wait on the CLAIM ladder. Every later nonce of this key queues behind an unmined
/// claim (other jobs' fulfils and releases included), so it must climb quickly too.
const CLAIM_RECEIPT_WAIT: Duration = Duration::from_secs(36);
/// After an unconfirmed claim rung, how long to poll job state before re-broadcasting.
const CLAIM_STATE_POLL: Duration = Duration::from_secs(12);
const RELEASE_STATE_POLL: Duration = Duration::from_secs(12);
/// Wall time the whole release ladder can take: MAX_TX_ATTEMPTS rungs of (receipt wait + state
/// poll + a send's RPC round-trips). The lifecycle starts the release at least this long before the
/// release window closes.
pub const RELEASE_LADDER_SECS: u64 = MAX_TX_ATTEMPTS as u64
    * (RELEASE_RECEIPT_WAIT.as_secs() + RELEASE_STATE_POLL.as_secs() + 6);

/// `FulfilFailure::error_name` of a fulfil held by a governance state (nothing was sent).
pub const GOVERNANCE_HOLD_NAME: &str = "GovernanceHold";

/// A governance state that KEEPS a lock (see [`ChainClient::governance_hold`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceHold {
    /// The router or the Registry is paused. Never release: `releaseJob` has no pause gate and would
    /// burn the penalty, while the lock's clock is credited for the pause.
    Paused,
    /// The job's adapter is Disabled: fulfils revert, the lock cannot be slashed, and
    /// `graceRelease` is a penalty-free exit.
    AdapterDisabled,
}

/// A job's clock as zkminer acts on it (see [`ChainClient::job_clock_state`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobClockState {
    /// A pause or a Disabled adapter: the clock is stopped for as long as it lasts, and a full
    /// RESUME_GRACE is credited after it lifts.
    pub hold: Option<GovernanceHold>,
    /// Seconds of RESUME_GRACE still running after a lift (0 = none).
    pub tail: u64,
}

/// The node refused a send because the account cannot cover `gas x maxFee (+ value)`.
pub(crate) fn is_funds_refusal(msg: &str) -> bool {
    msg.to_ascii_lowercase().contains("insufficient funds")
}

/// op-geth's default `--rpc.txfeecap` (1 ETH): a send whose `gasLimit x maxFeePerGas` exceeds it is
/// refused by the RPC.
const TX_FEE_CAP_WEI: u128 = 1_000_000_000_000_000_000;
/// Upper bound on a releaseJob's gas limit, for sizing what the balance can fund.
const RELEASE_GAS_BOUND: u128 = 500_000;

/// How many 12.5% replacement rungs the fulfil ladder leaves free below the per-nonce cap, so a
/// same-nonce `releaseJob` can ALWAYS displace our own pooled fulfil (a release needs a strictly
/// higher bid, and is the only thing that frees the collateral once the fulfil window closes).
const RELEASE_DISPLACE_RUNGS: u32 = 2;

/// A fee decision for the fulfil / release ladders (see [`job_path_bid`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobBid {
    /// Send at this `(tip, max_fee)`.
    Send(u128, u128),
    /// The ladder reached its ceiling: re-publish at the fees ALREADY broadcast at this nonce (the
    /// node answers "already known", or re-pools it if it was dropped) instead of raising further.
    Hold(u128, u128),
    /// No strictly-higher bid is possible within the cap.
    Exhausted,
}

/// The bid for a fulfil (`reserve_rungs = RELEASE_DISPLACE_RUNGS`) or a release displacing our own
/// pooled fulfil (`reserve_rungs = 0`) at a nonce with recorded `state`. The cap is the larger of
/// the nonce's `8 x seed` ratchet cap and the key-wide `ceiling` (handoff §10): an `8 x` cap seeded
/// from a 0.01-gwei tip tops out near 0.14 gwei, which makes holding our fulfil out of blocks cheap.
///
/// `affordable` is the highest `maxFeePerGas` the node will even admit for this send — `min(balance,
/// the RPC's 1-ETH txfeecap) / gasLimit` (handoff §10's effective ceiling). A rung above it is refused,
/// not pooled, so the ladder holds below it instead of sending bids that can only bounce.
fn job_path_bid(
    state: Option<crate::nonce::FeeFloorState>,
    tip: u128,
    max_fee: u128,
    ceiling: u128,
    reserve_rungs: u32,
    affordable: u128,
) -> JobBid {
    let over = |v: u128| v.saturating_add((v / 8).max(1));
    // Hemi orders by TIP: the ceiling (with its reserved release rungs) bounds the tip, and maxFee —
    // only a cap on what we pay, ~2 x baseFee + tip — is bounded by what the node will admit
    // (`affordable`). Bounding maxFee by the ceiling instead would freeze the tip far below it whenever
    // one quote came in with a high maxFee (e.g. a fallback after a failed header read).
    let cap = state.map_or(ceiling, |s| s.cap.max(ceiling));
    let mut tip_limit = cap;
    for _ in 0..reserve_rungs {
        tip_limit = tip_limit / 9 * 8;
    }
    let max_limit = affordable.max(1);
    // The fresh seed comes from `eth_maxPriorityFeePerGas`, which a block-filler can inflate: it is
    // clamped into the limits on EVERY send (a first send included), never allowed to refuse a send or
    // freeze the ladder. Only the replacement floor (what we already broadcast) can exhaust it.
    let Some(s) = state else {
        let m = max_fee.max(tip.min(tip_limit)).min(max_limit).max(1);
        return JobBid::Send(tip.min(tip_limit).min(m), m);
    };
    let floor_tip = over(s.broadcast.0);
    let floor_max = over(s.broadcast.1);
    if floor_tip > tip_limit || floor_max > max_limit {
        if reserve_rungs > 0 && s.broadcast.1 > 0 {
            return JobBid::Hold(s.broadcast.0.min(s.broadcast.1), s.broadcast.1);
        }
        return JobBid::Exhausted;
    }
    let want_tip = tip.max(floor_tip).min(tip_limit);
    let want_max = max_fee.max(floor_max).max(want_tip).min(max_limit);
    JobBid::Send(want_tip.min(want_max), want_max)
}

/// The fee of release rung `attempt` (1-based): from the normal start price up to the key-wide ceiling
/// by the last rung. A release not mined before D+G turns a flat 5% penalty into a 100% slash, its
/// ~225k gas makes even the top rung cheap (~0.001 ETH at 4 gwei), and a ladder that only climbs 15%
/// per rung can be held out of blocks for ~0.016 ETH. A release that mines at once pays the start
/// price, so the climb costs nothing unless someone is actually holding it out.
fn release_rung_fees(base_tip: u128, base_max_fee: u128, attempt: u32, ceiling: u128) -> (u128, u128) {
    let last = MAX_TX_ATTEMPTS.saturating_sub(1).max(1) as f64;
    let step = attempt.saturating_sub(1).min(MAX_TX_ATTEMPTS - 1) as f64;
    let start = base_tip.max(1).min(ceiling.max(1));
    let ratio = (ceiling.max(start) as f64 / start as f64).powf(step / last);
    let tip = ((start as f64) * ratio) as u128;
    let tip = tip.max(start).min(ceiling.max(start));
    // Keep the base-fee headroom of the quote (maxFee = 2 x baseFee + tip).
    let max_fee = base_max_fee.saturating_sub(base_tip).saturating_add(tip).max(tip);
    (tip, max_fee)
}

/// The fulfil gas limit (handoff §7 step 7; `script/lib/FulfillGas.sol` `limit`). The router refuses
/// to start verifying an adapter job unless `gasleft() >= 4,600,000 + callbackGasLimit` (a stored
/// `callbackGasLimit` of 0 means 200,000), so: `2 * CUSTOM_VERIFIER_GAS_LIMIT (2M) +
/// SETTLEMENT_GAS_BUFFER (500k) + 100k + callback + 250k pre-work + 16 * calldata bytes + 8 * journal
/// bytes + 500k margin`. `calldata_len` includes the 4-byte selector. Never size it with
/// `eth_estimateGas` — an estimate shows the seal to the RPC operator.
pub fn fulfill_gas_formula(callback_gas_limit: u32, calldata_len: usize, journal_len: usize) -> u64 {
    const ADAPTER_PREFLIGHT_GAS: u64 = 2 * 2_000_000 + 500_000 + 100_000;
    let cb = if callback_gas_limit == 0 {
        200_000
    } else {
        callback_gas_limit as u64
    };
    ADAPTER_PREFLIGHT_GAS
        + cb
        + 250_000
        + 16 * calldata_len as u64
        + 8 * journal_len as u64
        + 500_000
}

/// What `fulfillJobHashed` takes besides the jobId, journal and seal (HemiProveFulfill.sol at
/// 3bc441dd8; the same entry point on the c8333aa stack). The router rebuilds the job's
/// `descriptorHash` as `keccak256(abi.encode(programId, proofSystemId, callbackContract,
/// assignedProver, tag, inputDataHash, keccak256(callbackExtraData), keccak256(extraVerifierData),
/// expectedJournalHash, journalFields))` — `inputData` is never sent, only its keccak256, while
/// `callbackExtraData` and `extraVerifierData` travel raw and are hashed on-chain — and reverts
/// `InvalidDescriptorHash(stored, rebuilt)` on a mismatch. It then builds a descriptor with
/// `inputData = ""` and the raw extras, and runs `fulfillJob`'s checks (journal cap, binding in every
/// mode, governance gates, gas, verifier, settlement): nothing after the hash check reads `inputData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashedFulfil {
    /// Every descriptor field but the three `bytes`, with `inputDataHash = keccak256(inputData)`;
    /// the binding words verbatim.
    pub hashed: HashedDescriptor,
    pub callback_extra_data: Bytes,
    pub extra_verifier_data: Bytes,
}

impl HashedFulfil {
    /// The hashed form of `d`.
    pub fn from_descriptor(d: &JobDescriptor) -> Self {
        Self {
            hashed: HashedDescriptor {
                programId: d.programId,
                proofSystemId: d.proofSystemId,
                callbackContract: d.callbackContract,
                assignedProver: d.assignedProver,
                tag: d.tag,
                inputDataHash: alloy::primitives::keccak256(&d.inputData),
                expectedJournalHash: d.expectedJournalHash,
                journalFields: d.journalFields,
            },
            callback_extra_data: d.callbackExtraData.clone(),
            extra_verifier_data: d.extraVerifierData.clone(),
        }
    }

    /// The `descriptorHash` the router rebuilds from this (`_hashDescriptorFields`): it must equal
    /// the job's stored one, or the fulfil reverts `InvalidDescriptorHash`.
    pub fn descriptor_hash(&self) -> B256 {
        use alloy::sol_types::SolValue;
        let h = &self.hashed;
        alloy::primitives::keccak256(
            (
                h.programId,
                h.proofSystemId,
                h.callbackContract,
                h.assignedProver,
                h.tag,
                h.inputDataHash,
                alloy::primitives::keccak256(&self.callback_extra_data),
                alloy::primitives::keccak256(&self.extra_verifier_data),
                h.expectedJournalHash,
                h.journalFields,
            )
                .abi_encode(),
        )
    }
}

/// The `fulfillJobHashed` calldata (selector included) — what [`ChainClient::fulfill_job_hashed`]
/// sends and what its DA estimate and gas limit are sized from.
pub fn fulfill_job_hashed_calldata(
    job_id: B256,
    fulfil: &HashedFulfil,
    public_values: &[u8],
    proof_bytes: &[u8],
) -> Bytes {
    IHemiProveFulfill::fulfillJobHashedCall {
        jobId: job_id,
        hashedDesc: fulfil.hashed.clone(),
        callbackExtraData: fulfil.callback_extra_data.clone(),
        extraVerifierData: fulfil.extra_verifier_data.clone(),
        publicValues: Bytes::copy_from_slice(public_values),
        proofBytes: Bytes::copy_from_slice(proof_bytes),
    }
    .abi_encode()
    .into()
}

/// The fulfil entry point one send uses.
#[derive(Debug, Clone)]
enum FulfilCall {
    /// `fulfillJob(jobId, descriptor, publicValues, proofBytes)`.
    Full(JobDescriptor),
    /// `fulfillJobHashed(jobId, hashedDesc, callbackExtraData, extraVerifierData, publicValues,
    /// proofBytes)`: `inputData` stays out of the calldata.
    Hashed(HashedFulfil),
}

impl FulfilCall {
    fn name(&self) -> &'static str {
        match self {
            FulfilCall::Full(_) => "fulfillJob",
            FulfilCall::Hashed(_) => "fulfillJobHashed",
        }
    }

    fn proof_system_id(&self) -> B256 {
        match self {
            FulfilCall::Full(d) => d.proofSystemId,
            FulfilCall::Hashed(f) => f.hashed.proofSystemId,
        }
    }

    fn calldata(&self, job_id: B256, public_values: &Bytes, proof_bytes: &Bytes) -> Bytes {
        match self {
            FulfilCall::Full(d) => IHemiProveFulfill::fulfillJobCall {
                jobId: job_id,
                descriptor: d.clone(),
                publicValues: public_values.clone(),
                proofBytes: proof_bytes.clone(),
            }
            .abi_encode()
            .into(),
            FulfilCall::Hashed(f) => fulfill_job_hashed_calldata(job_id, f, public_values, proof_bytes),
        }
    }
}

/// The DA throttle rules a hashed fulfil is sent under (witness-construction-jobs §5.5; see
/// [`ChainClient::fulfill_job_hashed`]).
#[derive(Clone)]
pub struct FulfilDa {
    pub rule: crate::da::NonceRuleConfig,
    /// Where the backlog readings come from (the miner's shared [`crate::da::BacklogReader`]).
    pub backlog: crate::da::BacklogSource,
}

/// How many filler self-transfers one fulfil may spend to go out as the highest pending nonce
/// before it is sent anyway (the stuck detector then bounds what a filtered one costs).
const DA_MAX_FILLS: u32 = 3;

/// One hashed fulfil's DA state across its send loop.
struct DaRun<'a> {
    cfg: &'a FulfilDa,
    /// The exact fulfil's estimated DA bytes ([`crate::da::estimate_fulfil_da_bytes`]).
    est: u64,
    large: bool,
}

/// The stuck detector's step inside the send loop.
enum DaStep {
    Continue,
    /// Replaced by a self-transfer: hold, re-send once the throttle clears.
    Replaced(String),
    /// The fulfil settled meanwhile.
    Fulfilled,
    /// A replacement was due and could not be made.
    Failed(String),
}

/// The exact claim floors for one job, read at ONE mined block (handoff §7 step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimQuote {
    /// The mined block both reads were pinned to.
    pub block: u64,
    /// `eth_call` of `claimJob(jobId, 0, 0)` from our prover at `block` — the price a claim
    /// included now settles at. Raised to the job's high-water mark before a send.
    pub price_floor: u128,
    /// `getPremiumCap(jobId)` at `block` (0 on a competitive job). Never ratcheted.
    pub premium_floor: u128,
}

/// [`ChainClient::preview_claim`]'s answer when the quote didn't revert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimPreview {
    /// A claim sent now would go out at these floors.
    Claimable(ClaimQuote),
    /// Some prover (possibly us) already holds the job.
    Held(Address),
}

/// A lock confirmed on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimReceipt {
    /// The block the lock is known at — the claim receipt's, or the block a pre-existing lock was
    /// read at. Every later read that decides whether to publish a proof is pinned at or after it.
    pub block: u64,
    /// `JobClaimed.settledPrice` from OUR receipt (`None` for a lock found pre-existing / by poll).
    pub settled_price: Option<u128>,
}

/// Per-job claim-price high-water mark (handoff §10 "Claim floors"): the highest `priceFloor` we
/// have sent for a job. Never claim below it — a lower quote (a lagging replica, a reorg) is a reason
/// to WAIT, never to chase the price down. Forgotten on our own lock, a terminal job, or 10 reopens.
/// Process-wide, bounded like the run loop's other per-job maps.
static CLAIM_HIGH_WATER: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<B256, u128>>,
> = std::sync::OnceLock::new();
const CLAIM_HIGH_WATER_CAP: usize = 100_000;

fn claim_high_water() -> &'static std::sync::Mutex<std::collections::HashMap<B256, u128>> {
    CLAIM_HIGH_WATER.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// The floor to send for `job_id` given a fresh quote: the quote itself, recorded as the new
/// high-water mark — or, if the live price has fallen BELOW the mark, a typed `Wait` refusal (a
/// claim at the mark would revert `ClaimBelowFloor`; a claim below it is chasing the price down).
fn claim_floor_with_high_water(job_id: B256, quoted: u128) -> Result<u128> {
    let mut m = claim_high_water()
        .lock()
        .map_err(|_| anyhow::anyhow!("claim high-water map poisoned"))?;
    let hw = m.get(&job_id).copied().unwrap_or(0);
    if quoted < hw {
        return Err(ClaimFailure {
            class: ClaimClass::Wait,
            reason: format!("live price {quoted} is below our high-water floor {hw}"),
            definitely_not_locked: true,
            block: None,
        }
        .into());
    }
    if m.len() >= CLAIM_HIGH_WATER_CAP && !m.contains_key(&job_id) {
        if let Some(k) = m.keys().next().copied() {
            m.remove(&k);
        }
    }
    m.insert(job_id, quoted);
    Ok(quoted)
}

/// Forget a job's claim high-water mark (our own lock, a terminal job, or 10 reopens).
pub fn forget_claim_high_water(job_id: B256) {
    if let Ok(mut m) = claim_high_water().lock() {
        m.remove(&job_id);
    }
}

fn claim_not_sent(msg: String) -> anyhow::Error {
    ClaimNotSent(crate::programs::sanitize_log(&msg)).into()
}

/// A typed [`ClaimFailure`] from a call error carrying revert data; an untyped (ambiguous) error for
/// a transport failure with none. `block` is the mined block the call was evaluated at, if known.
fn claim_failure_from_call(
    e: &alloy::contract::Error,
    definitely_not_locked: bool,
    block: Option<u64>,
) -> anyhow::Error {
    match crate::revert::revert_data_of(e) {
        Some(data) => {
            let d = crate::revert::decode(&data);
            ClaimFailure {
                class: crate::revert::classify_claim(&d),
                reason: d.name(),
                definitely_not_locked,
                block,
            }
            .into()
        }
        None => anyhow::anyhow!(
            "claimJob call failed: {}",
            crate::programs::sanitize_log(&format!("{e:#}"))
        ),
    }
}

/// `JobClaimed.settledPrice` from OUR claim receipt: a router-emitted `JobClaimed(jobId, prover = us,
/// …)` log. `None` if absent (then the lock is confirmed by the `jobs()` re-read alone).
fn receipt_job_claimed(
    receipt: &TransactionReceipt,
    job_id: B256,
    prover: Address,
    router: Address,
) -> Option<u128> {
    use alloy::sol_types::SolEvent;
    receipt.inner.logs().iter().find_map(|log| {
        let t = log.topics();
        if log.inner.address != router
            || t.first() != Some(&zkminer_contracts::bindings::IHemiProveCore::JobClaimed::SIGNATURE_HASH)
            || t.get(1) != Some(&job_id)
            || t.get(2) != Some(&prover.into_word())
        {
            return None;
        }
        let data = log.data().data.as_ref();
        (data.len() >= 32).then(|| U256::from_be_slice(&data[..32]).to::<u128>())
    })
}

/// topic0 of the `JobFulfilled` event (see `bindings.rs`), computed like monitor.rs's other
/// canonical topics so a change to the event signature is caught by a test rather than
/// silently breaking the match.
fn job_fulfilled_topic0() -> B256 {
    alloy::primitives::keccak256(
        "JobFulfilled(bytes32,address,address,uint96,uint96,uint256,uint256,uint256,uint256,uint64,bytes)",
    )
}

/// Did this receipt's OWN logs record a `JobFulfilled(jobId, …)` emitted BY THE ROUTER for `job_id`?
///
/// Reading the mined transaction's logs is race-free, unlike a follow-up `getJobStatusView` which a
/// load-balanced RPC can serve from a block BEFORE the tx mined (showing the stale pre-fulfill
/// Locked state). A submitter-controlled callback that rejects makes `fulfillJob` mine successfully
/// (receipt.status() == true) WITHOUT fulfilling the job — so the mined receipt alone is not proof
/// of fulfillment; the emitted event is.
///
/// The emitter address MUST be checked: the submitter's callback contract runs INSIDE the
/// fulfillJob tx and can emit a counterfeit `JobFulfilled(jobId, …)` log from its own address. Only
/// a log emitted by the HemiProve router (`expected_emitter`) is authentic, so matching on topics
/// alone would let a rejecting callback forge "fulfilled" and walk the job into a slash.
fn receipt_fulfilled_this_job(
    receipt: &TransactionReceipt,
    job_id: B256,
    expected_emitter: Address,
) -> bool {
    receipt
        .inner
        .logs()
        .iter()
        .any(|log| log_is_authentic_fulfilled(log.inner.address, log.topics(), job_id, expected_emitter))
}

/// Pure predicate (testable without a TransactionReceipt): a log is an authentic `JobFulfilled` for
/// `job_id` iff it was emitted BY the router (`expected_emitter`) with topic0 == JobFulfilled and
/// topic1 == job_id. The emitter check is what defeats a submitter callback forging the event.
fn log_is_authentic_fulfilled(
    emitter: Address,
    topics: &[B256],
    job_id: B256,
    expected_emitter: Address,
) -> bool {
    emitter == expected_emitter
        && topics.first() == Some(&job_fulfilled_topic0())
        && topics.get(1) == Some(&job_id)
}
use zkminer_contracts::bindings::{
    HashedDescriptor, IHemiProveAux, IHemiProveCore, IHemiProveFulfill, IHemiProveRegistry,
    JobDescriptor, JobRecord, JobStatusView,
};

// Explicit gas on the single claimJob so GasFiller sees a limit and both
// fee fields set → it skips the eth_estimateGas that otherwise fires back-to-back with the
// send (up to 5x under retry, and a 429-fragile abort point) in the claim burst window.
// claimJob is a fixed, loop-free path measured at ~144k; 300k is >2x headroom, refunded if
// unused. (releaseJob deliberately does NOT set one —
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
/// The bid is logged because a fee-cap give-up is diagnosable only by re-deriving the
/// arithmetic from the cap: without the actual fee values on the wire, an operator sees
/// only a stream of rejected sends and has no number to reason from. Never make an
/// operator infer the number that was actually on the wire.
fn log_fee_cap_exhausted(what: &str, nonce: u64, state: &crate::nonce::FeeFloorState) {
    tracing::error!(
        "{what} at nonce {nonce}: fee cap EXHAUSTED — already broadcast \
         max_fee={} tip={} against cap={}; no strictly-higher replacement is possible, \
         so giving up instead of re-bidding a fee the node will reject forever. \
         The resident tx must mine or be evicted before this nonce frees.",
        state.broadcast.1,
        state.broadcast.0,
        state.cap,
    );
}

/// Raise `(tip, max_fee)` so it can DISPLACE whatever we last broadcast at `nonce`.
///
/// The escalation ladder is seeded per INVOCATION (`base_fees()` is fetched once per
/// `claim_job`/`fulfill_job` call and `attempt` restarts at 1), so a fresh invocation that
/// recycles a nonce through `freed` restarts at the UNBUMPED base and cannot clear the
/// node's replacement threshold against a resident tx left at a previous invocation's top
/// attempt. That makes the retry loop arithmetically non-terminating and wedges the signer.
/// Anchoring the floor to the NONCE fixes it: every send at that nonce is strictly above
/// the last one, whoever sends it.
///
/// `REPLACEMENT_BUMP_NUM/DEN` is the margin over the recorded high-water. geth's default
/// replacement rule needs +10%; 12.5% (= `+ v/8`) clears it with room for rounding, and
/// matches the floor already used inside `escalated_fees`.
/// Lift `(tip, max_fee)` over the recorded per-nonce floor so a re-broadcast can
/// displace whatever we last put at this nonce.
///
/// Returns `None` when the ratchet cap is EXHAUSTED — no strictly-higher bid is
/// possible, so any send would be rejected `replacement transaction underpriced`
/// every time. Callers must stop rather than spin: re-bidding a losing fee is rejected
/// forever, and the spin can strand locked collateral at the lock deadline.
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
    // exhaustion too -- a send at such a bid is rejected "replacement underpriced".
    if bid.1 <= state.broadcast.1 && state.broadcast.1 > 0 {
        return None;
    }
    Some(bid)
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
/// integer truncation. An additive-percentage-point schedule would instead decay as the
/// base grew (13% → 11.5% → 10.3% → 9.35% by attempt 4→5), dropping under geth's 10%
/// floor on the final attempt — which is exactly `release_job`'s same-nonce collateral
/// rescue, and the decay is the *normal* case on low-priority-fee L2s where max_fee
/// dominates the tip. attempt 1 == base fees (the initial send is not a replacement);
/// each further attempt multiplies by 1.15, with a strict +1 floor so a sub-100-wei
/// base still moves.
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

/// A tx is already PENDING at the nonce we're using — a stuck predecessor at
/// this nonce (a fulfill we're releasing over, or our own prior re-broadcast). The
/// correct response is to KEEP the same nonce and ESCALATE the fee so the next
/// attempt DISPLACES it. Re-syncing the nonce forward here instead queues the new tx
/// BEHIND the stuck one → it can never mine before the deadline → strand. This must be
/// checked BEFORE is_nonce_error.
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
/// forward on those breaks the fulfill→release same-nonce displacement.
fn is_nonce_error(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("nonce too low") || m.contains("nonce too high")
}

/// Attempts every tx path gives its send ladder.
///
/// A single constant shared by all tx paths, not a copy per path: the backoff tests assert
/// properties of the whole ladder, and a private per-path copy would let a path's real attempt
/// count drift from the number the tests check. The per-attempt waits are likewise single-sourced
/// through `nonce_retry_backoff` and the two unit constants — both arms of every ladder, not just
/// the `is_nonce_error` ones.
pub const MAX_TX_ATTEMPTS: u32 = 5;

/// Backoff unit for a rejected nonce on the claim/fulfil paths.
const NONCE_RETRY_UNIT: Duration = Duration::from_millis(250);

/// Wait after a send failure that is NOT about the nonce — a 429, a connection reset, an RPC
/// hiccup. Longer than the nonce units because the condition is the endpoint, not our bookkeeping.
///
/// Skipped on the final attempt, like the nonce arms. Without that skip, a 5s wait on every rung
/// lets `releaseJob` spend up to 25s asleep — more than half of `RELEASE_JOIN_BUDGET` on a
/// supervised stop, spent sleeping rather than broadcasting the tx that frees the collateral.
const SEND_FAILURE_RETRY_WAIT: Duration = Duration::from_secs(5);

/// Backoff unit for `releaseJob`, deliberately shorter: it is the collateral rescue, so its
/// ladder must not dawdle — ~1.0s across the four rungs it pays, against a lock deadline measured
/// in hours.
const RELEASE_NONCE_RETRY_UNIT: Duration = Duration::from_millis(100);

/// How long to wait before retrying a send whose nonce the node rejected.
///
/// The invariant this exists to enforce: a nonce-error ladder must never be able to run to
/// completion instantly. A `resync → reserve → continue` loop with no delay lets MAX_ATTEMPTS
/// re-sends burn in microseconds against a node view that has not moved — a livelock that
/// produces a long run of rejected sends while making no progress. Both the
/// `is_same_nonce_pending` arms and the `is_nonce_error` arms must back off, or the untreated
/// arm burns the whole ladder just as fast.
///
/// `progressed` is whether the re-sync actually handed back a DIFFERENT nonce:
///
/// * not progressed (`resync` returned the same number, or `reserve_nonce` failed and we
///   are about to re-send at the number the node just rejected) → full linear backoff. The
///   retry would otherwise re-issue an identical tx against an unchanged view and could
///   learn nothing.
/// * progressed → a FIFTH of the full backoff, not zero and not flat. Zero would still allow
///   the microsecond burn in the case that actually happens with a lagging RPC:
///   `getTransactionCount` reads low, every attempt "progresses" by one nonce, and all five
///   fail just as fast. A flat delay would cap that whole ladder at ~250ms, which gives a
///   lagging replica no chance to catch up on a chain whose blocks are seconds apart — so this
///   grows with the attempt too, totalling ~500ms over the rungs a ladder actually pays (the
///   final attempt's wait is skipped) while still costing a fifth of what repetition costs at
///   every rung.
fn nonce_retry_backoff(attempt: u32, progressed: bool, unit: Duration) -> Duration {
    let full = unit.saturating_mul(attempt);
    if progressed {
        full / 5
    } else {
        full
    }
}

/// Whether an error string is a rate-limit (429) response. Matches the HTTP 429
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
    Claimed(ClaimReceipt),
    /// Someone else already owns (or has released/fulfilled) this job.
    LostRace,
}

/// `claim_job` found the job held by another prover on a read that already includes our claim's
/// nonce: our claim cannot have locked it (an unpinned read showing another prover proves nothing
/// of the kind — a replica behind our claim still shows the job's previous holder).
#[derive(Debug, Clone)]
pub struct ClaimLostRace(pub Address);

impl std::fmt::Display for ClaimLostRace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "claimJob lost race — job taken by {}", self.0)
    }
}
impl std::error::Error for ClaimLostRace {}

/// What we know about where we last saw our own lock on a job (from the job journal): a block at
/// which it read Locked by us, and its reopen count then. See `release_job_with_nonce`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LockSeen {
    pub block: Option<u64>,
    pub reopens: Option<u8>,
}

/// Parsed job data from chain (derived from JobStatusView + events).
#[derive(Debug, Clone, Default)]
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
        let view = aux
            .getJobStatusView(job_id)
            .call()
            .await
            .context("Failed to get job status view")?;
        Ok(view)
    }

    /// `getJobStatusView` read at a block AT OR AFTER `min_block` (waiting while a lagging replica's
    /// head is below it), so a view taken right after our claim cannot show the pre-claim state.
    pub async fn get_job_status_view_at(&self, job_id: B256, min_block: u64) -> Result<JobStatusView> {
        const LAG_RETRIES: u32 = 10;
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        for attempt in 0..LAG_RETRIES {
            let head = self
                .provider
                .get_block_number()
                .await
                .context("getJobStatusView: block number")?;
            if head < min_block {
                if attempt + 1 < LAG_RETRIES {
                    tokio::time::sleep(LAG_RETRY_WAIT).await;
                }
                continue;
            }
            return aux
                .getJobStatusView(job_id)
                .block(BlockId::number(head))
                .call()
                .await
                .context("Failed to get job status view");
        }
        bail!("getJobStatusView({job_id}): RPC head stays below block {min_block} (lagging replica)")
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
        // CHUNK the multicall. A single aggregate3 over a large set (recovery can pass
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
                // allowFailure=TRUE per sub-call. alloy's `add_dynamic`
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
                // Classify the chunk failure. Fanning out one get_job_status_view PER job in
                // the failed chunk would be the exact per-job storm that AMPLIFIES the 429s,
                // so this must not fall back per-job under a rate-limit storm.
                //
                // Classify PRIMARILY on THIS chunk's error being a 429 (not just the global
                // recent-429 meter): a stray unrelated 429 within the window must not
                // reclassify a genuine one-chunk error. Mark ONLY the
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

    /// True if the endpoint rate-limited us within the recent-classify window — a
    /// secondary storm signal used alongside the per-error 429 check.
    fn rate_limited_now(&self) -> bool {
        self.rpc_meter()
            .rate_limited_within(std::time::Duration::from_secs(5))
    }

    /// Get current auction price for a job.
    pub async fn get_current_price(&self, job_id: B256) -> Result<u128> {
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        let price = aux
            .getCurrentPrice(job_id)
            .call()
            .await
            .context("Failed to get current price")?;
        Ok(price.to::<u128>())
    }

    /// The governance-set per-job collateral floor (`MIN_COLLATERAL_AMOUNT`). The
    /// on-chain claim floors `computeCollateral()` with this value, so the miner's
    /// collateral gate must use the SAME floor (not an adapter's `minStake`, which is
    /// the unrelated prover-eligibility total-stake threshold). Constant across
    /// a deployment, so callers fetch it once at startup and cache it.
    pub async fn get_min_collateral_amount(&self) -> Result<u128> {
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        let v = aux
            .MIN_COLLATERAL_AMOUNT()
            .call()
            .await
            .context("Failed to get MIN_COLLATERAL_AMOUNT")?;
        Ok(v.to::<u128>())
    }

    /// Get current job index (total jobs submitted).
    pub async fn get_job_index(&self) -> Result<u64> {
        let core = IHemiProveCore::new(self.hemi_prove, &*self.provider);
        let index = core
            .jobIndex()
            .call()
            .await
            .context("Failed to get job index")?;
        Ok(index.to::<u64>())
    }

    /// Scan `JobClaimed` events for jobs this miner locked on-chain (topic2 = prover == our
    /// address), within `lookback_blocks` of the chain head and never below the deployment's first
    /// block. Used on startup to find locks from the CHAIN, not local state (handoff §13 test 18):
    /// a crash before the journal write, a cleared journal, another machine. Chunked under RPC
    /// log-range limits; each failed chunk is RETRIED (a skipped window could hide a lock we must
    /// settle or release before D+G), and if one still fails the scan returns an error so the caller
    /// re-runs it rather than trusting a partial answer. The returned ids still need a per-job status
    /// check. `settleBid` also emits `JobClaimed`, so bid-won locks are found too.
    pub async fn find_locked_jobs(&self, lookback_blocks: u64) -> Result<Vec<B256>> {
        let head = self
            .head_block_cached()
            .await
            .context("find_locked_jobs: head block")?;
        let from = head.saturating_sub(lookback_blocks);
        Ok(self.find_locked_jobs_in(from, head).await?.0)
    }

    /// Every jobId with a JobClaimed(prover = us) log in `[from, to]` (floored at the deployment's
    /// first block), and the block the scan covered up to — the cursor for the next incremental scan.
    pub async fn find_locked_jobs_in(&self, from: u64, to: u64) -> Result<(Vec<B256>, u64)> {
        use alloy::rpc::types::Filter;
        const CHUNK: u64 = 9000;
        const CHUNK_TRIES: u32 = 3;
        let head = to;
        let from = from.max(self.scan_from_block.min(head));
        let topic = alloy::primitives::keccak256(
            "JobClaimed(bytes32,address,address,uint96,uint96,uint40)",
        );
        let prover_topic = self.address.into_word();

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
            let mut tries = 0;
            let logs = loop {
                tries += 1;
                match self.provider.get_logs(&filter).await {
                    Ok(l) => break l,
                    Err(e) if tries < CHUNK_TRIES => {
                        tracing::warn!(
                            "find_locked_jobs: get_logs {start}..={end} failed (try {tries}/{CHUNK_TRIES}): {e:#}"
                        );
                        tokio::time::sleep(Duration::from_secs(2 * tries as u64)).await;
                    }
                    Err(e) => {
                        bail!("LOOKBACK-FAILED: JobClaimed scan {start}..={end} failed {CHUNK_TRIES}x: {e:#}")
                    }
                }
            };
            for log in logs {
                // topics: [sig, jobId, prover, operator]
                if let Some(jid) = log.topics().get(1).copied() {
                    if !job_ids.contains(&jid) {
                        job_ids.push(jid);
                    }
                }
            }
            start = end.saturating_add(1);
        }
        Ok((job_ids, head))
    }

    /// Read the router's raw `jobs(jobId)` record at a block AT OR AFTER `min_block`.
    ///
    /// A load-balanced RPC may serve a replica that has not yet seen a block we already hold a
    /// receipt for; reading "latest" there shows the pre-claim state (prover 0) for a lock we own.
    /// Pinning the read to `max(min_block, head)` — and waiting while the head is below `min_block`
    /// — is the handoff's "re-read `jobs(jobId).prover` at a block at or after the receipt's".
    /// Returns the record and the block it was read at.
    pub async fn read_job_record(
        &self,
        job_id: B256,
        min_block: Option<u64>,
    ) -> Result<(JobRecord, u64)> {
        const LAG_RETRIES: u32 = 10;
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        for attempt in 0..LAG_RETRIES {
            let head = self
                .provider
                .get_block_number()
                .await
                .context("jobs(): block number")?;
            if let Some(m) = min_block {
                if head < m {
                    if attempt + 1 < LAG_RETRIES {
                        tokio::time::sleep(LAG_RETRY_WAIT).await;
                    }
                    continue;
                }
            }
            let words = aux
                .jobs(job_id)
                .block(BlockId::number(head))
                .call()
                .await
                .context("jobs() read")?;
            let rec = JobRecord::from_words(&words).map_err(|e| anyhow::anyhow!(e))?;
            return Ok((rec, head));
        }
        bail!(
            "jobs({job_id}): RPC head stays below block {} (lagging replica)",
            min_block.unwrap_or_default()
        )
    }

    /// Read `jobs(jobId)` at a block that already INCLUDES our transaction at `nonce` — i.e. where
    /// our account nonce is past it. Whatever our tx at `nonce` did (a claim that locked, a revert),
    /// the record read there reflects it, so a "not ours" answer is authoritative about that tx. Used
    /// when a later claim attempt is refused after an earlier one was broadcast: the refusal alone
    /// (`JobNotOpen`) cannot tell our own lock from someone else's.
    pub async fn read_job_record_after_nonce(&self, job_id: B256, nonce: u64) -> Result<(JobRecord, u64)> {
        const NONCE_RETRIES: u32 = 10;
        for attempt in 0..NONCE_RETRIES {
            let head = self
                .provider
                .get_block_number()
                .await
                .context("jobs(): block number")?;
            let count = self
                .provider
                .get_transaction_count(self.address)
                .block_id(BlockId::number(head))
                .await
                .context("jobs(): account nonce")?;
            if count > nonce {
                return self.read_job_record(job_id, Some(head)).await;
            }
            if attempt + 1 < NONCE_RETRIES {
                tokio::time::sleep(LAG_RETRY_WAIT).await;
            }
        }
        bail!("jobs({job_id}): our tx at nonce {nonce} is not yet included (pending or lagging replica)")
    }

    /// The governance state that makes a lock KEPT rather than fulfilled or released (handoff §9,
    /// §11), read at ONE block: the router or the Registry paused (every fulfil reverts; the lock's
    /// clock is credited), or the job's adapter Disabled (fulfils revert `AdapterDisabled`; the lock
    /// cannot be slashed and `graceRelease` is a penalty-free exit). `None` = no hold.
    pub async fn governance_hold(&self, proof_system_id: B256) -> Result<Option<GovernanceHold>> {
        let block = self.provider.get_block_number().await.context("block number")?;
        let at = BlockId::number(block);
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        if aux.paused().block(at).call().await.context("router paused()")? {
            return Ok(Some(GovernanceHold::Paused));
        }
        let reg = IHemiProveRegistry::new(self.hemi_prove_registry, &*self.provider);
        if reg.paused().block(at).call().await.context("Registry paused()")? {
            return Ok(Some(GovernanceHold::Paused));
        }
        if proof_system_id != B256::ZERO {
            let entry = reg
                .getAdapter(proof_system_id)
                .block(at)
                .call()
                .await
                .context("Registry getAdapter")?;
            // AdapterStatus: 0 Unregistered, 1 Active, 2 Deprecated, 3 Disabled.
            if entry.status == 3 {
                return Ok(Some(GovernanceHold::AdapterDisabled));
            }
        }
        Ok(None)
    }

    /// Seconds of RESUME_GRACE still running on a job's clock (0 when none): the base clock's (after a
    /// router or Registry lift) or the job's adapter key clock's (after the adapter is re-enabled — a
    /// key lift does not move the base anchor). For that long job-local time stays frozen, so a job's
    /// `cutoff - now` does not shrink and `getJobStatusView.lockDeadline` (credit so far) understates
    /// the real cutoff by up to this much. Both clocks are read at ONE block.
    pub async fn resume_grace_tail_secs(&self, proof_system_id: B256) -> Result<u64> {
        let block = self
            .provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await
            .context("resume grace: latest block")?
            .ok_or_else(|| anyhow::anyhow!("resume grace: no latest block"))?;
        let at = BlockId::number(block.header.number);
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        let union = aux.getUnionClock().block(at).call().await.context("getUnionClock")?;
        let mut grace_end = union.u.anchor.to::<u64>();
        if proof_system_id != B256::ZERO {
            let key = aux
                .getKeyClock(proof_system_id)
                .block(at)
                .call()
                .await
                .context("getKeyClock")?;
            // While a window is ACTIVE `a` is its start, not a grace end.
            if !key.active {
                grace_end = grace_end.max(key.a.to::<u64>());
            }
        }
        Ok(grace_end.saturating_sub(block.header.timestamp))
    }

    /// The governance hold and the resume-grace tail on a job's clock, read together.
    pub async fn job_clock_state(&self, proof_system_id: B256) -> Result<JobClockState> {
        let hold = self.governance_hold(proof_system_id).await?;
        let tail = self.resume_grace_tail_secs(proof_system_id).await?;
        Ok(JobClockState { hold, tail })
    }

    /// True while a job's clock is NOT consuming its window: a pause or Disabled hold, or a resume grace
    /// after a lift. A budget that looks exhausted then is not actually shrinking, so nothing should be
    /// abandoned or released on it. An unreadable state counts as not stopped.
    pub async fn job_clock_stopped(&self, proof_system_id: B256) -> bool {
        self.job_clock_state(proof_system_id)
            .await
            .is_ok_and(|c| c.hold.is_some() || c.tail > 0)
    }

    /// The psId a job was submitted under (`jobProofSystems`; zero once fulfilled).
    pub async fn job_proof_system(&self, job_id: B256) -> Result<B256> {
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        aux.jobProofSystems(job_id).call().await.context("jobProofSystems")
    }

    /// `graceRelease(jobId)`: the permissionless, PENALTY-FREE exit for a Locked job whose adapter is
    /// Disabled (HemiProveAux). `Ok(true)`: the lock is gone. `Ok(false)`: the call MINED and reverted
    /// (e.g. `JobExpiredBeforePause` — the lock was already late when the window opened), so retrying
    /// only burns gas. `Err`: not sent or not confirmed — the caller may retry.
    pub async fn grace_release_job(&self, job_id: B256) -> Result<bool> {
        let fulfill = IHemiProveFulfill::new(self.hemi_prove, &*self.provider);
        let nonce = self.reserve_nonce().await?;
        let (tip, max_fee) = self.base_fees().await;
        // Lift over anything already at this (possibly recycled) nonce.
        let (tip, max_fee) = match job_path_bid(
            self.nonce_fee_floor_state(nonce),
            tip,
            max_fee,
            self.fee_ceiling,
            0,
            u128::MAX,
        ) {
            JobBid::Send(t, m) | JobBid::Hold(t, m) => (t, m),
            JobBid::Exhausted => (tip, max_fee),
        };
        let sent = {
            let _guard = self.tx_lock.lock().await;
            let mut tx = fulfill.graceRelease(job_id).nonce(nonce);
            if max_fee > 0 {
                tx = tx.max_priority_fee_per_gas(tip).max_fee_per_gas(max_fee);
            }
            tx.send().await
        };
        let pending = match sent {
            Ok(p) => {
                self.note_broadcast_fee(nonce, tip, max_fee, max_fee);
                p
            }
            Err(e) => {
                self.abort_nonce(nonce);
                // graceRelease carries no explicit gas, so a revert surfaces HERE (gas estimation),
                // not as a mined receipt. A refusal from the contract is an answer: the lock was
                // already late when the window opened (`JobExpiredBeforePause` — it stays slashable),
                // is gone, or the adapter is no longer Disabled. Retrying would loop; the caller's
                // normal path decides.
                if let Some(data) = crate::revert::revert_data_of(&e) {
                    use zkminer_contracts::bindings::IHemiProveErrors::IHemiProveErrorsErrors as E;
                    match crate::revert::decode(&data) {
                        crate::revert::Decoded::Hemi(
                            E::JobExpiredBeforePause(_) | E::JobNotLocked(_) | E::UseGraceReleaseWithDescriptor(_),
                        ) => return Ok(false),
                        crate::revert::Decoded::Message(m) if m == "Adapter not disabled" => return Ok(false),
                        _ => {}
                    }
                }
                let msg = format!("{e:#}");
                if is_funds_refusal(&msg) {
                    self.note_funds_short();
                }
                bail!("graceRelease send failed: {}", crate::programs::sanitize_log(&msg));
            }
        };
        let tx_hash = *pending.tx_hash();
        match crate::tx::await_receipt(&*self.provider, tx_hash, RELEASE_RECEIPT_WAIT).await {
            Some(r) if r.status() => {
                self.commit_nonce(nonce);
                tracing::info!("Job {job_id} grace-released (penalty-free): {tx_hash:?}");
                Ok(true)
            }
            Some(_) => {
                self.commit_nonce(nonce);
                tracing::warn!("graceRelease {tx_hash:?} for {job_id} reverted — not retrying it");
                Ok(false)
            }
            None => {
                if let Ok((rec, at)) = self.read_job_record(job_id, None).await {
                    if rec.prover != self.address {
                        self.settle_nonce(nonce, Some(at)).await;
                        return Ok(true);
                    }
                }
                self.abort_nonce(nonce);
                bail!("graceRelease {tx_hash:?} not confirmed")
            }
        }
    }

    /// `getPremiumCap(jobId)`: the most of the job's speed premium a fulfil can still earn (each
    /// release lowers it, a slash zeroes it).
    pub async fn get_premium_cap(&self, job_id: B256) -> Result<u128> {
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        let cap = aux
            .getPremiumCap(job_id)
            .call()
            .await
            .context("getPremiumCap")?;
        Ok(cap.min(U256::from(u128::MAX)).to::<u128>())
    }

    /// `getJobSnapshots(jobId)` — a job's OWN economics, snapshotted at submit: `(releasePenaltyBps,
    /// minCollateral, collateralBps)` — for many jobs: two Multicall3 requests per 25 jobs, both
    /// pinned at one fresh head. A submitter may set collateralBps up to 50,000 (500%), so the
    /// collateral a claim locks must be sized from this, never a default. `getJobSnapshots` does not revert for a job the serving
    /// node hasn't seen — it answers with the live defaults — so each job's `jobs()` record is read at
    /// the same block, and only a job that exists there gets `Some`. A replica behind that block
    /// fails the pinned call rather than answering for an older state. `None` = unknown for now.
    pub async fn get_job_snapshots_batch(
        &self,
        job_ids: &[B256],
    ) -> Result<Vec<(B256, Option<(u128, u128, u128)>)>> {
        use alloy::providers::MulticallItem;
        const MC_CHUNK: usize = 25;
        if job_ids.is_empty() {
            return Ok(Vec::new());
        }
        let head = self
            .provider
            .get_block_number()
            .await
            .context("getJobSnapshots: block number")?;
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        let clamp = |v: U256| v.min(U256::from(u128::MAX)).to::<u128>();
        let mut out = Vec::with_capacity(job_ids.len());
        for chunk in job_ids.chunks(MC_CHUNK) {
            let mut snaps = self
                .provider
                .multicall()
                .dynamic::<IHemiProveAux::getJobSnapshotsCall>()
                .block(BlockId::number(head));
            let mut recs = self
                .provider
                .multicall()
                .dynamic::<IHemiProveAux::jobsCall>()
                .block(BlockId::number(head));
            for jid in chunk {
                snaps = snaps.add_call_dynamic(aux.getJobSnapshots(*jid).into_call(true));
                recs = recs.add_call_dynamic(aux.jobs(*jid).into_call(true));
            }
            let (snaps, recs) = match (snaps.aggregate3().await, recs.aggregate3().await) {
                (Ok(s), Ok(r)) => (s, r),
                (Err(e), _) | (_, Err(e)) => {
                    tracing::debug!("getJobSnapshots batch at block {head} failed: {e:#}");
                    out.extend(chunk.iter().map(|jid| (*jid, None)));
                    continue;
                }
            };
            for ((jid, snap), rec) in chunk.iter().zip(snaps).zip(recs) {
                let exists = rec
                    .ok()
                    .and_then(|w| JobRecord::from_words(&w).ok())
                    .is_some_and(|r| r.caller != Address::ZERO);
                out.push((
                    *jid,
                    snap.ok().filter(|_| exists).map(|r| {
                        (
                            clamp(r.releasePenaltyBps),
                            clamp(r.minCollateral),
                            clamp(r.collateralBps),
                        )
                    }),
                ));
            }
        }
        Ok(out)
    }

    /// `bidConfigs(jobId).underbidWindow`: non-zero means a COMPETITIVE job (priced by public,
    /// binding descending bids once a round starts). Immutable per job.
    pub async fn get_underbid_window(&self, job_id: B256) -> Result<u64> {
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        let r = aux.bidConfigs(job_id).call().await.context("bidConfigs")?;
        Ok(r.underbidWindow.to::<u64>())
    }

    /// True if the router OR the Registry is paused (handoff §11). While paused, claims and fulfils
    /// revert (`EnforcedPause` / `RegistryPaused`), every lock's effective deadline moves out by the
    /// pause's length, and a pause is NEVER a reason to release.
    pub async fn protocol_paused(&self) -> Result<bool> {
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        if aux.paused().call().await.context("router paused()")? {
            return Ok(true);
        }
        let reg = IHemiProveRegistry::new(self.hemi_prove_registry, &*self.provider);
        reg.paused().call().await.context("Registry paused()")
    }

    /// Whether a `VerifierCallFailed` on a `proof_system_id` job has a GOVERNANCE cause (handoff §9):
    /// the Registry is paused or the adapter is Disabled, read at ONE block. With a cause the lock is
    /// KEPT (time is credited; a penalty-free exit opens); without one the failure is our proof's and
    /// the lock is released. An Unregistered adapter is NOT a cause (release, and alert).
    pub async fn verifier_failure_has_governance_cause(&self, proof_system_id: B256) -> Result<bool> {
        let block = self.provider.get_block_number().await.context("block number")?;
        let at = BlockId::number(block);
        let reg = IHemiProveRegistry::new(self.hemi_prove_registry, &*self.provider);
        if reg.paused().block(at).call().await.context("Registry paused()")? {
            return Ok(true);
        }
        let entry = reg
            .getAdapter(proof_system_id)
            .block(at)
            .call()
            .await
            .context("Registry getAdapter")?;
        // AdapterStatus: 0 Unregistered, 1 Active, 2 Deprecated, 3 Disabled.
        Ok(entry.status == 3)
    }

    /// The exact claim floors for `job_id` (handoff §7 step 3), both read at ONE mined block:
    /// `priceFloor` is the return value of an `eth_call` of `claimJob(jobId, 0, 0)` FROM our prover
    /// address, and `premiumFloor` is `getPremiumCap(jobId)`. Never `minPrice`, `getCurrentPrice`, a
    /// `pending` read or 0. A reverting quote is the claim's own pre-check: it is returned as a typed
    /// [`ClaimFailure`] (`definitely_not_locked`), so the caller can tell a pause or a stake
    /// shortfall from a job that is gone.
    pub async fn quote_claim(&self, job_id: B256) -> Result<ClaimQuote> {
        let block = self
            .provider
            .get_block_number()
            .await
            .map_err(|e| claim_not_sent(format!("claim quote: block number: {e:#}")))?;
        let at = BlockId::number(block);
        let core = IHemiProveCore::new(self.hemi_prove, &*self.provider);
        let price = match core
            .claimJob(job_id, U96::ZERO, U96::ZERO)
            .from(self.address)
            .block(at)
            .call()
            .await
        {
            Ok(p) => p.to::<u128>(),
            // Not yet authoritative: `claim_job_idempotent` re-reads ownership at >= `block` before
            // treating it as "nothing of ours is locked".
            Err(e) if crate::revert::revert_data_of(&e).is_none() => {
                // A transport failure of an eth_call: nothing was sent, nothing is known.
                return Err(claim_not_sent(format!("claim quote: {e:#}")));
            }
            Err(e) => return Err(claim_failure_from_call(&e, true, Some(block))),
        };
        let aux = IHemiProveAux::new(self.hemi_prove, &*self.provider);
        let cap = aux
            .getPremiumCap(job_id)
            .block(at)
            .call()
            .await
            .map_err(|e| claim_not_sent(format!("claim quote: getPremiumCap: {e:#}")))?;
        // premiumFloor is a uint96 argument; the cap is a uint256 view. A cap above uint96 cannot be
        // a real premium (premiums are uint96), so clamp rather than truncate.
        let premium_floor = cap.min(U256::from(U96::MAX)).to::<u128>();
        Ok(ClaimQuote {
            block,
            price_floor: price,
            premium_floor,
        })
    }

    /// What [`Self::claim_job_idempotent`] would meet for `job_id` right now, read without sending
    /// anything (watch-only runs): the same ownership and reopen pre-checks, then the same quote.
    /// A refused quote is returned as the typed [`ClaimFailure`] the claim would have hit.
    pub async fn preview_claim(&self, job_id: B256) -> Result<ClaimPreview> {
        // An unreadable record skips these pre-checks and goes to the quote, as the real claim does.
        if let Ok((rec, at)) = self.read_job_record(job_id, None).await {
            if rec.prover != Address::ZERO {
                return Ok(ClaimPreview::Held(rec.prover));
            }
            if rec.reopen_count >= MAX_REOPEN_COUNT {
                return Err(ClaimFailure {
                    class: ClaimClass::Gone,
                    reason: format!(
                        "job at {} reopens (MaxReopenCountReached)",
                        rec.reopen_count
                    ),
                    definitely_not_locked: true,
                    block: Some(at),
                }
                .into());
            }
        }
        Ok(ClaimPreview::Claimable(self.quote_claim(job_id).await?))
    }

    /// Claim an open job at exactly `quote`'s floors. Sent ALONE (never pipelined with a fulfil);
    /// returns only once the lock is confirmed by re-reading `jobs(jobId).prover` at a block at or
    /// after the claim receipt's (handoff §7 step 4 / §10 broadcast rule).
    ///
    /// Errors: a revert (a preflighting node's send-time revert, or a mined revert re-simulated at its
    /// block for the reason) is a typed [`ClaimFailure`] with `definitely_not_locked = true`; anything
    /// else (no receipt, RPC errors) is ambiguous and untyped, so the caller checks ownership on-chain.
    pub async fn claim_job(&self, job_id: B256, quote: &ClaimQuote) -> Result<ClaimReceipt> {
        const MAX_ATTEMPTS: u32 = MAX_TX_ATTEMPTS;
        let core = IHemiProveCore::new(self.hemi_prove, &*self.provider);
        let price_floor = U96::saturating_from(quote.price_floor);
        let premium_floor = U96::saturating_from(quote.premium_floor);

        // Reserve the nonce once and reuse it across re-broadcasts, so a timed-out tx is *replaced*
        // at the same nonce rather than leaving a gap. Committed on success; on any error/give-up the
        // nonce is ABORTED (recycled as a gap for the next reservation).
        let mut nonce = self
            .reserve_nonce()
            .await
            .map_err(|e| claim_not_sent(format!("claim: nonce reservation: {e:#}")))?;
        let (base_tip, base_max_fee) = self.base_fees().await;
        // The highest nonce at which a claimJob of OURS reached the mempool. Once set, a later
        // attempt's refusal (`JobNotOpen`) can be caused by that earlier tx having LOCKED the job,
        // so it is never taken as "nothing locked" without a read at a block that includes it.
        let mut broadcast_nonce: Option<u64> = None;

        for attempt in 1..=MAX_ATTEMPTS {
            let send_result = {
                let _guard = self.tx_lock.lock().await;
                let mut tx = core
                    .claimJob(job_id, price_floor, premium_floor)
                    .nonce(nonce)
                    .gas(CLAIM_JOB_GAS_LIMIT);
                let mut bid = None;
                if base_max_fee > 0 {
                    let (tip, seed_max_fee) = escalated_fees(base_tip, base_max_fee, attempt);
                    // Must exceed anything WE already put at this nonce, even if that came
                    // from an earlier invocation with its own fresh ladder.
                    let Some((tip, max_fee)) = fees_over_floor(self, nonce, tip, seed_max_fee)
                    else {
                        // Cap exhausted: no strictly-higher bid exists, so every send from here is
                        // rejected "replacement underpriced". Leave abort EVIDENCE without handing the
                        // poisoned nonce back to reservers (see `note_nonce_unresolved`); the live
                        // watchdog's gap branch will heal it.
                        if let Some(st) = self.nonce_fee_floor_state(nonce) {
                            log_fee_cap_exhausted("claimJob", nonce, &st);
                        }
                        self.note_nonce_undisplaceable(nonce);
                        self.note_nonce_unresolved(nonce);
                        if broadcast_nonce.is_none() {
                            return Err(claim_not_sent(format!(
                                "{FEE_CAP_EXHAUSTED} at nonce {nonce} (claimJob)"
                            )));
                        }
                        bail!("{FEE_CAP_EXHAUSTED} at nonce {nonce} (claimJob)");
                    };
                    bid = Some((tip, max_fee, seed_max_fee));
                    tx = tx.max_priority_fee_per_gas(tip).max_fee_per_gas(max_fee);
                }
                let r = tx.send().await;
                // Ratchet ONLY on an accepted broadcast: a rejected send never reached the mempool.
                if r.is_ok() {
                    broadcast_nonce = Some(broadcast_nonce.map_or(nonce, |b| b.max(nonce)));
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
                    // A tx is pending at this nonce → keep it and let the next attempt's escalated
                    // fee displace it; do NOT walk the shared nonce forward.
                    if is_same_nonce_pending(&msg) {
                        tracing::warn!(
                            "claimJob replacement at nonce {nonce} (attempt {attempt}/{MAX_ATTEMPTS}): {} — bumping fee, keeping nonce",
                            crate::programs::sanitize_log(&msg)
                        );
                        crate::tx_events::emit(
                            job_id,
                            crate::tx_events::TxKind::Claim,
                            crate::tx_events::TxEvent::SendFailed {
                                attempt,
                                of: MAX_ATTEMPTS,
                                rate_limited: false,
                            },
                        );
                        if attempt < MAX_ATTEMPTS {
                            tokio::time::sleep(nonce_retry_backoff(
                                attempt,
                                false,
                                NONCE_RETRY_UNIT,
                            ))
                            .await;
                        }
                        continue;
                    }
                    // Genuine nonce mismatch: re-sync and take a FRESH distinct nonce.
                    if is_nonce_error(&msg) {
                        tracing::warn!(
                            "claimJob nonce error (attempt {attempt}/{MAX_ATTEMPTS}): {} — re-syncing nonce",
                            crate::programs::sanitize_log(&msg)
                        );
                        crate::tx_events::emit(
                            job_id,
                            crate::tx_events::TxKind::Claim,
                            crate::tx_events::TxEvent::SendFailed {
                                attempt,
                                of: MAX_ATTEMPTS,
                                rate_limited: false,
                            },
                        );
                        // "nonce too low" at a nonce WE broadcast a claim at means that claim MINED.
                        // Read the job where it is included before re-sending at a fresh nonce: if it
                        // locked the job, re-sending would only mine a JobNotOpen revert (and taking
                        // that refusal at face value would drop a lock we hold).
                        if broadcast_nonce == Some(nonce) {
                            if let Ok((rec, at)) = self.read_job_record_after_nonce(job_id, nonce).await {
                                if rec.prover == self.address && rec.status == JOB_STATUS_LOCKED {
                                    self.commit_nonce(nonce);
                                    tracing::info!("Job claimed: {job_id} (an earlier broadcast at nonce {nonce} mined)");
                                    return Ok(ClaimReceipt {
                                        block: at,
                                        settled_price: None,
                                    });
                                }
                                if rec.prover != Address::ZERO && rec.prover != self.address {
                                    self.commit_nonce(nonce);
                                    return Err(ClaimLostRace(rec.prover).into());
                                }
                            }
                        }
                        let rejected = nonce;
                        self.abort_nonce(nonce);
                        self.resync_nonce().await.ok();
                        let mut progressed = false;
                        match self.reserve_nonce().await {
                            Ok(n) => {
                                progressed = n != rejected;
                                nonce = n;
                            }
                            Err(e) => {
                                tracing::warn!("claimJob nonce re-reserve failed: {e:#} — retrying")
                            }
                        }
                        if attempt < MAX_ATTEMPTS {
                            tokio::time::sleep(nonce_retry_backoff(
                                attempt,
                                progressed,
                                NONCE_RETRY_UNIT,
                            ))
                            .await;
                        }
                        continue;
                    }
                    if is_funds_refusal(&msg) {
                        self.note_funds_short();
                    }
                    // A preflighting node rejects a reverting claim at SEND with the revert data.
                    // THIS send locked nothing — but if an earlier attempt of ours was broadcast,
                    // its tx may be the very reason the job is no longer open. Decide from a read
                    // at a block that includes it.
                    let Some(bn) = broadcast_nonce else {
                        // Nothing of ours ever went out → recycle the nonce as a gap.
                        self.abort_nonce(nonce);
                        return Err(claim_failure_from_call(&e, true, None));
                    };
                    let read = self.read_job_record_after_nonce(job_id, bn).await;
                    // This send did not land, but an earlier broadcast at this same nonce may have
                    // mined (and be what locked the job): commit it then, recycle it otherwise.
                    self.settle_nonce(nonce, read.as_ref().ok().map(|(_, at)| *at))
                        .await;
                    return match read {
                        Ok((rec, at)) if rec.prover == self.address && rec.status == JOB_STATUS_LOCKED => {
                            tracing::info!("Job claimed: {job_id} (an earlier broadcast at nonce {bn} mined)");
                            Ok(ClaimReceipt {
                                block: at,
                                settled_price: None,
                            })
                        }
                        Ok((rec, _)) if rec.prover != Address::ZERO => {
                            Err(ClaimLostRace(rec.prover).into())
                        }
                        Ok((_, at)) => Err(claim_failure_from_call(&e, true, Some(at))),
                        // Ownership unknown: keep the breadcrumb (ambiguous).
                        Err(_) => Err(claim_failure_from_call(&e, false, None)),
                    };
                }
            };
            let tx_hash = *pending.tx_hash();
            tracing::info!(
                "claimJob tx sent (attempt {attempt}/{MAX_ATTEMPTS}): {tx_hash:?}, waiting for receipt..."
            );
            crate::tx_events::emit(
                job_id,
                crate::tx_events::TxKind::Claim,
                crate::tx_events::TxEvent::Sent {
                    attempt,
                    of: MAX_ATTEMPTS,
                },
            );

            match crate::tx::await_receipt(&*self.provider, tx_hash, CLAIM_RECEIPT_WAIT).await {
                Some(receipt) => {
                    // A mined tx consumed the nonce either way.
                    self.commit_nonce(nonce);
                    let receipt_block = receipt.block_number.unwrap_or_default();
                    if receipt.status() {
                        let settled = receipt_job_claimed(&receipt, job_id, self.address, self.hemi_prove);
                        if let Some(s) = settled {
                            if s < quote.price_floor {
                                // The router enforces the floor, so this cannot happen unless our
                                // decode or the floor plumbing is wrong — page a human (CANARY).
                                tracing::error!(
                                    "CANARY: job {job_id} settled at {s} below the floor {} we sent",
                                    quote.price_floor
                                );
                            }
                        }
                        // Confirm the lock at a block >= the receipt's (a lagging replica would
                        // otherwise show the pre-claim state for a lock we own). The receipt's own
                        // router-emitted JobClaimed(jobId, us) already PROVES the lock at
                        // `receipt_block`: a read that cannot be completed (a 429, a lagging
                        // replica) must not turn that proven lock into an "ambiguous" failure — the
                        // caller would release it. Every later publish re-reads jobs() at >= this
                        // block anyway. Only a read that SUCCEEDS and disagrees (a reorg) refutes it.
                        let mut confirm = self.read_job_record(job_id, Some(receipt_block)).await;
                        for _ in 0..2 {
                            if confirm.is_ok() {
                                break;
                            }
                            tokio::time::sleep(LAG_RETRY_WAIT).await;
                            confirm = self.read_job_record(job_id, Some(receipt_block)).await;
                        }
                        match confirm {
                            Ok((rec, at)) => {
                                if rec.prover != self.address || rec.status != JOB_STATUS_LOCKED {
                                    bail!(
                                        "claimJob {tx_hash:?} mined but jobs({job_id}) at block {at} shows \
                                         status {} prover {} (reorg?) — ownership unconfirmed",
                                        rec.status,
                                        rec.prover
                                    );
                                }
                                tracing::info!("Job claimed: {job_id} tx: {tx_hash:?} (block {receipt_block})");
                                return Ok(ClaimReceipt {
                                    block: receipt_block.max(at),
                                    settled_price: settled,
                                });
                            }
                            Err(e) if settled.is_some() => {
                                tracing::warn!(
                                    "Job claimed: {job_id} tx: {tx_hash:?} (block {receipt_block}) — the \
                                     confirm read failed ({e:#}); the receipt's JobClaimed proves the lock"
                                );
                                return Ok(ClaimReceipt {
                                    block: receipt_block,
                                    settled_price: settled,
                                });
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    // A mined revert locked nothing AT THIS NONCE. The receipt carries no reason, so
                    // replay the identical call at its block to classify it (its calldata is already
                    // public). It is included at `receipt_block`, after every earlier nonce of ours, so
                    // an ownership read pinned there is authoritative for all of them.
                    let sim = core
                        .claimJob(job_id, price_floor, premium_floor)
                        .from(self.address)
                        .gas(CLAIM_JOB_GAS_LIMIT)
                        .block(BlockId::number(receipt_block))
                        .call()
                        .await;
                    return Err(match sim {
                        Err(e) => claim_failure_from_call(&e, true, Some(receipt_block)),
                        Ok(_) => ClaimFailure {
                            class: ClaimClass::Unknown,
                            reason: format!(
                                "claimJob {tx_hash:?} reverted but replays cleanly at block {receipt_block}"
                            ),
                            definitely_not_locked: true,
                            block: Some(receipt_block),
                        }
                        .into(),
                    });
                }
                None => {
                    // No receipt within budget: the tx may still land. Poll on-chain state
                    // before re-broadcasting (never re-send blindly).
                    tracing::warn!(
                        "claimJob receipt not confirmed (attempt {attempt}/{MAX_ATTEMPTS}, tx {tx_hash:?}); \
                         polling state before re-broadcast"
                    );
                    crate::tx_events::emit(
                        job_id,
                        crate::tx_events::TxKind::Claim,
                        crate::tx_events::TxEvent::Unconfirmed {
                            attempt,
                            of: MAX_ATTEMPTS,
                        },
                    );
                    let deadline = std::time::Instant::now() + CLAIM_STATE_POLL;
                    while std::time::Instant::now() < deadline {
                        if let Ok((rec, at)) = self.read_job_record(job_id, None).await {
                            if rec.prover == self.address && rec.status == JOB_STATUS_LOCKED {
                                // SOME claim of ours landed, not necessarily THIS nonce: commit only
                                // when the mined count is past it, else abort.
                                self.settle_nonce(nonce, Some(at)).await;
                                tracing::info!("Job {} claimed (confirmed via poll)", job_id);
                                return Ok(ClaimReceipt {
                                    block: at,
                                    settled_price: None,
                                });
                            }
                            // Another prover is the answer only at a block that includes our claim's
                            // nonce: before that, our claim may still mine (and lock it later).
                            if rec.prover != Address::ZERO && rec.prover != self.address {
                                let included = self
                                    .provider
                                    .get_transaction_count(self.address)
                                    .block_id(BlockId::number(at))
                                    .await
                                    .is_ok_and(|c| c > broadcast_nonce.unwrap_or(nonce));
                                if included {
                                    self.settle_nonce(nonce, Some(at)).await;
                                    return Err(ClaimLostRace(rec.prover).into());
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(4)).await;
                    }
                }
            }
        }

        // Final on-chain check before declaring failure — at a block that includes our last broadcast
        // claim when there was one, so "another prover" there is the answer.
        let read = match broadcast_nonce {
            Some(bn) => self.read_job_record_after_nonce(job_id, bn).await,
            None => self.read_job_record(job_id, None).await,
        };
        if let Ok((rec, at)) = read {
            if rec.prover == self.address && rec.status == JOB_STATUS_LOCKED {
                self.settle_nonce(nonce, Some(at)).await;
                return Ok(ClaimReceipt {
                    block: at,
                    settled_price: None,
                });
            }
            if rec.prover != Address::ZERO && rec.prover != self.address {
                self.settle_nonce(nonce, Some(at)).await;
                return Err(ClaimLostRace(rec.prover).into());
            }
        }
        self.abort_nonce(nonce);
        anyhow::bail!("claimJob failed after {MAX_ATTEMPTS} attempts (RPC may be dropping txs)")
    }

    /// Idempotent claim: pre-checks on-chain state, quotes the exact floors, applies the per-job
    /// price high-water mark, claims, and reconciles an ambiguous failure against the chain.
    ///
    /// - Already locked by us → `Claimed` without a tx. Held by someone else → `LostRace`.
    /// - A typed [`ClaimFailure`] from the quote or the claim is returned as-is: `Wait` (incl. a live
    ///   price below our high-water mark), `Paused`, `StakeShort`, `Gone`, `Unknown`.
    /// - An ambiguous failure (no receipt) is reconciled by reading `jobs(jobId)`.
    pub async fn claim_job_idempotent(
        &self,
        job_id: B256,
        min_price: u128,
    ) -> Result<ClaimOutcome> {
        if let Ok((rec, at)) = self.read_job_record(job_id, None).await {
            if rec.prover == self.address && rec.status == JOB_STATUS_LOCKED {
                forget_claim_high_water(job_id);
                tracing::info!("Job {} already held by us — skipping claim tx", job_id);
                return Ok(ClaimOutcome::Claimed(ClaimReceipt {
                    block: at,
                    settled_price: None,
                }));
            }
            if rec.prover != Address::ZERO && rec.prover != self.address {
                tracing::info!("Job {} already claimed by {} — skipping claim tx", job_id, rec.prover);
                return Ok(ClaimOutcome::LostRace);
            }
            if rec.reopen_count >= MAX_REOPEN_COUNT {
                forget_claim_high_water(job_id);
                return Err(ClaimFailure {
                    class: ClaimClass::Gone,
                    reason: format!("job at {} reopens (MaxReopenCountReached)", rec.reopen_count),
                    definitely_not_locked: true,
                    block: Some(at),
                }
                .into());
            }
        }

        let quote = match self.quote_claim(job_id).await {
            Ok(q) => q,
            Err(e) => return self.reconcile_claim_refusal(job_id, e).await,
        };
        // A quote below our high-water mark is a Wait refusal like any other: it can come from a
        // replica lagging behind a block where an EARLIER claim of ours already locked the job, so it
        // gets the same pinned ownership re-read before anyone treats it as "nothing locked".
        let price_floor = match claim_floor_with_high_water(job_id, quote.price_floor) {
            Ok(p) => p,
            Err(e) => {
                let e = match e.downcast::<ClaimFailure>() {
                    Ok(f) => ClaimFailure {
                        block: Some(quote.block),
                        ..f
                    }
                    .into(),
                    Err(e) => e,
                };
                return self.reconcile_claim_refusal(job_id, e).await;
            }
        };
        let quote = ClaimQuote { price_floor, ..quote };
        // Below the price the job was judged at: on a competitive job a bid settled and released in
        // between resumes the ramp at the winning bid, and claiming there sells the proof below
        // what was evaluated. (An ascending job's quote only rises.) Wait; the brain decides again.
        if quote.price_floor < min_price {
            return self
                .reconcile_claim_refusal(
                    job_id,
                    ClaimFailure {
                        class: ClaimClass::Wait,
                        reason: format!(
                            "quoted {} below the {} it was evaluated at",
                            quote.price_floor, min_price
                        ),
                        definitely_not_locked: true,
                        block: Some(quote.block),
                    }
                    .into(),
                )
                .await;
        }

        match self.claim_job(job_id, &quote).await {
            Ok(r) => {
                forget_claim_high_water(job_id);
                Ok(ClaimOutcome::Claimed(r))
            }
            Err(e) => {
                if let Some(f) = e.downcast_ref::<ClaimFailure>() {
                    if f.definitely_not_locked {
                        return self.reconcile_claim_refusal(job_id, e).await;
                    }
                }
                if e.downcast_ref::<ClaimLostRace>().is_some() {
                    return Ok(ClaimOutcome::LostRace);
                }
                // Ambiguous: the claim may have mined unseen. Our lock on a read is proof of it;
                // another prover on this unpinned read proves nothing, so that stays ambiguous (the
                // caller keeps the breadcrumb for recovery).
                if let Ok((rec, at)) = self.read_job_record(job_id, None).await {
                    if rec.prover == self.address && rec.status == JOB_STATUS_LOCKED {
                        forget_claim_high_water(job_id);
                        return Ok(ClaimOutcome::Claimed(ClaimReceipt {
                            block: at,
                            settled_price: None,
                        }));
                    }
                }
                Err(e)
            }
        }
    }

    /// A typed claim refusal does not say WHO holds the job: `JobNotOpen` fires for a job Locked by
    /// us (an earlier claim of ours mined; a recovered lock), and `EnforcedPause` fires before any
    /// ownership check. So before a refusal is treated as "nothing of ours is locked" — on which the
    /// lifecycle drops the claim breadcrumb, the only record of a lock — re-read `jobs(jobId)` at or
    /// after the block the refusal was evaluated at. Ours → `Claimed`; someone else's → `LostRace`;
    /// not ours → the refusal stands; unreadable → the refusal is DOWNGRADED to ambiguous
    /// (`definitely_not_locked = false`), which keeps the breadcrumb for an on-chain reconcile.
    async fn reconcile_claim_refusal(&self, job_id: B256, e: anyhow::Error) -> Result<ClaimOutcome> {
        let Some(f) = e.downcast_ref::<ClaimFailure>().cloned() else {
            return Err(e);
        };
        let mut read = self.read_job_record(job_id, f.block).await;
        if read.is_err() {
            tokio::time::sleep(LAG_RETRY_WAIT).await;
            read = self.read_job_record(job_id, f.block).await;
        }
        match read {
            Ok((rec, at)) if rec.prover == self.address && rec.status == JOB_STATUS_LOCKED => {
                forget_claim_high_water(job_id);
                tracing::info!(
                    "Job {job_id}: claim refused ({}) but the job is Locked by us at block {at} — \
                     treating it as our lock",
                    f.reason
                );
                Ok(ClaimOutcome::Claimed(ClaimReceipt {
                    block: at,
                    settled_price: None,
                }))
            }
            // Another prover's lock keeps the mark (handoff/guide: a sybil's settle is such a lock, and
            // the job can come back at its lower price); only a job that can never be claimed again
            // drops it.
            Ok((rec, _)) if rec.prover != Address::ZERO && rec.prover != self.address => {
                Ok(ClaimOutcome::LostRace)
            }
            Ok((rec, _)) => {
                if rec.reopen_count >= MAX_REOPEN_COUNT
                    || (rec.status != JOB_STATUS_OPEN && rec.status != JOB_STATUS_LOCKED)
                {
                    forget_claim_high_water(job_id);
                }
                Err(e)
            }
            Err(re) => Err(ClaimFailure {
                definitely_not_locked: false,
                reason: format!("{} (ownership unconfirmed: {re:#})", f.reason),
                ..f
            }
            .into()),
        }
    }

    /// Fulfil a locked job. Classifies every failure (handoff §9) as a typed [`FulfilFailure`] so the
    /// lifecycle can choose between fixing/releasing (a proof defect), KEEPING the lock (a pause, a
    /// disabled adapter, a pending settlement — time is credited), resending with more gas (handled
    /// here), stopping (the lock is gone, or the window closed) or alerting (anything unclassifiable).
    ///
    /// Before EVERY publish it re-reads `jobs(jobId)` at a block at or after `lock_block` (the claim
    /// receipt's) and refuses to send unless the job is Locked by us, and it holds the send while the
    /// router or Registry is paused: a reverted fulfil still publishes our unbound seal.
    ///
    /// `budget`, if set, caps the total wall time. The deadline is enforced HERE (not by an external
    /// `tokio::time::timeout` that would DROP this future mid-flight) so the give-up path always runs
    /// and STASHES the pending nonce — the next fulfil attempt for this job re-publishes AT THAT SAME
    /// nonce (fee-escalated), and a release displaces it there.
    pub async fn fulfill_job(
        &self,
        job_id: B256,
        descriptor: JobDescriptor,
        public_values: Bytes,
        proof_bytes: Bytes,
        budget: Option<Duration>,
        lock_block: Option<u64>,
    ) -> Result<()> {
        self.fulfill_inner(
            job_id,
            FulfilCall::Full(descriptor),
            public_values,
            proof_bytes,
            budget,
            lock_block,
            None,
        )
        .await
    }

    /// Fulfil a locked job with `fulfillJobHashed`: [`Self::fulfill_job`]'s path (the same lock
    /// checks, governance holds, fee ladder, nonce stash, gas bumps, receipt checks and typed
    /// failures), but `inputData` stays out of the calldata — only its keccak256 travels, in
    /// `fulfil.hashed.inputDataHash` (see [`HashedFulfil`] for the router's semantics). The gas limit
    /// is sized from the hashed calldata. Before publishing, the descriptor hash the router will
    /// rebuild is checked against the job's stored one: a mismatch is a `ProofDefect`
    /// (`InvalidDescriptorHash`) with nothing published.
    ///
    /// With `da`, the DA throttle rules of witness-construction-jobs §5.5 apply:
    /// - the exact transaction's DA size is estimated first ([`crate::da::estimate_fulfil_da_bytes`]);
    /// - a LARGE fulfil (above [`crate::da::STANDARD_FULFIL_DA_BYTES`]) is first sent only as this
    ///   key's highest pending nonce (a lower reserved nonce is spent on a filler self-transfer), and
    ///   held unsent while a reading proves the live DA cap below it;
    /// - while it is unmined, the detector ([`crate::da::NonceRuleConfig::verdict`]) watches the head
    ///   and the safe-head lag; once it is due, the fulfil is replaced at its nonce by a minimal
    ///   self-transfer ([`ChainClient::replace_with_self_transfer`]) and this returns a `Keep`
    ///   [`FulfilFailure`] named [`crate::da::DA_THROTTLE_HOLD_NAME`] (`published`: the seal was
    ///   broadcast). Keep the lock and call this again: it holds (same failure, no nonce touched)
    ///   until [`crate::da::NonceRuleConfig::resend`] lets it re-send at a fresh nonce.
    #[allow(clippy::too_many_arguments)]
    pub async fn fulfill_job_hashed(
        &self,
        job_id: B256,
        fulfil: HashedFulfil,
        public_values: Bytes,
        proof_bytes: Bytes,
        budget: Option<Duration>,
        lock_block: Option<u64>,
        da: Option<&FulfilDa>,
    ) -> Result<()> {
        let out = self
            .fulfill_inner(
                job_id,
                FulfilCall::Hashed(fulfil),
                public_values,
                proof_bytes,
                budget,
                lock_block,
                da,
            )
            .await;
        // A settled job, or a lock that is gone, leaves nothing for the DA rules to track. A held or
        // unconfirmed fulfil (Keep, Unknown) may still be pending: its entries stay.
        let settled = match &out {
            Ok(()) => true,
            Err(e) => e
                .downcast_ref::<FulfilFailure>()
                .is_some_and(|f| !matches!(f.class, FulfilClass::Keep | FulfilClass::Unknown)),
        };
        if settled {
            self.da_book().forget_job(job_id);
        }
        out
    }

    /// The fulfil path shared by [`Self::fulfill_job`] and [`Self::fulfill_job_hashed`].
    #[allow(clippy::too_many_arguments)]
    async fn fulfill_inner(
        &self,
        job_id: B256,
        call: FulfilCall,
        public_values: Bytes,
        proof_bytes: Bytes,
        budget: Option<Duration>,
        lock_block: Option<u64>,
        da: Option<&FulfilDa>,
    ) -> Result<()> {
        const MAX_ATTEMPTS: u32 = MAX_TX_ATTEMPTS;
        const MAX_GAS_BUMPS: u64 = 3;
        let what = call.name();
        let proof_system_id = call.proof_system_id();
        let started = std::time::Instant::now();
        let fail = |class: FulfilClass, error_name: String, reason: String, published: bool| -> anyhow::Error {
            FulfilFailure {
                class,
                error_name,
                reason,
                published,
            }
            .into()
        };
        // Held by governance (a pause, a Disabled adapter): do NOT touch the nonce allocator. Reserving
        // and aborting a nonce on every 30-s round leaves abort evidence at the mined frontier, and the
        // gap watchdog answers it with a >= 2 gwei self-transfer every ~2 minutes for the whole hold,
        // which can last days. Any stashed nonce stays stashed. The lock is still re-read, so a third
        // party's `graceRelease` ends the loop instead of holding for a lock that is gone.
        if let Ok(Some(hold)) = self.governance_hold(proof_system_id).await {
            let was_published = self.has_abandoned_nonce(job_id);
            if let Ok((rec, _)) = self.read_job_record(job_id, lock_block).await {
                if rec.status == JOB_STATUS_FULFILLED && rec.prover == self.address {
                    return Ok(());
                }
                if rec.status != JOB_STATUS_LOCKED || rec.prover != self.address {
                    return Err(fail(
                        FulfilClass::Stale,
                        String::new(),
                        format!(
                            "job is no longer Locked by us (status {}, prover {}) while held",
                            rec.status, rec.prover
                        ),
                        was_published,
                    ));
                }
            }
            return Err(fail(
                FulfilClass::Keep,
                GOVERNANCE_HOLD_NAME.to_string(),
                match hold {
                    GovernanceHold::Paused => "router or Registry paused — holding the fulfil".into(),
                    GovernanceHold::AdapterDisabled => {
                        "the job's adapter is Disabled — holding the fulfil".into()
                    }
                },
                was_published,
            ));
        }
        // The DA throttle rules (witness-construction-jobs §5.5), for a hashed fulfil sent with them:
        // estimate the exact transaction, then gate a re-send after a replacement, or a large
        // fulfil's first send, on a backlog reading. A hold touches no nonce.
        let da_run: Option<DaRun> = match (&call, da) {
            (FulfilCall::Hashed(f), Some(cfg)) => {
                let est = match crate::da::estimate_fulfil_da_bytes(
                    self,
                    job_id,
                    f,
                    &public_values,
                    &crate::da::SealSpec::Exact(proof_bytes.clone()),
                )
                .await
                {
                    Ok(e) => e.estimated_bytes,
                    Err(e) => {
                        let tx = crate::da::conservative_fulfil_tx(
                            self.chain_id,
                            self.hemi_prove,
                            call.calldata(job_id, &public_values, &proof_bytes),
                        );
                        let bound = crate::da::da_bytes_upper_bound(tx.len());
                        tracing::warn!(
                            "{what}: DA estimate for {job_id} failed ({e:#}); using the FastLZ upper \
                             bound, {bound} bytes"
                        );
                        bound
                    }
                };
                let large = est > crate::da::STANDARD_FULFIL_DA_BYTES;
                let replaced = self.da_book().replaced(job_id);
                let stashed = self.has_abandoned_nonce(job_id);
                if replaced.is_some() || (large && !stashed) {
                    let reading = cfg.backlog.read(self).await;
                    let gate = match replaced {
                        Some(r) => {
                            let head = match reading.head {
                                Some(h) => h,
                                None => self.get_block_number().await.unwrap_or(r.head),
                            };
                            cfg.rule
                                .resend(r.head, head, est, reading.backlog, reading.safe_lag_secs)
                        }
                        None => cfg.rule.presend(est, reading.backlog),
                    };
                    if let crate::da::Gate::Hold(why) = gate {
                        tracing::info!("{what} for {job_id} held by the DA throttle: {why}");
                        return Err(fail(
                            FulfilClass::Keep,
                            crate::da::DA_THROTTLE_HOLD_NAME.to_string(),
                            format!("DA throttle: holding the fulfil — {why}"),
                            replaced.is_some() || stashed,
                        ));
                    }
                    if replaced.is_some() {
                        tracing::info!("{what} for {job_id}: the DA throttle cleared — re-sending");
                        self.da_book().clear_replaced(job_id);
                    }
                }
                Some(DaRun { cfg, est, large })
            }
            _ => None,
        };
        // Resume the nonce a previous attempt for THIS job left pending (so the re-publish replaces
        // it at the same nonce instead of queueing behind it), else reserve a fresh one.
        let (mut nonce, resumed) = match self.take_abandoned_nonce(job_id) {
            Some(n) => (n, true),
            None => (self.reserve_nonce().await?, false),
        };
        // A resumed nonce means an earlier attempt already broadcast this job's fulfil.
        let mut published = resumed;
        // DA nonce rule: a large fulfil's first send goes out only as the highest pending nonce. A
        // lower nonce we reserved is spent on a filler self-transfer (siblings hold nonces above it),
        // and a fresh one taken; re-checked under the send lock below.
        let mut fills: u32 = 0;
        if da_run.as_ref().is_some_and(|d| d.large) && !resumed {
            while !self.nonce_is_highest_reserved(nonce) && fills < DA_MAX_FILLS {
                fills += 1;
                if let Err(e) = self.fill_reserved_nonce(nonce).await {
                    tracing::warn!("{e:#}");
                }
                nonce = self.reserve_nonce().await?;
            }
        }
        let (base_tip, base_max_fee) = self.base_fees().await;
        // Read once per invocation: bounds the fee ladder to what the node will admit (see
        // `job_path_bid`). Unknown → unbounded (the node's refusal is then the bound).
        let balance: Option<u128> = self
            .provider
            .get_balance(self.address)
            .await
            .ok()
            .map(|b| b.min(U256::from(u128::MAX)).to::<u128>());
        // The exact calldata of the entry point used: what is sent, replayed, and sized for gas
        // (the hashed form leaves `inputData` out, so its gas formula input is smaller).
        let calldata = call.calldata(job_id, &public_values, &proof_bytes);
        let calldata_len = calldata.len();
        let mut extra_gas: u64 = 0;
        let mut gas_bumps: u64 = 0;

        let mut attempt: u32 = 0;
        while attempt < MAX_ATTEMPTS {
            attempt += 1;
            if budget.is_some_and(|b| started.elapsed() >= b) {
                tracing::warn!(
                    "{what} budget reached for {job_id} after {} attempt(s)",
                    attempt - 1
                );
                break;
            }
            // DA nonce rule: a published large fulfil that stays unmined while the head advances (or
            // the safe-head lag passes its limit) is replaced at its nonce by a self-transfer.
            if let Some(d) = da_run.as_ref().filter(|d| d.large && published) {
                match self.da_stuck_step(job_id, nonce, d).await {
                    DaStep::Continue => {}
                    DaStep::Replaced(why) => {
                        // The nonce is spent by the self-transfer: nothing to stash.
                        return Err(fail(
                            FulfilClass::Keep,
                            crate::da::DA_THROTTLE_HOLD_NAME.to_string(),
                            why,
                            true,
                        ));
                    }
                    DaStep::Fulfilled => {
                        self.settle_nonce(nonce, None).await;
                        tracing::info!("Job {job_id} Fulfilled on-chain");
                        return Ok(());
                    }
                    DaStep::Failed(why) => {
                        self.stash_or_abort(job_id, nonce, published);
                        return Err(fail(FulfilClass::Unknown, String::new(), why, published));
                    }
                }
            }
            // Hold while paused or while the job's adapter is Disabled: the send would revert
            // (EnforcedPause / RegistryPaused / AdapterDisabled) and publish the seal for nothing,
            // every round, for the whole window; the lock's clock is credited meanwhile.
            // (Attempt 1 was checked above, before the nonce was touched.)
            let later_hold = if attempt > 1 {
                self.governance_hold(proof_system_id).await
            } else {
                Ok(None)
            };
            if let Ok(Some(hold)) = later_hold {
                self.stash_or_abort(job_id, nonce, published);
                return Err(fail(
                    FulfilClass::Keep,
                    GOVERNANCE_HOLD_NAME.to_string(),
                    match hold {
                        GovernanceHold::Paused => "router or Registry paused — holding the fulfil".into(),
                        GovernanceHold::AdapterDisabled => {
                            "the job's adapter is Disabled — holding the fulfil".into()
                        }
                    },
                    published,
                ));
            }
            // Lock check before publishing: Locked AND ours, at a block >= the claim receipt's.
            let (rec, read_at) = match self.read_job_record(job_id, lock_block).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("{what}: lock read for {job_id} failed: {e:#}");
                    if attempt < MAX_ATTEMPTS {
                        tokio::time::sleep(SEND_FAILURE_RETRY_WAIT).await;
                    }
                    continue;
                }
            };
            // An earlier publish at this nonce (a previous attempt, or the resumed stash) may be what
            // settled the job: `settle_nonce` commits the nonce if it mined.
            if rec.status == JOB_STATUS_FULFILLED && rec.prover == self.address {
                self.settle_nonce(nonce, Some(read_at)).await;
                tracing::info!("Job {} already Fulfilled on-chain", job_id);
                return Ok(());
            }
            if rec.status != JOB_STATUS_LOCKED || rec.prover != self.address {
                self.settle_nonce(nonce, Some(read_at)).await;
                return Err(fail(
                    FulfilClass::Stale,
                    String::new(),
                    format!(
                        "job is no longer Locked by us (status {}, prover {}) — not publishing",
                        rec.status, rec.prover
                    ),
                    published,
                ));
            }
            // The router rebuilds the descriptor hash from the hashed fields: a mismatch would revert
            // InvalidDescriptorHash after publishing the seal, so refuse it here, unsent.
            if let FulfilCall::Hashed(f) = &call {
                let rebuilt = f.descriptor_hash();
                if rebuilt != rec.descriptor_hash {
                    self.stash_or_abort(job_id, nonce, published);
                    return Err(fail(
                        FulfilClass::ProofDefect,
                        "InvalidDescriptorHash".to_string(),
                        format!(
                            "the hashed descriptor rebuilds {rebuilt}, the job's descriptorHash is {} \
                             — not publishing",
                            rec.descriptor_hash
                        ),
                        published,
                    ));
                }
            }
            let gas = self
                .fulfill_gas_limit
                .max(fulfill_gas_formula(
                    rec.callback_gas_limit,
                    calldata_len,
                    public_values.len(),
                ))
                .saturating_add(extra_gas);

            let mut bid: Option<(u128, u128, u128)> = None;
            // The bid is at its ceiling: a re-publish is byte-identical, so the node answers "already
            // known" and there is nothing to bump.
            let mut held = false;
            // DA nonce rule: the first send of a large fulfil only as the highest pending nonce.
            let must_be_highest = da_run.as_ref().is_some_and(|d| d.large) && !published;
            let send_result = {
                let _guard = self.tx_lock.lock().await;
                if must_be_highest && fills < DA_MAX_FILLS && !self.nonce_is_highest_reserved(nonce)
                {
                    None
                } else {
                    let mut tx = alloy::contract::CallBuilder::new_raw(&*self.provider, calldata.clone())
                        .to(self.hemi_prove)
                        .nonce(nonce)
                        // Explicit gas limit (never `eth_estimateGas`: an estimate shows the seal to the
                        // RPC operator, and the router's settlement preflight reverts
                        // InsufficientGasForFullSettlement if under-provisioned).
                        .gas(gas);
                    if base_max_fee > 0 {
                        let (tip, seed_max_fee) = escalated_fees(base_tip, base_max_fee, attempt);
                        // The fulfil climbs (>= 12.5% per re-publish) toward the key-wide ceiling but
                        // stops RELEASE_DISPLACE_RUNGS rungs below the cap, then keeps re-publishing at
                        // that level: the same-nonce release must always be able to out-bid it.
                        let affordable = balance
                            .map_or(u128::MAX, |b| (b / 10 * 9).min(TX_FEE_CAP_WEI) / u128::from(gas.max(1)));
                        let (tip, max_fee) = match job_path_bid(
                            self.nonce_fee_floor_state(nonce),
                            tip,
                            seed_max_fee,
                            self.fee_ceiling,
                            RELEASE_DISPLACE_RUNGS,
                            affordable,
                        ) {
                            JobBid::Send(t, m) => (t, m),
                            JobBid::Hold(t, m) => {
                                held = true;
                                (t, m)
                            }
                            JobBid::Exhausted => {
                                if let Some(st) = self.nonce_fee_floor_state(nonce) {
                                    log_fee_cap_exhausted(what, nonce, &st);
                                }
                                // Do NOT hand this nonce to the gap healer: its self-transfer would evict
                                // OUR OWN pending fulfil (seal already public, lock unsettled). Keep it
                                // stashed for this job so the next attempt or a release resumes it. A
                                // nonce we never published at carries someone ELSE's resident: leave it
                                // unresolved (healable) rather than recycle it into `freed`, where the
                                // next reserver would draw the same poisoned nonce and bail again.
                                self.note_nonce_undisplaceable(nonce);
                                if published {
                                    self.stash_abandoned_nonce(job_id, nonce);
                                } else {
                                    self.note_nonce_unresolved(nonce);
                                }
                                return Err(fail(
                                    FulfilClass::Unknown,
                                    String::new(),
                                    format!("{FEE_CAP_EXHAUSTED} at nonce {nonce} ({what})"),
                                    published,
                                ));
                            }
                        };
                        bid = Some((tip, max_fee, seed_max_fee));
                        tx = tx.max_priority_fee_per_gas(tip).max_fee_per_gas(max_fee);
                    }
                    Some(tx.send().await)
                }
            };
            let Some(send_result) = send_result else {
                // A sibling reserved a nonce above ours since the check before the loop: spend ours
                // on a filler and take a fresh one. Not a send attempt.
                fills += 1;
                if let Err(e) = self.fill_reserved_nonce(nonce).await {
                    tracing::warn!("{e:#}");
                }
                nonce = self.reserve_nonce().await?;
                attempt -= 1;
                continue;
            };

            let pending = match send_result {
                Ok(p) => {
                    published = true;
                    if let Some((t, m, seed)) = bid {
                        self.note_broadcast_fee(nonce, t, m, seed);
                    }
                    // The DA rules track each accepted hashed fulfil from its first acceptance's
                    // head (re-publishes at the same nonce keep it).
                    if let Some(d) = &da_run {
                        let tracked = self.da_book().get(nonce).is_some_and(|s| s.job_id == job_id);
                        if !tracked {
                            match self.provider.get_block_number().await {
                                Ok(head) => {
                                    self.da_book().note_accepted(job_id, nonce, d.est, head);
                                }
                                Err(e) => tracing::debug!(
                                    "{what}: head read after the send failed ({e:#}); tracking \
                                     nonce {nonce} from the next publish"
                                ),
                            }
                        }
                    }
                    p
                }
                Err(e) => {
                    let raw = format!("{e:#}");
                    // Classify on the RAW string, log the SANITIZED form (a hostile callback /
                    // verifier revert reason can carry terminal escapes).
                    let msg = crate::programs::sanitize_log(&raw);
                    if is_same_nonce_pending(&raw) {
                        if held && published {
                            // Our fulfil is pending at the ceiling bid: wait for it, as an unconfirmed
                            // receipt does, rather than burn the remaining attempts (and the shared RPC
                            // budget) in seconds re-sending the same bytes.
                            tracing::info!(
                                "{what} at nonce {nonce} is pending at its fee ceiling (attempt \
                                 {attempt}/{MAX_ATTEMPTS}) — waiting for it"
                            );
                            let mut poll_end = std::time::Instant::now() + FULFIL_HELD_WAIT;
                            if let Some(b) = budget {
                                poll_end = poll_end.min(started + b);
                            }
                            if let Some(at) = self
                                .poll_fulfilled_until(job_id, poll_end, FULFIL_HELD_POLL)
                                .await
                            {
                                self.settle_nonce(nonce, Some(at)).await;
                                tracing::info!(
                                    "Job {} Fulfilled (confirmed via state poll)",
                                    job_id
                                );
                                return Ok(());
                            }
                            continue;
                        }
                        tracing::warn!("{what} replacement at nonce {nonce} (attempt {attempt}/{MAX_ATTEMPTS}): {msg} — bumping fee, keeping nonce");
                        if attempt < MAX_ATTEMPTS {
                            tokio::time::sleep(nonce_retry_backoff(
                                attempt,
                                false,
                                NONCE_RETRY_UNIT,
                            ))
                            .await;
                        }
                        continue;
                    }
                    if is_nonce_error(&raw) {
                        tracing::warn!("{what} nonce error (attempt {attempt}/{MAX_ATTEMPTS}): {msg} — re-syncing");
                        let rejected = nonce;
                        self.abort_nonce(nonce);
                        self.resync_nonce().await.ok();
                        let mut progressed = false;
                        match self.reserve_nonce().await {
                            Ok(n) => {
                                progressed = n != rejected;
                                nonce = n;
                            }
                            Err(e) => tracing::warn!("{what} nonce re-sync failed (attempt {attempt}/{MAX_ATTEMPTS}): {e:#} — retrying"),
                        }
                        if attempt < MAX_ATTEMPTS {
                            tokio::time::sleep(nonce_retry_backoff(
                                attempt,
                                progressed,
                                NONCE_RETRY_UNIT,
                            ))
                            .await;
                        }
                        continue;
                    }
                    // A preflighting node rejects a reverting fulfil at SEND, with the revert data.
                    if let Some(data) = crate::revert::revert_data_of(&e) {
                        let d = crate::revert::decode(&data);
                        let class = crate::revert::classify_fulfil(&d);
                        if class == FulfilClass::Gas && gas_bumps < MAX_GAS_BUMPS {
                            gas_bumps += 1;
                            extra_gas += FULFIL_GAS_BUMP;
                            tracing::warn!("{what} preflight {} — resending with +{FULFIL_GAS_BUMP} gas", d.name());
                            continue;
                        }
                        if class == FulfilClass::Stale {
                            // A preflighting node simulates against ITS head. A load-balanced backend
                            // below our lock block sees the pre-claim state and answers JobNotLocked /
                            // NotJobProver for a lock we hold — the lifecycle would then drop it. Only
                            // a read pinned at or after the lock block may conclude the lock is gone.
                            match self.read_job_record(job_id, lock_block).await {
                                Ok((rec, at))
                                    if rec.prover == self.address
                                        && rec.status == JOB_STATUS_FULFILLED =>
                                {
                                    // An earlier publish at this nonce may be what settled it.
                                    self.settle_nonce(nonce, Some(at)).await;
                                    return Ok(());
                                }
                                Ok((rec, at))
                                    if rec.prover != self.address
                                        || rec.status != JOB_STATUS_LOCKED =>
                                {
                                    // Confirmed gone: nothing to displace, so recycle the nonce —
                                    // unless an earlier publish at it mined (a revert).
                                    self.settle_nonce(nonce, Some(at)).await;
                                    return Err(fail(
                                        class,
                                        d.name(),
                                        format!("send-time revert: {} (confirmed by jobs())", d.name()),
                                        published,
                                    ));
                                }
                                other => {
                                    tracing::warn!(
                                        "{what} preflight {} for {job_id}, but jobs() at or after the \
                                         lock block {} — a lagging preflight node; retrying",
                                        d.name(),
                                        if other.is_ok() { "still shows our lock" } else { "is unreadable" }
                                    );
                                    if attempt < MAX_ATTEMPTS {
                                        tokio::time::sleep(SEND_FAILURE_RETRY_WAIT).await;
                                    }
                                    continue;
                                }
                            }
                        }
                        self.stash_or_abort(job_id, nonce, published);
                        return Err(fail(class, d.name(), format!("send-time revert: {}", d.name()), published));
                    }
                    if is_funds_refusal(&raw) {
                        self.note_funds_short();
                    }
                    tracing::warn!("{what} send failed (attempt {attempt}/{MAX_ATTEMPTS}): {msg}");
                    crate::tx_events::emit(
                        job_id,
                        crate::tx_events::TxKind::Fulfil,
                        crate::tx_events::TxEvent::SendFailed {
                            attempt,
                            of: MAX_ATTEMPTS,
                            rate_limited: is_rate_limit_error(&msg),
                        },
                    );
                    if attempt < MAX_ATTEMPTS {
                        tokio::time::sleep(SEND_FAILURE_RETRY_WAIT).await;
                    }
                    continue;
                }
            };
            let tx_hash = *pending.tx_hash();
            tracing::info!(
                "{what} tx sent (attempt {attempt}/{MAX_ATTEMPTS}, gas {gas}): {tx_hash:?}, waiting for receipt..."
            );
            crate::tx_events::emit(
                job_id,
                crate::tx_events::TxKind::Fulfil,
                crate::tx_events::TxEvent::Sent {
                    attempt,
                    of: MAX_ATTEMPTS,
                },
            );

            // Short per-attempt wait (FULFIL_RECEIPT_WAIT, ~3 blocks), not the generic 120 s: an
            // unmined fulfil is re-published at the SAME nonce with both fees bumped (>= 12.5%, via the
            // escalation ladder and the per-nonce floor) every few blocks (handoff §10), and the
            // lifecycle keeps re-invoking this — resuming the stashed nonce — until D+G.
            let recv_budget = match budget {
                Some(b) => b.saturating_sub(started.elapsed()).min(FULFIL_RECEIPT_WAIT),
                None => FULFIL_RECEIPT_WAIT,
            };
            match crate::tx::await_receipt(&*self.provider, tx_hash, recv_budget).await {
                Some(receipt) => {
                    self.commit_nonce(nonce);
                    let receipt_block = receipt.block_number.unwrap_or_default();
                    if receipt.status() {
                        if receipt_fulfilled_this_job(&receipt, job_id, self.hemi_prove) {
                            tracing::info!("Job fulfilled: {job_id} tx: {tx_hash:?}");
                            return Ok(());
                        }
                        // On v2 a callback cannot withhold settlement, so a mined fulfil with no
                        // router-emitted JobFulfilled is unexpected: re-read before concluding.
                        if let Ok((rec, _)) = self.read_job_record(job_id, Some(receipt_block)).await {
                            if rec.status == JOB_STATUS_FULFILLED && rec.prover == self.address {
                                return Ok(());
                            }
                        }
                        return Err(fail(
                            FulfilClass::Unknown,
                            String::new(),
                            format!("{what} {tx_hash:?} mined but emitted no JobFulfilled for {job_id}"),
                            true,
                        ));
                    }
                    // A mined revert: replay the identical call (same gas) at its block for the
                    // reason — the calldata is already public, so the replay exposes nothing new.
                    let sim = alloy::contract::CallBuilder::new_raw(&*self.provider, calldata.clone())
                        .to(self.hemi_prove)
                        .from(self.address)
                        .gas(gas)
                        .block(BlockId::number(receipt_block))
                        .call()
                        .await;
                    let (class, name, reason) = match &sim {
                        Err(e) => match crate::revert::revert_data_of(e) {
                            Some(data) => {
                                let d = crate::revert::decode(&data);
                                (crate::revert::classify_fulfil(&d), d.name(), d.name())
                            }
                            None => (
                                FulfilClass::Unknown,
                                String::new(),
                                "mined revert; replay gave no revert data".to_string(),
                            ),
                        },
                        Ok(_) => (
                            FulfilClass::Unknown,
                            String::new(),
                            format!("{what} {tx_hash:?} reverted but replays cleanly at block {receipt_block}"),
                        ),
                    };
                    if class == FulfilClass::Gas && gas_bumps < MAX_GAS_BUMPS {
                        gas_bumps += 1;
                        extra_gas += FULFIL_GAS_BUMP;
                        tracing::warn!("{what} {tx_hash:?} reverted {reason} — resending with +{FULFIL_GAS_BUMP} gas");
                        nonce = self.reserve_nonce().await?;
                        continue;
                    }
                    return Err(fail(class, name, format!("mined revert: {reason}"), true));
                }
                None => {
                    tracing::warn!(
                        "{what} receipt not confirmed (attempt {attempt}/{MAX_ATTEMPTS}, tx {tx_hash:?}); \
                         polling on-chain state before re-broadcast"
                    );
                    crate::tx_events::emit(
                        job_id,
                        crate::tx_events::TxKind::Fulfil,
                        crate::tx_events::TxEvent::Unconfirmed {
                            attempt,
                            of: MAX_ATTEMPTS,
                        },
                    );
                    let mut poll_end = std::time::Instant::now() + FULFIL_STATE_POLL;
                    if let Some(b) = budget {
                        poll_end = poll_end.min(started + b);
                    }
                    if let Some(at) = self
                        .poll_fulfilled_until(job_id, poll_end, Duration::from_secs(5))
                        .await
                    {
                        // Usually our own fulfil at this nonce, mined inside the receipt wait: the
                        // nonce is spent then, and recycling it would hand the next claim "nonce
                        // too low".
                        self.settle_nonce(nonce, Some(at)).await;
                        tracing::info!("Job {} Fulfilled (confirmed via state poll)", job_id);
                        return Ok(());
                    }
                }
            }
        }

        // Final state check, bounded by the remaining budget.
        let final_budget = budget.map(|b| b.saturating_sub(started.elapsed()));
        if final_budget.is_none_or(|r| !r.is_zero()) {
            let read = match final_budget {
                Some(r) => tokio::time::timeout(r, self.read_job_record(job_id, None))
                    .await
                    .ok()
                    .and_then(|x| x.ok()),
                None => self.read_job_record(job_id, None).await.ok(),
            };
            if let Some((rec, at)) = read {
                if rec.status == JOB_STATUS_FULFILLED && rec.prover == self.address {
                    self.settle_nonce(nonce, Some(at)).await;
                    return Ok(());
                }
            }
        }
        // Our fulfil may still be pending at this nonce: STASH it so the next fulfil attempt for this
        // job re-publishes at the SAME nonce, and a release displaces it there.
        self.stash_or_abort(job_id, nonce, published);
        Err(fail(
            FulfilClass::Unknown,
            String::new(),
            format!("{what} not confirmed after {attempt} attempt(s) (RPC may be dropping txs)"),
            published,
        ))
    }

    /// Whether `view` (a read showing the job not ours) proves our lock on `job_id` is gone. Only on
    /// evidence: the reopen count risen past `seen.reopens`; a read pinned at or after `seen.block`
    /// (a block where it was ours); or, once our release went out at nonce `sent`, a read at a block
    /// where that nonce is included. An unpinned read alone may come from a replica behind our claim,
    /// still showing the job's previous holder, or none — and acting on it drops the record of a live
    /// lock (a 100% slash), or recycles the nonce of a release still pending.
    async fn lock_gone_on_evidence(
        &self,
        job_id: B256,
        view: &JobStatusView,
        seen: LockSeen,
        sent: Option<u64>,
    ) -> bool {
        if view.prover == self.address {
            return false;
        }
        if seen.reopens.is_some_and(|r| view.reopenCount > r) {
            return true;
        }
        let mut pin = seen.block;
        if let Some(n) = sent {
            if let Ok(head) = self.provider.get_block_number().await {
                if let Ok(count) = self
                    .provider
                    .get_transaction_count(self.address)
                    .block_id(BlockId::number(head))
                    .await
                {
                    if count > n {
                        pin = Some(head);
                    }
                }
            }
        }
        match pin {
            Some(b) => matches!(
                self.read_job_record(job_id, Some(b)).await,
                Ok((rec, _)) if rec.prover != self.address
            ),
            None => false,
        }
    }

    /// Poll `jobs()` every `every` until `poll_end` for this job Fulfilled by us; the block the read
    /// that saw it was taken at.
    async fn poll_fulfilled_until(
        &self,
        job_id: B256,
        poll_end: std::time::Instant,
        every: Duration,
    ) -> Option<u64> {
        while std::time::Instant::now() < poll_end {
            let call_budget = poll_end.saturating_duration_since(std::time::Instant::now());
            if let Ok(Ok((rec, at))) =
                tokio::time::timeout(call_budget, self.read_job_record(job_id, None)).await
            {
                if rec.status == JOB_STATUS_FULFILLED && rec.prover == self.address {
                    return Some(at);
                }
            }
            tokio::time::sleep(
                every.min(poll_end.saturating_duration_since(std::time::Instant::now())),
            )
            .await;
        }
        None
    }

    /// After a fulfil gives up: if anything was broadcast at `nonce`, STASH it for this job (it may
    /// still be pending, and only a same-nonce replacement can displace it); otherwise recycle it.
    fn stash_or_abort(&self, job_id: B256, nonce: u64, published: bool) {
        if published {
            self.stash_abandoned_nonce(job_id, nonce);
        } else {
            self.abort_nonce(nonce);
        }
    }

    /// The DA nonce rule's detector, once per send attempt of a published large fulfil at `nonce`:
    /// observe the head, the mined count and the safe-head lag; past the head-advance threshold,
    /// read the backlog for evidence that the throttle may be what holds it; replace it by a
    /// self-transfer when [`crate::da::NonceRuleConfig::verdict`] says so.
    async fn da_stuck_step(&self, job_id: B256, nonce: u64, d: &DaRun<'_>) -> DaStep {
        let entry = self.da_book().get(nonce);
        let Some(entry) = entry.filter(|e| e.job_id == job_id) else {
            return DaStep::Continue;
        };
        let obs = match self.observe_pending().await {
            Ok(o) => o,
            Err(e) => {
                tracing::debug!("DA detector read failed ({e:#}); checking again next attempt");
                return DaStep::Continue;
            }
        };
        let rule = d.cfg.rule;
        let unmined = obs.head.saturating_sub(entry.first_accepted_head);
        // Only read the backlog when it can change the verdict (past the head-advance threshold).
        let filter = if rule.require_da_evidence && unmined >= rule.unmined_blocks.max(1) {
            d.cfg.backlog.read(self).await.backlog.would_filter(d.est)
        } else {
            None
        };
        let reason = match rule.verdict(nonce, entry.first_accepted_head, obs, filter) {
            crate::da::StuckVerdict::Mined | crate::da::StuckVerdict::Waiting { .. } => {
                return DaStep::Continue
            }
            crate::da::StuckVerdict::Replace(reason) => reason,
        };
        tracing::warn!(
            "PAGE: PENDING-UNMINED — the {}-byte (estimated DA) fulfil of {job_id} at nonce {nonce} \
             is {reason}: the DA throttle may be filtering it, and every later nonce of this key waits \
             behind it",
            d.est
        );
        match self.replace_with_self_transfer(nonce).await {
            Ok(confirmed) => {
                self.da_book().note_replaced(
                    job_id,
                    crate::da::Replaced {
                        nonce,
                        head: obs.head,
                        estimated_bytes: d.est,
                    },
                );
                DaStep::Replaced(format!(
                    "DA nonce rule: the fulfil at nonce {nonce} was {reason}; replaced by a \
                     self-transfer{} — it is re-sent once the throttle clears",
                    if confirmed { "" } else { " (not yet confirmed)" }
                ))
            }
            Err(e) => {
                // The fulfil may have mined first (the replacement then meets "nonce too low").
                if let Ok((rec, _)) = self.read_job_record(job_id, None).await {
                    if rec.status == JOB_STATUS_FULFILLED && rec.prover == self.address {
                        return DaStep::Fulfilled;
                    }
                }
                DaStep::Failed(format!(
                    "DA nonce rule: the fulfil at nonce {nonce} was {reason}, and replacing it failed: \
                     {e:#}"
                ))
            }
        }
    }

    /// Release a claimed job (voluntary release, incurs penalty).
    ///
    /// Robust to a flaky/inconsistent RPC in the same way as `fulfill_job`: on a
    /// receipt timeout it polls on-chain state, and if the job is still locked by
    /// us it re-broadcasts at the same nonce with an escalating tip (to displace a
    /// stuck tx), up to a few attempts. Because releasing frees collateral before a
    /// missed deadline strands it permanently, giving up after a single receipt
    /// timeout would be the exact failure that leaves collateral
    /// locked — mirroring fulfill_job's rebroadcast/poll closes that gap.
    ///
    /// Success is defined as "our lock is gone" (`view.prover != self.address`):
    /// after a release the job reopens (prover cleared) or is reclaimed by another
    /// prover — in every case our collateral is no longer tied to a lock we hold.
    pub async fn release_job(&self, job_id: B256) -> Result<()> {
        self.release_job_with_nonce(job_id, None, LockSeen::default())
            .await
    }

    /// As [`Self::release_job`], but starts from a nonce the CALLER already reserved.
    ///
    /// The shutdown abandon path releases several jobs concurrently. A single signer's txs
    /// mine in strict NONCE order, so the nonce — not the spawn or send order — is a
    /// release's on-chain priority; reserving inside each task instead orders them by
    /// scheduling and RPC latency, which can put a job with hours of headroom ahead of one
    /// about to strand. Reserving in deadline order and handing the nonce in fixes that.
    /// The caller must recycle (`abort_nonce`) a pre-reserved nonce it never passes here.
    pub async fn release_job_with_nonce(
        &self,
        job_id: B256,
        preassigned: Option<u64>,
        seen: LockSeen,
    ) -> Result<()> {
        const MAX_ATTEMPTS: u32 = MAX_TX_ATTEMPTS;
        let fulfill = IHemiProveFulfill::new(self.hemi_prove, &*self.provider);
        // If a fulfill for THIS job gave up with its tx likely still pending, reuse
        // that EXACT nonce so releaseJob displaces the stuck fulfill (a fresh distinct
        // nonce would queue BEHIND it and strand). Displacing from the start seeds the fee
        // headroom below.
        // Otherwise reserve a fresh nonce and apply the fulfill-ceiling fee HEADROOM
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
            // A pre-assigned nonce is a plain reservation, so `displacing` stays false
            // and the fulfill-ceiling fee headroom is still only applied once we observe a
            // stuck same-nonce tx.
            None => match preassigned {
                Some(p) => (p, false),
                None => (self.reserve_nonce().await?, false),
            },
        };
        let (base_tip, base_max_fee) = self.base_fees().await;
        // What the node will admit for a release (handoff §10). Sized for RELEASE_GAS_BOUND, above what
        // a releaseJob uses; unknown balance -> unbounded (the node's refusal is then the bound).
        let affordable = self
            .provider
            .get_balance(self.address)
            .await
            .ok()
            .map(|b| b.min(U256::from(u128::MAX)).to::<u128>())
            .map_or(u128::MAX, |b| (b / 10 * 9).min(TX_FEE_CAP_WEI) / RELEASE_GAS_BOUND);
        // Have we actually put a releaseJob on the wire yet? Before that, a
        // `prover == ZERO` read (the job reads OPEN) is NOT proof our lock is gone — a claim
        // still pending and a lagging replica are indistinguishable from a real reopen. That
        // is the rule every other reader applies (`release_and_clean`'s own guard,
        // `classify_reconcile`, recovery), and they all RETAIN the journal breadcrumb on it.
        // This path is the one that DELETES it: our `Ok(())` makes `release_and_clean` drop
        // the breadcrumb, which is the only record that collateral is locked — after which
        // the drain union, the abandon list and the EX_TEMPFAIL exit gate (all
        // `active_jobs ∪ journal`) can never see the lock again. So "gone" needs evidence
        // (`lock_gone_on_evidence`), before a broadcast and after; without it the release is sent,
        // and its typed revert says what happened.
        let mut broadcast = false;
        // The nonce our release last went out at (see `lock_gone_on_evidence`).
        let mut sent: Option<u64> = None;

        for attempt in 1..=MAX_ATTEMPTS {
            // Already released? (a prior attempt landed on a node whose receipt we
            // never saw, or the job was reopened/slashed out from under us). Our lock
            // being gone means our collateral is free — treat as success.
            if let Ok(view) = self.get_job_status_view(job_id).await {
                if self.lock_gone_on_evidence(job_id, &view, seen, sent).await {
                    // Our lock is gone (release landed, or the fulfill we were displacing
                    // actually mined) → success. Commit the nonce if one of ours at it mined,
                    // else recycle it.
                    self.settle_nonce(nonce, None).await;
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
                    // Once we're displacing a stuck same-nonce tx, seed escalation
                    // ABOVE fulfill's ceiling (it can only be evicted by a strictly higher
                    // fee). Otherwise escalate normally.
                    let (tip, seed_max_fee) =
                        release_rung_fees(base_tip, base_max_fee, attempt, self.fee_ceiling);
                    // Lift over anything WE already broadcast at this nonce — mirroring
                    // claim_job. Without it this ladder is OPEN LOOP: it tops out at
                    // attempt 5 + headroom 5 => 1.15^9 ~= 3.52x base, while a nonce-gap heal
                    // bids >= 4x, and 4 / 1.125 = 3.556 > 3.52 — so a release racing a heal
                    // at the same nonce could NEVER clear the replacement threshold. All five
                    // attempts were rejected "replacement underpriced" and the releaseJob
                    // never reached the wire, silently, losing the collateral at the lock
                    // deadline. This is what made every heal-vs-release collision terminal
                    // rather than recoverable.
                    // Bid against the key-wide ceiling with NO reserved rungs, displacing or not: the
                    // fulfil ladder stopped RELEASE_DISPLACE_RUNGS rungs below it precisely so this bid
                    // always exists, and a release held out past D+G is a slash.
                    let bid_pair = match job_path_bid(
                        self.nonce_fee_floor_state(nonce),
                        tip,
                        seed_max_fee,
                        self.fee_ceiling,
                        0,
                        affordable,
                    ) {
                        JobBid::Send(t, m) => Some((t, m)),
                        JobBid::Hold(..) | JobBid::Exhausted => None,
                    };
                    let Some((tip, max_fee)) = bid_pair else {
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
                    broadcast = true; // a ZERO read may now legitimately be our release
                    sent = Some(nonce);
                                      // The read above is HALF the mechanism; without this write it is
                                      // incomplete. With a floor present, `max()` pins every attempt to the
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
                        displacing = true; // now escalate above fulfill's ceiling
                        tracing::warn!(
                            "releaseJob replacement at nonce {nonce} (attempt {attempt}/{MAX_ATTEMPTS}): {msg} \
                             — bumping tip, keeping nonce"
                        );
                        // Shorter backoff than the other three paths on purpose: this is the
                        // deadline-critical collateral rescue, so the ladder must not burn
                        // instantly (it learns nothing) but also must not dawdle. ~1.0s across
                        // the four rungs it pays, against a lock deadline measured in hours.
                        // See the claim paths: named unit, and not on the final attempt.
                        if attempt < MAX_ATTEMPTS {
                            tokio::time::sleep(nonce_retry_backoff(
                                attempt,
                                false,
                                RELEASE_NONCE_RETRY_UNIT,
                            ))
                            .await;
                        }
                        continue;
                    }
                    if is_nonce_error(&msg) {
                        tracing::warn!("releaseJob nonce error (attempt {attempt}/{MAX_ATTEMPTS}): {msg} — re-syncing");
                        // Recycle the abandoned nonce so a "nonce too high"
                        // (a gap below us) doesn't leak it; resync then prunes it from the
                        // gap set if it was actually consumed ("nonce too low").
                        let rejected = nonce;
                        self.abort_nonce(nonce);
                        self.resync_nonce().await.ok();
                        // Don't abort the whole deadline-critical release on a single
                        // transient re-sync failure; keep the attempt budget and retry.
                        let mut progressed = false;
                        match self.reserve_nonce().await {
                            Ok(n) => {
                                progressed = n != rejected;
                                nonce = n;
                                // A FRESH nonce has nothing of ours to displace, so the
                                // fulfill-ceiling headroom must not carry over. Leaving it set
                                // made attempt 2 bid `escalated_fees(base, 2 + 5)` ~= 2.31x
                                // base against an empty nonce — overpaying on a
                                // deadline-critical tx for no reason, and exactly the overpay
                                // the note at the top of this function forbids. `displacing`
                                // is re-armed by the `is_same_nonce_pending` arm above if the
                                // new nonce turns out to be occupied too.
                                //
                                // Only when the nonce actually MOVED, though. `reserve_locked`
                                // hands out the lowest freed nonce first, and `abort_nonce`
                                // just put `rejected` back in that set, so on "nonce too high"
                                // we are routinely handed the very same number — where the
                                // stuck fulfill is still resident and the headroom is exactly
                                // what must out-bid it. Clearing it there dropped attempt 2's
                                // bid BELOW attempt 1's on the collateral rescue.
                                if progressed {
                                    displacing = false;
                                }
                            }
                            Err(e) => {
                                tracing::warn!("releaseJob nonce re-sync failed (attempt {attempt}/{MAX_ATTEMPTS}): {e:#} — retrying");
                            }
                        }
                        // Shorter unit: see `RELEASE_NONCE_RETRY_UNIT`. Skipped on the last
                        // attempt, which is about to give up anyway.
                        if attempt < MAX_ATTEMPTS {
                            tokio::time::sleep(nonce_retry_backoff(
                                attempt,
                                progressed,
                                RELEASE_NONCE_RETRY_UNIT,
                            ))
                            .await;
                        }
                    } else {
                        if is_funds_refusal(&msg) {
                            self.note_funds_short();
                        }
                        tracing::warn!(
                            "releaseJob send failed (attempt {attempt}/{MAX_ATTEMPTS}): {msg}"
                        );
                        crate::tx_events::emit(
                            job_id,
                            crate::tx_events::TxKind::Release,
                            crate::tx_events::TxEvent::SendFailed {
                                attempt,
                                of: MAX_ATTEMPTS,
                                rate_limited: is_rate_limit_error(&msg),
                            },
                        );
                        if attempt < MAX_ATTEMPTS {
                            tokio::time::sleep(SEND_FAILURE_RETRY_WAIT).await;
                        }
                    }
                    continue;
                }
            };
            let tx_hash = *pending.tx_hash();
            tracing::info!(
                "releaseJob tx sent (attempt {attempt}/{MAX_ATTEMPTS}): {tx_hash:?}, waiting for receipt..."
            );
            crate::tx_events::emit(
                job_id,
                crate::tx_events::TxKind::Release,
                crate::tx_events::TxEvent::Sent {
                    attempt,
                    of: MAX_ATTEMPTS,
                },
            );

            // Poll for the receipt (no heartbeat watcher). None folds the old
            // timeout + RPC-error arms into the on-chain state poll below. Short rungs (~3 blocks):
            // the release window closes at D+G, and several fee-bumped same-nonce rungs must fit in
            // the margin the lifecycle reserves for it (RELEASE_LADDER_SECS).
            match crate::tx::await_receipt(&*self.provider, tx_hash, RELEASE_RECEIPT_WAIT).await {
                Some(receipt) => {
                    if receipt.status() {
                        self.commit_nonce(nonce);
                        tracing::info!(
                            "Job released: {} tx: {:?}",
                            job_id,
                            receipt.transaction_hash
                        );
                        return Ok(());
                    }
                    // Genuine revert — retrying won't help, and the reverted tx consumed the nonce
                    // on-chain. Replay it at its block for the typed reason: "At or past deadline"
                    // (job-local time reached D+G — only a slash frees the collateral now) is LATE,
                    // `JobNotLocked`/`NotJobProver` is STALE (the lock is already gone).
                    self.commit_nonce(nonce); // mined revert consumed the nonce
                    let receipt_block = receipt.block_number.unwrap_or_default();
                    let sim = fulfill
                        .releaseJob(job_id)
                        .from(self.address)
                        .block(BlockId::number(receipt_block))
                        .call()
                        .await;
                    let (class, error_name) = match &sim {
                        Err(e) => match crate::revert::revert_data_of(e) {
                            Some(data) => {
                                let d = crate::revert::decode(&data);
                                (crate::revert::classify_fulfil(&d), d.name())
                            }
                            None => (FulfilClass::Unknown, String::new()),
                        },
                        Ok(_) => (FulfilClass::Unknown, String::new()),
                    };
                    return Err(FulfilFailure {
                        class,
                        reason: format!(
                            "releaseJob {tx_hash:?} reverted: {}",
                            if error_name.is_empty() { "reason unavailable" } else { error_name.as_str() }
                        ),
                        error_name,
                        published: true,
                    }
                    .into());
                }
                None => {
                    tracing::warn!(
                        "releaseJob receipt not confirmed (attempt {attempt}/{MAX_ATTEMPTS}, tx {tx_hash:?}); \
                         polling on-chain state before re-broadcast"
                    );
                    crate::tx_events::emit(
                        job_id,
                        crate::tx_events::TxKind::Release,
                        crate::tx_events::TxEvent::Unconfirmed {
                            attempt,
                            of: MAX_ATTEMPTS,
                        },
                    );
                    let deadline = std::time::Instant::now() + RELEASE_STATE_POLL;
                    while std::time::Instant::now() < deadline {
                        if let Ok(view) = self.get_job_status_view(job_id).await {
                            if self.lock_gone_on_evidence(job_id, &view, seen, sent).await {
                                // "Our lock is gone" is NOT uniquely our doing — a keeper's
                                // slashAndReopen or another prover's reclaim clears it too, in
                                // which case our releaseJob at `nonce` never mined and it's a gap
                                // to recycle. So the mined count decides: past `nonce`, our tx
                                // there mined and the nonce is spent (recycling it would hand the
                                // next reservation "nonce too low"); otherwise abort — which,
                                // unlike a blunt invalidate, doesn't discard other gaps.
                                self.settle_nonce(nonce, None).await;
                                tracing::info!(
                                    "Job {} released (confirmed via state poll)",
                                    job_id
                                );
                                return Ok(());
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    // A sender's txs mine strictly in nonce order, so a release cannot land behind a
                    // lower pending nonce of ours whatever it bids — and a hold-out only has to outbid
                    // that lower tx. From the second unconfirmed rung, displace the blocker with the
                    // healer's high-fee self-transfer: its owner re-syncs to a fresh nonce on "nonce
                    // too low", while this lock's release has nothing after it but a slash.
                    // Only a blocker NO live task owns is displaced (one we abandoned, or a tx a
                    // previous run left pending): a sibling's live fulfil or release — possibly the
                    // most urgent lock's — climbs its own ladder and must never be evicted by ours.
                    if attempt >= 2 {
                        if let Ok(Some(hole)) = self.nonce_gap_safe_to_fill().await {
                            if hole < nonce {
                                tracing::warn!(
                                    "releaseJob at nonce {nonce} is queued behind our abandoned nonce \
                                     {hole} — filling it"
                                );
                                if let Err(e) = self
                                    .heal_owned_nonce_gap_at(hole, Duration::from_secs(20))
                                    .await
                                {
                                    tracing::warn!("filling nonce {hole} failed: {e:#}");
                                }
                            }
                        }
                    }
                }
            }
        }

        // Final state check before declaring failure — our lock may have cleared
        // on the very last broadcast whose receipt we didn't catch. Same rule: if every
        // attempt failed at `send` (persistent 429s) nothing was broadcast, so a ZERO read
        // here is UNKNOWN, not success.
        if let Ok(view) = self.get_job_status_view(job_id).await {
            if self.lock_gone_on_evidence(job_id, &view, seen, sent).await {
                self.settle_nonce(nonce, None).await;
                tracing::info!("Job {} released (confirmed on final check)", job_id);
                return Ok(());
            }
        }
        // Gave up without confirmation. A nonce that carries our broadcast release may still mine it:
        // leave it visible to the healer but do NOT offer it to reservers, whose next claim or fulfil
        // would out-bid and evict the very tx that can still save this lock.
        if broadcast {
            self.note_nonce_unresolved(nonce);
        } else {
            self.abort_nonce(nonce);
        }
        anyhow::bail!("releaseJob failed after {MAX_ATTEMPTS} attempts (RPC may be dropping txs)")
    }

}

#[cfg(test)]
mod h4_tests {
    use super::{job_fulfilled_topic0, log_is_authentic_fulfilled};
    use alloy::primitives::{Address, B256};

    #[test]
    fn job_fulfilled_topic0_matches_binding_signature() {
        // Pin the hand-computed topic0 to the generated ABI binding's signature hash,
        // mirroring the monitor's own test. If the JobFulfilled event signature ever drifts, this
        // fails in CI instead of silently making the fulfilled-event check see every real fulfill as
        // "not fulfilled" (which would release genuinely-fulfilled jobs).
        use alloy::sol_types::SolEvent;
        assert_eq!(
            job_fulfilled_topic0(),
            zkminer_contracts::bindings::IHemiProveFulfill::JobFulfilled::SIGNATURE_HASH
        );
    }

    #[test]
    fn authentic_only_when_router_emitted() {
        let router = Address::repeat_byte(0xAA);
        let attacker = Address::repeat_byte(0xBB);
        let job = B256::repeat_byte(0x11);
        let good_topics = vec![job_fulfilled_topic0(), job];

        // Router + correct topics → authentic.
        assert!(log_is_authentic_fulfilled(router, &good_topics, job, router));
        // The forgery: a submitter callback emits an identical log from ITS OWN address.
        // Must NOT be accepted.
        assert!(!log_is_authentic_fulfilled(attacker, &good_topics, job, router));
        // Router but a different jobId → not for us.
        assert!(!log_is_authentic_fulfilled(
            router,
            &[job_fulfilled_topic0(), B256::repeat_byte(0x22)],
            job,
            router
        ));
        // Router but wrong event (topic0) → not JobFulfilled.
        assert!(!log_is_authentic_fulfilled(
            router,
            &[B256::repeat_byte(0x99), job],
            job,
            router
        ));
        // No topics at all → not authentic.
        assert!(!log_is_authentic_fulfilled(router, &[], job, router));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        escalated_fees, fulfill_gas_formula, is_nonce_error, is_rate_limit_error,
        is_same_nonce_pending, nonce_retry_backoff, MAX_TX_ATTEMPTS, NONCE_RETRY_UNIT,
        RELEASE_NONCE_RETRY_UNIT,
    };
    use super::super::programs::sanitize_log;
    use std::time::Duration;

    // The fulfil gas limit must clear the router's preflight (gasleft() >= 4.6M + callback) with the
    // repo's documented terms (script/lib/FulfillGas.sol). A 5M flat limit is too low.
    #[test]
    fn fulfil_gas_formula_matches_the_repo_and_clears_the_preflight() {
        // Default callback (stored 0 => 200k), 1 KB calldata, empty journal: the handoff's "~5.6M".
        let g = fulfill_gas_formula(0, 1024, 0);
        assert_eq!(g, 4_600_000 + 200_000 + 250_000 + 16 * 1024 + 500_000);
        assert!(g > 5_000_000, "5,000,000 is too low (handoff §7 step 7)");
        // The preflight floor (4.6M + callback) is always cleared, for any stored callback limit.
        for cb in [0u32, 50_000, 500_000] {
            let eff = if cb == 0 { 200_000 } else { cb as u64 };
            assert!(fulfill_gas_formula(cb, 0, 0) > 4_600_000 + eff);
        }
        // Journal bytes are charged at 8 gas each.
        assert_eq!(
            fulfill_gas_formula(0, 0, 32_768) - fulfill_gas_formula(0, 0, 0),
            8 * 32_768
        );
    }

    // A hostile revert reason (surfaced by a preflighting RPC) is logged only through
    // `sanitize_log`: lock in that it strips escape/CRLF/bidi bytes.
    #[test]
    fn hostile_revert_text_is_sanitized_for_the_operator_console() {
        let hostile = "execution reverted: \x1b[2J\x1b]0;pwned\x07evil\r\nforged log line\u{202e}reversed";
        let safe = sanitize_log(hostile);
        assert!(!safe.contains('\x1b'), "ANSI/OSC escapes stripped");
        assert!(!safe.contains('\r') && !safe.contains('\n'), "CRLF stripped (no forged lines)");
        assert!(!safe.contains('\u{202e}'), "bidi override stripped (no Trojan-Source reorder)");
    }

    #[test]
    fn fulfill_send_error_is_classified_on_raw_but_logged_sanitized() {
        // The real-send `fulfill_job` error path (like the simulation path) classifies the send
        // error on the RAW string but LOGS the sanitized form. Sanitizing before classification
        // must not change the nonce/replacement verdict (those phrases are plain ASCII), and the
        // logged form must carry no terminal-escape / CRLF / bidi bytes a hostile revert reason
        // (surfaced by a preflighting RPC) could smuggle in.
        let hostile_nonce =
            "nonce too low\x1b[2J\x1b]0;pwned\x07\r\nforged log line\u{202e}reversed";
        // Classification runs on the raw string and still sees the nonce phrase.
        assert!(is_nonce_error(hostile_nonce), "classification sees the raw nonce phrase");
        // The display form is injection-safe.
        let safe = sanitize_log(hostile_nonce);
        assert!(!safe.contains('\x1b'), "ANSI/OSC escapes stripped from the logged send error");
        assert!(!safe.contains('\r') && !safe.contains('\n'), "CRLF stripped (no forged lines)");
        assert!(!safe.contains('\u{202e}'), "bidi override stripped");
        assert!(safe.contains("nonce too low"), "the human-readable reason survives");
        // A crafted catch-all revert reason: not a nonce/replacement phrase, so it falls to the
        // plain warn! sink — which now logs the sanitized form.
        let hostile_generic = "execution reverted: \x1b]0;evil\x07\r\nFAKE";
        assert!(!is_nonce_error(hostile_generic));
        assert!(!is_same_nonce_pending(hostile_generic));
        let safe_generic = sanitize_log(hostile_generic);
        assert!(!safe_generic.contains('\x1b') && !safe_generic.contains('\n'));
    }

    /// The real ladder length and the real units, read from production rather than restated —
    /// hard-coding `5` and `100ms` here would make lowering either in production invisible to
    /// every assertion below.
    const LADDER: u32 = MAX_TX_ATTEMPTS;

    /// The rungs production actually PAYS. The final attempt's wait is skipped (the loop is about
    /// to exit, so it buys nothing and delays the give-up), so summing `1..=LADDER` would describe
    /// a ladder that does not exist — 1.5x too long — and a bound checked against it would be too
    /// loose.
    fn paid_rungs() -> impl Iterator<Item = u32> {
        1..LADDER
    }

    /// The invariant: a nonce-error ladder cannot complete instantly.
    ///
    /// This is the measurable property a nonce-retry livelock violates: without a backoff the
    /// ladder completes in microseconds (measured ~18.85 µs) instead of seconds (~7.36 s),
    /// burning every attempt against an unchanged node view.
    #[test]
    fn a_nonce_error_ladder_cannot_burn_instantly() {
        let unit = NONCE_RETRY_UNIT;

        // Worst case: the re-sync keeps handing back the nonce the node just rejected.
        let stuck: Duration = paid_rungs()
            .map(|a| nonce_retry_backoff(a, false, unit))
            .sum();
        // 250+500+750+1000 = 2.5s across the four rungs production pays (the final attempt's
        // wait is skipped).
        assert!(
            stuck >= Duration::from_millis(2_400),
            "a stuck ladder must take seconds, not microseconds: {stuck:?}"
        );

        // And the case a lagging RPC actually produces: every attempt moves the nonce on by
        // one and fails just as fast. Zero backoff here would reproduce the microsecond burn
        // while reporting "progress", so this must still be bounded away from instant.
        let walking: Duration = paid_rungs()
            .map(|a| nonce_retry_backoff(a, true, unit))
            .sum();
        assert!(
            walking >= Duration::from_millis(200),
            "even a 'progressing' ladder must not complete instantly: {walking:?}"
        );
    }

    /// Progress must still be materially cheaper than repetition — these are
    /// deadline-critical paths (fulfil, and the collateral-rescue release), so a re-sync
    /// that genuinely moved us forward must not pay the full stall.
    #[test]
    fn progress_is_cheaper_than_repetition() {
        let unit = NONCE_RETRY_UNIT;
        for attempt in paid_rungs() {
            let moved = nonce_retry_backoff(attempt, true, unit);
            let stuck = nonce_retry_backoff(attempt, false, unit);
            assert!(
                moved < stuck,
                "attempt {attempt}: progress ({moved:?}) must cost less than repetition ({stuck:?})"
            );
        }
    }

    /// Backoff must grow with the attempt, so a transient disagreement clears on attempt 1
    /// or 2 while a persistent one gives the node real time.
    #[test]
    fn the_backoff_grows_with_the_attempt() {
        let unit = NONCE_RETRY_UNIT;
        let mut prev = Duration::ZERO;
        for attempt in paid_rungs() {
            let d = nonce_retry_backoff(attempt, false, unit);
            assert!(d > prev, "attempt {attempt}: {d:?} must exceed {prev:?}");
            prev = d;
        }
    }

    /// releaseJob passes a deliberately smaller unit (its ladder is the collateral rescue).
    /// It must stay well inside the lock deadline while still being non-instant.
    #[test]
    fn the_release_ladder_stays_short_but_not_instant() {
        let stuck: Duration = paid_rungs()
            .map(|a| nonce_retry_backoff(a, false, RELEASE_NONCE_RETRY_UNIT))
            .sum();
        // 100+200+300+400 = 1.0s against a lock deadline measured in hours.
        assert!(
            stuck >= Duration::from_millis(900) && stuck <= Duration::from_secs(2),
            "release ladder should be ~1.0s, got {stuck:?}"
        );
        // And it must stay materially shorter than the claim/fulfil ladder, which is the whole
        // reason it has its own unit.
        let normal: Duration = paid_rungs()
            .map(|a| nonce_retry_backoff(a, false, NONCE_RETRY_UNIT))
            .sum();
        assert!(
            stuck * 2 < normal,
            "the collateral rescue must back off far less than a claim: {stuck:?} vs {normal:?}"
        );
    }

    /// The "progressing" ladder must grow too. A flat delay capped it at ~250ms, which on a
    /// chain with multi-second blocks gives a lagging replica no chance to catch up — and a
    /// lagging replica is the case that actually happens.
    #[test]
    fn a_progressing_ladder_still_grows() {
        let mut prev = Duration::ZERO;
        for attempt in paid_rungs() {
            let d = nonce_retry_backoff(attempt, true, NONCE_RETRY_UNIT);
            assert!(d > prev, "attempt {attempt}: {d:?} must exceed {prev:?}");
            prev = d;
        }
        let total: Duration = paid_rungs()
            .map(|a| nonce_retry_backoff(a, true, NONCE_RETRY_UNIT))
            .sum();
        // 50+100+150+200 = 500ms.
        assert!(
            total >= Duration::from_millis(450),
            "a progressing ladder should still span half a second, got {total:?}"
        );
    }

    /// attempt 1 is the initial send (not a replacement) → base fees unchanged.
    #[test]
    fn escalated_fees_first_attempt_is_base() {
        assert_eq!(escalated_fees(2, 200, 1), (2, 200));
        assert_eq!(escalated_fees(0, 1_000_000_000, 1), (0, 1_000_000_000));
    }

    /// Every re-broadcast must clear geth's 12.5% same-nonce replacement floor on BOTH
    /// fields — including the LAST attempt (an additive schedule would drop to 9.35% here).
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
        for &(t, m) in &[
            (0u128, 0u128),
            (5, 3),
            (100, 100),
            (u128::MAX, 1),
            (1, u128::MAX),
        ] {
            for attempt in 1..=5u32 {
                let (tip, max_fee) = escalated_fees(t, m, attempt);
                assert!(
                    max_fee >= tip,
                    "max_fee {max_fee} < tip {tip} at ({t},{m},{attempt})"
                );
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
        // The recovery chunk classifier must recognize the endpoint's 429s so it
        // defers (marks the chunk None) instead of fanning out per-job.
        for msg in [
            "HTTP error 429 with body: ...",
            "server returned an error response: error code -32005: rate limit exceeded",
            "Rate Limit Exceeded",
        ] {
            assert!(
                is_rate_limit_error(msg),
                "should be a rate-limit error: {msg:?}"
            );
        }
        // A genuine (non-429) chunk error must NOT be classified as rate-limit (else it
        // skips the per-job fallback that reconciles the one broken chunk).
        for msg in [
            "execution reverted",
            "response size exceeded the limit",
            "connection reset by peer",
        ] {
            assert!(
                !is_rate_limit_error(msg),
                "must NOT be a rate-limit error: {msg:?}"
            );
        }
    }

    #[test]
    fn is_nonce_error_classification() {
        // Only genuine nonce mismatch → is_nonce_error (re-sync). Pending-at-nonce
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
            assert!(
                is_same_nonce_pending(msg),
                "should be same-nonce-pending: {msg:?}"
            );
            assert!(
                !is_nonce_error(msg),
                "pending is NOT a nonce error (would walk forward): {msg:?}"
            );
        }
        for msg in [
            "execution reverted",
            "insufficient funds for gas * price + value",
            "At or past deadline",
            "",
        ] {
            assert!(!is_nonce_error(msg), "should NOT be a nonce error: {msg:?}");
            assert!(
                !is_same_nonce_pending(msg),
                "should NOT be pending: {msg:?}"
            );
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
        assert!(
            got.1 > 1_000,
            "must strictly exceed what we already broadcast, got {}",
            got.1
        );
        assert_eq!(got.1, 1_125);
    }

    /// A caller bid already above the floor wins over the lift.
    #[test]
    fn a_higher_caller_bid_is_preserved() {
        let got = fees_over_floor_state(st(1_000, 8_000), 0, 9_999).unwrap();
        assert_eq!(got.1, 9_999);
    }

    /// AT the cap: exhausted. This is the boundary where re-bidding would otherwise livelock.
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
    /// what gets rejected forever and produces a run of futile sends that never progress.
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

#[cfg(test)]
mod job_path_bid_tests {
    use super::*;
    use crate::nonce::FeeFloorState;

    fn st(broadcast: (u128, u128), cap: u128) -> Option<FeeFloorState> {
        Some(FeeFloorState {
            floor: (broadcast.0.min(cap), broadcast.1.min(cap)),
            broadcast,
            cap,
            exhausted: broadcast.1 >= cap,
        })
    }

    /// The key-wide ceiling lifts the 8x-seed ratchet cap (handoff §10): a fulfil whose nonce cap is
    /// tiny keeps escalating up to the ceiling's reserved limit.
    #[test]
    fn the_ceiling_lifts_a_low_ratchet_cap() {
        // Nonce cap 8,000 is exhausted by a broadcast of 8,000, but the ceiling is 4,000,000.
        match job_path_bid(st((1_000, 8_000), 8_000), 1, 2, 4_000_000, RELEASE_DISPLACE_RUNGS, u128::MAX) {
            JobBid::Send(t, m) => {
                assert_eq!(m, 9_000, "12.5% over the resident");
                assert!(t <= m);
            }
            other => panic!("expected a raise, got {other:?}"),
        }
    }

    /// The fulfil ladder stops RELEASE_DISPLACE_RUNGS rungs below the cap and HOLDS there (re-publishing
    /// the bid already on the wire) — and from that point the same-nonce release can always out-bid it.
    #[test]
    fn a_held_fulfil_always_leaves_the_release_room_to_displace_it() {
        let cap = 1_000_000u128;
        let mut resident = (10u128, 1_000u128);
        let mut held = None;
        for _ in 0..200 {
            match job_path_bid(st(resident, 8_000), resident.0, resident.1, cap, RELEASE_DISPLACE_RUNGS, u128::MAX) {
                JobBid::Send(t, m) => {
                    assert!(m > resident.1, "every raise strictly exceeds the resident");
                    resident = (t, m);
                }
                JobBid::Hold(t, m) => {
                    assert_eq!((t, m), resident, "a hold re-publishes exactly what is on the wire");
                    held = Some(resident);
                    break;
                }
                JobBid::Exhausted => panic!("the fulfil ladder must hold, never exhaust, once it has a resident"),
            }
        }
        let held = held.expect("the ladder reaches its hold point");
        assert!(held.0 <= cap / 9 * 8 / 9 * 8, "the fulfil's TIP holds below the reserved limit");
        // The release (no reserved rungs) displaces the held fulfil, and has a second rung too.
        let JobBid::Send(t1, m1) = job_path_bid(st(held, 8_000), 0, 0, cap, 0, u128::MAX) else {
            panic!("the release must be able to displace a held fulfil");
        };
        assert!(t1 > held.0 && m1 > held.1 && t1 <= cap);
        assert!(
            matches!(job_path_bid(st((t1, m1), 8_000), 0, 0, cap, 0, u128::MAX), JobBid::Send(t2, _) if t2 > t1),
            "a second release rung must fit too"
        );
    }

    /// The release itself stops only at the cap: a raise it cannot fit is Exhausted (never a Hold, which
    /// would re-send a bid the node rejects as underpriced).
    #[test]
    fn the_release_exhausts_only_at_the_cap() {
        assert_eq!(job_path_bid(st((950_000, 960_000), 8_000), 0, 0, 1_000_000, 0, u128::MAX), JobBid::Exhausted);
    }

    /// A high fresh estimate (a block-filler inflates `eth_maxPriorityFeePerGas`) is clamped to the
    /// limit: it must neither freeze the ladder at its old bid nor stop a release being sent.
    #[test]
    fn a_seed_above_the_limit_is_clamped_not_treated_as_the_ceiling() {
        let cap = 1_000_000u128;
        let limit = cap / 9 * 8 / 9 * 8;
        assert_eq!(
            job_path_bid(st((10, 1_000), 8_000), 5_000_000, 5_000_000, cap, RELEASE_DISPLACE_RUNGS, u128::MAX),
            JobBid::Send(limit, 5_000_000)
        );
        assert_eq!(
            job_path_bid(st((10, 1_000), 8_000), 5_000_000, 5_000_000, cap, 0, u128::MAX),
            JobBid::Send(cap, 5_000_000)
        );
    }

    /// The first send on a nonce is clamped too: an unclamped seed is refused by the node (balance or
    /// txfeecap) on every rung, and a refused send records nothing to climb from.
    #[test]
    fn a_first_send_is_clamped_to_the_ceiling_and_the_balance() {
        let cap = 1_000_000u128;
        let limit = cap / 9 * 8 / 9 * 8;
        assert_eq!(
            job_path_bid(None, 5_000_000, 5_000_000, cap, RELEASE_DISPLACE_RUNGS, u128::MAX),
            JobBid::Send(limit, 5_000_000)
        );
        assert_eq!(
            job_path_bid(None, 5_000_000, 5_000_000, cap, RELEASE_DISPLACE_RUNGS, 3_000),
            JobBid::Send(3_000, 3_000)
        );
        assert_eq!(job_path_bid(None, 500, 900, cap, 0, 700), JobBid::Send(500, 700));
        assert_eq!(job_path_bid(None, 5, 9, cap, 0, u128::MAX), JobBid::Send(5, 9));
    }

    /// The release climbs from the normal start price to the ceiling across its rungs (a hold-out at a
    /// slightly higher tip stops being cheap), and a release that mines at once pays the start price.
    #[test]
    fn release_rungs_climb_from_the_start_price_to_the_ceiling() {
        let (tip0, max0) = (10_000_000u128, 10_000_506u128);
        let ceiling = 4_000_000_000u128;
        assert_eq!(release_rung_fees(tip0, max0, 1, ceiling), (tip0, max0));
        let mut prev = tip0;
        for attempt in 2..=MAX_TX_ATTEMPTS {
            let (t, m) = release_rung_fees(tip0, max0, attempt, ceiling);
            assert!(t > prev.saturating_add(prev / 8), "each rung clears the replacement margin");
            assert!(m >= t);
            prev = t;
        }
        let (top, _) = release_rung_fees(tip0, max0, MAX_TX_ATTEMPTS, ceiling);
        assert!(top >= ceiling / 100 * 99 && top <= ceiling, "the last rung reaches the ceiling: {top}");
        // A start price at or above the ceiling never panics or inverts.
        let (t, m) = release_rung_fees(ceiling * 2, ceiling * 2, 3, ceiling);
        assert!(t <= m);
    }

    /// A high maxFee from one quote (a fallback after a failed header read) must not freeze the TIP: the
    /// ceiling bounds the tip, maxFee only the balance.
    #[test]
    fn a_high_max_fee_quote_does_not_freeze_the_tip() {
        let ceiling = 4_000_000_000u128;
        let mut resident = (10_000_000u128, 2_010_000_000u128);
        for _ in 0..30 {
            match job_path_bid(st(resident, 8 * 2_010_000_000), resident.0, resident.1, ceiling, RELEASE_DISPLACE_RUNGS, u128::MAX) {
                JobBid::Send(t, m) => resident = (t, m),
                other => panic!("must keep climbing while the tip is far below the ceiling: {other:?}"),
            }
        }
        assert!(resident.0 > 300_000_000, "tip climbed: {}", resident.0);
    }

    /// A rung the balance cannot fund is refused by the node, never pooled: the fulfil holds at what is
    /// already on the wire instead (handoff §10: ceiling = min(TIP_CEILING, balance / gasLimit, ...)).
    #[test]
    fn the_fulfil_holds_below_what_the_balance_can_fund() {
        assert_eq!(
            job_path_bid(st((10, 1_000), 8_000), 0, 0, 4_000_000, RELEASE_DISPLACE_RUNGS, 1_100),
            JobBid::Hold(10, 1_000)
        );
    }
}

#[cfg(test)]
mod hashed_fulfil_tests {
    use super::{
        fulfill_gas_formula, fulfill_job_hashed_calldata, FulfilCall, HashedFulfil,
    };
    use alloy::dyn_abi::{DynSolValue, JsonAbiExt};
    use alloy::primitives::{keccak256, Address, Bytes, B256};
    use alloy::sol_types::SolCall;
    use zkminer_contracts::bindings::{IHemiProveFulfill, JobDescriptor};

    /// A descriptor with a large, recognizable `inputData` (a witness-job envelope can be up to the
    /// router's 64 KB), non-empty extras and a FIELDS binding.
    fn descriptor(input_len: usize) -> JobDescriptor {
        JobDescriptor {
            programId: B256::repeat_byte(0x11),
            proofSystemId: B256::repeat_byte(0x22),
            callbackContract: Address::repeat_byte(0x33),
            assignedProver: Address::repeat_byte(0x44),
            tag: B256::repeat_byte(0x55),
            inputData: (0..input_len).map(|i| (i % 251) as u8 ^ 0xa5).collect::<Vec<u8>>().into(),
            callbackExtraData: Bytes::from_static(b"callback extra data"),
            extraVerifierData: Bytes::from_static(b"extra verifier data, ignored by risc0"),
            expectedJournalHash: B256::repeat_byte(0x66),
            journalFields: B256::repeat_byte(0x77),
        }
    }

    fn router_abi() -> alloy::json_abi::JsonAbi {
        let path = format!(
            "{}/../../hemiprove-abi/HemiProveRouter.abi.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read the vendored ABI"))
            .expect("parse the vendored ABI")
    }

    #[test]
    fn the_hashed_calldata_matches_the_deployed_abi() {
        let d = descriptor(4_096);
        let f = HashedFulfil::from_descriptor(&d);
        let job = B256::repeat_byte(0x99);
        let journal = b"journal bytes".to_vec();
        let seal = vec![0xe7u8; 260];
        let calldata = fulfill_job_hashed_calldata(job, &f, &journal, &seal);
        // An independent encoder: the vendored c8333aa ABI's own types, through dyn-abi.
        let abi = router_abi();
        let func = &abi.function("fulfillJobHashed").expect("fulfillJobHashed in the ABI")[0];
        let fb = |b: B256| DynSolValue::FixedBytes(b, 32);
        let want = func
            .abi_encode_input(&[
                fb(job),
                DynSolValue::Tuple(vec![
                    fb(d.programId),
                    fb(d.proofSystemId),
                    DynSolValue::Address(d.callbackContract),
                    DynSolValue::Address(d.assignedProver),
                    fb(d.tag),
                    fb(keccak256(&d.inputData)),
                    fb(d.expectedJournalHash),
                    fb(d.journalFields),
                ]),
                DynSolValue::Bytes(d.callbackExtraData.to_vec()),
                DynSolValue::Bytes(d.extraVerifierData.to_vec()),
                DynSolValue::Bytes(journal.clone()),
                DynSolValue::Bytes(seal.clone()),
            ])
            .expect("encode with the ABI");
        assert_eq!(calldata.to_vec(), want);
        assert_eq!(calldata[..4], func.selector().0);
        // It round-trips through the binding, field for field.
        let back = IHemiProveFulfill::fulfillJobHashedCall::abi_decode(&calldata).unwrap();
        assert_eq!(back.jobId, job);
        assert_eq!(back.hashedDesc, f.hashed);
        assert_eq!(back.callbackExtraData, d.callbackExtraData);
        assert_eq!(back.extraVerifierData, d.extraVerifierData);
        assert_eq!(back.publicValues.to_vec(), journal);
        assert_eq!(back.proofBytes.to_vec(), seal);
        // The private dispatcher sends exactly this.
        let pv = Bytes::from(journal);
        let pb = Bytes::from(seal);
        assert_eq!(FulfilCall::Hashed(f).calldata(job, &pv, &pb), calldata);
    }

    #[test]
    fn input_data_is_not_in_the_hashed_calldata() {
        let d = descriptor(65_000);
        let f = HashedFulfil::from_descriptor(&d);
        let job = B256::repeat_byte(0x99);
        let (pv, pb) = (Bytes::from_static(b"journal"), Bytes::from(vec![0xe7u8; 260]));
        let hashed = FulfilCall::Hashed(f.clone()).calldata(job, &pv, &pb);
        let full = FulfilCall::Full(d.clone()).calldata(job, &pv, &pb);
        let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        // Not one 32-byte window of inputData appears in the hashed form; it does in the full one.
        let probe = &d.inputData[1_000..1_032];
        assert!(contains(&full, probe));
        assert!(!contains(&hashed, probe));
        for chunk in d.inputData.chunks(32).filter(|c| c.len() == 32) {
            assert!(!contains(&hashed, chunk));
        }
        // Only its hash travels, in the hashed descriptor.
        assert!(contains(&hashed, keccak256(&d.inputData).as_slice()));
        assert_eq!(f.hashed.inputDataHash, keccak256(&d.inputData));
        // The extras still travel raw: the router hashes them itself.
        assert!(contains(&hashed, &d.callbackExtraData));
        assert!(contains(&hashed, &d.extraVerifierData));
        // ~65 KB less calldata: the gas formula's 16/byte term drops by the same amount.
        assert!(full.len() - hashed.len() >= 65_000 - 64, "{} vs {}", full.len(), hashed.len());
        let (gf, gh) = (
            fulfill_gas_formula(0, full.len(), pv.len()),
            fulfill_gas_formula(0, hashed.len(), pv.len()),
        );
        assert_eq!(gf - gh, 16 * (full.len() - hashed.len()) as u64);
    }

    /// `run.rs` spawns the fulfil and gate futures on tokio: they must be `Send` (no `std` mutex
    /// guard of the DA book held across an await). Compile-time only.
    #[allow(dead_code)]
    fn the_da_futures_are_send(
        c: &crate::client::ChainClient,
        f: HashedFulfil,
        da: &super::FulfilDa,
        reader: &crate::da::BacklogReader,
    ) {
        fn send<T: Send>(_: T) {}
        send(c.fulfill_job_hashed(B256::ZERO, f.clone(), Bytes::new(), Bytes::new(), None, None, Some(da)));
        send(c.fulfill_job(B256::ZERO, descriptor(0), Bytes::new(), Bytes::new(), None, None));
        send(reader.read(c));
        send(crate::da::estimate_fulfil_da_bytes(
            c,
            B256::ZERO,
            &f,
            &[],
            &crate::da::SealSpec::risc0_groth16(),
        ));
        send(c.claimability(B256::ZERO, Address::ZERO));
        send(c.observe_pending());
        send(c.replace_with_self_transfer(0));
        send(c.fill_reserved_nonce(0));
    }

    #[test]
    fn the_rebuilt_descriptor_hash_is_the_submitted_one() {
        // `_hashDescriptorFields` from the hashed fields equals submit's hash of the full descriptor.
        for len in [0usize, 1, 31, 32, 33, 4_096] {
            let mut d = descriptor(len);
            assert_eq!(
                HashedFulfil::from_descriptor(&d).descriptor_hash(),
                crate::descriptor::compute_descriptor_hash(&d),
                "inputData of {len} bytes"
            );
            d.callbackExtraData = Bytes::new();
            d.extraVerifierData = Bytes::new();
            d.journalFields = B256::ZERO;
            assert_eq!(
                HashedFulfil::from_descriptor(&d).descriptor_hash(),
                crate::descriptor::compute_descriptor_hash(&d)
            );
        }
        // Every field is bound: changing any one changes the hash.
        let d = descriptor(100);
        let base = HashedFulfil::from_descriptor(&d);
        let h0 = base.descriptor_hash();
        let mut f = base.clone();
        f.hashed.inputDataHash = B256::ZERO;
        assert_ne!(f.descriptor_hash(), h0);
        let mut f = base.clone();
        f.callback_extra_data = Bytes::from_static(b"other");
        assert_ne!(f.descriptor_hash(), h0);
        let mut f = base.clone();
        f.extra_verifier_data = Bytes::new();
        assert_ne!(f.descriptor_hash(), h0);
        let mut f = base;
        f.hashed.journalFields = B256::ZERO;
        assert_ne!(f.descriptor_hash(), h0);
    }
}
