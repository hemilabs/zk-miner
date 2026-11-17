//! The pure decisions of the witness path (docs/witness-construction-jobs.md §5.2 step 7, §15.2,
//! §16, §17.2): routing, verdict lifetimes, the artifact budget, the reservation, the proving-time
//! estimate and its fits (the watchdog, the deadline), prove resources, which cards may prove a
//! bundle, pin evidence, and the post-lock failure tallies. No I/O, so each is unit-tested here.

use std::collections::HashMap;
use std::time::Duration;

use alloy::primitives::{keccak256, Address, B256, U256};
use zkminer_chain::claimability::NotClaimable;
use zkminer_chain::governance::GateRefusal;
use zkminer_witness::verdict::{PostLockFailureClass, Retry, SkipReason};

// ── routing ───────────────────────────────────────────────────────────────────

/// Whether `input_data` is a witness-construction job's (`WITNESS_JOB_TAG_V1 ‖ envelope`, §7.1).
pub(crate) fn is_witness_input(input_data: &[u8]) -> bool {
    zkminer_witness::envelope::classify(input_data).is_some()
}

/// Phase-1 admission (§17.3): allowlist mode. Only a caller listed in `[witness] callers` is
/// simulated; open admission is refused by the config's validation in this release.
pub(crate) fn caller_admitted(callers: &[Address], caller: Address) -> bool {
    callers.contains(&caller)
}

/// How long a witness job this host does not serve is set aside: ranked last in the Open set and
/// skipped by the candidate loop, as the inline path sets aside a job it cannot claim on a verdict
/// that lasts (`DETERMINISTIC_SKIP_TTL`). For a witness job with no runtime here, a caller not on
/// `[witness] callers`, journal-bound jobs off, or a caller over its post-lock failure limit: a
/// flood of high-priced witness jobs nobody here serves must not hold the Open set's top slots.
pub(crate) const UNSERVED_SET_ASIDE: Duration = Duration::from_secs(600);
/// The set-aside while witness serving is off here (its self-tests not passed yet, or failing): an
/// allowlisted caller's job is looked at again soon after serving comes back.
pub(crate) const SERVING_OFF_SET_ASIDE: Duration = Duration::from_secs(60);

/// The set-aside for a job whose verdict holds until `until` (unix seconds) at `now`: the rest of
/// the verdict.
pub(crate) fn verdict_set_aside(until: u64, now: u64) -> Duration {
    Duration::from_secs(until.saturating_sub(now))
}

// ── verdicts (§15.2, §16) ─────────────────────────────────────────────────────

/// How long a final verdict (no retry left, or one that never retries) is kept: long enough that a
/// permanently bad job is not simulated again while it can still be locked (a job's whole window
/// is at most 7 days), short enough that the store does not keep it forever. Verdicts of a terminal
/// job are dropped with its bundles.
pub(crate) const VERDICT_FINAL_TTL_SECS: u64 = 8 * 24 * 3600;
/// `Retry::OnHostChange`: the outcome cannot change before this host's configuration or build does;
/// a restart re-reads the configuration, and this bounds how long a change made otherwise waits.
pub(crate) const VERDICT_HOST_CHANGE_TTL_SECS: u64 = 3600;
/// `Retry::Deferred`: not a judgement of the job, looked at again soon.
pub(crate) const VERDICT_DEFERRED_TTL_SECS: u64 = 60;
/// `Retry::Backoff`: the first wait, doubled per attempt, capped.
pub(crate) const VERDICT_BACKOFF_BASE_SECS: u64 = 30;
pub(crate) const VERDICT_BACKOFF_MAX_SECS: u64 = 3600;
/// `Retry::OnceJittered`: the one retry waits this long plus up to `VERDICT_JITTER_SECS`.
pub(crate) const VERDICT_RETRY_MIN_SECS: u64 = 60;
pub(crate) const VERDICT_JITTER_SECS: u64 = 120;

/// What to persist for a skip: the attempt count, how long the verdict holds, and whether it is
/// final (no retry left).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerdictPlan {
    pub attempts: u8,
    pub ttl_secs: u64,
    pub final_verdict: bool,
}

/// The verdict to persist for `reason`, after `prior_attempts` earlier skips of the job recorded in
/// the store (an expired verdict still carries its count). `jitter` is a uniform draw in `[0, 1)`
/// for the one jittered retry. While a verdict holds, the job is neither simulated nor claimed.
pub(crate) fn verdict_plan(reason: SkipReason, prior_attempts: u8, jitter: f64) -> VerdictPlan {
    let attempts = prior_attempts.saturating_add(1);
    let final_plan = VerdictPlan { attempts, ttl_secs: VERDICT_FINAL_TTL_SECS, final_verdict: true };
    match reason.verdict().retry {
        Retry::Never => final_plan,
        Retry::OnceJittered if attempts >= 2 => final_plan,
        Retry::OnceJittered => {
            let j = if jitter.is_finite() { jitter.clamp(0.0, 1.0) } else { 0.0 };
            VerdictPlan {
                attempts,
                ttl_secs: VERDICT_RETRY_MIN_SECS + (j * VERDICT_JITTER_SECS as f64) as u64,
                final_verdict: false,
            }
        }
        Retry::Backoff { max_attempts } if attempts >= max_attempts => final_plan,
        Retry::Backoff { .. } => {
            let shift = u32::from(attempts.saturating_sub(1)).min(16);
            VerdictPlan {
                attempts,
                ttl_secs: (VERDICT_BACKOFF_BASE_SECS << shift).min(VERDICT_BACKOFF_MAX_SECS),
                final_verdict: false,
            }
        }
        Retry::OnHostChange => VerdictPlan {
            attempts,
            ttl_secs: VERDICT_HOST_CHANGE_TTL_SECS,
            final_verdict: false,
        },
        Retry::Deferred => VerdictPlan {
            attempts,
            ttl_secs: VERDICT_DEFERRED_TTL_SECS,
            final_verdict: false,
        },
    }
}

/// The `expires_at` at or below which a persisted verdict is deleted, at `now`: only verdicts expired
/// for a whole final-verdict lifetime. An expired verdict no longer holds its job back, but its
/// attempt count is what the job's next skip builds on (a one-retry verdict is final on the second
/// failure, a back-off counts to its limit); deleting it at expiry restarted that count every time,
/// and a job that keeps failing was simulated again forever.
pub(crate) fn verdict_drop_cutoff(now: u64) -> u64 {
    now.saturating_sub(VERDICT_FINAL_TTL_SECS)
}

/// A claimability refusal as a §16 verdict. Every refusal is state that moves on its own (a pause,
/// a window, a cooldown, stake), so all are `NotClaimable` (retried with back-off); a read that
/// failed is the operator's endpoint.
pub(crate) fn not_claimable_reason(nc: &NotClaimable) -> SkipReason {
    match nc {
        NotClaimable::Unreadable(_) => SkipReason::OperatorEndpoint,
        _ => SkipReason::NotClaimable,
    }
}

/// A governance refusal as a §16 verdict: an unsynced or stale watcher is this host's state; every
/// other refusal (a pause, a disable, a pending swap or upgrade, a cancel or bid) is the chain's.
pub(crate) fn gate_refusal_reason(r: &GateRefusal) -> SkipReason {
    match r {
        GateRefusal::NotSynced | GateRefusal::Stale => SkipReason::HostInternal,
        _ => SkipReason::NotClaimable,
    }
}

// ── the artifact budget ───────────────────────────────────────────────────────

/// The per-job budget for a `hemi-code` artifact read (§13.4 step 3): its bytes and chunk reads,
/// derived from the largest artifact this host reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArtifactBudget {
    pub max_bytes: u64,
    pub max_chunks: u32,
}

impl ArtifactBudget {
    /// `max_bytes` of artifact, in chunks of at most one contract's code each (plus one for a
    /// chunking that does not fill every chunk), never more than a manifest can list.
    pub(crate) fn for_max_bytes(max_bytes: u64) -> Self {
        let per_chunk = zkminer_witness::manifest::MAX_CHUNK_BODY as u64;
        let chunks = max_bytes.div_ceil(per_chunk).saturating_add(1);
        Self {
            max_bytes,
            max_chunks: u32::try_from(chunks)
                .unwrap_or(u32::MAX)
                .min(zkminer_witness::manifest::MAX_MANIFEST_CHUNKS),
        }
    }

    pub(crate) fn admits(&self, length: u64, chunks: u32) -> bool {
        length <= self.max_bytes && chunks <= self.max_chunks
    }
}

// ── the reservation (§17.2, simplified) ───────────────────────────────────────

/// Gas a `claimJob` transaction is budgeted at in the reservation.
pub(crate) const CLAIM_GAS: u64 = 400_000;
const WEI_PER_HEMI: f64 = 1e18;

/// The terms of §17.2's reservation this release computes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ReservationInputs {
    /// The fulfil's gas limit (the formula's, at least the configured floor).
    pub fulfil_gas: u64,
    /// `maxFeePerGas` the claim and the fulfil are expected to pay, wei.
    pub max_fee_per_gas: u128,
    /// `[witness] hemi_per_eth`.
    pub hemi_per_eth: f64,
    /// Seconds of proving expected (the deadline estimate's).
    pub prove_secs: f64,
    /// Seconds of simulation (builder wall time including compilation, plus guest execution).
    pub simulation_secs: f64,
    /// GiB-hours the bundle is expected to be retained.
    pub retained_gib_hours: f64,
    /// `[witness] unit_prices`, HEMI.
    pub cpu_second_hemi: f64,
    pub gib_hour_retained_hemi: f64,
    /// `[witness] k`.
    pub k: f64,
}

/// The reservation in HEMI wei (§17.2), simplified for Phase 1 and documented as such:
///
/// ```text
/// (claim gas + fulfil gas) x maxFeePerGas x HEMI_PER_ETH x 1.25
///   + prove seconds x cpu_second_hemi
///   + k x (simulation seconds x cpu_second_hemi + GiB-hours retained x gib_hour_retained_hemi)
/// ```
///
/// - The fulfil's L1 (DA) fee is not priced separately: Hemi's L1 fee per estimated DA byte is
///   tiny next to the L2 gas at the expected tip, and the claim gate already holds the exact fulfil
///   under the operator's DA cap. The 1.25 factor covers it.
/// - The callback's gas is inside the fulfil gas formula (`callbackGasLimit`, 200k when 0), whether
///   or not the callback contract has code.
/// - Proving is priced by the one CPU-second unit price, at the deadline estimate's seconds;
///   provider overage units are not counted (Phase 1 serves allowlisted callers' jobs, whose
///   sources the operator provisions).
/// - P̂(win) = 1: allowlist mode (§17.2), so the simulation term is not divided.
///
/// A non-finite or negative input counts as zero; the result saturates.
pub(crate) fn reservation_wei(r: &ReservationInputs) -> u128 {
    let nn = |v: f64| if v.is_finite() && v > 0.0 { v } else { 0.0 };
    let gas = (CLAIM_GAS.saturating_add(r.fulfil_gas)) as f64 * r.max_fee_per_gas as f64;
    let gas_hemi_wei = gas * nn(r.hemi_per_eth) * 1.25;
    let prove = nn(r.prove_secs) * nn(r.cpu_second_hemi) * WEI_PER_HEMI;
    let simulation = nn(r.k)
        * (nn(r.simulation_secs) * nn(r.cpu_second_hemi) + nn(r.retained_gib_hours) * nn(r.gib_hour_retained_hemi))
        * WEI_PER_HEMI;
    let total = gas_hemi_wei + prove + simulation;
    if total >= u128::MAX as f64 {
        u128::MAX
    } else {
        total.ceil() as u128
    }
}

// ── the proving-time estimate (§5.2 step 7: "prove time leaves a margin before D") ──────────

/// Seconds allowed for the lock transaction to be mined after the gate.
pub(crate) const CLAIM_MINE_ALLOWANCE_SECS: u64 = 60;
/// Seconds of a risc0 proof on a GPU card that do not scale with cycles when its benchmark measured
/// no Groth16 wrap (or it has no row): a GPU wraps in seconds; this covers a cold proving key and a
/// slow card.
pub(crate) const RISC0_GROTH16_ALLOWANCE_SECS: u64 = 120;
/// The same for a CPU slot with no measured wrap: on a CPU the Groth16 path (the succinct lift, the
/// `identity_p254` recursion and the shrink-wrap) takes minutes, whatever the guest — 337 s of a
/// 359 s proof of a 32k-cycle guest on an idle 32-core host; the same proof took 859 s beside other
/// heavy builds (a debug worker, 2026-11-16). A benchmarked CPU slot uses its measured wrap instead.
pub(crate) const RISC0_CPU_PROOF_ALLOWANCE_SECS: u64 = 900;
/// The cycles-per-second floor of a CPU slot with no benchmark row (the GPU floor is the inline
/// path's `risc0_conservative_cps`).
pub(crate) const RISC0_CPU_CONSERVATIVE_CPS: f64 = 10_000.0;
/// A measured wrap is budgeted at this multiple of the measurement...
pub(crate) const MEASURED_WRAP_FACTOR: f64 = 2.0;
/// ...and never below this.
pub(crate) const MEASURED_WRAP_FLOOR_SECS: u64 = 30;

/// The seconds of one card's proof that do not scale with cycles: its benchmark's measured Groth16
/// wrap (`DeviceBenchmark::wrap_secs`) with headroom, else the allowance for its kind.
pub(crate) fn fixed_allowance_secs(measured_wrap_secs: Option<f64>, cpu: bool) -> u64 {
    match measured_wrap_secs.filter(|w| w.is_finite() && *w > 0.0) {
        Some(w) => ((w * MEASURED_WRAP_FACTOR).ceil() as u64).max(MEASURED_WRAP_FLOOR_SECS),
        None if cpu => RISC0_CPU_PROOF_ALLOWANCE_SECS,
        None => RISC0_GROTH16_ALLOWANCE_SECS,
    }
}

/// How a witness proof's time is planned: the slowest rate among the cards that may prove it, the
/// largest fixed allowance among them, and the operator's `deadline_safety_margin`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ProvePlan {
    /// Cycles per second (each card's benchmarked rate at its size, else the floor for its kind).
    pub cps: f64,
    /// [`fixed_allowance_secs`], the largest over the cards.
    pub fixed_secs: u64,
    /// `[prover] deadline_safety_margin`, at least 1.
    pub margin: f64,
}

impl ProvePlan {
    /// The plan over cards given as `(cycles/s, fixed seconds)`; `None` without any.
    pub(crate) fn over(cards: impl IntoIterator<Item = (f64, u64)>, margin: f64) -> Option<Self> {
        let mut plan: Option<ProvePlan> = None;
        let margin = if margin.is_finite() && margin >= 1.0 { margin } else { 1.0 };
        for (cps, fixed) in cards {
            let cps = if cps.is_finite() && cps >= 1.0 { cps } else { 1.0 };
            plan = Some(match plan {
                None => ProvePlan { cps, fixed_secs: fixed, margin },
                Some(p) => ProvePlan { cps: p.cps.min(cps), fixed_secs: p.fixed_secs.max(fixed), margin },
            });
        }
        plan
    }
}

/// The expected seconds of one proof attempt of a witness lock: its sized cycles at the plan's rate
/// plus the fixed allowance (the Groth16 wrap), both times the safety margin (as the inline gate
/// sizes a job: the fixed part slows down on a loaded host as much as the rest), plus the execute
/// allowance (three times the measured execute, as `execute_allowance_secs` grants inline jobs: the
/// prove executes again and replays segments).
pub(crate) fn estimate_prove_secs(cycles: u64, plan: &ProvePlan, execute_secs: u64) -> u64 {
    let cps = if plan.cps.is_finite() && plan.cps >= 1.0 { plan.cps } else { 1.0 };
    let proving = ((cycles as f64 / cps + plan.fixed_secs as f64) * plan_margin(plan)).ceil();
    let proving = if proving >= u64::MAX as f64 { u64::MAX } else { proving as u64 };
    proving.saturating_add(execute_secs.saturating_mul(3))
}

/// The plan's safety margin, at least 1.
fn plan_margin(plan: &ProvePlan) -> f64 {
    if plan.margin.is_finite() && plan.margin >= 1.0 {
        plan.margin
    } else {
        1.0
    }
}

/// Whether one attempt of `prove_secs` finishes inside the per-attempt watchdog (the witness prove
/// runs under `[prover] proving_timeout_secs`): a proof the watchdog kills on every attempt is
/// released at a penalty, however long its window. The inline gate refuses at `>=` too.
pub(crate) fn watchdog_admits(prove_secs: u64, proving_timeout_secs: u64) -> bool {
    prove_secs < proving_timeout_secs
}

/// Whether a lock taken now leaves the margin before `D` (§5.2 step 7): the proof (with the safety
/// margin, [`estimate_prove_secs`]), the lock's mining, one minimum attempt's slack and the fulfil
/// margin all fit in the job's `fulfillmentTimeout` window.
pub(crate) fn deadline_fits(window_secs: u64, prove_secs: u64, fulfil_margin_secs: u64, min_attempt_secs: u64) -> bool {
    // An overflowing need never fits.
    prove_secs
        .checked_add(fulfil_margin_secs)
        .and_then(|n| n.checked_add(min_attempt_secs))
        .and_then(|n| n.checked_add(CLAIM_MINE_ALLOWANCE_SECS))
        .is_some_and(|need| need <= window_secs)
}

/// The host-derived maximum for `maxGuestCycles` when `[witness] max_guest_cycles` is unset: the
/// sized cycles one attempt can prove inside the watchdog at the plan's rate (beside its fixed
/// allowance, both with the margin, as [`estimate_prove_secs`] counts them), at most an hour of
/// proving, at most 2^34. Zero when the margined fixed allowance alone fills the watchdog: no witness
/// job can be proven here, and every one is refused at the static gates rather than simulated. The
/// claim gate then checks each job's measured cycles and execute.
pub(crate) fn host_max_guest_cycles(plan: &ProvePlan, proving_timeout_secs: u64) -> u64 {
    const MAX: u64 = 1 << 34;
    let cps = if plan.cps.is_finite() && plan.cps > 0.0 { plan.cps } else { 0.0 };
    // The watchdog admits an estimate strictly below it: (cycles / cps + fixed) x margin <= T - 1.
    let room = proving_timeout_secs.saturating_sub(1) as f64 / plan_margin(plan) - plan.fixed_secs as f64;
    let cycles = (room.max(0.0) * cps).min(cps * 3600.0);
    if cycles >= MAX as f64 {
        MAX
    } else {
        cycles.max(0.0) as u64
    }
}

/// `ZKMINER_RISC0_MAX_SESSION_CYCLES` as the risc0 prove worker reads it (it inherits the miner's
/// environment): `None` when unset, unparsable or zero.
pub(crate) fn parse_session_cap(v: Option<&str>) -> Option<u64> {
    v.and_then(|s| s.trim().parse::<u64>().ok()).filter(|&n| n > 0)
}

/// Whether a proof of `cycles` (sized: segments padded to their power of two, at least what the
/// executor counts against its session limit) stays inside the operator's session cap.
pub(crate) fn session_cap_admits(cycles: u64, cap: Option<u64>) -> bool {
    cap.is_none_or(|c| cycles <= c)
}

/// The time a held witness lock must be proven and fulfilled by: its deadline, or a pending
/// verifier swap's `readyAt` when that comes first (§5.5: a proof for the old verifier can then only
/// be released, so the miner acts before `readyAt`).
pub(crate) fn proving_cutoff(lock_deadline: u64, switch_ready_at: Option<u64>) -> u64 {
    match switch_ready_at {
        Some(r) if r < lock_deadline => r,
        _ => lock_deadline,
    }
}

// ── prove resources ───────────────────────────────────────────────────────────

/// Free bytes kept on the segment filesystem beyond every reservation.
pub(crate) const SEGMENT_FLOOR_BYTES: u64 = 1 << 30;

/// Whether one more proof's segments (`needed`) fit the segment filesystem's `free` bytes beside
/// the `reserved` bytes of witness proofs already planned or running, keeping the floor.
pub(crate) fn segments_fit(needed: u64, reserved: u64, free: u64) -> bool {
    needed.saturating_add(reserved).saturating_add(SEGMENT_FLOOR_BYTES) <= free
}

/// The segment bytes a proof of a bundle may write: the largest over its executed po2s (one proof
/// runs at one po2).
pub(crate) fn segment_need(per_po2_segment_bytes: impl IntoIterator<Item = u64>) -> u64 {
    per_po2_segment_bytes.into_iter().max().unwrap_or(0)
}

/// Whether the ETH balance funds this claim and the fulfil of every lock held besides it (`held`)
/// and of this one, at `max_fee` per gas: the inline gate's funding check (`FUNDS-SHORT`), so a
/// witness lock is never taken on a key whose fulfils the node would refuse.
pub(crate) fn funds_cover(balance: U256, fulfil_gas: u64, max_fee: u128, held: usize) -> bool {
    let fulfils = u128::from(fulfil_gas).saturating_mul(max_fee).saturating_mul(held as u128 + 1);
    let need = fulfils.saturating_add(u128::from(CLAIM_GAS).saturating_mul(max_fee));
    balance >= U256::from(need)
}

/// Whether a card is free for one more witness lock: the inline jobs still needing a card and the
/// witness locks held here leave room under the concurrency cap. A witness proof has no priority at
/// the dispatcher, so a lock queued behind a full look-ahead queue of inline work could wait out
/// its margin.
pub(crate) fn card_room(inline_needing: usize, witness_locks: usize, max_concurrent: usize) -> bool {
    inline_needing.saturating_add(witness_locks) < max_concurrent.max(1)
}

// ── which cards prove a bundle ────────────────────────────────────────────────

/// The cards (slot, its job po2) that may prove a bundle executed at `executed`, each at the
/// largest executed po2 that fits it (its own size or below: a smaller segment needs less of the
/// card). A card no executed po2 fits never proves it: a witness lock proves only at a po2 it
/// executed (§5.4, §18), with no fallback to an unexecuted size (inline jobs fall back to po2 20).
pub(crate) fn witness_prove_sizes(cards: &[(String, u8)], executed: &[u32]) -> HashMap<String, u8> {
    cards
        .iter()
        .filter_map(|(slot, card_po2)| {
            let p = executed.iter().copied().filter(|p| *p <= u32::from(*card_po2)).max()?;
            Some((slot.clone(), u8::try_from(p).ok()?))
        })
        .collect()
}

// ── per-caller accounting (§16, Phase 1) ──────────────────────────────────────

/// Per-caller blame: final verdicts that count against the caller (`blames_caller`). A simple
/// counter for Phase 1; the credit ledger of §17.4 replaces it. Post-lock failures are tallied apart
/// ([`caller_tally_key`]), persisted in the store.
#[derive(Debug, Default)]
pub(crate) struct Blame {
    simulation: HashMap<Address, u32>,
}

/// Callers tracked at most (a flood of fresh addresses evicts the oldest counts, never grows).
const BLAME_CAP: usize = 4096;

impl Blame {
    /// Records a final verdict; returns the caller's simulation-failure count if it was blamed.
    pub(crate) fn note_verdict(&mut self, caller: Address, reason: SkipReason, plan: &VerdictPlan) -> Option<u32> {
        if !(plan.final_verdict && reason.verdict().blames_caller) {
            return None;
        }
        if self.simulation.len() >= BLAME_CAP && !self.simulation.contains_key(&caller) {
            self.simulation.clear();
        }
        let n = self.simulation.entry(caller).or_default();
        *n = n.saturating_add(1);
        Some(*n)
    }

}

// ── post-lock failures (§16) ──────────────────────────────────────────────────

/// Post-lock witness failures of one caller (within [`POST_LOCK_TALLY_TTL_SECS`] of the latest)
/// from which its witness jobs are no longer admitted.
pub(crate) const POST_LOCK_CALLER_LIMIT: u8 = 3;
/// Post-lock witness failures of one class on one device from which the device proves no witness
/// lock (§16: "a device with ≥ 2 is quarantined").
pub(crate) const POST_LOCK_DEVICE_LIMIT: u8 = 2;
/// How long a post-lock tally lasts after its latest failure.
pub(crate) const POST_LOCK_TALLY_TTL_SECS: u64 = 7 * 24 * 3600;

/// The store key a caller's post-lock tally is kept under (a verdict record whose `attempts` is the
/// count): domain-separated, so never a job id, and fixed-size (no attacker string is stored).
pub(crate) fn caller_tally_key(caller: Address) -> B256 {
    keccak256([b"zkminer/witness/post-lock/caller/v1".as_slice(), caller.as_slice()].concat())
}

/// The store key of one device's tally for one failure class. `device` is this host's own name for
/// the card (its PCI bus id, or the slot), never anything a job supplies.
pub(crate) fn device_tally_key(device: &str, class: PostLockFailureClass) -> B256 {
    keccak256([b"zkminer/witness/post-lock/device/v1".as_slice(), device.as_bytes(), &[class as u8]].concat())
}

/// Every post-lock failure class, for the quarantine check.
pub(crate) const POST_LOCK_CLASSES: [PostLockFailureClass; 7] = [
    PostLockFailureClass::Gpu,
    PostLockFailureClass::ProverCrash,
    PostLockFailureClass::ResourceLimit,
    PostLockFailureClass::ProveTimeEstimate,
    PostLockFailureClass::GasOrRpc,
    PostLockFailureClass::BundleLoss,
    PostLockFailureClass::JournalDiverged,
];

/// A tally's count at `now`: its count while it lasts, else 0 (an expired tally starts again).
pub(crate) fn tally_count(attempts: u8, expires_at: u64, now: u64) -> u8 {
    if expires_at > now {
        attempts
    } else {
        0
    }
}

// ── pin evidence (§15.2) ──────────────────────────────────────────────────────

/// A read of a pinned job's record: its state and the block it was read at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinRead {
    pub status: u8,
    pub prover: Address,
    pub reopen_count: u8,
    pub at_block: u64,
}

/// What a pin records about the lock it was taken for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct PinFacts {
    /// The job's `reopenCount` when the pin was taken.
    pub reopen_count: Option<u8>,
    /// A block the job read Locked by us at (0: the claim was never confirmed).
    pub lock_block: u64,
    pub pinned_at_block: u64,
    /// Chain time when the pin was taken (0: unknown).
    pub pinned_at_unix: u64,
}

/// Whether a non-terminal read proves the lock a pin was taken for is gone (or never was), so the
/// pin may go (§15.2: "removed only on an authoritative terminal read, or when the claim provably
/// never landed ... judged by chain time, never wall clock alone"). Anything less keeps the pin:
///
/// - the reopen count is above the pin's (read at or after the pin's block when it was taken): that
///   lock instance ended, whoever held it (a read never shows a count above the chain's, however far
///   it lags);
/// - a read at or after our lock block shows another prover, or no one;
/// - the claim was never confirmed, chain time is past the claim-intent age since the pin, and a read
///   at or after the pin's block shows the job not ours: every claim attempt of ours has ended
///   (zkminer's breadcrumb rule), and none landed.
///
/// A read showing the job Locked by us is never evidence that a lock of ours is gone. `chain_now` is
/// the lower chain-time estimate (`chain_now_floor`), so the age is never overstated.
pub(crate) fn pin_lock_gone(pin: &PinFacts, read: &PinRead, us: Address, chain_now: u64, claim_intent_max_age: u64) -> bool {
    const LOCKED: u8 = 1;
    if read.prover == us && read.status == LOCKED {
        return false;
    }
    if pin.reopen_count.is_some_and(|r| read.reopen_count > r) {
        return true;
    }
    if pin.lock_block != 0 {
        return read.at_block >= pin.lock_block;
    }
    pin.pinned_at_unix != 0
        && chain_now >= pin.pinned_at_unix.saturating_add(claim_intent_max_age)
        && read.at_block >= pin.pinned_at_block
}

/// The journal-divergence decision (§15.3): a re-executed journal is acceptable for one re-dispatch
/// when the guest halted with 0, the whole journal came back, and it is within the journal cap; the
/// binding, DA and gas checks follow (they need the chain).
pub(crate) fn divergence_reusable(exit_halted_zero: bool, journal_len: usize, journal_len_reported: u32) -> bool {
    exit_halted_zero
        && journal_len as u64 == u64::from(journal_len_reported)
        && journal_len <= zkminer_chain::jobs::MAX_JOURNAL_BYTES
}

/// The seconds of `[witness] hemi_per_eth_expires` left at `now` (0 once it has passed).
pub(crate) fn rate_secs_left(expires_unix: i64, now_unix: i64) -> u64 {
    u64::try_from(expires_unix.saturating_sub(now_unix)).unwrap_or(0)
}

/// A job's short id for logs.
pub(crate) fn short(id: B256) -> String {
    format!("{id}")[..10].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkminer_witness::verdict::SkipReason::*;

    #[test]
    fn routing_needs_the_tag_and_an_allowlisted_caller() {
        let env = zkminer_witness::envelope::WITNESS_JOB_TAG_V1;
        let mut input = env.to_vec();
        input.extend_from_slice(&[0u8; 64]);
        assert!(is_witness_input(&input));
        assert!(!is_witness_input(&input[..31]), "shorter than the tag");
        assert!(!is_witness_input(&10u32.to_le_bytes()), "an inline input");
        let mut other = input.clone();
        other[0] ^= 1;
        assert!(!is_witness_input(&other));
        let (a, b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        assert!(caller_admitted(&[a], a));
        assert!(!caller_admitted(&[a], b));
        assert!(!caller_admitted(&[], a), "an empty allowlist serves no one");
    }

    #[test]
    fn verdict_lifetimes_follow_the_retry_class() {
        // Permanent for the job: final at once, for the long TTL.
        let p = verdict_plan(BuilderTrap, 0, 0.5);
        assert_eq!(p, VerdictPlan { attempts: 1, ttl_secs: VERDICT_FINAL_TTL_SECS, final_verdict: true });
        // One jittered retry, then final.
        let first = verdict_plan(BindingMismatch, 0, 0.5);
        assert!(!first.final_verdict);
        assert_eq!(first.ttl_secs, VERDICT_RETRY_MIN_SECS + VERDICT_JITTER_SECS / 2);
        assert!(verdict_plan(BindingMismatch, 0, 0.0).ttl_secs >= VERDICT_RETRY_MIN_SECS);
        assert!(verdict_plan(BindingMismatch, 0, 7.0).ttl_secs <= VERDICT_RETRY_MIN_SECS + VERDICT_JITTER_SECS);
        assert!(verdict_plan(BindingMismatch, 0, f64::NAN).ttl_secs >= VERDICT_RETRY_MIN_SECS);
        assert!(verdict_plan(BindingMismatch, 1, 0.5).final_verdict);
        // Back-off doubles, capped, then final at its attempt limit (NotClaimable: 8).
        let waits: Vec<u64> = (0..7).map(|n| verdict_plan(SkipReason::NotClaimable, n, 0.0).ttl_secs).collect();
        assert_eq!(waits, vec![30, 60, 120, 240, 480, 960, 1920]);
        assert!(verdict_plan(SkipReason::NotClaimable, 7, 0.0).final_verdict);
        assert_eq!(verdict_plan(HostInternal, 200, 0.0).ttl_secs, VERDICT_FINAL_TTL_SECS);
        // ArtifactUnavailable: three tries.
        assert!(!verdict_plan(ArtifactUnavailable, 1, 0.0).final_verdict);
        assert!(verdict_plan(ArtifactUnavailable, 2, 0.0).final_verdict);
        // Host support and deferrals are never final.
        let h = verdict_plan(UnsupportedSubmission, 9, 0.0);
        assert_eq!((h.ttl_secs, h.final_verdict), (VERDICT_HOST_CHANGE_TTL_SECS, false));
        let d = verdict_plan(NotAdmitted, 0, 0.0);
        assert_eq!((d.ttl_secs, d.final_verdict), (VERDICT_DEFERRED_TTL_SECS, false));
        // Attempts saturate.
        assert_eq!(verdict_plan(HostInternal, u8::MAX, 0.0).attempts, u8::MAX);
    }

    #[test]
    fn expired_verdicts_keep_their_attempts_until_long_after() {
        let now = 1_800_000_000u64;
        let cutoff = verdict_drop_cutoff(now);
        // `expire_verdicts(cutoff)` drops `expires_at <= cutoff`.
        let expired_a_minute_ago = now - 60;
        assert!(expired_a_minute_ago > cutoff, "kept: the job's next skip builds on its count");
        let first = verdict_plan(BindingMismatch, 0, 0.5);
        let second = verdict_plan(BindingMismatch, first.attempts, 0.5);
        assert!(second.final_verdict, "the retry's failure is final because the count survived");
        assert!(now - VERDICT_FINAL_TTL_SECS - 1 <= cutoff, "dropped once expired for a final lifetime");
        assert_eq!(verdict_drop_cutoff(5), 0);
    }

    #[test]
    fn only_final_caller_verdicts_blame_the_caller() {
        let mut b = Blame::default();
        let c = Address::repeat_byte(9);
        let first = verdict_plan(BindingMismatch, 0, 0.0);
        assert_eq!(b.note_verdict(c, BindingMismatch, &first), None, "a retry is not final");
        let last = verdict_plan(BindingMismatch, 1, 0.0);
        assert_eq!(b.note_verdict(c, BindingMismatch, &last), Some(1));
        let host = verdict_plan(HostInternal, 7, 0.0);
        assert!(host.final_verdict);
        assert_eq!(b.note_verdict(c, HostInternal, &host), None, "this host's failures are never the caller's");
        assert_eq!(b.note_verdict(c, BuilderTrap, &verdict_plan(BuilderTrap, 0, 0.0)), Some(2));
        // A post-lock failure is final for its job and never the caller's simulation record.
        let post = verdict_plan(PostLockFailure, 0, 0.0);
        assert!(post.final_verdict);
        assert_eq!(b.note_verdict(c, PostLockFailure, &post), None);
    }

    #[test]
    fn chain_refusals_map_to_verdicts() {
        use zkminer_chain::claimability::NotClaimable as Nc;
        assert_eq!(not_claimable_reason(&Nc::Paused), SkipReason::NotClaimable);
        assert_eq!(not_claimable_reason(&Nc::NotOpen), SkipReason::NotClaimable);
        assert_eq!(not_claimable_reason(&Nc::Unreadable("x".into())), OperatorEndpoint);
        assert_eq!(gate_refusal_reason(&GateRefusal::Stale), HostInternal);
        assert_eq!(gate_refusal_reason(&GateRefusal::RouterPaused), SkipReason::NotClaimable);
        assert_eq!(gate_refusal_reason(&GateRefusal::VerifierSwitch { ready_at: 1 }), SkipReason::NotClaimable);
    }

    #[test]
    fn the_artifact_budget_counts_bytes_and_chunks() {
        let b = ArtifactBudget::for_max_bytes(4 << 20);
        assert_eq!(b.max_chunks, (4u64 << 20).div_ceil(24_575) as u32 + 1);
        assert!(b.admits(4 << 20, b.max_chunks));
        assert!(!b.admits((4 << 20) + 1, 1));
        assert!(!b.admits(1, b.max_chunks + 1));
        let huge = ArtifactBudget::for_max_bytes(u64::MAX);
        assert_eq!(huge.max_chunks, zkminer_witness::manifest::MAX_MANIFEST_CHUNKS);
    }

    #[test]
    fn the_reservation_adds_its_terms() {
        let r = ReservationInputs {
            fulfil_gas: 5_600_000,
            max_fee_per_gas: 1_000_000_000, // 1 gwei
            hemi_per_eth: 10.0,
            prove_secs: 100.0,
            simulation_secs: 20.0,
            retained_gib_hours: 2.0,
            cpu_second_hemi: 0.001,
            gib_hour_retained_hemi: 0.5,
            k: 1.5,
        };
        // gas: 6.0M x 1 gwei = 0.006 ETH x 10 x 1.25 = 0.075 HEMI; prove: 0.1; sim: 1.5 x (0.02 + 1.0).
        let want = 0.075 + 0.1 + 1.5 * 1.02;
        let got = reservation_wei(&r) as f64 / 1e18;
        assert!((got - want).abs() < 1e-9, "{got} vs {want}");
        let zero = ReservationInputs { cpu_second_hemi: f64::NAN, gib_hour_retained_hemi: -1.0, k: 0.0, hemi_per_eth: 0.0, ..r };
        assert_eq!(reservation_wei(&zero), 0);
        let max = ReservationInputs { hemi_per_eth: f64::MAX, max_fee_per_gas: u128::MAX, ..r };
        assert_eq!(reservation_wei(&max), u128::MAX);
    }

    fn plan(cps: f64, fixed: u64, margin: f64) -> ProvePlan {
        ProvePlan::over([(cps, fixed)], margin).unwrap()
    }

    #[test]
    fn the_estimate_includes_the_margin_and_every_allowance() {
        let p = plan(400_000.0, RISC0_GROTH16_ALLOWANCE_SECS, 1.5);
        let prove = estimate_prove_secs(400_000 * 100, &p, 10);
        assert_eq!(prove, (100 + RISC0_GROTH16_ALLOWANCE_SECS) * 3 / 2 + 30);
        assert_eq!(estimate_prove_secs(10, &plan(0.0, 0, 1.0), 0), 10, "a bad rate is 1 c/s");
        assert_eq!(estimate_prove_secs(10, &plan(1.0, 0, f64::NAN), 0), 10, "a bad margin is 1");
        let need = prove + 60 + 30 + CLAIM_MINE_ALLOWANCE_SECS;
        assert!(deadline_fits(need, prove, 60, 30));
        assert!(!deadline_fits(need - 1, prove, 60, 30));
        assert!(!deadline_fits(u64::MAX, u64::MAX, 60, 30));
    }

    #[test]
    fn a_plan_takes_the_slowest_rate_and_the_largest_allowance() {
        let p = ProvePlan::over([(1e6, 30), (2e5, 120), (5e5, 600)], 1.5).unwrap();
        assert_eq!(p, ProvePlan { cps: 2e5, fixed_secs: 600, margin: 1.5 });
        assert_eq!(ProvePlan::over([], 1.5), None);
        assert_eq!(ProvePlan::over([(1e6, 0)], 0.5).unwrap().margin, 1.0, "never below 1");
    }

    #[test]
    fn the_fixed_allowance_is_measured_or_by_kind() {
        assert_eq!(fixed_allowance_secs(Some(2.02), false), MEASURED_WRAP_FLOOR_SECS);
        assert_eq!(fixed_allowance_secs(Some(100.0), true), 200);
        assert_eq!(fixed_allowance_secs(None, false), RISC0_GROTH16_ALLOWANCE_SECS);
        assert_eq!(fixed_allowance_secs(None, true), RISC0_CPU_PROOF_ALLOWANCE_SECS);
        assert_eq!(fixed_allowance_secs(Some(f64::NAN), true), RISC0_CPU_PROOF_ALLOWANCE_SECS);
        assert_eq!(fixed_allowance_secs(Some(-1.0), false), RISC0_GROTH16_ALLOWANCE_SECS);
    }

    /// The live localnet case: a CPU slot with no benchmark proved a 32,768-cycle witness job in
    /// 358.9 s (`identity_p254` alone 244 s) on an idle host and in 859.2 s on a loaded one, while
    /// the gate said ~121 s. The estimate is now above both, the 600 s default watchdog refuses it,
    /// and a timeout sized for a CPU proof admits it.
    #[test]
    fn a_cpu_proof_is_estimated_above_what_it_took() {
        let p = ProvePlan::over([(RISC0_CPU_CONSERVATIVE_CPS, fixed_allowance_secs(None, true))], 1.5).unwrap();
        let est = estimate_prove_secs(32_768, &p, 0);
        assert!(est >= 860, "{est}");
        assert!(!watchdog_admits(est, 600), "the default watchdog would kill it");
        assert!(watchdog_admits(est, 1_800));
    }

    /// The fixed allowance (the Groth16 path: minutes on a CPU) slows down on a loaded host like the
    /// rest of the proof, so the margin covers it too. Without it the CPU estimate of the localnet
    /// guest was 908 s, 1.06x the 859 s the proof took on a loaded host, and a 950 s watchdog
    /// admitted a lock that host could overrun on every attempt.
    #[test]
    fn the_margin_covers_the_fixed_allowance() {
        let p = ProvePlan::over([(RISC0_CPU_CONSERVATIVE_CPS, fixed_allowance_secs(None, true))], 1.5).unwrap();
        let est = estimate_prove_secs(32_768, &p, 1);
        assert!(est as f64 >= 859.2 * 1.5, "{est}: the margin over the loaded host's proof");
        assert!(!watchdog_admits(est, 950), "{est}");
        let gpu = plan(1e6, RISC0_GROTH16_ALLOWANCE_SECS, 2.0);
        assert_eq!(estimate_prove_secs(0, &gpu, 0), 2 * RISC0_GROTH16_ALLOWANCE_SECS);
        // The host maximum counts the margined allowance: a job at it still fits the watchdog.
        let max = host_max_guest_cycles(&gpu, 600);
        assert_eq!(max, ((599.0 / 2.0 - 120.0) * 1e6) as u64);
        assert!(watchdog_admits(estimate_prove_secs(max, &gpu, 0), 600));
        assert!(!watchdog_admits(estimate_prove_secs(max + 1_000_000, &gpu, 0), 600));
    }

    /// A 900M-cycle job on a 1M c/s card in a 3-hour window passed the deadline gate and was then
    /// killed by the 600 s watchdog on every attempt. The watchdog check refuses it, and the host
    /// maximum no longer admits it at the static gates.
    #[test]
    fn the_claim_gate_refuses_what_the_watchdog_would_kill() {
        let p = plan(1_000_000.0, RISC0_GROTH16_ALLOWANCE_SECS, 1.5);
        let cycles = 900_000_000u64;
        let prove = estimate_prove_secs(cycles, &p, 20);
        assert!(deadline_fits(3 * 3600, prove, 60, 30), "the window alone would admit it");
        assert!(!watchdog_admits(prove, 600));
        let max = host_max_guest_cycles(&p, 600);
        assert!(cycles > max, "{max}");
        // A job at the host maximum fits the watchdog (before its execute allowance).
        assert!(watchdog_admits(estimate_prove_secs(max, &p, 0), 600));
        assert!(!watchdog_admits(600, 600), "the inline gate refuses at >= too");
    }

    #[test]
    fn the_host_cycle_maximum_fits_the_watchdog() {
        // ((600 - 1) s / 1.5 - 120 s) x 400k c/s.
        assert_eq!(host_max_guest_cycles(&plan(400_000.0, 120, 1.5), 600), 111_733_333);
        // At most an hour of proving, at most 2^34.
        assert_eq!(host_max_guest_cycles(&plan(400_000.0, 0, 1.0), 1_000_000), 1_440_000_000);
        assert_eq!(host_max_guest_cycles(&plan(1e12, 0, 1.0), 1_000_000), 1 << 34);
        // A fixed allowance that fills the watchdog: nothing can be proven here.
        assert_eq!(host_max_guest_cycles(&plan(RISC0_CPU_CONSERVATIVE_CPS, 600, 1.5), 600), 0);
    }

    #[test]
    fn the_operator_session_cap_and_a_verifier_swap() {
        assert_eq!(parse_session_cap(None), None);
        assert_eq!(parse_session_cap(Some(" 1000 ")), Some(1000));
        assert_eq!(parse_session_cap(Some("0")), None);
        assert_eq!(parse_session_cap(Some("x")), None);
        assert!(session_cap_admits(1000, Some(1000)));
        assert!(!session_cap_admits(1001, Some(1000)));
        assert!(session_cap_admits(u64::MAX, None));
        assert_eq!(proving_cutoff(1000, None), 1000);
        assert_eq!(proving_cutoff(1000, Some(800)), 800, "act before readyAt");
        assert_eq!(proving_cutoff(1000, Some(2000)), 1000);
    }

    #[test]
    fn funds_and_card_room() {
        // 10M gas at 1 gwei per fulfil, 400k for the claim: two held locks plus this one.
        let need = 3 * 10_000_000u128 * 1_000_000_000 + 400_000 * 1_000_000_000;
        assert!(funds_cover(U256::from(need), 10_000_000, 1_000_000_000, 2));
        assert!(!funds_cover(U256::from(need - 1), 10_000_000, 1_000_000_000, 2));
        assert!(card_room(1, 0, 2));
        assert!(!card_room(1, 1, 2));
        assert!(!card_room(3, 0, 2), "a look-ahead queue of inline work");
        assert!(card_room(0, 0, 0), "a cap of 0 counts as 1");
    }

    #[test]
    fn unserved_jobs_are_set_aside_for_their_verdict_or_the_inline_ttl() {
        assert_eq!(UNSERVED_SET_ASIDE, Duration::from_secs(600));
        assert_eq!(verdict_set_aside(1_000, 400), Duration::from_secs(600));
        assert_eq!(verdict_set_aside(1_000, 2_000), Duration::ZERO);
        assert!(SERVING_OFF_SET_ASIDE < UNSERVED_SET_ASIDE);
    }

    /// A released witness lock left no verdict, so its job reopened and was re-locked from the
    /// retained bundle once the release cooldown ended, at another 5% each time.
    /// The post-lock verdict is final and outlives any job's window (at most 7 days), so a restart
    /// reading it back never locks the job again.
    #[test]
    fn a_job_released_after_a_lock_is_never_locked_again() {
        for prior in [0u8, 3, 200] {
            let p = verdict_plan(PostLockFailure, prior, 0.5);
            assert!(p.final_verdict);
            assert!(p.ttl_secs >= 7 * 24 * 3600 + 3600, "outlives the window and the cooldown");
        }
    }

    #[test]
    fn post_lock_tallies_are_keyed_apart_and_expire() {
        let (a, b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        assert_ne!(caller_tally_key(a), caller_tally_key(b));
        let gpu = |bus: &str| device_tally_key(bus, PostLockFailureClass::Gpu);
        assert_ne!(gpu("0000:02:00.0"), device_tally_key("0000:02:00.0", PostLockFailureClass::ProverCrash));
        assert_ne!(gpu("0000:02:00.0"), gpu("0000:03:00.0"));
        assert_ne!(caller_tally_key(a), device_tally_key(&format!("{a}"), PostLockFailureClass::Gpu));
        assert_eq!(tally_count(2, 100, 99), 2);
        assert_eq!(tally_count(2, 100, 100), 0, "expired: starts again");
        let mut classes: Vec<u8> = POST_LOCK_CLASSES.iter().map(|c| *c as u8).collect();
        classes.dedup();
        assert_eq!(classes.len(), 7);
    }

    #[test]
    fn a_pin_goes_only_on_evidence() {
        let us = Address::repeat_byte(0xaa);
        let other = Address::repeat_byte(0xbb);
        let read = |status, prover, reopen_count, at_block| PinRead { status, prover, reopen_count, at_block };
        const AGE: u64 = 900;
        // Pinned at block 100 / t=10_000 for reopen 1; the claim never confirmed.
        let pending = PinFacts { reopen_count: Some(1), lock_block: 0, pinned_at_block: 100, pinned_at_unix: 10_000 };
        // A lagging or early read showing it Open keeps the pin, however old it is by wall clock.
        assert!(!pin_lock_gone(&pending, &read(0, Address::ZERO, 1, 120), us, 10_100, AGE));
        assert!(!pin_lock_gone(&pending, &read(0, Address::ZERO, 1, 99), us, 20_000, AGE), "a read below the pin");
        // Past the claim-intent age by chain time, a read at or after the pin: never landed.
        assert!(pin_lock_gone(&pending, &read(0, Address::ZERO, 1, 120), us, 10_900, AGE));
        assert!(pin_lock_gone(&pending, &read(1, other, 1, 120), us, 10_900, AGE));
        // Ours and Locked: held, never gone.
        assert!(!pin_lock_gone(&pending, &read(1, us, 1, 120), us, 99_999, AGE));
        // A risen reopen count ends the instance on any read, unless the job reads Locked by us.
        assert!(pin_lock_gone(&pending, &read(0, Address::ZERO, 2, 50), us, 0, AGE));
        assert!(pin_lock_gone(&pending, &read(1, other, 2, 50), us, 0, AGE));
        assert!(!pin_lock_gone(&pending, &read(1, us, 2, 50), us, 0, AGE), "ours and Locked: never gone");
        // A confirmed lock: gone only on a read at or after the lock block.
        let held = PinFacts { lock_block: 200, ..pending };
        assert!(!pin_lock_gone(&held, &read(0, Address::ZERO, 1, 199), us, 99_999, AGE), "lags our lock");
        assert!(pin_lock_gone(&held, &read(1, other, 1, 200), us, 0, AGE));
        assert!(!pin_lock_gone(&held, &read(1, us, 1, 300), us, 99_999, AGE));
        // A pin with no evidence recorded (an older pin): only the reopen count can end it, and
        // without a count, nothing.
        let bare = PinFacts { pinned_at_block: 100, ..Default::default() };
        assert!(!pin_lock_gone(&bare, &read(0, Address::ZERO, 5, 500), us, 99_999, AGE));
    }

    #[test]
    fn segments_and_sizes() {
        assert_eq!(segment_need([3, 9, 4]), 9);
        assert_eq!(segment_need([]), 0);
        assert!(segments_fit(1, 1, 2 + SEGMENT_FLOOR_BYTES));
        assert!(!segments_fit(1, 2, 2 + SEGMENT_FLOOR_BYTES));
        let cards = vec![("a".to_string(), 20u8), ("b".to_string(), 18), ("c".to_string(), 16)];
        let sizes = witness_prove_sizes(&cards, &[18, 20]);
        assert_eq!(sizes.get("a"), Some(&20));
        assert_eq!(sizes.get("b"), Some(&18));
        assert_eq!(sizes.get("c"), None, "no executed po2 fits it: it never proves the bundle");
        assert!(witness_prove_sizes(&cards, &[21]).is_empty(), "no fallback to an unexecuted size");
    }

    #[test]
    fn divergence_and_rate() {
        assert!(divergence_reusable(true, 8, 8));
        assert!(!divergence_reusable(false, 8, 8));
        assert!(!divergence_reusable(true, 0, 40_000), "a journal that did not come back whole");
        assert!(!divergence_reusable(true, 40_000, 40_000), "over the cap");
        assert_eq!(rate_secs_left(100, 40), 60);
        assert_eq!(rate_secs_left(40, 100), 0);
    }
}
