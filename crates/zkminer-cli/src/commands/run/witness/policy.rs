//! The pure decisions of the witness path (docs/witness-construction-jobs.md §5.2 step 7, §15.2,
//! §16, §17.2): routing, verdict lifetimes, the artifact budget, the reservation, the deadline and
//! prove-resource fits, and which cards may prove a bundle. No I/O, so each is unit-tested here.

use std::collections::HashMap;

use alloy::primitives::{Address, B256};
use zkminer_chain::claimability::NotClaimable;
use zkminer_chain::governance::GateRefusal;
use zkminer_witness::verdict::{Retry, SkipReason};

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

// ── the deadline margin ───────────────────────────────────────────────────────

/// Seconds allowed for the lock transaction to be mined after the gate.
pub(crate) const CLAIM_MINE_ALLOWANCE_SECS: u64 = 60;
/// Seconds of a risc0 proof that do not scale with cycles: the Groth16 wrap (about half a minute
/// on a CPU for any guest), which a cycles-per-second rate measured on large jobs hides.
pub(crate) const RISC0_GROTH16_ALLOWANCE_SECS: u64 = 120;

/// The expected proving time of a witness lock: its sized cycles at `cps` (the slowest card that may
/// prove it, from the benchmark, or the conservative floor), the execute allowance (three times the
/// measured execute, as `execute_allowance_secs` grants inline jobs: the prove executes again and
/// replays segments) and the Groth16 wrap.
pub(crate) fn estimate_prove_secs(cycles: u64, cps: f64, execute_secs: u64) -> u64 {
    let cps = if cps.is_finite() && cps >= 1.0 { cps } else { 1.0 };
    let proving = (cycles as f64 / cps).ceil();
    let proving = if proving >= u64::MAX as f64 { u64::MAX } else { proving as u64 };
    proving
        .saturating_add(execute_secs.saturating_mul(3))
        .saturating_add(RISC0_GROTH16_ALLOWANCE_SECS)
}

/// Whether a lock taken now leaves the margin before `D` (§5.2 step 7): the proof, the lock's
/// mining, one minimum attempt's slack and the fulfil margin all fit in the job's
/// `fulfillmentTimeout` window.
pub(crate) fn deadline_fits(window_secs: u64, prove_secs: u64, fulfil_margin_secs: u64, min_attempt_secs: u64) -> bool {
    // An overflowing need never fits.
    prove_secs
        .checked_add(fulfil_margin_secs)
        .and_then(|n| n.checked_add(min_attempt_secs))
        .and_then(|n| n.checked_add(CLAIM_MINE_ALLOWANCE_SECS))
        .is_some_and(|need| need <= window_secs)
}

/// The host-derived maximum for `maxGuestCycles` when `[witness] max_guest_cycles` is unset: an
/// hour of proving at `cps` (the slowest card's benchmarked rate, or the conservative floor),
/// clamped to `[2^24, 2^34]` sized cycles. The deadline gate then checks the job's own window.
pub(crate) fn host_max_guest_cycles(cps: f64) -> u64 {
    const MIN: u64 = 1 << 24;
    const MAX: u64 = 1 << 34;
    let cps = if cps.is_finite() && cps > 0.0 { cps } else { 0.0 };
    let cycles = cps * 3600.0;
    if cycles >= MAX as f64 {
        MAX
    } else {
        (cycles as u64).clamp(MIN, MAX)
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

/// Per-caller blame: final verdicts that count against the caller (`blames_caller`), and post-lock
/// witness failures (never fed to program-wide marks). A simple counter for Phase 1; the credit
/// ledger of §17.4 replaces it.
#[derive(Debug, Default)]
pub(crate) struct Blame {
    simulation: HashMap<Address, u32>,
    post_lock: HashMap<Address, u32>,
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

    /// Records a post-lock failure of a witness lock; returns the caller's count.
    pub(crate) fn note_post_lock(&mut self, caller: Address) -> u32 {
        if self.post_lock.len() >= BLAME_CAP && !self.post_lock.contains_key(&caller) {
            self.post_lock.clear();
        }
        let n = self.post_lock.entry(caller).or_default();
        *n = n.saturating_add(1);
        *n
    }
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
        assert_eq!(b.note_post_lock(c), 1);
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

    #[test]
    fn the_deadline_margin_includes_every_allowance() {
        let prove = estimate_prove_secs(400_000 * 100, 400_000.0, 10);
        assert_eq!(prove, 100 + 30 + RISC0_GROTH16_ALLOWANCE_SECS);
        assert_eq!(estimate_prove_secs(10, 0.0, 0), 10 + RISC0_GROTH16_ALLOWANCE_SECS, "a bad rate is 1 c/s");
        let need = prove + 60 + 30 + CLAIM_MINE_ALLOWANCE_SECS;
        assert!(deadline_fits(need, prove, 60, 30));
        assert!(!deadline_fits(need - 1, prove, 60, 30));
        assert!(!deadline_fits(u64::MAX, u64::MAX, 60, 30));
    }

    #[test]
    fn the_host_cycle_maximum_is_an_hour_of_proving() {
        assert_eq!(host_max_guest_cycles(400_000.0), 1_440_000_000);
        assert_eq!(host_max_guest_cycles(0.0), 1 << 24);
        assert_eq!(host_max_guest_cycles(f64::NAN), 1 << 24);
        assert_eq!(host_max_guest_cycles(1e12), 1 << 34);
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
