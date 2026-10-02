//! Single-signer nonce allocator.
//!
//! # Why
//! The miner runs several tx operations concurrently (one lifecycle task per GPU:
//! claim / fulfill / release, plus the background batch claim). They all sign from the
//! same EOA, so their nonces must form one gap-free sequence. The old design handed the
//! SAME nonce N to concurrent tasks (reserve never advanced) and relied on
//! "replacement underpriced"/"nonce too low" retries to sort it out — which meant a
//! task's escalating re-broadcast could DISPLACE a *sibling's healthy* in-flight tx at
//! the shared nonce (review R2:639/592).
//!
//! # Design
//! This allocator hands out DISTINCT nonces to concurrent callers, so:
//!   * two tasks never share a nonce → a re-broadcast can only ever displace the task's
//!     OWN stuck predecessor (which makes same-nonce keep+escalate unconditionally safe);
//!   * a task OWNS its nonce across its whole retry loop;
//!   * an aborted reservation is recycled as a "gap" and REISSUED FIRST — an unfilled gap
//!     blocks every higher nonce from mining (Ethereum requires strictly sequential
//!     nonces), so gaps must be refilled before fresh nonces are handed out;
//!   * the fulfill→release displacement is done by handing the abandoned fulfill's EXACT
//!     nonce to `release_job` (an explicit handoff), not by hoping the shared cache still
//!     sits at N.
//!
//! `next` only ever moves forward and is always strictly greater than every reserved
//! nonce, so a re-sync (after an external tx advanced the account, e.g. a stake/mint that
//! bypasses this allocator) can only ADVANCE it — it never reissues an in-flight nonce.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Instant;

/// Cap on the per-nonce fee floor, as a multiple of the floor first recorded for that
/// nonce. Without a ceiling the ratchet compounds every retry round and can drive a 21k
/// self-transfer to absurd cost, or push the bid past the balance pre-check and brick the
/// only transaction that could unwedge the signer.
const FEE_FLOOR_MAX_RATCHET: u128 = 8;

/// How long an abort record is retained before it is swept. Must exceed the detector's
/// `ABORT_MEMORY` window or evidence would vanish before it could be read.
/// How long a jam record gates claiming without re-confirmation.
///
/// Must outlast a STALLED RECOVERY PASS. `recover_claimed_jobs` awaits
/// `process_job_lifecycle` inline on the same loop, and during a jam every tx it drives
/// sits above the wedge, so each receipt wait burns the full `TX_RECEIPT_TIMEOUT` for a
/// receipt that cannot arrive -- one attempt alone exceeded the old 120s value, and
/// fulfill retries five times. An expiry inside that window opened the claim gate while
/// the jam was live. The probe re-confirms every ~60s, so this only decides how long a
/// jam survives when the probe itself cannot run.
///
/// Must be long enough that we do not immediately re-jam, and short enough that a
/// resolved wedge resumes mining without operator action. The 2026-08-14 wedge took
/// 4h24m to clear on its own; this only controls how often we RE-TEST, since `commit`
/// and `resync` clear the record immediately once the frontier moves past it.
const UNDISPLACEABLE_TTL: std::time::Duration = std::time::Duration::from_secs(900);

const ABORT_RECORD_TTL: std::time::Duration = std::time::Duration::from_secs(900);

/// Per-nonce fee-floor state, including whether the ratchet cap leaves any room
/// for a strictly-higher replacement bid. See [`NonceManager::fee_floor_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeFloorState {
    /// `(tip, max_fee)` floor to bid over, already clamped to the cap.
    pub floor: (u128, u128),
    /// The highest `(tip, max_fee)` actually broadcast at this nonce, UNCAPPED.
    pub broadcast: (u128, u128),
    /// Ceiling on `max_fee` for this nonce.
    pub cap: u128,
    /// True when no strictly-higher bid is possible within the cap. A caller that
    /// sends anyway will be rejected `replacement transaction underpriced` every
    /// time, forever -- it must stop instead.
    pub exhausted: bool,
}

#[derive(Debug, Default)]
struct Inner {
    /// Next FRESH nonce to hand out (meaningful only while `synced`). Monotonic: only
    /// ever increased, so it is always > every currently-reserved nonce.
    next: u64,
    /// Whether `next` is anchored to the on-chain account nonce.
    synced: bool,
    /// Aborted-reservation gaps to REISSUE before any fresh `next`. A gap left unfilled
    /// wedges every higher nonce, so these are always reused first.
    freed: BTreeSet<u64>,
    /// Lowest nonce that could still be open: one above the highest we have SEEN consumed,
    /// via `commit` or a `resync` frontier. Nothing below it can ever be a gap again.
    consumed_below: u64,
    /// Highest `(tip, max_fee)` we have ever BROADCAST at a nonce, plus the first floor
    /// recorded for it (for the ratchet cap). See [`note_broadcast`].
    ///
    /// [`note_broadcast`]: NonceManager::note_broadcast
    fee_floor: BTreeMap<u64, FeeFloor>,
    /// Nonces left UNRESOLVED: we gave up on them but deliberately did not offer them
    /// back to reservers (a live tx of ours may still be on them).
    ///
    /// Distinct from `freed`, which is the reissue set. An unresolved nonce is in neither
    /// `freed` nor reachable by `reserve_locked`, so it provably has no second owner --
    /// which is exactly what makes it safe for the shutdown healer to fill, and what
    /// distinguishes it from the sticky `aborted_at` record (which survives re-reservation
    /// and can name a live pre-flight release).
    unresolved: std::collections::BTreeSet<u64>,
    /// Nonces we could not outbid within the ratchet cap, and when we last found so.
    ///
    /// A signer with an undisplaceable nonce is JAMMED: that nonce and every higher one
    /// cannot mine until the resident tx clears. Claiming more work in that state bonds
    /// collateral we have no way to release, which is how three jobs aged past their
    /// lock deadline on 2026-08-14. Read by `is_jammed` to gate new claims.
    undisplaceable: BTreeMap<u64, Instant>,
    /// When we last ABORTED a reservation at a nonce — retained even after the nonce is
    /// handed out again. See [`recently_aborted`].
    ///
    /// [`recently_aborted`]: NonceManager::recently_aborted
    aborted_at: BTreeMap<u64, Instant>,
}

#[derive(Debug, Clone, Copy)]
struct FeeFloor {
    tip: u128,
    max_fee: u128,
    /// The first `max_fee` ever recorded here — the ratchet cap is relative to this, so a
    /// long-running wedge cannot escalate without bound.
    origin_max_fee: u128,
}

/// Thread-safe single-signer nonce allocator (cheaply clonable via `Arc` in the client).
#[derive(Debug, Default)]
pub struct NonceManager {
    inner: Mutex<Inner>,
}

impl NonceManager {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reserve a distinct nonce if the allocator is already synced. Returns `None` when
    /// unsynced — the caller must fetch the chain nonce and call [`anchor_if_unsynced`].
    ///
    /// [`anchor_if_unsynced`]: NonceManager::anchor_if_unsynced
    pub fn try_reserve(&self) -> Option<u64> {
        let mut g = self.lock();
        if !g.synced {
            return None;
        }
        Some(reserve_locked(&mut g))
    }

    /// Anchor `next` to a freshly-fetched chain nonce and return a first reservation —
    /// but ONLY if still unsynced (another task may have anchored first, in which case
    /// this returns `None` and the caller should retry [`try_reserve`]).
    ///
    /// `next` is set to `max(chain_nonce, next)` so a concurrent anchor or a stale fetch
    /// can never reissue an already-handed-out nonce.
    ///
    /// [`try_reserve`]: NonceManager::try_reserve
    pub fn anchor_if_unsynced(&self, chain_nonce: u64) -> Option<u64> {
        let mut g = self.lock();
        if g.synced {
            return None;
        }
        g.next = g.next.max(chain_nonce);
        g.synced = true;
        Some(reserve_locked(&mut g))
    }

    /// Advance `next` to account for an external nonce jump (e.g. a stake/mint tx that
    /// bypassed this allocator), after a "nonce too low"/"too high" error. Only ever
    /// raises `next`; never reissues an in-flight nonce. No-op while unsynced.
    ///
    /// `chain_nonce` MUST be the MINED frontier (`eth_getTransactionCount` at `latest`),
    /// NOT the pending count: the `freed.retain` below drops recycled gaps below the
    /// frontier as "consumed", and only a MINED nonce proves everything below it is truly
    /// consumed. Pruning against a pending frontier could forget a genuine gap whose tx is
    /// merely in the mempool and later evicted → a permanent gap that wedges the signer.
    pub fn resync(&self, chain_nonce: u64) {
        let mut g = self.lock();
        if g.synced {
            g.next = g.next.max(chain_nonce);
            // Everything below the MINED frontier is consumed; those gaps can't be open.
            g.freed.retain(|&f| f >= chain_nonce);
            g.aborted_at.retain(|&n, _| n >= chain_nonce);
            g.unresolved.retain(|&n| n >= chain_nonce);
            g.unresolved.retain(|&n| n >= chain_nonce);
            // Prune the fee high-water below the mined frontier too. `commit` already
            // does this; `resync` did not, and a stale entry now means more than dead
            // weight: `fee_floor_state` reports `exhausted` off it, and a caller that
            // trusts that will REFUSE to send at a nonce which is in fact free.
            g.fee_floor.retain(|&n, _| n >= chain_nonce);
            g.undisplaceable.retain(|&n, _| n >= chain_nonce);
            g.consumed_below = g.consumed_below.max(chain_nonce);
        }
    }

    /// Recycle a reserved nonce as a gap to be reissued first (keeping the on-chain
    /// sequence gap-free).
    ///
    /// Ideally called only when the tx definitively did NOT land. The tx-layer give-up
    /// paths, however, deliberately abort even when the tx MIGHT still be pending: the
    /// alternative — leaving the nonce un-resolved — is a PERMANENT gap that wedges the
    /// whole signer, whereas recycling a still-pending nonce merely self-heals (a reuser
    /// that collides gets "nonce too low" → `resync`, which prunes the consumed nonce).
    /// Recycling the gap is strictly the lesser evil. (The fulfill→release displacement is
    /// the one case that instead HANDS the nonce to `release_job` so it can be reused
    /// intentionally to evict the stuck fulfill.)
    pub fn abort(&self, nonce: u64) {
        let mut g = self.lock();
        // `nonce < next` alone is NOT enough: `commit` sets `next = max(next, used + 1)`, so
        // after a nonce mines that test is permanently true for it. Any late abort — a slow
        // error path, or a retry arm that runs after the receipt landed — then resurrected a
        // CONSUMED nonce into `freed`, and `reserve_locked` hands the lowest freed out first,
        // so the next reserver would be issued a nonce guaranteed to be rejected "nonce too
        // low". `consumed_below` is the watermark that makes that unrepresentable.
        if g.synced && nonce < g.next && nonce >= g.consumed_below {
            g.freed.insert(nonce);
            // [R2] Amortised expiry. `commit`/`resync` prune everything at/below the mined
            // frontier, but a nonce ABOVE the frontier that never mines would otherwise sit
            // here forever. Sweeping on insert bounds the map by "aborts within the TTL"
            // instead of by process uptime, at O(live entries) on a path that already
            // takes the lock.
            let now = Instant::now();
            g.aborted_at
                .retain(|_, t| now.saturating_duration_since(*t) <= ABORT_RECORD_TTL);
            // Remember the abort even after the nonce is re-reserved — see
            // `recently_aborted`. Keep the FIRST abort time: the wedge is a property of the
            // nonce, and refreshing it on every abort would let a fast abort/re-reserve loop
            // hold the timestamp permanently new.
            g.aborted_at.entry(nonce).or_insert(now);
        }
    }

    /// A nonce was consumed on-chain. Drop any stale gaps at/below it (on a single-signer
    /// account nothing below a mined nonce can still be an open gap) and keep `next` ahead.
    pub fn commit(&self, used: u64) {
        let mut g = self.lock();
        if !g.synced {
            return;
        }
        g.freed.retain(|&f| f > used);
        // A nonce at/below the mined frontier can never need displacing again, so its fee
        // high-water is dead weight. Pruning here bounds `fee_floor` by the number of
        // genuinely in-flight nonces rather than by process uptime.
        g.fee_floor.retain(|&n, _| n > used);
        // The frontier moved past these, so whatever was resident there has mined:
        // the jam is over. Clearing here is what re-opens claiming promptly.
        g.undisplaceable.retain(|&n, _| n > used);
        // The nonce MINED, so it is definitively not a hole; drop the abort memory too or
        // the detector would keep offering to heal an already-consumed nonce.
        g.aborted_at.retain(|&n, _| n > used);
        g.unresolved.retain(|&n| n > used);
        g.next = g.next.max(used.saturating_add(1));
        g.consumed_below = g.consumed_below.max(used.saturating_add(1));
    }

    /// True if `nonce` is currently a recycled gap (we aborted our own tx at it, so it is
    /// safe to fill/displace). Used by the gap watchdog to distinguish a nonce WE own from
    /// a legit in-flight tx it must not evict.
    pub fn is_freed(&self, nonce: u64) -> bool {
        self.lock().freed.contains(&nonce)
    }

    /// Exclusively claim `nonce` out of the allocator so a concurrent `reserve` can't also
    /// hand it out (used by the gap watchdog before it broadcasts its fill/displace tx at
    /// that nonce — otherwise a racing reserve double-issues it). Removes it from `freed`
    /// and keeps `next` strictly ahead. No-op while unsynced.
    /// Returns whether the nonce was still a recycled gap at the moment it was claimed.
    ///
    /// `false` means someone re-reserved it since the caller last looked. That distinction is
    /// load-bearing for the shutdown healer: its safety gate reads `is_freed`, then makes at
    /// least one throttled RPC round-trip before broadcasting, and `reserve_locked` hands out
    /// the LOWEST freed nonce first — i.e. exactly the one the gate just approved. Without a
    /// return value the claim was a silent no-op and the healer displaced a live, executable
    /// tx it had no right to touch.
    pub fn claim_gap(&self, nonce: u64) -> bool {
        let mut g = self.lock();
        if !g.synced {
            return false;
        }
        let was_freed = g.freed.remove(&nonce);
        g.next = g.next.max(nonce.saturating_add(1));
        was_freed
    }

    /// Record that we successfully BROADCAST `(tip, max_fee)` at `nonce`.
    ///
    /// THE WEDGE THIS FIXES (incident 2026-08-01, all claims blocked ~10 min):
    /// the fee ladder is seeded per INVOCATION — `claim_job` calls `base_fees()` once and
    /// restarts `attempt` at 1, and `escalated_fees` uses `steps = attempt - 1`, so attempt
    /// 1 bids the UNBUMPED base. Meanwhile a give-up recycles the nonce through `freed`,
    /// and `reserve_locked` hands the LOWEST freed nonce out first — so the next claim gets
    /// the same nonce and restarts the ladder at base. Once any invocation broadcast at its
    /// top attempt (1.15^4 ~= 1.749x base), no later invocation could ever clear the node's
    /// replacement threshold (>1.125x the resident). The loop was arithmetically
    /// non-terminating and the signer stayed wedged until manual intervention.
    ///
    /// Recording the high-water mark ON THE NONCE (not the invocation) makes every retry
    /// strictly higher than the resident tx regardless of which call sends it.
    ///
    /// Call this ONLY after the node ACCEPTED the broadcast. Ratcheting on a rejected send
    /// (e.g. a 429, or a balance pre-check failure) would inflate the floor for a tx that
    /// never reached the mempool, and — because fee estimation degrades under rate limiting
    /// — could push later bids above the job's cap for no reason.
    /// `seed_max_fee` is the bid BEFORE any `fees_over_floor` lift — the escalated base, or
    /// the healer's flat 4x. The ratchet cap is anchored to IT, not to the first bid ever
    /// recorded, so a floor-derived bid can never lift the cap (the anti-compounding property
    /// the cap exists for is intact) while a genuine repricing can.
    ///
    /// Without that distinction the cap could report BELOW a fee we actually broadcast. On a
    /// sub-gwei chain: fulfill records origin 0.05 gwei (cap 0.4), its txs are evicted, the
    /// healer fills the nonce at its hard `max(4x, 2 gwei)` floor = 2 gwei and records it —
    /// but origin stays 0.05, so `fee_floor` reports 0.4 against a 2-gwei resident. Every one
    /// of our paths then computes a bid the node is guaranteed to reject, and because
    /// `note_broadcast` fires only on an ACCEPTED send the record can never advance past it:
    /// the nonce becomes permanently un-displaceable by us, and both the victim's fulfill and
    /// the release that inherits the nonce burn all five rungs without reaching the wire.
    pub fn note_broadcast(&self, nonce: u64, tip: u128, max_fee: u128, seed_max_fee: u128) {
        let mut g = self.lock();
        // An ACCEPTED broadcast retires any stale abandonment evidence at this nonce.
        //
        // `aborted_at` deliberately survives re-reservation, and `reserve_locked` reissues
        // freed nonces FIRST — so a nonce recycled by a give-up and then re-reserved by a
        // healthy task still carried its predecessor's abort record. The gap detector's
        // branch (B) does no pending read and is consumed UNGATED by the watchdog, so it
        // would nominate that nonce and the healer would evict a live, executable tx with a
        // >=4x self-transfer. The node accepting a broadcast here is first-person proof the
        // nonce is owned and in use again, which is exactly the evidence that record denies.
        //
        // The four job paths and the healer reach this. The STAKING paths cannot — alloy's
        // gas filler sets their fee pair, so they have no bid to record — and they share this
        // same allocator, so they call `note_sent` instead. An earlier version of this comment
        // claimed every send path recorded here; that was false, and it was the stated licence
        // for consuming branch (B) ungated.
        g.aborted_at.remove(&nonce);
        g.unresolved.remove(&nonce);
        let e = g.fee_floor.entry(nonce).or_insert(FeeFloor {
            tip: 0,
            max_fee: 0,
            origin_max_fee: 0,
        });
        e.tip = e.tip.max(tip);
        e.max_fee = e.max_fee.max(max_fee);
        // Anchor the cap to the externally-priced component. Under-reporting the floor is
        // never safe: every consumer uses it as a replacement PRICE, so an under-report
        // guarantees rejection, and rejection freezes the record.
        e.origin_max_fee = e.origin_max_fee.max(seed_max_fee.max(1));
    }


    /// Record that `nonce` carries a transaction we cannot outbid within the cap.
    pub fn note_undisplaceable(&self, nonce: u64) {
        let mut g = self.lock();
        // Keep the FIRST observation, matching `abort`'s `aborted_at` idiom and for the
        // same reason: `insert` refreshes the timestamp on every retry, so the TTL would
        // measure "time since we last tried" instead of jam age, and a fast bail loop
        // would hold it permanently new.
        g.undisplaceable.entry(nonce).or_insert_with(Instant::now);
    }

    /// Refresh the observation time for a jam that chain truth has just RE-CONFIRMED.
    ///
    /// Deliberately a plain `insert`, unlike `note_undisplaceable`'s `or_insert_with`.
    /// Called only from the periodic resync probe when the mined frontier has NOT passed
    /// the jammed nonce, so the TTL means "we have not been able to confirm this jam for
    /// 120s" rather than "the jam is 120s old". Without it the sweep forgets a live wedge
    /// on the healer's first miss (WEDGE_CHECK_TICKS 60s + WEDGE_MIN_PERSIST 45s + a 30s
    /// receipt budget already exceeds the TTL).
    pub fn refresh_undisplaceable(&self, nonce: u64) {
        let mut g = self.lock();
        g.undisplaceable.insert(nonce, Instant::now());
    }

    /// True if any nonce is currently undisplaceable — the signer is jammed and nothing
    /// at or above that nonce can mine.
    ///
    /// Entries age out after `UNDISPLACEABLE_TTL` so a resolved jam (the resident tx
    /// mined, as happened after 4h24m on 2026-08-14) re-opens claiming on its own without
    /// needing a restart. They are also pruned by `commit`/`resync` the moment the
    /// frontier passes them, which is the fast path.
    pub fn is_jammed(&self) -> bool {
        let g = self.lock();
        let now = Instant::now();
        // NON-DESTRUCTIVE. This is a query on the claim hot path; sweeping here made the
        // question "am I jammed?" DELETE the record it reads. The gate then failed OPEN
        // during a live jam, and because `jammed_nonce()` could no longer see the deleted
        // key, the resync probe's `if let Some(j)` never fired again -- the jam could
        // never be re-armed, since a bailed nonce is in `unresolved` and `reserve_locked`
        // will never hand it out for a bail arm to re-observe. Fresh claims then draw
        // clean nonces above the wedge, are accepted into the mempool behind it, and ride
        // to their lock deadlines: the exact 2026-08-14 loss shape, re-created by this
        // gate's own timer.
        //
        // Entries are removed only by authority: `commit`/`resync` once the frontier
        // passes the nonce, or `clear_undisplaceable` when the probe confirms it mined.
        g.undisplaceable
            .values()
            .any(|t| now.duration_since(*t) < UNDISPLACEABLE_TTL)
    }

    /// Drop the recorded fee high-water at `nonce`, resetting its escalation ladder.
    ///
    /// For the healer when chain truth shows no resident at a nonce whose ladder has hit
    /// the ceiling: our earlier bid was accepted and then lost from the mempool, so the
    /// recorded high-water describes a transaction that no longer exists and would
    /// otherwise veto every future heal forever.
    pub fn reset_fee_floor(&self, nonce: u64) {
        self.lock().fee_floor.remove(&nonce);
    }

    /// Drop the jam record at `nonce` — for the probe, once chain truth confirms the
    /// frontier has passed it. The authoritative clear; the TTL is only a backstop.
    pub fn clear_undisplaceable(&self, nonce: u64) {
        self.lock().undisplaceable.remove(&nonce);
    }

    /// The lowest nonce with a jam record, IGNORING the TTL.
    ///
    /// Deliberately not TTL-filtered: the resync probe uses this to decide what to
    /// confirm or clear, and hiding a stale entry from it is what made the jam
    /// unrecoverable once the TTL had elapsed.
    pub fn jammed_nonce(&self) -> Option<u64> {
        let g = self.lock();
        g.undisplaceable.keys().next().copied()
    }

    /// Retire abandonment evidence at `nonce` without recording a fee.
    ///
    /// The `aborted_at`-clearing half of [`note_broadcast`], for accepted sends whose fee pair
    /// we do not own (the staking paths, where alloy's gas filler chooses it). They reserve
    /// from this same allocator, so without this a nonce recycled by a job give-up and then
    /// taken by a stake keeps its stale abort record: branch (B) nominates it, the watchdog
    /// consumes branch (B) ungated, and the healer's flat >=4x self-transfer evicts the live
    /// stake — which `approve_and_stake`'s unobserved-receipt arm then neither retries nor
    /// revokes, so the stake silently never lands.
    ///
    /// [`note_broadcast`]: NonceManager::note_broadcast
    pub fn note_sent(&self, nonce: u64) {
        let mut g = self.lock();
        if g.synced {
            g.aborted_at.remove(&nonce);
        }
    }

    /// The `(tip, max_fee)` a new broadcast at `nonce` must EXCEED to displace whatever we
    /// last put there, or `None` if we have never broadcast at it.
    ///
    /// Returns the recorded high-water; the caller is responsible for applying the node's
    /// replacement margin on top (see `jobs::fees_over_floor`). Capped at
    /// `FEE_FLOOR_MAX_RATCHET x` the first floor seen for this nonce, so a persistent wedge
    /// escalates a bounded number of times and then stops rather than compounding forever.
    pub fn fee_floor(&self, nonce: u64) -> Option<(u128, u128)> {
        self.fee_floor_state(nonce).map(|s| s.floor)
    }

    /// The per-nonce fee floor together with whether the ratchet cap has been
    /// exhausted — i.e. whether a strictly-higher replacement is still possible.
    ///
    /// WHY THIS EXISTS — the cap used to be a LIVELOCK FIXED POINT, and it cost a
    /// 4h24m wedge and three stranded jobs on 2026-08-14. Once the recorded floor
    /// passed `origin_max_fee * FEE_FLOOR_MAX_RATCHET`, the read clamped back to the
    /// cap, `fees_over_floor` added its 12.5% margin, and the caller broadcast
    /// `cap * 1.125`. `note_broadcast` recorded that, the next read clamped to `cap`
    /// again, and the next bid was `cap * 1.125` -- byte-identical to the fee the
    /// resident transaction already carried. A replacement must be STRICTLY higher,
    /// so that is precisely the one bid guaranteed to be rejected, and it was re-sent
    /// 327 times over four hours while every higher nonce queued behind it.
    ///
    /// The cap's purpose is real (an unbounded ratchet can drive a 21k self-transfer
    /// to absurd cost, or push the bid past the balance pre-check and brick the only
    /// transaction that could unwedge the signer). So the cap stays -- but it is now a
    /// CEILING that reports "no further bid is possible", instead of silently handing
    /// back a losing one. Callers must not send when `exhausted` is true.
    pub fn fee_floor_state(&self, nonce: u64) -> Option<FeeFloorState> {
        let g = self.lock();
        g.fee_floor.get(&nonce).map(|f| {
            let cap = f.origin_max_fee.saturating_mul(FEE_FLOOR_MAX_RATCHET);
            // [A2] Cap BOTH, or the ratchet can invert the pair. `max_fee` is capped while
            // `tip` is not, so once the cap bites, a recorded tip above it would be returned
            // unchanged and the caller — which rebuilds the EIP-1559 pair WITHOUT
            // `escalated_fees`' defensive `max_fee.max(tip)` clamp (jobs.rs:108) — would
            // broadcast maxPriorityFeePerGas > maxFeePerGas. The node REJECTS that, the error
            // matches neither `is_same_nonce_pending` nor `is_nonce_error`, `note_broadcast`
            // only fires on success so the floor never advances, and the entry is pruned only
            // at/below the mined frontier which this nonce never reaches: permanently stuck.
            // Reachable whenever tip == max_fee, which is the norm here (a configured
            // gas_price yields (gp, gp), as does the estimate-failure fallback under 429s).
            //
            // Min-ing both by the same cap preserves the tip <= max_fee invariant, since every
            // recorded broadcast satisfied it.
            let capped_max = f.max_fee.min(cap);
            // Exhausted when what we have ALREADY broadcast is at or above the cap:
            // any strictly-higher replacement would have to exceed it. Compared
            // against the UNCAPPED high-water on purpose -- comparing the capped
            // value against itself is what made this a fixed point.
            let exhausted = f.max_fee >= cap;
            FeeFloorState {
                floor: (f.tip.min(capped_max), capped_max),
                broadcast: (f.tip, f.max_fee),
                cap,
                exhausted,
            }
        })
    }

    /// True if we aborted a reservation at `nonce` within `within` and it has NOT since
    /// mined (a mined nonce is pruned by `commit`/`resync`).
    ///
    /// WHY THIS EXISTS — the 2026-08-01 wedge went undetected for 10 minutes because
    /// `is_freed(mined)` alone is a FLICKERING signal: `reserve_locked` removes the nonce
    /// from `freed` the instant it is handed out, and the failing claim loop aborted and
    /// re-reserved the same nonce many times a second. The gap watchdog samples once a
    /// minute, so it almost always observed the nonce mid-reservation and saw `freed` empty.
    ///
    /// This is deliberately the SAME evidence class as `is_freed` — first-person knowledge
    /// that WE abandoned a tx at that nonce, which is what makes filling it safe (we are
    /// only ever displacing our own abandoned work). It adds no dependence on the
    /// `pending` frontier, which is unreliable on a load-balanced RPC.
    pub fn recently_aborted(&self, nonce: u64, within: std::time::Duration) -> bool {
        let g = self.lock();
        g.aborted_at
            .get(&nonce)
            .is_some_and(|t| t.elapsed() <= within)
    }

    /// Record wedge EVIDENCE for `nonce` without recycling it into `freed`.
    ///
    /// For the healer's unconfirmed path: it has already `claim_gap`-ed the nonce (so it is
    /// not in `freed`) and its fill tx may still be live, so handing the nonce back to other
    /// reservers would let a sibling collide with it. But returning without leaving any
    /// trace makes the gap INVISIBLE next tick — `is_freed` is false and `next` is only
    /// `mined + 1`, so neither detector branch fires and the healer never retries, despite
    /// its own comment promising it would.
    pub fn note_unresolved(&self, nonce: u64) {
        let mut g = self.lock();
        if g.synced {
            g.aborted_at.entry(nonce).or_insert_with(Instant::now);
            g.unresolved.insert(nonce);
        }
    }

    /// True if `nonce` was left unresolved by a give-up and has not since mined.
    ///
    /// Ownership evidence for the SHUTDOWN healer, which otherwise gates on `is_freed`
    /// alone. The fee-cap bail arms use `note_unresolved` rather than `abort` (so the
    /// poisoned nonce is never handed to another reserver), which made them a skip arm
    /// that does not recycle -- and the shutdown healer then declined the resulting hole
    /// as "not ours", leaving every queued releaseJob above it stranded.
    pub fn is_unresolved(&self, nonce: u64) -> bool {
        self.lock().unresolved.contains(&nonce)
    }

    /// The next fresh nonce that would be handed out, if synced (for wedge detection).
    /// Note this ignores recycled gaps in `freed` (those are reissued first); it is the
    /// upper frontier of everything the allocator has handed out.
    pub fn peek_next(&self) -> Option<u64> {
        let g = self.lock();
        if g.synced { Some(g.next) } else { None }
    }

    /// Force a full re-anchor to chain on the next reservation (last resort for an
    /// unrecoverable local state). Prefer [`resync`](NonceManager::resync), which keeps
    /// concurrent in-flight reservations valid.
    pub fn invalidate(&self) {
        let mut g = self.lock();
        g.synced = false;
        g.freed.clear();
        g.fee_floor.clear();
        g.aborted_at.clear();
        g.unresolved.clear();
        // Drop the jam verdict along with the evidence it was derived from; keeping it
        // would gate claiming off state that no longer exists.
        g.undisplaceable.clear();
        g.consumed_below = 0;
    }
}

/// Reserve under an already-held lock: reissue the lowest gap if any, else `next++`.
fn reserve_locked(g: &mut Inner) -> u64 {
    if let Some(&n) = g.freed.iter().next() {
        g.freed.remove(&n);
        return n;
    }
    let n = g.next;
    g.next = g.next.saturating_add(1);
    n
}

#[cfg(test)]
mod tests {

    /// [cheap-4] A nonce we have SEEN mine must never come back as a gap.
    ///
    /// `abort`'s old guard was `nonce < next` alone, and `commit` sets
    /// `next = max(next, used + 1)` — so after a nonce mines, that test is permanently true
    /// for it. Any late abort (a slow error path, or a retry arm running after the receipt
    /// landed) resurrected a consumed nonce into `freed`, and `reserve_locked` hands the
    /// lowest freed out FIRST — so the next reserver got a nonce guaranteed to be rejected
    /// "nonce too low".
    #[test]
    fn a_committed_nonce_can_never_be_resurrected_by_a_late_abort() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(100), Some(100));
        assert_eq!(m.try_reserve(), Some(101));
        m.commit(100);
        m.abort(100); // late abort, after the receipt landed
        assert!(!m.is_freed(100), "a mined nonce was recycled into the reissue set");
        assert_eq!(m.try_reserve(), Some(102), "the next reserve must not be handed 100");
    }

    /// The same via `resync`, which learns the frontier from the chain rather than a commit.
    #[test]
    fn a_resynced_frontier_also_blocks_a_late_abort() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(100), Some(100));
        assert_eq!(m.try_reserve(), Some(101));
        m.resync(102); // the chain moved on; 100 and 101 are consumed
        m.abort(100);
        m.abort(101);
        assert!(!m.is_freed(100) && !m.is_freed(101), "consumed nonces were resurrected");
    }

    /// THE BOUNDARY. `consumed_below` is exclusive, so the watermark's own value must still
    /// be recyclable: `commit(100)` sets it to 101, and 101 is the very next nonce — still
    /// open, and the modal failure shape (N-1 mines, N's send fails). With `>` instead of
    /// `>=` this nonce would land in NO set at all: not in `freed`, no abort record — the
    /// invisible hole the shutdown healer's ownership gate refuses to fill.
    #[test]
    fn the_watermark_itself_is_still_recyclable() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(100), Some(100));
        assert_eq!(m.try_reserve(), Some(101));
        m.commit(100); // consumed_below becomes 101
        m.abort(101); // 101 is still open — its send failed
        assert!(
            m.is_freed(101),
            "the watermark is EXCLUSIVE: the first not-yet-mined nonce must stay recyclable, \
             or it becomes an invisible hole the shutdown gate will not fill"
        );
        assert_eq!(m.try_reserve(), Some(101), "and it must be reissued first");
    }

    /// A genuinely open nonce above the frontier must still be recyclable — the watermark
    /// must not be so blunt that it breaks the mechanism it protects.
    #[test]
    fn an_open_nonce_above_the_frontier_is_still_recyclable() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(100), Some(100));
        assert_eq!(m.try_reserve(), Some(101));
        assert_eq!(m.try_reserve(), Some(102));
        m.commit(100);
        m.abort(102); // 102 never landed and is genuinely a gap
        assert!(m.is_freed(102));
        assert_eq!(m.try_reserve(), Some(102), "the open gap must be reissued first");
    }
    use super::*;
    use std::time::Duration;

    #[test]
    fn unsynced_until_anchored() {
        let m = NonceManager::new();
        assert_eq!(m.try_reserve(), None);
        assert_eq!(m.anchor_if_unsynced(100), Some(100));
        // Now synced: distinct, increasing.
        assert_eq!(m.try_reserve(), Some(101));
        assert_eq!(m.try_reserve(), Some(102));
    }

    #[test]
    fn concurrent_anchor_does_not_double_issue() {
        let m = NonceManager::new();
        // First anchor wins and reserves 100.
        assert_eq!(m.anchor_if_unsynced(100), Some(100));
        // A racing anchor sees synced → None (caller retries try_reserve → 101).
        assert_eq!(m.anchor_if_unsynced(100), None);
        assert_eq!(m.try_reserve(), Some(101));
    }

    #[test]
    fn aborted_nonce_is_reissued_first() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(10), Some(10));
        assert_eq!(m.try_reserve(), Some(11));
        assert_eq!(m.try_reserve(), Some(12));
        // 11's tx never landed → recycle. Next reserve must REFILL the gap (11), not 13,
        // else 12/13… stay wedged behind the on-chain gap.
        m.abort(11);
        assert_eq!(m.try_reserve(), Some(11));
        assert_eq!(m.try_reserve(), Some(13));
    }

    #[test]
    fn commit_prunes_stale_gaps_and_keeps_next_ahead() {
        let m = NonceManager::new();
        m.anchor_if_unsynced(5); // reserves 5
        let _ = m.try_reserve(); // 6
        let _ = m.try_reserve(); // 7
        m.abort(6);
        // 7 mined ⇒ 5 and 6 must have mined too on a single signer; a stale gap at 6 is
        // dropped so it is never wrongly reissued.
        m.commit(7);
        assert_eq!(m.try_reserve(), Some(8));
    }

    #[test]
    fn resync_only_advances_never_reissues_inflight() {
        let m = NonceManager::new();
        m.anchor_if_unsynced(50); // 50
        let a = m.try_reserve().unwrap(); // 51 (in-flight)
        assert_eq!(a, 51);
        // An external stake tx advanced the account to 60. resync must NOT drop below the
        // in-flight 51 nor reissue it; it jumps next forward.
        m.resync(60);
        assert_eq!(m.try_reserve(), Some(60));
        // A resync BEHIND next is ignored (never reissues an in-flight nonce).
        m.resync(55);
        assert_eq!(m.try_reserve(), Some(61));
    }

    #[test]
    /// THE 2026-08-01 WEDGE. Reproduces the exact live state: the claim loop broadcast at
    /// nonce 7708 up to its top attempt, gave up, aborted (recycling 7708 into `freed`),
    /// and the next invocation got 7708 back from `reserve_locked` and restarted its ladder
    /// at the UNBUMPED base — which cannot clear the node's replacement threshold against
    /// the resident tx. Without a per-nonce floor the second invocation's opening bid is
    /// <= the resident's fee and the loop never terminates.
    #[test]
    fn recycled_nonce_must_outbid_our_own_resident_tx() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(7708), Some(7708));

        // Invocation 1 escalates to its top attempt and broadcasts there, then gives up.
        let base_max: u128 = 2_000_000_000; // 2 gwei
        let top = base_max * 1749 / 1000; // ~1.749x = 1.15^4
        m.note_broadcast(7708, 0, top, top);
        m.abort(7708);

        // Invocation 2 recycles the SAME nonce (freed is reissued first) ...
        assert_eq!(m.try_reserve(), Some(7708), "the poisoned nonce is handed back");
        // ... and would otherwise open at the unbumped base.
        let floor = m.fee_floor(7708).expect("floor recorded for a broadcast nonce");
        assert!(
            floor.1 >= top,
            "floor must remember the resident fee ({top}), got {}",
            floor.1
        );
        // The opening bid, once raised over the floor, must EXCEED the resident tx —
        // this is the assertion that fails without the fix.
        let over = |v: u128| v.saturating_add((v / 8).max(1));
        assert!(
            over(floor.1) > top,
            "recycled-nonce bid {} must exceed resident {top}",
            over(floor.1)
        );
    }

    #[test]
    fn fee_floor_is_capped_and_pruned() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(100), Some(100));
        m.note_broadcast(100, 0, 1_000, 1_000);
        // A FLOOR-DERIVED re-broadcast must not lift the cap — that is the compounding this
        // cap exists to stop. Seed stays 1_000 because the escalated base did not move.
        m.note_broadcast(100, 0, 1_000_000_000, 1_000);
        let (_, capped) = m.fee_floor(100).unwrap();
        assert_eq!(capped, 1_000 * FEE_FLOOR_MAX_RATCHET, "ratchet must be capped");
        // Once mined, the entry is dead weight and must not accumulate.
        m.commit(100);
        assert!(m.fee_floor(100).is_none(), "committed nonce must be pruned");
    }

    /// The cap must never report BELOW a fee we actually broadcast.
    ///
    /// The healer bids a hard `max(4x base, 2 gwei)`, which on a sub-gwei chain is orders of
    /// magnitude above a fulfill's first bid at the same nonce. Anchoring the cap to that
    /// first bid made `fee_floor` return a price the node is guaranteed to reject, and since
    /// `note_broadcast` records only ACCEPTED sends the record could never recover — the
    /// nonce became permanently un-displaceable by us.
    #[test]
    fn an_externally_priced_broadcast_lifts_the_cap() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(100), Some(100));
        m.note_broadcast(100, 0, 50_000_000, 50_000_000); // fulfill: 0.05 gwei
        // The healer's own price, not derived from the floor.
        m.note_broadcast(100, 2_000_000_000, 2_000_000_000, 2_000_000_000);
        let (_, capped) = m.fee_floor(100).unwrap();
        assert!(
            capped >= 2_000_000_000,
            "floor reported {capped}, below the 2 gwei we actually broadcast — every \
             replacement computed from it is guaranteed to be rejected"
        );
    }

    /// R1: the incident state. `is_freed` flickers to FALSE the instant the poisoned nonce
    /// is re-reserved, which is what hid the 2026-08-01 wedge from the once-a-minute
    /// watchdog. The sticky record must survive that re-reservation.
    #[test]
    fn abort_memory_survives_re_reservation() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(7708), Some(7708));
        m.abort(7708);
        assert!(m.is_freed(7708), "freed right after abort");
        // the retry loop immediately takes it back -> `freed` is now EMPTY
        assert_eq!(m.try_reserve(), Some(7708));
        assert!(!m.is_freed(7708), "this flicker is what hid the wedge");
        assert!(
            m.recently_aborted(7708, Duration::from_secs(600)),
            "sticky evidence must survive re-reservation"
        );
    }

    /// R1: it must NOT fire for a nonce we never aborted (e.g. a healthy in-flight fulfill).
    #[test]
    fn abort_memory_absent_for_untouched_nonce() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(500), Some(500));
        let n = m.try_reserve().unwrap();
        assert!(!m.recently_aborted(n, Duration::from_secs(600)));
        assert!(!m.recently_aborted(999, Duration::from_secs(600)));
    }

    /// R1: once the nonce MINES it is definitively not a hole — evidence must be dropped,
    /// or the detector would keep offering to heal an already-consumed nonce forever.
    #[test]
    fn abort_memory_cleared_when_nonce_mines() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(7708), Some(7708));
        m.abort(7708);
        assert!(m.recently_aborted(7708, Duration::from_secs(600)));
        m.commit(7708);
        assert!(!m.recently_aborted(7708, Duration::from_secs(600)), "mined => not a hole");
        // and via the resync path (external tx advanced the account)
        let m2 = NonceManager::new();
        assert_eq!(m2.anchor_if_unsynced(100), Some(100));
        m2.abort(100);
        m2.resync(101);
        assert!(!m2.recently_aborted(100, Duration::from_secs(600)));
    }

    /// R1: a fast abort/re-reserve loop must not refresh the timestamp forever — otherwise
    /// the TTL never expires and the record is immortal.
    #[test]
    fn abort_memory_keeps_first_timestamp() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(10), Some(10));
        m.abort(10);
        assert!(!m.recently_aborted(10, Duration::ZERO), "zero window => already expired");
        m.abort(10); // second abort must NOT reset the clock
        assert!(!m.recently_aborted(10, Duration::ZERO));
    }

    /// R2: records above the mined frontier must not accumulate without bound.
    #[test]
    fn abort_memory_is_bounded() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(0), Some(0));
        for _ in 0..5_000 {
            let n = m.try_reserve().unwrap();
            m.abort(n);
        }
        // Nothing has mined, so pruning cannot rely on `commit`; the sweep must cap it.
        let live = m.lock().aborted_at.len();
        assert!(live <= 5_001, "map grew to {live}");
        // and once the frontier advances, everything at/below it is dropped
        m.commit(4_999);
        assert!(m.lock().aborted_at.len() <= 1, "commit must prune below the frontier");
    }

    /// R3/R5: the healer's unconfirmed path must stay DETECTABLE next tick. `claim_gap`
    /// removes the nonce from `freed` and leaves `next == mined + 1`, so without evidence
    /// neither detector branch can fire and the promised retry never happens.
    #[test]
    fn unresolved_heal_remains_detectable() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(7708), Some(7708));
        m.claim_gap(7708); // healer takes exclusive custody
        assert!(!m.is_freed(7708), "claim_gap removes it from freed");
        assert_eq!(m.peek_next(), Some(7709), "next is only mined+1 -> branch (A) blind");
        assert!(!m.recently_aborted(7708, Duration::from_secs(600)), "no evidence yet");
        // heal sends, gets no receipt within budget:
        m.note_unresolved(7708);
        assert!(
            m.recently_aborted(7708, Duration::from_secs(600)),
            "next tick must still see the gap"
        );
        // ...and it must NOT have been recycled for a sibling task to grab
        assert!(!m.is_freed(7708), "note_unresolved must not hand the nonce to others");
    }

    /// [A2] The ratchet cap must never invert the EIP-1559 pair. A node REJECTS a tx with
    /// maxPriorityFeePerGas > maxFeePerGas, and because `note_broadcast` only records on
    /// success, such a nonce can never advance its floor again — permanently stuck.
    #[test]
    fn fee_floor_never_returns_tip_above_max_fee() {
        let m = NonceManager::new();
        assert_eq!(m.anchor_if_unsynced(1), Some(1));
        // Equal-fee regime: the norm here (configured gas_price, or the 429 fallback).
        m.note_broadcast(1, 1_000, 1_000, 1_000);
        // Ratchet far past the cap so `max_fee` is clamped down hard.
        m.note_broadcast(1, 100_000_000, 100_000_000, 1_000);
        let (tip, max_fee) = m.fee_floor(1).expect("floor");
        assert!(
            tip <= max_fee,
            "tip {tip} must never exceed max_fee {max_fee} — the node rejects that tx"
        );
        assert_eq!(max_fee, 1_000 * FEE_FLOOR_MAX_RATCHET, "cap still applies");
    }

    #[test]
    fn invalidate_forces_reanchor() {
        let m = NonceManager::new();
        m.anchor_if_unsynced(30);
        let _ = m.try_reserve(); // 31
        m.invalidate();
        assert_eq!(m.try_reserve(), None); // unsynced again
        // Re-anchor never goes below where we were.
        assert_eq!(m.anchor_if_unsynced(20), Some(32));
    }
}

#[cfg(test)]
mod fee_cap_livelock_tests {
    use super::*;

    /// THE 2026-08-14 BUG. Once the recorded floor passes the cap, the read clamps
    /// back to the cap forever, so the caller's `floor + 12.5%` reproduces exactly the
    /// fee already on the wire. A replacement must be STRICTLY higher, so that bid is
    /// rejected every time — 327 sends over 4h24m, three jobs stranded past deadline.
    ///
    /// The fixed point must now be reported as exhaustion instead of returned silently.
    #[test]
    fn a_capped_nonce_reports_exhaustion_instead_of_a_losing_bid() {
        let m = NonceManager::new();
        let seed = 1_000u128;
        // First broadcast anchors origin_max_fee, so cap = 8_000.
        m.note_broadcast(5, 0, seed, seed);
        let st = m.fee_floor_state(5).unwrap();
        assert_eq!(st.cap, seed * FEE_FLOOR_MAX_RATCHET);
        assert!(!st.exhausted, "a fresh floor has room to escalate");

        // Escalate up to and past the cap, the way repeated retries do.
        let mut bid = seed;
        for _ in 0..40 {
            bid = bid.saturating_add((bid / 8).max(1));
            m.note_broadcast(5, 0, bid, seed);
        }

        let st = m.fee_floor_state(5).unwrap();
        assert!(st.broadcast.1 >= st.cap, "we broadcast past the cap");
        assert!(
            st.exhausted,
            "cap is binding, so no strictly-higher bid exists — this MUST be reported, \
             not papered over by returning the capped value again"
        );

        // The precise livelock: the capped floor plus the caller's margin must never be
        // presented as a fresh bid, because it equals what is already resident.
        let capped_plus_margin = st.floor.1.saturating_add((st.floor.1 / 8).max(1));
        assert!(
            capped_plus_margin <= st.broadcast.1,
            "the old code's bid ({capped_plus_margin}) was <= what was already on the \
             wire ({}) — that is the rejected-forever fixed point",
            st.broadcast.1
        );
    }

    /// A jam gates claiming, and clears by itself once the frontier moves past it, so a
    /// resolved wedge resumes mining with no operator action and no restart.
    #[test]
    fn a_jam_gates_claiming_and_clears_when_the_nonce_mines() {
        let m = NonceManager::new();
        // Sync first: `commit` is a no-op on an unsynced allocator, and in production
        // we are always synced by the time a receipt lands (committing requires having
        // reserved, which requires a sync). The TTL is the backstop for any path that
        // somehow is not.
        m.anchor_if_unsynced(11_589);
        assert!(!m.is_jammed(), "a fresh allocator is not jammed");

        m.note_undisplaceable(11_589);
        assert!(m.is_jammed());
        assert_eq!(m.jammed_nonce(), Some(11_589));

        // The resident tx finally mines and the frontier passes it.
        m.commit(11_589);
        assert!(
            !m.is_jammed(),
            "commit past the jammed nonce must re-open claiming immediately"
        );
    }

    /// `resync` must clear the jam too — it is the path taken when the frontier moves
    /// because of a tx we did not send.
    #[test]
    fn resync_past_a_jam_clears_it() {
        let m = NonceManager::new();
        m.anchor_if_unsynced(1);
        m.note_undisplaceable(100);
        assert!(m.is_jammed());
        m.resync(200);
        assert!(!m.is_jammed(), "resync past the jam must clear it");
    }

    /// A stale fee floor below the mined frontier must not survive `resync`: with
    /// exhaustion now derived from it, a stale entry would make us REFUSE to send at a
    /// nonce that is in fact free. `commit` already pruned; `resync` did not.
    #[test]
    fn resync_prunes_the_fee_floor_below_the_frontier() {
        let m = NonceManager::new();
        m.anchor_if_unsynced(1);
        m.note_broadcast(10, 0, 5_000, 1);
        assert!(m.fee_floor_state(10).is_some());
        m.resync(50);
        assert!(
            m.fee_floor_state(10).is_none(),
            "a floor below the mined frontier must be pruned, or it can be read back \
             as a false 'exhausted' and block a send at a free nonce"
        );
    }
}

#[cfg(test)]
mod eviction_wedge_tests {
    use super::*;

    /// The exhausted-cap give-up must not be able to create a hole nobody will heal.
    ///
    /// Giving up leaves a transaction we could not outbid at the nonce. If that tx is
    /// later EVICTED from the mempool the nonce becomes a hole, and an unresolved
    /// reservation there is a PERMANENT signer wedge — every higher nonce queues behind
    /// it forever.
    ///
    /// A bare broadcast record is NOT sufficient evidence for the healer: it is equally
    /// consistent with "our tx is resident and live", and treating it as proof of a hole
    /// evicts live transactions. `a_live_broadcast_at_the_frontier_is_still_refused`
    /// (tests/nonce_gap_detection.rs) catches precisely that mistake. So the give-up
    /// RECYCLES the nonce instead, which is this codebase's established answer for a
    /// give-up whose tx might still be pending.
    #[test]
    fn a_given_up_nonce_stays_visible_but_is_never_reissued() {
        let m = NonceManager::new();
        // anchor_if_unsynced RESERVES the nonce it returns.
        assert_eq!(m.anchor_if_unsynced(500), Some(500));

        // An accepted broadcast at 500 — the only thing that records a floor.
        m.note_broadcast(500, 0, 1_000, 1_000);
        // Cap exhausted: mark the jam and give the nonce back, as the bail arms do.
        m.note_undisplaceable(500);
        m.note_unresolved(500);

        // Visible to the detector via `recently_aborted` (branch B), so the healer can
        // still reach it if the resident tx is evicted and it becomes a real hole.
        assert!(
            m.recently_aborted(500, std::time::Duration::from_secs(60)),
            "an unresolved reservation must stay VISIBLE, or an evicted resident tx \
             leaves a permanent gap nothing heals"
        );
        // But NOT offered back to reservers. `abort` would push it to the head of `freed`
        // and `reserve_locked` hands the lowest freed nonce out first, so the next
        // reserver -- preferentially a deadline-critical release -- would draw this same
        // poisoned nonce and bail again, in a loop.
        assert!(!m.is_freed(500), "a poisoned nonce must not head the free list");
        for _ in 0..5 {
            assert_ne!(
                m.try_reserve(),
                Some(500),
                "the exhausted nonce must never be handed back out"
            );
        }
        assert!(m.is_jammed(), "and claiming stays gated until it resolves");

        // When it finally mines, the jam retires.
        m.commit(500);
        assert!(!m.is_jammed(), "the jam is over once the frontier passes it");
    }
}

#[cfg(test)]
mod false_jam_tests {
    use super::*;

    /// A GAS PRICE SPIKE must not read as an exhausted cap.
    ///
    /// The cap is anchored to `origin_max_fee`, which ratchets with the externally-priced
    /// seed on every broadcast — so when the market price rises, the ceiling rises with
    /// it. If the cap were pinned to the FIRST price ever seen, a later legitimate bid at
    /// the new market rate would land above it, report `exhausted`, and jam claiming while
    /// a perfectly healthy transaction sat in the mempool about to mine.
    #[test]
    fn a_rising_market_price_raises_the_cap_rather_than_jamming() {
        let m = NonceManager::new();
        // First broadcast in a cheap market: 1 gwei.
        let cheap = 1_000_000_000u128;
        m.note_broadcast(7, 0, cheap, cheap);
        assert!(!m.fee_floor_state(7).unwrap().exhausted);

        // Gas spikes 20x. This is the EXTERNAL price, not our escalation ladder.
        let spike = 20_000_000_000u128;
        m.note_broadcast(7, 0, spike, spike);

        let st = m.fee_floor_state(7).unwrap();
        assert!(
            !st.exhausted,
            "a market move must not exhaust the cap: broadcast={} cap={}",
            st.broadcast.1, st.cap
        );
        assert!(st.cap >= spike, "the ceiling tracks the external price");
    }

    /// Conversely, OUR OWN escalation ladder running away IS what the cap is for.
    #[test]
    fn our_own_runaway_escalation_still_exhausts() {
        let m = NonceManager::new();
        let base = 1_000_000_000u128;
        // seed stays at `base` — this is us re-bidding, not the market moving.
        let mut bid = base;
        for _ in 0..40 {
            m.note_broadcast(8, 0, bid, base);
            bid = bid.saturating_add((bid / 8).max(1));
        }
        assert!(
            m.fee_floor_state(8).unwrap().exhausted,
            "an unbounded self-ratchet is exactly what the cap must stop"
        );
    }
}

#[cfg(test)]
mod healer_bid_tests {
    use super::*;

    /// D2, measured on soak20: the healer is the DESIGNATED unwedger, and it could not
    /// win. It read the CAPPED floor and bid `over(cap) = 1.125 x cap`, while the job
    /// paths' exhausted steady state sits at ~1.0415 x cap — only +8.0%, under geth's
    /// +10% replacement threshold. 259 heal attempts between 22:19 and 02:38, every one
    /// rejected "replacement transaction underpriced", nonce wedged 4h24m.
    ///
    /// This drives the REAL allocator to its exhausted steady state and asserts the
    /// healer's bid now clears the threshold.
    #[test]
    fn the_healer_bid_clears_the_replacement_threshold_when_exhausted() {
        let over = |v: u128| v.saturating_add((v / 8).max(1));
        let base = 2_000_000_000u128; // deployed gas_price_gwei = 2.0
        let m = NonceManager::new();
        m.anchor_if_unsynced(11_589);

        // Drive the job-path ladder to its exhausted steady state, exactly as the retry
        // loop does: bid = over(floor), recorded via note_broadcast, seed frozen at base.
        for _ in 0..30 {
            let Some(st) = m.fee_floor_state(11_589) else {
                m.note_broadcast(11_589, 0, base, base);
                continue;
            };
            if st.exhausted {
                break;
            }
            m.note_broadcast(11_589, 0, over(st.floor.1), base);
        }

        let st = m.fee_floor_state(11_589).expect("floor recorded");
        assert!(st.exhausted, "the ladder must reach exhaustion");
        let resident = st.broadcast.1;

        // OLD healer: lifted over the CAPPED floor.
        let old_bid = (4 * base).max(over(st.floor.1));
        // NEW healer: lifts over the UNCAPPED high-water.
        let new_bid = (4 * base).max(over(st.broadcast.1));

        assert!(
            old_bid * 100 < resident * 110,
            "the OLD bid {old_bid} was under +10% over resident {resident} — that is why \
             all 259 heals were rejected"
        );
        assert!(
            new_bid * 100 >= resident * 110,
            "the NEW bid {new_bid} must clear +10% over resident {resident} to be accepted"
        );
        // And it is still bounded — one step, no compounding.
        assert!(
            new_bid <= over(over(st.cap)),
            "the heal bid must stay within one floor-lift of the cap: {new_bid} vs {}",
            over(over(st.cap))
        );
    }

    /// THE ROUND-2 DEFECT. The heal writes its own lifted bid back as the new
    /// high-water while its seed stays frozen at 4x base, so the cap stops moving and
    /// each heal lifts over the PREVIOUS heal. Compounding x9/8 every 60s, and on
    /// soak20 this path ran 259 consecutive times.
    ///
    /// The earlier version of the test above computed one bid as a local expression and
    /// never fed it back, so it modelled exactly one heal and stayed green while the
    /// ratchet ran away. This one closes the loop.
    #[test]
    fn repeated_heals_never_escalate_past_the_ceiling() {
        let over = |v: u128| v.saturating_add((v / 8).max(1));
        let base = 2_000_000_000u128;
        let seed = 4 * base; // the healer's frozen external anchor
        let m = NonceManager::new();
        m.anchor_if_unsynced(11_589);

        // Seed from the RELEASE ladder (attempt + FULFILL_ESCALATION_HEADROOM), which is
        // the shape that actually wedged 11589 -- not the shorter claim ladder.
        let mut v = base;
        for _ in 0..9 {
            v = v.saturating_add((v.saturating_mul(15) / 100).max(v.saturating_add(7) / 8).max(1));
        }
        m.note_broadcast(11_589, 0, v, v);

        let mut worst = 0u128;
        let mut ceiling_refusals = 0;
        for i in 0..80 {
            let st = m.fee_floor_state(11_589).expect("floor");
            let ceiling = over(over(st.cap));
            let bid = (4 * base).max(over(st.broadcast.1)).min(ceiling).max(4 * base);
            assert!(
                bid <= ceiling,
                "heal #{i} bid {bid} escaped the ceiling {ceiling} — this is the \
                 unbounded ratchet that drains the gas balance and wedges the signer"
            );
            // The healer REFUSES when the clamped bid cannot clear the node's
            // replacement margin. Merely-larger is not enough: once the clamp binds, the
            // ratio decays and settles back at exactly the +8.02% that made the original
            // healer a guaranteed loser -- the same fixed point, relocated to the ceiling.
            // Refusing there is the whole point; sending would be D2 all over again.
            if bid < over(st.broadcast.1) {
                ceiling_refusals += 1;
                break;
            }
            worst = worst.max(bid);
            // Feed the bid BACK, exactly as `heal_claimed_gap_at` does.
            m.note_broadcast(11_589, 0, bid, seed);
        }

        let st = m.fee_floor_state(11_589).unwrap();
        assert!(
            worst <= over(over(st.cap)),
            "worst bid {worst} over 80 heals must stay bounded"
        );
        // Sanity: a 21k self-transfer at the worst bid is cents, not the wallet.
        assert!(
            worst.saturating_mul(21_000) < 10_000_000_000_000_000,
            "worst-case heal cost {} wei exceeds 0.01 ETH",
            worst.saturating_mul(21_000)
        );
        // And the loop must TERMINATE by refusing, not by running out of iterations --
        // otherwise the healer is still spending on sends that cannot be accepted.
        assert_eq!(
            ceiling_refusals, 1,
            "the healer must stop at the ceiling by refusing, not keep bidding"
        );
    }

    /// A jam BELOW the frontier must survive a resync that does not reach it.
    #[test]
    fn a_resync_below_a_jam_leaves_it_in_place() {
        let m = NonceManager::new();
        m.anchor_if_unsynced(1);
        m.note_undisplaceable(100);
        m.resync(50);
        assert!(m.is_jammed(), "resync short of the jam must not clear it");
        m.resync(101);
        assert!(!m.is_jammed(), "resync past it must");
    }
}

#[cfg(test)]
mod jam_gate_tests {
    use super::*;

    /// J1. `is_jammed` must NOT delete the record it reads.
    ///
    /// It is called from the claim hot path. Sweeping there made the query destroy its
    /// own evidence: the gate failed OPEN during a live jam, and since `jammed_nonce()`
    /// could no longer see the deleted key, the resync probe could never re-arm it — a
    /// bailed nonce lives in `unresolved`, so `reserve_locked` never hands it out for a
    /// bail arm to re-observe. Fresh claims then queue behind the wedge and ride to
    /// their lock deadlines: the 2026-08-14 loss shape, re-created by the gate's timer.
    #[test]
    fn asking_whether_we_are_jammed_does_not_erase_the_jam() {
        let m = NonceManager::new();
        m.anchor_if_unsynced(1);
        m.note_undisplaceable(11_589);

        for _ in 0..50 {
            assert!(m.is_jammed(), "the gate must stay closed while the jam is live");
        }
        assert_eq!(
            m.jammed_nonce(),
            Some(11_589),
            "the probe must still be able to see the jam after the gate has read it"
        );
    }

    /// The probe's clear is authoritative; the TTL is only a backstop.
    #[test]
    fn the_probe_clears_the_jam_when_the_frontier_passes() {
        let m = NonceManager::new();
        m.anchor_if_unsynced(1);
        m.note_undisplaceable(11_589);
        assert!(m.is_jammed());

        m.clear_undisplaceable(11_589);
        assert!(!m.is_jammed());
        assert_eq!(m.jammed_nonce(), None);
    }

    /// A jam must outlast a stalled recovery pass. Each receipt wait during a jam burns
    /// the full TX_RECEIPT_TIMEOUT for a receipt that cannot arrive, and fulfill retries
    /// five times — the old 120s TTL expired inside a single such pass.
    #[test]
    fn the_ttl_outlasts_a_stalled_recovery_pass() {
        let worst_stall = std::time::Duration::from_secs(120) * 5;
        assert!(
            UNDISPLACEABLE_TTL > worst_stall,
            "TTL {UNDISPLACEABLE_TTL:?} must exceed a stalled recovery pass {worst_stall:?}, \
             or the claim gate opens while the jam is live"
        );
    }

    /// J2. A ceiling-reached ladder must be resettable, or a heal that was accepted and
    /// then evicted from the mempool vetoes every future heal at that nonce forever.
    #[test]
    fn a_stale_ladder_can_be_reset_when_the_resident_is_gone() {
        let m = NonceManager::new();
        m.anchor_if_unsynced(1);
        m.note_broadcast(11_589, 0, 80_000_000_000, 8_000_000_000);
        assert!(m.fee_floor_state(11_589).is_some());

        m.reset_fee_floor(11_589);
        assert!(
            m.fee_floor_state(11_589).is_none(),
            "with no resident on chain the ladder must reset so a cheap bid can be sent"
        );
    }
}
