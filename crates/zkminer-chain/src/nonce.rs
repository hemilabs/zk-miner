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

use std::collections::BTreeSet;
use std::sync::Mutex;

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
        if g.synced && nonce < g.next {
            g.freed.insert(nonce);
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
        g.next = g.next.max(used.saturating_add(1));
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
    pub fn claim_gap(&self, nonce: u64) {
        let mut g = self.lock();
        if g.synced {
            g.freed.remove(&nonce);
            g.next = g.next.max(nonce.saturating_add(1));
        }
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
    use super::*;

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
