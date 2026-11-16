//! The unit of `maxGuestCycles` (plan §7.1): for one po2, Σ over segments of 2^po2 plus
//! 2^(keccak po2 + 3) per keccak request (2^20 at the default keccak po2 17). The limit is compared
//! with the maximum over the po2s the prover may use.

pub const DEFAULT_KECCAK_PO2: u32 = 17;

/// Sized cycles of one execution at one po2.
pub fn sized_cycles(segment_po2s: impl IntoIterator<Item = u32>, keccak_requests: u64, keccak_po2: u32) -> u64 {
    let segments = segment_po2s
        .into_iter()
        .fold(0u64, |acc, po2| acc.saturating_add(1u64.checked_shl(po2).unwrap_or(u64::MAX)));
    let per_keccak = 1u64.checked_shl(keccak_po2.saturating_add(3)).unwrap_or(u64::MAX);
    segments.saturating_add(keccak_requests.saturating_mul(per_keccak))
}

/// The value compared with `maxGuestCycles`: the maximum over the executed po2s, `None` when nothing
/// was executed (which never passes the limit).
pub fn max_over_po2s(per_po2: impl IntoIterator<Item = u64>) -> Option<u64> {
    per_po2.into_iter().max()
}

/// Whether executions at every po2 the prover may use fit `maxGuestCycles`.
pub fn within_limit(per_po2: impl IntoIterator<Item = u64>, max_guest_cycles: u64) -> bool {
    max_over_po2s(per_po2).is_some_and(|c| c <= max_guest_cycles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(sized_cycles([20, 20, 19], 0, DEFAULT_KECCAK_PO2), (1 << 21) + (1 << 19));
        assert_eq!(sized_cycles([], 3, DEFAULT_KECCAK_PO2), 3 << 20);
        assert_eq!(sized_cycles([], 1, 18), 1 << 21);
        assert_eq!(sized_cycles([70], 0, 17), u64::MAX, "saturates");
        assert_eq!(max_over_po2s([5, 9, 7]), Some(9));
        assert_eq!(max_over_po2s([]), None);
        assert!(!within_limit([], u64::MAX), "nothing executed never passes");
        assert!(within_limit([5, 9], 9));
        assert!(!within_limit([5, 10], 9));
    }
}
