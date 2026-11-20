//! Anchors (plan §8.5): how a header becomes trusted.
//!
//! `blockHash` binds a header, not its place in the canonical chain, and nothing forward of a
//! trusted point can be checked from execution headers. Phase 1 ships the two anchors that need no
//! consensus verification:
//!
//! 1. **The target's hash is pinned** ([`pinned_block`]): the header hashes to a pinned word.
//!    Canonicality is the requester's job at submit time; on OP Stack chains take the hash from the
//!    node's `finalized` head (at least `safe`), never the unsafe head.
//! 2. **A later trusted hash is pinned and the guest walks `parentHash` backward**
//!    ([`parent_block`], one step at a time from the pinned block): each header must hash to its
//!    child's `parentHash` and carry its child's number minus one, so the target is proven to be an
//!    ancestor of the pinned block.
//!
//! Anchor 3 (verifying beacon, Tendermint, Bitcoin or OP-dispute-game consensus in the guest) is not
//! implemented; "the latest finalized block" is a live-input statement only with it.

use crate::guard::Authenticated;
use crate::header::{self, Header, HeaderError};

/// Anchor 1: `rlp` is the header of the block whose hash is `hash` (a pinned word).
pub fn pinned_block(rlp: &[u8], hash: &Authenticated<[u8; 32]>) -> Result<Authenticated<Header>, HeaderError> {
    header::decode_with_hash(rlp, hash.get()).map(Authenticated::new)
}

/// Anchor 2, one step: `rlp` is the header of `child`'s parent.
pub fn parent_block(child: &Authenticated<Header>, rlp: &[u8]) -> Result<Authenticated<Header>, HeaderError> {
    let child = child.get();
    let parent = header::decode_with_hash(rlp, &child.parent_hash)?;
    if child.number.checked_sub(1) != Some(parent.number) {
        return Err(HeaderError::NotParent);
    }
    Ok(Authenticated::new(parent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keccak::keccak256;

    fn header(number: u64, parent_hash: [u8; 32]) -> Header {
        Header {
            parent_hash,
            ommers_hash: crate::keccak::EMPTY_OMMERS_HASH,
            beneficiary: [0; 20],
            state_root: [number as u8; 32],
            transactions_root: [0; 32],
            receipts_root: [0; 32],
            logs_bloom: [0; 256],
            difficulty: [0; 32],
            number,
            gas_limit: 1,
            gas_used: 0,
            timestamp: number * 2,
            extra_data: Vec::new(),
            mix_hash: [0; 32],
            nonce: [0; 8],
            base_fee_per_gas: Some([0; 32]),
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        }
    }

    #[test]
    fn walks_back_from_a_pinned_hash() {
        let g = header(10, [0; 32]).encode().unwrap();
        let a = header(11, keccak256(&g)).encode().unwrap();
        let b = header(12, keccak256(&a)).encode().unwrap();
        let tip = pinned_block(&b, &Authenticated::new(keccak256(&b))).unwrap();
        let p = parent_block(&tip, &a).unwrap();
        let gp = parent_block(&p, &g).unwrap();
        assert_eq!(gp.get().number, 10);
        assert_eq!(parent_block(&tip, &g), Err(HeaderError::HashMismatch), "skipping a generation");
        // A header that hashes right but claims the wrong number.
        let liar = header(5, [0; 32]).encode().unwrap();
        let child = header(12, keccak256(&liar)).encode().unwrap();
        let child = pinned_block(&child, &Authenticated::new(keccak256(&child))).unwrap();
        assert_eq!(parent_block(&child, &liar), Err(HeaderError::NotParent));
    }
}
