//! The reference guest library for HemiProve `eth-block` (scheme 1) witness jobs: everything a
//! risc0 guest needs to prove facts about an EVM chain from a witness `W` it does not trust
//! (zkminer `docs/witness-construction-jobs.md` §8), and the codec a witness builder uses to write
//! that `W` (§12).
//!
//! | module | what |
//! |---|---|
//! | [`rlp`] | strict, canonical RLP decode and encode |
//! | [`header`] | block headers, London through Prague, Ethereum and OP Stack |
//! | [`mpt`] | Merkle-Patricia proofs: inclusion and exclusion, embedded nodes, strict node forms |
//! | [`state`] | accounts and storage slots (`eth_getProof`) |
//! | [`receipt`] | EIP-2718 receipts (OP deposit receipts included) and the receipts trie |
//! | [`tx`] | EIP-2718 transactions and the transactions trie |
//! | [`anchor`] | anchors 1 and 2 of §8.5: a pinned block hash, a `parentHash` walk |
//! | [`guard`] | `Pinned`, `Authenticated`, the journal writer (§8.3, "commit what you checked") |
//! | [`scheme1`] | the scheme-1 `W` format, the guest's reader and the structural mutations for tooling |
//!
//! `no_std` with `alloc`: the same code runs in a risc0 guest, in a wasm32 builder and on the host.
//! The `std` feature adds `std::error::Error` impls. See README.md for what a requester must audit.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod anchor;
pub mod guard;
pub mod header;
pub mod keccak;
pub mod mpt;
pub mod receipt;
pub mod rlp;
pub mod scheme1;
pub mod state;
pub mod tx;

/// 32 bytes from 64 hex digits, at compile time.
pub const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_digit(b[2 * i]) << 4) | hex_digit(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not a hex digit"),
    }
}
