//! keccak256 and the hashes every eth-block statement compares against.
//!
//! Software keccak (tiny-keccak). The risc0 keccak accelerator would be cheaper for large witnesses,
//! but it turns every guest into one with keccak proof requests (a second circuit to prove and a
//! guest-observable keccak po2); the reference keeps the plain rv32im path.

use tiny_keccak::{Hasher, Keccak};

/// `keccak256(data)`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    keccak256_concat(&[data])
}

/// `keccak256(parts[0] ‖ parts[1] ‖ …)`, without building the concatenation.
pub fn keccak256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// The root of an empty trie, `keccak256(rlp(""))` = `keccak256(0x80)`: the storage root of an
/// account without storage, and of an absent account.
pub const EMPTY_ROOT: [u8; 32] = crate::hex32("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

/// `keccak256("")`: the code hash of an account without code.
pub const KECCAK_EMPTY: [u8; 32] = crate::hex32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

/// `keccak256(rlp([]))`: the ommers hash of every post-merge header.
pub const EMPTY_OMMERS_HASH: [u8; 32] =
    crate::hex32("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_the_hashes_they_name() {
        assert_eq!(keccak256(&[0x80]), EMPTY_ROOT);
        assert_eq!(keccak256(b""), KECCAK_EMPTY);
        assert_eq!(keccak256(&[0xc0]), EMPTY_OMMERS_HASH);
        assert_eq!(keccak256_concat(&[b"ab", b"", b"c"]), keccak256(b"abc"));
        assert_eq!(keccak256(b"abc"), alloy_primitives::keccak256(b"abc").0);
    }
}
