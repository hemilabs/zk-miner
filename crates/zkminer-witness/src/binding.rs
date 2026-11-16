//! Journal layout and binding helpers for witness jobs (plan §7.2).
//!
//! Layout: `[abi.encode(jobId, prover) (64 bytes, prefix jobs)] ‖ header (k × 32-byte words, each
//! written with env::commit_slice) ‖ outputs (free)`. The whole header is pinned with FIELDS.
//!
//! The guest input of a witness job is `prefix ‖ W` for prefix jobs and `W` otherwise. Every path —
//! measure, prove, recovery, `simulate` — derives it with [`guest_input_prefix`] and hashes it with
//! [`input_sha256`], so the input the claim gate checked is the input the lock proves.

use std::io::{self, Read};

use alloy_primitives::{keccak256, Address, B256};
use sha2::{Digest, Sha256};

/// `journalFields` slot 0: the journal must begin with `abi.encode(jobId, prover)`.
pub const JOURNAL_PREFIX_MARKER: u32 = 0xffff_ffff;
/// `journalFields` slot 0: the SP1 seal's nonce word must equal `getProofNonce(jobId, prover)`.
pub const PROOF_NONCE_MARKER: u32 = 0xffff_fffe;
/// The prefix length.
pub const PREFIX_BYTES: usize = 64;
/// FIELDS ranges must end within the journal cap (32,768), or within 32,704 under the prefix.
pub const MAX_JOURNAL_BYTES: usize = 32_768;
pub const MAX_STATEMENT_BYTES_WITH_PREFIX: usize = MAX_JOURNAL_BYTES - PREFIX_BYTES;
/// `W` is hashed and streamed in pieces of at most this size (plan §10.1).
pub const STREAM_CHUNK_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    #[error("the header is empty")]
    EmptyHeader,
    #[error("the header length is not a multiple of 32")]
    NotWords,
    #[error("the header does not fit in one FIELDS range under the journal cap")]
    TooLong,
}

/// The marker in slot 0 of `journalFields`, if any (the router treats slot 0 values at or above
/// `0xfffffffe` as markers).
pub fn marker(journal_fields: B256) -> Option<u32> {
    let slot0 = u32::from_be_bytes(journal_fields.0[..4].try_into().expect("4 bytes"));
    (slot0 >= PROOF_NONCE_MARKER).then_some(slot0)
}

/// The router's `_journalFieldsHash`: the plain `keccak256` of the used slots' ranges concatenated
/// in slot order, or `B256::ZERO` when a used range ends past `statement`. A slot is
/// `(uint16 offset << 16) | uint16 length`, slot 0 the top 32 bits; length 0 is unused. Pass
/// `journalFields` with any marker already cleared, and the journal after any prefix.
pub fn fields_hash(statement: &[u8], fields: B256) -> B256 {
    let mut buf = Vec::new();
    for slot in fields.0.chunks_exact(4) {
        let off = u16::from_be_bytes([slot[0], slot[1]]) as usize;
        let len = u16::from_be_bytes([slot[2], slot[3]]) as usize;
        if len == 0 {
            continue;
        }
        if off + len > statement.len() {
            return B256::ZERO;
        }
        buf.extend_from_slice(&statement[off..off + len]);
    }
    keccak256(&buf)
}

/// `journalFields` with a slot-0 marker cleared, as the router does before choosing the mode.
pub fn clear_marker(journal_fields: B256) -> B256 {
    let mut f = journal_fields;
    if marker(f).is_some() {
        f.0[..4].fill(0);
    }
    f
}

/// `abi.encode(jobId, prover)`: the jobId, 12 zero bytes, the prover address.
pub fn journal_prefix(job_id: B256, prover: Address) -> [u8; PREFIX_BYTES] {
    let mut p = [0u8; PREFIX_BYTES];
    p[..32].copy_from_slice(job_id.as_slice());
    p[44..].copy_from_slice(prover.as_slice());
    p
}

/// The prefix the guest input starts with: `Some` exactly when slot 0 of `journalFields` carries
/// the journal-prefix marker. The one derivation every path uses.
pub fn guest_input_prefix(journal_fields: B256, job_id: B256, prover: Address) -> Option<[u8; PREFIX_BYTES]> {
    (marker(journal_fields) == Some(JOURNAL_PREFIX_MARKER)).then(|| journal_prefix(job_id, prover))
}

/// `sha256(prefix ‖ W)` and `|W|`, streaming `w` in pieces of at most [`STREAM_CHUNK_BYTES`].
pub fn input_sha256(prefix: Option<&[u8; PREFIX_BYTES]>, mut w: impl Read) -> io::Result<(B256, u64)> {
    let mut h = Sha256::new();
    if let Some(p) = prefix {
        h.update(p);
    }
    let mut buf = vec![0u8; STREAM_CHUNK_BYTES];
    let mut total = 0u64;
    loop {
        let n = match w.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok((B256::from(<[u8; 32]>::from(h.finalize())), total))
}

/// Concatenates header words.
pub fn header_from_words(words: &[B256]) -> Vec<u8> {
    words.iter().flat_map(|w| w.0).collect()
}

/// `journalFields` that pins a header of `header_len` bytes at the start of the statement:
/// with the prefix marker, slot 0 = marker and slot 1 = (offset 0, length H); without it,
/// slot 0 = (offset 0, length H).
pub fn journal_fields_for_header(header_len: usize, with_prefix: bool) -> Result<B256, BindingError> {
    if header_len == 0 {
        return Err(BindingError::EmptyHeader);
    }
    if !header_len.is_multiple_of(32) {
        return Err(BindingError::NotWords);
    }
    let limit = if with_prefix { MAX_STATEMENT_BYTES_WITH_PREFIX } else { MAX_JOURNAL_BYTES };
    if header_len > limit || header_len > u16::MAX as usize {
        return Err(BindingError::TooLong);
    }
    let range = header_len as u32; // (offset 0 << 16) | length
    let mut w = [0u8; 32];
    if with_prefix {
        w[0..4].copy_from_slice(&JOURNAL_PREFIX_MARKER.to_be_bytes());
        w[4..8].copy_from_slice(&range.to_be_bytes());
    } else {
        w[0..4].copy_from_slice(&range.to_be_bytes());
    }
    Ok(B256::from(w))
}

/// `expectedJournalHash` for a FIELDS binding of one range at offset 0: the keccak of the pinned
/// bytes. Compute it from the requester's own parameters, never from a prover's journal.
pub fn expected_journal_hash(header: &[u8]) -> B256 {
    keccak256(header)
}

/// Why the mutation check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationFailure {
    /// The FIELDS hash of the unmutated statement is zero: a range ends past the statement.
    RangePastEnd,
    /// Changing byte `byte` of parameter `param` leaves the FIELDS hash unchanged.
    Unpinned { param: usize, byte: usize },
}

/// The mutation check (plan §7.2, §21.1): changing any byte of any parameter must change the hash the
/// router computes. `statement` maps parameter words to the journal the guest commits *after* any
/// prefix; the hash is taken exactly as the router takes it, under `journal_fields` (marker cleared).
pub fn mutation_check(
    params: &[B256],
    journal_fields: B256,
    statement: impl Fn(&[B256]) -> Vec<u8>,
) -> Result<(), MutationFailure> {
    let fields = clear_marker(journal_fields);
    let h = |p: &[B256]| fields_hash(&statement(p), fields);
    let base = h(params);
    if base == B256::ZERO {
        return Err(MutationFailure::RangePastEnd);
    }
    for i in 0..params.len() {
        for b in 0..32 {
            let mut p = params.to_vec();
            p[i].0[b] ^= 0xff;
            if h(&p) == base {
                return Err(MutationFailure::Unpinned { param: i, byte: b });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    #[test]
    fn prefix_layout_and_derivation() {
        let p = journal_prefix(B256::repeat_byte(0xaa), Address::repeat_byte(0xbb));
        assert_eq!(&p[..32], &[0xaa; 32]);
        assert_eq!(&p[32..44], &[0; 12]);
        assert_eq!(&p[44..], &[0xbb; 20]);
        let with = journal_fields_for_header(64, true).unwrap();
        let without = journal_fields_for_header(64, false).unwrap();
        assert_eq!(guest_input_prefix(with, B256::repeat_byte(0xaa), Address::repeat_byte(0xbb)), Some(p));
        assert_eq!(guest_input_prefix(without, B256::ZERO, Address::ZERO), None);
        let mut nonce = without;
        nonce.0[..4].copy_from_slice(&PROOF_NONCE_MARKER.to_be_bytes());
        assert_eq!(guest_input_prefix(nonce, B256::ZERO, Address::ZERO), None);
    }

    #[test]
    fn input_hash_streams_prefix_then_w() {
        let p = journal_prefix(B256::repeat_byte(1), Address::repeat_byte(2));
        let w: Vec<u8> = (0..(3 * STREAM_CHUNK_BYTES + 7)).map(|i| i as u8).collect();
        let (h, n) = input_sha256(Some(&p), &w[..]).unwrap();
        let mut whole = p.to_vec();
        whole.extend_from_slice(&w);
        assert_eq!(h.0, <[u8; 32]>::from(Sha256::digest(&whole)));
        assert_eq!(n, w.len() as u64);
        let (h, _) = input_sha256(None, &w[..]).unwrap();
        assert_eq!(h.0, <[u8; 32]>::from(Sha256::digest(&w)));
    }

    #[test]
    fn fields_words_match_the_formula_and_the_router_hash() {
        for h in [32usize, 160, 32_704] {
            let w = journal_fields_for_header(h, true).unwrap();
            let want = (U256::from(0xffff_ffffu64) << 224) | (U256::from(h) << 192);
            assert_eq!(U256::from_be_bytes(w.0), want);
            let w = journal_fields_for_header(h, false).unwrap();
            assert_eq!(U256::from_be_bytes(w.0), U256::from(h) << 224);
        }
        assert!(journal_fields_for_header(32_768, false).is_ok());
        assert_eq!(journal_fields_for_header(32_800, false), Err(BindingError::TooLong));
        assert_eq!(journal_fields_for_header(0, true), Err(BindingError::EmptyHeader));
        assert_eq!(journal_fields_for_header(33, true), Err(BindingError::NotWords));
        assert!(journal_fields_for_header(32_704, true).is_ok());
        assert_eq!(journal_fields_for_header(32_736, true), Err(BindingError::TooLong));
        // Router round trip: prefix ‖ header ‖ outputs hashes to keccak(header).
        let header = header_from_words(&[B256::repeat_byte(3), B256::repeat_byte(4)]);
        let fields = journal_fields_for_header(header.len(), true).unwrap();
        let mut statement = header.clone();
        statement.extend_from_slice(b"free outputs");
        assert_eq!(fields_hash(&statement, clear_marker(fields)), expected_journal_hash(&header));
        assert_eq!(fields_hash(&header[..63], clear_marker(fields)), B256::ZERO, "range past the end");
    }

    #[test]
    fn mutation_check_catches_unpinned_bytes() {
        let params = [B256::repeat_byte(1), B256::repeat_byte(2)];
        let fields64 = journal_fields_for_header(64, true).unwrap();
        assert_eq!(mutation_check(&params, fields64, header_from_words), Ok(()));
        // Only the first word is pinned: the second parameter is free.
        let fields32 = journal_fields_for_header(32, true).unwrap();
        assert_eq!(
            mutation_check(&params, fields32, header_from_words),
            Err(MutationFailure::Unpinned { param: 1, byte: 0 })
        );
        // A guest that commits each parameter as an address leaves 12 bytes of each free.
        let as_addresses = |p: &[B256]| {
            p.iter().flat_map(|w| {
                let mut out = [0u8; 32];
                out[12..].copy_from_slice(&w.0[12..]);
                out
            }).collect::<Vec<u8>>()
        };
        assert_eq!(
            mutation_check(&params, fields64, as_addresses),
            Err(MutationFailure::Unpinned { param: 0, byte: 0 })
        );
        // A range past the statement fails rather than passing vacuously.
        let fields96 = journal_fields_for_header(96, true).unwrap();
        assert_eq!(mutation_check(&params, fields96, header_from_words), Err(MutationFailure::RangePastEnd));
    }
}
