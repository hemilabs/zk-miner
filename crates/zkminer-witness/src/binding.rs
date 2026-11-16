//! Journal layout and binding helpers for witness jobs (plan §7.2).
//!
//! Layout: `[abi.encode(jobId, prover) (64 bytes, prefix jobs)] ‖ header (k × 32-byte words, each
//! written with env::commit_slice) ‖ outputs (free)`. The whole header is pinned with FIELDS.

use alloy_primitives::{keccak256, Address, B256};

/// The journal-prefix marker in slot 0 of `journalFields`.
pub const JOURNAL_PREFIX_MARKER: u32 = 0xffff_ffff;
/// The prefix length.
pub const PREFIX_BYTES: usize = 64;
/// FIELDS ranges must end within the journal cap (32,768), or within 32,704 under the prefix.
pub const MAX_JOURNAL_BYTES: usize = 32_768;
pub const MAX_STATEMENT_BYTES_WITH_PREFIX: usize = MAX_JOURNAL_BYTES - PREFIX_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    #[error("the header is empty")]
    EmptyHeader,
    #[error("the header length is not a multiple of 32")]
    NotWords,
    #[error("the header does not fit in one FIELDS range under the journal cap")]
    TooLong,
}

/// `abi.encode(jobId, prover)`: the jobId, 12 zero bytes, the prover address.
pub fn journal_prefix(job_id: B256, prover: Address) -> [u8; PREFIX_BYTES] {
    let mut p = [0u8; PREFIX_BYTES];
    p[..32].copy_from_slice(job_id.as_slice());
    p[44..].copy_from_slice(prover.as_slice());
    p
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
    if header_len % 32 != 0 {
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

/// `expectedJournalHash` for a FIELDS binding of one range: the keccak of the pinned bytes.
/// Compute it from the requester's own parameters, never from a prover's journal.
pub fn expected_journal_hash(header: &[u8]) -> B256 {
    keccak256(header)
}

/// The mutation check (plan §7.2): changing any one header word must change the FIELDS hash.
/// `encode` maps parameter words to the header the guest commits. Returns the index of the first
/// parameter whose change is not reflected.
pub fn mutation_check(params: &[B256], encode: impl Fn(&[B256]) -> Vec<u8>) -> Result<(), usize> {
    let base = expected_journal_hash(&encode(params));
    for i in 0..params.len() {
        let mut p = params.to_vec();
        p[i].0[31] ^= 1;
        if expected_journal_hash(&encode(&p)) == base {
            return Err(i);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_layout() {
        let p = journal_prefix(B256::repeat_byte(0xaa), Address::repeat_byte(0xbb));
        assert_eq!(&p[..32], &[0xaa; 32]);
        assert_eq!(&p[32..44], &[0; 12]);
        assert_eq!(&p[44..], &[0xbb; 20]);
    }

    #[test]
    fn fields_words() {
        let w = journal_fields_for_header(160, true).unwrap();
        assert_eq!(&w[0..8], &[0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0xa0]);
        assert!(w[8..].iter().all(|b| *b == 0));
        let w = journal_fields_for_header(160, false).unwrap();
        assert_eq!(&w[0..4], &[0x00, 0x00, 0x00, 0xa0]);
        assert!(w[4..].iter().all(|b| *b == 0));
        assert_eq!(journal_fields_for_header(0, true), Err(BindingError::EmptyHeader));
        assert_eq!(journal_fields_for_header(33, true), Err(BindingError::NotWords));
        assert!(journal_fields_for_header(32_704, true).is_ok());
        assert_eq!(journal_fields_for_header(32_736, true), Err(BindingError::TooLong));
    }

    #[test]
    fn mutation_check_catches_unpinned_parameters() {
        let params = [B256::repeat_byte(1), B256::repeat_byte(2)];
        assert_eq!(mutation_check(&params, header_from_words), Ok(()));
        // A guest that commits only the first parameter leaves the second free.
        assert_eq!(mutation_check(&params, |p| header_from_words(&p[..1])), Err(1));
    }
}
