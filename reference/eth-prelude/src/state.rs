//! Accounts and storage slots against a state root (plan §8.4, "Accounts and storage").
//!
//! - The state trie maps `keccak256(address)` to `rlp([nonce, balance, storageRoot, codeHash])`;
//!   `storageRoot` comes from this leaf, never from RPC JSON.
//! - A storage trie maps `keccak256(slot)` to the RLP of the slot's value, inside the leaf's byte
//!   string: the leaf value is decoded strictly as an integer of at most 32 bytes, without leading
//!   zeros and non-zero (a zero slot is deleted from the trie), then left-padded.
//! - **Absence needs an exclusion proof.** An absent account is nonce 0, balance 0, empty storage
//!   (root [`EMPTY_ROOT`], under which only the empty proof is accepted, so every slot reads 0) and
//!   no code. [`extcodehash`] gives the EVM's `EXTCODEHASH` semantics: 0 for an absent account,
//!   [`KECCAK_EMPTY`] for a present account without code.

use alloc::vec::Vec;
use core::fmt;

use crate::guard::Authenticated;
use crate::keccak::{keccak256, EMPTY_ROOT, KECCAK_EMPTY};
use crate::mpt::{self, ProofError};
use crate::rlp::{self, RlpError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    Proof(ProofError),
    /// A leaf value that is not a canonical account or storage value.
    Rlp(RlpError),
    /// A storage leaf holding zero (zero slots are not stored).
    ZeroStorageValue,
}

impl From<ProofError> for StateError {
    fn from(e: ProofError) -> Self {
        Self::Proof(e)
    }
}

impl From<RlpError> for StateError {
    fn from(e: RlpError) -> Self {
        Self::Rlp(e)
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proof(e) => e.fmt(f),
            Self::Rlp(e) => write!(f, "state leaf: {e}"),
            Self::ZeroStorageValue => f.write_str("storage leaf: holds zero"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StateError {}

/// An account leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    /// 256-bit, big-endian.
    pub balance: [u8; 32],
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

impl Account {
    /// What an absent account reads as.
    pub const ABSENT: Self = Self { nonce: 0, balance: [0; 32], storage_root: EMPTY_ROOT, code_hash: KECCAK_EMPTY };

    /// Strictly decodes a state-trie leaf value.
    pub fn decode(value: &[u8]) -> Result<Self, RlpError> {
        let [nonce, balance, storage_root, code_hash] = rlp::decode_exact(value)?.items::<4>()?;
        Ok(Self { nonce: nonce.u64()?, balance: balance.u256()?, storage_root: storage_root.fixed()?, code_hash: code_hash.fixed()? })
    }

    /// The leaf value's canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(80);
        rlp::encode_u64(&mut p, self.nonce);
        rlp::encode_uint(&mut p, &self.balance);
        rlp::encode_bytes(&mut p, &self.storage_root);
        rlp::encode_bytes(&mut p, &self.code_hash);
        let mut out = Vec::with_capacity(p.len() + 2);
        rlp::encode_list(&mut out, &p);
        out
    }
}

/// `EXTCODEHASH`: 0 for an absent account, its code hash otherwise ([`KECCAK_EMPTY`] without code).
pub fn extcodehash(account: &Option<Account>) -> [u8; 32] {
    account.map(|a| a.code_hash).unwrap_or([0; 32])
}

/// The storage root to read slots under: [`EMPTY_ROOT`] for an absent account.
pub fn storage_root(account: &Option<Account>) -> [u8; 32] {
    account.map(|a| a.storage_root).unwrap_or(EMPTY_ROOT)
}

/// Verifies an account proof (`eth_getProof`'s `accountProof`): `Some` for a present account,
/// `None` for an absent one (an exclusion proof).
pub fn verify_account<N: AsRef<[u8]>>(state_root: &[u8; 32], address: &[u8; 20], proof: &[N]) -> Result<Option<Account>, StateError> {
    match mpt::verify(state_root, &keccak256(address), proof)? {
        Some(value) => Ok(Some(Account::decode(value)?)),
        None => Ok(None),
    }
}

/// Decodes a storage leaf value: RLP of a non-zero integer of at most 32 bytes, left-padded.
pub fn decode_storage_value(value: &[u8]) -> Result<[u8; 32], StateError> {
    let v = rlp::decode_exact(value)?.uint_bytes(32)?;
    if v.is_empty() {
        return Err(StateError::ZeroStorageValue);
    }
    Ok(rlp::left_pad(v))
}

/// The leaf value encoding of a non-zero slot value (for builders and tests).
pub fn encode_storage_value(value: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    rlp::encode_uint(&mut out, value);
    out
}

/// Verifies a storage proof (an entry of `eth_getProof`'s `storageProof`) under an account's
/// storage root: the slot's value, zero when the proof shows the slot absent.
pub fn verify_storage<N: AsRef<[u8]>>(storage_root: &[u8; 32], slot: &[u8; 32], proof: &[N]) -> Result<[u8; 32], StateError> {
    match mpt::verify(storage_root, &keccak256(slot), proof)? {
        Some(value) => decode_storage_value(value),
        None => Ok([0; 32]),
    }
}

/// [`verify_account`] on authenticated inputs.
pub fn prove_account<N: AsRef<[u8]>>(
    state_root: &Authenticated<[u8; 32]>,
    address: &Authenticated<[u8; 20]>,
    proof: &[N],
) -> Result<Authenticated<Option<Account>>, StateError> {
    verify_account(state_root.get(), address.get(), proof).map(Authenticated::new)
}

/// [`verify_storage`] on authenticated inputs.
pub fn prove_storage<N: AsRef<[u8]>>(
    storage_root: &Authenticated<[u8; 32]>,
    slot: &Authenticated<[u8; 32]>,
    proof: &[N],
) -> Result<Authenticated<[u8; 32]>, StateError> {
    verify_storage(storage_root.get(), slot.get(), proof).map(Authenticated::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn account_round_trip_and_alloy() {
        let mut balance = [0u8; 32];
        balance[20] = 0x12;
        let a = Account { nonce: 9, balance, storage_root: [3; 32], code_hash: [4; 32] };
        let enc = a.encode();
        assert_eq!(Account::decode(&enc), Ok(a));
        let theirs = alloy_trie::TrieAccount::decode(&mut &enc[..]).unwrap();
        let mut re = Vec::new();
        theirs.encode(&mut re);
        assert_eq!(re, enc);
        assert_eq!(Account::decode(&Account::ABSENT.encode()), Ok(Account::ABSENT));
    }

    #[test]
    fn storage_values_are_strict() {
        let mut v = [0u8; 32];
        v[31] = 1;
        assert_eq!(decode_storage_value(&encode_storage_value(&v)), Ok(v));
        assert_eq!(encode_storage_value(&v), vec![0x01]);
        assert_eq!(decode_storage_value(&[0x80]), Err(StateError::ZeroStorageValue));
        assert_eq!(decode_storage_value(&[0x00]), Err(StateError::Rlp(RlpError::LeadingZeros)));
        assert_eq!(decode_storage_value(&[0x82, 0x00, 0x01]), Err(StateError::Rlp(RlpError::LeadingZeros)));
        let mut big = vec![0xa1];
        big.extend([1u8; 33]);
        assert_eq!(decode_storage_value(&big), Err(StateError::Rlp(RlpError::IntegerTooLarge)));
        assert_eq!(decode_storage_value(&[0xc1, 0x01]), Err(StateError::Rlp(RlpError::ExpectedString)));
    }

    #[test]
    fn extcodehash_semantics() {
        assert_eq!(extcodehash(&None), [0; 32]);
        assert_eq!(extcodehash(&Some(Account::ABSENT)), KECCAK_EMPTY);
        assert_eq!(storage_root(&None), EMPTY_ROOT);
    }
}
