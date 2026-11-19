//! Transactions and the transactions trie (plan §8.4).
//!
//! The transactions trie maps `rlp(txIndex)` to the transaction's EIP-2718 encoding, and
//! `keccak256` of that encoding is the transaction hash. [`Transaction::decode`] checks the
//! structure of every type a Base, Hemi or Ethereum block carries (legacy, 0x01, 0x02, 0x03, 0x04
//! and the OP Stack deposit 0x7E) and exposes the fields a statement about calldata needs.
//!
//! **Not here yet: sender recovery.** A statement that names the sender of a signed transaction
//! must recover it from the signature under the pinned chain id (per type: the EIP-155 or typed
//! signing hash, low-s, `yParity` 0 or 1), which needs secp256k1 in the guest. Until the prelude
//! has it, use only deposits' `from` (set by L1 derivation, not by a signature) or statements that
//! do not depend on the sender.

use alloc::vec::Vec;
use core::fmt;

use crate::guard::Authenticated;
use crate::keccak::keccak256;
use crate::mpt::{self, ProofError};
use crate::receipt::{split_typed, TYPE_ACCESS_LIST, TYPE_BLOB, TYPE_DEPOSIT, TYPE_DYNAMIC_FEE, TYPE_LEGACY, TYPE_SET_CODE};
use crate::rlp::{self, Item, RlpError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    Rlp(RlpError),
    Proof(ProofError),
    UnknownType(u8),
    /// A legacy `v` that is neither 27/28 nor an EIP-155 value.
    BadV,
    /// A `yParity` other than 0 or 1.
    BadParity,
    /// A blob or set-code transaction without a recipient, or without blobs / authorizations.
    MissingField,
    /// A chain id beyond 64 bits.
    ChainIdTooLarge,
}

impl From<RlpError> for TxError {
    fn from(e: RlpError) -> Self {
        Self::Rlp(e)
    }
}

impl From<ProofError> for TxError {
    fn from(e: ProofError) -> Self {
        Self::Proof(e)
    }
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rlp(e) => write!(f, "transaction: {e}"),
            Self::Proof(e) => e.fmt(f),
            Self::UnknownType(t) => write!(f, "transaction: unknown type {t:#04x}"),
            Self::BadV => f.write_str("transaction: legacy v is neither 27/28 nor EIP-155"),
            Self::BadParity => f.write_str("transaction: yParity is neither 0 nor 1"),
            Self::MissingField => f.write_str("transaction: required recipient, blobs or authorizations missing"),
            Self::ChainIdTooLarge => f.write_str("transaction: chain id beyond 64 bits"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TxError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    /// `yParity` (typed) or `(v − 27)` / `(v − 35) mod 2` (legacy).
    pub y_parity: bool,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

crate::guard::plain_data!(struct Signature { y_parity, r, s });

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub tx_type: u8,
    /// `None` for pre-EIP-155 legacy transactions and for deposits.
    pub chain_id: Option<u64>,
    /// `None` for deposits.
    pub nonce: Option<u64>,
    pub gas_limit: u64,
    /// `None` for a contract creation.
    pub to: Option<[u8; 20]>,
    pub value: [u8; 32],
    pub input: Vec<u8>,
    /// Signed transactions only.
    pub signature: Option<Signature>,
    /// Deposits only: the sender L1 derivation set (no signature).
    pub deposit_from: Option<[u8; 20]>,
    /// Deposits only.
    pub source_hash: Option<[u8; 32]>,
    /// Deposits only: ETH minted on L2.
    pub mint: Option<[u8; 32]>,
    /// Deposits only.
    pub is_system_tx: Option<bool>,
}

crate::guard::plain_data!(struct Transaction {
    tx_type, chain_id, nonce, gas_limit, to, value, input, signature, deposit_from, source_hash, mint, is_system_tx,
});

fn chain_id(item: &Item<'_>) -> Result<u64, TxError> {
    let b = item.uint_bytes(32)?;
    if b.len() > 8 {
        return Err(TxError::ChainIdTooLarge);
    }
    Ok(b.iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x)))
}

fn to(item: &Item<'_>, required: bool) -> Result<Option<[u8; 20]>, TxError> {
    match item.bytes()? {
        [] if !required => Ok(None),
        [] => Err(TxError::MissingField),
        _ => Ok(Some(item.fixed()?)),
    }
}

fn parity(item: &Item<'_>) -> Result<bool, TxError> {
    match item.u64()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(TxError::BadParity),
    }
}

fn signature(y: &Item<'_>, r: &Item<'_>, s: &Item<'_>) -> Result<Signature, TxError> {
    Ok(Signature { y_parity: parity(y)?, r: r.u256()?, s: s.u256()? })
}

/// `[[address, [storageKey, …]], …]`, every address 20 bytes and every key 32.
fn access_list(item: &Item<'_>) -> Result<(), TxError> {
    for entry in item.to_vec()? {
        let [address, keys] = entry.items::<2>()?;
        address.fixed::<20>()?;
        for k in keys.to_vec()? {
            k.fixed::<32>()?;
        }
    }
    Ok(())
}

/// `[[chainId, address, nonce, yParity, r, s], …]`, non-empty.
fn authorization_list(item: &Item<'_>) -> Result<(), TxError> {
    let auths = item.to_vec()?;
    if auths.is_empty() {
        return Err(TxError::MissingField);
    }
    for a in auths {
        let [chain, address, nonce, y, r, s] = a.items::<6>()?;
        chain.u256()?;
        address.fixed::<20>()?;
        nonce.u64()?;
        y.u64()?; // an authority's parity is checked at recovery; any u8 encodes
        r.u256()?;
        s.u256()?;
    }
    Ok(())
}

impl Transaction {
    /// Strictly decodes a transaction's EIP-2718 encoding (a transactions-trie leaf value).
    pub fn decode(bytes: &[u8]) -> Result<Self, TxError> {
        let first = *bytes.first().ok_or(RlpError::Truncated)?;
        if first < 0xc0 && !matches!(first, TYPE_ACCESS_LIST | TYPE_DYNAMIC_FEE | TYPE_BLOB | TYPE_SET_CODE | TYPE_DEPOSIT) {
            return Err(TxError::UnknownType(first));
        }
        let (tx_type, payload) = split_typed(bytes)?;
        let f = payload.to_vec()?;
        let count = |n: usize| if f.len() == n { Ok(()) } else { Err(TxError::Rlp(RlpError::WrongCount)) };
        let signed = |chain: Option<u64>, nonce: &Item<'_>, gas: &Item<'_>, to_: Option<[u8; 20]>, value: &Item<'_>, input: &Item<'_>, sig| {
            Ok::<_, TxError>(Self {
                tx_type,
                chain_id: chain,
                nonce: Some(nonce.u64()?),
                gas_limit: gas.u64()?,
                to: to_,
                value: value.u256()?,
                input: input.bytes()?.to_vec(),
                signature: Some(sig),
                deposit_from: None,
                source_hash: None,
                mint: None,
                is_system_tx: None,
            })
        };
        match tx_type {
            TYPE_LEGACY => {
                // [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
                count(9)?;
                f[1].u256()?;
                let v = f[6].u64()?;
                let (chain, y) = match v {
                    27 | 28 => (None, v == 28),
                    v if v >= 35 => (Some((v - 35) / 2), (v - 35) % 2 == 1),
                    _ => return Err(TxError::BadV),
                };
                let sig = Signature { y_parity: y, r: f[7].u256()?, s: f[8].u256()? };
                signed(chain, &f[0], &f[2], to(&f[3], false)?, &f[4], &f[5], sig)
            }
            TYPE_ACCESS_LIST => {
                // [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yParity, r, s]
                count(11)?;
                f[2].u256()?;
                access_list(&f[7])?;
                signed(Some(chain_id(&f[0])?), &f[1], &f[3], to(&f[4], false)?, &f[5], &f[6], signature(&f[8], &f[9], &f[10])?)
            }
            TYPE_DYNAMIC_FEE => {
                // [chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList, yParity, r, s]
                count(12)?;
                f[2].u256()?;
                f[3].u256()?;
                access_list(&f[8])?;
                signed(Some(chain_id(&f[0])?), &f[1], &f[4], to(&f[5], false)?, &f[6], &f[7], signature(&f[9], &f[10], &f[11])?)
            }
            TYPE_BLOB => {
                // [chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList,
                //  maxFeePerBlobGas, blobVersionedHashes, yParity, r, s]
                count(14)?;
                f[2].u256()?;
                f[3].u256()?;
                access_list(&f[8])?;
                f[9].u256()?;
                let blobs = f[10].to_vec()?;
                if blobs.is_empty() {
                    return Err(TxError::MissingField);
                }
                for b in blobs {
                    b.fixed::<32>()?;
                }
                signed(Some(chain_id(&f[0])?), &f[1], &f[4], to(&f[5], true)?, &f[6], &f[7], signature(&f[11], &f[12], &f[13])?)
            }
            TYPE_SET_CODE => {
                // [chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList,
                //  authorizationList, yParity, r, s]
                count(13)?;
                f[2].u256()?;
                f[3].u256()?;
                access_list(&f[8])?;
                authorization_list(&f[9])?;
                signed(Some(chain_id(&f[0])?), &f[1], &f[4], to(&f[5], true)?, &f[6], &f[7], signature(&f[10], &f[11], &f[12])?)
            }
            TYPE_DEPOSIT => {
                // [sourceHash, from, to, mint, value, gas, isSystemTx, data]
                count(8)?;
                Ok(Self {
                    tx_type,
                    chain_id: None,
                    nonce: None,
                    gas_limit: f[5].u64()?,
                    to: to(&f[2], false)?,
                    value: f[4].u256()?,
                    input: f[7].bytes()?.to_vec(),
                    signature: None,
                    deposit_from: Some(f[1].fixed()?),
                    source_hash: Some(f[0].fixed()?),
                    mint: Some(f[3].u256()?),
                    is_system_tx: Some(f[6].bool()?),
                })
            }
            t => Err(TxError::UnknownType(t)),
        }
    }
}

/// A transaction from a trie proof, with its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashedTransaction {
    pub tx: Transaction,
    /// `keccak256` of the EIP-2718 encoding.
    pub hash: [u8; 32],
}

crate::guard::plain_data!(struct HashedTransaction { tx, hash });

/// The transaction hash: `keccak256` of the EIP-2718 encoding.
pub fn tx_hash(encoded: &[u8]) -> [u8; 32] {
    keccak256(encoded)
}

/// Verifies a transactions-trie proof for `index` under `transactions_root`: the transaction and
/// its hash, or `None` when the proof shows no transaction at that index.
pub fn verify_transaction<N: AsRef<[u8]>>(
    transactions_root: &[u8; 32],
    index: u64,
    proof: &[N],
) -> Result<Option<HashedTransaction>, TxError> {
    match mpt::verify(transactions_root, &rlp::index_key(index), proof)? {
        Some(value) => Ok(Some(HashedTransaction { tx: Transaction::decode(value)?, hash: tx_hash(value) })),
        None => Ok(None),
    }
}

/// [`verify_transaction`] on authenticated inputs.
pub fn prove_transaction<N: AsRef<[u8]>>(
    transactions_root: &Authenticated<[u8; 32]>,
    index: &Authenticated<u64>,
    proof: &[N],
) -> Result<Authenticated<Option<HashedTransaction>>, TxError> {
    verify_transaction(transactions_root.get(), *index.get(), proof).map(Authenticated::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxEnvelope, TxLegacy};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_eips::eip2930::{AccessList, AccessListItem};
    use alloy_eips::eip7702::{Authorization, SignedAuthorization};
    use alloy_primitives::{Address, Bytes, Signature as ASig, TxKind, B256, U256};

    fn sig() -> ASig {
        ASig::new(U256::from(11u64), U256::from(22u64), true)
    }

    fn al() -> AccessList {
        AccessList(vec![AccessListItem { address: Address::repeat_byte(9), storage_keys: vec![B256::repeat_byte(8)] }])
    }

    #[test]
    fn every_signed_type_matches_alloy() {
        let to = Address::repeat_byte(0x42);
        let input = Bytes::from(vec![1, 2, 3]);
        let envelopes: Vec<TxEnvelope> = vec![
            TxLegacy { chain_id: Some(8453), nonce: 1, gas_price: 2, gas_limit: 21_000, to: TxKind::Call(to), value: U256::from(5u64), input: input.clone() }
                .into_signed(sig())
                .into(),
            TxLegacy { chain_id: None, nonce: 1, gas_price: 2, gas_limit: 21_000, to: TxKind::Create, value: U256::ZERO, input: input.clone() }
                .into_signed(sig())
                .into(),
            TxEip2930 { chain_id: 1, nonce: 2, gas_price: 3, gas_limit: 50_000, to: TxKind::Call(to), value: U256::from(1u64), input: input.clone(), access_list: al() }
                .into_signed(sig())
                .into(),
            TxEip1559 {
                chain_id: 43111,
                nonce: 3,
                gas_limit: 60_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 1,
                to: TxKind::Call(to),
                value: U256::from(7u64),
                access_list: al(),
                input: input.clone(),
            }
            .into_signed(sig())
            .into(),
            TxEnvelope::Eip4844(
                TxEip4844 {
                    chain_id: 1,
                    nonce: 4,
                    gas_limit: 70_000,
                    max_fee_per_gas: 10,
                    max_priority_fee_per_gas: 1,
                    to,
                    value: U256::ZERO,
                    access_list: AccessList::default(),
                    blob_versioned_hashes: vec![B256::repeat_byte(1)],
                    max_fee_per_blob_gas: 3,
                    input: input.clone(),
                }
                .into_signed(sig())
                .into(),
            ),
            TxEip7702 {
                chain_id: 8453,
                nonce: 5,
                gas_limit: 80_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 1,
                to,
                value: U256::ZERO,
                access_list: AccessList::default(),
                authorization_list: vec![SignedAuthorization::new_unchecked(
                    Authorization { chain_id: U256::from(8453u64), address: to, nonce: 9 },
                    1,
                    U256::from(3u64),
                    U256::from(4u64),
                )],
                input: input.clone(),
            }
            .into_signed(sig())
            .into(),
        ];
        for env in envelopes {
            let enc = env.encoded_2718();
            let tx = Transaction::decode(&enc).unwrap_or_else(|e| panic!("{:?}: {e}", env.tx_type()));
            assert_eq!(tx.tx_type, env.tx_type() as u8);
            assert_eq!(tx_hash(&enc), env.tx_hash().0);
            assert_eq!(tx.input, input.to_vec());
            assert_eq!(tx.gas_limit, alloy_consensus::Transaction::gas_limit(&env));
            assert_eq!(tx.chain_id, alloy_consensus::Transaction::chain_id(&env));
            assert_eq!(tx.to.map(Address::from), alloy_consensus::Transaction::to(&env));
            let s = tx.signature.unwrap();
            assert!(s.y_parity);
            assert_eq!(U256::from_be_bytes(s.r), U256::from(11u64));
        }
    }

    #[test]
    fn malformed_transactions_are_refused() {
        // A blob transaction without blobs is unencodable by alloy; build it by hand.
        let mut p = Vec::new();
        for _ in 0..5 {
            rlp::encode_u64(&mut p, 1);
        }
        rlp::encode_bytes(&mut p, &[0x42; 20]);
        rlp::encode_u64(&mut p, 0);
        rlp::encode_bytes(&mut p, &[]);
        rlp::encode_list(&mut p, &[]);
        rlp::encode_u64(&mut p, 1);
        rlp::encode_list(&mut p, &[]); // no blobs
        rlp::encode_u64(&mut p, 1);
        rlp::encode_u64(&mut p, 1);
        rlp::encode_u64(&mut p, 1);
        let mut enc = vec![TYPE_BLOB];
        rlp::encode_list(&mut enc, &p);
        assert_eq!(Transaction::decode(&enc), Err(TxError::MissingField));
        assert_eq!(Transaction::decode(&[0x05, 0xc0]), Err(TxError::UnknownType(5)));
        // Legacy v = 30.
        let mut p = Vec::new();
        for _ in 0..3 {
            rlp::encode_u64(&mut p, 1);
        }
        rlp::encode_bytes(&mut p, &[]);
        rlp::encode_u64(&mut p, 0);
        rlp::encode_bytes(&mut p, &[]);
        rlp::encode_u64(&mut p, 30);
        rlp::encode_u64(&mut p, 1);
        rlp::encode_u64(&mut p, 1);
        let mut enc = Vec::new();
        rlp::encode_list(&mut enc, &p);
        assert_eq!(Transaction::decode(&enc), Err(TxError::BadV));
    }
}
