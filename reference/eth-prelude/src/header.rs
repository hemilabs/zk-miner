//! Execution-layer block headers, London through Prague, on Ethereum and the OP Stack.
//!
//! A header is the RLP list of its fields in consensus order; each fork appended fields:
//!
//! | fields | fork | appended |
//! |---|---|---|
//! | 15 | Frontier … Berlin | `parentHash` … `nonce` |
//! | 16 | London | `baseFeePerGas` |
//! | 17 | Shanghai | `withdrawalsRoot` |
//! | 20 | Cancun | `blobGasUsed`, `excessBlobGas`, `parentBeaconBlockRoot` |
//! | 21 | Prague | `requestsHash` |
//!
//! OP Stack chains (Base, Hemi) use the same encoding: since Isthmus their headers have all 21
//! fields, with `withdrawalsRoot` holding the `L2ToL1MessagePasser` storage root, `requestsHash` the
//! hash of empty requests, and the EIP-1559 parameters in `extraData` (Holocene; Jovian adds the
//! minimum base fee and puts the DA footprint in `blobGasUsed`). None of that changes the encoding
//! or the hash.
//!
//! Any other field count is refused, so a fork that appends a field fails closed until a prelude
//! release knows it; the header's hash is all that authenticates it, and an unknown trailing field
//! would otherwise be a value no statement checks.

use alloc::vec::Vec;
use core::fmt;

use crate::keccak::keccak256;
use crate::rlp::{self, RlpError};

/// The header layouts this prelude knows, by the fork that introduced them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variant {
    /// 15 fields (Frontier through Berlin).
    Legacy,
    /// 16 fields: `baseFeePerGas`.
    London,
    /// 17 fields: `withdrawalsRoot`.
    Shanghai,
    /// 20 fields: `blobGasUsed`, `excessBlobGas`, `parentBeaconBlockRoot`.
    Cancun,
    /// 21 fields: `requestsHash`.
    Prague,
}

impl Variant {
    pub fn field_count(self) -> usize {
        match self {
            Self::Legacy => 15,
            Self::London => 16,
            Self::Shanghai => 17,
            Self::Cancun => 20,
            Self::Prague => 21,
        }
    }

    fn from_field_count(n: usize) -> Option<Self> {
        Some(match n {
            15 => Self::Legacy,
            16 => Self::London,
            17 => Self::Shanghai,
            20 => Self::Cancun,
            21 => Self::Prague,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    Rlp(RlpError),
    /// A field count no known fork uses (18, 19, more than 21, fewer than 15).
    UnknownLayout(usize),
    /// Optional fields that do not form one fork's suffix (say `withdrawalsRoot` without
    /// `baseFeePerGas`), so no encoding exists.
    InconsistentFields,
    /// The header does not hash to the hash it must have.
    HashMismatch,
    /// A parent header whose number is not the child's minus one.
    NotParent,
}

impl From<RlpError> for HeaderError {
    fn from(e: RlpError) -> Self {
        Self::Rlp(e)
    }
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rlp(e) => write!(f, "header: {e}"),
            Self::UnknownLayout(n) => write!(f, "header: {n} fields is no known fork's layout"),
            Self::InconsistentFields => f.write_str("header: optional fields are not one fork's suffix"),
            Self::HashMismatch => f.write_str("header: does not hash to the expected block hash"),
            Self::NotParent => f.write_str("header: not the parent of the header before it"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HeaderError {}

/// A decoded header. Integers that consensus bounds to 64 bits (`number`, `gasLimit`, `gasUsed`,
/// `timestamp`, the blob gas fields) are `u64`; `difficulty` and `baseFeePerGas` are 256-bit, as
/// big-endian bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub parent_hash: [u8; 32],
    pub ommers_hash: [u8; 32],
    pub beneficiary: [u8; 20],
    pub state_root: [u8; 32],
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: [u8; 256],
    pub difficulty: [u8; 32],
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: [u8; 32],
    pub nonce: [u8; 8],
    pub base_fee_per_gas: Option<[u8; 32]>,
    pub withdrawals_root: Option<[u8; 32]>,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub parent_beacon_block_root: Option<[u8; 32]>,
    pub requests_hash: Option<[u8; 32]>,
}

impl Header {
    /// Strictly decodes an RLP header: canonical RLP, a known layout, every field of its exact
    /// size, nothing after the list.
    pub fn decode(rlp_bytes: &[u8]) -> Result<Self, HeaderError> {
        let item = rlp::decode_exact(rlp_bytes)?;
        let fields = item.to_vec()?;
        let variant = Variant::from_field_count(fields.len()).ok_or(HeaderError::UnknownLayout(fields.len()))?;
        let f = &fields;
        let at_least = |v: Variant| variant >= v;
        Ok(Self {
            parent_hash: f[0].fixed()?,
            ommers_hash: f[1].fixed()?,
            beneficiary: f[2].fixed()?,
            state_root: f[3].fixed()?,
            transactions_root: f[4].fixed()?,
            receipts_root: f[5].fixed()?,
            logs_bloom: f[6].fixed()?,
            difficulty: f[7].u256()?,
            number: f[8].u64()?,
            gas_limit: f[9].u64()?,
            gas_used: f[10].u64()?,
            timestamp: f[11].u64()?,
            extra_data: f[12].bytes()?.to_vec(),
            mix_hash: f[13].fixed()?,
            nonce: f[14].fixed()?,
            base_fee_per_gas: if at_least(Variant::London) { Some(f[15].u256()?) } else { None },
            withdrawals_root: if at_least(Variant::Shanghai) { Some(f[16].fixed()?) } else { None },
            blob_gas_used: if at_least(Variant::Cancun) { Some(f[17].u64()?) } else { None },
            excess_blob_gas: if at_least(Variant::Cancun) { Some(f[18].u64()?) } else { None },
            parent_beacon_block_root: if at_least(Variant::Cancun) { Some(f[19].fixed()?) } else { None },
            requests_hash: if at_least(Variant::Prague) { Some(f[20].fixed()?) } else { None },
        })
    }

    /// The layout, from which optional fields are present; `None` when they are not one fork's
    /// suffix.
    pub fn variant(&self) -> Option<Variant> {
        let cancun = [self.blob_gas_used.is_some(), self.excess_blob_gas.is_some(), self.parent_beacon_block_root.is_some()];
        let cancun = match cancun {
            [true, true, true] => true,
            [false, false, false] => false,
            _ => return None,
        };
        let present = [self.base_fee_per_gas.is_some(), self.withdrawals_root.is_some(), cancun, self.requests_hash.is_some()];
        let n = present.iter().take_while(|&&p| p).count();
        if present[n..].iter().any(|&p| p) {
            return None;
        }
        Some([Variant::Legacy, Variant::London, Variant::Shanghai, Variant::Cancun, Variant::Prague][n])
    }

    /// The canonical RLP encoding, whose keccak is the block hash.
    pub fn encode(&self) -> Result<Vec<u8>, HeaderError> {
        let variant = self.variant().ok_or(HeaderError::InconsistentFields)?;
        let mut p = Vec::with_capacity(640);
        rlp::encode_bytes(&mut p, &self.parent_hash);
        rlp::encode_bytes(&mut p, &self.ommers_hash);
        rlp::encode_bytes(&mut p, &self.beneficiary);
        rlp::encode_bytes(&mut p, &self.state_root);
        rlp::encode_bytes(&mut p, &self.transactions_root);
        rlp::encode_bytes(&mut p, &self.receipts_root);
        rlp::encode_bytes(&mut p, &self.logs_bloom);
        rlp::encode_uint(&mut p, &self.difficulty);
        rlp::encode_u64(&mut p, self.number);
        rlp::encode_u64(&mut p, self.gas_limit);
        rlp::encode_u64(&mut p, self.gas_used);
        rlp::encode_u64(&mut p, self.timestamp);
        rlp::encode_bytes(&mut p, &self.extra_data);
        rlp::encode_bytes(&mut p, &self.mix_hash);
        rlp::encode_bytes(&mut p, &self.nonce);
        if let Some(v) = &self.base_fee_per_gas {
            rlp::encode_uint(&mut p, v);
        }
        if let Some(v) = &self.withdrawals_root {
            rlp::encode_bytes(&mut p, v);
        }
        if variant >= Variant::Cancun {
            rlp::encode_u64(&mut p, self.blob_gas_used.unwrap_or_default());
            rlp::encode_u64(&mut p, self.excess_blob_gas.unwrap_or_default());
            rlp::encode_bytes(&mut p, &self.parent_beacon_block_root.unwrap_or_default());
        }
        if let Some(v) = &self.requests_hash {
            rlp::encode_bytes(&mut p, v);
        }
        let mut out = Vec::with_capacity(p.len() + 3);
        rlp::encode_list(&mut out, &p);
        Ok(out)
    }
}

/// Decodes `rlp_bytes` and checks that it hashes to `expected`: the only thing that authenticates
/// a header. The hash is taken over the bytes given, and decoding is canonical, so the decoded
/// fields are the ones `expected` commits to.
pub fn decode_with_hash(rlp_bytes: &[u8], expected: &[u8; 32]) -> Result<Header, HeaderError> {
    if keccak256(rlp_bytes) != *expected {
        return Err(HeaderError::HashMismatch);
    }
    Header::decode(rlp_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(variant: Variant) -> Header {
        let mut h = Header {
            parent_hash: [1; 32],
            ommers_hash: crate::keccak::EMPTY_OMMERS_HASH,
            beneficiary: [2; 20],
            state_root: [3; 32],
            transactions_root: [4; 32],
            receipts_root: [5; 32],
            logs_bloom: [0; 256],
            difficulty: [0; 32],
            number: 0x1234,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 1_700_000_000,
            extra_data: b"extra".to_vec(),
            mix_hash: [6; 32],
            nonce: [0; 8],
            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        };
        if variant >= Variant::London {
            let mut fee = [0; 32];
            fee[31] = 7;
            h.base_fee_per_gas = Some(fee);
        }
        if variant >= Variant::Shanghai {
            h.withdrawals_root = Some(crate::keccak::EMPTY_ROOT);
        }
        if variant >= Variant::Cancun {
            h.blob_gas_used = Some(0);
            h.excess_blob_gas = Some(131_072);
            h.parent_beacon_block_root = Some([9; 32]);
        }
        if variant >= Variant::Prague {
            h.requests_hash = Some([10; 32]);
        }
        h
    }

    #[test]
    fn every_variant_round_trips_and_matches_alloy() {
        use alloy_rlp::Decodable;
        for v in [Variant::Legacy, Variant::London, Variant::Shanghai, Variant::Cancun, Variant::Prague] {
            let h = sample(v);
            assert_eq!(h.variant(), Some(v));
            let enc = h.encode().unwrap();
            assert_eq!(Header::decode(&enc).unwrap(), h);
            assert_eq!(rlp::decode_exact(&enc).unwrap().to_vec().unwrap().len(), v.field_count());
            let theirs = alloy_consensus::Header::decode(&mut &enc[..]).unwrap();
            assert_eq!(theirs.hash_slow().0, keccak256(&enc), "{v:?}");
            assert_eq!(theirs.number, h.number);
            assert_eq!(decode_with_hash(&enc, &keccak256(&enc)).unwrap(), h);
            let mut wrong = keccak256(&enc);
            wrong[0] ^= 1;
            assert_eq!(decode_with_hash(&enc, &wrong), Err(HeaderError::HashMismatch));
        }
    }

    #[test]
    fn inconsistent_and_unknown_layouts_are_refused() {
        let mut h = sample(Variant::Prague);
        h.excess_blob_gas = None;
        assert_eq!(h.encode(), Err(HeaderError::InconsistentFields));
        let mut h = sample(Variant::Legacy);
        h.withdrawals_root = Some([0; 32]);
        assert_eq!(h.encode(), Err(HeaderError::InconsistentFields));
        // 18 and 22 fields.
        let enc = sample(Variant::Shanghai).encode().unwrap();
        let item = rlp::decode_exact(&enc).unwrap();
        for extra in [1usize, 5] {
            let mut payload: Vec<u8> = item.to_vec().unwrap().iter().flat_map(|i| i.raw().to_vec()).collect();
            if extra == 5 {
                let p = sample(Variant::Prague).encode().unwrap();
                payload = rlp::decode_exact(&p).unwrap().to_vec().unwrap().iter().flat_map(|i| i.raw().to_vec()).collect();
            }
            payload.push(0x80);
            let mut out = Vec::new();
            rlp::encode_list(&mut out, &payload);
            let n = rlp::decode_exact(&out).unwrap().to_vec().unwrap().len();
            assert_eq!(Header::decode(&out), Err(HeaderError::UnknownLayout(n)));
        }
    }

    #[test]
    fn fields_have_exact_sizes() {
        let h = sample(Variant::Prague);
        let enc = h.encode().unwrap();
        let fields = rlp::decode_exact(&enc).unwrap().to_vec().unwrap();
        // A 19-byte beneficiary.
        let mut payload = Vec::new();
        for (i, f) in fields.iter().enumerate() {
            if i == 2 {
                rlp::encode_bytes(&mut payload, &[2; 19]);
            } else {
                payload.extend_from_slice(f.raw());
            }
        }
        let mut out = Vec::new();
        rlp::encode_list(&mut out, &payload);
        assert_eq!(Header::decode(&out), Err(HeaderError::Rlp(RlpError::WrongLength)));
    }
}
