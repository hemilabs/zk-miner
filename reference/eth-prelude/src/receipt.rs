//! Receipts and the receipts trie (plan §8.4, "Receipts and transactions").
//!
//! The receipts trie maps `rlp(txIndex)` to the receipt's EIP-2718 encoding: `type ‖ rlp(payload)`
//! for typed transactions (0x01 access list, 0x02 dynamic fee, 0x03 blob, 0x04 set-code, and the OP
//! Stack deposit type 0x7E), the bare `rlp(payload)` list for legacy ones. The payload is
//! `[status, cumulativeGasUsed, logsBloom, logs]`; a deposit receipt appends `depositNonce`
//! (Regolith) and `depositReceiptVersion` (Canyon). Before Byzantium the first field was a 32-byte
//! post-state root.
//!
//! A log's position is `(txIndex, logIndexInReceipt)`: a block-level log index needs every earlier
//! receipt of the block. Linking a log to its sender or calldata takes a transaction-trie proof at
//! the same index ([`crate::tx`]).

use alloc::vec::Vec;
use core::fmt;

use crate::guard::Authenticated;
use crate::keccak::keccak256;
use crate::mpt::{self, ProofError};
use crate::rlp::{self, Item, RlpError};

pub const TYPE_LEGACY: u8 = 0x00;
pub const TYPE_ACCESS_LIST: u8 = 0x01;
pub const TYPE_DYNAMIC_FEE: u8 = 0x02;
pub const TYPE_BLOB: u8 = 0x03;
pub const TYPE_SET_CODE: u8 = 0x04;
/// The OP Stack deposit transaction type.
pub const TYPE_DEPOSIT: u8 = 0x7e;

/// A log may carry at most four topics (`LOG0` … `LOG4`).
pub const MAX_TOPICS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptError {
    Rlp(RlpError),
    Proof(ProofError),
    /// A first byte that is neither a known type nor the start of a legacy list.
    UnknownType(u8),
    /// A status that is neither 0, 1 nor a 32-byte post-state root.
    BadStatus,
    /// A log with more than four topics.
    TooManyTopics,
    /// Deposit fields on a non-deposit receipt, or a receipt version without a deposit nonce.
    BadDepositFields,
    /// A legacy receipt with a type byte, or an empty encoding.
    Empty,
}

impl From<RlpError> for ReceiptError {
    fn from(e: RlpError) -> Self {
        Self::Rlp(e)
    }
}

impl From<ProofError> for ReceiptError {
    fn from(e: ProofError) -> Self {
        Self::Proof(e)
    }
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rlp(e) => write!(f, "receipt: {e}"),
            Self::Proof(e) => e.fmt(f),
            Self::UnknownType(t) => write!(f, "receipt: unknown type {t:#04x}"),
            Self::BadStatus => f.write_str("receipt: status is neither 0, 1 nor a post-state root"),
            Self::TooManyTopics => f.write_str("receipt: log with more than four topics"),
            Self::BadDepositFields => f.write_str("receipt: deposit fields out of place"),
            Self::Empty => f.write_str("receipt: empty encoding"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ReceiptError {}

/// The first field of a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Byzantium and later: success or failure.
    Status(bool),
    /// Before Byzantium: the post-transaction state root.
    PostState([u8; 32]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub tx_type: u8,
    pub outcome: Outcome,
    pub cumulative_gas_used: u64,
    pub logs_bloom: [u8; 256],
    pub logs: Vec<Log>,
    /// Deposit receipts from Regolith.
    pub deposit_nonce: Option<u64>,
    /// Deposit receipts from Canyon.
    pub deposit_receipt_version: Option<u64>,
}

fn is_known_type(t: u8) -> bool {
    matches!(t, TYPE_ACCESS_LIST | TYPE_DYNAMIC_FEE | TYPE_BLOB | TYPE_SET_CODE | TYPE_DEPOSIT)
}

/// Splits an EIP-2718 encoding into its type (0 for legacy) and the RLP payload list.
pub(crate) fn split_typed(bytes: &[u8]) -> Result<(u8, Item<'_>), RlpError> {
    match bytes.first() {
        None => Err(RlpError::Truncated),
        Some(&b) if b >= 0xc0 => Ok((TYPE_LEGACY, rlp::decode_exact(bytes)?)),
        Some(&b) => Ok((b, rlp::decode_exact(&bytes[1..])?)),
    }
}

fn decode_log(item: &Item<'_>) -> Result<Log, ReceiptError> {
    let [address, topics, data] = item.items::<3>()?;
    let topics = topics.to_vec()?;
    if topics.len() > MAX_TOPICS {
        return Err(ReceiptError::TooManyTopics);
    }
    Ok(Log {
        address: address.fixed()?,
        topics: topics.iter().map(|t| t.fixed()).collect::<Result<_, _>>()?,
        data: data.bytes()?.to_vec(),
    })
}

impl Receipt {
    /// Strictly decodes a receipt's EIP-2718 encoding (a receipts-trie leaf value).
    pub fn decode(bytes: &[u8]) -> Result<Self, ReceiptError> {
        let first = *bytes.first().ok_or(ReceiptError::Empty)?;
        if first < 0xc0 && !is_known_type(first) {
            return Err(ReceiptError::UnknownType(first));
        }
        let (tx_type, payload) = split_typed(bytes)?;
        let fields = payload.to_vec()?;
        let deposit = tx_type == TYPE_DEPOSIT;
        let n = fields.len();
        if !(n == 4 || (deposit && (n == 5 || n == 6))) {
            return Err(if n > 4 { ReceiptError::BadDepositFields } else { ReceiptError::Rlp(RlpError::WrongCount) });
        }
        let outcome = match fields[0].bytes()? {
            [] => Outcome::Status(false),
            [1] => Outcome::Status(true),
            root if root.len() == 32 => Outcome::PostState(root.try_into().expect("32 bytes")),
            _ => return Err(ReceiptError::BadStatus),
        };
        let logs = fields[3].to_vec()?.iter().map(decode_log).collect::<Result<_, _>>()?;
        Ok(Self {
            tx_type,
            outcome,
            cumulative_gas_used: fields[1].u64()?,
            logs_bloom: fields[2].fixed()?,
            logs,
            deposit_nonce: if n >= 5 { Some(fields[4].u64()?) } else { None },
            deposit_receipt_version: if n == 6 { Some(fields[5].u64()?) } else { None },
        })
    }

    /// The canonical EIP-2718 encoding (what builders put in a receipts trie).
    pub fn encode(&self) -> Result<Vec<u8>, ReceiptError> {
        let deposit = self.tx_type == TYPE_DEPOSIT;
        if self.tx_type != TYPE_LEGACY && !is_known_type(self.tx_type) {
            return Err(ReceiptError::UnknownType(self.tx_type));
        }
        if (!deposit && (self.deposit_nonce.is_some() || self.deposit_receipt_version.is_some()))
            || (self.deposit_receipt_version.is_some() && self.deposit_nonce.is_none())
        {
            return Err(ReceiptError::BadDepositFields);
        }
        let mut p = Vec::new();
        match self.outcome {
            Outcome::Status(s) => rlp::encode_bool(&mut p, s),
            Outcome::PostState(root) => rlp::encode_bytes(&mut p, &root),
        }
        rlp::encode_u64(&mut p, self.cumulative_gas_used);
        rlp::encode_bytes(&mut p, &self.logs_bloom);
        let mut logs = Vec::new();
        for log in &self.logs {
            if log.topics.len() > MAX_TOPICS {
                return Err(ReceiptError::TooManyTopics);
            }
            let mut l = Vec::new();
            rlp::encode_bytes(&mut l, &log.address);
            let mut topics = Vec::new();
            for t in &log.topics {
                rlp::encode_bytes(&mut topics, t);
            }
            rlp::encode_list(&mut l, &topics);
            rlp::encode_bytes(&mut l, &log.data);
            rlp::encode_list(&mut logs, &l);
        }
        rlp::encode_list(&mut p, &logs);
        if let Some(n) = self.deposit_nonce {
            rlp::encode_u64(&mut p, n);
        }
        if let Some(v) = self.deposit_receipt_version {
            rlp::encode_u64(&mut p, v);
        }
        let mut out = Vec::with_capacity(p.len() + 4);
        if self.tx_type != TYPE_LEGACY {
            out.push(self.tx_type);
        }
        rlp::encode_list(&mut out, &p);
        Ok(out)
    }

    /// Whether `logs_bloom` is the bloom of `logs`, as consensus requires. A receipt from a verified
    /// trie proof always passes; the check is for builders and for statements about absence.
    pub fn bloom_matches(&self) -> bool {
        logs_bloom(&self.logs) == self.logs_bloom
    }
}

/// The 2048-bit bloom of `logs`: three bits per address and per topic, from their keccak.
pub fn logs_bloom(logs: &[Log]) -> [u8; 256] {
    let mut bloom = [0u8; 256];
    let mut add = |data: &[u8]| {
        let h = keccak256(data);
        for i in [0, 2, 4] {
            let bit = (usize::from(h[i]) << 8 | usize::from(h[i + 1])) & 2047;
            bloom[255 - bit / 8] |= 1 << (bit % 8);
        }
    };
    for log in logs {
        add(&log.address);
        for t in &log.topics {
            add(t);
        }
    }
    bloom
}

/// Verifies a receipts-trie proof for transaction `index` under `receipts_root`: the receipt, or
/// `None` when the proof shows no transaction at that index.
pub fn verify_receipt<N: AsRef<[u8]>>(receipts_root: &[u8; 32], index: u64, proof: &[N]) -> Result<Option<Receipt>, ReceiptError> {
    match mpt::verify(receipts_root, &rlp::index_key(index), proof)? {
        Some(value) => Ok(Some(Receipt::decode(value)?)),
        None => Ok(None),
    }
}

/// [`verify_receipt`] on authenticated inputs.
pub fn prove_receipt<N: AsRef<[u8]>>(
    receipts_root: &Authenticated<[u8; 32]>,
    index: &Authenticated<u64>,
    proof: &[N],
) -> Result<Authenticated<Option<Receipt>>, ReceiptError> {
    verify_receipt(receipts_root.get(), *index.get(), proof).map(Authenticated::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_consensus::{Eip658Value, Receipt as AReceipt, ReceiptEnvelope, ReceiptWithBloom};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{Address, Bytes, Log as ALog, LogData, B256};

    fn sample(tx_type: u8) -> Receipt {
        let logs = vec![
            Log { address: [1; 20], topics: vec![[2; 32], [3; 32]], data: vec![4; 40] },
            Log { address: [5; 20], topics: vec![], data: vec![] },
        ];
        Receipt {
            tx_type,
            outcome: Outcome::Status(tx_type != TYPE_ACCESS_LIST),
            cumulative_gas_used: 123_456,
            logs_bloom: logs_bloom(&logs),
            logs,
            deposit_nonce: (tx_type == TYPE_DEPOSIT).then_some(77),
            deposit_receipt_version: (tx_type == TYPE_DEPOSIT).then_some(1),
        }
    }

    #[test]
    fn typed_receipts_match_alloy() {
        for t in [TYPE_LEGACY, TYPE_ACCESS_LIST, TYPE_DYNAMIC_FEE, TYPE_BLOB, TYPE_SET_CODE] {
            let r = sample(t);
            let ours = r.encode().unwrap();
            assert_eq!(Receipt::decode(&ours).unwrap(), r);
            assert!(r.bloom_matches());
            let logs = r
                .logs
                .iter()
                .map(|l| ALog {
                    address: Address::from(l.address),
                    data: LogData::new_unchecked(l.topics.iter().map(|t| B256::from(*t)).collect(), Bytes::from(l.data.clone())),
                })
                .collect();
            let inner = AReceipt {
                status: Eip658Value::Eip658(matches!(r.outcome, Outcome::Status(true))),
                cumulative_gas_used: r.cumulative_gas_used,
                logs,
            };
            let with_bloom = ReceiptWithBloom { receipt: inner, logs_bloom: r.logs_bloom.into() };
            let env = match t {
                TYPE_LEGACY => ReceiptEnvelope::Legacy(with_bloom),
                TYPE_ACCESS_LIST => ReceiptEnvelope::Eip2930(with_bloom),
                TYPE_DYNAMIC_FEE => ReceiptEnvelope::Eip1559(with_bloom),
                TYPE_BLOB => ReceiptEnvelope::Eip4844(with_bloom),
                _ => ReceiptEnvelope::Eip7702(with_bloom),
            };
            assert_eq!(env.encoded_2718(), ours, "type {t}");
        }
    }

    #[test]
    fn deposit_receipts() {
        let r = sample(TYPE_DEPOSIT);
        let enc = r.encode().unwrap();
        assert_eq!(enc[0], 0x7e);
        assert_eq!(Receipt::decode(&enc).unwrap(), r);
        let mut pre_canyon = r.clone();
        pre_canyon.deposit_receipt_version = None;
        assert_eq!(Receipt::decode(&pre_canyon.encode().unwrap()).unwrap(), pre_canyon);
        let mut pre_regolith = pre_canyon.clone();
        pre_regolith.deposit_nonce = None;
        assert_eq!(Receipt::decode(&pre_regolith.encode().unwrap()).unwrap(), pre_regolith);
        let mut bad = r.clone();
        bad.deposit_nonce = None;
        assert_eq!(bad.encode(), Err(ReceiptError::BadDepositFields));
        let mut bad = sample(TYPE_DYNAMIC_FEE);
        bad.deposit_nonce = Some(1);
        assert_eq!(bad.encode(), Err(ReceiptError::BadDepositFields));
        // Deposit fields smuggled onto a dynamic-fee receipt's encoding.
        let mut forged = enc.clone();
        forged[0] = TYPE_DYNAMIC_FEE;
        assert_eq!(Receipt::decode(&forged), Err(ReceiptError::BadDepositFields));
    }

    #[test]
    fn malformed_receipts_are_refused() {
        assert_eq!(Receipt::decode(&[]), Err(ReceiptError::Empty));
        assert_eq!(Receipt::decode(&[0x05, 0xc0]), Err(ReceiptError::UnknownType(0x05)));
        let mut r = sample(TYPE_DYNAMIC_FEE);
        r.logs[0].topics = vec![[0; 32]; 5];
        assert_eq!(r.encode(), Err(ReceiptError::TooManyTopics));
        // A post-state root of the wrong size.
        let mut legacy = sample(TYPE_LEGACY);
        legacy.outcome = Outcome::PostState([7; 32]);
        let enc = legacy.encode().unwrap();
        assert_eq!(Receipt::decode(&enc).unwrap(), legacy);
        // Trailing bytes after a typed receipt's list.
        let mut enc = sample(TYPE_DYNAMIC_FEE).encode().unwrap();
        enc.push(0);
        assert_eq!(Receipt::decode(&enc), Err(ReceiptError::Rlp(RlpError::TrailingBytes)));
    }
}
