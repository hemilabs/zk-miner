//! RLP encodings: the block header (every fork's optional tail) and consensus receipts.

use alloy_rlp::{Encodable, Header};

use crate::hex::{Bytes, Quantity, H256};
use crate::types::{Block, Log, Receipt};

/// Builds one RLP list from its encoded items.
#[derive(Default)]
pub struct List(Vec<u8>);

impl List {
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        b.encode(&mut self.0);
        self
    }

    #[allow(dead_code)]
    pub fn u64(&mut self, v: u64) -> &mut Self {
        v.encode(&mut self.0);
        self
    }

    pub fn quantity(&mut self, q: &Quantity) -> &mut Self {
        self.bytes(q.trimmed())
    }

    pub fn hash(&mut self, h: &H256) -> &mut Self {
        h.0.encode(&mut self.0);
        self
    }

    /// An already-encoded item.
    pub fn raw(&mut self, item: &[u8]) -> &mut Self {
        self.0.extend_from_slice(item);
        self
    }

    pub fn finish(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() + 9);
        Header { list: true, payload_length: self.0.len() }.encode(&mut out);
        out.extend_from_slice(&self.0);
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// A later fork's field is present while an earlier one is missing.
    Gap(&'static str),
}

/// `rlp(header)`: the fields every header has, then the fork tail (London base fee, Shanghai
/// withdrawals root, Cancun blob gas and beacon root, Prague requests hash), which must be
/// contiguous.
pub fn header(b: &Block) -> Result<Vec<u8>, HeaderError> {
    let mut l = List::default();
    l.hash(&b.parent_hash)
        .hash(&b.sha3_uncles)
        .bytes(&b.miner.0)
        .hash(&b.state_root)
        .hash(&b.transactions_root)
        .hash(&b.receipts_root)
        .bytes(&b.logs_bloom.0)
        .quantity(&b.difficulty)
        .quantity(&b.number)
        .quantity(&b.gas_limit)
        .quantity(&b.gas_used)
        .quantity(&b.timestamp)
        .bytes(&b.extra_data.0)
        .hash(&b.mix_hash)
        .bytes(&b.nonce.0);
    enum Field<'a> {
        Q(&'a Option<Quantity>),
        H(&'a Option<H256>),
    }
    let tail = [
        ("baseFeePerGas", Field::Q(&b.base_fee_per_gas)),
        ("withdrawalsRoot", Field::H(&b.withdrawals_root)),
        ("blobGasUsed", Field::Q(&b.blob_gas_used)),
        ("excessBlobGas", Field::Q(&b.excess_blob_gas)),
        ("parentBeaconBlockRoot", Field::H(&b.parent_beacon_block_root)),
        ("requestsHash", Field::H(&b.requests_hash)),
    ];
    let mut ended: Option<&'static str> = None;
    for (name, field) in &tail {
        let present = match field {
            Field::Q(q) => q.as_ref().map(|q| {
                l.quantity(q);
            }),
            Field::H(h) => h.as_ref().map(|h| {
                l.hash(h);
            }),
        }
        .is_some();
        match (present, ended) {
            (true, Some(missing)) => return Err(HeaderError::Gap(missing)),
            (false, None) => ended = Some(name),
            _ => {}
        }
    }
    Ok(l.finish())
}

fn log(l: &Log) -> Vec<u8> {
    let mut topics = List::default();
    for t in &l.topics {
        topics.hash(t);
    }
    let mut out = List::default();
    out.bytes(&l.address.0).raw(&topics.finish()).bytes(&l.data.0);
    out.finish()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptError {
    NoOutcome,
    UnknownType(u64),
}

/// The consensus encoding of a receipt, as the receipts trie stores it: `type ‖ rlp([status,
/// cumulativeGasUsed, logsBloom, logs])` for typed receipts, the bare list for legacy ones
/// (pre-Byzantium receipts carry the state root instead of the status).
pub fn receipt(r: &Receipt) -> Result<Vec<u8>, ReceiptError> {
    let ty = r.tx_type.as_u64().ok_or(ReceiptError::UnknownType(u64::MAX))?;
    if ty > 4 {
        return Err(ReceiptError::UnknownType(ty));
    }
    let mut logs = List::default();
    for l in &r.logs {
        logs.raw(&log(l));
    }
    let mut body = List::default();
    match (&r.status, &r.root) {
        (Some(s), _) => body.quantity(s),
        (None, Some(root)) => body.hash(root),
        (None, None) => return Err(ReceiptError::NoOutcome),
    };
    body.quantity(&r.cumulative_gas_used).bytes(&r.logs_bloom.0).raw(&logs.finish());
    let encoded = body.finish();
    if ty == 0 {
        return Ok(encoded);
    }
    let mut out = Vec::with_capacity(1 + encoded.len());
    out.push(ty as u8);
    out.extend_from_slice(&encoded);
    Ok(out)
}

/// `rlp(index)`: a receipt's (or transaction's) key in its trie.
pub fn index_key(i: u64) -> Vec<u8> {
    let mut out = Vec::new();
    i.encode(&mut out);
    out
}

/// One RLP item at the start of `buf`: (is a list, payload, the whole item).
pub fn item(buf: &[u8]) -> Result<(bool, &[u8], &[u8]), alloy_rlp::Error> {
    let mut rest = buf;
    let h = Header::decode(&mut rest)?;
    if rest.len() < h.payload_length {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    let header_len = buf.len() - rest.len();
    Ok((h.list, &rest[..h.payload_length], &buf[..header_len + h.payload_length]))
}

/// The items of an RLP list, each whole.
pub fn list_items(buf: &[u8]) -> Result<Vec<&[u8]>, alloy_rlp::Error> {
    let (is_list, mut payload, whole) = item(buf)?;
    if !is_list {
        return Err(alloy_rlp::Error::UnexpectedString);
    }
    if whole.len() != buf.len() {
        return Err(alloy_rlp::Error::UnexpectedLength);
    }
    let mut items = Vec::new();
    while !payload.is_empty() {
        let (_, _, it) = item(payload)?;
        items.push(it);
        payload = &payload[it.len()..];
    }
    Ok(items)
}

/// Raw byte strings in W: `len (u32 BE) ‖ bytes`.
pub fn put(w: &mut Vec<u8>, b: &[u8]) {
    w.extend_from_slice(&(b.len() as u32).to_be_bytes());
    w.extend_from_slice(b);
}

/// So `Bytes` can be written like any other field.
impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
