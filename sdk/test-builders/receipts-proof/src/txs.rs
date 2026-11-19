//! Consensus encodings of transactions (legacy, EIP-2930, EIP-1559, EIP-4844, EIP-7702) and
//! withdrawals, and logs blooms: what the transactions root, the withdrawals root and the blooms are
//! computed from.

use crate::mpt::keccak;
use crate::rlp::List;
use crate::types::{AccessListItem, Log, Transaction, Withdrawal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    UnknownType,
    Missing(&'static str),
}

fn access_list(items: &Option<Vec<AccessListItem>>) -> Vec<u8> {
    let mut l = List::default();
    for item in items.iter().flatten() {
        let mut keys = List::default();
        for k in &item.storage_keys {
            keys.hash(k);
        }
        let mut entry = List::default();
        entry.bytes(&item.address.0).raw(&keys.finish());
        l.raw(&entry.finish());
    }
    l.finish()
}

fn need<'a, T>(v: &'a Option<T>, what: &'static str) -> Result<&'a T, TxError> {
    v.as_ref().ok_or(TxError::Missing(what))
}

/// The signature's y parity: `yParity`, or derived from `v` (27/28, or EIP-155's `35 + 2 × chainId`).
fn y_parity(tx: &Transaction) -> Result<u8, TxError> {
    if let Some(y) = &tx.y_parity {
        return Ok(y.0[31] & 1);
    }
    let v = need(&tx.v, "v")?.as_u64().ok_or(TxError::Missing("v"))?;
    Ok(match v {
        27 | 28 => (v - 27) as u8,
        v if v >= 35 => ((v - 35) % 2) as u8,
        v => (v & 1) as u8,
    })
}

/// `type ‖ rlp(fields)` (the bare list for legacy transactions): the transactions trie's values,
/// whose keccak is the transaction hash.
pub fn encode(tx: &Transaction) -> Result<Vec<u8>, TxError> {
    let ty = tx.tx_type.as_u64().ok_or(TxError::UnknownType)?;
    let to: &[u8] = tx.to.as_ref().map_or(&[], |a| &a.0);
    let mut l = List::default();
    match ty {
        0 => {
            l.quantity(&tx.nonce)
                .quantity(need(&tx.gas_price, "gasPrice")?)
                .quantity(&tx.gas)
                .bytes(to)
                .quantity(&tx.value)
                .bytes(&tx.input.0)
                .quantity(need(&tx.v, "v")?)
                .quantity(&tx.r)
                .quantity(&tx.s);
            return Ok(l.finish());
        }
        1 => {
            l.quantity(need(&tx.chain_id, "chainId")?)
                .quantity(&tx.nonce)
                .quantity(need(&tx.gas_price, "gasPrice")?)
                .quantity(&tx.gas)
                .bytes(to)
                .quantity(&tx.value)
                .bytes(&tx.input.0)
                .raw(&access_list(&tx.access_list));
        }
        2..=4 => {
            l.quantity(need(&tx.chain_id, "chainId")?)
                .quantity(&tx.nonce)
                .quantity(need(&tx.max_priority_fee_per_gas, "maxPriorityFeePerGas")?)
                .quantity(need(&tx.max_fee_per_gas, "maxFeePerGas")?)
                .quantity(&tx.gas)
                .bytes(to)
                .quantity(&tx.value)
                .bytes(&tx.input.0)
                .raw(&access_list(&tx.access_list));
            if ty == 3 {
                let mut hashes = List::default();
                for h in need(&tx.blob_versioned_hashes, "blobVersionedHashes")? {
                    hashes.hash(h);
                }
                l.quantity(need(&tx.max_fee_per_blob_gas, "maxFeePerBlobGas")?).raw(&hashes.finish());
            }
            if ty == 4 {
                let mut auths = List::default();
                for a in need(&tx.authorization_list, "authorizationList")? {
                    let mut e = List::default();
                    e.quantity(&a.chain_id)
                        .bytes(&a.address.0)
                        .quantity(&a.nonce)
                        .quantity(&a.y_parity)
                        .quantity(&a.r)
                        .quantity(&a.s);
                    auths.raw(&e.finish());
                }
                l.raw(&auths.finish());
            }
        }
        _ => return Err(TxError::UnknownType),
    }
    let parity = y_parity(tx)?;
    l.bytes(if parity == 0 { &[] } else { &[1] }).quantity(&tx.r).quantity(&tx.s);
    let body = l.finish();
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(ty as u8);
    out.extend_from_slice(&body);
    Ok(out)
}

/// `rlp([index, validatorIndex, address, amount])`.
pub fn withdrawal(w: &Withdrawal) -> Vec<u8> {
    let mut l = List::default();
    l.quantity(&w.index).quantity(&w.validator_index).bytes(&w.address.0).quantity(&w.amount);
    l.finish()
}

/// A 2048-bit logs bloom.
pub struct Bloom(pub [u8; 256]);

impl Bloom {
    pub fn new() -> Self {
        Self([0; 256])
    }

    fn accrue(&mut self, input: &[u8]) {
        let h = keccak(input);
        for i in [0, 2, 4] {
            let bit = ((usize::from(h[i]) << 8) | usize::from(h[i + 1])) & 2047;
            self.0[255 - bit / 8] |= 1 << (bit % 8);
        }
    }

    pub fn add_log(&mut self, l: &Log) {
        self.accrue(&l.address.0);
        for t in &l.topics {
            self.accrue(&t.0);
        }
    }

    pub fn or(&mut self, other: &[u8]) {
        for (a, b) in self.0.iter_mut().zip(other) {
            *a |= b;
        }
    }
}
