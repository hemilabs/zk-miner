//! Consistency checks across the block and its receipts, and a one-line summary for the log.

use core::fmt;

use crate::hex::{self, Quantity};
use crate::types::{Block, Receipt};

/// 256-bit unsigned addition on big-endian words; `None` on overflow.
fn add(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    (carry == 0).then_some(out)
}

#[derive(Default)]
pub struct Summary {
    pub number: u64,
    pub by_type: [u32; 5],
    pub value: [u8; 32],
    pub logs: u32,
    pub access_list_keys: u32,
    pub authorizations: u32,
    pub blobs: u32,
    pub creations: u32,
    pub withdrawals: u32,
    pub withdrawn_gwei: u64,
    pub failed: u32,
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [legacy, al, dynamic, blob, setcode] = self.by_type;
        write!(
            f,
            "block {}: {legacy} legacy, {al} access-list, {dynamic} dynamic-fee, {blob} blob ({} blobs), {setcode} \
             set-code ({} authorizations) txs; {} creations, {} failed; {} logs; {} access-list keys; value {}; \
             {} withdrawals of {} gwei",
            self.number,
            self.blobs,
            self.authorizations,
            self.creations,
            self.failed,
            self.logs,
            self.access_list_keys,
            hex::encode(&self.value),
            self.withdrawals,
            self.withdrawn_gwei,
        )
    }
}

fn u64_of(q: &Quantity, what: &'static str) -> Result<u64, &'static str> {
    q.as_u64().ok_or(what)
}

/// Checks what a guest would otherwise have to reject: every receipt belongs to this block, gas
/// adds up, log indices run in order, typed fields match their transaction types.
pub fn check(block: &Block, receipts: &[Receipt]) -> Result<Summary, &'static str> {
    let mut s = Summary { number: u64_of(&block.number, "block number over u64")?, ..Default::default() };
    let mut cumulative = 0u64;
    let mut next_log = 0u64;
    for (tx, r) in block.transactions.iter().zip(receipts) {
        let ty = u64_of(&tx.tx_type, "transaction type")? as usize;
        *s.by_type.get_mut(ty).ok_or("unknown transaction type")? += 1;
        if tx.block_hash.as_ref().is_some_and(|h| *h != block.hash) || r.block_hash != block.hash {
            return Err("a transaction or receipt of another block");
        }
        if tx.block_number.as_ref().is_some_and(|n| *n != block.number) || r.block_number != block.number {
            return Err("a transaction or receipt at another height");
        }
        if r.from != tx.from || r.to != tx.to || r.tx_type != tx.tx_type {
            return Err("a receipt that does not match its transaction");
        }
        s.value = add(&s.value, &tx.value.0).ok_or("value overflow")?;
        let gas = u64_of(&r.gas_used, "gas used")?;
        if gas > u64_of(&tx.gas, "gas limit")? {
            return Err("a receipt using more gas than its limit");
        }
        cumulative = cumulative.checked_add(gas).ok_or("gas overflow")?;
        if u64_of(&r.cumulative_gas_used, "cumulative gas")? != cumulative {
            return Err("cumulative gas does not add up");
        }
        match (ty, &tx.gas_price, &tx.max_fee_per_gas, &tx.max_priority_fee_per_gas) {
            (0 | 1, Some(_), _, _) => {}
            (2..=4, _, Some(max), Some(tip)) if tip.0 <= max.0 => {}
            _ => return Err("fee fields do not match the transaction type"),
        }
        if ty == 0 && tx.v.is_none() {
            return Err("legacy transaction without v");
        }
        if ty > 0 && (tx.chain_id.is_none() || tx.y_parity.as_ref().is_some_and(|y| y.0[31] > 1)) {
            return Err("typed transaction without chain id or with a bad y parity");
        }
        if tx.r.trimmed().is_empty() || tx.s.trimmed().is_empty() {
            return Err("zero signature value");
        }
        for item in tx.access_list.iter().flatten() {
            s.access_list_keys += item.storage_keys.len() as u32;
            if item.address.0 == [0u8; 20] && !item.storage_keys.is_empty() {
                s.access_list_keys += 0;
            }
        }
        if ty == 3 {
            let hashes = tx.blob_versioned_hashes.as_ref().ok_or("blob transaction without blobs")?;
            if hashes.is_empty() || hashes.iter().any(|h| h.0[0] != 1) || tx.max_fee_per_blob_gas.is_none() {
                return Err("bad blob versioned hashes");
            }
            s.blobs += hashes.len() as u32;
            if r.blob_gas_used.is_none() || r.blob_gas_price.is_none() {
                return Err("blob receipt without blob gas");
            }
        }
        if ty == 4 {
            let auths = tx.authorization_list.as_ref().ok_or("set-code transaction without authorizations")?;
            for a in auths {
                if a.y_parity.0[31] > 1 || a.r.trimmed().is_empty() || a.s.trimmed().is_empty() {
                    return Err("bad authorization signature");
                }
                let _ = (&a.chain_id, &a.address, a.nonce.as_u64());
            }
            s.authorizations += auths.len() as u32;
        }
        if tx.to.is_none() {
            s.creations += 1;
            if r.contract_address.is_none() {
                return Err("a creation without a contract address");
            }
        }
        if r.status.as_ref().is_some_and(|st| st.trimmed().is_empty()) {
            s.failed += 1;
        }
        let _ = (&tx.nonce, &tx.input, &tx.transaction_index, &r.effective_gas_price);
        for l in &r.logs {
            if l.removed {
                return Err("a removed log");
            }
            if l.block_hash.as_ref().is_some_and(|h| *h != block.hash)
                || l.transaction_hash.as_ref().is_some_and(|h| *h != r.transaction_hash)
                || l.transaction_index.as_ref().is_some_and(|i| *i != r.transaction_index)
                || l.block_number.as_ref().is_some_and(|n| *n != block.number)
            {
                return Err("a log of another transaction");
            }
            if let Some(i) = &l.log_index {
                if u64_of(i, "log index")? != next_log {
                    return Err("log indices out of order");
                }
            }
            if l.topics.len() > 4 {
                return Err("a log with more than four topics");
            }
            next_log += 1;
            s.logs += 1;
        }
    }
    if cumulative != u64_of(&block.gas_used, "block gas used")? {
        return Err("receipts do not add up to the block's gas used");
    }
    for w in block.withdrawals.iter().flatten() {
        s.withdrawals += 1;
        s.withdrawn_gwei = s.withdrawn_gwei.checked_add(u64_of(&w.amount, "withdrawal amount")?).ok_or("overflow")?;
        let _ = (u64_of(&w.index, "withdrawal index")?, u64_of(&w.validator_index, "validator index")?, &w.address);
    }
    Ok(s)
}
