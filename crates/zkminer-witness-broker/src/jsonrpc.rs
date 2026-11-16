//! The broker's own JSON-RPC client for its fixed reads (plan §13.4, §11.2): `eth_chainId`,
//! `eth_blockNumber`, `eth_getBlockByNumber` / `eth_getBlockByHash` (without transactions) and
//! `eth_getCode` pinned to a block hash (single and batched). It never sees builder bytes:
//! requests are built here, responses parsed into fixed shapes with every code read capped at
//! 24,576 bytes before it is decoded.

use std::sync::atomic::{AtomicU64, Ordering};

use alloy_primitives::{Address, B256};
use serde::Deserialize;
use serde_json::json;
use zkminer_witness::manifest::MAX_CODE_BYTES;

use crate::lanes::WaitFlag;
use crate::net::{Endpoint, EndpointError};

/// The largest JSON batch of `eth_getCode` reads (plan §13.4 step 4).
pub const MAX_CODE_BATCH: usize = 256;
/// Response cap for one code read: the hex of 24,576 bytes plus the envelope.
pub const CODE_RESPONSE_CAP: u64 = 2 * MAX_CODE_BYTES as u64 + 512;
/// Per-element allowance in a batch of code reads besides the code's hex: the envelope, the id,
/// the `0x` and the `00` prefix byte.
pub const CODE_ANSWER_OVERHEAD: u64 = 128;
/// Response cap for a block header without transaction bodies.
const BLOCK_RESPONSE_CAP: u64 = 4 << 20;
const SMALL_RESPONSE_CAP: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RpcError {
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    #[error("malformed JSON-RPC response")]
    Malformed,
    #[error("JSON-RPC error {0}")]
    Rpc(i64),
    #[error("code longer than {MAX_CODE_BYTES} bytes")]
    CodeTooLarge,
}

#[derive(Deserialize)]
struct ErrObj {
    #[serde(default)]
    code: i64,
}

#[derive(Deserialize)]
struct StrResp<'a> {
    id: u64,
    #[serde(borrow)]
    result: Option<&'a str>,
    error: Option<ErrObj>,
}

#[derive(Deserialize)]
struct BlockObj<'a> {
    #[serde(borrow)]
    number: &'a str,
    #[serde(borrow)]
    hash: &'a str,
}

#[derive(Deserialize)]
struct BlockResp<'a> {
    id: u64,
    #[serde(borrow)]
    result: Option<BlockObj<'a>>,
    error: Option<ErrObj>,
}

/// A block, by number and hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef {
    pub number: u64,
    pub hash: B256,
}

/// A client bound to one endpoint, lane, id counter and wait flag.
pub struct RpcClient<'a> {
    pub ep: &'a Endpoint,
    pub held: bool,
    pub ids: &'a AtomicU64,
    /// Marked while a request waits for the pacer or a concurrency slot.
    pub wait: &'a WaitFlag,
}

fn request(id: u64, method: &str, params: serde_json::Value) -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

/// `0x` and 1–16 hex digits.
pub fn quantity(s: &str) -> Option<u64> {
    let h = s.strip_prefix("0x")?;
    if h.is_empty() || h.len() > 16 {
        return None;
    }
    u64::from_str_radix(h, 16).ok()
}

/// `0x` and exactly 64 hex digits.
pub fn hash32(s: &str) -> Option<B256> {
    let h = s.strip_prefix("0x")?;
    if h.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(h, &mut out).ok()?;
    Some(B256::from(out))
}

/// `0x`-prefixed code hex, refused above [`MAX_CODE_BYTES`] before decoding.
pub fn code_hex(s: &str) -> Result<Vec<u8>, RpcError> {
    let h = s.strip_prefix("0x").ok_or(RpcError::Malformed)?;
    if h.len() % 2 != 0 {
        return Err(RpcError::Malformed);
    }
    if h.len() / 2 > MAX_CODE_BYTES {
        return Err(RpcError::CodeTooLarge);
    }
    hex::decode(h).map_err(|_| RpcError::Malformed)
}

fn block_param(n: u64) -> String {
    format!("{n:#x}")
}

fn at_hash(h: B256) -> serde_json::Value {
    json!({ "blockHash": h.to_string() })
}

impl RpcClient<'_> {
    fn next_id(&self, n: u64) -> u64 {
        self.ids.fetch_add(n, Ordering::Relaxed)
    }

    async fn post(&self, body: Vec<u8>, cap: u64) -> Result<Vec<u8>, RpcError> {
        Ok(self.ep.post_json(self.held, body, cap, self.wait).await?)
    }

    async fn call_str(&self, method: &str, params: serde_json::Value, cap: u64) -> Result<Option<String>, RpcError> {
        let id = self.next_id(1);
        let body = serde_json::to_vec(&request(id, method, params)).expect("serializes");
        let bytes = self.post(body, cap).await?;
        let r: StrResp<'_> = serde_json::from_slice(&bytes).map_err(|_| RpcError::Malformed)?;
        if r.id != id {
            return Err(RpcError::Malformed);
        }
        if let Some(e) = r.error {
            return Err(RpcError::Rpc(e.code));
        }
        Ok(r.result.map(str::to_string))
    }

    pub async fn chain_id(&self) -> Result<u64, RpcError> {
        let s = self.call_str("eth_chainId", json!([]), SMALL_RESPONSE_CAP).await?;
        s.as_deref().and_then(quantity).ok_or(RpcError::Malformed)
    }

    pub async fn block_number(&self) -> Result<u64, RpcError> {
        let s = self.call_str("eth_blockNumber", json!([]), SMALL_RESPONSE_CAP).await?;
        s.as_deref().and_then(quantity).ok_or(RpcError::Malformed)
    }

    async fn block(&self, method: &str, params: serde_json::Value) -> Result<Option<BlockRef>, RpcError> {
        let id = self.next_id(1);
        let body = serde_json::to_vec(&request(id, method, params)).expect("serializes");
        let bytes = self.post(body, BLOCK_RESPONSE_CAP).await?;
        let r: BlockResp<'_> = serde_json::from_slice(&bytes).map_err(|_| RpcError::Malformed)?;
        if r.id != id {
            return Err(RpcError::Malformed);
        }
        if let Some(e) = r.error {
            return Err(RpcError::Rpc(e.code));
        }
        match r.result {
            None => Ok(None),
            Some(b) => match (quantity(b.number), hash32(b.hash)) {
                (Some(number), Some(hash)) => Ok(Some(BlockRef { number, hash })),
                _ => Err(RpcError::Malformed),
            },
        }
    }

    /// The block `tag` (`"safe"`, `"finalized"`, `"latest"`) names; `None` when the node has none
    /// (a null result).
    pub async fn tag_block(&self, tag: &str) -> Result<Option<BlockRef>, RpcError> {
        self.block("eth_getBlockByNumber", json!([tag, false])).await
    }

    /// The block at height `n` on the node's canonical chain.
    pub async fn block_by_number(&self, n: u64) -> Result<Option<BlockRef>, RpcError> {
        self.block("eth_getBlockByNumber", json!([block_param(n), false])).await
    }

    /// The block with hash `h`, if the node has it.
    pub async fn block_by_hash(&self, h: B256) -> Result<Option<BlockRef>, RpcError> {
        self.block("eth_getBlockByHash", json!([h.to_string(), false])).await
    }

    /// `eth_getCode(address, {"blockHash": at})`.
    pub async fn get_code(&self, address: Address, at: B256) -> Result<Vec<u8>, RpcError> {
        let s = self
            .call_str("eth_getCode", json!([address.to_string().to_ascii_lowercase(), at_hash(at)]), CODE_RESPONSE_CAP)
            .await?;
        code_hex(s.as_deref().ok_or(RpcError::Malformed)?)
    }

    /// `eth_getCode` for each address at block `at`, as one JSON-RPC batch (at most
    /// [`MAX_CODE_BATCH`]) whose raw body may be at most `cap` bytes; answers in address order
    /// whatever order the node used.
    pub async fn get_codes(&self, addresses: &[Address], at: B256, cap: u64) -> Result<Vec<Vec<u8>>, RpcError> {
        assert!(!addresses.is_empty() && addresses.len() <= MAX_CODE_BATCH);
        let n = addresses.len() as u64;
        let first = self.next_id(n);
        let batch: Vec<_> = addresses
            .iter()
            .enumerate()
            .map(|(i, a)| request(first + i as u64, "eth_getCode", json!([a.to_string().to_ascii_lowercase(), at_hash(at)])))
            .collect();
        let body = serde_json::to_vec(&batch).expect("serializes");
        let bytes = self.post(body, cap).await?;
        let answers: Vec<StrResp<'_>> = serde_json::from_slice(&bytes).map_err(|_| RpcError::Malformed)?;
        if answers.len() != addresses.len() {
            return Err(RpcError::Malformed);
        }
        let mut out: Vec<Option<Vec<u8>>> = vec![None; addresses.len()];
        for a in answers {
            let i = a.id.checked_sub(first).filter(|&i| i < n).ok_or(RpcError::Malformed)? as usize;
            if out[i].is_some() {
                return Err(RpcError::Malformed);
            }
            if let Some(e) = a.error {
                return Err(RpcError::Rpc(e.code));
            }
            out[i] = Some(code_hex(a.result.ok_or(RpcError::Malformed)?)?);
        }
        Ok(out.into_iter().map(|c| c.expect("every id seen once")).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantities_and_code() {
        assert_eq!(quantity("0x0"), Some(0));
        assert_eq!(quantity("0xb56c7"), Some(743111));
        assert_eq!(quantity("0x"), None);
        assert_eq!(quantity("12"), None);
        assert_eq!(quantity("0x10000000000000000"), None);
        assert_eq!(code_hex("0x").unwrap(), Vec::<u8>::new());
        assert_eq!(code_hex("0x00Ab").unwrap(), vec![0, 0xab]);
        assert_eq!(code_hex("0x0"), Err(RpcError::Malformed));
        assert_eq!(code_hex("00"), Err(RpcError::Malformed));
        assert_eq!(code_hex(&format!("0x{}", "00".repeat(MAX_CODE_BYTES))).unwrap().len(), MAX_CODE_BYTES);
        assert_eq!(code_hex(&format!("0x{}", "00".repeat(MAX_CODE_BYTES + 1))), Err(RpcError::CodeTooLarge));
        assert_eq!(block_param(255), "0xff");
        assert_eq!(hash32(&format!("0x{}", "ab".repeat(32))), Some(B256::repeat_byte(0xab)));
        assert_eq!(hash32(&format!("0x{}", "ab".repeat(31))), None);
        assert_eq!(hash32(&format!("0x{}", "zz".repeat(32))), None);
        assert_eq!(at_hash(B256::repeat_byte(1)), json!({"blockHash": format!("0x{}", "01".repeat(32))}));
    }
}
