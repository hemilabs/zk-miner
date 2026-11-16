//! The broker's own JSON-RPC client for its fixed reads (plan §13.4): `eth_chainId`,
//! `eth_blockNumber`, `eth_getBlockByNumber(tag, false)` and `eth_getCode` (single and batched).
//! It never sees builder bytes: requests are built here, responses parsed into fixed shapes with
//! every code read capped at 24,576 bytes before it is decoded.

use std::sync::atomic::{AtomicU64, Ordering};

use alloy_primitives::Address;
use serde::Deserialize;
use serde_json::json;
use zkminer_witness::manifest::MAX_CODE_BYTES;

use crate::net::{Endpoint, EndpointError};

/// The largest JSON batch of `eth_getCode` reads (plan §13.4 step 4).
pub const MAX_CODE_BATCH: usize = 256;
/// Response cap for one code read: the hex of 24,576 bytes plus the envelope.
pub const CODE_RESPONSE_CAP: u64 = 2 * MAX_CODE_BYTES as u64 + 512;
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
struct BlockNum<'a> {
    #[serde(borrow)]
    number: &'a str,
}

#[derive(Deserialize)]
struct BlockResp<'a> {
    id: u64,
    #[serde(borrow)]
    result: Option<BlockNum<'a>>,
    error: Option<ErrObj>,
}

/// A client bound to one endpoint, lane and id counter.
pub struct RpcClient<'a> {
    pub ep: &'a Endpoint,
    pub held: bool,
    pub ids: &'a AtomicU64,
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

impl RpcClient<'_> {
    fn next_id(&self, n: u64) -> u64 {
        self.ids.fetch_add(n, Ordering::Relaxed)
    }

    async fn call_str(&self, method: &str, params: serde_json::Value, cap: u64) -> Result<Option<String>, RpcError> {
        let id = self.next_id(1);
        let body = serde_json::to_vec(&request(id, method, params)).expect("serializes");
        let bytes = self.ep.post_json(self.held, body, cap).await?;
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

    /// The number of the block `tag` (`"safe"`, `"finalized"`, `"latest"`) names; `None` when the
    /// node has none (a null result).
    pub async fn tag_number(&self, tag: &str) -> Result<Option<u64>, RpcError> {
        let id = self.next_id(1);
        let body = serde_json::to_vec(&request(id, "eth_getBlockByNumber", json!([tag, false]))).expect("serializes");
        let bytes = self.ep.post_json(self.held, body, BLOCK_RESPONSE_CAP).await?;
        let r: BlockResp<'_> = serde_json::from_slice(&bytes).map_err(|_| RpcError::Malformed)?;
        if r.id != id {
            return Err(RpcError::Malformed);
        }
        if let Some(e) = r.error {
            return Err(RpcError::Rpc(e.code));
        }
        match r.result {
            None => Ok(None),
            Some(b) => quantity(b.number).map(Some).ok_or(RpcError::Malformed),
        }
    }

    /// `eth_getCode(address, block)`.
    pub async fn get_code(&self, address: Address, block: u64) -> Result<Vec<u8>, RpcError> {
        let s = self
            .call_str("eth_getCode", json!([address.to_string().to_ascii_lowercase(), block_param(block)]), CODE_RESPONSE_CAP)
            .await?;
        code_hex(s.as_deref().ok_or(RpcError::Malformed)?)
    }

    /// `eth_getCode` for each address at `block`, as one JSON-RPC batch (at most
    /// [`MAX_CODE_BATCH`]), answers in address order whatever order the node used.
    pub async fn get_codes(&self, addresses: &[Address], block: u64) -> Result<Vec<Vec<u8>>, RpcError> {
        assert!(!addresses.is_empty() && addresses.len() <= MAX_CODE_BATCH);
        let n = addresses.len() as u64;
        let first = self.next_id(n);
        let batch: Vec<_> = addresses
            .iter()
            .enumerate()
            .map(|(i, a)| {
                request(first + i as u64, "eth_getCode", json!([a.to_string().to_ascii_lowercase(), block_param(block)]))
            })
            .collect();
        let body = serde_json::to_vec(&batch).expect("serializes");
        let cap = n * (CODE_RESPONSE_CAP - 384) + 1024;
        let bytes = self.ep.post_json(self.held, body, cap).await?;
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
    }
}
