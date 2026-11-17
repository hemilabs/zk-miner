//! A JSON-RPC client over [`fetch`](crate::fetch), for `evm-rpc/v1` capabilities (zkminer
//! docs/witness-construction-jobs.md §11.2).
//!
//! Requests are written in the one form the broker accepts: exactly
//! `{"jsonrpc":"2.0","id":1,"method":…,"params":[…]}`, with `params` given as JSON text the caller
//! composes (canonical hex: [`json::to_hex`](crate::json::to_hex)). The broker resolves `latest`,
//! `safe` and `finalized` to numbers and re-emits the response canonically.
//!
//! Everything a node answers is untrusted: a builder only gathers material, and the guest checks
//! it against what the binding pins.

use crate::{fetch, json, Error};

/// The request bytes for `method` with `params` (a JSON array, as text).
pub fn request(method: &str, params: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#).into_bytes()
}

/// Calls `method` through capability `cap` and returns its `result` (raw JSON, not `null`); a
/// JSON-RPC error answer is [`json::JsonError::RpcError`].
pub fn call(cap: u32, method: &str, params: &str) -> Result<Vec<u8>, Error> {
    let response = fetch(cap, &request(method, params))?;
    Ok(json::rpc_result(&response)?.to_vec())
}

/// `{"blockHash":"0x…"}`: an EIP-1898 block parameter fixed by hash, so every query a builder makes
/// reads the same block whatever the chain's head does meanwhile.
pub fn at_block_hash(hash: &[u8; 32]) -> String {
    format!(r#"{{"blockHash":"{}"}}"#, json::to_hex(hash))
}

#[cfg(test)]
mod tests {
    #[test]
    fn requests_are_canonical() {
        assert_eq!(
            super::request("eth_getBlockByHash", r#"["0x01",false]"#),
            br#"{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByHash","params":["0x01",false]}"#.to_vec()
        );
        assert_eq!(super::at_block_hash(&[0xab; 32]), format!(r#"{{"blockHash":"0x{}"}}"#, "ab".repeat(32)));
    }
}
