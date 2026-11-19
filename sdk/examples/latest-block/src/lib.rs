//! Example witness builder: the latest finalized block of the chain behind capability 0.
//!
//! It reads its context, checks that capability 0 is `evm-rpc/v1`, fetches
//! `eth_getBlockByNumber("finalized", false)` and writes
//!
//! ```text
//! W = blockNumber (u64, big-endian) ‖ blockHash (32 bytes)
//! ```
//!
//! taken from the canonical response the broker returns,
//! `{"jsonrpc":"2.0","id":1,"result":{…,"hash":"0x…",…,"number":"0x…",…}}`.
//!
//! A guest proving over this W must still check it (here: the header hashes to `blockHash` and is
//! anchored as plan §8.5 requires); the builder is untrusted.

use hemiprove_builder_sdk::{self as sdk, json, Error, EvmRpcConfig};

sdk::entry!(build);

/// The request in the exact form `evm-rpc/v1` accepts (§11.2): canonical keys, `finalized` resolved
/// by the broker to a number.
const REQUEST: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["finalized",false]}"#;

fn build() -> Result<(), Error> {
    let ctx = sdk::context()?;
    let source = ctx.sources.first().ok_or(Error::Other("the job declares no capability 0"))?;
    if source.class != sdk::CLASS_EVM_RPC_V1 {
        return Err(Error::Other("capability 0 is not evm-rpc/v1"));
    }
    let rpc = EvmRpcConfig::decode(&source.config)?;
    sdk::log(&format!(
        "latest-block: hemi chain {}, capability 0 = evm-rpc/v1 chain {}, {} builder param bytes\n",
        ctx.hemi_chain_id,
        rpc.chain_id,
        ctx.builder_params.len()
    ));

    let response = sdk::fetch(0, REQUEST)?;
    let block = json::rpc_result(&response)?;
    let number = json::quantity_u64(json::str_member(block, "number")?)?;
    let hash = json::bytes32(json::str_member(block, "hash")?)?;

    let mut w = [0u8; 40];
    w[..8].copy_from_slice(&number.to_be_bytes());
    w[8..].copy_from_slice(&hash);
    sdk::write_witness(&w)?;
    sdk::log(&format!("latest-block: block {number}\n"));
    Ok(())
}
