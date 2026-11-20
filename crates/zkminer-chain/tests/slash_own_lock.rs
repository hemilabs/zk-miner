//! Chainless test of the self-slash send path (`ChainClient::slash_own_expired_lock`).
//!
//! A loopback JSON-RPC stub (as in `stake_tx_shape.rs`) answers just enough Ethereum for the real
//! client to run, and captures the raw transactions it signs. Checked: the one transaction sent is
//! `slashAndReopen(jobId)` to the router; a refusal from the contract at gas estimation ("Not
//! expired yet", the slash not open yet) is an answer, `Ok(false)`, with nothing sent; a mined
//! revert is `Ok(false)` too; a mined success is `Ok(true)`.

use std::sync::{Arc, Mutex};

use alloy::consensus::Transaction as _;
use alloy::eips::eip2718::Decodable2718;
use alloy::primitives::{address, Address, Bytes, B256, U256};
use alloy_sol_types::SolCall;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zkminer_chain::client::ChainClient;
use zkminer_contracts::bindings::IHemiProveFulfill;

const ROUTER: Address = address!("00000000000000000000000000000000000000CC");
const CHAIN_ID: u64 = 743111;
const PENDING_NONCE: u64 = 7;
/// Test key (well-known anvil key #0).
const KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[derive(Clone, Copy, PartialEq)]
enum Chain {
    /// The slash is accepted and mines.
    Slashes,
    /// Gas estimation reverts "Not expired yet".
    NotExpiredYet,
    /// It is sent and mines, reverted.
    MinedRevert,
}

struct Stub {
    chain: Chain,
    raw_txs: Vec<Bytes>,
}

fn handle(req: &Value, stub: &Arc<Mutex<Stub>>) -> Value {
    let method = req["method"].as_str().unwrap_or_default();
    let params = &req["params"];
    let chain = stub.lock().unwrap().chain;
    let result: Value = match method {
        "eth_chainId" => json!(format!("0x{:x}", CHAIN_ID)),
        "eth_blockNumber" => json!("0x100"),
        "eth_getTransactionCount" => json!(format!("0x{:x}", PENDING_NONCE)),
        "eth_gasPrice" | "eth_maxPriorityFeePerGas" => json!("0x3b9aca00"),
        "eth_feeHistory" => json!({
            "oldestBlock": "0xfe",
            "baseFeePerGas": ["0x7", "0x7", "0x7"],
            "gasUsedRatio": [0.5, 0.5],
            "reward": [["0x3b9aca00"], ["0x3b9aca00"]],
        }),
        "eth_estimateGas" if chain == Chain::NotExpiredYet => {
            // Error(string) "Not expired yet", as a node returns a revert.
            let reason = "Not expired yet";
            let data = format!(
                "0x08c379a0{:064x}{:064x}{:0<64}",
                32,
                reason.len(),
                alloy::hex::encode(reason)
            );
            return json!({
                "jsonrpc": "2.0",
                "id": req["id"].clone(),
                "error": { "code": 3, "message": "execution reverted: Not expired yet", "data": data },
            });
        }
        "eth_estimateGas" => json!("0x186a0"),
        "eth_call" => json!(format!("0x{}", "00".repeat(32 * 12))),
        "eth_sendRawTransaction" => {
            let raw = params[0].as_str().unwrap_or("0x");
            let bytes: Bytes = raw.parse().expect("raw tx hex");
            let hash = alloy::primitives::keccak256(&bytes);
            stub.lock().unwrap().raw_txs.push(bytes);
            json!(format!("{hash:#x}"))
        }
        "eth_getTransactionReceipt" => {
            let hash = params[0].as_str().unwrap_or_default().to_string();
            json!({
                "transactionHash": hash,
                "transactionIndex": "0x0",
                "blockHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "blockNumber": "0x101",
                "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                "to": format!("{ROUTER:#x}"),
                "cumulativeGasUsed": "0x186a0",
                "gasUsed": "0x186a0",
                "effectiveGasPrice": "0x3b9aca00",
                "contractAddress": Value::Null,
                "logs": [],
                "logsBloom": format!("0x{}", "00".repeat(256)),
                "status": if chain == Chain::MinedRevert { "0x0" } else { "0x1" },
                "type": "0x2",
            })
        }
        other => panic!("stub RPC got an unexpected method: {other}"),
    };
    json!({ "jsonrpc": "2.0", "id": req["id"].clone(), "result": result })
}

async fn start_stub(stub: Arc<Mutex<Stub>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let stub = stub.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                loop {
                    let mut chunk = [0u8; 4096];
                    let n = match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    let Some(hdr_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&buf[..hdr_end]).to_lowercase();
                    let len: usize = head
                        .split("content-length:")
                        .nth(1)
                        .and_then(|s| s.split("\r\n").next())
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(0);
                    if buf.len() < hdr_end + 4 + len {
                        continue;
                    }
                    let body: Value =
                        serde_json::from_slice(&buf[hdr_end + 4..hdr_end + 4 + len]).unwrap();
                    let resp = match &body {
                        Value::Array(reqs) => {
                            Value::Array(reqs.iter().map(|r| handle(r, &stub)).collect())
                        }
                        r => handle(r, &stub),
                    };
                    let out = serde_json::to_vec(&resp).unwrap();
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        out.len()
                    );
                    if sock.write_all(hdr.as_bytes()).await.is_err()
                        || sock.write_all(&out).await.is_err()
                    {
                        return;
                    }
                    buf.drain(..hdr_end + 4 + len);
                }
            });
        }
    });
    url
}

fn config(rpc_url: &str) -> zkminer_config::ZkMinerConfig {
    let mut c = zkminer_config::ZkMinerConfig::default();
    c.chain.rpc_url = rpc_url.to_string();
    c.chain.chain_id = CHAIN_ID;
    c.contracts.hemi_prove = format!("{ROUTER:#x}");
    c.contracts.hemi_prove_staking = format!(
        "{:#x}",
        address!("00000000000000000000000000000000000000BB")
    );
    c.contracts.hemi_prove_registry = format!(
        "{:#x}",
        address!("00000000000000000000000000000000000000DD")
    );
    c.contracts.hemi_token = format!(
        "{:#x}",
        address!("00000000000000000000000000000000000000AA")
    );
    c
}

async fn slash(chain: Chain) -> (Vec<Bytes>, anyhow::Result<bool>) {
    let stub = Arc::new(Mutex::new(Stub {
        chain,
        raw_txs: Vec::new(),
    }));
    let url = start_stub(stub.clone()).await;
    let signer: alloy::signers::local::PrivateKeySigner = KEY.parse().unwrap();
    let client = ChainClient::new(&config(&url), signer).await.unwrap();
    let res = client.slash_own_expired_lock(B256::repeat_byte(0x42)).await;
    let txs = stub.lock().unwrap().raw_txs.clone();
    (txs, res)
}

/// The one transaction is `slashAndReopen(jobId)` to the router, and a mined success is `true`.
#[tokio::test(flavor = "multi_thread")]
async fn a_self_slash_sends_slash_and_reopen_for_the_job() {
    let (txs, res) = slash(Chain::Slashes).await;
    assert!(res.expect("the slash is sent and mines"));
    assert_eq!(txs.len(), 1);
    let tx = alloy::consensus::TxEnvelope::decode_2718(&mut txs[0].as_ref()).unwrap();
    assert_eq!(tx.to(), Some(ROUTER));
    assert_eq!(tx.nonce(), PENDING_NONCE);
    let call = IHemiProveFulfill::slashAndReopenCall::abi_decode(tx.input()).unwrap();
    assert_eq!(call.jobId, B256::repeat_byte(0x42));
    assert_eq!(tx.value(), U256::ZERO);
}

/// Not slashable yet: the contract's refusal at gas estimation is an answer, nothing is sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_slash_that_is_not_open_yet_is_refused_without_a_send() {
    let (txs, res) = slash(Chain::NotExpiredYet).await;
    assert!(!res.expect("a refusal is an answer, not an error"));
    assert!(txs.is_empty());
}

/// Mined, reverted: not slashed, tried again later.
#[tokio::test(flavor = "multi_thread")]
async fn a_mined_revert_is_not_a_slash() {
    let (txs, res) = slash(Chain::MinedRevert).await;
    assert!(!res.expect("a mined revert is an answer"));
    assert_eq!(txs.len(), 1);
}
