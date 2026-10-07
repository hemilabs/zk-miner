//! Chainless integration test for the `stake` send path.
//!
//! No anvil, no node, no network: a loopback JSON-RPC stub speaks just enough
//! Ethereum to let the REAL `ChainClient::approve_and_stake` run to completion,
//! and captures the raw signed transactions it broadcasts. The assertions are on
//! the bytes that would have hit the chain.

use std::sync::{Arc, Mutex};

use alloy::consensus::Transaction as _;
use alloy::eips::eip2718::Decodable2718;
use alloy::primitives::{address, Address, Bytes, U256};
use alloy_sol_types::SolCall;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zkminer_chain::client::ChainClient;
use zkminer_contracts::bindings::{IHemiProveStaking, IERC20};

const TOKEN: Address = address!("00000000000000000000000000000000000000AA");
const STAKING: Address = address!("00000000000000000000000000000000000000BB");
const CHAIN_ID: u64 = 743111;
/// The node reports this as the PENDING transaction count.
const PENDING_NONCE: u64 = 7;
/// Test key (well-known anvil key #0).
const KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[derive(Default)]
struct Captured {
    raw_txs: Vec<Bytes>,
    /// Whether allowance() has already been answered (lets a test flip it).
    allowance: U256,
    balance: U256,
    /// When true the stub ACCEPTS sends but never produces a receipt — the
    /// "accepted, receipt unobserved" state, which is NOT the same as "did not land".
    no_receipt: bool,
}

fn word(v: U256) -> String {
    format!("0x{:064x}", v)
}

fn handle(req: &Value, cap: &Arc<Mutex<Captured>>) -> Value {
    let method = req["method"].as_str().unwrap_or_default();
    let params = &req["params"];
    let result: Value = match method {
        "eth_chainId" => json!(format!("0x{:x}", CHAIN_ID)),
        "eth_blockNumber" => json!("0x100"),
        "eth_getTransactionCount" => json!(format!("0x{:x}", PENDING_NONCE)),
        "eth_gasPrice" => json!("0x3b9aca00"),
        "eth_maxPriorityFeePerGas" => json!("0x3b9aca00"),
        "eth_estimateGas" => json!("0x186a0"),
        "eth_feeHistory" => json!({
            "oldestBlock": "0xfe",
            "baseFeePerGas": ["0x7", "0x7", "0x7"],
            "gasUsedRatio": [0.5, 0.5],
            "reward": [["0x3b9aca00"], ["0x3b9aca00"]],
        }),
        "eth_call" => {
            // alloy serializes the calldata as `input`; accept `data` too.
            let data = params[0]["input"]
                .as_str()
                .or_else(|| params[0]["data"].as_str())
                .unwrap_or("0x");
            let bytes = alloy::hex::decode(data.trim_start_matches("0x")).unwrap_or_default();
            let sel: [u8; 4] = bytes
                .get(..4)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 4]);
            let c = cap.lock().unwrap();
            if sel == IERC20::balanceOfCall::SELECTOR {
                json!(word(c.balance))
            } else if sel == IERC20::allowanceCall::SELECTOR {
                json!(word(c.allowance))
            } else {
                json!(word(U256::ZERO))
            }
        }
        "eth_sendRawTransaction" => {
            let raw = params[0].as_str().unwrap_or("0x");
            let bytes: Bytes = raw.parse().expect("raw tx hex");
            let hash = alloy::primitives::keccak256(&bytes);
            cap.lock().unwrap().raw_txs.push(bytes);
            json!(format!("{hash:#x}"))
        }
        "eth_getTransactionReceipt" => {
            if cap.lock().unwrap().no_receipt {
                return json!({ "jsonrpc": "2.0", "id": req["id"].clone(), "result": Value::Null });
            }
            let hash = params[0].as_str().unwrap_or_default().to_string();
            json!({
                "transactionHash": hash,
                "transactionIndex": "0x0",
                "blockHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "blockNumber": "0x101",
                "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                "to": format!("{TOKEN:#x}"),
                "cumulativeGasUsed": "0x186a0",
                "gasUsed": "0x186a0",
                "effectiveGasPrice": "0x3b9aca00",
                "contractAddress": Value::Null,
                "logs": [],
                "logsBloom": format!("0x{}", "00".repeat(256)),
                "status": "0x1",
                "type": "0x2",
            })
        }
        other => panic!("stub RPC got an unexpected method: {other}"),
    };
    json!({ "jsonrpc": "2.0", "id": req["id"].clone(), "result": result })
}

/// Start the stub and return its URL.
async fn start_stub(cap: Arc<Mutex<Captured>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let cap = cap.clone();
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
                            Value::Array(reqs.iter().map(|r| handle(r, &cap)).collect())
                        }
                        r => handle(r, &cap),
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
    c.contracts.hemi_prove = format!(
        "{:#x}",
        address!("00000000000000000000000000000000000000CC")
    );
    c.contracts.hemi_prove_staking = format!("{STAKING:#x}");
    c.contracts.hemi_prove_registry = format!(
        "{:#x}",
        address!("00000000000000000000000000000000000000DD")
    );
    c.contracts.hemi_token = format!("{TOKEN:#x}");
    c
}

async fn run_stake(
    amount_wei: u128,
    allowance: U256,
    balance: U256,
) -> (Vec<Bytes>, anyhow::Result<()>) {
    let cap = Arc::new(Mutex::new(Captured {
        raw_txs: Vec::new(),
        allowance,
        balance,
        no_receipt: false,
    }));
    let url = start_stub(cap.clone()).await;
    let signer: alloy::signers::local::PrivateKeySigner = KEY.parse().unwrap();
    let client = ChainClient::new(&config(&url), signer).await.unwrap();
    let res = client.approve_and_stake(amount_wei).await;
    let txs = cap.lock().unwrap().raw_txs.clone();
    (txs, res)
}

/// TRAP 1+2: the ABI is `stake(address,uint128)`, and the allowance starts at 0 so an
/// approve must precede it — on the right nonces, in the right order.
#[tokio::test(flavor = "multi_thread")]
async fn approve_then_stake_uses_the_uint128_abi_and_consecutive_nonces() {
    // 4.25 HEMI — the exact shortfall from the incident.
    let amount: u128 = 4_250_000_000_000_000_000;
    let (txs, res) = run_stake(
        amount,
        U256::ZERO,
        U256::from(444_804u64) * U256::from(10u64).pow(U256::from(18)),
    )
    .await;
    res.expect("approve_and_stake should succeed against the stub");
    assert_eq!(txs.len(), 2, "expected exactly approve + stake");

    let approve = alloy::consensus::TxEnvelope::decode_2718(&mut txs[0].as_ref()).unwrap();
    let stake = alloy::consensus::TxEnvelope::decode_2718(&mut txs[1].as_ref()).unwrap();

    // Order + destination.
    assert_eq!(
        approve.to(),
        Some(TOKEN),
        "first tx must be the ERC-20 approve"
    );
    assert_eq!(stake.to(), Some(STAKING), "second tx must be the stake");

    // TRAP: nonces must come from the shared allocator, anchored at the node's
    // PENDING count, and be consecutive.
    assert_eq!(approve.nonce(), PENDING_NONCE);
    assert_eq!(stake.nonce(), PENDING_NONCE + 1);

    // TRAP: the deployed ABI is `stake(address,uint128)`. `stake(address,uint256)`
    // is a DIFFERENT selector; it mines with status 1 and changes nothing.
    // The expected value is HARDCODED ground truth on purpose — deriving it from
    // `IHemiProveStaking::stakeCall::SELECTOR` would make the assertion circular and
    // it would happily follow the bindings into the wrong ABI (verified: mutating
    // bindings.rs:322 to uint256 kept a bindings-derived assertion green).
    const STAKE_ADDRESS_UINT128: [u8; 4] = [0x19, 0xf8, 0xd5, 0xb4]; // keccak("stake(address,uint128)")[..4]
    const STAKE_ADDRESS_UINT256: [u8; 4] = [0xad, 0xc9, 0x77, 0x2e]; // the silent no-op
    let sel: [u8; 4] = stake.input()[..4].try_into().unwrap();
    assert_ne!(
        sel, STAKE_ADDRESS_UINT256,
        "uint256 stake() silently does nothing"
    );
    assert_eq!(sel, STAKE_ADDRESS_UINT128, "wrong stake() selector");
    assert_eq!(
        stake.input().len(),
        4 + 32 + 32,
        "stake calldata must be 2 words"
    );
    let decoded = IHemiProveStaking::stakeCall::abi_decode(stake.input()).unwrap();
    assert_eq!(decoded.amount, amount, "amount must be the full wei value");
    assert_eq!(
        decoded.prover,
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse::<Address>()
            .unwrap(),
        "stake() must credit this signer as prover"
    );

    // The approve must cover the stake.
    let a = IERC20::approveCall::abi_decode(approve.input()).unwrap();
    assert_eq!(a.spender, STAKING);
    assert!(a.amount >= U256::from(amount));
}

/// The balance pre-flight must refuse BEFORE granting an allowance.
#[tokio::test(flavor = "multi_thread")]
async fn insufficient_balance_sends_nothing_at_all() {
    let (txs, res) = run_stake(500 * 10u128.pow(18), U256::ZERO, U256::from(1u64)).await;
    let err = format!("{:#}", res.unwrap_err());
    assert!(err.contains("Insufficient HEMI balance"), "got: {err}");
    assert!(txs.is_empty(), "no approval may be left dangling: {txs:?}");
}

/// An allowance that already covers the amount must not be re-approved.
#[tokio::test(flavor = "multi_thread")]
async fn sufficient_allowance_skips_the_approve() {
    let amount: u128 = 10 * 10u128.pow(18);
    let (txs, res) = run_stake(amount, U256::MAX, U256::MAX).await;
    res.unwrap();
    assert_eq!(txs.len(), 1, "only the stake should be sent");
    let stake = alloy::consensus::TxEnvelope::decode_2718(&mut txs[0].as_ref()).unwrap();
    assert_eq!(stake.to(), Some(STAKING));
    // The single tx takes the FIRST allocator nonce, not a skipped one.
    assert_eq!(stake.nonce(), PENDING_NONCE);
}

/// The cross-process hazard, made executable. Two `ChainClient`s over the same
/// signer and the same node — a running miner and a `zkminer stake` invocation —
/// each mint their own `NonceManager` (client.rs:256) anchored at the node's
/// pending count (client.rs:283-287), so they hand out the SAME nonce. The
/// allocator's "no two tasks share a nonce" invariant (nonce.rs) is per-process.
///
/// This documents the CHAIN-LAYER behaviour, which is unchanged and still correct to
/// assert: `ChainClient` itself offers no cross-process coordination. The guard added for
/// this hazard lives one layer up, in the CLI (`stake.rs::other_running_miners`, which
/// scans /proc and refuses), so it does not affect this assertion. If cross-process
/// coordination ever moves INTO the chain layer, invert it then.
#[tokio::test(flavor = "multi_thread")]
async fn two_processes_over_one_signer_collide_on_the_same_nonce() {
    let cap = Arc::new(Mutex::new(Captured {
        raw_txs: Vec::new(),
        allowance: U256::MAX,
        balance: U256::MAX,
        no_receipt: false,
    }));
    let url = start_stub(cap).await;
    let signer: alloy::signers::local::PrivateKeySigner = KEY.parse().unwrap();

    // "the miner"
    let miner = ChainClient::new(&config(&url), signer.clone())
        .await
        .unwrap();
    // "zkminer stake", a separate process, same key, same node
    let cli = ChainClient::new(&config(&url), signer).await.unwrap();

    let miner_nonce = miner.reserve_nonce().await.unwrap();
    let cli_nonce = cli.reserve_nonce().await.unwrap();
    assert_eq!(miner_nonce, PENDING_NONCE);
    assert_eq!(
        cli_nonce, miner_nonce,
        "the CLI does not merely risk the miner's nonce — it picks exactly it"
    );
}

/// [round-4 R4-A] An accepted send whose RECEIPT is never observed must not recycle its nonce.
///
/// `abort` inserts into `freed` AND writes an abandonment record, and the following `resync`
/// cannot undo either: the stake is unmined, so the mined frontier IS that nonce and
/// `freed.retain(f >= chain_nonce)` keeps it. That is the gap detector's branch (B) trigger,
/// and the watchdog consumes branch (B) ungated — it then bids `max(4x base, 2 gwei)` with no
/// floor to lift over (staking records no fee) and replaces the still-resident stake with a
/// 0-value self-transfer. Nothing retries: `approve_and_stake`'s unobserved arm deliberately
/// neither re-sends nor revokes, precisely because the tx may still be in the mempool.
///
/// SLOW (~120s): it must traverse the real TX_RECEIPT_TIMEOUT. A paused clock does not work
/// here — auto-advance races the stub's TCP round-trip and the send never happens at all.
/// Worth the wall clock: this is a silent fund-loss path with no other coverage.
#[tokio::test(flavor = "multi_thread")]
async fn an_unobserved_receipt_does_not_recycle_the_nonce() {
    let cap = Arc::new(Mutex::new(Captured {
        raw_txs: Vec::new(),
        allowance: U256::MAX, // skip the approve; exercise the stake send alone
        balance: U256::MAX,
        no_receipt: true,
    }));
    let url = start_stub(cap.clone()).await;
    let signer: alloy::signers::local::PrivateKeySigner = KEY.parse().unwrap();
    let client = ChainClient::new(&config(&url), signer).await.unwrap();

    let res = client.approve_and_stake(10 * 10u128.pow(18)).await;
    assert!(
        res.is_err(),
        "an unobserved receipt must not be reported as success"
    );

    assert_eq!(
        cap.lock().unwrap().raw_txs.len(),
        1,
        "exactly one stake tx was accepted"
    );
    assert!(
        !client.nonce_is_freed(PENDING_NONCE),
        "nonce {PENDING_NONCE} was recycled after an ACCEPTED send — that arms the gap \
         detector against our own live stake, and the watchdog will evict it"
    );
}
