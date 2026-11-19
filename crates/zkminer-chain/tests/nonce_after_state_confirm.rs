//! A nonce whose transaction a STATE read confirmed — the receipt never seen — is committed when our
//! mined transaction count is past it, and recycled only otherwise.
//!
//! The fulfil (and claim) paths wait a bounded time for a receipt, then poll `jobs()`. On Hemi the
//! fulfil's receipt wait can end inside the very block that mines it: the poll then finds the job
//! Fulfilled by us. The nonce was spent by our own transaction, yet the path recycled it as a gap,
//! so the next reservation drew it again and the next claim met "nonce too low" (it recovered only
//! on its retry). These drive the REAL `ChainClient` against a loopback JSON-RPC stub that accepts
//! the send, never returns a receipt, and flips the job's state as if the transaction had mined.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use alloy::primitives::{address, keccak256, Address, Bytes, B256};
use alloy::sol_types::SolCall;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zkminer_chain::client::ChainClient;
use zkminer_chain::jobs::{ClaimQuote, JOB_STATUS_FULFILLED, JOB_STATUS_LOCKED, JOB_STATUS_OPEN};
use zkminer_contracts::bindings::{IHemiProveAux, JobDescriptor};

const CHAIN_ID: u64 = 743111;
/// anvil's first dev key (address 0xf39F…2266); the stub's chain is not a real one.
const KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// The account's transaction count before our send: the nonce the operation reserves.
const N: u64 = 100;
const HEAD: u64 = 0x100;

/// What the job and the account look like once our send was accepted.
#[derive(Clone, Copy)]
struct Scenario {
    /// `jobs()` before / after our send: (status, prover is us).
    before: (u8, bool),
    after: (u8, bool),
    /// The mined count after the send, at the block the state was read at ("0x100") and at
    /// "latest" (a load-balanced replica may answer the latter from behind).
    count_at_head: u64,
    count_latest: u64,
}

struct Stub {
    scenario: Scenario,
    us: Address,
    sent: AtomicBool,
}

fn reply(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: Value, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": message } })
}

fn hex_u64(v: u64) -> Value {
    json!(format!("0x{v:x}"))
}

/// The 27-word `jobs()` return with `status` and `prover` set (everything else zero).
fn job_words(status: u8, prover: Address) -> Value {
    let mut out = vec![0u8; 27 * 32];
    out[32 + 31] = status;
    out[8 * 32 + 12..9 * 32].copy_from_slice(prover.as_slice());
    json!(format!("0x{}", alloy::hex::encode(out)))
}

fn handle(req: &Value, stub: &Stub) -> Value {
    let id = req["id"].clone();
    let params = &req["params"];
    let sent = stub.sent.load(Ordering::SeqCst);
    let s = stub.scenario;
    match req["method"].as_str().unwrap_or_default() {
        "eth_chainId" => reply(id, hex_u64(CHAIN_ID)),
        "eth_blockNumber" => reply(id, hex_u64(HEAD)),
        "eth_gasPrice" | "eth_maxPriorityFeePerGas" => reply(id, json!("0x3b9aca00")),
        "eth_getBalance" => reply(id, json!("0xde0b6b3a7640000")),
        "eth_getTransactionCount" => {
            let tag = params[1].as_str().unwrap_or("latest");
            let count = match (sent, tag) {
                (false, _) => N,
                (true, "pending") => N + 1,
                (true, "latest") => s.count_latest,
                (true, _) => s.count_at_head,
            };
            reply(id, hex_u64(count))
        }
        "eth_sendRawTransaction" => {
            let raw = params[0].as_str().unwrap_or_default();
            let bytes = alloy::hex::decode(raw.trim_start_matches("0x")).unwrap_or_default();
            stub.sent.store(true, Ordering::SeqCst);
            reply(id, json!(format!("{:#x}", keccak256(&bytes))))
        }
        // The receipt is never seen: the wait ends first.
        "eth_getTransactionReceipt" => reply(id, Value::Null),
        "eth_call" => {
            let input = params[0]["input"]
                .as_str()
                .or_else(|| params[0]["data"].as_str())
                .unwrap_or_default();
            let selector = alloy::hex::encode(IHemiProveAux::jobsCall::SELECTOR);
            if input.trim_start_matches("0x").starts_with(&selector) {
                let (status, ours) = if sent { s.after } else { s.before };
                let prover = if ours { stub.us } else { Address::ZERO };
                reply(id, job_words(status, prover))
            } else {
                // Governance reads (paused(), getAdapter): unreadable counts as no hold.
                rpc_error(id, "execution reverted")
            }
        }
        _ => rpc_error(id, "method not served by the stub"),
    }
}

async fn start_stub(stub: Arc<Stub>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
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
    let fmt = |a: Address| format!("{a:#x}");
    let mut c = zkminer_config::ZkMinerConfig::default();
    c.chain.rpc_url = rpc_url.to_string();
    c.chain.chain_id = CHAIN_ID;
    c.contracts.hemi_prove = fmt(address!("00000000000000000000000000000000000000CC"));
    c.contracts.hemi_prove_staking = fmt(address!("00000000000000000000000000000000000000BB"));
    c.contracts.hemi_prove_registry = fmt(address!("00000000000000000000000000000000000000DD"));
    c.contracts.hemi_token = fmt(address!("00000000000000000000000000000000000000AA"));
    c
}

async fn client_for(scenario: Scenario) -> ChainClient {
    let signer: alloy::signers::local::PrivateKeySigner = KEY.parse().unwrap();
    let stub = Arc::new(Stub {
        scenario,
        us: signer.address(),
        sent: AtomicBool::new(false),
    });
    let url = start_stub(stub).await;
    ChainClient::new(&config(&url), signer).await.unwrap()
}

async fn fulfil(client: &ChainClient) -> anyhow::Result<()> {
    client
        .fulfill_job(
            B256::repeat_byte(0x22),
            JobDescriptor {
                programId: B256::ZERO,
                proofSystemId: B256::ZERO,
                callbackContract: Address::ZERO,
                assignedProver: Address::ZERO,
                tag: B256::ZERO,
                inputData: Bytes::new(),
                callbackExtraData: Bytes::new(),
                extraVerifierData: Bytes::new(),
                expectedJournalHash: B256::ZERO,
                journalFields: B256::ZERO,
            },
            Bytes::from_static(&[1, 2, 3]),
            Bytes::from_static(&[4, 5, 6]),
            None,
            None,
        )
        .await
}

const FULFILLED_BY_US: Scenario = Scenario {
    before: (JOB_STATUS_LOCKED, true),
    after: (JOB_STATUS_FULFILLED, true),
    count_at_head: N + 1,
    count_latest: N + 1,
};

/// The live shape: our fulfil mined inside the receipt wait. Its nonce is spent, so the next
/// reservation must be a fresh one — before the fix it was this nonce again ("nonce too low").
#[tokio::test(flavor = "multi_thread")]
async fn a_fulfil_confirmed_by_state_poll_spends_its_nonce() {
    let client = client_for(FULFILLED_BY_US).await;
    fulfil(&client)
        .await
        .expect("the state poll shows the job Fulfilled by us");
    assert!(
        !client.nonce_is_freed(N),
        "nonce {N} carried our fulfil, which mined (count {}), yet it was recycled as a gap",
        N + 1
    );
    assert_eq!(
        client.reserve_nonce().await.unwrap(),
        N + 1,
        "the next operation drew the spent nonce: its send would fail \"nonce too low\""
    );
}

/// The count at the block the state was read at decides, so a replica answering "latest" from
/// behind does not recycle a mined nonce.
#[tokio::test(flavor = "multi_thread")]
async fn a_lagging_latest_count_does_not_recycle_a_mined_nonce() {
    let client = client_for(Scenario {
        count_latest: N,
        ..FULFILLED_BY_US
    })
    .await;
    fulfil(&client)
        .await
        .expect("the state poll shows the job Fulfilled by us");
    assert!(
        !client.nonce_is_freed(N),
        "a stale latest count recycled the mined nonce {N}"
    );
    assert_eq!(client.reserve_nonce().await.unwrap(), N + 1);
}

/// The other half: the job is Fulfilled by us, but nothing at OUR nonce has mined (an earlier
/// transaction of ours settled it). The nonce is still open and must be refilled, not skipped:
/// committing it would leave a hole that wedges every later nonce.
#[tokio::test(flavor = "multi_thread")]
async fn a_nonce_below_the_mined_count_is_still_recycled() {
    let client = client_for(Scenario {
        count_at_head: N,
        count_latest: N,
        ..FULFILLED_BY_US
    })
    .await;
    fulfil(&client)
        .await
        .expect("the state poll shows the job Fulfilled by us");
    assert!(
        client.nonce_is_freed(N),
        "nonce {N} never mined, so it is a gap the next reservation must refill"
    );
    assert_eq!(client.reserve_nonce().await.unwrap(), N);
}

/// The claim path has the same shape: no receipt, then `jobs()` shows our lock.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_confirmed_by_state_poll_spends_its_nonce() {
    let client = client_for(Scenario {
        before: (JOB_STATUS_OPEN, false),
        after: (JOB_STATUS_LOCKED, true),
        count_at_head: N + 1,
        count_latest: N + 1,
    })
    .await;
    let quote = ClaimQuote {
        block: 0,
        price_floor: 0,
        premium_floor: 0,
    };
    client
        .claim_job(B256::repeat_byte(0x33), &quote)
        .await
        .expect("the state poll shows our lock");
    assert!(
        !client.nonce_is_freed(N),
        "the claim's mined nonce {N} was recycled"
    );
    assert_eq!(client.reserve_nonce().await.unwrap(), N + 1);
}
