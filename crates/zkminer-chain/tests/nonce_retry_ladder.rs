//! The nonce-error retry ladder, driven through the REAL `ChainClient` against a loopback
//! JSON-RPC stub that rejects every send with "nonce too low".
//!
//! WHY THIS FILE EXISTS. All four `is_nonce_error` arms used to do
//! `abort → resync → reserve → continue` with no delay at all, so `MAX_TX_ATTEMPTS` re-sends
//! could burn in microseconds against a node view that had not moved. That is the shape of the
//! 2026-08-14 wedge: 327 rejected sends in 4h24m. The fix added a backoff — and was covered
//! only by unit tests of the 5-line `nonce_retry_backoff` helper, which pass with every
//! production sleep deleted. A guard that cannot fail when the bug returns is not a guard.
//!
//! So this measures the thing the invariant is about: how long the ladder takes, and how many
//! sends it makes, when the node keeps rejecting the nonce.

use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use alloy::primitives::{address, Address, B256};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zkminer_chain::client::ChainClient;
use zkminer_chain::jobs::MAX_TX_ATTEMPTS;

const CHAIN_ID: u64 = 743111;
const KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// What the stub observed.
#[derive(Default)]
struct Seen {
    sends: AtomicU32,
    /// When each send arrived. The GAPS between these are the measurement that matters: see
    /// the test for why total elapsed time is not good enough.
    send_times: Mutex<Vec<Instant>>,
}

fn reply(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn handle(req: &Value, seen: &Arc<Seen>) -> Value {
    let id = req["id"].clone();
    let method = req["method"].as_str().unwrap_or_default();
    match method {
        "eth_chainId" => reply(id, json!(format!("0x{CHAIN_ID:x}"))),
        "eth_blockNumber" => reply(id, json!("0x100")),
        // STATIC: the node's view never moves, so a re-sync hands back the nonce it just
        // rejected. That is the `progressed == false` case, i.e. the full backoff.
        "eth_getTransactionCount" => reply(id, json!("0x64")),
        "eth_gasPrice" | "eth_maxPriorityFeePerGas" => reply(id, json!("0x3b9aca00")),
        "eth_estimateGas" => reply(id, json!("0x5208")),
        "eth_feeHistory" => reply(
            id,
            json!({
                "oldestBlock": "0xfe",
                "baseFeePerGas": ["0x7", "0x7", "0x7"],
                "gasUsedRatio": [0.5, 0.5],
                "reward": [["0x3b9aca00"], ["0x3b9aca00"]],
            }),
        ),
        // The whole point: every send is rejected as a genuine nonce mismatch, which is what
        // `is_nonce_error` matches on ("nonce too low" / "nonce too high") — NOT
        // `is_same_nonce_pending`, whose arm already had a backoff.
        "eth_sendRawTransaction" => {
            seen.sends.fetch_add(1, Ordering::Relaxed);
            seen.send_times.lock().unwrap().push(Instant::now());
            rpc_error(id, -32000, "nonce too low: next nonce 100, tx nonce 99")
        }
        // The post-loop on-chain confirmation; failing it is handled (`if let Ok(view)`), and
        // leaves the error path intact.
        "eth_call" => rpc_error(id, -32000, "execution reverted"),
        "eth_getTransactionReceipt" => reply(id, Value::Null),
        other => panic!("stub RPC got an unexpected method: {other}"),
    }
}

async fn start_stub(seen: Arc<Seen>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let seen = seen.clone();
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
                            Value::Array(reqs.iter().map(|r| handle(r, &seen)).collect())
                        }
                        r => handle(r, &seen),
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

fn fmt(a: Address) -> String {
    format!("{a:#x}")
}

fn config(rpc_url: &str) -> zkminer_config::ZkMinerConfig {
    let mut c = zkminer_config::ZkMinerConfig::default();
    c.chain.rpc_url = rpc_url.to_string();
    c.chain.chain_id = CHAIN_ID;
    c.contracts.hemi_prove = fmt(address!("00000000000000000000000000000000000000CC"));
    c.contracts.hemi_prove_staking = fmt(address!("00000000000000000000000000000000000000BB"));
    c.contracts.hemi_prove_registry = fmt(address!("00000000000000000000000000000000000000DD"));
    c.contracts.hemi_token = fmt(address!("00000000000000000000000000000000000000AA"));
    c
}

/// THE regression test, and it measures the GAPS BETWEEN SENDS rather than total elapsed
/// time.
///
/// Total elapsed time looked like the obvious assertion and is not good enough. Measured with
/// the production backoff deleted, this ladder still took 3.50s (against 5.05s with it),
/// because each attempt pays ~500ms of ambient cost of its own — fee estimation, the re-sync,
/// the re-reservation. A threshold on the total cannot separate "backed off" from "hammered the
/// node as fast as it would answer"; it can only be tuned until it happens to. The first
/// version of this test asserted `total >= 2s` and passed with all four sleeps removed.
///
/// The backoff has a signature that latency does not: it GROWS linearly with the attempt
/// (250ms × attempt). Ambient latency is roughly constant per attempt, so the gap between the
/// last two sends must exceed the gap between the first two by most of the ladder's slope.
/// That is a property of the fix and of nothing else. Measured: gaps of
/// [499ms, 500ms, 500ms, 500ms] with the backoff removed — flat, as predicted — against growing
/// gaps with it in place.
///
/// Where that ~500ms floor comes from, since it decides the margin: `ChainClient` installs
/// `ThrottleLayer::new(4)`, i.e. a 250ms minimum interval between RPCs, and each attempt makes two
/// (the send plus the re-sync's `eth_getTransactionCount`). So attempt 1's 250ms backoff is
/// entirely absorbed by the throttle and the visible slope is 1000 − 250 = 750ms, against a 500ms
/// assertion. If that throttle were ever tightened to 1 request/second, every rung would be
/// absorbed and this test would fail WITH the fix in place — so it is coupled to that constant,
/// deliberately and now explicitly.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_nonce_ladder_backs_off_between_sends() {
    let seen = Arc::new(Seen::default());
    let url = start_stub(seen.clone()).await;
    let signer: alloy::signers::local::PrivateKeySigner = KEY.parse().unwrap();
    let client = ChainClient::new(&config(&url), signer).await.unwrap();

    let t0 = Instant::now();
    let outcome = client.claim_job(B256::repeat_byte(0x11)).await;
    let total = t0.elapsed();

    assert!(
        outcome.is_err(),
        "every send was rejected, so the claim must fail rather than report success"
    );

    let sends = seen.sends.load(Ordering::Relaxed);
    assert_eq!(
        sends, MAX_TX_ATTEMPTS,
        "the ladder must spend its whole attempt budget: {sends} sends against {MAX_TX_ATTEMPTS}"
    );

    let times = seen.send_times.lock().unwrap().clone();
    let gaps: Vec<Duration> = times.windows(2).map(|w| w[1] - w[0]).collect();
    assert_eq!(
        gaps.len() as u32,
        MAX_TX_ATTEMPTS - 1,
        "need every gap to compare them"
    );

    let first = gaps[0];
    let last = *gaps.last().unwrap();
    // Nominal slope across the ladder: attempt 1 waits 250ms, attempt 4 waits 1000ms, so the
    // last gap should exceed the first by ~750ms. Require most of that, to leave room for
    // scheduling noise without leaving room for "no backoff at all".
    assert!(
        last >= first + Duration::from_millis(500),
        "the gaps between rejected sends are not growing: {gaps:?} (total {total:?}). A flat \
         sequence means the ladder is re-sending against an unchanged node view as fast as it \
         will answer — the 2026-08-14 wedge shape, 327 rejected sends in 4h24m — and that each \
         attempt learns nothing from the one before it."
    );

    // And it must not dawdle: this is a claim, and the auction is moving.
    assert!(
        total < Duration::from_secs(20),
        "the ladder took {total:?}, which is too long for a claim decision"
    );
}
