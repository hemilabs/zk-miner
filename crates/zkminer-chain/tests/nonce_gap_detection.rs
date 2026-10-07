//! [A4] Chainless test for `ChainClient::nonce_gap_frontier`.
//!
//! A loopback JSON-RPC stub reports whatever `latest` and `pending` transaction counts a
//! test asks for, so the REAL detector runs against controlled chain state with no node.
//!
//! THE DEFECT: the detector could only ever nominate the MINED frontier as a hole. Its
//! external-hole branch required `pending <= mined`, and its local-evidence branch looked
//! for an abort record at `mined`. A hole ABOVE the mined frontier — the shape left by a
//! leaked reservation (a task that reserved a nonce then panicked, was cancelled at an
//! await, or returned down a path that skips `abort`) — satisfies neither: `pending` sits
//! AT the hole, strictly above `mined`, and there is no local trace at `mined` because the
//! leak is not at `mined`. Every tx above the hole is queued and unmineable; for a
//! releaseJob that means its collateral rides to the lock deadline and is lost.
//!
//! The fix reads the hole off the node instead of assuming it: `eth_getTransactionCount`
//! at `pending` IS the lowest nonce with no executable tx.

use std::sync::{Arc, Mutex};

use alloy::primitives::{address, Address};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zkminer_chain::client::ChainClient;

const CHAIN_ID: u64 = 743111;
const KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[derive(Clone, Copy)]
struct Counts {
    mined: u64,
    pending: u64,
}

fn handle(req: &Value, c: &Arc<Mutex<Counts>>) -> Value {
    let method = req["method"].as_str().unwrap_or_default();
    let params = &req["params"];
    let result: Value = match method {
        "eth_chainId" => json!(format!("0x{:x}", CHAIN_ID)),
        "eth_blockNumber" => json!("0x100"),
        "eth_getTransactionCount" => {
            // params[1] is the block tag; alloy sends "pending" for `.pending()`.
            let tag = params[1].as_str().unwrap_or("latest");
            let c = c.lock().unwrap();
            let n = if tag == "pending" { c.pending } else { c.mined };
            json!(format!("0x{n:x}"))
        }
        // Enough of a node to let a REAL heal broadcast and then wait for a receipt that
        // never comes. Without these the send panics the stub thread, the heal takes its
        // Err path, and any test of the receipt-wait path silently measures nothing.
        "eth_gasPrice" | "eth_maxPriorityFeePerGas" => json!("0x3b9aca00"),
        "eth_estimateGas" => json!("0x5208"),
        "eth_feeHistory" => json!({
            "oldestBlock": "0xfe",
            "baseFeePerGas": ["0x7", "0x7", "0x7"],
            "gasUsedRatio": [0.5, 0.5],
            "reward": [["0x3b9aca00"], ["0x3b9aca00"]],
        }),
        "eth_sendRawTransaction" => {
            let raw = params[0].as_str().unwrap_or("0x");
            let bytes = alloy::hex::decode(raw.trim_start_matches("0x")).unwrap_or_default();
            json!(format!("{:#x}", alloy::primitives::keccak256(&bytes)))
        }
        // Accepted, but never mined: the state the receipt budget exists to bound.
        "eth_getTransactionReceipt" => Value::Null,
        other => panic!("stub RPC got an unexpected method: {other}"),
    };
    json!({ "jsonrpc": "2.0", "id": req["id"].clone(), "result": result })
}

async fn start_stub(counts: Arc<Mutex<Counts>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let counts = counts.clone();
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
                            Value::Array(reqs.iter().map(|r| handle(r, &counts)).collect())
                        }
                        r => handle(r, &counts),
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
    c.contracts.hemi_prove = fmt(address!("00000000000000000000000000000000000000CC"));
    c.contracts.hemi_prove_staking = fmt(address!("00000000000000000000000000000000000000BB"));
    c.contracts.hemi_prove_registry = fmt(address!("00000000000000000000000000000000000000DD"));
    c.contracts.hemi_token = fmt(address!("00000000000000000000000000000000000000AA"));
    c
}

fn fmt(a: Address) -> String {
    format!("{a:#x}")
}

/// Build a client whose allocator has handed out nonces up to `next - 1`.
///
/// The allocator anchors at the node's PENDING count on its first reservation, so the stub
/// starts there and the counts are set afterwards — mirroring reality, where the hole opens
/// after the nonces around it were handed out.
async fn client_with(mined: u64, pending: u64, next: u64) -> ChainClient {
    client_from(mined, mined, pending, next).await
}

/// `anchor_at` is what the node reports when the allocator first syncs; `mined`/`pending`
/// are what it reports afterwards. Separating them lets a test advance the chain underneath
/// a synced allocator, which is the only way to reach `next == mined` with `synced == true`.
async fn client_from(anchor_at: u64, mined: u64, pending: u64, next: u64) -> ChainClient {
    let counts = Arc::new(Mutex::new(Counts {
        mined: anchor_at,
        pending: anchor_at,
    }));
    let url = start_stub(counts.clone()).await;
    let signer: alloy::signers::local::PrivateKeySigner = KEY.parse().unwrap();
    let client = ChainClient::new(&config(&url), signer).await.unwrap();
    // Hand out nonces `anchor_at .. next-1`, so `peek_next() == next`.
    for _ in anchor_at..next {
        client.reserve_nonce().await.unwrap();
    }
    if next > anchor_at {
        assert_eq!(client.peek_nonce(), Some(next), "test setup: wrong `next`");
    }
    // Now set the chain state under it: executable txs up to `pending`, nothing AT `pending`.
    {
        let mut c = counts.lock().unwrap();
        c.mined = mined;
        c.pending = pending;
    }
    client
}

/// THE A4 REGRESSION. mined=100, txs executable at 100 and 101, hole at 102, queued txs at
/// 103-104. The old detector returned None here: `pending`(102) > `mined`(100) failed its
/// `pending <= mined` test, and there is no local abort record at 100.
#[tokio::test(flavor = "multi_thread")]
async fn detects_a_hole_above_the_mined_frontier() {
    let c = client_with(100, 102, 105).await;
    assert_eq!(
        c.nonce_gap_frontier().await.unwrap(),
        Some(102),
        "a hole above the mined frontier must be detected — everything above it is queued \
         and unmineable, and a queued releaseJob loses its collateral at the lock deadline"
    );
}

/// The classic case must be unchanged: the hole IS the mined frontier.
#[tokio::test(flavor = "multi_thread")]
async fn still_detects_a_hole_at_the_mined_frontier() {
    let c = client_with(100, 100, 103).await;
    assert_eq!(c.nonce_gap_frontier().await.unwrap(), Some(100));
}

/// A single reserved-but-not-yet-sent nonce is NOT a hole. This is the false positive the
/// `> pending + 1` guard exists to prevent: filling it would collide with the task's own
/// imminent broadcast.
#[tokio::test(flavor = "multi_thread")]
async fn a_lone_unsent_reservation_is_not_a_hole() {
    // At the frontier: reserved 100, nothing sent yet.
    assert_eq!(
        client_with(100, 100, 101)
            .await
            .nonce_gap_frontier()
            .await
            .unwrap(),
        None
    );
    // Above the frontier: 100-101 executable, 102 reserved but unsent, nothing above it.
    assert_eq!(
        client_with(100, 102, 103)
            .await
            .nonce_gap_frontier()
            .await
            .unwrap(),
        None
    );
}

/// Nothing handed out past the mined frontier => nothing of ours can be stuck. Reached by
/// letting the chain catch up to a SYNCED allocator (anchored at 100, handed out 100, then
/// the chain mines it so mined == next == 101).
#[tokio::test(flavor = "multi_thread")]
async fn no_gap_when_the_allocator_is_level_with_chain() {
    let c = client_from(100, 101, 101, 101).await;
    assert_eq!(
        c.peek_nonce(),
        Some(101),
        "must be SYNCED and level, not unsynced"
    );
    assert_eq!(c.nonce_gap_frontier().await.unwrap(), None);
}

/// An allocator that has never anchored knows nothing about the chain and must never
/// nominate a hole — there is no first-person evidence that anything is ours.
#[tokio::test(flavor = "multi_thread")]
async fn an_unsynced_allocator_never_reports_a_gap() {
    let counts = Arc::new(Mutex::new(Counts {
        mined: 100,
        pending: 100,
    }));
    let url = start_stub(counts).await;
    let signer: alloy::signers::local::PrivateKeySigner = KEY.parse().unwrap();
    let c = ChainClient::new(&config(&url), signer).await.unwrap();
    assert_eq!(c.peek_nonce(), None, "no reservation yet => unsynced");
    assert_eq!(c.nonce_gap_frontier().await.unwrap(), None);
}

/// A fully-executable queue is not a hole, however long it is: `pending` has advanced past
/// everything we handed out, so every tx will mine in order.
#[tokio::test(flavor = "multi_thread")]
async fn a_healthy_backlog_is_not_a_hole() {
    assert_eq!(
        client_with(100, 105, 105)
            .await
            .nonce_gap_frontier()
            .await
            .unwrap(),
        None
    );
}

/// A load-balanced RPC can serve a STALE pending read that trails `mined`. That must never
/// be taken at face value and turned into a fabricated low hole — filling a nonce below the
/// mined frontier is meaningless, and the resulting tx would be rejected "nonce too low"
/// every tick.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_pending_read_below_mined_never_fabricates_a_low_hole() {
    let c = client_with(100, 98, 105).await;
    let got = c.nonce_gap_frontier().await.unwrap();
    assert!(
        got.is_none_or(|h| h >= 100),
        "nominated {got:?}, which is below the mined frontier"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// nonce_gap_safe_to_fill — the SHUTDOWN gate.
//
// Filling a hole during shutdown is destructive when the nonce is actually a live unsent
// reservation: heal bids >= 4x base, the release ladder tops out at 1.15^9 ~= 3.52x base and
// never lifts over the recorded floor, so the releaseJob is rejected "replacement
// underpriced" on all 5 attempts and never reaches the wire — silently, with the process
// exiting immediately after. So the gate demands a first-person abort record at the hole.
// ─────────────────────────────────────────────────────────────────────────────

/// The abandon path pre-reserves a nonce for EVERY doomed job in one burst before any task
/// sends. A task still in pre-flight when the join budget expires leaves a nonce that looks
/// exactly like a hole. Filling it destroys that job's release.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_gate_refuses_a_hole_with_no_abort_record() {
    // mined=100, release@100 broadcast (pending=101), 101 and 102 reserved but still unsent.
    let c = client_with(100, 101, 103).await;
    assert_eq!(
        c.nonce_gap_frontier().await.unwrap(),
        Some(101),
        "the detector still SEES it — the gate, not the detector, is what must refuse"
    );
    assert_eq!(
        c.nonce_gap_safe_to_fill().await.unwrap(),
        None,
        "no abort record at 101: it may be a live unsent release, and filling it at >=4x base \
         makes that release unsendable"
    );
}

/// The motivating A4 case must still heal: every skip arm in the abandon path recycles its
/// nonce through `abort_nonce`, so the hole carries a first-person abort record.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_gate_fills_a_hole_we_provably_abandoned() {
    let c = client_with(100, 101, 103).await;
    c.abort_nonce(101); // what release_and_clean_with_nonce's skip arms do
    assert_eq!(
        c.nonce_gap_safe_to_fill().await.unwrap(),
        Some(101),
        "we recycled this nonce ourselves — it is a real hole and safe to fill"
    );
}

/// [D2] Branch (B) runs first and its `recently_aborted` evidence is sticky for 600s and
/// survives re-reservation. A stale record at `mined` made the detector nominate `mined`,
/// which the gate then refused (frontier busy) — masking a genuine hole above it on the very
/// path this gate was added for. The gate must fall through, not give up.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_abort_record_at_the_frontier_does_not_mask_a_hole_above_it() {
    // mined=100 with an executable tx at 100 (pending=101), hole at 101, 102 broadcast.
    let c = client_with(100, 101, 103).await;
    c.abort_nonce(100); // stale record from earlier in the session; 100 was re-reserved+sent
    c.abort_nonce(101); // the genuinely abandoned nonce
    assert_eq!(
        c.nonce_gap_frontier().await.unwrap(),
        Some(100),
        "branch (B) nominates the frontier on the stale record"
    );
    assert_eq!(
        c.nonce_gap_safe_to_fill().await.unwrap(),
        Some(101),
        "must fall through to the real hole above, not return None"
    );
}

/// Displacing a tx at the frontier stays forbidden during shutdown: it would replace our own
/// still-mineable releaseJob with a 0-value self-transfer, with no time left to re-send.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_gate_never_displaces_an_executable_tx_at_the_frontier() {
    // mined=100, executable tx at 100 (pending=101), and NO hole above (101 is the last).
    let c = client_with(100, 101, 102).await;
    c.abort_nonce(100);
    assert_eq!(c.nonce_gap_safe_to_fill().await.unwrap(), None);
}

/// An empty frontier is NECESSARY but not SUFFICIENT evidence during shutdown.
///
/// This test previously asserted `Some(100)` and so PINNED a bug: in the abandon burst every
/// nonce is pre-reserved before any task sends, which makes "nothing executable at the
/// frontier" true BY CONSTRUCTION. With the allocator level with chain — mined=100,
/// pending=100, next=103, all three jobs still in pre-flight — the gate handed back 100, the
/// NEAREST-DEADLINE job's live nonce, for a >=4x self-transfer seconds before process::exit.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_gate_refuses_an_empty_frontier_we_cannot_prove_we_abandoned() {
    let c = client_with(100, 100, 103).await;
    assert_eq!(
        c.nonce_gap_frontier().await.unwrap(),
        Some(100),
        "the detector still nominates it"
    );
    assert_eq!(
        c.nonce_gap_safe_to_fill().await.unwrap(),
        None,
        "no abort record: 100 may be the nearest-deadline job's live pre-flight nonce"
    );
}

/// With an empty frontier AND proof we abandoned the nonce, displacing our own tx there is
/// the original, still-correct behaviour.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_gate_fills_an_empty_frontier_we_provably_abandoned() {
    let c = client_with(100, 100, 103).await;
    c.abort_nonce(100);
    assert_eq!(c.nonce_gap_safe_to_fill().await.unwrap(), Some(100));
}

/// [round-1 #2] An ACCEPTED broadcast retires stale abandonment evidence.
///
/// `aborted_at` deliberately survives re-reservation and `reserve_locked` reissues freed
/// nonces FIRST, so a nonce recycled by a give-up and then taken by a healthy task still
/// carried its predecessor's abort record. Branch (B) does no pending read and is consumed
/// UNGATED by the watchdog, so it nominated that nonce and the healer would evict a live,
/// executable tx with a >=4x self-transfer.
///
/// State: mined=100, everything up to 103 executable (pending=103), so branch (A) cannot
/// fire and branch (B) is isolated.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_broadcast_clears_the_abort_record() {
    let c = client_with(100, 103, 103).await;
    c.abort_nonce(100);
    assert_eq!(
        c.reserve_nonce().await.unwrap(),
        100,
        "freed is reissued first"
    );
    assert_eq!(
        c.nonce_gap_frontier().await.unwrap(),
        Some(100),
        "before the new owner broadcasts, the sticky record still flags it — this is the \
         flicker-proofing branch (B) needs, and it must be preserved"
    );
    // The new owner's send is ACCEPTED by the node.
    c.note_broadcast_fee(100, 1_000, 1_000, 1_000);
    assert_eq!(
        c.nonce_gap_frontier().await.unwrap(),
        None,
        "100 is legitimately in use again; nominating it would evict a live executable tx"
    );
}

/// [round-0 #2] `reserve_locked` reissues the LOWEST freed nonce FIRST, and `aborted_at`
/// survives that re-reservation. Together that means the abandon burst typically hands the
/// NEAREST-DEADLINE job a nonce still carrying its predecessor's abort record. That record is
/// evidence about the PAST, not proof the nonce is unowned — so the gate must refuse.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_gate_refuses_a_nonce_re_reserved_after_its_abort() {
    let c = client_with(100, 101, 103).await;
    c.abort_nonce(101);
    assert_eq!(
        c.reserve_nonce().await.unwrap(),
        101,
        "freed is reissued FIRST"
    );
    assert_eq!(
        c.nonce_gap_safe_to_fill().await.unwrap(),
        None,
        "101 is a LIVE pre-flight release; filling it at >=4x base makes it unsendable, and \
         the process exits with nothing alive to re-send it"
    );
}

/// [round-0 #1] The gate and the detector are DESIGNED to disagree (the D2 fall-through). A
/// caller that vetted a nonce and then let heal re-derive its own target filled precisely the
/// nonce the gate had refused. This pins that they can differ, so the split entry point
/// (`heal_nonce_gap_at`) is load-bearing rather than cosmetic.
#[tokio::test(flavor = "multi_thread")]
async fn the_gate_and_the_detector_can_nominate_different_nonces() {
    let c = client_with(100, 101, 103).await;
    c.abort_nonce(100); // stale record at the frontier, where an executable tx now sits
    c.abort_nonce(101); // the genuinely abandoned nonce
    let detector = c.nonce_gap_frontier().await.unwrap();
    let gate = c.nonce_gap_safe_to_fill().await.unwrap();
    assert_eq!(detector, Some(100), "branch (B) nominates the frontier");
    assert_eq!(gate, Some(101), "the gate nominates the real hole above it");
    assert_ne!(
        detector, gate,
        "they disagree — so heal MUST take the vetted nonce as an argument, not re-derive it"
    );
}

/// [round-2 R2-B] The shutdown gate and the broadcast are separated by at least one throttled
/// RPC round-trip (`base_fees`). In that window a sibling task can take the very nonce the
/// gate approved — `reserve_locked` hands out the LOWEST freed first — and broadcast an
/// immediately-executable releaseJob on it. The healer must then refuse rather than evict it.
#[tokio::test(flavor = "multi_thread")]
async fn a_vetted_heal_refuses_a_nonce_re_reserved_after_the_gate() {
    let c = client_with(100, 100, 103).await;
    c.abort_nonce(100);
    // The gate approves it: it is a gap we own.
    assert_eq!(c.nonce_gap_safe_to_fill().await.unwrap(), Some(100));
    // ...then a sibling task takes it out of `freed` before the fill goes out.
    assert_eq!(
        c.reserve_nonce().await.unwrap(),
        100,
        "freed is reissued FIRST"
    );
    assert_eq!(
        c.heal_owned_nonce_gap_at(100, std::time::Duration::from_secs(1))
            .await
            .unwrap(),
        zkminer_chain::client::OwnedHealOutcome::RefusedNotOurs,
        "must not displace a nonce that was re-reserved after the gate approved it — that \
         task's releaseJob is live, and we exit with nothing alive to re-send it. It must \
         also be DISTINGUISHABLE from an unconfirmed fill: the refusal proves this nonce \
         will be plugged by its owner, so the shutdown walk should continue to the hole above"
    );
}

/// [round-3 R3] The staking paths reserve from the SAME allocator as the job paths but cannot
/// record a fee (alloy's gas filler owns their pair). Without an explicit retirement signal a
/// nonce recycled by a job give-up and then taken by a stake keeps its stale abort record, so
/// branch (B) nominates it and the UNGATED watchdog evicts the live stake.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_send_with_no_fee_record_still_retires_the_abort() {
    let c = client_with(100, 103, 103).await;
    c.abort_nonce(100);
    assert_eq!(
        c.reserve_nonce().await.unwrap(),
        100,
        "freed is reissued first"
    );
    assert_eq!(
        c.nonce_gap_frontier().await.unwrap(),
        Some(100),
        "before the send, the sticky record still flags it"
    );
    // A staking send is accepted; it has no bid of its own to record.
    c.note_nonce_in_use(100);
    assert_eq!(
        c.nonce_gap_frontier().await.unwrap(),
        None,
        "100 is a live stake now; healing it would evict a tx whose unobserved-receipt arm \
         neither retries nor revokes, so the stake would silently never land"
    );
}

/// [round-3 R1] The detector and the gate must judge against the SAME mined frontier. Taking
/// two independent reads let the gate decide against a frontier the nomination never saw.
#[tokio::test(flavor = "multi_thread")]
async fn the_gate_never_nominates_below_the_mined_frontier() {
    for (mined, pending, next) in [(100u64, 100u64, 103u64), (100, 101, 103), (100, 103, 103)] {
        let c = client_from(100, mined, pending, next).await;
        c.abort_nonce(mined);
        if let Some(h) = c.nonce_gap_safe_to_fill().await.unwrap() {
            assert!(
                h >= mined,
                "nominated {h} below the frontier {mined}: a bid there is rejected \
                 'nonce too low', which ends the multi-hole walk before the real hole"
            );
        }
    }
}

/// [round-4] A fee record must not PERMANENTLY veto healing a hole we provably abandoned.
///
/// `fee_floor` is immortal at a nonce that never mines (`commit` is its only pruner; `resync`
/// deliberately skips it), and a broadcast tx can be EVICTED — which this codebase names as
/// the canonical cause of a hole. Requiring `fee_floor(mined).is_none()` outright therefore
/// short-circuited past both `frontier_has_executable_tx` and `is_freed`, and the shutdown
/// loop broke on its first iteration with every sibling releaseJob queued above the hole.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_fee_record_does_not_veto_healing_a_hole_we_abandoned() {
    let c = client_with(100, 100, 103).await;
    c.note_broadcast_fee(100, 1_000, 1_000, 1_000); // we broadcast there...
    c.abort_nonce(100); // ...then gave up; the tx was evicted
    assert_eq!(
        c.nonce_gap_safe_to_fill().await.unwrap(),
        Some(100),
        "an abort record is strictly LATER evidence than the fee record and must win"
    );
}

/// The converse still holds, via `is_freed` rather than the fee record: an accepted broadcast
/// means someone HELD the nonce, and holding it removed it from `freed`.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_broadcast_at_the_frontier_is_still_refused() {
    let c = client_with(100, 100, 103).await;
    c.abort_nonce(100);
    assert_eq!(
        c.reserve_nonce().await.unwrap(),
        100,
        "a sibling takes it back"
    );
    c.note_broadcast_fee(100, 1_000, 1_000, 1_000); // ...and broadcasts
    assert_eq!(
        c.nonce_gap_safe_to_fill().await.unwrap(),
        None,
        "that tx is live and must not be evicted"
    );
}

/// [round-4 R4-A] A staking receipt timeout must NOT arm branch (B) against its own live tx.
/// The node accepted the send; only the receipt went unobserved. Aborting there put the nonce
/// in `freed` (and `resync` keeps it, since the unmined stake IS the mined frontier), which is
/// branch (B)'s literal trigger — and the ungated watchdog then evicts the live stake.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_send_with_an_unobserved_receipt_is_not_a_hole() {
    let c = client_with(100, 101, 101).await;
    c.note_nonce_in_use(100); // the send was ACCEPTED
                              // ...the receipt never arrives. The path must leave no abandonment evidence behind.
    assert_eq!(
        c.nonce_gap_frontier().await.unwrap(),
        None,
        "the stake may still be resident; nominating it lets the watchdog evict a tx that \
         nothing will retry or revoke"
    );
}

/// [round-5 R1] The shutdown heal must honour the caller's remaining budget, not a hard-coded
/// 30s. A 30s wait inside a 20s loop budget is arithmetic, not a race: the first frontier pass
/// always overruns, the walk becomes single-shot, and shutdown runs past the supervisor kill —
/// losing the worker reap and the exit-75 verdict that triggers the recovery restart.
#[tokio::test(flavor = "multi_thread")]
async fn the_vetted_heal_honours_the_callers_receipt_budget() {
    let c = client_with(100, 100, 103).await;
    c.abort_nonce(100);
    assert_eq!(c.nonce_gap_safe_to_fill().await.unwrap(), Some(100));
    // The stub never yields a receipt, so this returns only when the budget elapses.
    let budget = std::time::Duration::from_secs(2);
    let t0 = std::time::Instant::now();
    let _ = c.heal_owned_nonce_gap_at(100, budget).await;
    let waited = t0.elapsed();
    assert!(
        waited < std::time::Duration::from_secs(12),
        "waited {waited:?} against a 2s budget — a hard-coded receipt wait would blow the \
         shutdown deadline and make the multi-hole walk single-shot"
    );
}
