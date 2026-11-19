//! Chainless tests of the witness-job chain gates against a loopback JSON-RPC stub, so the REAL
//! request paths run (calldata and filters as alloy encodes them, answers as the bindings decode them):
//!
//! - the submission form every descriptor fetch path reports (fast path, scan, submit-tx hint), and
//!   that the fetches still accept and refuse exactly what they did;
//! - the governance watcher: its start-up read (every view pinned to one block, a bounded look-back),
//!   its incremental polls in bounded ranges from the monitor's cached head, the aborts it broadcasts,
//!   and a resync correcting state no log announced.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::primitives::aliases::{U40, U48, U96};
use alloy::primitives::{address, keccak256, Address, Bytes, B256, U256};
use alloy::sol_types::{SolCall, SolEvent};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zkminer_chain::client::ChainClient;
use zkminer_chain::descriptor::{
    compute_descriptor_hash, fetch_job_descriptor_checked, fetch_job_descriptor_checked_with_form,
    fetch_job_descriptor_from_submit_tx_with_form, fetch_job_descriptor_with_form, SubmissionForm,
    SubmitEntryPoint, UndecodableDescriptor, UnsupportedSubmission,
};
use zkminer_chain::governance::{
    AbortReason, AbortSimulation, GateRefusal, GovernanceConfig, GovernanceWatcher,
};
use zkminer_contracts::bindings::{
    AdapterEntry, IHemiProveAux, IHemiProveCore, IHemiProveFulfill, IHemiProveRegistry,
    IHemiProveRouterGov, JobDescriptor,
};

// Not 743111: no known deployment, so no scan floor.
const CHAIN_ID: u64 = 31337;
const ROUTER: Address = address!("00000000000000000000000000000000000000cc");
const REGISTRY: Address = address!("00000000000000000000000000000000000000dd");
const PROXY: Address = address!("00000000000000000000000000000000000000ee");
const ADAPTER: Address = address!("0000000000000000000000000000000000000a0a");
const ME: Address = address!("1111111111111111111111111111111111111111");
const OTHER: Address = address!("2222222222222222222222222222222222222222");
const KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[derive(Default)]
struct Chain {
    head: u64,
    txs: HashMap<B256, Value>,
    logs: Vec<Value>,
    /// (to, calldata) → return data; an absent pair reverts.
    calls: HashMap<(Address, Bytes), Bytes>,
    /// The block parameter of every eth_call.
    call_blocks: Vec<Value>,
    /// The `[from, to]` of every eth_getLogs, and its addresses and topic0 set.
    log_queries: Vec<(u64, u64, Vec<String>, Vec<String>)>,
    methods: Vec<String>,
}

type Shared = Arc<Mutex<Chain>>;

fn hexu(n: u64) -> String {
    format!("0x{n:x}")
}

fn num(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a
            .iter()
            .map(|x| x.as_str().unwrap().to_lowercase())
            .collect(),
        Value::String(s) => vec![s.to_lowercase()],
        _ => vec![],
    }
}

fn handle(req: &Value, chain: &Shared) -> Value {
    let method = req["method"].as_str().unwrap_or_default();
    let params = &req["params"];
    let mut c = chain.lock().unwrap();
    c.methods.push(method.to_string());
    let ok = |result: Value| json!({ "jsonrpc": "2.0", "id": req["id"].clone(), "result": result });
    match method {
        "eth_chainId" => ok(json!(hexu(CHAIN_ID))),
        "eth_blockNumber" => ok(json!(hexu(c.head))),
        "eth_getTransactionByHash" => {
            let h: B256 = params[0].as_str().unwrap().parse().unwrap();
            ok(c.txs.get(&h).cloned().unwrap_or(Value::Null))
        }
        "eth_getTransactionReceipt" => {
            let h = params[0].as_str().unwrap().to_lowercase();
            if !c.txs.contains_key(&h.parse::<B256>().unwrap()) {
                return ok(Value::Null);
            }
            let logs: Vec<Value> = c
                .logs
                .iter()
                .filter(|l| l["transactionHash"].as_str().unwrap().to_lowercase() == h)
                .cloned()
                .collect();
            ok(json!({ "status": "0x1", "transactionHash": h, "logs": logs }))
        }
        "eth_getLogs" => {
            let f = &params[0];
            let (from, to) = (num(&f["fromBlock"]), num(&f["toBlock"]));
            let addrs = strings(&f["address"]);
            let t0s = strings(&f["topics"][0]);
            let t1s = strings(&f["topics"][1]);
            c.log_queries.push((from, to, addrs.clone(), t0s.clone()));
            let hits: Vec<Value> = c
                .logs
                .iter()
                .filter(|l| {
                    let b = num(&l["blockNumber"]);
                    let topic =
                        |i: usize| l["topics"][i].as_str().unwrap_or_default().to_lowercase();
                    (from..=to).contains(&b)
                        && (addrs.is_empty()
                            || addrs.contains(&l["address"].as_str().unwrap().to_lowercase()))
                        && (t0s.is_empty() || t0s.contains(&topic(0)))
                        && (t1s.is_empty() || t1s.contains(&topic(1)))
                })
                .cloned()
                .collect();
            ok(Value::Array(hits))
        }
        "eth_call" => {
            let to: Address = params[0]["to"].as_str().unwrap().parse().unwrap();
            let data = params[0]
                .get("input")
                .or_else(|| params[0].get("data"))
                .and_then(|d| d.as_str())
                .unwrap();
            let data: Bytes = data.parse().unwrap();
            c.call_blocks.push(params[1].clone());
            match c.calls.get(&(to, data)) {
                Some(r) => ok(json!(r.to_string())),
                None => json!({
                    "jsonrpc": "2.0", "id": req["id"].clone(),
                    "error": { "code": 3, "message": "execution reverted", "data": "0x" }
                }),
            }
        }
        other => panic!("stub RPC got an unexpected method: {other}"),
    }
}

async fn start_stub(chain: Shared) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let chain = chain.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                loop {
                    let mut chunk = [0u8; 8192];
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
                            Value::Array(reqs.iter().map(|r| handle(r, &chain)).collect())
                        }
                        r => handle(r, &chain),
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

async fn client(chain: &Shared) -> ChainClient {
    let url = start_stub(chain.clone()).await;
    let mut c = zkminer_config::ZkMinerConfig::default();
    c.chain.rpc_url = url;
    c.chain.chain_id = CHAIN_ID;
    c.chain.scan_from_block = Some(0);
    // The pacer is not under test here.
    c.chain.max_requests_per_sec = Some(1000);
    c.contracts.hemi_prove = format!("{ROUTER:#x}");
    c.contracts.hemi_prove_registry = format!("{REGISTRY:#x}");
    c.contracts.hemi_prove_staking = format!("{:#x}", Address::repeat_byte(0xbb));
    c.contracts.hemi_token = format!("{:#x}", Address::repeat_byte(0xaa));
    let signer: alloy::signers::local::PrivateKeySigner = KEY.parse().unwrap();
    ChainClient::new(&c, signer).await.unwrap()
}

fn log_json<E: SolEvent>(address: Address, ev: &E, block: u64, index: u64, tx: B256) -> Value {
    let d = ev.encode_log_data();
    json!({
        "address": format!("{address:#x}"),
        "topics": d.topics().iter().map(|t| format!("{t:#x}")).collect::<Vec<_>>(),
        "data": d.data.to_string(),
        "blockNumber": hexu(block),
        "blockHash": format!("{:#x}", B256::left_padding_from(&block.to_be_bytes())),
        "logIndex": hexu(index),
        "transactionHash": format!("{tx:#x}"),
        "transactionIndex": "0x0",
        "removed": false,
    })
}

fn tx_json(hash: B256, from: Address, to: Option<Address>, input: &[u8]) -> Value {
    json!({
        "hash": format!("{hash:#x}"),
        "from": format!("{from:#x}"),
        "to": to.map(|a| format!("{a:#x}")),
        "input": format!("0x{}", alloy::hex::encode(input)),
        "blockNumber": "0x10",
        "nonce": "0x0",
        "value": "0x0",
        "gas": "0x5208",
        "gasPrice": "0x1",
        "type": "0x0",
    })
}

fn ps() -> B256 {
    keccak256("risczero.groth16.v1")
}

fn descriptor(input: &'static [u8]) -> JobDescriptor {
    JobDescriptor {
        programId: B256::repeat_byte(0x42),
        proofSystemId: ps(),
        callbackContract: Address::ZERO,
        assignedProver: Address::ZERO,
        tag: B256::ZERO,
        inputData: Bytes::from_static(input),
        callbackExtraData: Bytes::new(),
        extraVerifierData: Bytes::new(),
        expectedJournalHash: B256::repeat_byte(0x33),
        journalFields: B256::ZERO,
    }
}

/// A job's submit transaction, as the stub records it.
struct Submit<'a> {
    job: B256,
    tx: B256,
    from: Address,
    to: Option<Address>,
    calldata: &'a [u8],
    block: u64,
}

/// Record `s.job` (descriptor `d`) as submitted by `s.tx`, sent by `s.from` to `s.to`.
fn submit(c: &mut Chain, s: Submit<'_>, d: &JobDescriptor) {
    let Submit {
        job,
        tx,
        from,
        to,
        calldata,
        block,
    } = s;
    c.txs.insert(tx, tx_json(tx, from, to, calldata));
    let ev = IHemiProveCore::JobSubmitted {
        jobId: job,
        proofSystemId: d.proofSystemId,
        caller: from,
        programId: d.programId,
        descriptorHash: compute_descriptor_hash(d),
        depositedAmount: U96::from(1u64),
        minPrice: U96::from(1u64),
        maxPrice: U96::from(2u64),
        fulfillmentTimeout: U40::from(600u64),
        trust: 0,
    };
    c.logs.push(log_json(ROUTER, &ev, block, 0, tx));
}

#[tokio::test]
async fn every_descriptor_path_reports_the_submission_form() {
    let chain: Shared = Arc::new(Mutex::new(Chain {
        head: 500,
        ..Default::default()
    }));
    let cl = client(&chain).await;

    // 1. Direct submitJobSimple to the router, found through the monitor's fast path.
    let d1 = descriptor(b"direct");
    let (job1, tx1) = (B256::repeat_byte(0x01), B256::repeat_byte(0xf1));
    let call1 = IHemiProveCore::submitJobSimpleCall {
        descriptor: d1.clone(),
        presetName: B256::ZERO,
    }
    .abi_encode();
    // 2. The same entry point forwarded verbatim by an integrator contract, found by the log scan.
    let d2 = descriptor(b"through a proxy");
    let (job2, tx2) = (B256::repeat_byte(0x02), B256::repeat_byte(0xf2));
    let call2 = IHemiProveCore::submitJobSimpleCall {
        descriptor: d2.clone(),
        presetName: B256::ZERO,
    }
    .abi_encode();
    // 3. Direct submitJobDefault, named by a submit-tx hint.
    let d3 = JobDescriptor {
        callbackContract: Address::repeat_byte(0x0c),
        ..descriptor(b"default entry")
    };
    let (job3, tx3) = (B256::repeat_byte(0x03), B256::repeat_byte(0xf3));
    let call3 = IHemiProveCore::submitJobDefaultCall {
        programId: d3.programId,
        proofSystemId: d3.proofSystemId,
        inputData: d3.inputData.clone(),
        callbackContract: d3.callbackContract,
        expectedJournalHash: d3.expectedJournalHash,
        journalFields: d3.journalFields,
    }
    .abi_encode();
    // 4. Inside the router's multicall: no descriptor to rebuild.
    let (job4, tx4) = (B256::repeat_byte(0x04), B256::repeat_byte(0xf4));
    let mut call4 = vec![0xac, 0x96, 0x50, 0xd8];
    call4.extend_from_slice(&[0u8; 64]);
    {
        let mut c = chain.lock().unwrap();
        let s = |job, tx, from, to, calldata, block| Submit {
            job,
            tx,
            from,
            to,
            calldata,
            block,
        };
        submit(&mut c, s(job1, tx1, ME, Some(ROUTER), &call1, 100), &d1);
        submit(&mut c, s(job2, tx2, OTHER, Some(PROXY), &call2, 101), &d2);
        submit(&mut c, s(job3, tx3, ME, Some(ROUTER), &call3, 102), &d3);
        submit(&mut c, s(job4, tx4, ME, Some(ROUTER), &call4, 103), &d1);
    }

    cl.note_submit_tx(job1, tx1);
    let f1 = fetch_job_descriptor_checked_with_form(&cl, job1, compute_descriptor_hash(&d1))
        .await
        .unwrap();
    assert_eq!(f1.descriptor, d1);
    assert_eq!(
        f1.form,
        SubmissionForm::Direct {
            selector: SubmitEntryPoint::SubmitJobSimple
        }
    );
    assert_eq!((f1.submit_tx, f1.tx_from), (tx1, Some(ME)));
    assert!(
        !chain
            .lock()
            .unwrap()
            .methods
            .contains(&"eth_getLogs".to_string()),
        "the fast path answered without a scan"
    );

    let f2 = fetch_job_descriptor_checked_with_form(&cl, job2, compute_descriptor_hash(&d2))
        .await
        .unwrap();
    assert_eq!(
        f2.descriptor, d2,
        "inline jobs: the proxied descriptor is still served"
    );
    assert_eq!(
        f2.form,
        SubmissionForm::Unsupported {
            reason: UnsupportedSubmission::NotSentToRouter { to: Some(PROXY) }
        }
    );
    assert_eq!(f2.tx_from, Some(OTHER));
    // The plain fetch is unchanged.
    assert_eq!(
        fetch_job_descriptor_checked(&cl, job2, compute_descriptor_hash(&d2))
            .await
            .unwrap(),
        d2
    );
    // The unchecked scan reports it too.
    assert_eq!(
        fetch_job_descriptor_with_form(&cl, job2)
            .await
            .unwrap()
            .form,
        f2.form
    );

    let f3 =
        fetch_job_descriptor_from_submit_tx_with_form(&cl, job3, tx3, compute_descriptor_hash(&d3))
            .await
            .unwrap()
            .expect("the hint is the submit tx");
    assert_eq!(f3.descriptor, d3);
    assert_eq!(
        f3.form,
        SubmissionForm::Direct {
            selector: SubmitEntryPoint::SubmitJobDefault
        }
    );

    // Multicall: refused exactly as before (permanent), on both the old and the new entry point.
    let err = fetch_job_descriptor_checked_with_form(&cl, job4, compute_descriptor_hash(&d1))
        .await
        .unwrap_err();
    assert!(
        err.downcast_ref::<UndecodableDescriptor>().is_some(),
        "{err:#}"
    );
    let err = fetch_job_descriptor_checked(&cl, job4, compute_descriptor_hash(&d1))
        .await
        .unwrap_err();
    assert!(
        err.downcast_ref::<UndecodableDescriptor>().is_some(),
        "{err:#}"
    );
}

fn set_views(
    c: &mut Chain,
    router_paused: bool,
    registry_paused: bool,
    adapter_status: u8,
    switch: (Address, u64),
) {
    let enc_bool = |b: bool| Bytes::from(IHemiProveAux::pausedCall::abi_encode_returns(&b));
    c.calls.insert(
        (ROUTER, IHemiProveAux::pausedCall {}.abi_encode().into()),
        enc_bool(router_paused),
    );
    c.calls.insert(
        (
            REGISTRY,
            IHemiProveRegistry::pausedCall {}.abi_encode().into(),
        ),
        enc_bool(registry_paused),
    );
    c.calls.insert(
        (
            ROUTER,
            IHemiProveRouterGov::pendingUpgradeCall {}
                .abi_encode()
                .into(),
        ),
        IHemiProveRouterGov::pendingUpgradeCall::abi_encode_returns(
            &IHemiProveRouterGov::pendingUpgradeReturn {
                operationHash: B256::ZERO,
                readyAt: U48::ZERO,
            },
        )
        .into(),
    );
    c.calls.insert(
        (
            REGISTRY,
            IHemiProveRegistry::pendingUpgradeCall {}
                .abi_encode()
                .into(),
        ),
        IHemiProveRegistry::pendingUpgradeCall::abi_encode_returns(
            &IHemiProveRegistry::pendingUpgradeReturn {
                opHash: B256::ZERO,
                readyAt: U48::ZERO,
            },
        )
        .into(),
    );
    c.calls.insert(
        (
            REGISTRY,
            IHemiProveRegistry::getAdapterCall {
                proofSystemId: ps(),
            }
            .abi_encode()
            .into(),
        ),
        IHemiProveRegistry::getAdapterCall::abi_encode_returns(&AdapterEntry {
            adapter: ADAPTER,
            status: adapter_status,
            deprecatedAt: U40::ZERO,
            successorId: B256::ZERO,
            defaultCollateralRatio: U96::from(15_000u64),
            minStake: 0,
            feeRateBps: 0,
            cycleAttestationMode: 0,
        })
        .into(),
    );
    c.calls.insert(
        (
            REGISTRY,
            IHemiProveRegistry::pendingReactivationCall {
                proofSystemId: ps(),
            }
            .abi_encode()
            .into(),
        ),
        IHemiProveRegistry::pendingReactivationCall::abi_encode_returns(
            &IHemiProveRegistry::pendingReactivationReturn {
                newAdapter: switch.0,
                readyAt: U40::from(switch.1),
            },
        )
        .into(),
    );
}

fn job_claimed(job: B256, prover: Address) -> IHemiProveCore::JobClaimed {
    IHemiProveCore::JobClaimed {
        jobId: job,
        prover,
        operator: Address::ZERO,
        settledPrice: U96::from(1u64),
        bonusAmount: U96::ZERO,
        lockDeadline: U40::from(9_999u64),
    }
}

#[tokio::test]
async fn the_governance_watcher_syncs_polls_in_bounded_ranges_and_broadcasts_aborts() {
    let chain: Shared = Arc::new(Mutex::new(Chain {
        head: 1_000,
        ..Default::default()
    }));
    let (job_bid, job_old_claim, job_cancel, job_live, job_mine) = (
        B256::repeat_byte(0xa1),
        B256::repeat_byte(0xa2),
        B256::repeat_byte(0xa3),
        B256::repeat_byte(0xa4),
        B256::repeat_byte(0xa5),
    );
    let tx = B256::repeat_byte(0xee);
    {
        let mut c = chain.lock().unwrap();
        set_views(&mut c, false, false, 1, (Address::ZERO, 0));
        // History inside the look-back.
        let bid = IHemiProveAux::BidSubmitted {
            jobId: job_bid,
            bidder: OTHER,
            bidAmount: U96::from(1u64),
            newBidDeadline: U40::from(1u64),
            operator: Address::ZERO,
            previousBidder: Address::ZERO,
        };
        c.logs.push(log_json(ROUTER, &bid, 950, 0, tx));
        c.logs.push(log_json(
            ROUTER,
            &job_claimed(job_old_claim, OTHER),
            960,
            0,
            tx,
        ));
        let cancel = IHemiProveFulfill::JobCancelled {
            jobId: job_cancel,
            caller: OTHER,
            refundAmount: U256::from(1u64),
            bonusBurned: U256::ZERO,
        };
        c.logs.push(log_json(ROUTER, &cancel, 970, 0, tx));
        // A pause that was lifted before the head: the views at the head agree it is lifted.
        c.logs.push(log_json(
            ROUTER,
            &IHemiProveAux::Paused { account: OTHER },
            980,
            0,
            tx,
        ));
        c.logs.push(log_json(
            ROUTER,
            &IHemiProveAux::Unpaused { account: OTHER },
            990,
            0,
            tx,
        ));
    }
    let cl = client(&chain).await;
    let mut cfg = GovernanceConfig::new(ME, vec![ps()]);
    cfg.chunk_blocks = 40;
    cfg.max_chunks_per_poll = 2;
    let watcher = GovernanceWatcher::new(cl.clone(), cfg);
    let view = watcher.view();
    assert_eq!(view.sync_refusal(), Some(GateRefusal::NotSynced));
    assert!(
        watcher.poll_once().await.is_err(),
        "no poll before the start-up read"
    );

    assert_eq!(watcher.init().await.unwrap(), 1_000);
    assert_eq!(view.sync_refusal(), None);
    assert_eq!(view.scanned_through(), Some(1_000));
    assert!(view.bid_submitted(job_bid));
    assert_eq!(
        view.abort_reason(job_cancel),
        Some(AbortReason::Cancelled { caller: OTHER })
    );
    assert_eq!(
        view.abort_reason(job_old_claim),
        None,
        "a historical claim is not an abort"
    );
    assert!(!view.paused());
    assert_eq!(view.hold(ps()), None);
    {
        let c = chain.lock().unwrap();
        // Every view read at the one block the logs were read up to.
        assert_eq!(c.call_blocks.len(), 6);
        assert!(
            c.call_blocks.iter().all(|b| b == &json!(hexu(1_000))),
            "{:?}",
            c.call_blocks
        );
        // The look-back: bounded ranges covering [0, 1000], both contracts, every watched topic.
        let q = &c.log_queries;
        assert_eq!(q.first().unwrap().0, 0);
        assert_eq!(q.last().unwrap().1, 1_000);
        assert!(q.iter().all(|(f, t, _, _)| t - f < 40));
        for w in q.windows(2) {
            assert_eq!(w[1].0, w[0].1 + 1, "contiguous");
        }
        let addrs = &q[0].2;
        assert!(
            addrs.contains(&format!("{ROUTER:#x}")) && addrs.contains(&format!("{REGISTRY:#x}"))
        );
        assert_eq!(
            q[0].3.len(),
            zkminer_chain::governance::governance_topics().len()
        );
    }

    // Live events.
    let mut aborts = view.subscribe_aborts();
    {
        let mut c = chain.lock().unwrap();
        c.logs.push(log_json(
            REGISTRY,
            &IHemiProveRegistry::Paused { account: OTHER },
            1_005,
            0,
            tx,
        ));
        c.logs.push(log_json(
            ROUTER,
            &job_claimed(job_live, OTHER),
            1_010,
            0,
            tx,
        ));
        c.logs
            .push(log_json(ROUTER, &job_claimed(job_mine, ME), 1_011, 0, tx));
        c.logs.push(log_json(
            REGISTRY,
            &IHemiProveRegistry::AdapterDisabledEvent {
                proofSystemId: ps(),
            },
            1_015,
            0,
            tx,
        ));
        c.logs.push(log_json(
            REGISTRY,
            &IHemiProveRegistry::VerifierSwitchProposed {
                proofSystemId: ps(),
                newAdapter: OTHER,
                readyAt: U40::from(5_000u64),
            },
            1_015,
            1,
            tx,
        ));
        c.logs.push(log_json(
            ROUTER,
            &IHemiProveRouterGov::UpgradeProposed {
                operationHash: B256::repeat_byte(0x0b),
                readyAt: U48::from(9_000u64),
            },
            1_090,
            0,
            tx,
        ));
        c.head = 1_100;
        c.log_queries.clear();
        c.methods.clear();
    }
    // The monitor's head.
    cl.set_head_block(1_100);
    let o = watcher.poll_once().await.unwrap();
    assert_eq!(
        (o.head, o.scanned_through, o.aborts),
        (1_100, 1_080, 1),
        "two ranges of 40"
    );
    assert_eq!(
        aborts.try_recv().unwrap(),
        AbortSimulation {
            job_id: job_live,
            reason: AbortReason::ClaimedByOther { prover: OTHER },
            block: Some(1_010)
        }
    );
    assert!(aborts.try_recv().is_err(), "our own claim aborts nothing");
    assert!(view.paused());
    assert_eq!(view.hold(ps()), Some(GateRefusal::RegistryPaused));
    assert!(view.verifier_switch_ready_before(ps(), 5_000));
    assert!(!view.verifier_switch_ready_before(ps(), 4_999));
    assert!(view.adapter_disabled(ps()));
    assert!(
        !view.upgrade_ready_before(u64::MAX),
        "block 1090 not scanned yet"
    );
    let o = watcher.poll_once().await.unwrap();
    assert_eq!(o.scanned_through, 1_100);
    assert!(view.upgrade_ready_before(9_000));
    {
        let c = chain.lock().unwrap();
        assert_eq!(
            c.log_queries.iter().map(|q| (q.0, q.1)).collect::<Vec<_>>(),
            vec![(1_001, 1_040), (1_041, 1_080), (1_081, 1_100)]
        );
        assert!(
            !c.methods.contains(&"eth_blockNumber".to_string()),
            "the monitor's cached head was used: {:?}",
            c.methods
        );
    }
    assert_eq!(
        view.witness_lock_gate(job_live, ps(), 10_000),
        Err(GateRefusal::RegistryPaused)
    );

    // Unpause and the swap lands: the gate then only refuses on the pending upgrade.
    {
        let mut c = chain.lock().unwrap();
        c.logs.push(log_json(
            REGISTRY,
            &IHemiProveRegistry::Unpaused { account: OTHER },
            1_150,
            0,
            tx,
        ));
        c.logs.push(log_json(
            REGISTRY,
            &IHemiProveRegistry::AdapterReactivated {
                proofSystemId: ps(),
                adapter: OTHER,
            },
            1_160,
            0,
            tx,
        ));
        c.head = 1_200;
    }
    cl.set_head_block(1_200);
    while view.scanned_through() < Some(1_200) {
        watcher.poll_once().await.unwrap();
    }
    assert!(!view.paused());
    assert!(!view.adapter_disabled(ps()));
    assert!(!view.verifier_switch_ready_before(ps(), u64::MAX));
    assert!(!view.adapter_address_disabled(ADAPTER) && !view.adapter_address_disabled(OTHER));
    assert_eq!(
        view.witness_lock_gate(job_live, ps(), 10_000),
        Err(GateRefusal::Upgrade {
            contract: zkminer_chain::governance::GovContract::Router,
            ready_at: 9_000
        })
    );
    assert_eq!(view.witness_lock_gate(job_live, ps(), 8_999), Ok(()));
    assert!(matches!(
        view.witness_lock_gate(job_bid, ps(), 8_999),
        Err(GateRefusal::Aborted(AbortReason::BidSubmitted { .. }))
    ));
}

/// A state change no log announced (a provider that dropped a log) is corrected by the periodic
/// view resync, read at the block the logs are applied through.
#[tokio::test]
async fn a_resync_corrects_state_no_log_announced() {
    let chain: Shared = Arc::new(Mutex::new(Chain {
        head: 300,
        ..Default::default()
    }));
    set_views(&mut chain.lock().unwrap(), true, false, 3, (OTHER, 7_000));
    let cl = client(&chain).await;
    let mut cfg = GovernanceConfig::new(ME, vec![ps()]);
    cfg.resync_interval = Duration::ZERO;
    let watcher = GovernanceWatcher::new(cl.clone(), cfg);
    let view = watcher.view();
    watcher.init().await.unwrap();
    // From the views alone (no logs at all).
    assert!(view.paused());
    assert!(view.adapter_disabled(ps()));
    assert!(view.adapter_address_disabled(ADAPTER));
    assert!(view.verifier_switch_ready_before(ps(), 7_000));

    {
        let mut c = chain.lock().unwrap();
        set_views(&mut c, false, false, 1, (Address::ZERO, 0));
        c.head = 310;
        c.call_blocks.clear();
    }
    cl.set_head_block(310);
    watcher.poll_once().await.unwrap();
    assert!(!view.paused());
    assert!(!view.adapter_disabled(ps()));
    assert!(!view.verifier_switch_ready_before(ps(), u64::MAX));
    let c = chain.lock().unwrap();
    assert!(!c.call_blocks.is_empty() && c.call_blocks.iter().all(|b| b == &json!(hexu(310))));
}

/// The start-up read refuses a partial picture: a view that does not read fails init (the watcher
/// stays NotSynced and `run` retries), rather than starting from a guess.
#[tokio::test]
async fn init_fails_when_a_view_does_not_read() {
    let chain: Shared = Arc::new(Mutex::new(Chain {
        head: 300,
        ..Default::default()
    }));
    set_views(
        &mut chain.lock().unwrap(),
        false,
        false,
        1,
        (Address::ZERO, 0),
    );
    chain.lock().unwrap().calls.remove(&(
        REGISTRY,
        IHemiProveRegistry::pausedCall {}.abi_encode().into(),
    ));
    let cl = client(&chain).await;
    let watcher = GovernanceWatcher::new(cl, GovernanceConfig::new(ME, vec![ps()]));
    assert!(watcher.init().await.is_err());
    assert_eq!(watcher.view().sync_refusal(), Some(GateRefusal::NotSynced));
}
