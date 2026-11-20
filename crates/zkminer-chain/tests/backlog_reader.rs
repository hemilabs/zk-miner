//! Chainless test of `da::BacklogReader` (witness-construction-jobs §13.5).
//!
//! A loopback JSON-RPC stub serves a small chain — headers by number and by the `latest` / `safe`
//! tags, and `eth_getBlockReceipts` with OP Stack receipts — and counts every request, so the REAL
//! reader runs against controlled chain state with no node: the sum over (safe, head], the per-block
//! cache (a second reading fetches only new blocks), reorg handling, the scan cap and an endpoint
//! whose receipts carry no `l1GasUsed`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy::primitives::{address, keccak256, Address, B256};
use alloy::signers::local::PrivateKeySigner;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use zkminer_chain::client::ChainClient;
use zkminer_chain::da::{Backlog, BacklogConfig, BacklogReader};

const CHAIN_ID: u64 = 743111;

/// The stub's chain: blocks `0..=head`, each hash derived from `(number, fork[number])`.
struct Chain {
    head: u64,
    safe: u64,
    /// A block's "fork id": changing it for a range of blocks reorgs them (new hashes).
    fork: HashMap<u64, u64>,
    /// Blocks whose user receipt carries no `l1GasUsed` (an endpoint that is not op-geth).
    no_l1_gas: Vec<u64>,
    /// Requests served, by method.
    calls: HashMap<String, u64>,
    /// Block numbers whose receipts were requested, in order.
    receipts_for: Vec<u64>,
}

impl Chain {
    fn hash(&self, n: u64) -> B256 {
        let f = self.fork.get(&n).copied().unwrap_or(0);
        keccak256(format!("block {n} fork {f}"))
    }

    /// Estimated DA bytes of the user transaction in block `n` (fork-dependent, so a reorg shows).
    fn user_bytes(&self, n: u64) -> u64 {
        100 + (n % 7) * 10 + self.fork.get(&n).copied().unwrap_or(0) * 1_000
    }

    fn header(&self, n: u64) -> Value {
        let z = format!("{:#x}", B256::ZERO);
        json!({
            "hash": format!("{:#x}", self.hash(n)),
            "parentHash": format!("{:#x}", if n == 0 { B256::ZERO } else { self.hash(n - 1) }),
            "sha3Uncles": z, "miner": format!("{:#x}", Address::ZERO), "stateRoot": z,
            "transactionsRoot": z, "receiptsRoot": z,
            "logsBloom": format!("0x{}", "00".repeat(256)),
            "difficulty": "0x0", "number": format!("0x{n:x}"), "gasLimit": "0x1c9c380",
            "gasUsed": "0x0", "timestamp": format!("0x{:x}", 1_800_000_000 + 12 * n),
            "extraData": "0x", "mixHash": z, "nonce": "0x0000000000000000",
            "baseFeePerGas": "0xfe", "transactions": [], "uncles": [],
        })
    }

    fn receipts(&self, n: u64) -> Value {
        let h = format!("{:#x}", self.hash(n));
        let num = format!("0x{n:x}");
        let mut user = json!({"type": "0x2", "blockNumber": num, "blockHash": h});
        if !self.no_l1_gas.contains(&n) {
            user["l1GasUsed"] = json!(format!("0x{:x}", self.user_bytes(n) * 16));
        }
        json!([
            {"type": "0x7e", "blockNumber": num, "blockHash": h},
            user,
            // A PoP payout: skipped whatever it carries.
            {"type": "0x7d", "blockNumber": num, "blockHash": h, "l1GasUsed": "0xffff"},
        ])
    }
}

fn handle(req: &Value, c: &Arc<Mutex<Chain>>) -> Value {
    let method = req["method"].as_str().unwrap_or_default().to_string();
    let params = &req["params"];
    let mut c = c.lock().unwrap();
    *c.calls.entry(method.clone()).or_default() += 1;
    let block_of = |tag: &str, c: &Chain| -> Option<u64> {
        match tag {
            "latest" | "pending" => Some(c.head),
            "safe" => Some(c.safe),
            t => u64::from_str_radix(t.trim_start_matches("0x"), 16).ok(),
        }
    };
    let result: Value = match method.as_str() {
        "eth_chainId" => json!(format!("0x{:x}", CHAIN_ID)),
        "eth_blockNumber" => json!(format!("0x{:x}", c.head)),
        "eth_getBlockByNumber" => match block_of(params[0].as_str().unwrap_or("latest"), &c) {
            Some(n) if n <= c.head => c.header(n),
            _ => Value::Null,
        },
        "eth_getBlockReceipts" => {
            let n = block_of(params[0].as_str().unwrap(), &c).unwrap();
            c.receipts_for.push(n);
            c.receipts(n)
        }
        other => panic!("stub RPC got an unexpected method: {other}"),
    };
    json!({ "jsonrpc": "2.0", "id": req["id"].clone(), "result": result })
}

async fn start_stub(chain: Arc<Mutex<Chain>>) -> String {
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

fn config(rpc_url: &str) -> zkminer_config::ZkMinerConfig {
    let mut c = zkminer_config::ZkMinerConfig::default();
    c.chain.rpc_url = rpc_url.to_string();
    c.chain.chain_id = CHAIN_ID;
    c.chain.max_requests_per_sec = Some(1_000);
    let a = |x: Address| format!("{x:#x}");
    c.contracts.hemi_prove = a(address!("00000000000000000000000000000000000000CC"));
    c.contracts.hemi_prove_staking = a(address!("00000000000000000000000000000000000000BB"));
    c.contracts.hemi_prove_registry = a(address!("00000000000000000000000000000000000000DD"));
    c.contracts.hemi_token = a(address!("00000000000000000000000000000000000000AA"));
    c
}

async fn setup(head: u64, safe: u64) -> (Arc<Mutex<Chain>>, ChainClient) {
    let chain = Arc::new(Mutex::new(Chain {
        head,
        safe,
        fork: HashMap::new(),
        no_l1_gas: Vec::new(),
        calls: HashMap::new(),
        receipts_for: Vec::new(),
    }));
    let url = start_stub(chain.clone()).await;
    let client = ChainClient::new(&config(&url), PrivateKeySigner::random())
        .await
        .expect("client on the stub");
    (chain, client)
}

fn expected(chain: &Chain) -> u64 {
    (chain.safe + 1..=chain.head)
        .map(|n| chain.user_bytes(n))
        .sum()
}

#[tokio::test]
async fn sums_the_unposted_window_and_reads_each_block_once() {
    let (chain, client) = setup(1_000, 990).await;
    let reader = BacklogReader::default();
    let r = reader.read(&client).await;
    let want = expected(&chain.lock().unwrap());
    assert_eq!(r.backlog, Backlog::Known(want), "{r:?}");
    assert_eq!(r.chain_bytes, Some(want));
    assert_eq!(
        (r.head, r.safe, r.safe_lag_secs),
        (Some(1_000), Some(990), Some(120))
    );
    assert_eq!(r.blocks_fetched, 10);
    assert_eq!(
        chain.lock().unwrap().receipts_for,
        (991..=1_000).collect::<Vec<_>>()
    );

    // The head moves 3 blocks and the safe head 2: only the 3 new blocks are fetched.
    {
        let mut c = chain.lock().unwrap();
        c.head = 1_003;
        c.safe = 992;
        c.receipts_for.clear();
    }
    let r = reader.read(&client).await;
    let want = expected(&chain.lock().unwrap());
    assert_eq!(r.backlog, Backlog::Known(want), "{r:?}");
    assert_eq!(r.blocks_fetched, 3);
    assert_eq!(
        chain.lock().unwrap().receipts_for,
        vec![1_001, 1_002, 1_003]
    );

    // Nothing new: no receipts at all, and two header reads (head, safe).
    let before = chain.lock().unwrap().calls.clone();
    let r = reader.read(&client).await;
    assert_eq!(r.backlog, Backlog::Known(want));
    assert_eq!(r.blocks_fetched, 0);
    let after = chain.lock().unwrap().calls.clone();
    assert_eq!(
        after.get("eth_getBlockReceipts"),
        before.get("eth_getBlockReceipts")
    );
    assert_eq!(
        after["eth_getBlockByNumber"] - before["eth_getBlockByNumber"],
        2,
        "a reading with nothing new costs the two headers"
    );

    // This key's own unmined fulfils count too.
    client
        .da_book()
        .note_accepted(B256::repeat_byte(1), 5, 1_400, 1_003);
    let r = reader.read(&client).await;
    assert_eq!(r.own_unmined_bytes, 1_400);
    assert_eq!(r.backlog, Backlog::Known(want + 1_400));
}

#[tokio::test]
async fn a_reorg_drops_the_cache() {
    let (chain, client) = setup(1_000, 990).await;
    let reader = BacklogReader::default();
    reader.read(&client).await;
    // Blocks 998.. are replaced (new hashes, new contents), and the head moves on to 1,001.
    {
        let mut c = chain.lock().unwrap();
        for n in 998..=1_001 {
            c.fork.insert(n, 1);
        }
        c.head = 1_001;
        c.receipts_for.clear();
    }
    let r = reader.read(&client).await;
    let want = expected(&chain.lock().unwrap());
    assert_eq!(
        r.backlog,
        Backlog::Known(want),
        "the reorged contents count: {r:?}"
    );
    // The new block did not extend the cached 1,000: the whole window was re-read.
    assert_eq!(
        chain.lock().unwrap().receipts_for,
        (991..=1_001).collect::<Vec<_>>()
    );

    // The head itself replaced at the same height: also re-read.
    {
        let mut c = chain.lock().unwrap();
        c.fork.insert(1_001, 2);
        c.receipts_for.clear();
    }
    let r = reader.read(&client).await;
    assert_eq!(r.backlog, Backlog::Known(expected(&chain.lock().unwrap())));
    assert_eq!(
        chain.lock().unwrap().receipts_for,
        (991..=1_001).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_long_lag_or_a_non_op_endpoint_reads_as_unknown() {
    // More unposted blocks than the cap: unknown, and nothing scanned.
    let (chain, client) = setup(1_000, 800).await;
    let reader = BacklogReader::new(BacklogConfig { max_blocks: 150 });
    let r = reader.read(&client).await;
    assert_eq!(r.backlog, Backlog::Unknown);
    assert!(r.note.as_deref().unwrap().contains("scan cap"), "{r:?}");
    assert_eq!(r.safe_lag_secs, Some(2_400), "the lag is still reported");
    assert!(chain.lock().unwrap().receipts_for.is_empty());

    // A user receipt without l1GasUsed (anvil, a non-OP node): unknown.
    let (chain, client) = setup(1_000, 990).await;
    chain.lock().unwrap().no_l1_gas.push(995);
    let r = BacklogReader::default().read(&client).await;
    assert_eq!(r.backlog, Backlog::Unknown);
    assert!(r.note.as_deref().unwrap().contains("l1GasUsed"), "{r:?}");
}
