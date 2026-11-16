//! Shared helpers for the broker's integration tests.
#![allow(dead_code)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy_primitives::{Address, B256};
use serde_json::{json, Value};
use zkminer_witness::ipc::JobBudget;
use zkminer_witness::manifest::{chunk_runtime_code, creation_code, manifest_runtime_code, sha256};
use zkminer_witness_broker::client::{job_socketpair, BrokerClient, JobRegistration};
use zkminer_witness_broker::testkit::{spawn_broker, FakeBuilder, TestRequest, TestResponse};
use zkminer_witness_broker::egress::NetMode;
use zkminer_witness_broker::{BrokerConfig, Hooks};

pub fn budget(max_fetches: u32, max_fetch_bytes: u64, max_response_bytes: u32) -> JobBudget {
    JobBudget { max_fetches, max_fetch_bytes, max_request_bytes: 65_536, max_response_bytes }
}

/// Starts an in-process broker in developer mode: these tests' endpoints are servers on
/// 127.0.0.1, which only developer mode admits (the miner's `[dev] private_network`).
pub async fn start(dir: &Path, text: &str, hooks: Hooks) -> (BrokerClient, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let cfg = BrokerConfig::from_toml(text, dir, NetMode::DevPrivate).expect("test config");
    spawn_broker(cfg, hooks).await
}

/// Registers a job and returns the builder's end of its socket.
pub async fn register(
    client: &BrokerClient,
    key: u8,
    sources: Vec<(B256, Vec<u8>)>,
    budget: JobBudget,
    held_lock: bool,
) -> FakeBuilder {
    let (builder, broker_end) = job_socketpair().unwrap();
    client
        .register_job(
            JobRegistration { job_key: B256::repeat_byte(key), caller: Address::repeat_byte(0xca), sources, budget, held_lock },
            broker_end,
        )
        .await
        .expect("registered");
    FakeBuilder::new(builder, budget.max_response_bytes)
}

/// An `eth_chainId`-only JSON-RPC node.
pub fn chain_id_node(chain_id: u64) -> impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static {
    move |req| {
        let v: Value = serde_json::from_slice(&req.body).unwrap_or_default();
        let id = v.get("id").cloned().unwrap_or(Value::Null);
        TestResponse::ok(serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":format!("{chain_id:#x}")})).unwrap())
    }
}

// ---------------------------------------------------------------------------------------------
// anvil

/// anvil's first default dev account (unlocked: anvil signs its transactions).
pub const DEV: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

/// An anvil process, killed by pid when dropped.
pub struct Anvil {
    child: Child,
    pub port: u16,
    pub url: String,
    http: reqwest::Client,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

impl Anvil {
    pub async fn start(extra: &[&str]) -> Self {
        for _ in 0..5 {
            let port = free_port();
            let child = Command::new("anvil")
                .args(["--port", &port.to_string(), "--silent"])
                .args(extra)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("anvil 1.7.1 on PATH");
            let mut a = Anvil { child, port, url: format!("http://127.0.0.1:{port}"), http: reqwest::Client::new() };
            for _ in 0..100 {
                if a.try_rpc("eth_chainId", json!([])).await.is_some() {
                    return a;
                }
                if a.child.try_wait().unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            // Port taken or anvil failed: dropping `a` kills it; try another port.
        }
        panic!("anvil did not start");
    }

    async fn try_rpc(&self, method: &str, params: Value) -> Option<Value> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let r = self
            .http
            .post(&self.url)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap())
            .send()
            .await
            .ok()?;
        serde_json::from_slice(&r.bytes().await.ok()?).ok()
    }

    pub async fn rpc(&self, method: &str, params: Value) -> Value {
        let v = self.try_rpc(method, params).await.expect("anvil answers");
        assert!(v.get("error").is_none(), "{method}: {v}");
        v["result"].clone()
    }

    pub async fn block_number(&self) -> u64 {
        let s = self.rpc("eth_blockNumber", json!([])).await;
        u64::from_str_radix(s.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    }

    pub async fn tag_number(&self, tag: &str) -> u64 {
        let b = self.rpc("eth_getBlockByNumber", json!([tag, false])).await;
        u64::from_str_radix(b["number"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    }

    pub async fn mine(&self, blocks: u64) {
        self.rpc("anvil_mine", json!([format!("{blocks:#x}")])).await;
    }

    /// Deploys `runtime` verbatim with [`creation_code`], signed by anvil for [`DEV`].
    pub async fn deploy(&self, runtime: &[u8]) -> Address {
        let data = format!("0x{}", hex::encode(creation_code(runtime)));
        let tx = self.rpc("eth_sendTransaction", json!([{"from": DEV, "data": data}])).await;
        // anvil mines it at once, but its receipt can lag the answer by a moment.
        for _ in 0..100 {
            let receipt = self.rpc("eth_getTransactionReceipt", json!([tx])).await;
            if !receipt.is_null() {
                assert_eq!(receipt["status"], "0x1", "deployment succeeded");
                return receipt["contractAddress"].as_str().unwrap().parse().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no receipt for {tx}");
    }

    /// Overwrites the code at `address` (`anvil_setCode`), e.g. with an `0xef`-prefixed body that
    /// EIP-3541 forbids deploying.
    pub async fn set_code(&self, address: Address, code: &[u8]) {
        self.rpc("anvil_setCode", json!([address.to_string(), format!("0x{}", hex::encode(code))])).await;
    }

    pub async fn code(&self, address: Address) -> Vec<u8> {
        let s = self.rpc("eth_getCode", json!([address.to_string(), "latest"])).await;
        hex::decode(s.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }
}

/// A published artifact.
pub struct Published {
    pub manifest: Address,
    pub sha256: B256,
    pub chunks: Vec<Address>,
    pub bytes: Vec<u8>,
}

/// Publishes `bytes` as `hemi-code`: chunks of `chunk` bytes, then the manifest.
pub async fn publish(anvil: &Anvil, bytes: &[u8], chunk: usize) -> Published {
    let mut chunks = Vec::new();
    for c in bytes.chunks(chunk) {
        chunks.push(anvil.deploy(&chunk_runtime_code(c)).await);
    }
    let sha = sha256(bytes);
    let manifest = anvil.deploy(&manifest_runtime_code(bytes.len() as u64, &sha, &chunks)).await;
    Published { manifest, sha256: B256::from(sha), chunks, bytes: bytes.to_vec() }
}

/// Deterministic test bytes.
pub fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u32).wrapping_mul(2_654_435_761).to_be_bytes()[0] ^ seed).collect()
}
