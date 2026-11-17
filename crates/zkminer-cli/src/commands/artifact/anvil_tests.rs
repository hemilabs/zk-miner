//! `zkminer artifact publish` against a local anvil (one block a second, so the pacing gate, the
//! stuck-chunk detection and the safe-head wait all run as on a real chain): mock router and staking
//! contracts, and a mock `GasPriceOracle` at the predeploy address. Skipped when anvil is not on
//! PATH, unless `ZKMINER_ANVIL_TESTS_REQUIRED` is set.

use std::io::Write;
use std::os::fd::FromRawFd;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::primitives::{Address, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use serde_json::{json, Value};
use zkminer_config::ZkMinerConfig;

use super::test_contracts::{join, MOCK_GAS_PRICE_ORACLE_RUNTIME, MOCK_ROUTER, MOCK_STAKING};
use super::*;

/// anvil's first dev account (unlocked): deploys and drives the mocks.
const DEV: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
/// anvil's second dev key: the publisher's, in a keystore.
const PUBLISHER_KEY: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

struct Anvil {
    child: Child,
    url: String,
    http: alloy::transports::http::reqwest::Client,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        // By pid, never by name.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn anvil_on_path() -> bool {
    let found = Command::new("anvil").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok();
    if !found && std::env::var_os("ZKMINER_ANVIL_TESTS_REQUIRED").is_some() {
        panic!("anvil is not on PATH");
    }
    if !found {
        let _ = writeln!(std::io::stderr(), "SKIPPED: anvil is not on PATH");
    }
    found
}

impl Anvil {
    async fn start() -> Self {
        for _ in 0..5 {
            let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
            let child = Command::new("anvil")
                .args(["--port", &port.to_string(), "--block-time", "1", "--silent"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("anvil runs");
            let mut a = Anvil { child, url: format!("http://127.0.0.1:{port}"), http: Default::default() };
            for _ in 0..100 {
                if a.try_rpc("eth_chainId", json!([])).await.is_some() {
                    return a;
                }
                if a.child.try_wait().unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        panic!("anvil did not start");
    }

    async fn try_rpc(&self, method: &str, params: Value) -> Option<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let r = self.http.post(&self.url).json(&body).send().await.ok()?;
        r.json().await.ok()
    }

    async fn rpc(&self, method: &str, params: Value) -> Value {
        let v = self.try_rpc(method, params).await.expect("anvil answers");
        assert!(v.get("error").is_none(), "{method}: {v}");
        v["result"].clone()
    }

    async fn receipt(&self, tx: &Value) -> Value {
        for _ in 0..100 {
            let r = self.rpc("eth_getTransactionReceipt", json!([tx])).await;
            if !r.is_null() {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("no receipt for {tx}");
    }

    async fn deploy(&self, creation_hex: &str) -> Address {
        let tx = self.rpc("eth_sendTransaction", json!([{"from": DEV, "data": format!("0x{creation_hex}")}])).await;
        let r = self.receipt(&tx).await;
        assert_eq!(r["status"], "0x1");
        r["contractAddress"].as_str().unwrap().parse().unwrap()
    }

    async fn call_from_dev(&self, to: Address, data: Vec<u8>) {
        let tx = self
            .rpc("eth_sendTransaction", json!([{"from": DEV, "to": format!("{to:#x}"), "data": format!("0x{}", alloy::hex::encode(data))}]))
            .await;
        assert_eq!(self.receipt(&tx).await["status"], "0x1");
    }

    async fn nonce(&self, a: Address) -> u64 {
        qty(&self.rpc("eth_getTransactionCount", json!([format!("{a:#x}"), "latest"])).await).unwrap() as u64
    }
}

alloy::sol! {
    interface IMocks {
        function setStake(address p, uint128 a) external;
        function authorize(address prover, address operator) external;
        function revokeAllOperators(address prover) external;
    }
}

/// anvil with the mocks: returns it, the router and the staking contract.
async fn chain() -> (Anvil, Address, Address) {
    let a = Anvil::start().await;
    let staking = a.deploy(&join(MOCK_STAKING)).await;
    let router = a.deploy(&format!("{}{}", join(MOCK_ROUTER), alloy::hex::encode(B256::left_padding_from(staking.as_slice())))).await;
    a.rpc(
        "anvil_setCode",
        json!([format!("{:#x}", zkminer_contracts::bindings::GAS_PRICE_ORACLE), format!("0x{}", join(MOCK_GAS_PRICE_ORACLE_RUNTIME))]),
    )
    .await;
    (a, router, staking)
}

/// The publisher's keystore (password `pw`), in `dir`.
fn keystore(dir: &Path) -> (PathBuf, Address) {
    let key: B256 = PUBLISHER_KEY.parse().unwrap();
    // The file is named by the name given (the returned string is the keystore's UUID).
    let (signer, _uuid) = PrivateKeySigner::encrypt_keystore(dir, &mut rand::thread_rng(), key, "pw", Some("publisher")).unwrap();
    (dir.join("publisher"), signer.address())
}

/// A pipe holding the password, its read end for `--password-fd`.
fn password_fd() -> i32 {
    let mut fds = [0i32; 2];
    // SAFETY: a valid array of two fds.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: the write end is ours.
    let mut w = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    w.write_all(b"pw\n").unwrap();
    fds[0]
}

/// A developer-mode configuration for anvil's chain, with a fixed DA backlog (anvil's receipts
/// carry no `l1GasUsed`).
fn dev_config() -> ZkMinerConfig {
    let mut c = ZkMinerConfig::default();
    c.chain.chain_id = 31337;
    c.chain.rpc_url = "http://chain-rpc.invalid:8545".into();
    c.dev.private_network = true;
    c.dev.chain_id = Some(31337);
    c.dev.da_backlog_bytes = Some(0);
    c
}

/// A WASM module of about `n` bytes (a data segment of incompressible bytes).
fn builder_wasm(n: usize) -> Vec<u8> {
    let data = zkminer_chain::da::incompressible(n, b"artifact-publish-test");
    let escaped: String = data.iter().map(|b| format!("\\{b:02x}")).collect();
    wat::parse_str(format!(
        r#"(module (memory (export "memory") 2) (data (i32.const 0) "{escaped}") (func (export "run") (result i32) i32.const 0))"#
    ))
    .unwrap()
}

/// Each publication in a test is bounded: a wait that never ends is a failure, not a hang.
async fn bounded<T>(f: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(240), f).await.unwrap_or_else(|_| Err(anyhow::anyhow!("timed out")))
}

fn options(file: PathBuf, url: &str, keystore: PathBuf, router: Address) -> PublishOptions {
    PublishOptions {
        file,
        kind: Kind::Builder,
        rpc_url: url.to_string(),
        verify_rpc_url: None,
        chain_id: 31337,
        keystore,
        password_fd: Some(keys::take_password_fd(password_fd()).unwrap()),
        router: Some(router),
        from_block: Some(0),
        tip_wei: None,
        max_requests_per_sec: 1000,
        block_time_ms: None,
        progress: None,
        yes: true,
        json: true,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publishes_paced_chunks_redeploys_a_failed_creation_and_reads_them_back() {
    if !anvil_on_path() {
        return;
    }
    let (a, router, _) = chain().await;
    let dir = tempfile::tempdir().unwrap();
    let (ks, me) = keystore(dir.path());
    let wasm = builder_wasm(50_000);
    let file = dir.path().join("b.wasm");
    std::fs::write(&file, &wasm).unwrap();
    let start = a.nonce(me).await;
    // The first creation runs out of gas (enough for the intrinsic cost and the calldata floor, not
    // for the code deposit): the nonce is spent and the chunk deployed again.
    let faults = Faults { first_gas_limit: Some(2_000_000), ..Default::default() };
    let p = bounded(publish_with(&dev_config(), options(file, &a.url, ks, router), faults)).await.unwrap();
    assert_eq!(p.length, wasm.len());
    assert_eq!(p.chunks.len(), 3, "50 KB in chunks below the 19,500-byte DA cap");
    assert!(p.chunks.iter().all(|c| c.body_bytes <= plan::DEFAULT_CHUNK_BYTES));
    assert_eq!(p.chunks[0].redeploys, 1);
    assert_eq!(p.chunks[0].nonce, start + 1, "the failed creation spent nonce {start}");
    assert_eq!(p.builder_id, Some(B256::from(zkminer_witness::manifest::sha256(&wasm))));
    // Each chunk at most one per block, in order, and the manifest last.
    let blocks: Vec<u64> = p.chunks.iter().chain([&p.manifest]).map(|d| d.block_number).collect();
    assert!(blocks.windows(2).all(|w| w[0] < w[1]), "{blocks:?}");
    // The locator, and the manifest as the chain holds it.
    let loc = HemiCodeLocator::parse(&p.locator).unwrap();
    assert_eq!(loc.manifest, p.manifest.address);
    let code = data(&a.rpc("eth_getCode", json!([format!("{:#x}", p.manifest.address), "latest"])).await).unwrap();
    let m = parse_manifest(&code, p.manifest.address, 1 << 30, Some(&zkminer_witness::manifest::sha256(&wasm))).unwrap();
    assert_eq!(m.chunks, p.chunks.iter().map(|c| c.address).collect::<Vec<_>>());
    // Every deploying block is at or below the safe head now.
    let safe = qty(&a.rpc("eth_getBlockByNumber", json!(["safe", false])).await["number"]).unwrap() as u64;
    assert!(blocks.iter().all(|b| *b <= safe));
    assert!(p.total_cost_wei.parse::<U256>().unwrap() > U256::ZERO);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chunk_that_never_mines_is_replaced_at_its_nonce() {
    if !anvil_on_path() {
        return;
    }
    let (a, router, _) = chain().await;
    let dir = tempfile::tempdir().unwrap();
    let (ks, me) = keystore(dir.path());
    let wasm = builder_wasm(10_000);
    let file = dir.path().join("b.wasm");
    std::fs::write(&file, &wasm).unwrap();
    let start = a.nonce(me).await;
    let faults = Faults { drop_first_send: true, ..Default::default() };
    let p = bounded(publish_with(&dev_config(), options(file, &a.url, ks, router), faults)).await.unwrap();
    assert_eq!(p.chunks.len(), 1);
    assert!(p.chunks[0].replacements >= 1, "the dropped send was replaced");
    assert_eq!(p.chunks[0].nonce, start, "at the same nonce");
    assert_eq!(p.manifest.nonce, start + 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prover_keys_and_busy_keys_are_refused_before_anything_is_sent() {
    if !anvil_on_path() {
        return;
    }
    let (a, router, staking) = chain().await;
    let dir = tempfile::tempdir().unwrap();
    let (ks, me) = keystore(dir.path());
    let file = dir.path().join("b.wasm");
    std::fs::write(&file, builder_wasm(1_000)).unwrap();
    let start = a.nonce(me).await;
    let run = |c: ZkMinerConfig| {
        let o = options(file.clone(), &a.url, ks.clone(), router);
        async move { bounded(publish_with(&c, o, Faults::default())).await.map(|_| ()).unwrap_err().to_string() }
    };

    // The configured prover.
    let mut c = dev_config();
    c.witness.prover_address = Some(me);
    assert!(run(c).await.contains("prover_address"));
    // Staked as a prover.
    a.call_from_dev(staking, IMocks::setStakeCall { p: me, a: 1 }.abi_encode()).await;
    assert!(run(dev_config()).await.contains("staked as a prover"));
    a.call_from_dev(staking, IMocks::setStakeCall { p: me, a: 0 }.abi_encode()).await;
    // Authorized as a prover's operator.
    let prover = Address::repeat_byte(0x77);
    a.call_from_dev(router, IMocks::authorizeCall { prover, operator: me }.abi_encode()).await;
    let e = run(dev_config()).await;
    assert!(e.contains("operator"), "{e}");
    assert_eq!(a.nonce(me).await, start, "nothing was sent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_with_foreign_pending_transactions_is_refused() {
    if !anvil_on_path() {
        return;
    }
    let (a, router, _) = chain().await;
    let dir = tempfile::tempdir().unwrap();
    let (ks, me) = keystore(dir.path());
    let file = dir.path().join("b.wasm");
    std::fs::write(&file, builder_wasm(1_000)).unwrap();
    // A transaction of this key the publisher did not send, held pending (no mining).
    a.rpc("evm_setIntervalMining", json!([0])).await;
    a.rpc("anvil_impersonateAccount", json!([format!("{me:#x}")])).await;
    a.rpc("eth_sendTransaction", json!([{"from": format!("{me:#x}"), "to": DEV, "value": "0x1"}])).await;
    let e = bounded(publish_with(&dev_config(), options(file, &a.url, ks, router), Faults::default())).await.unwrap_err().to_string();
    assert!(e.contains("pending"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_rpc_is_refused_outside_developer_mode() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("b.wasm");
    std::fs::write(&file, builder_wasm(1_000)).unwrap();
    let mut public = ZkMinerConfig::default();
    public.chain.chain_id = 31337;
    let o = options(file.clone(), "http://127.0.0.1:1", dir.path().join("no-keystore.json"), Address::repeat_byte(1));
    let e = publish_with(&public, o, Faults::default()).await.unwrap_err().to_string();
    assert!(e.contains("refused by the network guard"), "{e}");
    // Developer mode for another chain does not open this one.
    let mut other = dev_config();
    other.chain.chain_id = 1337;
    other.dev.chain_id = Some(1337);
    let o = options(file.clone(), "http://127.0.0.1:1", dir.path().join("no-keystore.json"), Address::repeat_byte(1));
    let e = publish_with(&other, o, Faults::default()).await.unwrap_err().to_string();
    assert!(e.contains("refused by the network guard"), "{e}");
    // A file that is not what --kind says is refused before the network.
    let mut o = options(file, "http://127.0.0.1:1", dir.path().join("k.json"), Address::repeat_byte(1));
    o.kind = Kind::Elf;
    let e = publish_with(&dev_config(), o, Faults::default()).await.unwrap_err().to_string();
    assert!(e.contains("not an ELF"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_operator_revoked_with_all_others_is_no_longer_refused() {
    if !anvil_on_path() {
        return;
    }
    let (a, router, _) = chain().await;
    let dir = tempfile::tempdir().unwrap();
    let (ks, me) = keystore(dir.path());
    let file = dir.path().join("b.wasm");
    std::fs::write(&file, builder_wasm(1_000)).unwrap();
    let start = a.nonce(me).await;
    // Each run stops right before its first send.
    let run = || {
        let o = options(file.clone(), &a.url, ks.clone(), router);
        async move {
            bounded(publish_with(&dev_config(), o, Faults { stop_after: Some(0), ..Default::default() }))
                .await
                .map(|_| ())
                .unwrap_err()
                .to_string()
        }
    };
    let prover = Address::repeat_byte(0x77);
    a.call_from_dev(router, IMocks::authorizeCall { prover, operator: me }.abi_encode()).await;
    assert!(run().await.contains("operator"));
    // `revokeAllOperators` voids the authorization: the key is no operator any more.
    a.call_from_dev(router, IMocks::revokeAllOperatorsCall { prover }.abi_encode()).await;
    let e = run().await;
    assert!(e.contains("stopped by the test after 0"), "{e}");
    // Authorized again (under the prover's new nonce): refused again.
    a.call_from_dev(router, IMocks::authorizeCall { prover, operator: me }.abi_encode()).await;
    assert!(run().await.contains("operator"));
    assert_eq!(a.nonce(me).await, start, "nothing was sent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_that_stopped_part_way_resumes_from_its_progress_file() {
    if !anvil_on_path() {
        return;
    }
    let (a, router, _) = chain().await;
    let dir = tempfile::tempdir().unwrap();
    let (ks, me) = keystore(dir.path());
    let wasm = builder_wasm(50_000);
    let file = dir.path().join("b.wasm");
    std::fs::write(&file, &wasm).unwrap();
    let progress = dir.path().join("progress.json");
    let with_progress = || {
        let mut o = options(file.clone(), &a.url, ks.clone(), router);
        o.progress = Some(progress.clone());
        o
    };
    let start = a.nonce(me).await;
    // The first run dies after two of the three chunks.
    let e = bounded(publish_with(&dev_config(), with_progress(), Faults { stop_after: Some(2), ..Default::default() })).await.unwrap_err();
    assert!(e.to_string().contains("stopped by the test"), "{e:#}");
    let record: Value = serde_json::from_slice(&std::fs::read(&progress).unwrap()).unwrap();
    assert_eq!(record["chunks"].as_array().unwrap().len(), 2, "{record:#}");
    assert_eq!(a.nonce(me).await, start + 2);
    // The second sends only the last chunk and the manifest.
    let p = bounded(publish_with(&dev_config(), with_progress(), Faults::default())).await.unwrap();
    assert_eq!(p.chunks.len(), 3);
    assert!(p.chunks[0].reused && p.chunks[1].reused && !p.chunks[2].reused && !p.manifest.reused, "{p:#?}");
    assert_eq!(p.chunks[2].nonce, start + 2);
    assert_eq!(a.nonce(me).await, start + 4, "two sends");
    // A third reuses everything, the manifest too, sends nothing, and reads it all back.
    let again = bounded(publish_with(&dev_config(), with_progress(), Faults::default())).await.unwrap();
    assert!(again.manifest.reused && again.chunks.iter().all(|c| c.reused));
    assert_eq!(again.locator, p.locator);
    assert_eq!(again.total_cost_wei, "0");
    assert_eq!(a.nonce(me).await, start + 4, "nothing sent");
    // A record whose chunk is not on chain as recorded (here: another address) is not reused from
    // there on.
    let mut record: Value = serde_json::from_slice(&std::fs::read(&progress).unwrap()).unwrap();
    record["chunks"][1]["address"] = json!(format!("{:#x}", Address::repeat_byte(9)));
    std::fs::write(&progress, serde_json::to_vec(&record).unwrap()).unwrap();
    let fourth = bounded(publish_with(&dev_config(), with_progress(), Faults { stop_after: Some(0), ..Default::default() })).await;
    assert!(fourth.unwrap_err().to_string().contains("stopped by the test"));
    let record: Value = serde_json::from_slice(&std::fs::read(&progress).unwrap()).unwrap();
    assert_eq!(record["chunks"].as_array().unwrap().len(), 1, "only what was found is kept: {record:#}");
    assert!(record["manifest"].is_null());
    // Another artifact under the same record is refused.
    std::fs::write(&file, builder_wasm(1_000)).unwrap();
    let e = bounded(publish_with(&dev_config(), with_progress(), Faults::default())).await.unwrap_err();
    assert!(e.to_string().contains("another publication"), "{e:#}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sends_are_paced_by_the_local_clock() {
    if !anvil_on_path() {
        return;
    }
    let (a, router, _) = chain().await;
    let dir = tempfile::tempdir().unwrap();
    let (ks, _) = keystore(dir.path());
    let file = dir.path().join("b.wasm");
    std::fs::write(&file, builder_wasm(30_000)).unwrap();
    // One block a second, and a floor of three seconds: three sends (two chunks, the manifest)
    // take at least six, and land at least two blocks apart.
    let mut o = options(file, &a.url, ks, router);
    o.block_time_ms = Some(3_000);
    let t = std::time::Instant::now();
    let p = bounded(publish_with(&dev_config(), o, Faults::default())).await.unwrap();
    assert_eq!(p.chunks.len(), 2);
    let blocks: Vec<u64> = p.chunks.iter().chain([&p.manifest]).map(|d| d.block_number).collect();
    assert!(blocks.windows(2).all(|w| w[1] >= w[0] + 2), "{blocks:?}");
    assert!(t.elapsed() >= Duration::from_secs(6), "{:?}", t.elapsed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_rpc_must_show_each_deployment_before_the_next_send() {
    if !anvil_on_path() {
        return;
    }
    let (a, router, _) = chain().await;
    let dir = tempfile::tempdir().unwrap();
    let (ks, me) = keystore(dir.path());
    let file = dir.path().join("b.wasm");
    std::fs::write(&file, builder_wasm(1_000)).unwrap();
    // The same node as the second RPC: everything shows there, and is read back there too.
    let mut o = options(file.clone(), &a.url, ks.clone(), router);
    o.verify_rpc_url = Some(a.url.clone());
    let p = bounded(publish_with(&dev_config(), o, Faults::default())).await.unwrap();
    assert!(p.warnings.iter().any(|w| w.contains("same host")), "{:?}", p.warnings);
    // Another chain with the same id (what a lying first RPC would look like from the second): the
    // first chunk never shows there, and nothing after it is sent.
    let other = Anvil::start().await;
    let start = a.nonce(me).await;
    let mut o = options(file, &a.url, ks, router);
    o.verify_rpc_url = Some(other.url.clone());
    let faults = Faults { verify_timeout: Some(Duration::from_secs(5)), ..Default::default() };
    let e = bounded(publish_with(&dev_config(), o, faults)).await.unwrap_err().to_string();
    assert!(e.contains("does not show"), "{e}");
    assert_eq!(a.nonce(me).await, start + 1, "the chunk, and nothing after it");
}
