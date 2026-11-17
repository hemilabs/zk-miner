//! The governance watcher, the deployment-constants cache and the submission form against the REAL
//! stack zkminer pins (`deployment::HEMI_TESTNET_743111`): an anvil fork of Hemi testnet 743111, started as `zkminer-cli/tests/localnet.rs`
//! starts it. The router is paused and unpaused by its owner (impersonated) to see the watcher follow
//! a real `Paused`/`Unpaused` from the real router.
//!
//! `#[ignore]`: needs Foundry's `anvil` and the network. Run with
//! `cargo test -p zkminer-chain --test governance_fork -- --ignored --nocapture`.
//! - `ZKMINER_LOCALNET_FORK_URL`: the 743111 RPC to fork (default: the public testnet RPC).
//! - `ZKMINER_LOCALNET_FORK_BLOCK`: a block number, or unset for the latest.
//! - `ANVIL`: the anvil binary (default: `anvil` on the PATH).

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;

use zkminer_chain::auction::ProofSystem;
use zkminer_chain::client::ChainClient;
use zkminer_chain::deployment::HEMI_TESTNET_743111 as DEPLOYMENT;
use zkminer_chain::descriptor::fetch_job_descriptor_with_form;
use zkminer_chain::governance::{
    DeploymentConstants, GateRefusal, GovernanceConfig, GovernanceWatcher,
};
use zkminer_contracts::bindings::{IHemiProveAux, IHemiProveCore, IHemiProveRegistry};

const DEFAULT_FORK_URL: &str = "https://testnet.rpc.hemi.network/rpc";
// Anvil's first default account (a well-known test key, no funds anywhere real).
const KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

struct Anvil {
    child: Child,
    url: String,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_anvil() -> Anvil {
    let port = free_port();
    let fork_url =
        std::env::var("ZKMINER_LOCALNET_FORK_URL").unwrap_or_else(|_| DEFAULT_FORK_URL.into());
    // `--fork-chain-id` (which spares anvil asking a flaky upstream for it) needs an explicit block:
    // the given one, else the upstream's head now.
    let fork_block = match std::env::var("ZKMINER_LOCALNET_FORK_BLOCK") {
        Ok(b) if b != "latest" => b,
        _ => alloy::providers::ProviderBuilder::new()
            .connect_http(fork_url.parse().unwrap())
            .get_block_number()
            .await
            .expect("the fork URL's head")
            .to_string(),
    };
    let log = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("governance_fork_anvil_{port}.log"));
    let log = std::fs::File::create(&log).expect("anvil log");
    let mut cmd = Command::new(std::env::var("ANVIL").unwrap_or_else(|_| "anvil".into()));
    cmd.args(["--fork-url", &fork_url])
        .args(["--fork-block-number", &fork_block])
        .args(["--chain-id", &DEPLOYMENT.chain_id.to_string()])
        .args(["--fork-chain-id", &DEPLOYMENT.chain_id.to_string()])
        .args(["--host", "127.0.0.1", "--port", &port.to_string()])
        .arg("--auto-impersonate")
        .args([
            "--retries",
            "60",
            "--fork-retry-backoff",
            "2000",
            "--timeout",
            "60000",
        ])
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    let child = cmd
        .spawn()
        .expect("start anvil: install Foundry, or set ANVIL to its path");
    let anvil = Anvil {
        child,
        url: format!("http://127.0.0.1:{port}"),
    };
    // Wait for it to answer.
    for _ in 0..120 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return anvil;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("anvil did not start on port {port}");
}

async fn client(url: &str) -> ChainClient {
    let mut c = zkminer_config::ZkMinerConfig::default();
    c.chain.rpc_url = url.to_string();
    c.chain.chain_id = DEPLOYMENT.chain_id;
    c.chain.max_requests_per_sec = Some(50);
    c.contracts.hemi_prove = format!("{:#x}", DEPLOYMENT.router);
    c.contracts.hemi_prove_staking = format!("{:#x}", DEPLOYMENT.staking);
    c.contracts.hemi_prove_registry = format!("{:#x}", DEPLOYMENT.registry);
    c.contracts.hemi_token = format!("{:#x}", DEPLOYMENT.token);
    let signer: alloy::signers::local::PrivateKeySigner = KEY.parse().unwrap();
    ChainClient::new(&c, signer).await.unwrap()
}

/// Send `data` to the router as its owner (anvil impersonates it) and wait for the receipt.
async fn as_router_owner(client: &ChainClient, data: &str) {
    let p = &*client.provider;
    let owner: Bytes = p
        .raw_request(
            "eth_call".into(),
            (serde_json::json!({ "to": format!("{:#x}", DEPLOYMENT.router), "data": "0x8da5cb5b" }), "latest"),
        )
        .await
        .expect("router.owner()");
    let owner = Address::from_slice(&owner[12..32]);
    let _: serde_json::Value = p
        .raw_request(
            "anvil_setBalance".into(),
            (owner, U256::from(10u128.pow(18))),
        )
        .await
        .unwrap();
    let tx: alloy::primitives::B256 = p
        .raw_request(
            "eth_sendTransaction".into(),
            (serde_json::json!({
                "from": format!("{owner:#x}"),
                "to": format!("{:#x}", DEPLOYMENT.router),
                "data": data,
                "gas": "0x200000",
            }),),
        )
        .await
        .unwrap_or_else(|e| panic!("router call {data} as owner {owner}: {e:#}"));
    for _ in 0..60 {
        let r: Option<serde_json::Value> = p
            .raw_request("eth_getTransactionReceipt".into(), (tx,))
            .await
            .unwrap();
        if let Some(r) = r {
            assert_eq!(r["status"], "0x1", "router call {data} reverted");
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("router call {data} never mined");
}

/// Poll until the watcher has applied every log up to the current head.
async fn catch_up(client: &ChainClient, watcher: &GovernanceWatcher) {
    let head = client.get_block_number().await.unwrap();
    client.set_head_block(head);
    while watcher.view().scanned_through() < Some(head) {
        watcher.poll_once().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "needs anvil and the 743111 RPC"]
async fn the_watcher_and_the_gates_read_the_real_deployed_stack() {
    let anvil = start_anvil().await;
    let client = client(&anvil.url).await;
    let risc0 = ProofSystem::Risc0Groth16.id();
    let p = &*client.provider;
    let head = client.get_block_number().await.unwrap();
    println!("fork head {head}");

    // ── Start-up read against the real views ────────────────────────────────────────────────
    let mut cfg = GovernanceConfig::new(Address::repeat_byte(0x11), vec![risc0]);
    cfg.lookback_blocks = 2_000;
    let watcher = GovernanceWatcher::new(client.clone(), cfg);
    let view = watcher.view();
    watcher
        .init()
        .await
        .expect("start-up read on the real stack");
    assert_eq!(view.sync_refusal(), None);
    let state = view.state();
    let router_paused = IHemiProveAux::new(DEPLOYMENT.router, p)
        .paused()
        .call()
        .await
        .unwrap();
    let registry = IHemiProveRegistry::new(DEPLOYMENT.registry, p);
    let registry_paused = registry.paused().call().await.unwrap();
    let entry = registry.getAdapter(risc0).call().await.unwrap();
    let switch = registry.pendingReactivation(risc0).call().await.unwrap();
    let upgrade = registry.pendingUpgrade().call().await.unwrap();
    println!(
        "router paused {router_paused}, Registry paused {registry_paused}, risc0 adapter {} status {}, \
         pending switch {:?}@{}, Registry pending upgrade {}@{}, watcher upgrades {:?}",
        entry.adapter,
        entry.status,
        switch.newAdapter,
        switch.readyAt,
        upgrade.opHash,
        upgrade.readyAt,
        state.pending_upgrades()
    );
    assert_eq!(state.router_paused(), router_paused);
    assert_eq!(state.registry_paused(), registry_paused);
    assert_eq!(state.adapter_disabled(risc0), entry.status == 3);
    assert_eq!(state.adapter(risc0).map(|a| a.adapter), Some(entry.adapter));
    assert_eq!(
        state.pending_switch(risc0).is_some(),
        switch.readyAt.to::<u64>() != 0
    );

    // ── Deployment constants, cached per block ──────────────────────────────────────────────
    let consts = DeploymentConstants::new();
    client.set_head_block(head);
    let a = consts
        .risc0_adapter(&client, risc0)
        .await
        .expect("risc0 adapter constants");
    println!("risc0 adapter constants at {}: {a:?}", a.block);
    assert_eq!(a.adapter, entry.adapter);
    assert_ne!(a.selector, [0u8; 4]);
    let before = client.rpc_meter().total();
    assert_eq!(consts.risc0_adapter(&client, risc0).await.unwrap(), a);
    assert_eq!(
        client.rpc_meter().total(),
        before,
        "a hit at the same block costs no request"
    );

    // ── A real pause and unpause, followed live ─────────────────────────────────────────────
    if router_paused {
        as_router_owner(&client, "0x3f4ba83a").await; // unpause()
        catch_up(&client, &watcher).await;
    }
    let mut aborts = view.subscribe_aborts();
    as_router_owner(&client, "0x8456cb59").await; // pause()
    catch_up(&client, &watcher).await;
    assert!(view.paused(), "the router's Paused was not seen");
    assert_eq!(view.hold(risc0), Some(GateRefusal::RouterPaused));
    as_router_owner(&client, "0x3f4ba83a").await; // unpause()
    catch_up(&client, &watcher).await;
    assert!(
        !view.state().router_paused(),
        "the router's Unpaused was not seen"
    );
    assert!(aborts.try_recv().is_err(), "a pause aborts no job");

    // ── The submission form of the newest real job ───────────────────────────────────────────
    let mut end = head;
    let mut found = None;
    while found.is_none() && end > DEPLOYMENT.scan_from_block {
        let start = end.saturating_sub(8_999).max(DEPLOYMENT.scan_from_block);
        let f = Filter::new()
            .address(DEPLOYMENT.router)
            .event_signature(IHemiProveCore::JobSubmitted::SIGNATURE_HASH)
            .from_block(start)
            .to_block(end);
        found = p.get_logs(&f).await.unwrap().last().cloned();
        end = start.saturating_sub(1);
    }
    match found {
        Some(log) => {
            let job = log.topics()[1];
            let f = fetch_job_descriptor_with_form(&client, job)
                .await
                .expect("descriptor of a real job");
            println!(
                "newest job {job} (tx {}, from {:?}): {}",
                f.submit_tx, f.tx_from, f.form
            );
        }
        None => println!("no JobSubmitted on the deployment: submission form not checked"),
    }
}
