//! End to end against anvil with the REAL `evm_rpc` codec and the REAL `egress` floor
//! (`Hooks::real()`): state reads, tag resolution, `hemi-code` and the self-test, and failover
//! between a node at height 0 and one ahead of it.

mod common;

use alloy_primitives::B256;
use common::*;
use serde_json::{json, Value};
use zkminer_witness::envelope::{encode_evm_rpc_config, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ};
use zkminer_witness::ipc::{ArtifactSource, FetchStatus, SelfTestCheck};
use zkminer_witness_broker::client::ArtifactRequest;
use zkminer_witness_broker::hooks::Hooks;
use zkminer_witness_broker::testkit::config_text;

const ANVIL_CHAIN: u64 = 31337;

fn endpoint(anvil: &Anvil) -> String {
    format!(
        "[[evm_rpc]]\nalias = \"anvil\"\nurl = \"{}\"\nchain_id = {ANVIL_CHAIN}\narchive = true\nmax_proof_age = 1000000\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n",
        anvil.url
    )
}

fn cap() -> (B256, Vec<u8>) {
    (CLASS_EVM_RPC_V1, encode_evm_rpc_config(ANVIL_CHAIN, true, METHOD_SET_STATE_READ, 0))
}

fn json_of(b: &[u8]) -> Value {
    serde_json::from_slice(b).expect("canonical JSON")
}

#[tokio::test]
async fn state_reads_through_the_broker() {
    let anvil = Anvil::start(&[]).await;
    // A contract that always reverts: PUSH1 0 PUSH1 0 REVERT.
    let reverter = anvil.deploy(&[0x60, 0x00, 0x60, 0x00, 0xfd]).await;
    anvil.mine(3).await;
    let dir = tempfile::tempdir().unwrap();
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &endpoint(&anvil)), Hooks::real()).await;
    let mut b = register(&client, 1, vec![cap()], budget(100, 1 << 22, 1 << 20), false).await;

    let (s, body) = b.fetch(0, br#"{"jsonrpc":"2.0","id":7,"method":"eth_chainId","params":[]}"#).await;
    assert_eq!(s, FetchStatus::Ok);
    assert_eq!(json_of(&body), json!({"jsonrpc":"2.0","id":7,"result":"0x7a69"}));

    // A batch keeps request order and the builder's ids; `latest` is resolved by the broker.
    let req = format!(
        r#"[{{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["{DEV}","latest"]}},{{"jsonrpc":"2.0","id":"b","method":"eth_blockNumber","params":[]}}]"#
    );
    let (s, body) = b.fetch(0, req.as_bytes()).await;
    assert_eq!(s, FetchStatus::Ok);
    let v = json_of(&body);
    assert_eq!(v[0]["id"], 1);
    assert_eq!(v[1]["id"], "b");
    assert!(v[0]["result"].as_str().unwrap().starts_with("0x"));

    // A pinned read (EIP-1898 blockHash): answered identically from the cache the second time.
    let head = anvil.rpc("eth_getBlockByNumber", json!(["latest", false])).await;
    let hash = head["hash"].as_str().unwrap().to_string();
    let pinned = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"eth_getCode","params":["{}",{{"blockHash":"{hash}"}}]}}"#,
        reverter.to_string().to_lowercase()
    );
    let first = b.fetch(0, pinned.as_bytes()).await;
    let second = b.fetch(0, pinned.as_bytes()).await;
    assert_eq!(first.0, FetchStatus::Ok);
    assert_eq!(first, second);
    assert_eq!(json_of(&first.1)["result"], "0x60006000fd");

    // A reverted call is an answer (an error object), not a failure.
    let call = format!(
        r#"{{"jsonrpc":"2.0","id":4,"method":"eth_call","params":[{{"to":"{}","data":"0x"}},"latest"]}}"#,
        reverter.to_string().to_lowercase()
    );
    let (s, body) = b.fetch(0, call.as_bytes()).await;
    assert_eq!(s, FetchStatus::Ok);
    assert!(json_of(&body).get("error").is_some());

    // Refused: methods outside state-read, a case-variant key, `pending`.
    for bad in [
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_sendTransaction","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"debug_setHead","params":["0x1"]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","Method":"debug_setHead","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","pending"]}"#,
    ] {
        assert_eq!(b.fetch(0, bad.as_bytes()).await.0, FetchStatus::Denied, "{bad}");
    }
    let stats = client.end_job(B256::repeat_byte(1)).await.unwrap();
    assert_eq!(stats.denied, 4);
    assert_eq!(stats.fetches, 1 + 2 + 1 + 1 + 1 + 4);
    assert!(!stats.operator_failure && !stats.unanswerable);
}

#[tokio::test]
async fn tags_resolve_once_per_fetch_against_anvil() {
    let anvil = Anvil::start(&[]).await;
    anvil.mine(40).await;
    let dir = tempfile::tempdir().unwrap();
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &endpoint(&anvil)), Hooks::real()).await;
    let mut b = register(&client, 2, vec![cap()], budget(100, 1 << 22, 1 << 20), false).await;
    let req = r#"[{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["safe",false]},{"jsonrpc":"2.0","id":2,"method":"eth_getBlockByNumber","params":["latest",false]}]"#;
    let (s, body) = b.fetch(0, req.as_bytes()).await;
    assert_eq!(s, FetchStatus::Ok);
    let v = json_of(&body);
    let n = |i: usize| u64::from_str_radix(v[i]["result"]["number"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    assert_eq!(n(1) - n(0), 32, "anvil's safe head trails latest by 32");
}

#[tokio::test]
async fn hemi_code_and_self_test_with_the_real_floor() {
    let anvil = Anvil::start(&[]).await;
    let p = publish(&anvil, &pattern(5_000, 1), 1_000).await;
    let dir = tempfile::tempdir().unwrap();
    let text = config_text(
        dir.path(),
        &format!(
            "{}[artifacts]\nalias = \"hemi\"\nurl = \"{}\"\nchain_id = {ANVIL_CHAIN}\nmax_requests_per_sec = 1000\ncidrs = [\"127.0.0.1/32\"]\n",
            endpoint(&anvil),
            anvil.url
        ),
    );
    let (client, _t) = start(dir.path(), &text, Hooks::real()).await;
    let req = ArtifactRequest {
        job_key: B256::ZERO,
        caller: Default::default(),
        source: ArtifactSource::HemiCode { chain_id: ANVIL_CHAIN, manifest: p.manifest },
        builder_type: 1,
        expected_sha256: Some(p.sha256),
        max_bytes: 1 << 20,
        held_lock: false,
    };
    let a = client.fetch_artifact(req, |_| async { true }).await.unwrap().unwrap();
    assert_eq!(a.len, 5_000);
    let r = client.self_test().await.unwrap();
    for c in [
        SelfTestCheck::LoopbackDenied,
        SelfTestCheck::MetadataDenied,
        SelfTestCheck::Rfc1918Denied,
        SelfTestCheck::OwnAddressDenied,
        SelfTestCheck::ConnectedPrefixDenied,
        SelfTestCheck::EndpointsReachable,
        SelfTestCheck::ArtifactEndpointChainId,
    ] {
        assert!(r.checks.contains(&(c, true)), "{c:?}: {r:?}");
    }
}
