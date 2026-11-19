//! The broker's network mode: public unless the miner passes `--dev-private-network` (its own
//! `[dev] private_network`). The configs these tests' local servers need are refused in public
//! mode, in-process and by the binary, before anything connects; developer mode is refused with a
//! mainnet endpoint; and the public-mode self-test fails when a role entry stops being public.

mod common;

use std::process::{Command, Stdio};

use alloy_primitives::B256;
use common::{budget, register, start};
use zkminer_witness::envelope::{encode_evm_rpc_config, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ};
use zkminer_witness::ipc::{FetchStatus, IpPrefix, SelfTestCheck};
use zkminer_witness_broker::egress::NetMode;
use zkminer_witness_broker::testkit::{config_text, mock_node, spawn_broker, test_hooks, TestServer};
use zkminer_witness_broker::BrokerConfig;

fn mock_cap() -> (B256, Vec<u8>) {
    (CLASS_EVM_RPC_V1, encode_evm_rpc_config(8453, false, METHOD_SET_STATE_READ, 0))
}

const BROKER: &str = env!("CARGO_BIN_EXE_zkminer-witness-broker");

fn local_config(dir: &std::path::Path, node: &TestServer) -> String {
    config_text(
        dir,
        &format!(
            "[[evm_rpc]]\nalias = \"local\"\nurl = \"{}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n",
            node.url()
        ),
    )
}

/// The same config: served in developer mode, refused in public mode (its endpoint is loopback).
#[tokio::test]
async fn the_same_local_config_is_served_in_developer_mode_and_refused_in_public_mode() {
    let node = TestServer::start(mock_node(1)).await;
    let dir = tempfile::tempdir().unwrap();
    let text = local_config(dir.path(), &node);

    let e = BrokerConfig::from_toml(&text, dir.path(), NetMode::Public).expect_err("loopback in public mode").to_string();
    assert!(e.contains("local: role entry 127.0.0.1/32") && e.contains("not on the public internet"), "{e}");

    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut b = register(&client, 1, vec![mock_cap()], budget(10, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#""a""#).await.0, FetchStatus::Ok);
    assert_eq!(node.hits(), 1);
    let _ = client.end_job(B256::repeat_byte(1)).await;
}

fn run_binary(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(BROKER)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_clear()
        .output()
        .unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The binary refuses the local config without `--dev-private-network`, before it reads fd 3 or
/// applies its sandbox; with the flag it gets past the config to the missing control socket.
#[tokio::test]
async fn the_binary_refuses_a_local_config_without_the_flag() {
    let node = TestServer::start(mock_node(1)).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broker.toml");
    std::fs::write(&path, local_config(dir.path(), &node)).unwrap();
    let path = path.to_str().unwrap();

    let (code, err) = run_binary(&["--config", path]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("not on the public internet"), "{err}");

    for args in [["--config", path, "--dev-private-network"], ["--dev-private-network", "--config", path]] {
        let (code, err) = run_binary(&args);
        assert_eq!(code, Some(2), "{err}");
        assert!(err.contains("no control socket at fd 3"), "the config was accepted: {err}");
    }
    assert_eq!(node.hits(), 0);
}

/// Developer mode with an endpoint on Hemi mainnet (43111) is refused by the binary.
#[test]
fn the_binary_refuses_developer_mode_with_a_mainnet_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    for table in [
        "[[evm_rpc]]\nalias = \"main\"\nurl = \"http://127.0.0.1:8545\"\nchain_id = 43111\nmethod_sets = [\"state-read\"]\n",
        "[artifacts]\nalias = \"main\"\nurl = \"http://127.0.0.1:8545\"\nchain_id = 43111\n",
    ] {
        let path = dir.path().join("broker.toml");
        std::fs::write(&path, config_text(dir.path(), table)).unwrap();
        let (code, err) = run_binary(&["--config", path.to_str().unwrap(), "--dev-private-network"]);
        assert_eq!(code, Some(2), "{err}");
        assert!(err.contains("developer mode") && err.contains("43111"), "{err}");
    }
}

/// The mode never comes from the file, and the flag comes only as itself, once.
#[test]
fn the_mode_is_only_a_flag() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broker.toml");
    for key in ["dev = true\n", "private_network = true\n", "[dev]\nprivate_network = true\n"] {
        std::fs::write(&path, config_text(dir.path(), key)).unwrap();
        let (code, err) = run_binary(&["--config", path.to_str().unwrap(), "--dev-private-network"]);
        assert_eq!(code, Some(2), "{err}");
        assert!(err.contains("unknown field"), "{key}: {err}");
    }
    std::fs::write(&path, config_text(dir.path(), "")).unwrap();
    let p = path.to_str().unwrap();
    for args in [
        vec!["--config", p, "--dev-private-network", "--dev-private-network"],
        vec!["--config", p, "--dev-private-network=true"],
        vec!["--config", p, "--private-network"],
        vec!["--config", p, "--config", p],
        vec!["--dev-private-network"],
    ] {
        let (code, err) = run_binary(&args);
        assert_eq!(code, Some(2), "{args:?}: {err}");
        assert!(err.contains("usage:"), "{args:?}: {err}");
    }
}

/// In public mode the self-test checks the effective role set: a public mirror passes, and once
/// the miner reports its address as on a connected network the role entry is no longer public and
/// the check (and `ok`) fails. The mirror is never contacted.
#[tokio::test]
async fn the_public_self_test_fails_when_a_role_entry_is_not_public() {
    let dir = tempfile::tempdir().unwrap();
    let text = config_text(dir.path(), "[[blob_mirror]]\nalias = \"m\"\nurl_template = \"https://1.1.1.1/b/{sha256}\"\n");
    let cfg = BrokerConfig::from_toml(&text, dir.path(), NetMode::Public).unwrap();
    let (client, _t) = spawn_broker(cfg, test_hooks()).await;
    let r = client.self_test().await.unwrap();
    assert!(r.checks.contains(&(SelfTestCheck::RoleEntriesPublic, true)), "{r:?}");
    for c in [SelfTestCheck::LoopbackDenied, SelfTestCheck::MetadataDenied, SelfTestCheck::Rfc1918Denied] {
        assert!(r.checks.contains(&(c, true)), "{c:?}: {r:?}");
    }

    client.refresh_prefixes(vec![IpPrefix { addr: "1.1.1.0".parse().unwrap(), len: 24 }], vec![]).await.unwrap();
    let r = client.self_test().await.unwrap();
    assert!(r.checks.contains(&(SelfTestCheck::RoleEntriesPublic, false)), "{r:?}");
    assert!(!r.ok);

    // Developer mode reports no such check.
    let dev = BrokerConfig::from_toml(&text, dir.path(), NetMode::DevPrivate).unwrap();
    let (client, _t) = spawn_broker(dev, test_hooks()).await;
    let r = client.self_test().await.unwrap();
    assert!(!r.checks.iter().any(|(c, _)| *c == SelfTestCheck::RoleEntriesPublic), "{r:?}");
}
