//! `evm-rpc/v1` serving logic with the mock codec (`testkit::MockCodec`, standing in for
//! `evm_rpc.rs` until the merge) against mock nodes on 127.0.0.1: tag resolution per fetch,
//! failover, lagging retries, partial cache hits, budgets and the operator budget.

mod common;

use std::time::Duration;

use alloy_primitives::B256;
use common::*;
use serde_json::Value;
use zkminer_witness::envelope::{encode_evm_rpc_config, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ};
use zkminer_witness::ipc::FetchStatus;
use zkminer_witness_broker::testkit::{config_text, mock_node, test_hooks, TestDns, TestRequest, TestResponse, TestServer};

fn cap() -> (B256, Vec<u8>) {
    (CLASS_EVM_RPC_V1, encode_evm_rpc_config(8453, false, METHOD_SET_STATE_READ, 0))
}

fn endpoints(urls: &[String], extra: &str) -> String {
    let mut s = String::new();
    for (i, u) in urls.iter().enumerate() {
        s.push_str(&format!(
            "\n[[evm_rpc]]\nalias = \"node{i}\"\nurl = \"{u}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n{extra}\n"
        ));
    }
    s
}

/// The call names the node was asked for in its last non-tag request.
fn calls_seen(s: &TestServer) -> Vec<Vec<String>> {
    s.requests
        .lock()
        .unwrap()
        .iter()
        .filter_map(|r| {
            let v: Value = serde_json::from_slice(&r.body).ok()?;
            Some(v.get("calls")?.as_array()?.iter().map(|c| c.as_str().unwrap().to_string()).collect())
        })
        .collect()
}

fn s(v: &[u8]) -> String {
    String::from_utf8_lossy(v).to_string()
}

#[tokio::test]
async fn single_batch_and_tags_fixed_per_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let node = TestServer::start(mock_node(77)).await;
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &endpoints(&[node.url()], "")), test_hooks()).await;
    let mut b = register(&client, 1, vec![cap()], budget(100, 1 << 20, 1 << 20), false).await;
    let (st, body) = b.fetch(0, br#""x""#).await;
    assert_eq!((st, s(&body)), (FetchStatus::Ok, r#""x@{}""#.into()));
    // Two calls naming `latest` share one resolution; the node sees the number, not the tag.
    let (st, body) = b.fetch(0, br#"["latest","y","latest"]"#).await;
    assert_eq!(st, FetchStatus::Ok);
    assert_eq!(s(&body), r#"["latest@{\"latest\":77}","y@{\"latest\":77}","latest@{\"latest\":77}"]"#);
    let tag_queries = node.requests.lock().unwrap().iter().filter(|r| s(&r.body).contains("tag_query")).count();
    assert_eq!(tag_queries, 1);
    // An execution error is an answer.
    let (st, body) = b.fetch(0, br#""revert""#).await;
    assert_eq!((st, s(&body)), (FetchStatus::Ok, r#"{"error":"reverted"}"#.into()));
    // Refused: malformed or a method outside the set.
    assert_eq!(b.fetch(0, b"{").await.0, FetchStatus::Denied);
    assert_eq!(b.fetch(0, br#""deny_me""#).await.0, FetchStatus::Denied);
    let stats = client.end_job(B256::repeat_byte(1)).await.unwrap();
    assert_eq!(stats.fetches, 1 + 3 + 1 + 2, "one unit per call; one per refused request");
    assert_eq!(stats.denied, 2);
    assert!(!stats.operator_failure);
}

#[tokio::test]
async fn failover_on_transport_errors_429_and_lagging_nodes() {
    let dir = tempfile::tempdir().unwrap();
    let dead = "http://127.0.0.1:1".to_string(); // connection refused
    let limited = TestServer::start(|_| TestResponse::status(429)).await;
    let lagging = TestServer::start(|_| TestResponse::ok(br#"{"lagging":true}"#.to_vec())).await;
    let garbage = TestServer::start(|_| TestResponse::ok(b"<html>".to_vec())).await;
    let good = TestServer::start(mock_node(5)).await;
    let urls = [dead, limited.url(), lagging.url(), garbage.url(), good.url()];
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &endpoints(&urls, "")), test_hooks()).await;
    let mut b = register(&client, 2, vec![cap()], budget(100, 1 << 20, 1 << 20), false).await;
    // The tag query and the call each walk the endpoints to the good one.
    let (st, body) = b.fetch(0, br#"["safe","z"]"#).await;
    assert_eq!(st, FetchStatus::Ok);
    assert_eq!(s(&body), r#"["safe@{\"safe\":5}","z@{\"safe\":5}"]"#);
    assert_eq!((limited.hits(), lagging.hits(), garbage.hits(), good.hits()), (2, 2, 2, 2));
    let stats = client.end_job(B256::repeat_byte(2)).await.unwrap();
    assert!(!stats.operator_failure);

    // With no good endpoint left: status 2, the operator's (refused, 429).
    let urls = ["http://127.0.0.1:1".to_string(), limited.url(), lagging.url()];
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &endpoints(&urls, "")), test_hooks()).await;
    let mut b = register(&client, 3, vec![cap()], budget(100, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#""z""#).await.0, FetchStatus::Failed);
    let stats = client.end_job(B256::repeat_byte(3)).await.unwrap();
    assert!(stats.operator_failure);
    assert_eq!(stats.fetches, 1, "retries are not the job's units");
}

#[tokio::test]
async fn pinned_answers_are_cached_but_charged_as_misses() {
    let dir = tempfile::tempdir().unwrap();
    let node = TestServer::start(mock_node(1)).await;
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &endpoints(&[node.url()], "")), test_hooks()).await;
    let mut b = register(&client, 4, vec![cap()], budget(100, 1 << 20, 1 << 20), false).await;
    let first = b.fetch(0, br#"["h:a","b"]"#).await;
    // h:a is now cached: only b goes out (the subset, with the broker's own ids).
    let second = b.fetch(0, br#"["h:a","b"]"#).await;
    assert_eq!(first, second);
    // All pinned and cached: no request at all.
    let third = b.fetch(0, br#""h:a""#).await;
    assert_eq!(third.0, FetchStatus::Ok);
    // Errors are never cached.
    b.fetch(0, br#""h:revert""#).await;
    b.fetch(0, br#""h:revert""#).await;
    assert_eq!(
        calls_seen(&node),
        vec![
            vec!["h:a".to_string(), "b".into()],
            vec!["b".into()],
            vec!["h:revert".into()],
            vec!["h:revert".into()],
        ]
    );
    let stats = client.end_job(B256::repeat_byte(4)).await.unwrap();
    assert_eq!(stats.fetches, 2 + 2 + 1 + 1 + 1, "every call charged, hit or miss");
    let bytes = 2 * first.1.len() + third.1.len() + 2 * br#"{"error":"reverted"}"#.len();
    assert_eq!(stats.fetch_bytes, bytes as u64, "bytes charged as delivered, hit or miss");

    // The cache is the broker's, across jobs (and keyed by chain): another job's hit.
    let mut b = register(&client, 5, vec![cap()], budget(100, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#""h:a""#).await, third);
    assert_eq!(calls_seen(&node).len(), 4);
}

#[tokio::test]
async fn job_budgets_are_status_3() {
    let dir = tempfile::tempdir().unwrap();
    let node = TestServer::start(mock_node(1)).await;
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &endpoints(&[node.url()], "")), test_hooks()).await;
    // maxFetches = 3: a batch of four does not fit.
    let mut b = register(&client, 6, vec![cap()], budget(3, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#"["a","b","c","d"]"#).await.0, FetchStatus::Exhausted);
    assert_eq!(b.fetch(0, br#"["a","b","c"]"#).await.0, FetchStatus::Ok);
    assert_eq!(b.fetch(0, br#""a""#).await.0, FetchStatus::Exhausted);
    client.end_job(B256::repeat_byte(6)).await.unwrap();
    // maxResponseBytes: the canonical answers exceed it.
    let mut b = register(&client, 7, vec![cap()], budget(100, 1 << 20, 10), false).await;
    assert_eq!(b.fetch(0, br#""a_long_name_for_a_call""#).await.0, FetchStatus::Exhausted);
    client.end_job(B256::repeat_byte(7)).await.unwrap();
    // maxFetchBytes.
    let mut b = register(&client, 8, vec![cap()], budget(100, 12, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#""a""#).await.0, FetchStatus::Ok); // "a@{}" with quotes: 6 bytes
    assert_eq!(b.fetch(0, br#""b""#).await.0, FetchStatus::Ok);
    assert_eq!(b.fetch(0, br#""c""#).await.0, FetchStatus::Exhausted);
    let stats = client.end_job(B256::repeat_byte(8)).await.unwrap();
    assert_eq!(stats.fetch_bytes, 12);
    assert!(!stats.operator_failure);
}

#[tokio::test]
async fn an_operator_budget_is_status_2() {
    let dir = tempfile::tempdir().unwrap();
    let node = TestServer::start(mock_node(1)).await;
    let text = config_text(dir.path(), &endpoints(&[node.url()], "max_units_per_minute = 3"));
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut b = register(&client, 9, vec![cap()], budget(100, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#"["a","b"]"#).await.0, FetchStatus::Ok);
    assert_eq!(b.fetch(0, br#"["a","b"]"#).await.0, FetchStatus::Failed, "the endpoint's units are spent");
    let stats = client.end_job(B256::repeat_byte(9)).await.unwrap();
    assert!(stats.operator_failure);
}

#[tokio::test]
async fn keys_go_in_the_header_and_requests_carry_no_referer_or_redirects() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("k");
    std::fs::write(&key_path, "Bearer sekrit\n").unwrap();
    std::fs::set_permissions(&key_path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    // A LIVE redirect target (it would answer), inside the endpoint's own role entry.
    let target = TestServer::start(mock_node(1)).await;
    let location = format!("{}/internal", target.url());
    let redirecting = TestServer::start(move |_| TestResponse::status(307).with_header("Location", &location)).await;
    let node = TestServer::start(mock_node(1)).await;
    let text = config_text(
        dir.path(),
        &format!(
            "[[evm_rpc]]\nalias = \"r\"\nurl = \"{}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n\
             [[evm_rpc]]\nalias = \"k\"\nurl = \"{}/v1\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\nkey_file = \"k\"\nkey_header = \"authorization\"\n",
            redirecting.url(),
            node.url()
        ),
    );
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut b = register(&client, 10, vec![cap()], budget(100, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#""a""#).await.0, FetchStatus::Ok);
    assert_eq!(redirecting.hits(), 1, "a redirect is not followed: it fails over");
    assert_eq!(target.hits(), 0, "the live redirect target is never contacted");
    let req: TestRequest = node.requests.lock().unwrap()[0].clone();
    assert_eq!(req.path, "/v1");
    assert_eq!(req.header("authorization"), Some("Bearer sekrit"));
    // No Referer on any request the broker sends (`net::tests` shows the client settings drop it
    // even when a redirect is followed, where a stock client sends one).
    for r in node.requests.lock().unwrap().iter().chain(redirecting.requests.lock().unwrap().iter()) {
        assert_eq!(r.header("referer"), None);
    }
    assert_eq!(req.header("user-agent"), Some("zkminer-witness-broker"));
    assert_eq!(req.header("accept-encoding"), None, "no decompression");
}

#[tokio::test]
async fn an_endpoint_outside_its_role_entry_is_never_contacted() {
    let dir = tempfile::tempdir().unwrap();
    let node = TestServer::start(mock_node(1)).await;
    // The role entry names another address: the floor refuses 127.0.0.1 for this endpoint.
    let text = config_text(
        dir.path(),
        &format!("[[evm_rpc]]\nalias = \"n\"\nurl = \"{}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\ncidrs = [\"10.9.9.9/32\"]\n", node.url()),
    );
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut b = register(&client, 11, vec![cap()], budget(100, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#""a""#).await.0, FetchStatus::Failed);
    assert_eq!(node.hits(), 0);
    // A host name resolves (at startup, through the broker's own resolver) and its address is
    // pinned and checked the same way: inside its explicit cidrs, a loopback answer is admitted.
    let dns = TestDns::start(&[("node.test", &["127.0.0.1"])]).await;
    let text = config_text(
        dir.path(),
        &format!(
            "{}[[evm_rpc]]\nalias = \"n\"\nurl = \"http://node.test:{}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n",
            dns.config(),
            node.port()
        ),
    );
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut b = register(&client, 12, vec![cap()], budget(100, 1 << 20, 1 << 20), false).await;
    let r = tokio::time::timeout(Duration::from_secs(10), b.fetch(0, br#""a""#)).await.unwrap();
    assert_eq!(r.0, FetchStatus::Ok);
}
