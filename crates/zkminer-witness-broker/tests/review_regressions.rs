//! Regression tests from the broker review's proofs of concept, each asserting the fixed
//! behaviour (the PoCs asserted the flaws), plus the test gaps the review listed.

mod common;

use std::time::Duration;

use alloy_primitives::B256;
use common::*;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use zkminer_witness::envelope::{encode_blob_config, encode_evm_rpc_config, CLASS_BLOB_V1, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ};
use zkminer_witness::ipc::{exit, FetchStatus, SelfTestCheck, KIND_FETCH, MAX_FRAMES_AFTER_EXHAUSTION};
use zkminer_witness::manifest::sha256;
use zkminer_witness::verdict::{builder_verdict, BuilderOutcome, SkipReason};
use zkminer_witness_broker::hooks::Hooks;
use zkminer_witness_broker::testkit::{config_text, mock_node, spawn_broker, test_hooks, TestDns, TestRequest, TestResponse, TestServer};
use zkminer_witness_broker::{BrokerConfig, HostFacts};

const ANVIL_CHAIN: u64 = 31337;

fn anvil_cap() -> (B256, Vec<u8>) {
    (CLASS_EVM_RPC_V1, encode_evm_rpc_config(ANVIL_CHAIN, false, METHOD_SET_STATE_READ, 0))
}

fn mock_cap() -> (B256, Vec<u8>) {
    (CLASS_EVM_RPC_V1, encode_evm_rpc_config(8453, false, METHOD_SET_STATE_READ, 0))
}

const CHAIN_ID: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#;

fn evm(alias: &str, url: &str, chain: u64, extra: &str) -> String {
    format!("[[evm_rpc]]\nalias = \"{alias}\"\nurl = \"{url}\"\nchain_id = {chain}\nmethod_sets = [\"state-read\"]\n{extra}\n")
}

// ------------------------------------------------------------------------------------------------
// F1: a host name without `cidrs` gets only what the DNS filter admits.

/// PoC 1, inverted: a host name resolving to loopback, without `cidrs`, is never connected to, and
/// the self-test does not count a DNS answer as configured.
#[tokio::test]
async fn a_host_name_resolving_to_loopback_without_cidrs_is_refused() {
    let node = TestServer::start(mock_node(1)).await;
    let dns = TestDns::start(&[("rpc.test", &["127.0.0.1", "::1"])]).await;
    let dir = tempfile::tempdir().unwrap();
    let url = format!("http://rpc.test:{}/", node.port());
    let text = config_text(dir.path(), &format!("{}{}", dns.config(), evm("provider", &url, 8453, "")));
    let (client, _t) = start(dir.path(), &text, Hooks { codec: test_hooks().codec, egress: Hooks::real().egress }).await;
    let mut b = register(&client, 1, vec![mock_cap()], budget(10, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#""a""#).await.0, FetchStatus::Failed);
    assert_eq!(node.hits(), 0, "loopback reached through a DNS answer");
    assert!(dns.queries() >= 2, "resolved at startup and again on use");
    let r = client.self_test().await.unwrap();
    assert!(r.checks.contains(&(SelfTestCheck::LoopbackDenied, true)), "{r:?}");
    let stats = client.end_job(B256::repeat_byte(1)).await.unwrap();
    assert!(stats.operator_failure, "a refused endpoint is the operator's configuration");

    // The same name with explicit cidrs: the operator's word, admitted.
    let text = config_text(dir.path(), &format!("{}{}", dns.config(), evm("provider", &url, 8453, "cidrs = [\"127.0.0.1/32\"]")));
    let (client, _t) = start(dir.path(), &text, Hooks { codec: test_hooks().codec, egress: Hooks::real().egress }).await;
    let mut b = register(&client, 2, vec![mock_cap()], budget(10, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#""a""#).await.0, FetchStatus::Ok);
    assert_eq!(node.hits(), 1);
}

/// PoC 1b, inverted: the first resolution happens on first use, in the miner's connector, through
/// the same filter, so the loopback answer is still refused (the broker resolves nothing).
#[tokio::test]
async fn lazy_resolution_goes_through_the_same_filter() {
    let anvil = Anvil::start(&[]).await;
    let dns = TestDns::start(&[("rpc.test", &["127.0.0.1"])]).await;
    let dir = tempfile::tempdir().unwrap();
    let text = config_text(dir.path(), &evm("provider", &format!("http://rpc.test:{}/", anvil.port), ANVIL_CHAIN, ""));
    let mut cfg = BrokerConfig::from_toml(&text, dir.path(), zkminer_witness_broker::egress::NetMode::DevPrivate).unwrap();
    cfg.host = Some(HostFacts { connected: vec![], own_addresses: vec![], dns_servers: vec![dns.addr], resolvers: vec![] });
    let (client, _t) = spawn_broker(cfg, Hooks::real()).await;
    let mut b = register(&client, 1, vec![anvil_cap()], budget(10, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, CHAIN_ID).await.0, FetchStatus::Failed, "127.0.0.1 admitted after lazy resolution");
    assert!(dns.queries() >= 1, "it did resolve");
}

/// F1(c): a host name is resolved again once its answer is `reresolve_secs` old, and the new answer
/// replaces the pinned addresses.
#[tokio::test]
async fn host_names_are_resolved_again_and_the_answer_replaces_the_pin() {
    let a = TestServer::start(mock_node(1)).await;
    let b_srv = TestServer::start_at(format!("127.0.0.2:{}", a.port()).parse().unwrap(), mock_node(2))
        .await
        .expect("127.0.0.2 on the loopback interface, same port");
    let dns = TestDns::start(&[("rpc.test", &["127.0.0.1"])]).await;
    let dir = tempfile::tempdir().unwrap();
    let text = config_text(
        dir.path(),
        &format!(
            "{}reresolve_secs = 1\n{}",
            dns.config(),
            evm("n", &format!("http://rpc.test:{}/", a.port()), 8453, "cidrs = [\"127.0.0.1/32\", \"127.0.0.2/32\"]")
        ),
    );
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut b = register(&client, 1, vec![mock_cap()], budget(100, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#""x""#).await.0, FetchStatus::Ok);
    assert_eq!((a.hits(), b_srv.hits()), (1, 0));
    dns.set("rpc.test", &["127.0.0.2"]);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    // The stale answer still serves while it is refreshed in the background...
    assert_eq!(b.fetch(0, br#""y""#).await.0, FetchStatus::Ok);
    tokio::time::sleep(Duration::from_millis(300)).await;
    // ...then the new one replaces it.
    let before = a.hits();
    for _ in 0..3 {
        assert_eq!(b.fetch(0, br#""z""#).await.0, FetchStatus::Ok);
    }
    assert_eq!(a.hits(), before, "the old address is no longer pinned");
    assert_eq!(b_srv.hits(), 3);
}

// ------------------------------------------------------------------------------------------------
// F2/F5: unanswerable requests are capped, classified and never excuse the builder.

fn null_node() -> impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static {
    |req| {
        let v: Value = serde_json::from_slice(&req.body).unwrap_or_default();
        let one = |c: &Value| json!({"jsonrpc":"2.0","id":c["id"].clone(),"result":null});
        let out = match &v {
            Value::Array(a) => Value::Array(a.iter().map(one).collect()),
            c => one(c),
        };
        TestResponse::ok(serde_json::to_vec(&out).unwrap())
    }
}

/// PoC 3, inverted: an unknown block hash is unanswerable — at most two endpoints are asked, the
/// failure is not the operator's, and a builder that then traps is judged on its trap.
#[tokio::test]
async fn a_builder_cannot_make_its_failure_transient() {
    let dir = tempfile::tempdir().unwrap();
    let nodes = [TestServer::start(null_node()).await, TestServer::start(null_node()).await, TestServer::start(null_node()).await];
    let mut text = String::new();
    for (i, n) in nodes.iter().enumerate() {
        text.push_str(&evm(&format!("n{i}"), &n.url(), ANVIL_CHAIN, "cidrs = [\"127.0.0.1/32\"]\nmax_units_per_minute = 60"));
    }
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &text), Hooks::real()).await;
    let mut b = register(&client, 1, vec![anvil_cap()], budget(100, 1 << 20, 1 << 20), false).await;
    let unknown = format!("0x{}", "00".repeat(31) + "01");
    let one = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByHash","params":["{unknown}",false]}}"#);
    assert_eq!(b.fetch(0, one.as_bytes()).await.0, FetchStatus::Failed);
    let hits = || nodes.iter().map(TestServer::hits).collect::<Vec<_>>();
    assert_eq!(hits(), vec![1, 1, 0], "the lagging failover stops after two endpoints");
    // A batch of 32: each attempted endpoint is charged 32 operator units (60/min, 25% held back).
    let batch: Vec<String> = (0..32)
        .map(|i| format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"eth_getBlockByHash","params":["{unknown}",false]}}"#))
        .collect();
    let batch = format!("[{}]", batch.join(","));
    assert_eq!(b.fetch(0, batch.as_bytes()).await.0, FetchStatus::Failed);
    assert_eq!(hits(), vec![2, 2, 0]);
    // n0 and n1 have 60 − 1 − 32 = 27 left, under 32 + the 15 held back: failover charged them.
    assert_eq!(b.fetch(0, batch.as_bytes()).await.0, FetchStatus::Failed);
    assert_eq!(hits(), vec![2, 2, 1], "spent budgets are skipped (the operator's), the third endpoint is asked");
    let stats = client.end_job(B256::repeat_byte(1)).await.unwrap();
    assert!(stats.unanswerable);
    assert!(stats.operator_failure, "the last fetch found budgets spent");
    assert_eq!(stats.fetches, 65);

    // Unanswerable alone: the builder's trap is a trap.
    let mut b = register(&client, 2, vec![anvil_cap()], budget(100, 1 << 20, 1 << 20), true).await;
    assert_eq!(b.fetch(0, one.as_bytes()).await.0, FetchStatus::Failed);
    let stats = client.end_job(B256::repeat_byte(2)).await.unwrap();
    assert!(stats.unanswerable && !stats.operator_failure, "{stats:?}");
    let v = builder_verdict(&BuilderOutcome {
        exit: Some(exit::TRAP),
        oom_killed: false,
        wall_clock_hit: false,
        operator_failure: stats.operator_failure,
        fetch_in_flight_at_end: stats.fetch_in_flight_at_end,
        in_flight_operator_wait: stats.in_flight_operator_wait,
        module_started: true,
        signal: None,
        miner_side_failure: false,
    });
    assert_eq!(v, Some(SkipReason::BuilderTrap));
    assert!(SkipReason::BuilderTrap.verdict().blames_caller);
}

/// PoC 4, inverted, with the real codec end to end: a node at height 0 ahead of one that has
/// the block. Its "resource not found" (by hash) and "BlockOutOfRangeError" (by number) are
/// lagging, and the node ahead answers; a number above every head is refused outright.
#[tokio::test]
async fn a_lagging_node_fails_over_to_one_that_has_the_block() {
    let behind = Anvil::start(&[]).await; // height 0
    let ahead = Anvil::start(&[]).await;
    ahead.mine(10).await;
    let hash5 = ahead.rpc("eth_getBlockByNumber", json!(["0x5", false])).await["hash"].as_str().unwrap().to_string();
    let dir = tempfile::tempdir().unwrap();
    let mut text = String::new();
    for (alias, a) in [("behind", &behind), ("ahead", &ahead)] {
        text.push_str(&evm(alias, &a.url, ANVIL_CHAIN, "archive = true\nmax_proof_age = 1000000\ncidrs = [\"127.0.0.1/32\"]"));
    }
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &text), Hooks::real()).await;
    let mut b = register(&client, 1, vec![anvil_cap()], budget(100, 1 << 20, 1 << 20), false).await;
    let direct = ahead.rpc("eth_getBalance", json!([DEV, "0x5"])).await;
    let by_hash = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["{DEV}",{{"blockHash":"{hash5}"}}]}}"#);
    let (s, body) = b.fetch(0, by_hash.as_bytes()).await;
    assert_eq!(s, FetchStatus::Ok);
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), json!({"jsonrpc":"2.0","id":1,"result":direct}));
    let by_num = format!(r#"{{"jsonrpc":"2.0","id":2,"method":"eth_getBalance","params":["{DEV}","0x5"]}}"#);
    let (s, body) = b.fetch(0, by_num.as_bytes()).await;
    assert_eq!(s, FetchStatus::Ok);
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), json!({"jsonrpc":"2.0","id":2,"result":direct}));
    // Above every head: status 1, one unit for the whole (refused) batch.
    let future = format!(
        r#"[{{"jsonrpc":"2.0","id":3,"method":"eth_getBalance","params":["{DEV}","0x1000"]}},{{"jsonrpc":"2.0","id":4,"method":"eth_chainId","params":[]}}]"#
    );
    assert_eq!(b.fetch(0, future.as_bytes()).await.0, FetchStatus::Denied);
    let stats = client.end_job(B256::repeat_byte(1)).await.unwrap();
    assert_eq!((stats.fetches, stats.denied), (3, 1), "1 + 1 + one unit for the refused batch");
    assert!(!stats.operator_failure && !stats.unanswerable);
}

/// The mock codec's explicit numbers: a head from a lagging first endpoint is not the last word.
#[tokio::test]
async fn an_explicit_number_is_checked_against_a_second_head() {
    let dir = tempfile::tempdir().unwrap();
    let (low, high) = (TestServer::start(mock_node(10)).await, TestServer::start(mock_node(100)).await);
    let text = config_text(
        dir.path(),
        &format!("{}{}", evm("low", &low.url(), 8453, "cidrs = [\"127.0.0.1/32\"]"), evm("high", &high.url(), 8453, "cidrs = [\"127.0.0.1/32\"]")),
    );
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut b = register(&client, 1, vec![mock_cap()], budget(100, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#""n:50""#).await.0, FetchStatus::Ok, "100 is the head");
    assert_eq!(b.fetch(0, br#"["n:101","a","b"]"#).await.0, FetchStatus::Denied);
    let stats = client.end_job(B256::repeat_byte(1)).await.unwrap();
    assert_eq!(stats.fetches, 2, "the refused batch of three costs one unit");
}

// ------------------------------------------------------------------------------------------------
// F3/F4: held-lock reserves in operator budgets and the spool.

/// PoC 2, inverted: a simulation cannot spend the held-lock share of an operator budget.
#[tokio::test]
async fn held_lock_work_keeps_its_share_of_an_operator_budget() {
    let dir = tempfile::tempdir().unwrap();
    let node = TestServer::start(mock_node(1)).await;
    let text = config_text(dir.path(), &evm("n", &node.url(), 8453, "cidrs = [\"127.0.0.1/32\"]\nmax_units_per_minute = 32"));
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut sim = register(&client, 1, vec![mock_cap()], budget(1000, 1 << 20, 1 << 20), false).await;
    let batch = |n: usize| serde_json::to_vec(&(0..n).map(|i| format!("c{i}")).collect::<Vec<_>>()).unwrap();
    assert_eq!(sim.fetch(0, &batch(32)).await.0, FetchStatus::Failed, "a whole budget is more than its shared part");
    assert_eq!(sim.fetch(0, &batch(24)).await.0, FetchStatus::Ok, "the shared part (75%)");
    assert_eq!(sim.fetch(0, br#""more""#).await.0, FetchStatus::Failed);
    let mut held = register(&client, 2, vec![mock_cap()], budget(1000, 1 << 20, 1 << 20), true).await;
    assert_eq!(held.fetch(0, br#""a""#).await.0, FetchStatus::Ok, "the held lock is not starved");
}

/// PoC 5, inverted: a result's byte permit lives until the result is written, so builders that
/// never read cannot run more bodies past the in-flight budget, and the held lock's blob fetch has
/// both its lane and spool room.
#[tokio::test]
async fn slow_readers_cannot_spend_the_held_locks_spool_and_lane() {
    let dir = tempfile::tempdir().unwrap();
    let content = pattern(1 << 20, 3);
    let id = sha256(&content);
    let path = format!("/b/{}", hex::encode(id));
    let mirror = {
        let c = content.clone();
        TestServer::start(move |r| if r.path == path { TestResponse::ok(c.clone()) } else { TestResponse::status(404) }).await
    };
    // 2 MiB in flight (1 MiB shared, 1 MiB held-lock), 3 MiB of spool (1.5 MiB held-lock).
    let text = config_text(
        dir.path(),
        &format!(
            "spool_quota_bytes = 3145728\n[budget]\ninflight_bytes = 2097152\nheld_lock_share = 0.5\n[timeouts]\npartial_frame_secs = 20\n\
             [[blob_mirror]]\nalias = \"m\"\nurl_template = \"{}/b/{{sha256}}\"\ncidrs = [\"127.0.0.1/32\"]\n",
            mirror.url()
        ),
    );
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let blob = (CLASS_BLOB_V1, encode_blob_config(1 << 20));
    let mut sims = Vec::new();
    for k in 0..3u8 {
        let mut b = register(&client, 10 + k, vec![blob.clone()], budget(10, 1 << 21, 1 << 20), false).await;
        b.send(0, &id).await; // ...and never read the result
        sims.push(b);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(mirror.hits(), 1, "the first unread result still holds the shared lane");
    let mut held = register(&client, 30, vec![blob.clone()], budget(10, 1 << 21, 1 << 20), true).await;
    let (s, body) = held.fetch(0, &id).await;
    assert_eq!(s, FetchStatus::Ok);
    assert_eq!(body, content);
    assert!(!client.end_job(B256::repeat_byte(30)).await.unwrap().operator_failure);
}

/// A builder that stops reading its result loses its socket after `partial_frame_secs`, and with
/// it the result's permit and spool file: the next simulation fetch proceeds.
#[tokio::test]
async fn a_slow_reader_times_out_and_releases_its_result() {
    let dir = tempfile::tempdir().unwrap();
    let content = pattern(1 << 20, 4);
    let id = sha256(&content);
    let mirror = {
        let c = content.clone();
        TestServer::start(move |_| TestResponse::ok(c.clone())).await
    };
    let text = config_text(
        dir.path(),
        &format!(
            "[budget]\ninflight_bytes = 2097152\nheld_lock_share = 0.5\n[timeouts]\npartial_frame_secs = 1\n\
             [[blob_mirror]]\nalias = \"m\"\nurl_template = \"{}/b/{{sha256}}\"\ncidrs = [\"127.0.0.1/32\"]\n",
            mirror.url()
        ),
    );
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let blob = (CLASS_BLOB_V1, encode_blob_config(1 << 20));
    let mut slow = register(&client, 1, vec![blob.clone()], budget(10, 1 << 21, 1 << 20), false).await;
    slow.send(0, &id).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut next = register(&client, 2, vec![blob.clone()], budget(10, 1 << 21, 1 << 20), false).await;
    let started = std::time::Instant::now();
    let (s, body) = tokio::time::timeout(Duration::from_secs(10), next.fetch(0, &id)).await.unwrap();
    assert_eq!((s, body.len()), (FetchStatus::Ok, content.len()));
    assert!(started.elapsed() >= Duration::from_millis(500), "it waited for the slow reader's permit");
    // The slow reader's socket was closed mid-result.
    let mut partial = Vec::new();
    let _ = tokio::io::AsyncReadExt::read_to_end(&mut slow.sock, &mut partial).await;
    assert!(partial.len() < content.len() + 6, "the result was cut off: {} bytes", partial.len());
}

// ------------------------------------------------------------------------------------------------
// F7: cached answers are charged to operator budgets as misses.

/// PoC 7, inverted: once the operator budget is spent, a cached pinned call is status 2 like an
/// uncached one; cache state cannot be read off the status.
#[tokio::test]
async fn cache_state_cannot_be_probed_through_status() {
    let dir = tempfile::tempdir().unwrap();
    let node = TestServer::start(mock_node(1)).await;
    let text = config_text(dir.path(), &evm("n", &node.url(), 8453, "cidrs = [\"127.0.0.1/32\"]\nmax_units_per_minute = 4"));
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut victim = register(&client, 1, vec![mock_cap()], budget(100, 1 << 20, 1 << 20), false).await;
    assert_eq!(victim.fetch(0, br#""h:victim-secret""#).await.0, FetchStatus::Ok);
    let mut p = register(&client, 2, vec![mock_cap()], budget(100, 1 << 20, 1 << 20), false).await;
    assert_eq!(p.fetch(0, br#"["a","b"]"#).await.0, FetchStatus::Ok);
    assert_eq!(p.fetch(0, br#""h:victim-secret""#).await.0, FetchStatus::Failed, "a hit, charged as a miss");
    assert_eq!(p.fetch(0, br#""h:never-read""#).await.0, FetchStatus::Failed);
    assert_eq!(node.hits(), 2, "the hit went to no endpoint");
    assert!(client.end_job(B256::repeat_byte(2)).await.unwrap().operator_failure);
}

// ------------------------------------------------------------------------------------------------
// F14 and the post-exhaustion frame cap.

/// A spent `maxFetchBytes` is status 3 at once, with no charge and no endpoint contact; a builder
/// that keeps sending frames past a spent budget loses its socket after
/// `MAX_FRAMES_AFTER_EXHAUSTION` of them.
#[tokio::test]
async fn a_spent_budget_is_status_3_at_once_and_spinning_on_it_closes_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let node = TestServer::start(mock_node(1)).await;
    let text = config_text(dir.path(), &evm("n", &node.url(), 8453, "cidrs = [\"127.0.0.1/32\"]"));
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    // "a@{}" with quotes is 6 bytes: the budget is spent after one fetch.
    let mut b = register(&client, 1, vec![mock_cap()], budget(100, 6, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#""a""#).await.0, FetchStatus::Ok);
    for _ in 0..MAX_FRAMES_AFTER_EXHAUSTION {
        assert_eq!(b.fetch(0, br#""b""#).await.0, FetchStatus::Exhausted);
    }
    assert_eq!(node.hits(), 1, "no endpoint contact past the spent budget");
    b.send(0, br#""c""#).await;
    assert!(b.recv().await.is_none(), "the socket is closed");
    let stats = client.end_job(B256::repeat_byte(1)).await.unwrap();
    assert_eq!(stats.fetches, 1, "no charge past the spent budget");
    assert_eq!(stats.frames_after_exhaustion, MAX_FRAMES_AFTER_EXHAUSTION + 1);
}

/// A malformed frame past a spent budget is status 3 too (no unit, no parse).
#[tokio::test]
async fn frames_past_a_spent_unit_budget_are_not_parsed() {
    let dir = tempfile::tempdir().unwrap();
    let node = TestServer::start(mock_node(1)).await;
    let text = config_text(dir.path(), &evm("n", &node.url(), 8453, "cidrs = [\"127.0.0.1/32\"]"));
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let mut b = register(&client, 1, vec![mock_cap()], budget(1, 1 << 20, 1 << 20), false).await;
    assert_eq!(b.fetch(0, br#""a""#).await.0, FetchStatus::Ok);
    // A raw frame without even a cap index.
    let mut frame = vec![KIND_FETCH];
    frame.extend_from_slice(&2u32.to_be_bytes());
    frame.extend_from_slice(b"{}");
    b.sock.write_all(&frame).await.unwrap();
    assert_eq!(b.recv().await.unwrap().0, FetchStatus::Exhausted);
    let stats = client.end_job(B256::repeat_byte(1)).await.unwrap();
    assert_eq!((stats.fetches, stats.denied, stats.frames_after_exhaustion), (1, 0, 1));
}
