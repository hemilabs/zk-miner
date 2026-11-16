//! The round-1 adversarial review of the private-network guard, broker lens: each reviewer PoC
//! (`guard-review/r1-broker/pocs/tests/broker_pocs.rs`, t1–t7), inverted to assert the fix.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use alloy_primitives::{Address, B256};
use zkminer_netguard::{FactsOptions, RawFacts, Route};
use zkminer_witness::envelope::{encode_evm_rpc_config, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ};
use zkminer_witness::ipc::{FetchStatus, JobBudget};
use zkminer_witness_broker::client::{job_socketpair, BrokerClient, JobRegistration};
use zkminer_witness_broker::egress::{Admit, NetMode, Role};
use zkminer_witness_broker::testkit::{
    config_text, mock_node, prefix, spawn_broker, test_egress_real_codec, test_hooks, FakeBuilder, TestRequest,
    TestResponse, TestServer,
};
use zkminer_witness_broker::{BrokerConfig, HostFacts};

fn cap() -> (B256, Vec<u8>) {
    (CLASS_EVM_RPC_V1, encode_evm_rpc_config(8453, false, METHOD_SET_STATE_READ, 0))
}

async fn register(client: &BrokerClient, job: u8, caller: u8) -> FakeBuilder {
    let budget = JobBudget { max_fetches: 100, max_fetch_bytes: 1 << 20, max_request_bytes: 65_536, max_response_bytes: 1 << 20 };
    let (builder, broker_end) = job_socketpair().unwrap();
    client
        .register_job(
            JobRegistration {
                job_key: B256::repeat_byte(job),
                caller: Address::repeat_byte(caller),
                sources: vec![cap()],
                budget,
                held_lock: false,
            },
            broker_end,
        )
        .await
        .expect("registered");
    FakeBuilder::new(builder, budget.max_response_bytes)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// t1 (F4): an IP-literal URL host with explicit global `cidrs` — a loopback literal — no longer
/// loads in public mode (nor in developer mode: the literal is outside its own role entry).
#[tokio::test]
async fn t1_a_loopback_literal_with_global_cidrs_is_refused_at_load() {
    let node = TestServer::start(mock_node(1)).await;
    let dir = tempfile::tempdir().unwrap();
    let text = config_text(
        dir.path(),
        &format!("[[evm_rpc]]\nalias = \"x\"\nurl = \"{}/\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\ncidrs = [\"1.1.1.0/24\"]\n", node.url()),
    );
    for mode in [NetMode::Public, NetMode::DevPrivate] {
        let e = BrokerConfig::from_toml(&text, dir.path(), mode).expect_err("a literal outside its cidrs").to_string();
        assert!(e.contains("outside the endpoint's cidrs"), "{e}");
    }
    assert_eq!(node.hits(), 0);
}

/// t2 (F5): a key over cleartext http to a global literal inside the endpoint's cidrs is refused
/// in public mode.
#[test]
fn t2_no_key_over_http_in_public_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k");
    std::fs::write(&key, "SECRETKEY123").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let text = config_text(
        dir.path(),
        &format!(
            "[[evm_rpc]]\nalias = \"p\"\nurl = \"http://1.1.1.1:8545/v1/{{key}}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\nkey_file = \"{}\"\ncidrs = [\"1.1.1.1/32\"]\n",
            key.display()
        ),
    );
    let e = BrokerConfig::from_toml(&text, dir.path(), NetMode::Public).expect_err("key over http").to_string();
    assert!(e.contains("only over https"), "{e}");
    assert!(!e.contains("SECRETKEY123"));
    let https = text.replace("http://1.1.1.1:8545", "https://1.1.1.1:8545");
    assert!(BrokerConfig::from_toml(&https, dir.path(), NetMode::Public).unwrap().evm_rpc[0].spec.key_bearing);
}

/// t3 (F1): a DHCPv6 host's address is a /128 and its on-link /64 a route. With the route read,
/// a neighbour in that /64 fails the public-mode config check and the per-connection floor; so do
/// one elsewhere in the site's /56 and one behind a VPN route.
#[test]
fn t3_an_on_link_neighbour_of_a_dhcpv6_host_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let own = ip("2606:4700:1::5");
    let net = zkminer_netguard::HostFacts::assemble(
        RawFacts {
            interface_prefixes: vec![prefix(&format!("{own}/128"))],
            interface_addresses: vec![own],
            routes: vec![
                Route::on_link(prefix("2606:4700:1::/64"), 2),
                Route::via(prefix("::/0"), ip("fe80::1"), 2),
                Route::via(prefix("45.60.1.0/24"), ip("10.8.0.1"), 7),
            ],
            ..RawFacts::default()
        },
        &FactsOptions { discover_public_addresses: false, ..FactsOptions::default() },
    );
    let facts = HostFacts::from_netguard(&net);
    for (alias, url) in [
        ("lan", "http://[2606:4700:1::6]:8545/"),
        ("site", "http://[2606:4700:1:7::6]:8545/"),
        ("vpn", "http://45.60.1.9:8545/"),
    ] {
        let text = config_text(
            dir.path(),
            &format!("[[evm_rpc]]\nalias = \"{alias}\"\nurl = \"{url}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\n"),
        );
        let cfg = BrokerConfig::from_toml(&text, dir.path(), NetMode::Public).expect("loads before the host is known");
        let e = cfg.validate_host(&facts).expect_err(alias).to_string();
        assert!(e.contains("role entry"), "{alias}: {e}");
        let policy = zkminer_witness_broker::net::build_policy(
            NetMode::Public,
            cfg.endpoints(),
            &facts.resolved,
            cfg.effective_deny_for(&facts),
            facts.connected.clone(),
            &facts.own_addresses,
        );
        let target = cfg.evm_rpc[0].spec.literal.unwrap();
        let a = policy.admit(Some((Role::EvmRpc, alias)), SocketAddr::new(target, 8545));
        assert!(matches!(a, Admit::Denied(_)), "{alias}: {a:?}");
    }
    // This host's real facts carry its routes' on-link prefixes too.
    let real = zkminer_netguard::HostFacts::gather_with(&FactsOptions { discover_public_addresses: false, ..FactsOptions::default() })
        .unwrap();
    let flat = HostFacts::from_netguard(&real).connected;
    for p in real.routes().on_link_prefixes() {
        assert!(flat.contains(&p), "{p}");
    }
}

/// t4 (F2): RPC cache hits are keyed by the requester, so one requester's job cannot tell by
/// timing whether another requester asked a query; jobs of the same requester still share them.
#[tokio::test]
async fn t4_cached_answers_are_not_shared_across_requesters() {
    let node = TestServer::start(|req: TestRequest| {
        let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        let one = |c: &serde_json::Value| serde_json::json!({"jsonrpc":"2.0","id":c["id"],"result":"0x1"});
        let out = match &v {
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(one).collect()),
            c => one(c),
        };
        TestResponse::ok(serde_json::to_vec(&out).unwrap()).delayed(Duration::from_millis(400))
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let text = config_text(
        dir.path(),
        &format!("[[evm_rpc]]\nalias = \"n\"\nurl = \"{}/\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n", node.url()),
    );
    // Developer mode only because the test node is on loopback; the cache is the same in both modes.
    let cfg = BrokerConfig::from_toml(&text, dir.path(), NetMode::DevPrivate).unwrap();
    let (client, _t) = spawn_broker(cfg, test_egress_real_codec()).await;
    let q = |h: u8| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0x{}",{{"blockHash":"0x{}"}}]}}"#,
            "11".repeat(20),
            format!("{h:02x}").repeat(32)
        )
        .into_bytes()
    };
    let mut victim = register(&client, 1, 1).await;
    assert_eq!(victim.fetch(0, &q(0xaa)).await.0, FetchStatus::Ok);
    assert_eq!(node.hits(), 1);
    // Another requester asking the same pinned query pays the endpoint's latency: a miss.
    let mut spy = register(&client, 2, 2).await;
    let t = Instant::now();
    assert_eq!(spy.fetch(0, &q(0xaa)).await.0, FetchStatus::Ok);
    assert!(t.elapsed() >= Duration::from_millis(350), "served from another requester's cache: {:?}", t.elapsed());
    assert_eq!(node.hits(), 2, "the spy's query reached the endpoint");
    // The victim's own next job is served from its cache.
    let mut again = register(&client, 3, 1).await;
    let t = Instant::now();
    assert_eq!(again.fetch(0, &q(0xaa)).await.0, FetchStatus::Ok);
    assert!(t.elapsed() < Duration::from_millis(350), "{:?}", t.elapsed());
    assert_eq!(node.hits(), 2);
}

/// t5: public mode, real floor and real host facts: DNS answers that spell loopback, metadata or
/// this host in any embedded form, or name its own /64, get no connection (unchanged; kept as a
/// regression).
#[tokio::test]
async fn t5_dns_answers_in_every_private_spelling_are_refused() {
    use zkminer_witness_broker::hooks::Hooks;
    use zkminer_witness_broker::testkit::TestDns;
    let node = TestServer::start(mock_node(1)).await;
    let real = zkminer_netguard::HostFacts::gather_with(&FactsOptions { discover_public_addresses: false, ..FactsOptions::default() })
        .unwrap();
    let mut answers: Vec<String> =
        ["127.0.0.1", "::ffff:127.0.0.1", "::ffff:0:7f00:1", "64:ff9b::7f00:1", "::7f00:1", "169.254.169.254", "::ffff:a9fe:a9fe", "100.100.100.200"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    answers.extend(real.own_addresses().iter().map(|i| i.to_string()));
    answers.extend(real.connected().iter().filter(|p| p.addr.is_ipv6() && zkminer_netguard::is_global(p.addr)).map(|p| match p.addr {
        IpAddr::V6(v) => std::net::Ipv6Addr::from(u128::from(v) | 0x1234).to_string(),
        _ => unreachable!(),
    }));
    let refs: Vec<&str> = answers.iter().map(|s| s.as_str()).collect();
    // (Not 1.1.1.0/24, as the PoC had: a host whose upstream DNS server is 1.1.1.1 now refuses
    // that role entry outright.)
    for cidrs in ["", "cidrs = [\"45.60.1.0/24\", \"::ffff:45.60.1.0/120\", \"2a00:1450:4001::/48\"]\n"] {
        let dns = TestDns::start(&[("rpc.example.com", &refs)]).await;
        let dir = tempfile::tempdir().unwrap();
        let text = config_text(
            dir.path(),
            &format!(
                "{}[egress]\ndiscover_public_addresses = false\n[[evm_rpc]]\nalias = \"p\"\nurl = \"http://rpc.example.com:{}/\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\n{cidrs}",
                dns.config(),
                node.port()
            ),
        );
        let cfg = BrokerConfig::from_toml(&text, dir.path(), NetMode::Public).expect("public config loads");
        let (client, _t) = spawn_broker(cfg, Hooks { codec: test_hooks().codec, egress: Hooks::real().egress }).await;
        let mut b = register(&client, 3, 3).await;
        let (st, _) = b.fetch(0, br#""a""#).await;
        assert_ne!(st, FetchStatus::Ok);
        assert_eq!(node.hits(), 0, "cidrs {cidrs:?}");
    }
}

/// t6 (F6): a deny CIDR written in NAT64, SIIT or IPv4-compatible form denies the IPv4 address
/// at connect time, as it already did at load.
#[test]
fn t6_a_deny_cidr_in_nat64_form_denies_the_ipv4_address() {
    let facts = zkminer_netguard::HostFacts::empty();
    for deny in ["64:ff9b::808:808/128", "::ffff:0:808:808/128", "::808:808/128", "::ffff:8.8.8.8/128"] {
        let d = vec![prefix(deny)];
        for a in ["8.8.8.8", "64:ff9b::808:808", "::ffff:8.8.8.8"] {
            assert!(zkminer_netguard::admit(NetMode::Public, ip(a), &facts, &d).is_err(), "deny {deny}: {a}");
        }
        assert!(zkminer_netguard::admit_prefix(NetMode::Public, prefix("8.8.8.8/32"), &facts, &d).is_err());
        let policy = zkminer_witness_broker::egress::EgressPolicy { deny: d, ..Default::default() };
        assert!(policy.public_floor(ip("8.8.8.8")).is_err(), "{deny}");
    }
}

/// t7 (the other side of F6): a DNS64 answer (NAT64 spelling) as a /128 role entry now matches
/// its own connection, in either spelling.
#[test]
fn t7_a_nat64_role_entry_matches_its_own_address() {
    use zkminer_witness_broker::egress::{EgressPolicy, RoleEntry};
    let a = ip("64:ff9b::808:808");
    let policy = EgressPolicy {
        mode: NetMode::Public,
        roles: vec![RoleEntry { role: Role::EvmRpc, alias: "p".into(), prefixes: vec![zkminer_netguard::Prefix::host(a)], port: 443 }],
        deny: vec![],
        facts: zkminer_netguard::HostFacts::empty(),
    };
    assert!(policy.dns_admissible(a));
    for target in [a, ip("8.8.8.8")] {
        assert_eq!(policy.admit(Some((Role::EvmRpc, "p")), SocketAddr::new(target, 443)), Admit::Role, "{target}");
    }
    assert_eq!(policy.admit(Some((Role::EvmRpc, "p")), SocketAddr::new(ip("8.8.4.4"), 443)), Admit::Denied(zkminer_witness_broker::egress::DenyReason::NoRoleEntry));
}
