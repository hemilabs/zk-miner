//! The control channel: provisioning, registration errors, the self-test and prefix refreshes.

mod common;

use std::os::fd::AsFd;

use alloy_primitives::B256;
use common::*;
use zkminer_witness::envelope::{
    encode_blob_config, encode_evm_rpc_config, CLASS_BLOB_V1, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ,
    METHOD_SET_STATE_TRACE,
};
use zkminer_witness::ipc::{
    encode_control, ControlErrorCode, ControlMessage, ControlRequest, IpPrefix, SelfTestCheck, KIND_CONTROL,
};
use zkminer_witness_broker::client::{job_socketpair, ClientError, JobRegistration};
use zkminer_witness_broker::fdpass::{recv_with_fd, send_with_fd};
use zkminer_witness_broker::hooks::Hooks;
use zkminer_witness_broker::hostinfo::own_addresses;
use zkminer_witness_broker::testkit::{config_text, prefix, test_hooks, MockCodec, TestEgress, TestServer};

const EVM: &str = r#"
[[evm_rpc]]
alias = "base-archive"
url = "http://127.0.0.1:1"
chain_id = 8453
archive = true
max_proof_age = 1000
method_sets = ["state-read"]
cidrs = ["127.0.0.1/32"]

[[evm_rpc]]
alias = "mainnet-tip"
url = "http://127.0.0.1:2"
chain_id = 1
max_proof_age = 10
method_sets = ["state-read", "state-trace"]
cidrs = ["127.0.0.1/32"]
"#;

fn evm(chain: u64, archive: bool, set: B256, age: u64) -> (B256, Vec<u8>) {
    (CLASS_EVM_RPC_V1, encode_evm_rpc_config(chain, archive, set, age))
}

#[tokio::test]
async fn provisioning_is_per_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let (client, _t) = start(dir.path(), &config_text(dir.path(), EVM), test_hooks()).await;
    let ok = client
        .check_provisioned(vec![
            evm(8453, true, METHOD_SET_STATE_READ, 1000),
            evm(8453, true, METHOD_SET_STATE_READ, 1001), // deeper proofs than served
            evm(8453, false, METHOD_SET_STATE_TRACE, 0),  // method set not listed
            evm(1, true, METHOD_SET_STATE_READ, 0),       // archive not served
            evm(1, false, METHOD_SET_STATE_TRACE, 10),
            evm(10, false, METHOD_SET_STATE_READ, 0), // chain not served
            (CLASS_BLOB_V1, encode_blob_config(100)), // no mirror
            (B256::repeat_byte(9), vec![]),           // unknown class
            (CLASS_EVM_RPC_V1, vec![1, 2, 3]),        // undecodable config
        ])
        .await
        .unwrap();
    assert_eq!(ok, vec![true, false, false, false, true, false, false, false, false]);

    let with_mirror = format!("{EVM}\n[[blob_mirror]]\nalias = \"m\"\nurl_template = \"http://127.0.0.1:3/{{sha256}}\"\ncidrs = [\"127.0.0.1/32\"]\n");
    let (client, _t) = start(dir.path(), &config_text(dir.path(), &with_mirror), test_hooks()).await;
    assert_eq!(client.check_provisioned(vec![(CLASS_BLOB_V1, encode_blob_config(1))]).await.unwrap(), vec![true]);
}

#[tokio::test]
async fn registration_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (client, _t) = start(dir.path(), &config_text(dir.path(), EVM), test_hooks()).await;
    let reg = |key: u8, sources| JobRegistration {
        job_key: B256::repeat_byte(key),
        caller: Default::default(),
        sources,
        budget: budget(10, 1000, 1000),
        held_lock: false,
    };
    let (_b, end) = job_socketpair().unwrap();
    let e = client.register_job(reg(1, vec![(CLASS_BLOB_V1, encode_blob_config(1))]), end).await.unwrap_err();
    assert!(matches!(e, ClientError::Refused(ControlErrorCode::NotProvisioned)), "{e:?}");
    let (_b, end) = job_socketpair().unwrap();
    client.register_job(reg(2, vec![evm(1, false, METHOD_SET_STATE_READ, 0)]), end).await.unwrap();
    let (_b2, end) = job_socketpair().unwrap();
    let e = client.register_job(reg(2, vec![evm(1, false, METHOD_SET_STATE_READ, 0)]), end).await.unwrap_err();
    assert!(matches!(e, ClientError::Refused(ControlErrorCode::DuplicateJob)), "{e:?}");
    // A job's socket must be a Unix stream socket: a memfd is refused.
    let m = zkminer_witness_broker::fdpass::memfd(c"x").unwrap();
    let e = client.register_job(reg(3, vec![evm(1, false, METHOD_SET_STATE_READ, 0)]), m.into()).await.unwrap_err();
    assert!(matches!(e, ClientError::Refused(ControlErrorCode::Malformed)), "{e:?}");
    let e = client.end_job(B256::repeat_byte(77)).await.unwrap_err();
    assert!(matches!(e, ClientError::Refused(ControlErrorCode::UnknownJob)), "{e:?}");
    let stats = client.end_job(B256::repeat_byte(2)).await.unwrap();
    assert_eq!(
        (stats.fetches, stats.fetch_bytes, stats.operator_failure, stats.unanswerable, stats.fetch_in_flight_at_end),
        (0, 0, false, false, false)
    );
}

/// Raw frames: an fd on a message that takes none, or none on `RegisterJob`, is malformed; junk is
/// answered with id 0 and the channel stays up.
#[tokio::test]
async fn raw_control_frames() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = zkminer_witness_broker::BrokerConfig::from_toml(&config_text(dir.path(), EVM), dir.path(), zkminer_witness_broker::egress::NetMode::DevPrivate).unwrap();
    let (miner, broker) = std::os::unix::net::UnixStream::pair().unwrap();
    let conn = zkminer_witness_broker::testkit::connector_end(&cfg, &test_hooks()).await;
    let _t = tokio::spawn(zkminer_witness_broker::serve_with(cfg, broker.into(), conn, test_hooks()));
    let miner = tokio::task::spawn_blocking(move || {
        let ask = |id: u64, body: ControlRequest, fd: Option<std::os::fd::BorrowedFd<'_>>| {
            send_with_fd(&miner, KIND_CONTROL, &encode_control(&ControlMessage { id, body }), fd).unwrap();
            let f = recv_with_fd(&miner, 1 << 16).unwrap().unwrap();
            let m: ControlMessage<zkminer_witness::ipc::ControlResponse> =
                zkminer_witness::ipc::decode_control(&f.payload).unwrap();
            (m.id, m.body)
        };
        let m = zkminer_witness_broker::fdpass::memfd(c"x").unwrap();
        let (id, body) = ask(5, ControlRequest::SelfTest, Some(m.as_fd()));
        assert_eq!(id, 5);
        assert!(matches!(body, zkminer_witness::ipc::ControlResponse::Error { code: ControlErrorCode::Malformed }));
        let reg = ControlRequest::RegisterJob {
            job_key: B256::ZERO,
            caller: Default::default(),
            sources: vec![],
            budget: budget(1, 1, 1),
            held_lock: false,
        };
        let (id, body) = ask(6, reg, None);
        assert_eq!(id, 6);
        assert!(matches!(body, zkminer_witness::ipc::ControlResponse::Error { code: ControlErrorCode::Malformed }));
        send_with_fd(&miner, KIND_CONTROL, b"not json", None).unwrap();
        let f = recv_with_fd(&miner, 1 << 16).unwrap().unwrap();
        assert!(String::from_utf8_lossy(&f.payload).contains(r#""id":0"#));
        // Still serving.
        let (id, body) = ask(7, ControlRequest::CheckProvisioned { sources: vec![] }, None);
        assert_eq!(id, 7);
        assert!(matches!(body, zkminer_witness::ipc::ControlResponse::Provisioned { ok } if ok.is_empty()));
        miner
    })
    .await
    .unwrap();
    drop(miner);
}

/// Control ids: many requests in flight at once are each answered once under their own id; a
/// request reusing the id of one still being served is refused with id 0 and does not disturb it;
/// the id is free again once its request was answered.
#[tokio::test]
async fn concurrent_and_reused_control_ids() {
    use zkminer_witness::ipc::ControlResponse;
    let dir = tempfile::tempdir().unwrap();
    // A slow endpoint keeps a SelfTest in flight for a while.
    let slow = TestServer::start(|req| {
        let r = chain_id_node(8453)(req);
        r.delayed(std::time::Duration::from_millis(1_500))
    })
    .await;
    let text = config_text(
        dir.path(),
        &format!("[[evm_rpc]]\nalias = \"slow\"\nurl = \"{}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n", slow.url()),
    );
    let cfg = zkminer_witness_broker::BrokerConfig::from_toml(&text, dir.path(), zkminer_witness_broker::egress::NetMode::DevPrivate).unwrap();
    let (miner, broker) = std::os::unix::net::UnixStream::pair().unwrap();
    let conn = zkminer_witness_broker::testkit::connector_end(&cfg, &test_hooks()).await;
    let _t = tokio::spawn(zkminer_witness_broker::serve_with(cfg, broker.into(), conn, test_hooks()));
    tokio::task::spawn_blocking(move || {
        let send = |id: u64, body: ControlRequest| {
            send_with_fd(&miner, KIND_CONTROL, &encode_control(&ControlMessage { id, body }), None).unwrap();
        };
        let recv = || {
            let f = recv_with_fd(&miner, 1 << 16).unwrap().unwrap();
            let m: ControlMessage<ControlResponse> = zkminer_witness::ipc::decode_control(&f.payload).unwrap();
            (m.id, m.body)
        };
        let check = || ControlRequest::CheckProvisioned { sources: vec![evm(8453, false, METHOD_SET_STATE_READ, 0)] };
        // The long request, then 20 quick ones interleaved.
        send(7, ControlRequest::SelfTest);
        for id in 100..120 {
            send(id, check());
        }
        // Reusing 7 while the self-test runs: refused (id 0), whatever the request.
        send(7, check());
        send(7, ControlRequest::SelfTest);
        // A charge decision for nothing pending is ignored (no answer).
        send(8, ControlRequest::ChargeDecision { proceed: true });
        let mut answers = std::collections::HashMap::new();
        let mut refused = 0;
        for _ in 0..23 {
            let (id, body) = recv();
            match (id, body) {
                (0, ControlResponse::Error { code: ControlErrorCode::Malformed }) => refused += 1,
                (id, body) => assert!(answers.insert(id, body).is_none(), "id {id} answered twice"),
            }
        }
        assert_eq!(refused, 2);
        for id in 100..120 {
            assert_eq!(answers.get(&id), Some(&ControlResponse::Provisioned { ok: vec![true] }), "{id}");
        }
        assert!(matches!(answers.get(&7), Some(ControlResponse::SelfTest { .. })), "the pending request kept its answer");
        // Answered: 7 may be used again.
        send(7, check());
        assert_eq!(recv(), (7, ControlResponse::Provisioned { ok: vec![true] }));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn self_test_and_prefix_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let node = TestServer::start(chain_id_node(8453)).await;
    let artifact = TestServer::start(chain_id_node(743111)).await;
    let text = config_text(
        dir.path(),
        &format!(
            r#"
[egress]
deny_cidrs = ["8.8.4.0/24"]

[[evm_rpc]]
alias = "base"
url = "{}"
chain_id = 8453
method_sets = ["state-read"]

[artifacts]
alias = "hemi"
url = "{}"
chain_id = 743111
"#,
            node.url(),
            artifact.url()
        ),
    );
    // The test floor's connected prefixes cover the host's own addresses, as the real ones do.
    let connected: Vec<_> = own_addresses().unwrap().into_iter().map(|ip| prefix(&format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }))).collect();
    let hooks = Hooks { egress: std::sync::Arc::new(TestEgress { connected }), codec: std::sync::Arc::new(MockCodec) };
    let (client, _t) = start(dir.path(), &text, hooks).await;
    let r = client.self_test().await.unwrap();
    let checks: std::collections::HashMap<_, _> = r.checks.iter().copied().collect();
    for c in [
        SelfTestCheck::LoopbackDenied,
        SelfTestCheck::MetadataDenied,
        SelfTestCheck::Rfc1918Denied,
        SelfTestCheck::OwnAddressDenied,
        SelfTestCheck::ConnectedPrefixDenied,
        SelfTestCheck::EndpointsReachable,
        SelfTestCheck::ArtifactEndpointChainId,
    ] {
        assert_eq!(checks.get(&c), Some(&true), "{c:?}: {r:?}");
    }
    assert_eq!(checks.get(&SelfTestCheck::ConnectorRefusesBadIndex), Some(&true), "{r:?}");
    // This test broker is not sandboxed, so its in-process sandbox and no-network checks fail and
    // with them `ok`; nothing else does.
    let failing: Vec<_> = r.checks.iter().filter(|(_, p)| !p).map(|(c, _)| *c).collect();
    for c in &failing {
        assert!(in_process_only(c), "{c:?}: {r:?}");
    }
    assert!(failing.contains(&SelfTestCheck::SeccompActive));
    assert!(failing.contains(&SelfTestCheck::InetSocketDenied) && failing.contains(&SelfTestCheck::ConnectDenied));
    assert!(!r.ok);

    // The miner reports a global own address outside every connected prefix. The broker's old
    // floor refused own addresses only through their prefix, so this self-test used to fail;
    // netguard's floor refuses the host's own addresses themselves.
    // Review r2 B2: a refresh adds to the broker's own startup facts and never takes them away.
    let base = client.refresh_prefixes(vec![], vec!["8.8.8.8".parse().unwrap()]).await.unwrap();
    assert!(base as usize >= own_addresses().unwrap().len(), "the startup prefixes stay: {base}");
    let r = client.self_test().await.unwrap();
    assert!(!r.ok, "the in-process sandbox checks still fail here");
    assert!(r.checks.contains(&(SelfTestCheck::OwnAddressDenied, true)), "{r:?}");
    assert!(r.checks.contains(&(SelfTestCheck::ConnectedPrefixDenied, true)), "{r:?}");
    // Refreshed with its prefix, it passes again; deny CIDRs count too.
    let n = client
        .refresh_prefixes(vec![IpPrefix { addr: "8.8.8.8".parse().unwrap(), len: 24 }], vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()])
        .await
        .unwrap();
    assert_eq!(n, base + 1);
    let r = client.self_test().await.unwrap();
    assert!(r.checks.iter().all(|(c, p)| *p || in_process_only(c)), "only the in-process sandbox checks may fail here: {r:?}");
    let e = client.refresh_prefixes(vec![IpPrefix { addr: "1.2.3.4".parse().unwrap(), len: 40 }], vec![]).await.unwrap_err();
    assert!(matches!(e, ClientError::Refused(ControlErrorCode::Malformed)));

    // A wrong chain id fails its check.
    let wrong = TestServer::start(chain_id_node(1)).await;
    let text = config_text(dir.path(), &format!("[artifacts]\nalias = \"hemi\"\nurl = \"{}\"\nchain_id = 743111\n", wrong.url()));
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let r = client.self_test().await.unwrap();
    assert!(r.checks.contains(&(SelfTestCheck::ArtifactEndpointChainId, false)));
    assert!(!r.ok);
}

/// The checks an unsandboxed, in-process broker fails by construction.
fn in_process_only(c: &SelfTestCheck) -> bool {
    matches!(
        c,
        SelfTestCheck::SeccompActive
            | SelfTestCheck::NoNewPrivs
            | SelfTestCheck::LandlockActive
            | SelfTestCheck::GpuNodeUnopenable
            | SelfTestCheck::InetSocketDenied
            | SelfTestCheck::ConnectDenied
            | SelfTestCheck::SocketOptionsDenied
    )
}
