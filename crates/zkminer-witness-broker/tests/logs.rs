//! Keys never reach the broker's logs, at TRACE for every crate (review PoC 7 and F9), with the
//! subscriber the binary installs: [`logging::Redacting`] over the sink, [`logging::env_filter`].
//! Its own test binary: the subscriber is process-wide.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::B256;
use common::*;
use zkminer_witness::envelope::{encode_evm_rpc_config, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ};
use zkminer_witness::ipc::FetchStatus;
use zkminer_witness_broker::hooks::Hooks;
use zkminer_witness_broker::logging::{env_filter, Redacting};
use zkminer_witness_broker::testkit::{config_text, mock_node, test_hooks, TestResponse, TestServer};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn keys_never_reach_the_logs_even_at_trace() {
    let buf = Buf::default();
    let w = buf.clone();
    tracing_subscriber::fmt()
        .with_env_filter(env_filter(Some("trace")))
        .with_writer(Redacting(move || w.clone()))
        .with_ansi(false)
        .try_init()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    for (n, k) in [("p.key", "PATHKEYSECRET123"), ("h.key", "HDRKEYSECRET456")] {
        let p = dir.path().join(n);
        std::fs::write(&p, k).unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    }
    let e500 = TestServer::start(|_| TestResponse::status(500)).await;
    let good = TestServer::start(mock_node(3)).await;
    let ep = |alias: &str, url: String, key: &str| {
        format!(
            "[[evm_rpc]]\nalias = \"{alias}\"\nurl = \"{url}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n{key}\n"
        )
    };
    let text = config_text(
        dir.path(),
        &[
            ep("dead", "http://127.0.0.1:1/v2/{key}".into(), "key_file = \"p.key\""),
            ep("e500", format!("{}/v2/{{key}}", e500.url()), "key_file = \"p.key\""),
            ep("hdr", format!("{}/h", e500.url()), "key_file = \"h.key\"\nkey_header = \"x-api-key\""),
            ep("good", format!("{}/v2/{{key}}", good.url()), "key_file = \"p.key\""),
        ]
        .concat(),
    );
    let (client, _t) = start(dir.path(), &text, Hooks { codec: test_hooks().codec, egress: Hooks::real().egress }).await;
    let cap = (CLASS_EVM_RPC_V1, encode_evm_rpc_config(8453, false, METHOD_SET_STATE_READ, 0));
    let mut b = register(&client, 1, vec![cap], budget(100, 1 << 20, 1 << 20), false).await;
    let (s, body) = b.fetch(0, br#"["latest","x"]"#).await;
    assert_eq!(s, FetchStatus::Ok);
    let _ = client.self_test().await.unwrap();
    client.end_job(B256::repeat_byte(1)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let logs = String::from_utf8_lossy(&buf.0.lock().unwrap()).to_string();
    assert!(logs.lines().count() > 10, "captured: {logs}");
    assert!(logs.contains("evm-rpc request failed"), "the failures were logged: {logs}");
    assert!(!logs.contains("PATHKEYSECRET123") && !logs.contains("HDRKEYSECRET456"), "a key leaked:\n{logs}");
    assert!(!logs.contains("http://"), "a URL reached the log:\n{logs}");
    assert!(logs.lines().all(|l| l.bytes().all(|c| (0x20..0x7f).contains(&c))), "every line is printable ASCII");
    assert!(!String::from_utf8_lossy(&body).contains("SECRET"));
}
