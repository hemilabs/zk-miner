//! Proxy environment variables are ignored (review gap). Its own test binary: it sets process
//! environment variables before anything else runs.

mod common;

use alloy_primitives::B256;
use common::*;
use zkminer_witness::envelope::{encode_evm_rpc_config, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ};
use zkminer_witness::ipc::FetchStatus;
use zkminer_witness_broker::testkit::{config_text, mock_node, test_hooks, TestServer};

#[tokio::test]
async fn proxy_environment_variables_are_ignored() {
    let proxy = TestServer::start(mock_node(1)).await;
    for k in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        // SAFETY: this binary's only test; nothing else reads the environment concurrently.
        unsafe { std::env::set_var(k, proxy.url()) };
    }
    let dir = tempfile::tempdir().unwrap();
    // The endpoint is down: a proxy that honoured the variables would answer instead.
    let text = config_text(
        dir.path(),
        "[[evm_rpc]]\nalias = \"n\"\nurl = \"http://127.0.0.1:1/\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n",
    );
    let (client, _t) = start(dir.path(), &text, test_hooks()).await;
    let cap = (CLASS_EVM_RPC_V1, encode_evm_rpc_config(8453, false, METHOD_SET_STATE_READ, 0));
    let mut b = register(&client, 1, vec![cap], budget(10, 1 << 20, 1 << 20), false).await;
    let (s, _) = b.fetch(0, br#""a""#).await;
    assert_eq!(proxy.hits(), 0, "the proxy was used");
    assert_eq!(s, FetchStatus::Failed);
    assert!(client.end_job(B256::repeat_byte(1)).await.unwrap().operator_failure);
}
