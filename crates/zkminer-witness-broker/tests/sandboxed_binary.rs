//! The real broker binary under the real sandbox, against anvil: spawned through the sandbox launcher
//! into a job cgroup with its control socket at fd 3, it restricts itself (Landlock: no readable
//! file, the spool dir writable, TCP connect only to the configured ports; seccomp; no new
//! privileges), then serves a builder's `evm-rpc/v1` and `blob/v1` fetches and `hemi-code` reads
//! through the real codec and floor, resolves host names with its own resolver (UDP, no `bind`),
//! passes its own self-test, sandbox checks included, and exits 0 when the control socket closes.
//!
//! Needs a delegated cgroup:
//!
//! ```text
//! systemd-run --user --scope -q -p Delegate=yes -- \
//!     env ZKMINER_SANDBOX_TESTS_REQUIRED=1 cargo test -p zkminer-witness-broker --test sandboxed_binary
//! ```

mod common;

use std::io::Write;
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use alloy_primitives::{Address, B256};
use common::*;
use zkminer_witness::envelope::{encode_evm_rpc_config, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ};
use zkminer_witness::ipc::{FetchStatus, JobBudget, SelfTestCheck};
use zkminer_witness_broker::client::{job_socketpair, BrokerClient, JobRegistration};
use zkminer_witness_broker::testkit::{config_text, FakeBuilder, TestDns, TestResponse, TestServer};
use zkminer_witness_sandbox::{
    delegated_root, landlock_abi, prepare_command, Cgroup, CgroupSpec, SandboxError, MIN_LANDLOCK_ABI,
};

const BROKER: &str = env!("CARGO_BIN_EXE_zkminer-witness-broker");
const ANVIL_CHAIN: u64 = 31337;

fn skip(test: &str, reason: &str) {
    if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
        panic!("{test}: sandbox unavailable: {reason}");
    }
    let _ = writeln!(std::io::stderr(), "SKIPPED {test}: {reason}");
}

fn delegated(test: &str) -> Option<PathBuf> {
    let abi = landlock_abi();
    if abi < MIN_LANDLOCK_ABI {
        skip(test, &format!("Landlock ABI {abi} < {MIN_LANDLOCK_ABI}"));
        return None;
    }
    match delegated_root() {
        Ok(root) => Some(root),
        Err(e @ SandboxError::NotDelegated { .. }) => {
            skip(test, &e.to_string());
            None
        }
        Err(e) => panic!("{test}: delegated_root: {e}"),
    }
}

fn status_field(pid: u32, field: &str) -> String {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    s.lines()
        .find_map(|l| l.strip_prefix(field).map(|v| v.trim().to_string()))
        .unwrap_or_else(|| panic!("{field} missing"))
}

#[tokio::test]
async fn the_broker_binary_serves_under_the_sandbox() {
    let Some(root) = delegated("the_broker_binary_serves_under_the_sandbox") else { return };
    let anvil = Anvil::start(&[]).await;
    anvil.mine(3).await;
    // The config and spool live on the real disk (the broker refuses nothing here, but keep tmpfs out).
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let endpoint = format!(
        "[[evm_rpc]]\nalias = \"anvil\"\nurl = \"{}\"\nchain_id = {ANVIL_CHAIN}\narchive = true\nmax_proof_age = 1000000\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n",
        anvil.url
    );
    let config = dir.path().join("broker.toml");
    std::fs::write(&config, config_text(dir.path(), &endpoint)).unwrap();

    let cg = Cgroup::create(
        &root,
        &CgroupSpec {
            name: format!("broker-test-{}", std::process::id()),
            memory_max: 512 << 20,
            pids_max: 32,
            cpu_max: None,
            cpu_weight: 50,
        },
    )
    .unwrap();
    let (miner_end, broker_end) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut cmd = Command::new(BROKER);
    cmd.arg("--config").arg(&config).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    cmd.env("RUST_LOG", "warn");
    prepare_command(&mut cmd, &cg, &[(broker_end.as_fd(), 3)]).unwrap();
    let mut child = cmd.spawn().unwrap();
    drop(broker_end);
    drop(cmd);
    let pid = child.id();

    let client = BrokerClient::new(miner_end).unwrap();
    let (builder_end, broker_job_end) = job_socketpair().unwrap();
    let max_response_bytes = 1 << 20;
    let reg = client
        .register_job(
            JobRegistration {
                job_key: B256::repeat_byte(7),
                caller: Address::repeat_byte(8),
                sources: vec![(CLASS_EVM_RPC_V1, encode_evm_rpc_config(ANVIL_CHAIN, true, METHOD_SET_STATE_READ, 0))],
                budget: JobBudget { max_fetches: 10, max_fetch_bytes: 1 << 22, max_request_bytes: 65_536, max_response_bytes },
                held_lock: false,
            },
            broker_job_end,
        )
        .await;
    if let Err(e) = reg {
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        panic!("register_job: {e:?}; broker {:?} stderr:\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    }

    // The broker is up and restricted.
    assert_eq!(status_field(pid, "Seccomp:"), "2");
    assert_eq!(status_field(pid, "NoNewPrivs:"), "1");
    assert!(std::fs::read(format!("/proc/{pid}/environ")).is_err(), "environ readable");
    let threads: u32 = status_field(pid, "Threads:").parse().unwrap();
    assert!(threads <= 13, "{threads} threads");

    let mut b = FakeBuilder::new(builder_end, max_response_bytes);
    let (s, body) = b.fetch(0, br#"{"jsonrpc":"2.0","id":7,"method":"eth_chainId","params":[]}"#).await;
    assert_eq!(s, FetchStatus::Ok, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body, br#"{"jsonrpc":"2.0","id":7,"result":"0x7a69"}"#);
    // A tag the broker resolves itself, inside the sandbox.
    let (s, body) = b
        .fetch(
            0,
            br#"{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","latest"]}"#,
        )
        .await;
    assert_eq!(s, FetchStatus::Ok, "{}", String::from_utf8_lossy(&body));
    // A method outside the set is refused.
    let (s, _) = b.fetch(0, br#"{"jsonrpc":"2.0","id":1,"method":"debug_setHead","params":["0x1"]}"#).await;
    assert_eq!(s, FetchStatus::Denied);

    // The self-test, from inside the sandbox: every check passes, sandbox checks included.
    let r = client.self_test().await.unwrap();
    for c in [
        SelfTestCheck::SeccompActive,
        SelfTestCheck::NoNewPrivs,
        SelfTestCheck::LandlockActive,
        SelfTestCheck::GpuNodeUnopenable,
        SelfTestCheck::LoopbackDenied,
        SelfTestCheck::MetadataDenied,
        SelfTestCheck::Rfc1918Denied,
        SelfTestCheck::EndpointsReachable,
    ] {
        assert!(r.checks.contains(&(c, true)), "{c:?}: {r:?}");
    }
    assert!(r.ok, "{r:?}");

    let stats = client.end_job(B256::repeat_byte(7)).await.unwrap();
    assert_eq!(stats.fetches, 3);
    assert_eq!(stats.denied, 1);

    // Closing the control socket ends the broker, cleanly.
    drop(client);
    let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await.unwrap().unwrap();
    assert_eq!(out.status.code(), Some(0), "{:?}; stderr:\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    cg.remove().unwrap();
}

/// Spawns the broker binary into a fresh cgroup with `config`; returns the client and the child.
fn spawn_broker_binary(root: &std::path::Path, config: &std::path::Path, tag: &str) -> (BrokerClient, std::process::Child, Cgroup) {
    let cg = Cgroup::create(
        root,
        &CgroupSpec { name: format!("broker-test-{tag}-{}", std::process::id()), memory_max: 512 << 20, pids_max: 32, cpu_max: None, cpu_weight: 50 },
    )
    .unwrap();
    let (miner_end, broker_end) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut cmd = Command::new(BROKER);
    cmd.arg("--config").arg(config).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    cmd.env("RUST_LOG", "warn");
    prepare_command(&mut cmd, &cg, &[(broker_end.as_fd(), 3)]).unwrap();
    let child = cmd.spawn().unwrap();
    drop(broker_end);
    (BrokerClient::new(miner_end).unwrap(), child, cg)
}

/// `blob/v1` (spool files under Landlock), `hemi-code` (memfds, seals, `SCM_RIGHTS`, a cached
/// duplicate) and an endpoint named by host name, resolved at startup and again inside the sandbox
/// by the broker's own resolver.
#[tokio::test]
async fn blob_hemi_code_and_host_names_under_the_sandbox() {
    let Some(root) = delegated("blob_hemi_code_and_host_names_under_the_sandbox") else { return };
    let anvil = Anvil::start(&[]).await;
    anvil.mine(3).await;
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let blob_content = pattern(300_000, 9);
    let blob_id = zkminer_witness::manifest::sha256(&blob_content);
    let blob_path = format!("/b/{}", hex::encode(blob_id));
    let mirror = {
        let c = blob_content.clone();
        TestServer::start(move |r| if r.path == blob_path { TestResponse::ok(c.clone()) } else { TestResponse::status(404) }).await
    };
    let published = publish(&anvil, &pattern(50_000, 4), 20_000).await;
    anvil.mine(40).await;
    let dns = TestDns::start(&[("anvil.test", &["127.0.0.1"])]).await;
    let endpoint = format!(
        "{}reresolve_secs = 1\n\
         [[evm_rpc]]\nalias = \"anvil\"\nurl = \"http://anvil.test:{}\"\nchain_id = {ANVIL_CHAIN}\narchive = true\nmax_proof_age = 1000000\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n\
         [[blob_mirror]]\nalias = \"m\"\nurl_template = \"{}/b/{{sha256}}\"\ncidrs = [\"127.0.0.1/32\"]\n\
         [artifacts]\nalias = \"hemi\"\nurl = \"{}\"\nchain_id = {ANVIL_CHAIN}\nmax_requests_per_sec = 1000\ncidrs = [\"127.0.0.1/32\"]\n",
        dns.config(),
        anvil.port,
        mirror.url(),
        anvil.url
    );
    let config = dir.path().join("broker.toml");
    std::fs::write(&config, config_text(dir.path(), &endpoint)).unwrap();
    let (client, mut child, cg) = spawn_broker_binary(&root, &config, "names");
    let pid = child.id();

    let (builder_end, broker_job_end) = job_socketpair().unwrap();
    let max_response_bytes = 1 << 20;
    let reg = client
        .register_job(
            JobRegistration {
                job_key: B256::repeat_byte(7),
                caller: Address::repeat_byte(8),
                sources: vec![
                    (CLASS_EVM_RPC_V1, encode_evm_rpc_config(ANVIL_CHAIN, true, METHOD_SET_STATE_READ, 0)),
                    (zkminer_witness::envelope::CLASS_BLOB_V1, zkminer_witness::envelope::encode_blob_config(1 << 20)),
                ],
                budget: JobBudget { max_fetches: 10, max_fetch_bytes: 1 << 22, max_request_bytes: 65_536, max_response_bytes },
                held_lock: false,
            },
            broker_job_end,
        )
        .await;
    if let Err(e) = reg {
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        panic!("register_job: {e:?}; broker {:?} stderr:\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    }
    assert_eq!(status_field(pid, "Seccomp:"), "2");
    let mut b = FakeBuilder::new(builder_end, max_response_bytes);
    let chain_id = br#"{"jsonrpc":"2.0","id":7,"method":"eth_chainId","params":[]}"#;
    let (s, body) = b.fetch(0, chain_id).await;
    assert_eq!(s, FetchStatus::Ok, "{}", String::from_utf8_lossy(&body));
    // The name is resolved again inside the sandbox once its answer is a second old.
    let before = dns.queries();
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    assert_eq!(b.fetch(0, chain_id).await.0, FetchStatus::Ok);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(dns.queries() > before, "no DNS query from inside the sandbox");
    assert_eq!(b.fetch(0, chain_id).await.0, FetchStatus::Ok, "still served after the new answer");

    // blob/v1: a spool file in spool_dir (O_TMPFILE under Landlock), written off the runtime.
    let (s, body) = b.fetch(1, &blob_id).await;
    assert_eq!(s, FetchStatus::Ok, "blob under the sandbox");
    assert_eq!(body, blob_content);
    // hemi-code: memfd_create, F_ADD_SEALS, SCM_RIGHTS; then the cached duplicate.
    let fetch = || {
        client.fetch_artifact(
            zkminer_witness_broker::client::ArtifactRequest {
                job_key: B256::repeat_byte(7),
                caller: Address::repeat_byte(8),
                source: zkminer_witness::ipc::ArtifactSource::HemiCode { chain_id: ANVIL_CHAIN, manifest: published.manifest },
                builder_type: 1,
                expected_sha256: Some(published.sha256),
                max_bytes: 1 << 20,
                held_lock: false,
            },
            |_| async { true },
        )
    };
    let a = fetch().await.unwrap().expect("hemi-code under the sandbox");
    assert_eq!(a.len, 50_000);
    let again = fetch().await.unwrap().expect("cached duplicate under the sandbox");
    assert!(again.cached);
    let mut bytes = vec![0u8; 50_000];
    std::os::unix::fs::FileExt::read_exact_at(&again.memfd, &mut bytes, 0).unwrap();
    assert_eq!(bytes, published.bytes);

    let r = client.self_test().await.unwrap();
    assert!(r.ok, "{r:?}");
    let stats = client.end_job(B256::repeat_byte(7)).await.unwrap();
    assert_eq!(stats.fetches, 4);
    assert!(!stats.operator_failure && !stats.unanswerable);
    drop(client);
    let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await.unwrap().unwrap();
    assert_eq!(out.status.code(), Some(0), "{:?}; stderr:\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    cg.remove().unwrap();
}
