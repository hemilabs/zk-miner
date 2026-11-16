//! The real broker binary under the real sandbox, against anvil: spawned through the sandbox launcher
//! into a job cgroup with its control socket at fd 3, it restricts itself (Landlock: resolver files
//! read-only, the spool dir writable, TCP connect only to the configured ports; seccomp; no new
//! privileges), then serves a builder's `evm-rpc/v1` fetches through the real codec and floor and
//! passes its own self-test, sandbox checks included.
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
use zkminer_witness_broker::testkit::{config_text, FakeBuilder};
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

    // Closing the control socket ends the broker.
    drop(client);
    let status = tokio::task::spawn_blocking(move || child.wait()).await.unwrap().unwrap();
    assert!(status.success() || status.code().is_some(), "{status:?}");
    cg.remove().unwrap();
}
