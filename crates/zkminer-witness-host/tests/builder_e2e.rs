//! A whole builder run on the real binaries: the broker binary (sandboxed, its own cgroup) in front
//! of anvil, and the runner binary (sandboxed, a job cgroup) running the SDK's example builder, which
//! fetches `eth_getBlockByNumber("finalized")` through the broker and writes `number ‖ hash` as W.
//!
//! Needs a delegated cgroup and anvil:
//!
//! ```text
//! systemd-run --user --scope -q -p Delegate=yes -- \
//!     env ZKMINER_SANDBOX_TESTS_REQUIRED=1 cargo test -p zkminer-witness-host --test builder_e2e
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy_primitives::{Address, B256};
use zkminer_witness::context::{build_context, encode_context, DescriptorFields};
use zkminer_witness::envelope::{
    encode_evm_rpc_config, effective_limits, Capability, HostMaxima, Limits, CLASS_EVM_RPC_V1, METHOD_SET_STATE_READ,
};
use zkminer_witness::ipc::JobBudget;
use zkminer_witness::verdict::SkipReason;
use zkminer_witness::WitnessJobV1;
use zkminer_witness_broker::client::JobRegistration;
use zkminer_witness_host::broker_proc::BrokerProcess;
use zkminer_witness_host::builder_run::{run_builder, BuilderRun, VecSink};
use zkminer_witness_host::spawner::Spawner;
use zkminer_witness_sandbox::{delegated_root, landlock_abi, SandboxError, MIN_LANDLOCK_ABI};

const ANVIL_CHAIN: u64 = 31337;

fn skip(test: &str, reason: &str) {
    if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
        panic!("{test}: sandbox unavailable: {reason}");
    }
    let _ = writeln!(std::io::stderr(), "SKIPPED {test}: {reason}");
}

fn delegated(test: &str) -> Option<PathBuf> {
    if landlock_abi() < MIN_LANDLOCK_ABI {
        skip(test, "Landlock too old");
        return None;
    }
    match delegated_root() {
        Ok(r) => Some(r),
        Err(e @ SandboxError::NotDelegated { .. }) => {
            skip(test, &e.to_string());
            None
        }
        Err(e) => panic!("{test}: {e}"),
    }
}

/// The workspace target dir this test binary lives in (`<target>/debug/deps/<test>`).
fn target_dir() -> PathBuf {
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().parent().unwrap().to_path_buf()
}

/// Builds the runner and broker binaries into this test's target dir and returns their paths.
fn binaries() -> (PathBuf, PathBuf) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args(["build", "-p", "zkminer-witness-builder", "-p", "zkminer-witness-broker", "--bins", "--target-dir"])
        .arg(target_dir())
        .output()
        .expect("cargo runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let debug = target_dir().join("debug");
    (debug.join("zkminer-witness-builder"), debug.join("zkminer-witness-broker"))
}

fn sdk_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk").canonicalize().unwrap()
}

fn sdk_tool(tool: &str) -> std::ffi::OsString {
    let out = Command::new("rustup").args(["which", tool]).current_dir(sdk_dir()).env_remove("RUSTUP_TOOLCHAIN").output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8(o.stdout).unwrap().trim().into(),
        _ => tool.into(),
    }
}

/// The SDK's example builder, built with the SDK's pinned toolchain and target features.
fn example_wasm() -> Vec<u8> {
    let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("sdk-target-host-e2e");
    let mut cmd = Command::new(sdk_tool("cargo"));
    cmd.current_dir(sdk_dir())
        .args(["build", "--locked", "--release", "--target", "wasm32-unknown-unknown", "-p", "latest-block", "--target-dir"])
        .arg(&target)
        .env("RUSTC", sdk_tool("rustc"));
    for v in ["RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_DIR"] {
        cmd.env_remove(v);
    }
    let out = cmd.output().expect("cargo runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    std::fs::read(target.join("wasm32-unknown-unknown/release/latest_block.wasm")).unwrap()
}

struct Anvil {
    child: Child,
    url: String,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn rpc(url: &str, method: &str, params: &str) -> serde_json_lite::Value {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let out = Command::new("curl")
        .args(["-s", "-H", "content-type: application/json", "-d", &body, url])
        .output()
        .expect("curl");
    serde_json_lite::parse(&String::from_utf8_lossy(&out.stdout))
}

fn start_anvil() -> Anvil {
    let port = free_port();
    let child = Command::new("anvil")
        .args(["--port", &port.to_string(), "--silent"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("anvil on PATH");
    let a = Anvil { child, url: format!("http://127.0.0.1:{port}") };
    for _ in 0..100 {
        if rpc(&a.url, "eth_chainId", "[]").get("result").is_some() {
            return a;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("anvil did not start");
}

/// A tiny JSON reader for test assertions (no extra dev-dependency).
mod serde_json_lite {
    pub type Value = std::collections::HashMap<String, String>;
    /// Flat string fields of the top object and of a `result` object (enough for these RPCs).
    pub fn parse(s: &str) -> Value {
        let mut m = Value::new();
        let mut rest = s;
        while let Some(i) = rest.find("\":") {
            let key_start = rest[..i].rfind('"').map(|j| j + 1).unwrap_or(0);
            let key = rest[key_start..i].to_string();
            let after = rest[i + 2..].trim_start();
            if let Some(stripped) = after.strip_prefix('"') {
                if let Some(end) = stripped.find('"') {
                    m.entry(key).or_insert_with(|| stripped[..end].to_string());
                }
            } else if after.starts_with('{') {
                m.entry(key).or_insert_with(|| "{".into());
            }
            rest = &rest[i + 2..];
        }
        m
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_builder_fetches_through_the_broker_and_w_reaches_the_sink() {
    let Some(root) = delegated("a_builder_fetches_through_the_broker_and_w_reaches_the_sink") else { return };
    let (runner_bin, broker_bin) = binaries();
    let wasm = example_wasm();
    let anvil = start_anvil();
    rpc(&anvil.url, "anvil_mine", "[\"0x64\"]"); // 100 blocks, so `finalized` (latest − 64) is non-zero
    let finalized = rpc(&anvil.url, "eth_getBlockByNumber", "[\"finalized\",false]");
    let want_number = u64::from_str_radix(finalized["number"].trim_start_matches("0x"), 16).unwrap();
    let want_hash = finalized["hash"].clone();

    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let config = dir.path().join("broker.toml");
    std::fs::write(
        &config,
        format!(
            "chain_rpc_host = \"chain-rpc.invalid\"\nspool_dir = \"{}\"\n[[evm_rpc]]\nalias = \"anvil\"\nurl = \"{}\"\n\
             chain_id = {ANVIL_CHAIN}\narchive = true\nmax_proof_age = 1000000\nmethod_sets = [\"state-read\"]\n\
             cidrs = [\"127.0.0.1/32\"]\n",
            dir.path().join("spool").display(),
            anvil.url
        ),
    )
    .unwrap();
    let spawner = Spawner::new().unwrap();
    let broker = BrokerProcess::start(&spawner, &broker_bin, &config, &root, 512 << 20).unwrap();

    let source = Capability {
        class: CLASS_EVM_RPC_V1,
        config: encode_evm_rpc_config(ANVIL_CHAIN, true, METHOD_SET_STATE_READ, 0).into(),
    };
    let declared = Limits {
        maxFetches: 16,
        maxFetchBytes: 1 << 22,
        maxRequestBytes: 65_536,
        maxResponseBytes: 1 << 20,
        maxBuilderFuel: 1_000_000_000,
        maxBuilderMemoryBytes: 64 << 20,
        maxBuilderSeconds: 30,
        maxWitnessBytes: 1 << 20,
        maxGuestCycles: 1 << 26,
    };
    let host = HostMaxima {
        max_witness_bytes: 32 << 20,
        max_guest_cycles: 1 << 30,
        max_fetches: 1_024,
        max_fetch_bytes: 1 << 28,
        max_request_bytes: 65_536,
        max_response_bytes: 32 << 20,
        max_builder_fuel: 20_000_000_000,
        max_builder_memory_bytes: 512 << 20,
        max_builder_seconds: 120,
    };
    let limits = effective_limits(&declared, &host).unwrap();
    let job = WitnessJobV1 {
        builderType: 1,
        builderId: B256::ZERO,
        builderURIs: vec![],
        builderParams: vec![].into(),
        sources: vec![source.clone()],
        limits: declared.clone(),
    };
    let d = DescriptorFields {
        program_id: B256::repeat_byte(1),
        proof_system_id: B256::repeat_byte(2),
        expected_journal_hash: B256::repeat_byte(3),
        journal_fields: B256::repeat_byte(4),
    };
    let context = encode_context(&build_context(743_111, Address::repeat_byte(5), &d, &job));
    let job_key = B256::repeat_byte(0x42);
    let (result, sink) = run_builder(
        &spawner,
        &broker.client,
        &BuilderRun { binary: &runner_bin, cgroup_root: &root, job_key, module: &wasm, context: &context, limits: &limits },
        JobRegistration {
            job_key,
            caller: Address::repeat_byte(6),
            sources: vec![(source.class, source.config.to_vec())],
            budget: JobBudget {
                max_fetches: limits.maxFetches,
                max_fetch_bytes: limits.maxFetchBytes,
                max_request_bytes: limits.maxRequestBytes,
                max_response_bytes: limits.maxResponseBytes,
            },
            held_lock: false,
        },
        VecSink::default(),
    )
    .await
    .unwrap();
    assert_eq!(result.verdict, None, "outcome {:?}\nlog:\n{}", result.outcome, result.log);
    assert!(result.outcome.module_started);
    let mut want = want_number.to_be_bytes().to_vec();
    want.extend_from_slice(&hex::decode(want_hash.trim_start_matches("0x")).unwrap());
    assert_eq!(sink.0, want, "W must be the finalized block's number ‖ hash");
    assert_eq!(result.w_bytes, 40);
    let stats = result.stats.unwrap();
    assert_eq!(stats.fetches, 1);
    assert!(!stats.operator_failure);

    // A module that spins: FUEL, the caller's, and no W kept.
    let spin = wat::parse_str(
        r#"(module (memory (export "memory") 1) (func (export "run") (result i32) (loop $l (br $l)) (i32.const 0)))"#,
    )
    .unwrap();
    let job_key = B256::repeat_byte(0x43);
    let mut small = limits.clone();
    small.maxBuilderFuel = 1_000_000;
    let (result, sink) = run_builder(
        &spawner,
        &broker.client,
        &BuilderRun { binary: &runner_bin, cgroup_root: &root, job_key, module: &spin, context: &context, limits: &small },
        JobRegistration {
            job_key,
            caller: Address::repeat_byte(6),
            sources: vec![(source.class, source.config.to_vec())],
            budget: JobBudget { max_fetches: 1, max_fetch_bytes: 1, max_request_bytes: 65_536, max_response_bytes: 1 },
            held_lock: false,
        },
        VecSink::default(),
    )
    .await
    .unwrap();
    assert_eq!(result.verdict, Some(SkipReason::BuilderFuelExhausted), "{:?}\n{}", result.outcome, result.log);
    assert!(sink.0.is_empty());
    drop(broker);
}
