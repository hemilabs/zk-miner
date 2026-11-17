//! `zkminer simulate --adversarial` on the real scheme-1 witness of plan §12: an EIP-1967 proxy on
//! anvil, the job encoded by `zkminer witness envelope encode`, the reference builder
//! (`sdk/examples/proxy-slots`) run by the miner's own pipeline behind the real broker and runner,
//! the reference guest on the CPU executor (the sandboxed `zkminer-prove-risc0-cpu
//! --witness-execute`), and every attack: scheme 1's structural mutations from the prelude's codec
//! (the parent and the next block's header swapped in, fetched through the job's own `evm-rpc`
//! source), the generic ones, the host inputs and two providers. None may change the answer under
//! the pinned header.
//!
//! Needs a delegated cgroup, anvil, the risc0 toolchain and the SDK's pinned toolchain:
//!
//! ```text
//! systemd-run --user --scope -q -p Delegate=yes -- \
//!     env ZKMINER_SANDBOX_TESTS_REQUIRED=1 CARGO_TARGET_DIR=... \
//!     cargo test -p hemiprove-proxy-slots-methods --test simulate_adversarial
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy_primitives::keccak256;
use hemiprove_proxy_slots::{decode_journal, Rule, RuleKind, Statement, EIP1967_IMPLEMENTATION_SLOT};
use hemiprove_proxy_slots_methods::PROXY_SLOTS_ELF;
use serde_json::Value;

const ANVIL_CHAIN: u64 = 31337;
const DEV: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const PROVER: &str = "0x00000000000000000000000000000000000000b0";

fn delegated(test: &str) -> bool {
    match zkminer_witness_sandbox::delegated_root() {
        Ok(_) => true,
        Err(e) => {
            if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
                panic!("{test}: {e}");
            }
            let _ = writeln!(std::io::stderr(), "SKIPPED {test}: {e}");
            false
        }
    }
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

/// The workspace target dir this test binary lives in (`<target>/debug/deps/<test>`).
fn target_dir() -> PathBuf {
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().parent().unwrap().to_path_buf()
}

fn cargo_build(args: &[&str]) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(repo())
        .arg("build")
        .args(args)
        .arg("--target-dir")
        .arg(target_dir())
        .output()
        .expect("cargo runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

/// `zkminer` and what it finds next to itself: the runner, the broker, the sandbox probe and the CPU
/// risc0 worker.
fn zkminer() -> PathBuf {
    cargo_build(&["-p", "zkminer-cli", "--bin", "zkminer", "-p", "zkminer-witness-builder", "-p", "zkminer-witness-broker", "-p", "zkminer-witness-sandbox", "--bins"]);
    cargo_build(&["-p", "zkminer-prove-risc0", "--features", "cpu", "--bin", "zkminer-prove-risc0-cpu"]);
    target_dir().join("debug/zkminer")
}

fn sdk_tool(tool: &str) -> std::ffi::OsString {
    let out = Command::new("rustup").args(["which", tool]).current_dir(repo().join("sdk")).env_remove("RUSTUP_TOOLCHAIN").output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8(o.stdout).unwrap().trim().into(),
        _ => tool.into(),
    }
}

/// The reference builder, built with the SDK's pinned toolchain.
fn builder_wasm() -> Vec<u8> {
    let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("sdk-target-proxy-slots");
    let mut cmd = Command::new(sdk_tool("cargo"));
    cmd.current_dir(repo().join("sdk"))
        .args(["build", "--locked", "--release", "--target", "wasm32-unknown-unknown", "-p", "proxy-slots-builder", "--target-dir"])
        .arg(&target)
        .env("RUSTC", sdk_tool("rustc"));
    for v in ["RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_DIR"] {
        cmd.env_remove(v);
    }
    let out = cmd.output().expect("cargo runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    std::fs::read(target.join("wasm32-unknown-unknown/release/proxy_slots_builder.wasm")).unwrap()
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

impl Anvil {
    fn start() -> Self {
        // A free port of its own: never another test's node.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let child = Command::new("anvil")
            .args(["--port", &port.to_string(), "--silent"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("anvil on PATH");
        let a = Anvil { child, url: format!("http://127.0.0.1:{port}") };
        for _ in 0..100 {
            if a.try_rpc("eth_chainId", "[]").is_some() {
                return a;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("anvil did not start");
    }

    fn try_rpc(&self, method: &str, params: &str) -> Option<Value> {
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
        let out = Command::new("curl").args(["-s", "-H", "content-type: application/json", "-d", &body, &self.url]).output().ok()?;
        let v: Value = serde_json::from_slice(&out.stdout).ok()?;
        v.get("result").cloned()
    }

    fn rpc(&self, method: &str, params: &str) -> Value {
        self.try_rpc(method, params).unwrap_or_else(|| panic!("{method} {params}"))
    }

    fn deploy(&self, creation: &[u8]) -> [u8; 20] {
        let hash = self.rpc("eth_sendTransaction", &format!(r#"[{{"from":"{DEV}","data":"0x{}"}}]"#, hex::encode(creation)));
        for _ in 0..100 {
            if let Some(r) = self.try_rpc("eth_getTransactionReceipt", &format!("[{hash}]")).filter(|r| !r.is_null()) {
                assert_eq!(r["status"], "0x1");
                return hex::decode(&r["contractAddress"].as_str().unwrap()[2..]).unwrap().try_into().unwrap();
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("no receipt");
    }
}

/// Creation code: `SSTORE(slot, value)` for each pair, then return `runtime` (as anvil_e2e.rs).
fn creation(stores: &[([u8; 32], [u8; 32])], runtime: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    for (slot, value) in stores {
        c.push(0x7f);
        c.extend_from_slice(value);
        c.push(0x7f);
        c.extend_from_slice(slot);
        c.push(0x55);
    }
    let len = u16::try_from(runtime.len()).unwrap().to_be_bytes();
    let offset = u16::try_from(c.len() + 15).unwrap().to_be_bytes();
    c.extend_from_slice(&[0x61, len[0], len[1], 0x61, offset[0], offset[1], 0x60, 0x00, 0x39, 0x61, len[0], len[1], 0x60, 0x00, 0xf3]);
    c.extend_from_slice(runtime);
    c
}

/// The implementation of anvil_e2e.rs (stores calldata word 1 at the slot word 0 names, returns 42).
const IMPLEMENTATION_RUNTIME: [u8; 14] = [0x60, 0x20, 0x35, 0x5f, 0x35, 0x55, 0x60, 0x2a, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];

/// An EIP-1967 proxy (as anvil_e2e.rs).
fn proxy_runtime() -> Vec<u8> {
    let mut r = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x7f];
    r.extend_from_slice(&EIP1967_IMPLEMENTATION_SLOT);
    r.extend_from_slice(&[0x54, 0x5a, 0xf4, 0x3d, 0x5f, 0x5f, 0x3e, 0x60, 0x36, 0x57, 0x3d, 0x5f, 0xfd, 0x5b, 0x3d, 0x5f, 0xf3]);
    r
}

fn word(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

#[test]
fn simulate_adversarial_attacks_the_real_scheme1_witness() {
    if !delegated("simulate_adversarial_attacks_the_real_scheme1_witness") {
        return;
    }
    let zkminer = zkminer();
    let wasm = builder_wasm();
    let anvil = Anvil::start();

    // The proxy: slots 10–12 under rule 1, pointing at the implementation.
    let implementation = anvil.deploy(&creation(&[], &IMPLEMENTATION_RUNTIME));
    let mut imp_word = [0u8; 32];
    imp_word[12..].copy_from_slice(&implementation);
    let stores = [(EIP1967_IMPLEMENTATION_SLOT, imp_word), (word(10), word(100)), (word(11), word(101)), (word(12), word(102))];
    let proxy = anvil.deploy(&creation(&stores, &proxy_runtime()));
    anvil.rpc("anvil_mine", "[\"0x3\"]");
    let b = anvil.rpc("eth_getBlockByNumber", "[\"latest\",false]");
    let block_hash: [u8; 32] = hex::decode(&b["hash"].as_str().unwrap()[2..]).unwrap().try_into().unwrap();
    // A block after B, for the "next block" header the scheme's mutations swap in.
    anvil.rpc("anvil_mine", "[\"0x2\"]");
    let statement = Statement { block_hash, proxy, rule: Rule::new(RuleKind::Consecutive, &word(10)).unwrap(), k: 3 };

    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let d = dir.path();
    std::fs::create_dir_all(d.join("spool")).unwrap();
    let rpc = |alias: &str| {
        format!(
            "[[evm_rpc]]\nalias = \"{alias}\"\nurl = \"{}\"\nchain_id = {ANVIL_CHAIN}\narchive = true\nmax_proof_age = 1000000\n\
             method_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n",
            anvil.url
        )
    };
    std::fs::write(
        d.join("broker.toml"),
        format!("chain_rpc_host = \"chain-rpc.invalid\"\nspool_dir = \"{}\"\n{}{}", d.join("spool").display(), rpc("anvil-a"), rpc("anvil-b")),
    )
    .unwrap();
    std::fs::write(
        d.join("config.toml"),
        format!(
            "[chain]\nchain_id = {ANVIL_CHAIN}\nrpc_url = \"{}\"\n[contracts]\nhemi_prove = \"0x000000000000000000000000000000000000a11c\"\n\
             hemi_prove_staking = \"0x000000000000000000000000000000000000a11d\"\n\
             hemi_prove_registry = \"0x000000000000000000000000000000000000a11e\"\n\
             hemi_token = \"0x000000000000000000000000000000000000a11f\"\n[dev]\nprivate_network = true\nchain_id = {ANVIL_CHAIN}\n\
             [witness]\nsandbox_mode = \"rootless\"\n[broker]\nconfig = \"{}\"\n",
            anvil.url,
            d.join("broker.toml").display()
        ),
    )
    .unwrap();
    let image_id = risc0_zkvm::compute_image_id(PROXY_SLOTS_ELF).unwrap();
    let words: Vec<String> = statement.header_words().iter().map(|w| format!("\"word:0x{}\"", hex::encode(w))).collect();
    std::fs::write(
        d.join("job.toml"),
        format!(
            "program_id = \"0x{}\"\n[binding]\nprefix = true\nheader = [{}]\n[envelope]\nbuilder_params = \"0x{}\"\n\
             [[envelope.sources]]\nclass = \"evm-rpc/v1\"\nchain_id = {ANVIL_CHAIN}\narchive = true\nmethod_set = \"state-read\"\n\
             max_proof_age = 1000\n[envelope.limits]\nmax_fetches = 8\nmax_fetch_bytes = 4194304\nmax_request_bytes = 65536\n\
             max_response_bytes = 1048576\nmax_builder_fuel = 5000000000\nmax_builder_memory_bytes = 67108864\n\
             max_builder_seconds = 60\nmax_witness_bytes = 1048576\nmax_guest_cycles = 67108864\n",
            hex::encode(image_id.as_bytes()),
            words.join(", "),
            hex::encode(statement.builder_params(ANVIL_CHAIN))
        ),
    )
    .unwrap();
    std::fs::write(d.join("builder.wasm"), &wasm).unwrap();
    std::fs::write(d.join("guest.elf"), PROXY_SLOTS_ELF).unwrap();
    let run = |args: &[&str]| {
        Command::new(&zkminer).arg("-c").arg(d.join("config.toml")).args(args).env("HOME", d).current_dir(d).output().unwrap()
    };
    let out = run(&["witness", "envelope", "encode", "job.toml", "--builder", "builder.wasm", "--descriptor-out", "d.json"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    // The binding pins the whole header, by the requester's own tool.
    let out = run(&["witness", "binding", "check", "--descriptor", "d.json", "--statement", &format!("0x{}", hex::encode(statement.header()))]);
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));

    let started = std::time::Instant::now();
    let out = run(&[
        "simulate", "--descriptor", "d.json", "--builder", "builder.wasm", "--elf", "guest.elf", "--po2", "20", "--prover", PROVER,
        "--cache-dir", "cache", "--out", "report.json", "--adversarial", "--adversarial-secs", "1500", "--flips", "4",
        "--max-mutations", "64", "--providers", "anvil-a,anvil-b",
    ]);
    let report: Value = serde_json::from_slice(&std::fs::read(d.join("report.json")).unwrap_or_default()).unwrap_or(Value::Null);
    eprintln!("simulate --adversarial took {:.0} s", started.elapsed().as_secs_f64());
    assert_eq!(report["outcome"], "simulated", "{}\n{report:#}", String::from_utf8_lossy(&out.stderr));

    // The honest run answers the statement at B.
    let journal = hex::decode(&report["journal"]["hex"].as_str().unwrap()[2..]).unwrap();
    let j = decode_journal(&journal).unwrap();
    assert_eq!(j.outputs.implementation, implementation);
    assert_eq!(j.outputs.code_hash, keccak256(IMPLEMENTATION_RUNTIME).0);
    assert_eq!(j.outputs.slots.iter().map(|(_, v)| *v).collect::<Vec<_>>(), vec![word(100), word(101), word(102)]);
    assert_eq!(report["binding"]["ok"], true);
    assert_eq!(report["builder"]["fetches"], 4, "header, implementation slot, two proofs");

    // The attacks.
    let a = &report["adversarial"];
    eprintln!("adversarial: {}", serde_json::to_string(&a["counts"]).unwrap());
    assert_eq!(a["scheme"]["id"], 1);
    assert_eq!(a["scheme"]["name"], "eth-block");
    assert!(a["scheme"]["status"].as_str().unwrap().contains("2 of 2 fetched answers used"), "{}", a["scheme"]);
    let mutations = a["mutations"].as_array().unwrap();
    for id in ["scheme1:header0=parent", "scheme1:header0=next-block"] {
        let m = mutations.iter().find(|m| m["id"] == id).unwrap_or_else(|| panic!("{id} not tried"));
        assert_eq!(m["outcome"], "rejected_in_guest", "{m}");
    }
    assert!(mutations.iter().any(|m| m["kind"] == "flip-kind"));
    assert!(mutations.iter().any(|m| m["kind"] == "swap-proofs"));
    assert!(mutations.iter().any(|m| m["kind"] == "flip"), "the generic mutations ran too");
    assert_eq!(a["counts"]["soundnessFailures"], 0, "{a:#}");
    assert_eq!(a["counts"]["notRun"], 0, "within the bound");
    assert!(a["hostInputs"].as_array().unwrap().iter().all(|h| h["dependent"] == false && h["ran"] == true));
    assert_eq!(a["differential"]["journalSame"], true, "{:#}", a["differential"]);
    assert_eq!(a["verdict"], "pass", "{a:#}");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}
