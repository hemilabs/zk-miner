//! `zkminer simulate --adversarial` on the real scheme-1 witness of plan §12: an EIP-1967 proxy on
//! anvil, the job encoded by `zkminer witness envelope encode`, the reference builder
//! (`sdk/examples/proxy-slots`) run by the miner's own pipeline behind the real broker and runner,
//! the reference guest on the CPU executor (the sandboxed `zkminer-prove-risc0-cpu
//! --witness-execute`), and every attack: scheme 1's structural mutations from the prelude's codec
//! (the parent and the next block's header swapped in, fetched through the job's own `evm-rpc`
//! source), the generic ones, the host inputs and two providers. None may change the answer under
//! the pinned header.
//!
//! And what those attacks must catch, each shown here end to end:
//! - a binding that pins fewer header words than the guest commits (a free header word is
//!   exploitable only with a consistent change of `W`, so the mutations alone never see it);
//! - a journal that depends on the `sys_rand` seed or on the keccak po2 (the `hostdep` guest);
//! - two providers that disagree (the SDK's `latest-block` builder against two anvils).
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
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use alloy_primitives::keccak256;
use hemiprove_proxy_slots::{decode_journal, Rule, RuleKind, Statement, EIP1967_IMPLEMENTATION_SLOT};
use hemiprove_proxy_slots_methods::{HOSTDEP_ELF, KECCAK_3_0_ELF, PROXY_SLOTS_ELF};
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

/// One test at a time: they share the delegated cgroup, and each starts brokers and sandboxes.
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
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

/// An SDK builder (`package`, its module `file`), built with the SDK's pinned toolchain, one package
/// per invocation.
fn sdk_wasm(package: &str, file: &str) -> Vec<u8> {
    let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sdk-target-{package}"));
    let mut cmd = Command::new(sdk_tool("cargo"));
    cmd.current_dir(repo().join("sdk"))
        .args(["build", "--locked", "--release", "--target", "wasm32-unknown-unknown", "-p", package, "--target-dir"])
        .arg(&target)
        .env("RUSTC", sdk_tool("rustc"));
    for v in ["RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_DIR"] {
        cmd.env_remove(v);
    }
    let out = cmd.output().expect("cargo runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    std::fs::read(target.join(format!("wasm32-unknown-unknown/release/{file}"))).unwrap()
}

/// The reference builder.
fn builder_wasm() -> Vec<u8> {
    sdk_wasm("proxy-slots-builder", "proxy_slots_builder.wasm")
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

/// A work directory: the miner's configuration (developer mode on anvil's chain) and the broker's,
/// with `a` as provider `anvil-a` and `b` as `anvil-b`.
struct World {
    dir: tempfile::TempDir,
    zkminer: PathBuf,
}

impl World {
    fn new(zkminer: PathBuf, a: &Anvil, b: &Anvil) -> Self {
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("spool")).unwrap();
        let rpc = |alias: &str, url: &str| {
            format!(
                "[[evm_rpc]]\nalias = \"{alias}\"\nurl = \"{url}\"\nchain_id = {ANVIL_CHAIN}\narchive = true\n\
                 max_proof_age = 1000000\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n"
            )
        };
        std::fs::write(
            d.join("broker.toml"),
            format!(
                "chain_rpc_host = \"chain-rpc.invalid\"\nspool_dir = \"{}\"\n{}{}",
                d.join("spool").display(),
                rpc("anvil-a", &a.url),
                rpc("anvil-b", &b.url)
            ),
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
                a.url,
                d.join("broker.toml").display()
            ),
        )
        .unwrap();
        World { dir, zkminer }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn run(&self, args: &[&str]) -> Output {
        let d = self.dir.path();
        Command::new(&self.zkminer)
            .arg("-c")
            .arg(d.join("config.toml"))
            .args(args)
            .env("HOME", d)
            .current_dir(d)
            .output()
            .unwrap()
    }

    /// `job.toml` for `elf` (its image id) built by `wasm` with `params`, bound by `binding` (a
    /// `[binding]` body), encoded into the descriptor file `d.json`; the guest saved as `guest.elf`.
    fn job(&self, elf: &[u8], wasm: &[u8], binding: &str, params: &[u8]) {
        self.job_with_cycles(elf, wasm, binding, params, 67108864)
    }

    /// [`World::job`] with `maxGuestCycles` of `max_guest_cycles`.
    fn job_with_cycles(
        &self,
        elf: &[u8],
        wasm: &[u8],
        binding: &str,
        params: &[u8],
        max_guest_cycles: u64,
    ) {
        let image_id = risc0_zkvm::compute_image_id(elf).unwrap();
        std::fs::write(
            self.path("job.toml"),
            format!(
                "program_id = \"0x{}\"\n[binding]\n{binding}\n[envelope]\nbuilder_params = \"0x{}\"\n\
                 [[envelope.sources]]\nclass = \"evm-rpc/v1\"\nchain_id = {ANVIL_CHAIN}\narchive = true\nmethod_set = \"state-read\"\n\
                 max_proof_age = 1000\n[envelope.limits]\nmax_fetches = 8\nmax_fetch_bytes = 4194304\nmax_request_bytes = 65536\n\
                 max_response_bytes = 1048576\nmax_builder_fuel = 5000000000\nmax_builder_memory_bytes = 67108864\n\
                 max_builder_seconds = 60\nmax_witness_bytes = 1048576\nmax_guest_cycles = {max_guest_cycles}\n",
                hex::encode(image_id.as_bytes()),
                hex::encode(params)
            ),
        )
        .unwrap();
        std::fs::write(self.path("builder.wasm"), wasm).unwrap();
        std::fs::write(self.path("guest.elf"), elf).unwrap();
        let out = self.run(&[
            "witness",
            "envelope",
            "encode",
            "job.toml",
            "--builder",
            "builder.wasm",
            "--descriptor-out",
            "d.json",
        ]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    /// `zkminer simulate --descriptor d.json` with the job's builder and guest, at po2 20, no
    /// attacks; the output and the report.
    fn simulate(&self) -> (Output, Value) {
        let _ = std::fs::remove_file(self.path("report.json"));
        let out = self.run(&[
            "simulate",
            "--descriptor",
            "d.json",
            "--builder",
            "builder.wasm",
            "--elf",
            "guest.elf",
            "--po2",
            "20",
            "--cache-dir",
            "cache",
            "--out",
            "report.json",
        ]);
        let report =
            serde_json::from_slice(&std::fs::read(self.path("report.json")).unwrap_or_default()).unwrap_or(Value::Null);
        (out, report)
    }

    /// `zkminer simulate --descriptor d.json` with the job's builder and guest, no attacks, and
    /// `extra` (no `--po2` unless it says so); the output and the report.
    fn simulate_with(&self, extra: &[&str]) -> (Output, Value) {
        let _ = std::fs::remove_file(self.path("report.json"));
        let mut args = vec![
            "simulate",
            "--descriptor",
            "d.json",
            "--builder",
            "builder.wasm",
            "--elf",
            "guest.elf",
            "--cache-dir",
            "cache",
            "--out",
            "report.json",
        ];
        args.extend_from_slice(extra);
        let out = self.run(&args);
        let report =
            serde_json::from_slice(&std::fs::read(self.path("report.json")).unwrap_or_default())
                .unwrap_or(Value::Null);
        (out, report)
    }

    /// `zkminer simulate --descriptor d.json --adversarial` with the job's builder and guest, at po2
    /// 20, with two providers; the output and the report.
    fn attack(&self, extra: &[&str]) -> (Output, Value) {
        let _ = std::fs::remove_file(self.path("report.json"));
        let mut args = vec![
            "simulate",
            "--descriptor",
            "d.json",
            "--builder",
            "builder.wasm",
            "--elf",
            "guest.elf",
            "--po2",
            "20",
            "--prover",
            PROVER,
            "--cache-dir",
            "cache",
            "--out",
            "report.json",
            "--adversarial",
            "--adversarial-secs",
            "1500",
            "--providers",
            "anvil-a,anvil-b",
        ];
        args.extend_from_slice(extra);
        let started = std::time::Instant::now();
        let out = self.run(&args);
        eprintln!("simulate --adversarial took {:.0} s", started.elapsed().as_secs_f64());
        let report =
            serde_json::from_slice(&std::fs::read(self.path("report.json")).unwrap_or_default()).unwrap_or(Value::Null);
        (out, report)
    }
}

/// anvil with an EIP-1967 proxy (slots 10–12 under rule 1, pointing at the implementation), the
/// statement of k = 3 slots at a block B, and a block after it (the "next block" header the
/// scheme's mutations swap in).
fn proxy_world() -> (Anvil, Statement, [u8; 20]) {
    let anvil = Anvil::start();
    let implementation = anvil.deploy(&creation(&[], &IMPLEMENTATION_RUNTIME));
    let mut imp_word = [0u8; 32];
    imp_word[12..].copy_from_slice(&implementation);
    let stores = [(EIP1967_IMPLEMENTATION_SLOT, imp_word), (word(10), word(100)), (word(11), word(101)), (word(12), word(102))];
    let proxy = anvil.deploy(&creation(&stores, &proxy_runtime()));
    anvil.rpc("anvil_mine", "[\"0x3\"]");
    let b = anvil.rpc("eth_getBlockByNumber", "[\"latest\",false]");
    let block_hash: [u8; 32] = hex::decode(&b["hash"].as_str().unwrap()[2..]).unwrap().try_into().unwrap();
    anvil.rpc("anvil_mine", "[\"0x2\"]");
    (
        anvil,
        Statement { block_hash, proxy, rule: Rule::new(RuleKind::Consecutive, &word(10)).unwrap(), k: 3 },
        implementation,
    )
}

fn header_words(statement: &Statement, n: usize) -> String {
    let words: Vec<String> =
        statement.header_words().iter().take(n).map(|w| format!("\"word:0x{}\"", hex::encode(w))).collect();
    format!("prefix = true\nheader = [{}]", words.join(", "))
}

#[test]
fn simulate_adversarial_attacks_the_real_scheme1_witness() {
    let _g = serial();
    if !delegated("simulate_adversarial_attacks_the_real_scheme1_witness") {
        return;
    }
    let (anvil, statement, implementation) = proxy_world();
    let w = World::new(zkminer(), &anvil, &anvil);
    w.job(PROXY_SLOTS_ELF, &builder_wasm(), &header_words(&statement, 5), &statement.builder_params(ANVIL_CHAIN));
    // The binding pins the whole header, by the requester's own tool (the header's length given:
    // without it the check cannot know the header is whole).
    let header = format!("0x{}", hex::encode(statement.header()));
    let out = w.run(&[
        "witness",
        "binding",
        "check",
        "--descriptor",
        "d.json",
        "--statement",
        &header,
        "--header-bytes",
        "160",
    ]);
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));

    let (out, report) = w.attack(&["--flips", "4", "--max-mutations", "64"]);
    assert_eq!(report["outcome"], "simulated", "{}\n{report:#}", String::from_utf8_lossy(&out.stderr));

    // The honest run answers the statement at B.
    let journal = hex::decode(&report["journal"]["hex"].as_str().unwrap()[2..]).unwrap();
    let j = decode_journal(&journal).unwrap();
    assert_eq!(j.outputs.implementation, implementation);
    assert_eq!(j.outputs.code_hash, keccak256(IMPLEMENTATION_RUNTIME).0);
    assert_eq!(j.outputs.slots.iter().map(|(_, v)| *v).collect::<Vec<_>>(), vec![word(100), word(101), word(102)]);
    assert_eq!(report["binding"]["ok"], true);
    assert_eq!(report["binding"]["headerBytes"], 160, "from the scheme-1 W's word count");
    assert_eq!(report["builder"]["fetches"], 4, "header, implementation slot, two proofs");

    // The attacks.
    let a = &report["adversarial"];
    eprintln!("adversarial: {}", serde_json::to_string(&a["counts"]).unwrap());
    assert_eq!(a["bindingCoverage"]["ok"], true, "{:#}", a["bindingCoverage"]);
    assert_eq!(a["bindingCoverage"]["headerSource"], "scheme 1 W");
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
    assert!(
        a["hostInputs"].as_array().unwrap().iter().all(|h| h["dependent"] == false && h["ran"] == true),
        "{:#}",
        a["hostInputs"]
    );
    assert_eq!(a["differential"]["journalSame"], true, "{:#}", a["differential"]);
    assert_eq!(a["verdict"], "pass", "{a:#}");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

/// A binding that pins only the scheme word of the five the guest commits. No mutation of `W`
/// finds it (another k, block or rule needs a consistent `W`, which the prover makes and a mutation
/// does not), so the requester's tools judge the binding itself: `binding check` fails, simulate's
/// binding report shows the free words, and the attack's verdict is `fail` before any mutation.
#[test]
fn a_binding_that_leaves_header_words_free_fails() {
    let _g = serial();
    if !delegated("a_binding_that_leaves_header_words_free_fails") {
        return;
    }
    let (anvil, statement, _) = proxy_world();
    let w = World::new(zkminer(), &anvil, &anvil);
    w.job(PROXY_SLOTS_ELF, &builder_wasm(), &header_words(&statement, 1), &statement.builder_params(ANVIL_CHAIN));
    let header = format!("0x{}", hex::encode(statement.header()));
    // The reviewer's invocation (the header's length unknown), and with the length.
    let out = w.run(&["witness", "binding", "check", "--descriptor", "d.json", "--statement", &header]);
    assert!(!out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    assert!(String::from_utf8_lossy(&out.stdout).contains("header length is unknown"));
    let out = w.run(&[
        "witness",
        "binding",
        "check",
        "--descriptor",
        "d.json",
        "--statement",
        &header,
        "--header-bytes",
        "160",
        "--json",
    ]);
    assert!(!out.status.success());
    let check: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(check["headerFree"], serde_json::json!([{"start": 32, "end": 160}]));

    let (out, report) = w.attack(&["--flips", "2", "--max-mutations", "16"]);
    assert!(!out.status.success(), "the verdict is fail");
    assert_eq!(report["outcome"], "simulated", "{report:#}");
    assert_eq!(report["binding"]["ok"], false);
    assert_eq!(report["binding"]["headerFree"], serde_json::json!([{"start": 32, "end": 160}]));
    let a = &report["adversarial"];
    assert_eq!(a["verdict"], "fail", "{a:#}");
    assert_eq!(a["bindingCoverage"]["ok"], false);
    assert!(
        a["soundnessFailures"][0]
            .as_str()
            .unwrap()
            .starts_with("binding: the binding leaves 128 of the header's 160 bytes free"),
        "{a:#}"
    );
}

/// The hostdep guest's journal follows the keccak po2 (W = 0xA4, the raw permutation's batch
/// status): the reruns under another keccak po2 catch it, and nothing else is reported dependent.
/// One that follows the `sys_rand` seed (W = 0xA1) is refused before any attack: it draws from
/// `sys_rand` (see `a_guest_that_draws_from_sys_rand_is_refused`).
#[test]
fn host_inputs_a_prover_controls_are_caught() {
    let _g = serial();
    if !delegated("host_inputs_a_prover_controls_are_caught") {
        return;
    }
    let anvil = Anvil::start();
    let w = World::new(zkminer(), &anvil, &anvil);
    let echo = sdk_wasm("params-echo", "params_echo.wasm");
    w.job(
        HOSTDEP_ELF,
        &echo,
        "prefix = false\nheader = [\"uint256:0x77\"]",
        &[0xa4],
    );
    let (out, report) = w.attack(&[
        "--flips",
        "1",
        "--max-mutations",
        "1",
        "--header-bytes",
        "32",
    ]);
    assert_eq!(
        report["outcome"],
        "simulated",
        "{}\n{report:#}",
        String::from_utf8_lossy(&out.stderr)
    );
    let a = &report["adversarial"];
    let hosts = a["hostInputs"].as_array().unwrap();
    for h in hosts {
        assert_eq!(h["dependent"], h["input"] == "keccak_po2", "{h:#}");
    }
    assert!(
        a["soundnessFailures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f.as_str().unwrap().starts_with("host input KeccakPo2")),
        "{a:#}"
    );
    assert_eq!(a["verdict"], "fail");
    assert!(!out.status.success());

    w.job(
        HOSTDEP_ELF,
        &echo,
        "prefix = false\nheader = [\"uint256:0x77\"]",
        &[0xa1],
    );
    let (out, report) = w.attack(&[
        "--flips",
        "1",
        "--max-mutations",
        "1",
        "--header-bytes",
        "32",
    ]);
    assert!(!out.status.success());
    assert_eq!(report["outcome"], "skipped", "{report:#}");
    assert_eq!(
        report["verdict"]["reason"], "GuestUsesSysRand",
        "{report:#}"
    );
}

/// A guest whose honest journal ignores the `sys_rand` seed while its check of `W` follows it
/// (hostdep 0xA5: one of k items checked, at an index drawn from `sys_rand`). Its journals agree
/// under every seed, so comparing journals passes it, while a prover who picks the seed proves a
/// forged `W` (shown with the CPU executor). The execute counts the guest's own `sys_rand` call, and
/// simulate refuses the job as a miner does: `GuestUsesSysRand` at the execute step, the caller's,
/// never retried, with and without `--adversarial` (a job the miner skips is not attacked).
#[test]
fn a_guest_that_draws_from_sys_rand_is_refused() {
    let _g = serial();
    if !delegated("a_guest_that_draws_from_sys_rand_is_refused") {
        return;
    }
    let anvil = Anvil::start();
    let w = World::new(zkminer(), &anvil, &anvil);
    let echo = sdk_wasm("params-echo", "params_echo.wasm");
    let k = 16u8;
    let v = 1000u64.to_le_bytes();
    let mut honest = vec![0xa5];
    honest.extend_from_slice(&v);
    honest.push(k);
    for _ in 0..k {
        honest.extend_from_slice(&v);
    }
    w.job(
        HOSTDEP_ELF,
        &echo,
        "prefix = false\nheader = [\"uint256:0x78\"]",
        &honest,
    );
    for (name, (out, report)) in [
        ("simulate", w.simulate()),
        ("--adversarial", w.attack(&["--header-bytes", "32"])),
    ] {
        assert!(
            !out.status.success(),
            "{name}: a skipped job exits non-zero"
        );
        assert_eq!(report["outcome"], "skipped", "{name}: {report:#}");
        let v = &report["verdict"];
        assert_eq!(v["reason"], "GuestUsesSysRand", "{name}: {v:#}");
        assert_eq!(v["step"], "execute");
        assert_eq!(
            (v["blamesCaller"].as_bool(), v["retry"].as_str()),
            (Some(true), Some("never")),
            "{v:#}"
        );
        assert!(
            v["detail"]
                .as_str()
                .unwrap()
                .contains("called sys_rand 1 time(s) past its runtime's own draw"),
            "{v:#}"
        );
        assert!(report["adversarial"].is_null(), "{name}: not attacked");
    }

    // Why: W* claims v' with v' at one index only, and passes under a seed the prover picks.
    let forged_v = 1_000_000u64.to_le_bytes();
    let mut forged = vec![0xa5];
    forged.extend_from_slice(&forged_v);
    forged.push(k);
    for i in 0..k {
        forged.extend_from_slice(if i == 5 { &forged_v } else { &v });
    }
    let run = |seed: [u8; 32]| {
        let mut b = risc0_zkvm::ExecutorEnv::builder();
        b.write_slice(&forged);
        b.random_seed(seed);
        risc0_zkvm::default_executor()
            .execute(b.build().unwrap(), HOSTDEP_ELF)
            .ok()
            .map(|s| s.journal.bytes)
    };
    let journal = (0u8..=255)
        .find_map(|s| run([s; 32]))
        .expect("a seed the spot check misses");
    let mut header = [0u8; 32];
    header[31] = 0x78;
    assert_eq!(
        (&journal[..32], &journal[32..]),
        (&header[..], &forged_v[..]),
        "the forged statement"
    );
}

/// Two providers at different heads: the latest-block builder makes a different W from each, and the
/// hostdep guest (which echoes W) commits it: both journals satisfy the binding, so the job's
/// statement depends on which provider a prover asks.
#[test]
fn providers_that_disagree_are_a_soundness_failure() {
    let _g = serial();
    if !delegated("providers_that_disagree_are_a_soundness_failure") {
        return;
    }
    let (a, b) = (Anvil::start(), Anvil::start());
    a.rpc("anvil_mine", "[\"0x100\"]");
    b.rpc("anvil_mine", "[\"0x80\"]");
    let w = World::new(zkminer(), &a, &b);
    w.job(
        HOSTDEP_ELF,
        &sdk_wasm("latest-block", "latest_block.wasm"),
        "prefix = false\nheader = [\"uint256:0x77\"]",
        &[],
    );
    let (out, report) = w.attack(&["--flips", "1", "--max-mutations", "1", "--header-bytes", "32"]);
    assert_eq!(report["outcome"], "simulated", "{}\n{report:#}", String::from_utf8_lossy(&out.stderr));
    let d = &report["adversarial"]["differential"];
    assert_eq!(d["runs"][0]["outcome"], "simulated", "{d:#}");
    assert_eq!(d["runs"][1]["outcome"], "simulated", "{d:#}");
    assert_eq!(d["wSame"], false, "{d:#}");
    assert_eq!(d["journalSame"], false);
    assert_eq!(d["soundnessFailure"], true);
    assert!(report["adversarial"]["soundnessFailures"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f.as_str().unwrap().starts_with("differential:")));
    assert!(!out.status.success());
}

/// A guest built with risc0-zkvm 3.0 that needs two keccak batches (1000 permutations at the miner's
/// keccak po2, 17) executes cleanly and fails every proof here (methods/tests/keccak_batches.rs). The
/// miner refuses it before any claim, and its report says why and what to do: rebuild with 3.1.0.
/// The same work in a guest on 3.1.0 (hostdep) simulates.
#[test]
fn a_guest_built_with_risc0_3_0_is_refused_by_name() {
    let _g = serial();
    if !delegated("a_guest_built_with_risc0_3_0_is_refused_by_name") {
        return;
    }
    let anvil = Anvil::start();
    let w = World::new(zkminer(), &anvil, &anvil);
    let echo = sdk_wasm("params-echo", "params_echo.wasm");
    let n = 1000u32.to_le_bytes();
    w.job(KECCAK_3_0_ELF, &echo, &format!("prefix = false\nfull_statement = \"0x{}\"", hex::encode(n)), &n);
    let (out, report) = w.simulate();
    assert!(!out.status.success(), "a skipped job exits non-zero");
    assert_eq!(report["outcome"], "skipped", "{}\n{report:#}", String::from_utf8_lossy(&out.stderr));
    let v = &report["verdict"];
    assert_eq!(v["reason"], "GuestFailed", "{v:#}");
    assert_eq!(v["step"], "execute", "{v:#}");
    let detail = v["detail"].as_str().unwrap();
    assert!(
        detail.contains("the guest was built with risc0-zkvm older than 3.1")
            && detail.contains("Rebuild the guest with risc0-zkvm 3.1.0"),
        "{detail}"
    );
    eprintln!("the 3.0 guest's verdict: {detail}");

    // hostdep's mode 0xA2: the same 1000 permutations through the batcher, on 3.1.0.
    let mut a2 = vec![0xa2];
    a2.extend_from_slice(&1000u16.to_le_bytes());
    w.job(HOSTDEP_ELF, &echo, "prefix = false\nheader = [\"uint256:0x77\"]", &a2);
    let (out, report) = w.simulate();
    assert_eq!(report["outcome"], "simulated", "{}\n{report:#}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

/// A job within `maxGuestCycles` at some sizes only (hostdep 0xA2, 600 keccak permutations, under a
/// limit of 2,000,000 sized cycles: its last segment pads to 2^20 at the large sizes, so it fits at
/// po2 18 and 19 and not at 20). Without `--po2` and without any card sizes (no benchmark cache: HOME
/// is the work directory), simulate judges at po2 20, the size every uncalibrated card proves at, as a
/// miner with such cards does: skipped, `GuestCyclesAboveLimit`, non-zero exit. `--po2 18` says the
/// prover's cards prove at 18, where it fits.
#[test]
fn without_card_sizes_the_cycle_limit_is_judged_at_the_default_size() {
    let _g = serial();
    if !delegated("without_card_sizes_the_cycle_limit_is_judged_at_the_default_size") {
        return;
    }
    let anvil = Anvil::start();
    let w = World::new(zkminer(), &anvil, &anvil);
    let echo = sdk_wasm("params-echo", "params_echo.wasm");
    let mut a2 = vec![0xa2];
    a2.extend_from_slice(&600u16.to_le_bytes());
    w.job_with_cycles(
        HOSTDEP_ELF,
        &echo,
        "prefix = false\nheader = [\"uint256:0x77\"]",
        &a2,
        2_000_000,
    );
    let (out, report) = w.simulate_with(&[]);
    eprintln!(
        "{:#}",
        serde_json::json!({"po2Source": report["po2Source"], "cycleLimit": report["cycleLimit"]})
    );
    assert!(
        !out.status.success(),
        "a job a default miner skips exits non-zero"
    );
    assert_eq!(report["outcome"], "skipped", "{report:#}");
    assert_eq!(
        report["verdict"]["reason"], "GuestCyclesAboveLimit",
        "{report:#}"
    );
    assert!(report["po2Source"]
        .as_str()
        .unwrap()
        .starts_with("every job size, judged at po2 20"));
    let limit = &report["cycleLimit"];
    assert_eq!(limit["judgedAt"], serde_json::json!([20]));
    assert!(
        limit["overAt"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(20)),
        "{limit:#}"
    );
    assert!(
        !limit["withinAt"].as_array().unwrap().is_empty(),
        "it fits at some size: {limit:#}"
    );

    let fits: u64 = limit["withinAt"][0].as_u64().unwrap();
    let (out, report) = w.simulate_with(&["--po2", &fits.to_string()]);
    assert_eq!(report["outcome"], "simulated", "{report:#}");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
