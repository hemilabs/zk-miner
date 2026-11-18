//! `zkminer simulate --descriptor` and `zkminer artifact publish`, end to end on the real binaries:
//! the requester's job spec encoded by `zkminer witness envelope encode`, simulated through the
//! miner's pipeline (the sandboxed runner, the broker, the risc0 CPU worker in `--witness-execute`
//! mode) on anvil, attacked with `--adversarial`, and a builder published with `zkminer artifact
//! publish` and then fetched by the broker's own `hemi-code` reader.
//!
//! The SDK's `params-echo` test builder writes its `builderParams` as `W`; the worker's fibonacci
//! guest reads `n` (4 little-endian bytes) and commits `fib(n)` as 8 little-endian bytes.
//!
//! Needs a delegated cgroup, anvil and the SDK's pinned toolchain:
//!
//! ```text
//! systemd-run --user --scope -q -p Delegate=yes -- \
//!     env ZKMINER_SANDBOX_TESTS_REQUIRED=1 cargo test -p zkminer-cli --test simulate_witness -- --test-threads=1
//! ```

#![cfg(target_os = "linux")]

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use alloy::primitives::{Address, B256};
use serde_json::{json, Value};

#[path = "../src/commands/artifact/test_contracts.rs"]
mod test_contracts;

const ANVIL_CHAIN: u64 = 31337;
/// anvil's first dev account (unlocked).
const DEV: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
/// anvil's third dev key: the publisher's, in a keystore.
const PUBLISHER_KEY: &str = "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

fn skip(test: &str, reason: &str) -> bool {
    if std::env::var_os("ZKMINER_SANDBOX_TESTS_REQUIRED").is_some() {
        panic!("{test}: {reason}");
    }
    let _ = writeln!(std::io::stderr(), "SKIPPED {test}: {reason}");
    true
}

/// Whether this test can run here: a delegated cgroup and anvil.
fn unavailable(test: &str) -> bool {
    if zkminer_witness_sandbox_available().is_err() {
        return skip(test, "no delegated cgroup (run under systemd-run --user --scope -p Delegate=yes)");
    }
    if Command::new("anvil").arg("--version").stdout(Stdio::null()).status().is_err() {
        return skip(test, "anvil is not on PATH");
    }
    false
}

fn zkminer_witness_sandbox_available() -> Result<(), ()> {
    zkminer_witness_sandbox::delegated_root().map(|_| ()).map_err(|_| ())
}

/// One test at a time (they share the delegated cgroup).
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn target_debug() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_zkminer")).parent().unwrap().to_path_buf()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn cargo_build(args: &[&str]) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(workspace_root())
        .arg("build")
        .args(args)
        .arg("--target-dir")
        .arg(target_debug().parent().unwrap())
        .output()
        .expect("cargo runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

/// The binaries `zkminer` finds next to itself, and the fibonacci guest with its image id.
fn setup() -> &'static (Vec<u8>, B256) {
    static S: OnceLock<(Vec<u8>, B256)> = OnceLock::new();
    S.get_or_init(|| {
        cargo_build(&["-p", "zkminer-witness-builder", "-p", "zkminer-witness-broker", "-p", "zkminer-witness-sandbox", "--bins"]);
        cargo_build(&["-p", "zkminer-prove-risc0", "--features", "cpu", "--bin", "zkminer-prove-risc0-cpu"]);
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let path = dir.path().join("fib.elf");
        let out = Command::new(target_debug().join("zkminer-prove-risc0-cpu"))
            .args(["--export-guest", "fibonacci"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success());
        let id: B256 = String::from_utf8(out.stdout).unwrap().trim().parse().unwrap();
        (std::fs::read(&path).unwrap(), id)
    })
}

fn sdk_tool(tool: &str) -> std::ffi::OsString {
    let out = Command::new("rustup").args(["which", tool]).current_dir(workspace_root().join("sdk")).env_remove("RUSTUP_TOOLCHAIN").output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8(o.stdout).unwrap().trim().into(),
        _ => tool.into(),
    }
}

/// The SDK's `params-echo` builder, built with the SDK's pinned toolchain.
fn params_echo() -> &'static [u8] {
    static W: OnceLock<Vec<u8>> = OnceLock::new();
    W.get_or_init(|| {
        let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("sdk-target-simulate-witness");
        let mut cmd = Command::new(sdk_tool("cargo"));
        cmd.current_dir(workspace_root().join("sdk"))
            .args(["build", "--locked", "--release", "--target", "wasm32-unknown-unknown", "-p", "params-echo", "--target-dir"])
            .arg(&target)
            .env("RUSTC", sdk_tool("rustc"));
        for v in ["RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_DIR"] {
            cmd.env_remove(v);
        }
        let out = cmd.output().expect("the SDK's cargo runs");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        std::fs::read(target.join("wasm32-unknown-unknown/release/params_echo.wasm")).unwrap()
    })
}

struct Anvil {
    child: Child,
    port: u16,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Anvil {
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn start() -> Self {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let child = Command::new("anvil")
            .args(["--port", &port.to_string(), "--block-time", "1", "--silent"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let a = Anvil { child, port };
        for _ in 0..100 {
            if a.try_rpc("eth_chainId", json!([])).is_some() {
                return a;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("anvil did not start");
    }

    fn try_rpc(&self, method: &str, params: Value) -> Option<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let out = Command::new("curl")
            .args(["-s", "-m", "10", "-H", "content-type: application/json", "-d", &body, &self.url()])
            .output()
            .ok()?;
        serde_json::from_slice(&out.stdout).ok()
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        let v = self.try_rpc(method, params).expect("anvil answers");
        assert!(v.get("error").is_none(), "{method}: {v}");
        v["result"].clone()
    }

    fn deploy(&self, creation_hex: &str) -> Address {
        let tx = self.rpc("eth_sendTransaction", json!([{"from": DEV, "data": format!("0x{creation_hex}")}]));
        for _ in 0..100 {
            let r = self.rpc("eth_getTransactionReceipt", json!([tx]));
            if !r.is_null() {
                assert_eq!(r["status"], "0x1");
                return r["contractAddress"].as_str().unwrap().parse().unwrap();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("no receipt");
    }
}

/// A work directory with the miner's configuration (developer mode on anvil's chain) and the
/// broker's (anvil twice as `evm-rpc/v1`, under two aliases, and as the artifact endpoint).
struct Env {
    anvil: Anvil,
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let anvil = Anvil::start();
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let d = dir.path().display().to_string();
        let url = anvil.url();
        std::fs::create_dir_all(dir.path().join("spool")).unwrap();
        let rpc = |alias: &str| {
            format!(
                "[[evm_rpc]]\nalias = \"{alias}\"\nurl = \"{url}\"\nchain_id = {ANVIL_CHAIN}\narchive = true\n\
                 max_proof_age = 1000000\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n"
            )
        };
        std::fs::write(
            dir.path().join("broker.toml"),
            format!(
                "chain_rpc_host = \"chain-rpc.invalid\"\nspool_dir = \"{d}/spool\"\n{}{}\
                 [artifacts]\nalias = \"anvil-artifacts\"\nurl = \"{url}\"\nchain_id = {ANVIL_CHAIN}\n\
                 max_requests_per_sec = 1000\nmax_builder_bytes = 4194304\ncidrs = [\"127.0.0.1/32\"]\n",
                rpc("anvil-a"),
                rpc("anvil-b")
            ),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[chain]\nchain_id = {ANVIL_CHAIN}\nrpc_url = \"{url}\"\n\
                 [contracts]\nhemi_prove = \"0x000000000000000000000000000000000000a11c\"\n\
                 hemi_prove_staking = \"0x000000000000000000000000000000000000a11d\"\n\
                 hemi_prove_registry = \"0x000000000000000000000000000000000000a11e\"\n\
                 hemi_token = \"0x000000000000000000000000000000000000a11f\"\n\
                 [dev]\nprivate_network = true\nchain_id = {ANVIL_CHAIN}\nda_backlog_bytes = 0\n\
                 [witness]\nsandbox_mode = \"rootless\"\n[broker]\nconfig = \"{d}/broker.toml\"\n"
            ),
        )
        .unwrap();
        Env { anvil, dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The miner's configuration with `lines` added to its `[witness]` table.
    fn witness_config(&self, lines: &str) {
        let path = self.path("config.toml");
        let text = std::fs::read_to_string(&path).unwrap();
        let at = "[witness]\nsandbox_mode = \"rootless\"\n";
        assert!(text.contains(at));
        std::fs::write(&path, text.replace(at, &format!("{at}{lines}\n"))).unwrap();
    }

    /// The miner's configuration with a `[prover]` table naming its cards' job sizes.
    fn card_sizes(&self, table: &str) {
        let path = self.path("config.toml");
        let mut text = std::fs::read_to_string(&path).unwrap();
        if let Some(at) = text.find("\n[prover]\n") {
            text.truncate(at + 1);
        }
        text.push_str(&format!("[prover]\nrisc0_job_po2 = {table}\n"));
        std::fs::write(&path, text).unwrap();
    }

    fn zkminer(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_zkminer"));
        c.arg("-c").arg(self.path("config.toml")).args(args).env("HOME", self.dir.path());
        c
    }

    /// A job spec for the fibonacci guest built by params-echo with `n`, under `binding` (a TOML
    /// `[binding]` body), encoded by `zkminer witness envelope encode` into a descriptor file.
    fn descriptor(
        &self,
        name: &str,
        n: u32,
        binding: &str,
        uris: &[String],
        extra: &str,
    ) -> PathBuf {
        self.descriptor_capped(name, n, binding, uris, extra, 1 << 24)
    }

    /// [`Env::descriptor`] with the envelope's `maxGuestCycles`.
    fn descriptor_capped(
        &self,
        name: &str,
        n: u32,
        binding: &str,
        uris: &[String],
        extra: &str,
        cycles: u64,
    ) -> PathBuf {
        let (_, image_id) = setup();
        let spec = self.path(&format!("{name}.toml"));
        std::fs::write(
            &spec,
            format!(
                "program_id = \"{image_id}\"\n{extra}\n[binding]\n{binding}\n[envelope]\nbuilder_uris = {uris:?}\n\
                 builder_params = \"0x{params}\"\n[[envelope.sources]]\nclass = \"evm-rpc/v1\"\nchain_id = {ANVIL_CHAIN}\n\
                 archive = true\nmethod_set = \"state-read\"\nmax_proof_age = 0\n[envelope.limits]\nmax_fetches = 4\n\
                 max_fetch_bytes = 1048576\nmax_request_bytes = 65536\nmax_response_bytes = 1048576\n\
                 max_builder_fuel = 1000000000\nmax_builder_memory_bytes = 67108864\nmax_builder_seconds = 30\n\
                 max_witness_bytes = 65536\nmax_guest_cycles = {cycles}\n",
                params = alloy::hex::encode(n.to_le_bytes())
            ),
        )
        .unwrap();
        let wasm = self.path("echo.wasm");
        std::fs::write(&wasm, params_echo()).unwrap();
        let out_path = self.path(&format!("{name}.json"));
        let out = self
            .zkminer(&["witness", "envelope", "encode"])
            .arg(&spec)
            .arg("--builder")
            .arg(&wasm)
            .arg("--descriptor-out")
            .arg(&out_path)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        out_path
    }

    /// `zkminer simulate --descriptor` with the ELF, writing the report; the output and the report.
    fn simulate(&self, descriptor: &Path, args: &[&str]) -> (Output, Value) {
        let report = self.path("report.json");
        let _ = std::fs::remove_file(&report);
        let elf = self.path("fib.elf");
        std::fs::write(&elf, &setup().0).unwrap();
        let out = self
            .zkminer(&["simulate", "--descriptor"])
            .arg(descriptor)
            .arg("--elf")
            .arg(&elf)
            .arg("--cache-dir")
            .arg(self.path("cache"))
            .arg("--out")
            .arg(&report)
            .args(args)
            .output()
            .unwrap();
        let v = std::fs::read(&report).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
        (out, v)
    }
}

fn fib(n: u32) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        (a, b) = (b, a.wrapping_add(b));
    }
    a
}

fn full_binding(n: u32) -> String {
    format!("prefix = false\nfull_statement = \"0x{}\"", alloy::hex::encode(fib(n).to_le_bytes()))
}

#[test]
fn a_descriptor_job_runs_the_miners_pipeline_and_survives_the_attacks() {
    let _g = serial();
    if unavailable("a_descriptor_job_runs_the_miners_pipeline_and_survives_the_attacks") {
        return;
    }
    let env = Env::new();
    let d = env.descriptor("full", 10, &full_binding(10), &[], "");
    let wasm = env.path("echo.wasm");
    // Flipping n's high byte makes billions of iterations: this host's maximum, not the job's
    // maxGuestCycles, bounds the re-executions, so keep it small here.
    let (out, r) = env.simulate(
        &d,
        &[
            "--builder",
            wasm.to_str().unwrap(),
            "--po2",
            "16,20",
            "--adversarial",
            "--flips",
            "8",
            "--max-guest-cycles",
            "67108864",
        ],
    );
    assert!(out.status.success(), "{}\n{r:#}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(r["kind"], "witness");
    assert_eq!(r["outcome"], "simulated");
    assert_eq!(r["journal"]["hex"], format!("0x{}", alloy::hex::encode(fib(10).to_le_bytes())));
    assert_eq!(r["perPo2"].as_array().unwrap().len(), 2);
    assert_eq!(r["builder"]["artifactOrigin"], "local");
    assert!(r["builder"]["fuelUsed"].as_u64().unwrap() > 0);
    assert_eq!(r["witness"]["bytes"], 4);
    assert_eq!(r["binding"]["mode"], "full");
    assert_eq!(r["binding"]["ok"], true);
    assert!(r["fulfil"]["estimatedDaBytes"].as_u64().unwrap() > 0);
    assert_eq!(r["fulfil"]["withinCap"], true);
    let not_checked: Vec<&str> = r["notChecked"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(not_checked.len() >= 8, "{not_checked:?}");
    assert!(not_checked.iter().any(|n| n.contains("--builder replaced")), "{not_checked:?}");
    assert!(not_checked.iter().any(|n| n.contains("--elf replaced")), "{not_checked:?}");
    assert!(not_checked.iter().any(|n| n.contains("DA backlog")), "{not_checked:?}");
    assert!(!not_checked.iter().any(|n| n.contains("guest cycles against")), "--max-guest-cycles was given");
    assert_eq!(r["cycles"]["hostMaxSource"], "--max-guest-cycles");
    // The attacks: every mutation rejected, refused by the binding or harmless; no host input
    // changes the journal; both providers agree.
    let a = &r["adversarial"];
    assert_eq!(a["verdict"], "pass", "{a:#}");
    assert_eq!(a["bindingCoverage"]["ok"], true);
    assert_eq!(a["bindingCoverage"]["wholeJournal"], true);
    assert_eq!(a["counts"]["soundnessFailures"], 0);
    assert!(a["counts"]["total"].as_u64().unwrap() >= 8);
    assert!(a["counts"]["bindingRejects"].as_u64().unwrap() >= 1, "a changed n changes fib(n)");
    assert!(a["counts"]["rejectedInGuest"].as_u64().unwrap() >= 1, "a truncated W fails in the guest");
    assert!(a["counts"]["identicalJournal"].as_u64().unwrap() >= 1, "trailing bytes are never read");
    assert!(a["notes"][0].as_str().unwrap().contains("trailing bytes"), "{:#}", a["notes"]);
    assert_eq!(a["hostInputs"].as_array().unwrap().len(), 3);
    assert!(a["hostInputs"].as_array().unwrap().iter().all(|h| h["dependent"] == false && h["ran"] == true));
    assert_eq!(a["differential"]["journalSame"], true);
    assert_eq!(a["differential"]["runs"][1]["alias"], "anvil-b");
}

#[test]
fn a_none_bound_job_fails_the_attack_and_names_the_mutation() {
    let _g = serial();
    if unavailable("a_none_bound_job_fails_the_attack_and_names_the_mutation") {
        return;
    }
    let env = Env::new();
    let prover = "0x00000000000000000000000000000000000000b0";
    let d = env.descriptor("none", 10, "prefix = false\nnone = true", &[], &format!("assigned_prover = \"{prover}\""));
    let wasm = env.path("echo.wasm");
    let (out, r) = env.simulate(
        &d,
        &[
            "--builder",
            wasm.to_str().unwrap(),
            "--po2",
            "20",
            "--prover",
            prover,
            "--adversarial",
            "--flips",
            "2",
            "--providers",
            "anvil-a,anvil-b",
            // n's high byte flipped: this host's maximum bounds the run.
            "--max-guest-cycles",
            "67108864",
        ],
    );
    assert!(!out.status.success(), "a soundness failure exits non-zero");
    assert_eq!(r["outcome"], "simulated");
    let a = &r["adversarial"];
    assert_eq!(a["verdict"], "fail");
    // NONE binds nothing: the coverage fails first, and the flips show it.
    assert_eq!(a["bindingCoverage"]["ok"], false);
    let failures: Vec<&str> = a["soundnessFailures"].as_array().unwrap().iter().map(|f| f.as_str().unwrap()).collect();
    assert!(failures[0].starts_with("binding: NONE"), "{failures:?}");
    let mutations: Vec<&&str> = failures.iter().filter(|f| f.starts_with("mutation ")).collect();
    assert!(!mutations.is_empty());
    assert!(mutations.iter().all(|f| f.starts_with("mutation flip@")), "{failures:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("verdict is fail"));
}

#[test]
fn a_job_the_miner_would_skip_reports_its_verdict() {
    let _g = serial();
    if unavailable("a_job_the_miner_would_skip_reports_its_verdict") {
        return;
    }
    let env = Env::new();
    // The binding names fib(11), the builder makes n = 10.
    let d = env.descriptor("wrong", 10, &full_binding(11), &[], "");
    let wasm = env.path("echo.wasm");
    let (out, r) = env.simulate(&d, &["--builder", wasm.to_str().unwrap(), "--po2", "20"]);
    assert!(!out.status.success());
    assert_eq!(r["outcome"], "skipped");
    assert_eq!(r["verdict"]["reason"], "BindingMismatch");
    assert_eq!(r["verdict"]["step"], "binding");
    assert_eq!(r["verdict"]["retry"], "once_jittered");
    // A --builder that is not the envelope's builderId is the job's fault, as a decoy manifest is.
    let other = env.path("other.wasm");
    std::fs::write(&other, wat::parse_str("(module (memory (export \"memory\") 1) (func (export \"run\") (result i32) i32.const 0))").unwrap())
        .unwrap();
    let (out, r) = env.simulate(&d, &["--builder", other.to_str().unwrap(), "--po2", "20"]);
    assert!(!out.status.success());
    assert_eq!(r["verdict"]["reason"], "ArtifactAllSourcesBad");
}

/// maxGuestCycles is judged over the po2s the prover may use (§7.1): a job over it at some segment
/// sizes only is served by a miner whose cards prove at the others. Without card sizes the verdict
/// names the sizes over it and says it depends on them; `--po2` and this configuration's card sizes
/// judge as such a miner does.
#[test]
fn a_cycle_limit_met_at_some_sizes_only_is_judged_at_the_provers_sizes() {
    let _g = serial();
    if unavailable("a_cycle_limit_met_at_some_sizes_only_is_judged_at_the_provers_sizes") {
        return;
    }
    let env = Env::new();
    let wasm = env.path("echo.wasm");
    let builder = wasm.to_str().unwrap().to_string();
    // Enough iterations for many segments at po2 16: the sized count differs across sizes.
    let n = 300_000;
    let d = env.descriptor("sizes", n, &full_binding(n), &[], "");
    let (out, r) = env.simulate(
        &d,
        &[
            "--builder",
            &builder,
            "--po2",
            "16..22",
            "--max-guest-cycles",
            "67108864",
        ],
    );
    assert!(
        out.status.success(),
        "{}\n{r:#}",
        String::from_utf8_lossy(&out.stderr)
    );
    let counts: Vec<(u8, u64)> = r["perPo2"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["po2"].as_u64().unwrap() as u8,
                p["cycles"].as_str().unwrap().parse().unwrap(),
            )
        })
        .collect();
    assert_eq!(counts.len(), 7, "{counts:?}");
    // The job's cap: the smallest count, so the sizes above it go over.
    let cap = counts.iter().map(|c| c.1).min().unwrap();
    let within: Vec<u8> = counts.iter().filter(|c| c.1 <= cap).map(|c| c.0).collect();
    let over: Vec<u8> = counts.iter().filter(|c| c.1 > cap).map(|c| c.0).collect();
    assert!(
        !over.is_empty(),
        "every size counts {cap}: raise n ({counts:?})"
    );
    let d = env.descriptor_capped("capped", n, &full_binding(n), &[], "", cap);

    // No card sizes known (no benchmark cache under this HOME, no prover.risc0_job_po2): every size
    // runs, each judged on its own, and the job is servable at the sizes within the cap.
    let (out, r) = env.simulate(&d, &["--builder", &builder]);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "{stderr}\n{r:#}");
    assert_eq!(r["outcome"], "simulated");
    assert!(
        r["po2Source"]
            .as_str()
            .unwrap()
            .starts_with("every job size"),
        "{}",
        r["po2Source"]
    );
    let c = &r["cycleLimit"];
    let list = |v: &Value| -> Vec<u8> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u8)
            .collect()
    };
    assert_eq!(list(&c["overAt"]), over, "{c:#}");
    assert_eq!(list(&c["withinAt"]), within, "{c:#}");
    assert!(list(&c["judgedAt"]).is_empty());
    assert_eq!(c["maxGuestCycles"], cap.to_string());
    assert!(stderr.contains("depends on the segment size"), "{stderr}");
    assert_eq!(
        list(&Value::Array(
            r["perPo2"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p["po2"].clone())
                .collect()
        )),
        within
    );

    // Every size, asked explicitly: judged at each, as a miner with a card at each would.
    let (out, r) = env.simulate(&d, &["--builder", &builder, "--po2", "16..22"]);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success());
    assert_eq!(r["outcome"], "skipped");
    assert_eq!(r["verdict"]["reason"], "GuestCyclesAboveLimit");
    assert_eq!(r["verdict"]["step"], "execute");
    assert_eq!(list(&r["cycleLimit"]["overAt"]), over);
    assert!(stderr.contains("would skip this job"), "{stderr}");

    // This configuration's card proves at a size within the cap: served, at that size only.
    let (ok, bad) = (within[0], over[0]);
    env.card_sizes(&format!("{{ gpu0 = {ok} }}"));
    let (out, r) = env.simulate(&d, &["--builder", &builder]);
    assert!(
        out.status.success(),
        "{}\n{r:#}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(r["outcome"], "simulated");
    assert_eq!(list(&r["po2s"]), vec![ok]);
    assert!(
        r["po2Source"]
            .as_str()
            .unwrap()
            .contains(&format!("gpu0 at po2 {ok}")),
        "{}",
        r["po2Source"]
    );
    assert!(list(&r["cycleLimit"]["overAt"]).is_empty());

    // ... and at a size over it: skipped, as that miner skips it.
    env.card_sizes(&format!("{{ gpu0 = {bad} }}"));
    let (out, r) = env.simulate(&d, &["--builder", &builder]);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success());
    assert_eq!(r["verdict"]["reason"], "GuestCyclesAboveLimit");
    assert_eq!(list(&r["cycleLimit"]["judgedAt"]), vec![bad]);
    assert!(
        stderr.contains(&format!("a miner proving at po2 {bad}")),
        "{stderr}"
    );
}

#[test]
fn a_fulfil_over_the_configured_da_cap_is_skipped() {
    let _g = serial();
    if unavailable("a_fulfil_over_the_configured_da_cap_is_skipped") {
        return;
    }
    let env = Env::new();
    // Below any proof-carrying fulfil: the claim gate's operator cap skips it.
    env.witness_config("fulfil_da_cap_bytes = 200");
    let d = env.descriptor("full", 10, &full_binding(10), &[], "");
    let wasm = env.path("echo.wasm");
    let (out, r) = env.simulate(&d, &["--builder", wasm.to_str().unwrap(), "--po2", "20", "--adversarial"]);
    assert!(!out.status.success(), "a miner on this configuration skips it");
    assert_eq!(r["outcome"], "skipped");
    assert_eq!(r["verdict"]["reason"], "FulfilDaTooLarge");
    assert_eq!(r["verdict"]["step"], "claim_gate");
    assert_eq!(r["fulfil"]["capBytes"], 200);
    assert_eq!(r["fulfil"]["withinCap"], false);
    assert!(r["journal"]["hex"].is_string(), "the simulation itself ran");
    assert!(r["adversarial"].is_null(), "a job the miner skips is not attacked");
    // Without --max-guest-cycles or [witness] max_guest_cycles, the card-derived maximum is unchecked.
    assert_eq!(r["cycles"]["hostMaxSource"], "unset");
    assert!(r["notChecked"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("guest cycles against")));
}

#[test]
fn a_published_builder_is_fetched_by_the_miners_hemi_code_reader() {
    let _g = serial();
    if unavailable("a_published_builder_is_fetched_by_the_miners_hemi_code_reader") {
        return;
    }
    let env = Env::new();
    // The router and staking the publisher's key checks read, and a GasPriceOracle.
    let staking = env.anvil.deploy(&test_contracts::join(test_contracts::MOCK_STAKING));
    let router = env.anvil.deploy(&format!(
        "{}{}",
        test_contracts::join(test_contracts::MOCK_ROUTER),
        alloy::hex::encode(B256::left_padding_from(staking.as_slice()))
    ));
    env.anvil.rpc(
        "anvil_setCode",
        json!(["0x420000000000000000000000000000000000000F", format!("0x{}", test_contracts::join(test_contracts::MOCK_GAS_PRICE_ORACLE_RUNTIME))]),
    );
    let key: B256 = PUBLISHER_KEY.parse().unwrap();
    alloy::signers::local::PrivateKeySigner::encrypt_keystore(env.dir.path(), &mut rand::thread_rng(), key, "pw", Some("publisher"))
        .unwrap();
    std::fs::write(env.path("echo.wasm"), params_echo()).unwrap();

    // `zkminer artifact publish`, its password on fd 3.
    let mut fds = [0i32; 2];
    // SAFETY: a valid array of two fds.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: the write end is ours.
    let mut w = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fds[1]) };
    w.write_all(b"pw\n").unwrap();
    drop(w);
    let read_end = fds[0];
    let mut publish = env.zkminer(&["artifact", "publish"]);
    publish
        .arg(env.path("echo.wasm"))
        .args(["--kind", "builder", "--rpc-url", &env.anvil.url(), "--chain-id", &ANVIL_CHAIN.to_string()])
        .arg("--keystore")
        .arg(env.path("publisher"))
        .args(["--password-fd", "3", "--router", &format!("{router:#x}"), "--from-block", "0", "--yes", "--json"]);
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        publish.pre_exec(move || {
            // `dup2` onto itself, when the read end already is 3, would leave it close-on-exec.
            if read_end != 3 && libc::dup2(read_end, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = publish.output().unwrap();
    // SAFETY: the parent's copy of the read end.
    unsafe { libc::close(read_end) };
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let published: Value = serde_json::from_slice(&out.stdout).unwrap();
    let locator = published["locator"].as_str().unwrap().to_string();
    assert!(locator.starts_with("hemi-code://31337/0x"), "{locator}");
    assert_eq!(published["builderId"].as_str().unwrap().parse::<B256>().unwrap(), B256::from(sha256(params_echo())));

    // The miner's reader (the sandboxed broker's `hemi-code` fetch) serves what was published.
    let d = env.descriptor("published", 12, &full_binding(12), std::slice::from_ref(&locator), "");
    let (out, r) = env.simulate(&d, &["--po2", "20"]);
    assert!(out.status.success(), "{}\n{r:#}", String::from_utf8_lossy(&out.stderr));
    let origin = r["builder"]["artifactOrigin"].as_str().unwrap();
    assert_eq!(origin, format!("hemi-code:{}", published["manifest"]["address"].as_str().unwrap().parse::<Address>().unwrap()));
    assert_eq!(r["builder"]["artifactCharges"][0][0], params_echo().len());
    assert_eq!(r["journal"]["hex"], format!("0x{}", alloy::hex::encode(fib(12).to_le_bytes())));
}

/// `zkminer artifact publish --kind elf` takes a real risc0 guest, the worker's fibonacci program
/// binary (`R0BF`), past its input check (it then stops at the RPC, which nothing answers); a WASM
/// builder is refused as an ELF.
#[test]
fn an_elf_publish_takes_a_risc0_program_binary() {
    let _g = serial();
    let (elf, _) = setup();
    assert_eq!(&elf[..4], b"R0BF");
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    std::fs::write(dir.path().join("fib.bin"), elf).unwrap();
    std::fs::write(dir.path().join("echo.wasm"), params_echo()).unwrap();
    // A closed port: the run ends at its first request, after the input check.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "[chain]\nchain_id = {ANVIL_CHAIN}\nrpc_url = \"http://127.0.0.1:{port}\"\n\
             [contracts]\nhemi_prove = \"0x000000000000000000000000000000000000a11c\"\n\
             hemi_prove_staking = \"0x000000000000000000000000000000000000a11d\"\n\
             hemi_prove_registry = \"0x000000000000000000000000000000000000a11e\"\n\
             hemi_token = \"0x000000000000000000000000000000000000a11f\"\n\
             [dev]\nprivate_network = true\nchain_id = {ANVIL_CHAIN}\n"
        ),
    )
    .unwrap();
    let publish = |file: &str| {
        Command::new(env!("CARGO_BIN_EXE_zkminer"))
            .args(["-c", "config.toml", "artifact", "publish", file, "--kind", "elf"])
            .args(["--rpc-url", &format!("http://127.0.0.1:{port}")])
            .args([
                "--chain-id",
                "31337",
                "--keystore",
                "none",
                "--router",
                "0x000000000000000000000000000000000000a11c",
            ])
            .args(["--from-block", "0", "--yes"])
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .output()
            .unwrap()
    };
    let out = publish("fib.bin");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(!err.contains("--kind elf, but"), "{err}");
    let out = publish("echo.wasm");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--kind elf, but"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}
