//! The pre-claim pipeline (`pipeline::simulate_witness_job`) end to end on the real binaries: the
//! broker binary (sandboxed, its own cgroup) with anvil as both its `evm-rpc/v1` endpoint and its
//! `[artifacts]` endpoint; builders published to anvil as `hemi-code` (chunks and a manifest deployed
//! with `manifest::creation_code` from anvil's unlocked dev account); the runner binary; the risc0
//! CPU worker in `--witness-execute` mode on its fibonacci guest; a real retention store on the
//! target dir's disk (`/tmp` is tmpfs, which the store refuses).
//!
//! The SDK's `params-echo` test builder writes its `builderParams` as `W`; the fibonacci guest reads
//! `n` (a u32, 4 little-endian bytes) from its input and commits `fib(n)` as 8 little-endian bytes.
//!
//! Needs a delegated cgroup, anvil and the SDK's pinned toolchain:
//!
//! ```text
//! systemd-run --user --scope -q -p Delegate=yes -- \
//!     env ZKMINER_SANDBOX_TESTS_REQUIRED=1 CARGO_TARGET_DIR=... \
//!     cargo test -p zkminer-witness-host --test pipeline_e2e
//! ```
//!
//! `ZKMINER_TEST_RISC0_CPU_WORKER` may name a prebuilt `zkminer-prove-risc0-cpu`; otherwise it is
//! built into this test's target dir. The tests run one at a time (they share the delegated cgroup
//! root, and the abort test watches it).

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use alloy_primitives::{keccak256, Address, B256};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zkminer_chain::auction::risc_zero_groth16_v1_id;
use zkminer_chain::binding::full_hash;
use zkminer_chain::descriptor::compute_descriptor_hash;
use zkminer_contracts::bindings::JobDescriptor;
use zkminer_witness::envelope::{
    encode_envelope, encode_evm_rpc_config, Capability, HostMaxima, Limits, WitnessJobV1, CLASS_EVM_RPC_V1,
    METHOD_SET_STATE_READ,
};
use zkminer_witness::manifest::{chunk_runtime_code, creation_code, manifest_runtime_code, sha256};
use zkminer_witness::verdict::SkipReason;
use zkminer_witness_broker::client::ArtifactCharge;
use zkminer_witness_host::abort::{AbortReason, AbortToken};
use zkminer_witness_host::broker_proc::BrokerProcess;
use zkminer_witness_host::pipeline::{
    descriptor_hash_of_abi, eviction_by_age, execute_worker_build, simulate_witness_job,
    sys_rand_rule, ArtifactOrigin, CycleJudging, HookFuture, HostContext, ImageIdFn, JobInput,
    PipelineHooks, Simulated, Skip, Step,
};
use zkminer_witness_host::spawner::Spawner;
use zkminer_witness_sandbox::{delegated_root, landlock_abi, SandboxError, MIN_LANDLOCK_ABI};
use zkminer_witness_store::{ExpectedIdentity, Store, StoreError, StoreIdentityInit, StoreOptions};

const ANVIL_CHAIN: u64 = 31337;
/// anvil's first dev account (unlocked: `eth_sendTransaction` signs for it).
const DEV: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const PO2S: [u8; 2] = [16, 18];

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

/// One test at a time, each on its own runtime.
fn serial<F: Future>(f: impl FnOnce() -> F) -> F::Output {
    static LOCK: Mutex<()> = Mutex::new(());
    let _g = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap().block_on(f())
}

// ---------------------------------------------------------------------------------------------
// Binaries, the builder and the guest.

/// The workspace target dir this test binary lives in (`<target>/debug/deps/<test>`).
fn target_dir() -> PathBuf {
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().parent().unwrap().to_path_buf()
}

struct Bins {
    runner: PathBuf,
    broker: PathBuf,
    worker: PathBuf,
}

fn cargo_build(args: &[&str]) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .arg("build")
        .args(args)
        .arg("--target-dir")
        .arg(target_dir())
        .output()
        .expect("cargo runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

/// The runner, the broker and the risc0 CPU worker (one cargo at a time).
fn bins() -> &'static Bins {
    static BINS: OnceLock<Bins> = OnceLock::new();
    BINS.get_or_init(|| {
        cargo_build(&["-p", "zkminer-witness-builder", "-p", "zkminer-witness-broker", "--bins"]);
        let debug = target_dir().join("debug");
        let worker = match std::env::var_os("ZKMINER_TEST_RISC0_CPU_WORKER") {
            Some(p) => PathBuf::from(p),
            None => {
                cargo_build(&["-p", "zkminer-prove-risc0", "--features", "cpu", "--bin", "zkminer-prove-risc0-cpu"]);
                debug.join("zkminer-prove-risc0-cpu")
            }
        };
        Bins { runner: debug.join("zkminer-witness-builder"), broker: debug.join("zkminer-witness-broker"), worker }
    })
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

/// The SDK's `params-echo` test builder, built with the SDK's pinned toolchain and target features.
fn params_echo_wasm() -> &'static [u8] {
    static WASM: OnceLock<Vec<u8>> = OnceLock::new();
    WASM.get_or_init(|| {
        let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("sdk-target-pipeline-e2e");
        let mut cmd = Command::new(sdk_tool("cargo"));
        cmd.current_dir(sdk_dir())
            .args(["build", "--locked", "--release", "--target", "wasm32-unknown-unknown", "-p", "params-echo", "--target-dir"])
            .arg(&target)
            .env("RUSTC", sdk_tool("rustc"));
        for v in ["RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_DIR"] {
            cmd.env_remove(v);
        }
        let out = cmd.output().expect("cargo runs");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        std::fs::read(target.join("wasm32-unknown-unknown/release/params_echo.wasm")).unwrap()
    })
}

/// The worker's fibonacci guest and its image id, as `--export-guest` writes and prints them.
fn fibonacci() -> &'static (Vec<u8>, B256) {
    static GUEST: OnceLock<(Vec<u8>, B256)> = OnceLock::new();
    GUEST.get_or_init(|| {
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let path = dir.path().join("fibonacci.elf");
        let out = Command::new(&bins().worker).args(["--export-guest", "fibonacci"]).arg(&path).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let id: B256 = String::from_utf8(out.stdout).unwrap().trim().parse().unwrap();
        (std::fs::read(&path).unwrap(), id)
    })
}

fn fib(n: u32) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        (a, b) = (b, a.wrapping_add(b));
    }
    a
}

/// A builder that traps at once.
fn trap_wasm() -> Vec<u8> {
    wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "run") (result i32) unreachable))"#).unwrap()
}

/// A builder that spins until its fuel or wall clock runs out.
fn spin_wasm() -> Vec<u8> {
    wat::parse_str(r#"(module (memory (export "memory") 1) (func (export "run") (result i32) (loop $l (br $l)) (i32.const 0)))"#)
        .unwrap()
}

// ---------------------------------------------------------------------------------------------
// anvil.

struct Anvil {
    child: Child,
    url: String,
    http: reqwest::Client,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        // By pid, never by name.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

impl Anvil {
    async fn start() -> Self {
        for _ in 0..5 {
            let port = free_port();
            let child = Command::new("anvil")
                .args(["--port", &port.to_string(), "--silent"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("anvil on PATH");
            let mut a = Anvil { child, url: format!("http://127.0.0.1:{port}"), http: reqwest::Client::new() };
            for _ in 0..100 {
                if a.try_rpc("eth_chainId", json!([])).await.is_some() {
                    return a;
                }
                if a.child.try_wait().unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        panic!("anvil did not start");
    }

    async fn try_rpc(&self, method: &str, params: Value) -> Option<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let r = self
            .http
            .post(&self.url)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&body).unwrap())
            .send()
            .await
            .ok()?;
        serde_json::from_slice(&r.bytes().await.ok()?).ok()
    }

    async fn rpc(&self, method: &str, params: Value) -> Value {
        let v = self.try_rpc(method, params).await.expect("anvil answers");
        assert!(v.get("error").is_none(), "{method}: {v}");
        v["result"].clone()
    }

    async fn block_number(&self) -> u64 {
        let s = self.rpc("eth_blockNumber", json!([])).await;
        u64::from_str_radix(s.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    }

    async fn mine(&self, blocks: u64) {
        self.rpc("anvil_mine", json!([format!("{blocks:#x}")])).await;
    }

    /// Deploys `runtime` verbatim with `creation_code`, from the dev account.
    async fn deploy(&self, runtime: &[u8]) -> Address {
        let data = format!("0x{}", hex::encode(creation_code(runtime)));
        let tx = self.rpc("eth_sendTransaction", json!([{"from": DEV, "data": data}])).await;
        for _ in 0..100 {
            let receipt = self.rpc("eth_getTransactionReceipt", json!([tx])).await;
            if !receipt.is_null() {
                assert_eq!(receipt["status"], "0x1", "deployment succeeded");
                return receipt["contractAddress"].as_str().unwrap().parse().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no receipt for {tx}");
    }

    /// Publishes `bytes` as `hemi-code` (chunks of at most `chunk` bytes, then the manifest) and
    /// returns its locator.
    async fn publish(&self, bytes: &[u8], chunk: usize) -> String {
        let mut chunks = Vec::new();
        for c in bytes.chunks(chunk) {
            chunks.push(self.deploy(&chunk_runtime_code(c)).await);
        }
        let manifest = self.deploy(&manifest_runtime_code(bytes.len() as u64, &sha256(bytes), &chunks)).await;
        format!("hemi-code://{ANVIL_CHAIN}/0x{}", hex::encode(manifest.as_slice()))
    }
}

// ---------------------------------------------------------------------------------------------
// The host and the hooks.

struct Hooks {
    token: AbortToken,
    claimable_calls: AtomicU32,
    charges: Mutex<Vec<ArtifactCharge>>,
}

impl Hooks {
    fn new() -> Self {
        Self { token: AbortToken::new(), claimable_calls: AtomicU32::new(0), charges: Mutex::default() }
    }
    fn claimable_calls(&self) -> u32 {
        self.claimable_calls.load(Ordering::SeqCst)
    }
    fn charges(&self) -> Vec<(u64, u32)> {
        self.charges.lock().unwrap().iter().map(|c| (c.length, c.chunks)).collect()
    }
}

impl PipelineHooks for Hooks {
    fn claimable(&self) -> HookFuture<'_, Result<(), SkipReason>> {
        self.claimable_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
    fn admit_artifact_charge(&self, charge: ArtifactCharge) -> HookFuture<'_, bool> {
        self.charges.lock().unwrap().push(charge);
        Box::pin(async { true })
    }
    fn abort_token(&self) -> &AbortToken {
        &self.token
    }
}

struct Env {
    anvil: Anvil,
    _broker: BrokerProcess,
    ctx: HostContext,
    root: PathBuf,
    /// The params-echo builder's locator and id.
    echo_uri: String,
    echo_id: B256,
    router: Address,
    prover: Address,
    _dir: tempfile::TempDir,
}

fn host_maxima() -> HostMaxima {
    HostMaxima {
        max_witness_bytes: 32 << 20,
        max_guest_cycles: 1 << 30,
        max_fetches: 1_024,
        max_fetch_bytes: 1 << 28,
        max_request_bytes: 65_536,
        max_response_bytes: 32 << 20,
        max_builder_fuel: 20_000_000_000,
        max_builder_memory_bytes: 512 << 20,
        max_builder_seconds: 120,
    }
}

/// A miner config on anvil's chain with `[dev] private_network = true`: the broker it starts runs
/// in developer mode.
fn dev_miner() -> zkminer_config::ZkMinerConfig {
    let mut c = zkminer_config::ZkMinerConfig::default();
    c.chain.chain_id = ANVIL_CHAIN;
    c.dev.private_network = true;
    c.dev.chain_id = Some(ANVIL_CHAIN);
    assert_eq!(c.net_mode(), zkminer_netguard::NetMode::DevPrivate);
    c
}

impl Env {
    async fn start(test: &str) -> Option<Self> {
        let root = delegated(test)?;
        let bins = bins();
        let (elf, image_id) = fibonacci().clone();
        let anvil = Anvil::start().await;
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let config = dir.path().join("broker.toml");
        std::fs::write(
            &config,
            format!(
                "chain_rpc_host = \"chain-rpc.invalid\"\nspool_dir = \"{spool}\"\n\
                 [[evm_rpc]]\nalias = \"anvil\"\nurl = \"{url}\"\nchain_id = {ANVIL_CHAIN}\narchive = true\n\
                 max_proof_age = 1000000\nmethod_sets = [\"state-read\"]\ncidrs = [\"127.0.0.1/32\"]\n\
                 [artifacts]\nalias = \"anvil-artifacts\"\nurl = \"{url}\"\nchain_id = {ANVIL_CHAIN}\n\
                 max_requests_per_sec = 1000\nmax_builder_bytes = 4194304\ncidrs = [\"127.0.0.1/32\"]\n",
                spool = dir.path().join("spool").display(),
                url = anvil.url
            ),
        )
        .unwrap();
        let spawner = Spawner::new().unwrap();
        // anvil is on 127.0.0.1: developer mode, as a miner with `[dev] private_network` runs it.
        let broker =
            BrokerProcess::start(&spawner, &bins.broker, &config, &root, 512 << 20, &dev_miner())
                .unwrap();

        let (router, prover) = (Address::repeat_byte(0x0a), Address::repeat_byte(0x9e));
        let store_dir = dir.path().join("store");
        std::fs::create_dir(&store_dir).unwrap();
        let id = Store::init(
            &store_dir,
            &StoreIdentityInit { chain_id: ANVIL_CHAIN, router, prover, require_dedicated_mount: false, allow_any_filesystem: false },
        )
        .unwrap();
        let store = Store::open(
            &store_dir,
            &ExpectedIdentity { chain_id: ANVIL_CHAIN, router, prover, store_uuid: id.store_uuid },
            StoreOptions {
                quota_bytes: 1 << 30,
                quota_inodes: 100_000,
                free_space_floor_bytes: 0,
                require_dedicated_mount: false,
                allow_any_filesystem: false,
            },
        )
        .unwrap();

        // The params-echo builder on chain, in several chunks, at or below the safe head.
        let wasm = params_echo_wasm();
        let echo_uri = anvil.publish(wasm, 8_000).await;
        anvil.mine(40).await;

        let known = elf.clone();
        let image_id_fn: ImageIdFn = Arc::new(move |b: &[u8]| (b == known.as_slice()).then_some(image_id));
        // The execute worker's build, from its handshake before any guest ran in it, as the runtime
        // asks when serving starts.
        let execute_build = execute_worker_build(&bins.worker, &root, Duration::from_secs(60)).await.unwrap();
        let ctx = HostContext {
            spawner,
            broker: broker.client.clone(),
            store: Arc::new(store),
            cgroup_root: root.clone(),
            builder_binary: bins.runner.clone(),
            execute_binary: bins.worker.clone(),
            host_maxima: host_maxima(),
            po2s: PO2S.to_vec(),
            cycle_judging: CycleJudging::EveryPo2,
            keccak_po2: 17,
            worker_builds: vec!["test-worker-build".into()],
            execute_build,
            execute_memory_bytes: 512 << 20,
            execute_timeout: Duration::from_secs(120),
            max_artifact_bytes: 4 << 20,
            image_id_fn,
            eviction_value: eviction_by_age(),
        };
        Some(Env {
            anvil,
            _broker: broker,
            ctx,
            root,
            echo_uri,
            echo_id: B256::from(sha256(wasm)),
            router,
            prover,
            _dir: dir,
        })
    }

    fn image_id(&self) -> B256 {
        fibonacci().1
    }
}

/// One job: the envelope and the binding.
#[derive(Clone)]
struct Spec {
    job_id: B256,
    builder_id: B256,
    uris: Vec<String>,
    params: Vec<u8>,
    sources: Vec<Capability>,
    limits: Limits,
    expected: B256,
    fields: B256,
}

fn anvil_source(chain_id: u64) -> Capability {
    Capability { class: CLASS_EVM_RPC_V1, config: encode_evm_rpc_config(chain_id, true, METHOD_SET_STATE_READ, 0).into() }
}

fn limits() -> Limits {
    Limits {
        maxFetches: 4,
        maxFetchBytes: 1 << 20,
        maxRequestBytes: 65_536,
        maxResponseBytes: 1 << 20,
        maxBuilderFuel: 1_000_000_000,
        maxBuilderMemoryBytes: 64 << 20,
        maxBuilderSeconds: 30,
        maxWitnessBytes: 1 << 16,
        maxGuestCycles: 1 << 24,
    }
}

/// `journalFields` with the given slot words.
fn slots(s: &[u32]) -> B256 {
    let mut w = B256::ZERO;
    for (i, v) in s.iter().enumerate() {
        w.0[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    w
}

impl Env {
    /// A FULL-bound fibonacci job for `fib(n)`, built by params-echo.
    fn full(&self, n: u32) -> Spec {
        Spec {
            job_id: keccak256(format!("job-{n}")),
            builder_id: self.echo_id,
            uris: vec![self.echo_uri.clone()],
            params: n.to_le_bytes().to_vec(),
            sources: vec![anvil_source(ANVIL_CHAIN)],
            limits: limits(),
            expected: full_hash(risc_zero_groth16_v1_id(), self.image_id(), &fib(n).to_le_bytes()),
            fields: B256::ZERO,
        }
    }

    fn descriptor(&self, s: &Spec) -> JobDescriptor {
        let envelope = WitnessJobV1 {
            builderType: 1,
            builderId: s.builder_id,
            builderURIs: s.uris.clone(),
            builderParams: s.params.clone().into(),
            sources: s.sources.clone(),
            limits: s.limits.clone(),
        };
        JobDescriptor {
            programId: self.image_id(),
            proofSystemId: risc_zero_groth16_v1_id(),
            callbackContract: Address::ZERO,
            assignedProver: Address::ZERO,
            tag: B256::ZERO,
            inputData: encode_envelope(&envelope).into(),
            callbackExtraData: Default::default(),
            extraVerifierData: Default::default(),
            expectedJournalHash: s.expected,
            journalFields: s.fields,
        }
    }

    async fn run(&self, s: &Spec, hooks: &Hooks) -> (JobDescriptor, Result<Simulated, Skip>) {
        let d = self.descriptor(s);
        let block = self.anvil.block_number().await;
        let job = JobInput {
            job_id: s.job_id,
            descriptor: &d,
            descriptor_hash: compute_descriptor_hash(&d),
            submit_tx_hash: B256::repeat_byte(0x7c),
            caller: Address::repeat_byte(0xca),
            prover: self.prover,
            chain_id: ANVIL_CHAIN,
            router: self.router,
            elf: Some(&fibonacci().0),
            artifact: None,
            current_block: block,
        };
        let r = simulate_witness_job(&self.ctx, &job, hooks).await;
        (d, r)
    }

    /// Asserts nothing was published for `d`, and that the store holds no bundle at all.
    fn assert_no_bundle(&self, s: &Spec, d: &JobDescriptor) {
        assert!(matches!(
            self.ctx.store.latest(s.job_id, compute_descriptor_hash(d), self.prover),
            Err(StoreError::Missing { .. })
        ));
        assert!(self.ctx.store.scan().unwrap().bundles.is_empty());
    }

    /// Sandboxes left in the delegated root by the pipeline (the broker's cgroup aside).
    fn leftover_sandboxes(&self) -> Vec<String> {
        std::fs::read_dir(&self.root)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("builder-") || n.starts_with("wexec-"))
            .collect()
    }
}

fn verdict(r: &Result<Simulated, Skip>) -> (SkipReason, Step, String) {
    match r {
        Err(Skip::Verdict { reason, step, detail }) => (*reason, *step, detail.clone()),
        Err(e) => panic!("expected a verdict, got {e}"),
        Ok(s) => panic!("expected a skip, got a bundle {:?}", s.bundle),
    }
}

// ---------------------------------------------------------------------------------------------
// Cases.

#[test]
fn a_full_binding_job_publishes_a_bundle_the_store_reads_back_verified() {
    serial(|| async {
        let Some(env) = Env::start("full").await else { return };
        let spec = env.full(1000);
        let hooks = Hooks::new();
        let (d, r) = env.run(&spec, &hooks).await;
        let sim = r.unwrap_or_else(|e| panic!("{e}"));
        let journal = fib(1000).to_le_bytes();
        assert_eq!(sim.journal, journal);
        assert_eq!(sim.per_po2.iter().map(|p| p.po2).collect::<Vec<_>>(), vec![16, 18]);
        assert!(sim.per_po2.iter().all(|p| p.cycles > 0 && p.segment_bytes > 0));
        assert_eq!((sim.w_len, sim.prefix), (4, false));
        assert_eq!(hooks.claimable_calls(), 1);
        assert_eq!(hooks.charges().len(), 1, "charged once, before the chunks were read");
        assert!(matches!(sim.builder.artifact_origin, ArtifactOrigin::HemiCode { .. }));
        assert!(!sim.builder.artifact_cached);

        // The store reads it back verified: record, W, ELF.
        let image_id_fn = env.ctx.image_id_fn.clone();
        let b = env.ctx.store.verify(&sim.bundle, &descriptor_hash_of_abi, &*image_id_fn).unwrap();
        assert_eq!(b, sim.record);
        let mut w = Vec::new();
        std::io::Read::read_to_end(&mut env.ctx.store.open_w(&sim.bundle).unwrap(), &mut w).unwrap();
        assert_eq!(w, 1000u32.to_le_bytes());
        assert_eq!(b.input_sha256, B256::from(<[u8; 32]>::from(Sha256::digest(&w))));
        assert_eq!(b.w_sha256, b.input_sha256);
        assert_eq!(b.job_id, spec.job_id);
        assert_eq!(b.descriptor_hash, compute_descriptor_hash(&d));
        assert_eq!(descriptor_hash_of_abi(&hex::decode(&b.descriptor_hex).unwrap()), Some(b.descriptor_hash));
        assert_eq!((b.prover, b.caller, b.builder_id), (env.prover, Address::repeat_byte(0xca), env.echo_id));
        assert_eq!((b.image_id, b.keccak_po2, b.submit_tx_hash), (env.image_id(), 17, B256::repeat_byte(0x7c)));
        assert_eq!(b.sys_rand_rule, sys_rand_rule());
        // The prove workers' builds and the execute worker's own, as its handshake named it (and its
        // response agreed).
        assert!(sim.execute_build.starts_with("risc0/risc0-zkvm "), "{}", sim.execute_build);
        assert_eq!(sim.execute_build, env.ctx.execute_build);
        let mut want = vec!["test-worker-build".to_string(), sim.execute_build.clone()];
        want.sort();
        assert_eq!(b.worker_builds, want);
        assert!(b.execute_ms_per_po2.is_some());
        assert_eq!(b.elf_sha256, Some(B256::from(<[u8; 32]>::from(Sha256::digest(&fibonacci().0)))));
        // The ELF reads back by its digest, with no image-id derivation.
        let (_, elf_back) = env.ctx.store.verify_with_elf(&sim.bundle, &descriptor_hash_of_abi, &|_| None).unwrap();
        assert_eq!(elf_back, fibonacci().0);
        assert!(b.created_at_block > 0);
        assert_eq!(b.version, sim.bundle.version);
        assert_eq!(b.po2_results.len(), 2);
        for p in &b.po2_results {
            assert_eq!(hex::decode(&p.journal_hex).unwrap(), journal);
            assert_eq!(p.exit, zkminer_witness::bundle::GuestExit::Halted(0));
        }
        assert_eq!(env.ctx.store.open_elf(env.image_id(), &*image_id_fn).unwrap(), fibonacci().0);

        // Simulating the job again: the artifact is served from the broker's cache (no new charge)
        // and the result is a new version.
        let (_, again) = env.run(&spec, &hooks).await;
        let again = again.unwrap_or_else(|e| panic!("{e}"));
        assert!(again.builder.artifact_cached);
        assert_eq!(hooks.charges().len(), 1);
        assert!(again.bundle.version > sim.bundle.version);
        assert_eq!(again.journal, journal);
        assert!(env.leftover_sandboxes().is_empty(), "{:?}", env.leftover_sandboxes());
    })
}

/// The bundle records the execute worker's build from its handshake, made before any guest ran in it,
/// never what the process that ran the requester's guest says of itself: a response naming another
/// build (here, a handshake recorded for another binary) skips the job and publishes nothing.
#[test]
fn a_response_naming_another_build_than_the_handshake_publishes_nothing() {
    serial(|| async {
        let Some(mut env) = Env::start("build").await else { return };
        env.ctx.execute_build = "risc0/risc0-zkvm 0.0.0/0.0.0".into();
        let spec = env.full(1000);
        let (d, r) = env.run(&spec, &Hooks::new()).await;
        let (reason, step, detail) = verdict(&r);
        assert_eq!((reason, step), (SkipReason::HostInternal, Step::Execute), "{detail}");
        assert!(detail.contains("handshake"), "{detail}");
        env.assert_no_bundle(&spec, &d);
        assert!(env.leftover_sandboxes().is_empty(), "{:?}", env.leftover_sandboxes());
    })
}

#[test]
fn a_fields_binding_job_succeeds() {
    serial(|| async {
        let Some(env) = Env::start("fields").await else { return };
        let mut spec = env.full(77);
        // One range: the journal's 8 bytes.
        spec.fields = slots(&[8]);
        spec.expected = keccak256(fib(77).to_le_bytes());
        let (_, r) = env.run(&spec, &Hooks::new()).await;
        let sim = r.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(sim.journal, fib(77).to_le_bytes());
    })
}

#[test]
fn a_wrong_expected_journal_hash_is_a_binding_mismatch_and_publishes_nothing() {
    serial(|| async {
        let Some(env) = Env::start("wrong-hash").await else { return };
        let mut spec = env.full(1000);
        spec.expected = full_hash(risc_zero_groth16_v1_id(), env.image_id(), &fib(1001).to_le_bytes());
        let (d, r) = env.run(&spec, &Hooks::new()).await;
        let (reason, step, detail) = verdict(&r);
        assert_eq!((reason, step), (SkipReason::BindingMismatch, Step::Binding), "{detail}");
        env.assert_no_bundle(&spec, &d);
        assert!(env.leftover_sandboxes().is_empty());
    })
}

#[test]
fn a_prefix_job_whose_guest_does_not_commit_the_prefix_is_a_binding_mismatch() {
    serial(|| async {
        let Some(env) = Env::start("prefix").await else { return };
        let mut spec = env.full(1000);
        // The guest reads its u32 from the start of its input, which is now the prefix's jobId:
        // make that 12, so it computes fib(12) and commits it without the prefix.
        let mut job_id = [0x33u8; 32];
        job_id[..4].copy_from_slice(&12u32.to_le_bytes());
        spec.job_id = B256::from(job_id);
        spec.fields = slots(&[0xffff_ffff, 8]);
        spec.expected = keccak256(fib(12).to_le_bytes());
        let (d, r) = env.run(&spec, &Hooks::new()).await;
        let (reason, step, detail) = verdict(&r);
        assert_eq!((reason, step), (SkipReason::BindingMismatch, Step::Binding), "{detail}");
        assert!(detail.contains("JournalPrefixMismatch"), "{detail}");
        env.assert_no_bundle(&spec, &d);
    })
}

#[test]
fn a_builder_that_traps_is_skipped_with_no_bundle() {
    serial(|| async {
        let Some(env) = Env::start("trap").await else { return };
        let wasm = trap_wasm();
        let uri = env.anvil.publish(&wasm, 24_575).await;
        env.anvil.mine(40).await;
        let mut spec = env.full(1000);
        spec.builder_id = B256::from(sha256(&wasm));
        spec.uris = vec![uri];
        let (d, r) = env.run(&spec, &Hooks::new()).await;
        let (reason, step, detail) = verdict(&r);
        assert_eq!((reason, step), (SkipReason::BuilderTrap, Step::Builder), "{detail}");
        env.assert_no_bundle(&spec, &d);
        assert!(env.leftover_sandboxes().is_empty());
    })
}

#[test]
fn an_unprovisioned_capability_is_skipped_before_any_builder_runs() {
    serial(|| async {
        let Some(env) = Env::start("unprovisioned").await else { return };
        let mut spec = env.full(1000);
        // The broker serves evm-rpc/v1 for chain 31337 only.
        spec.sources = vec![anvil_source(1)];
        let hooks = Hooks::new();
        let (d, r) = env.run(&spec, &hooks).await;
        let (reason, step, detail) = verdict(&r);
        assert_eq!((reason, step), (SkipReason::CapabilityNotProvisioned, Step::StaticGates), "{detail}");
        assert_eq!(hooks.claimable_calls(), 0, "the chain gates were not reached");
        assert!(hooks.charges().is_empty(), "no artifact was read");
        env.assert_no_bundle(&spec, &d);
    })
}

#[test]
fn limits_above_the_host_maxima_are_skipped() {
    serial(|| async {
        let Some(env) = Env::start("limits").await else { return };
        let mut spec = env.full(1000);
        spec.limits.maxWitnessBytes = host_maxima().max_witness_bytes + 1;
        let hooks = Hooks::new();
        let (_, r) = env.run(&spec, &hooks).await;
        assert_eq!(verdict(&r).0, SkipReason::LimitsAboveHostMaxima);
        assert_eq!(verdict(&r).1, Step::StaticGates);
        let mut spec = env.full(1000);
        spec.limits.maxGuestCycles = host_maxima().max_guest_cycles + 1;
        let (_, r) = env.run(&spec, &hooks).await;
        assert_eq!(verdict(&r).0, SkipReason::LimitsAboveHostMaxima);
        assert_eq!(hooks.claimable_calls(), 0);
    })
}

#[test]
fn an_artifact_for_another_builder_id_is_all_sources_bad() {
    serial(|| async {
        let Some(env) = Env::start("id-mismatch").await else { return };
        let mut spec = env.full(1000);
        // The locator names params-echo's manifest; the job claims another artifact.
        spec.builder_id = B256::from(sha256(b"some other builder"));
        let hooks = Hooks::new();
        let (d, r) = env.run(&spec, &hooks).await;
        let (reason, step, detail) = verdict(&r);
        assert_eq!((reason, step), (SkipReason::ArtifactAllSourcesBad, Step::Artifact), "{detail}");
        assert!(hooks.charges().is_empty(), "refused at the manifest, before any chunk read");
        env.assert_no_bundle(&spec, &d);
    })
}

#[test]
fn max_guest_cycles_below_the_execution_is_guest_cycles_above_limit() {
    serial(|| async {
        let Some(env) = Env::start("cycles").await else { return };
        let mut spec = env.full(1000);
        spec.limits.maxGuestCycles = 1_000;
        let (d, r) = env.run(&spec, &Hooks::new()).await;
        let (reason, step, detail) = verdict(&r);
        assert_eq!((reason, step), (SkipReason::GuestCyclesAboveLimit, Step::Execute), "{detail}");
        env.assert_no_bundle(&spec, &d);
        assert!(env.leftover_sandboxes().is_empty());
    })
}

#[test]
fn an_abort_mid_builder_kills_the_runner() {
    serial(|| async {
        let Some(env) = Env::start("abort").await else { return };
        let wasm = spin_wasm();
        let uri = env.anvil.publish(&wasm, 24_575).await;
        env.anvil.mine(40).await;
        let mut spec = env.full(1000);
        spec.builder_id = B256::from(sha256(&wasm));
        spec.uris = vec![uri];
        spec.limits.maxBuilderFuel = u64::MAX; // clamped to the host's 2·10^10
        spec.limits.maxBuilderSeconds = 60;
        let hooks = Hooks::new();
        // Fire the token once the runner's cgroup exists and has had half a second.
        let fired = Arc::new(Mutex::new(None::<Instant>));
        let watcher = {
            let (root, token, fired) = (env.root.clone(), hooks.token.clone(), fired.clone());
            tokio::spawn(async move {
                loop {
                    let running = std::fs::read_dir(&root)
                        .unwrap()
                        .filter_map(|e| e.ok())
                        .any(|e| e.file_name().to_string_lossy().starts_with("builder-"));
                    if running {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        *fired.lock().unwrap() = Some(Instant::now());
                        token.abort(AbortReason::JobClaimed);
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
        };
        let (d, r) = env.run(&spec, &hooks).await;
        let returned = Instant::now();
        watcher.await.unwrap();
        assert_eq!(r.as_ref().err(), Some(&Skip::Aborted { reason: AbortReason::JobClaimed, step: Step::Builder }));
        let fired = fired.lock().unwrap().expect("the watcher fired");
        assert!(returned - fired < Duration::from_secs(5), "returned {:?} after the abort", returned - fired);
        assert!(env.leftover_sandboxes().is_empty(), "{:?}", env.leftover_sandboxes());
        env.assert_no_bundle(&spec, &d);
        // An aborted attempt never consults the chain gates again, and a new token works afresh.
        assert_eq!(hooks.claimable_calls(), 1);
    })
}
