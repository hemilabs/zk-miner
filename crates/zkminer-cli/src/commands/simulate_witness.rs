//! `zkminer simulate --descriptor <file>`: a witness-construction job that is not on chain, run
//! through the miner's own pre-claim pipeline (docs/witness-construction-jobs.md §5.2, §16, §18), and
//! with `--adversarial` attacked through its witness and its host inputs (§21.1 item 3).
//!
//! **The same path as the miner.** The job goes through `zkminer_witness_host::pipeline::
//! simulate_witness_job`, the function the miner's runtime calls before any lock: the static gates,
//! the builder artifact (through the broker: the operator mirror, then the job's `hemi-code`
//! locators; or `--builder`, held to the same id and size checks), the builder in its sandbox with
//! `W` streamed into a retention store, the guest executed in the execute sandbox on `prefix ‖ W` at
//! every po2 of `--po2` (the guest input from `guest_input_prefix`, the seed derived as the miner
//! derives it), the router's binding check with the prover's address, and the bundle published and
//! verified by the store. The limits are the miner's (`pipeline::host_maxima` of this
//! configuration's `[witness]`), and so are the sandbox and broker self-tests, which must pass
//! first. So a simulation cannot pass where a miner with this configuration would refuse; it can
//! only check less: what depends on the chain (the claimability `eth_call`, the submission form, the
//! deployment pins, admission, the reservation, the deadline margin, prove resources) is listed under
//! `notChecked`, since the job is not on chain.
//!
//! What differs, deliberately: the `sys_rand` key is this run's own (never `~/.zkminer`'s, §16); the
//! retention store is a throwaway one under the cache directory (on a real filesystem: the store
//! refuses tmpfs), removed at the end; the guest ELF's image id is checked by the execute worker
//! (an ELF that is not the job's program skips at the execute step, `ElfImageIdMismatch`, where the
//! miner's measure worker would skip it before the builder ran).
//!
//! **Outputs (§16):** fuel, fetches, bytes, the builder's peak memory, `|W|`, cycles in the
//! `maxGuestCycles` unit and the journal per po2, the pinned bytes and the binding's mutation check,
//! the estimated fulfil DA size, and this host's admission parameters; one JSON document.
//!
//! **`--adversarial`** (see `zkminer_witness_host::adversarial`): the generic mutations of `W` and
//! the job's scheme's own (by the scheme id in the journal header, or `--scheme`), each re-executed;
//! re-execution under two `sys_rand` keys, two po2s and two keccak po2s; and a differential run of
//! the whole pipeline against two `evm-rpc` providers of the broker configuration (`--providers`,
//! default the first two serving the job's chain), each from a broker configuration holding only
//! that provider. All within `--adversarial-secs`; anything not run is reported, and makes the
//! verdict `incomplete`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use alloy::primitives::{keccak256, Address, B256};
use anyhow::{bail, Context, Result};
use serde::Serialize;

use zkminer_chain::client::ChainClient;
use zkminer_chain::da::{
    conservative_fulfil_tx, da_bytes_upper_bound, estimate_fulfil_da_bytes, SealSpec, DEFAULT_FULFIL_DA_CAP_BYTES,
    STANDARD_FULFIL_DA_BYTES,
};
use zkminer_chain::jobs::{fulfill_gas_formula, fulfill_job_hashed_calldata, HashedFulfil};
use zkminer_config::ZkMinerConfig;
use zkminer_contracts::bindings::JobDescriptor;
use zkminer_witness::binding::{guest_input_prefix, PREFIX_BYTES};
use zkminer_witness::envelope::{decode, CapabilityKind, Limits};
use zkminer_witness::verdict::SkipReason;
use zkminer_witness_broker::client::ArtifactCharge;
use zkminer_witness_host::abort::{AbortReason, AbortToken};
use zkminer_witness_host::adversarial::{
    fetch_through_job, framings, generic_mutations, host_input_checks, run_mutations, scheme_id_of, seed_for, Baseline,
    HostInputResult, Judge, MutationOutcome, MutationResult, RpcCall, SchemeContext, SchemeRegistry,
};
use zkminer_witness_host::broker_proc::BrokerProcess;
use zkminer_witness_host::paths;
use zkminer_witness_host::pipeline::{
    eviction_by_age, execute_worker_build, host_maxima, key_fingerprint, simulate_witness_job, ArtifactOrigin,
    HookFuture, HostContext, ImageIdFn, JobInput, PipelineHooks, Simulated, Skip,
    DEFAULT_MAX_ARTIFACT_BYTES, MAX_HOST_GUEST_CYCLES,
};
use zkminer_witness_host::spawner::Spawner;
use zkminer_witness_store::{ExpectedIdentity, Store, StoreIdentityInit, StoreOptions};

use super::simulate::redact_urls;
use super::witness_tools::{check_binding, BindingReport, CheckInput, DescriptorFile};

/// The witness report's schema version.
pub const WITNESS_REPORT_SCHEMA: u32 = 1;
/// The default `--adversarial-secs`.
pub const DEFAULT_ADVERSARIAL_SECS: u64 = 600;
/// The default `--flips`: byte flips at sampled offsets of `W`.
pub const DEFAULT_FLIPS: usize = 32;
/// The most mutations one run executes (generic and scheme together), and the default of
/// `--max-mutations`.
pub const MAX_MUTATIONS: usize = 256;
/// The scheme mutations asked of a registered scheme (structural ones first).
const SCHEME_MUTATIONS: usize = 160;
/// Bound on each self-test and on the execute worker's build handshake.
const SETUP_BOUND: Duration = Duration::from_secs(120);
/// Bound on the registry read and the ELF download when no `--elf` is given.
const ELF_FETCH_BOUND: Duration = Duration::from_secs(120);
/// The throwaway store's byte quota.
const STORE_QUOTA_BYTES: u64 = 4 << 30;

/// `--adversarial` and its knobs.
#[derive(Debug, Clone)]
pub struct AdversarialOptions {
    pub budget: Duration,
    pub flips: usize,
    /// The most mutations executed (the scheme's first, then the generic ones).
    pub max_mutations: usize,
    pub scheme: Option<u64>,
    /// Two `[[evm_rpc]]` aliases of the broker configuration.
    pub providers: Option<Vec<String>>,
}

/// One descriptor-file simulation.
#[derive(Debug, Clone)]
pub struct WitnessSimOptions {
    pub descriptor: PathBuf,
    pub builder: Option<PathBuf>,
    pub elf: Option<PathBuf>,
    pub prover: Option<Address>,
    pub po2s: Vec<u8>,
    pub keccak_po2: u8,
    pub broker_config: Option<PathBuf>,
    pub execute_worker: Option<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub execute_timeout: Duration,
    pub out: Option<PathBuf>,
    pub adversarial: Option<AdversarialOptions>,
}

// ---------------------------------------------------------------------------------------------
// The report.

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerdictReport {
    pub reason: SkipReason,
    pub step: String,
    pub retry: String,
    pub blames_caller: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuilderReport {
    /// `local` (`--builder`), `mirror`, or `hemi-code:<manifest>`.
    pub artifact_origin: String,
    pub artifact_bytes: u64,
    pub artifact_cached: bool,
    /// `hemi-code` reads admitted before any chunk was read (§13.4 step 3): `(length, chunks)`.
    pub artifact_charges: Vec<(u64, u32)>,
    pub fetches: u32,
    pub fetch_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fuel_used: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_ms: Option<u32>,
    pub wall_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_peak_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Po2Report {
    pub po2: u32,
    /// Sized cycles, the `maxGuestCycles` unit (a decimal string).
    pub cycles: String,
    pub segment_bytes: u64,
    pub peak_host_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalReport {
    pub bytes: usize,
    pub hex: String,
    pub sha256: B256,
    pub keccak256: B256,
    /// The pinned statement bytes (after any prefix), hex, per pinned range.
    pub pinned_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FulfilReport {
    pub calldata_bytes: usize,
    pub estimated_da_bytes: u64,
    /// `GasPriceOracle` (an `eth_call` on the configured chain RPC), or `upper bound` (no RPC).
    pub estimate_source: String,
    /// LARGE for the DA nonce rule (above the standard ~600 bytes, §5.5).
    pub large: bool,
    /// Within the claim gate's default operator cap (§5.5).
    pub within_default_cap: bool,
    pub default_cap_bytes: u64,
    /// The guide's fulfil gas, with the default callback gas (a descriptor file has no
    /// `callbackGasLimit`, which is a submit argument).
    pub gas: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessFacts {
    pub bytes: u64,
    pub sha256: B256,
    /// `sha256(prefix ‖ W)`, the input the bundle records.
    pub input_sha256: B256,
    pub prefix: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CyclesReport {
    pub declared_max_guest_cycles: String,
    /// The largest over the executed po2s.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured: Option<String>,
    /// This host's maximum (`[witness] max_guest_cycles`, else the cap simulate uses).
    pub host_max_guest_cycles: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Timings {
    pub static_gates_ms: u64,
    pub artifact_ms: u64,
    pub builder_ms: u64,
    pub execute_ms: u64,
    pub publish_ms: u64,
    pub total_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderRun {
    pub alias: String,
    /// `simulated`, `skipped` or `not_run`.
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<VerdictReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub w_sha256: Option<B256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_sha256: Option<B256>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DifferentialReport {
    pub runs: Vec<ProviderRun>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub w_same: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_same: Option<bool>,
    /// Both runs satisfied the binding with different journals: what the job proves depends on which
    /// provider answered, and a prover picks its provider.
    pub soundness_failure: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationCounts {
    pub total: usize,
    pub rejected_in_guest: usize,
    pub identical_journal: usize,
    pub binding_rejects: usize,
    pub soundness_failures: usize,
    pub inconclusive: usize,
    pub not_run: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemeReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdversarialReport {
    /// `pass`, `fail` (a soundness failure or a host-input dependence), or `incomplete` (something
    /// not run or inconclusive).
    pub verdict: String,
    pub budget_secs: u64,
    pub elapsed_secs: f64,
    pub run_seed: String,
    pub scheme: SchemeReport,
    pub framings: Vec<String>,
    pub counts: MutationCounts,
    pub mutations: Vec<MutationResult>,
    pub host_inputs: Vec<HostInputResult>,
    pub differential: DifferentialReport,
    /// One line per failure, naming what caused it.
    pub soundness_failures: Vec<String>,
    /// Findings that are not failures (a guest that ignores trailing bytes of `W`).
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessReport {
    pub schema: u32,
    pub kind: &'static str,
    pub job_id: B256,
    pub descriptor_hash: B256,
    pub program_id: B256,
    pub prover: Address,
    pub caller: Address,
    pub chain_id: u64,
    pub router: Address,
    /// `simulated` (a bundle was published: a miner with this configuration would go on to its
    /// claim gate), `skipped` (a §16 verdict), or `aborted`.
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<VerdictReport>,
    pub po2s: Vec<u8>,
    pub keccak_po2: u8,
    /// The per-run `sys_rand` key's fingerprint (never a miner's key).
    pub sys_rand_key_fingerprint: B256,
    pub execute_build: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder: Option<BuilderReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<WitnessFacts>,
    pub per_po2: Vec<Po2Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles: Option<CyclesReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal: Option<JournalReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<BindingReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfil: Option<FulfilReport>,
    pub admission: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timings: Option<Timings>,
    pub not_checked: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adversarial: Option<AdversarialReport>,
    pub zkminer_version: &'static str,
    pub protocol_version: u32,
}

fn verdict_report(s: &Skip) -> Option<VerdictReport> {
    match s {
        Skip::Verdict { reason, step, detail } => {
            let v = reason.verdict();
            Some(VerdictReport {
                reason: *reason,
                step: format!("{step:?}"),
                retry: format!("{:?}", v.retry),
                blames_caller: v.blames_caller,
                detail: redact_urls(detail),
            })
        }
        Skip::Aborted { .. } => None,
    }
}

/// What a descriptor-file simulation cannot check, the job not being on chain (§5.3, §5.2 step 7).
const NOT_CHECKED: [&str; 7] = [
    "claimability eth_call (exclusivity, bids, cooldown, pauses, stake)",
    "submission form",
    "deployment core pins",
    "admission (caller allowlist, lanes, credit)",
    "reservation against the price",
    "deadline margin and proving time",
    "prove resources (segment disk, host RAM, VRAM)",
];

/// The parts of the report that depend on this host's configuration only.
fn admission_parameters(config: &ZkMinerConfig, maxima: &zkminer_witness::envelope::HostMaxima) -> serde_json::Value {
    let w = &config.witness;
    serde_json::json!({
        "journalCapBytes": zkminer_witness::binding::MAX_JOURNAL_BYTES,
        "fulfilDaCapBytes": w.fulfil_da_cap_bytes,
        "daBacklogHoldBytes": w.da_backlog_hold_bytes,
        "callerAllowlist": !w.open_admission,
        "k": w.k,
        "creditC": w.credit_c,
        "hostMaxima": {
            "maxWitnessBytes": maxima.max_witness_bytes,
            "maxGuestCycles": maxima.max_guest_cycles.to_string(),
            "maxFetches": maxima.max_fetches,
            "maxFetchBytes": maxima.max_fetch_bytes,
            "maxRequestBytes": maxima.max_request_bytes,
            "maxResponseBytes": maxima.max_response_bytes,
            "maxBuilderFuel": maxima.max_builder_fuel.to_string(),
            "maxBuilderMemoryBytes": maxima.max_builder_memory_bytes,
            "maxBuilderSeconds": maxima.max_builder_seconds,
        },
        "maxArtifactBytes": DEFAULT_MAX_ARTIFACT_BYTES,
        "note": "this configuration's values (the published defaults unless it overrides them); other miners may differ"
    })
}

// ---------------------------------------------------------------------------------------------
// The host.

/// What every pipeline run of this simulation shares: the sandbox's cgroup root and spawner, the
/// binaries, the execute worker's build, and a throwaway retention store.
struct SimHost {
    spawner: Spawner,
    root: PathBuf,
    builder_binary: PathBuf,
    execute_binary: PathBuf,
    broker_binary: PathBuf,
    broker_memory: u64,
    execute_build: String,
    work: PathBuf,
    store: Arc<Store>,
}

impl Drop for SimHost {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.work) {
            tracing::warn!("simulate: removing {}: {e}", self.work.display());
        }
    }
}

fn existing(p: PathBuf) -> Result<PathBuf> {
    if p.is_file() {
        Ok(p)
    } else {
        bail!("{} does not exist", p.display())
    }
}

impl SimHost {
    async fn start(
        config: &ZkMinerConfig,
        secret: &Path,
        opts: &WitnessSimOptions,
        router: Address,
        prover: Address,
    ) -> Result<Self> {
        let root = zkminer_witness_sandbox::delegated_root().context(
            "the delegated cgroup (run it as `systemd-run --user --scope -p Delegate=yes -- zkminer simulate …`)",
        )?;
        let spawner = Spawner::new().context("the spawner thread")?;
        let w = &config.witness;
        let builder_binary = existing(paths::binary(w.builder_binary.as_deref(), paths::BUILDER_BINARY)?)?;
        let execute_binary = existing(paths::binary(
            opts.execute_worker.as_deref().or(w.execute_binary.as_deref()),
            paths::EXECUTE_BINARY,
        )?)?;
        let broker_binary =
            existing(paths::binary(config.broker.as_ref().and_then(|b| b.binary.as_deref()), paths::BROKER_BINARY)?)?;
        let probe = existing(paths::binary(None, zkminer_witness_sandbox::probe::PROBE_BINARY)?)?;
        // The miner serves nothing without a passing sandbox self-test; neither does this.
        let mode = match w.sandbox_mode {
            zkminer_config::witness::SandboxModeConfig::System => zkminer_witness_sandbox::SandboxMode::System,
            zkminer_config::witness::SandboxModeConfig::Rootless => zkminer_witness_sandbox::SandboxMode::Rootless,
        };
        let (p, s) = (probe, secret.to_path_buf());
        let report = tokio::time::timeout(SETUP_BOUND, spawner.run_async(move || zkminer_witness_sandbox::self_test(mode, &p, &s)))
            .await
            .context("the sandbox self-test did not finish")??;
        if !report.passed() {
            let failed: Vec<String> = report.checks.iter().filter(|c| !c.passed).map(|c| format!("{}: {}", c.name, c.detail)).collect();
            bail!("the sandbox self-test failed: {}", failed.join("; "));
        }
        let execute_build = execute_worker_build(&execute_binary, &root, SETUP_BOUND)
            .await
            .map_err(|e| anyhow::anyhow!("the execute worker's build handshake: {e}"))?;
        let cache = match &opts.cache_dir {
            Some(d) => d.clone(),
            None => dirs::home_dir().context("no home directory: pass --cache-dir")?.join(".zkminer").join("simulate"),
        };
        // Absolute: the store and every derived broker configuration name paths the sandboxed
        // processes (which run in `/`) must find.
        let cache = std::path::absolute(&cache).with_context(|| format!("{}", cache.display()))?;
        let work = cache.join("witness-runs").join(format!("{}-{}", std::process::id(), chrono::Utc::now().timestamp_millis()));
        std::fs::create_dir_all(work.join("store")).with_context(|| format!("creating {}", work.display()))?;
        let store_dir = work.join("store");
        let chain_id = config.chain.chain_id;
        let id = Store::init(
            &store_dir,
            &StoreIdentityInit { chain_id, router, prover, require_dedicated_mount: false, allow_any_filesystem: true },
        )
        .map_err(|e| anyhow::anyhow!("a throwaway retention store at {}: {e}", store_dir.display()))?;
        let store = Store::open(
            &store_dir,
            &ExpectedIdentity { chain_id, router, prover, store_uuid: id.store_uuid },
            StoreOptions {
                quota_bytes: STORE_QUOTA_BYTES,
                quota_inodes: 100_000,
                free_space_floor_bytes: 0,
                require_dedicated_mount: false,
                allow_any_filesystem: true,
            },
        )
        .map_err(|e| anyhow::anyhow!("opening the throwaway retention store: {e}"))?;
        Ok(SimHost {
            spawner,
            root,
            builder_binary,
            execute_binary,
            broker_binary,
            broker_memory: config.broker.as_ref().map_or(1 << 30, |b| b.memory_bytes),
            execute_build,
            work,
            store: Arc::new(store),
        })
    }

    /// A broker on `broker_config`, after its self-test (and the connector's) passed.
    async fn broker(&self, config: &ZkMinerConfig, broker_config: &Path) -> Result<BrokerProcess> {
        let b = BrokerProcess::start(&self.spawner, &self.broker_binary, broker_config, &self.root, self.broker_memory, config)
            .with_context(|| format!("starting the broker on {}", broker_config.display()))?;
        let r = tokio::time::timeout(SETUP_BOUND, zkminer_witness_host::broker_proc::self_test(&b.client, &b.connector))
            .await
            .context("the broker self-test did not finish")?
            .map_err(|e| anyhow::anyhow!("the broker self-test: {e}"))?;
        if !r.ok {
            let failed: Vec<String> = r.checks.iter().filter(|(_, ok)| !ok).map(|(c, _)| format!("{c:?}")).collect();
            bail!("the broker self-test failed: {}", failed.join(", "));
        }
        Ok(b)
    }

    /// A pipeline context on `broker`. Its `image_id_fn` names nothing; [`hooks_and_context`] sets the
    /// real one.
    fn context(
        &self,
        broker: &BrokerProcess,
        config: &ZkMinerConfig,
        po2s: Vec<u8>,
        keccak_po2: u8,
        sys_rand_key: [u8; 32],
        execute_timeout: Duration,
    ) -> HostContext {
        let w = &config.witness;
        let image_id_fn: ImageIdFn = Arc::new(|_: &[u8]| None);
        HostContext {
            spawner: self.spawner.clone(),
            broker: broker.client.clone(),
            store: self.store.clone(),
            cgroup_root: self.root.clone(),
            builder_binary: self.builder_binary.clone(),
            execute_binary: self.execute_binary.clone(),
            host_maxima: host_maxima(w, w.max_guest_cycles.unwrap_or(MAX_HOST_GUEST_CYCLES)),
            po2s,
            keccak_po2,
            sys_rand_key,
            worker_builds: vec![self.execute_build.clone()],
            execute_build: self.execute_build.clone(),
            execute_memory_bytes: w.execute_memory_bytes,
            execute_timeout,
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
            image_id_fn,
            eviction_value: eviction_by_age(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The hooks.

/// The pipeline's hooks for a job that is not on chain: no chain gates (they are `notChecked`), every
/// artifact charge admitted and recorded, the ELF from the ProgramRegistry when no `--elf` is given.
struct SimHooks {
    token: AbortToken,
    charges: Mutex<Vec<ArtifactCharge>>,
    client: Option<ChainClient>,
    program_id: B256,
    /// The ELF the run executes: `--elf`'s, or what [`PipelineHooks::guest_elf`] fetched.
    fetched_elf: Arc<Mutex<Option<Vec<u8>>>>,
}

impl PipelineHooks for SimHooks {
    fn claimable(&self) -> HookFuture<'_, Result<(), SkipReason>> {
        Box::pin(async { Ok(()) })
    }

    fn admit_artifact_charge(&self, charge: ArtifactCharge) -> HookFuture<'_, bool> {
        self.charges.lock().unwrap_or_else(|p| p.into_inner()).push(charge);
        Box::pin(async { true })
    }

    fn abort_token(&self) -> &AbortToken {
        &self.token
    }

    /// The miner's ELF path: the registry entry, then the bytes its `elf_hash` names from any URI
    /// that serves them, else the first URI that answers (`download_elf`, guarded). Its image id is
    /// checked by the execute worker.
    fn guest_elf(&self) -> HookFuture<'_, Result<Vec<u8>, (SkipReason, String)>> {
        Box::pin(async move {
            let Some(client) = &self.client else {
                return Err((SkipReason::ElfUnavailable, "no --elf, and no chain client to read the ProgramRegistry".into()));
            };
            let fetch = async {
                let info = client.get_program_info(self.program_id).await.map_err(|e| format!("the ProgramRegistry: {e:#}"))?;
                zkminer_chain::programs::download_elf(client.elf_fetcher(), &info.storage_uris, info.elf_hash)
                    .await
                    .map_err(|e| format!("{e:#}"))
            };
            let elf = match tokio::time::timeout(ELF_FETCH_BOUND, fetch).await {
                Ok(Ok(elf)) => elf,
                Ok(Err(e)) => return Err((SkipReason::ElfUnavailable, redact_urls(&e))),
                Err(_) => return Err((SkipReason::ElfUnavailable, "the ELF fetch timed out".into())),
            };
            *self.fetched_elf.lock().unwrap_or_else(|p| p.into_inner()) = Some(elf.clone());
            Ok(elf)
        })
    }
}

// ---------------------------------------------------------------------------------------------
// The run.

/// The two providers of a differential run: `--providers`, else the first two `[[evm_rpc]]` entries
/// of `broker_config` that serve the job's first `evm-rpc/v1` chain. `Err` says why there are not
/// two.
fn pick_providers(broker_config: &toml::Value, chain: Option<u64>, asked: Option<&[String]>) -> Result<[String; 2], String> {
    let entries = broker_config.get("evm_rpc").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let alias = |e: &toml::Value| e.get("alias").and_then(|a| a.as_str()).map(str::to_string);
    if let Some(asked) = asked {
        if asked.len() != 2 || asked[0] == asked[1] {
            return Err("--providers names exactly two different aliases".into());
        }
        for a in asked {
            if !entries.iter().any(|e| alias(e).as_deref() == Some(a.as_str())) {
                return Err(format!("no [[evm_rpc]] entry {a:?} in the broker configuration"));
            }
        }
        return Ok([asked[0].clone(), asked[1].clone()]);
    }
    let Some(chain) = chain else {
        return Err("the job declares no evm-rpc/v1 capability".into());
    };
    let serving: Vec<String> = entries
        .iter()
        .filter(|e| e.get("chain_id").and_then(|c| c.as_integer()) == Some(chain as i64))
        .filter_map(alias)
        .collect();
    match serving.as_slice() {
        [a, b, ..] => Ok([a.clone(), b.clone()]),
        _ => Err(format!("the broker configuration has {} evm-rpc endpoint(s) for chain {chain}: a differential run needs two", serving.len())),
    }
}

/// `broker_config` with only the `[[evm_rpc]]` entry `alias`, and a spool directory of its own.
fn single_provider_config(broker_config: &toml::Value, alias: &str, spool: &Path) -> Result<String> {
    let mut v = broker_config.clone();
    let t = v.as_table_mut().context("the broker configuration is not a table")?;
    let kept: Vec<toml::Value> = t
        .get("evm_rpc")
        .and_then(|e| e.as_array())
        .map(|a| a.iter().filter(|e| e.get("alias").and_then(|x| x.as_str()) == Some(alias)).cloned().collect())
        .unwrap_or_default();
    t.insert("evm_rpc".into(), toml::Value::Array(kept));
    t.insert("spool_dir".into(), toml::Value::String(spool.display().to_string()));
    Ok(toml::to_string(&v)?)
}

/// Fills `r` from a published simulation.
fn fill_success(r: &mut WitnessReport, s: &Simulated, d: &JobDescriptor, declared: &Limits, host_max_cycles: u64, charges: Vec<(u64, u32)>) {
    let b = &s.builder;
    r.builder = Some(BuilderReport {
        artifact_origin: match b.artifact_origin {
            ArtifactOrigin::Local => "local".into(),
            ArtifactOrigin::Mirror => "mirror".into(),
            ArtifactOrigin::HemiCode { manifest } => format!("hemi-code:{manifest}"),
        },
        artifact_bytes: b.artifact_bytes,
        artifact_cached: b.artifact_cached,
        artifact_charges: charges,
        fetches: b.fetches,
        fetch_bytes: b.fetch_bytes,
        fuel_used: b.fuel_used,
        compile_ms: b.compile_ms,
        run_ms: b.run_ms,
        wall_ms: b.wall.as_millis() as u64,
        memory_peak_bytes: b.memory_peak,
    });
    r.witness = Some(WitnessFacts { bytes: s.w_len, sha256: s.w_sha256, input_sha256: s.input_sha256, prefix: s.prefix });
    r.per_po2 = s
        .per_po2
        .iter()
        .map(|p| Po2Report { po2: p.po2, cycles: p.cycles.to_string(), segment_bytes: p.segment_bytes, peak_host_bytes: p.peak_host_bytes })
        .collect();
    r.cycles = Some(CyclesReport {
        declared_max_guest_cycles: declared.maxGuestCycles.to_string(),
        measured: s.per_po2.iter().map(|p| p.cycles).max().map(|c| c.to_string()),
        host_max_guest_cycles: host_max_cycles.to_string(),
    });
    let statement = if s.prefix { &s.journal[PREFIX_BYTES.min(s.journal.len())..] } else { &s.journal[..] };
    let report = check_binding(&CheckInput {
        journal_fields: d.journalFields,
        expected_journal_hash: Some(d.expectedJournalHash),
        proof_system_id: d.proofSystemId,
        program_id: d.programId,
        statement,
        header_bytes: None,
        words: &[],
    });
    r.journal = Some(JournalReport {
        bytes: s.journal.len(),
        hex: format!("0x{}", alloy::hex::encode(&s.journal)),
        sha256: B256::from(zkminer_witness::manifest::sha256(&s.journal)),
        keccak256: keccak256(&s.journal),
        pinned_hex: report
            .pinned
            .iter()
            .map(|p| format!("0x{}", alloy::hex::encode(&statement[p.start..p.end])))
            .collect(),
    });
    r.binding = Some(report);
    let t = &s.timings;
    r.timings = Some(Timings {
        static_gates_ms: t.static_gates.as_millis() as u64,
        artifact_ms: t.artifact.as_millis() as u64,
        builder_ms: t.builder.as_millis() as u64,
        execute_ms: t.execute.as_millis() as u64,
        publish_ms: t.publish.as_millis() as u64,
        total_ms: t.total.as_millis() as u64,
    });
}

/// The exact `fulfillJobHashed` this job's fulfil would send (a placeholder seal of a Groth16
/// seal's length), its DA estimate by the chain's `GasPriceOracle` when the configured RPC answers,
/// else the RPC-free upper bound.
async fn fulfil_report(client: Option<&ChainClient>, chain_id: u64, router: Address, job_id: B256, d: &JobDescriptor, journal: &[u8]) -> FulfilReport {
    let fulfil = HashedFulfil::from_descriptor(d);
    let seal = SealSpec::risc0_groth16();
    let calldata = fulfill_job_hashed_calldata(job_id, &fulfil, journal, &seal.bytes());
    let calldata_bytes = calldata.len();
    let tx_len = conservative_fulfil_tx(chain_id, router, calldata).len();
    let (estimated, source) = match client {
        Some(c) => match tokio::time::timeout(Duration::from_secs(30), estimate_fulfil_da_bytes(c, job_id, &fulfil, journal, &seal)).await {
            Ok(Ok(e)) => (e.estimated_bytes, "GasPriceOracle".to_string()),
            Ok(Err(e)) => (da_bytes_upper_bound(tx_len), format!("upper bound (GasPriceOracle failed: {})", redact_urls(&format!("{e:#}")))),
            Err(_) => (da_bytes_upper_bound(tx_len), "upper bound (GasPriceOracle timed out)".into()),
        },
        None => (da_bytes_upper_bound(tx_len), "upper bound (no chain RPC)".into()),
    };
    FulfilReport {
        calldata_bytes,
        estimated_da_bytes: estimated,
        estimate_source: source,
        large: estimated > STANDARD_FULFIL_DA_BYTES,
        within_default_cap: estimated <= DEFAULT_FULFIL_DA_CAP_BYTES,
        default_cap_bytes: DEFAULT_FULFIL_DA_CAP_BYTES,
        gas: fulfill_gas_formula(0, calldata_bytes, journal.len()),
    }
}

/// The verdict of an adversarial run.
fn adversarial_verdict(mutations: &[MutationResult], host: &[HostInputResult], diff: &DifferentialReport) -> &'static str {
    let failed = mutations.iter().any(|m| m.outcome.is_soundness_failure()) || host.iter().any(|h| h.dependent) || diff.soundness_failure;
    let incomplete = mutations.iter().any(|m| matches!(m.outcome, MutationOutcome::NotRun | MutationOutcome::Inconclusive { .. }))
        || host.iter().any(|h| !h.ran)
        || diff.runs.len() < 2
        || diff.runs.iter().any(|r| r.outcome != "simulated");
    if failed {
        "fail"
    } else if incomplete {
        "incomplete"
    } else {
        "pass"
    }
}

fn counts(m: &[MutationResult]) -> MutationCounts {
    let mut c = MutationCounts { total: m.len(), ..Default::default() };
    for r in m {
        match r.outcome {
            MutationOutcome::RejectedInGuest { .. } => c.rejected_in_guest += 1,
            MutationOutcome::IdenticalJournal => c.identical_journal += 1,
            MutationOutcome::BindingRejects { .. } => c.binding_rejects += 1,
            MutationOutcome::SoundnessFailure { .. } => c.soundness_failures += 1,
            MutationOutcome::Inconclusive { .. } => c.inconclusive += 1,
            MutationOutcome::NotRun => c.not_run += 1,
        }
    }
    c
}

/// Everything one simulation needs, gathered before any process starts.
struct Prepared {
    config: ZkMinerConfig,
    secret: PathBuf,
    descriptor: JobDescriptor,
    descriptor_hash: B256,
    job_id: B256,
    prover: Address,
    caller: Address,
    router: Address,
    builder: Option<Vec<u8>>,
    elf: Option<Vec<u8>>,
    broker_config: PathBuf,
}

fn prepare(config_path: Option<&Path>, opts: &WitnessSimOptions) -> Result<Prepared> {
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_network()?;
    if let Some(banner) = config.dev_mode_banner() {
        tracing::warn!("{banner}");
    }
    if config.wallet.key_source == "env" {
        // No key is used; none must reach a sandbox either.
        std::env::remove_var(&config.wallet.key_env_var);
    }
    let file = DescriptorFile::load(&opts.descriptor)?;
    let descriptor = file.descriptor();
    let descriptor_hash = zkminer_chain::descriptor::compute_descriptor_hash(&descriptor);
    let router: Address = config
        .contracts
        .hemi_prove
        .parse()
        .with_context(|| format!("contracts.hemi_prove {:?} is not an address", config.contracts.hemi_prove))?;
    let read = |p: &Option<PathBuf>| -> Result<Option<Vec<u8>>> {
        p.as_ref().map(|p| std::fs::read(p).with_context(|| format!("reading {}", p.display()))).transpose()
    };
    let broker_config = match (&opts.broker_config, &config.broker) {
        (Some(p), _) => p.clone(),
        (None, Some(b)) => b.config.clone(),
        (None, None) => bail!("no broker configuration: pass --broker-config, or set [broker] config"),
    };
    // The self-test proves no sandbox can read a file outside its grants: the configuration when
    // there is one, else the descriptor file.
    let config_file = config_path.map(PathBuf::from).unwrap_or_else(ZkMinerConfig::default_path);
    let secret = if config_file.is_file() { config_file } else { opts.descriptor.clone() };
    // Absolute: the probes run in `/`.
    let secret = std::path::absolute(&secret).with_context(|| format!("{}", secret.display()))?;
    Ok(Prepared {
        job_id: file.job_id_or_default(),
        caller: file.caller.unwrap_or(Address::ZERO),
        prover: opts.prover.or(config.witness.prover_address).unwrap_or(Address::ZERO),
        builder: read(&opts.builder)?,
        elf: read(&opts.elf)?,
        config,
        secret,
        descriptor,
        descriptor_hash,
        router,
        broker_config,
    })
}

/// Runs the pipeline once on `ctx` for the prepared job.
async fn run_pipeline(p: &Prepared, ctx: &HostContext, hooks: &SimHooks, current_block: u64) -> Result<Simulated, Skip> {
    let job = JobInput {
        job_id: p.job_id,
        descriptor: &p.descriptor,
        descriptor_hash: p.descriptor_hash,
        submit_tx_hash: B256::ZERO,
        caller: p.caller,
        prover: p.prover,
        chain_id: p.config.chain.chain_id,
        router: p.router,
        elf: p.elf.as_deref(),
        artifact: p.builder.as_deref(),
        current_block,
    };
    simulate_witness_job(ctx, &job, hooks).await
}

/// The pipeline's hooks and its context for one broker: the retention check names `programId` for
/// exactly the ELF bytes the run executed, `--elf`'s or the ones the hook fetched (one slot, shared).
#[allow(clippy::too_many_arguments)]
fn hooks_and_context(
    p: &Prepared,
    host: &SimHost,
    broker: &BrokerProcess,
    client: Option<ChainClient>,
    token: &AbortToken,
    po2s: Vec<u8>,
    keccak_po2: u8,
    sys_rand_key: [u8; 32],
    execute_timeout: Duration,
) -> (SimHooks, HostContext) {
    let slot = Arc::new(Mutex::new(p.elf.clone()));
    let hooks = SimHooks {
        token: token.clone(),
        charges: Mutex::new(Vec::new()),
        client,
        program_id: p.descriptor.programId,
        fetched_elf: slot.clone(),
    };
    let mut ctx = host.context(broker, &p.config, po2s, keccak_po2, sys_rand_key, execute_timeout);
    let id = p.descriptor.programId;
    ctx.image_id_fn = Arc::new(move |b: &[u8]| {
        slot.lock().unwrap_or_else(|e| e.into_inner()).as_deref().filter(|e| *e == b).map(|_| id)
    });
    (hooks, ctx)
}

/// `zkminer simulate --descriptor`.
pub async fn run(config_path: Option<&Path>, opts: WitnessSimOptions) -> Result<()> {
    let p = prepare(config_path, &opts)?;
    // The chain is read for the fulfil's DA estimate and, without `--elf`, the ProgramRegistry.
    let client = match ChainClient::new_watch_only(&p.config, p.prover).await {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(
                "simulate: no chain client ({}): the fulfil's DA size is an upper bound{}",
                redact_urls(&format!("{e:#}")),
                if p.elf.is_none() { ", and the ELF cannot be read from the ProgramRegistry" } else { "" }
            );
            None
        }
    };
    let current_block = match &client {
        Some(c) => c.get_block_number().await.unwrap_or(0),
        None => 0,
    };
    let host = SimHost::start(&p.config, &p.secret, &opts, p.router, p.prover).await?;
    let sys_rand_key: [u8; 32] = rand::random();
    let token = AbortToken::new();
    {
        let t = token.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                t.abort(AbortReason::Shutdown);
            }
        });
    }
    let w = &p.config.witness;
    let host_max_cycles = w.max_guest_cycles.unwrap_or(MAX_HOST_GUEST_CYCLES);
    let mut report = WitnessReport {
        schema: WITNESS_REPORT_SCHEMA,
        kind: "witness",
        job_id: p.job_id,
        descriptor_hash: p.descriptor_hash,
        program_id: p.descriptor.programId,
        prover: p.prover,
        caller: p.caller,
        chain_id: p.config.chain.chain_id,
        router: p.router,
        outcome: "skipped",
        verdict: None,
        po2s: opts.po2s.clone(),
        keccak_po2: opts.keccak_po2,
        sys_rand_key_fingerprint: key_fingerprint(&sys_rand_key),
        execute_build: host.execute_build.clone(),
        builder: None,
        witness: None,
        per_po2: Vec::new(),
        cycles: None,
        journal: None,
        binding: None,
        fulfil: None,
        admission: admission_parameters(&p.config, &host_maxima(w, host_max_cycles)),
        timings: None,
        not_checked: NOT_CHECKED.to_vec(),
        adversarial: None,
        zkminer_version: env!("CARGO_PKG_VERSION"),
        protocol_version: zkminer_prover_protocol::PROTOCOL_VERSION,
    };

    let broker = host.broker(&p.config, &p.broker_config).await?;
    let (hooks, ctx) = hooks_and_context(
        &p,
        &host,
        &broker,
        client.clone(),
        &token,
        opts.po2s.clone(),
        opts.keccak_po2,
        sys_rand_key,
        opts.execute_timeout,
    );
    let result = run_pipeline(&p, &ctx, &hooks, current_block).await;
    let declared = decode(&p.descriptor.inputData).map(|e| e.job.limits).ok();
    let simulated = match result {
        Ok(s) => {
            report.outcome = "simulated";
            let charges = hooks.charges.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|c| (c.length, c.chunks)).collect();
            if let Some(declared) = &declared {
                fill_success(&mut report, &s, &p.descriptor, declared, host_max_cycles, charges);
            }
            report.fulfil =
                Some(fulfil_report(client.as_ref(), p.config.chain.chain_id, p.router, p.job_id, &p.descriptor, &s.journal).await);
            Some(s)
        }
        Err(skip) => {
            report.outcome = if matches!(skip, Skip::Aborted { .. }) { "aborted" } else { "skipped" };
            report.verdict = verdict_report(&skip);
            None
        }
    };

    if let (Some(adv), Some(s)) = (&opts.adversarial, &simulated) {
        let elf = hooks.fetched_elf.lock().unwrap_or_else(|e| e.into_inner()).clone();
        match elf {
            Some(elf) => {
                let a = Adversary { p: &p, host: &host, ctx: &ctx, token: &token, opts: &opts, client: client.as_ref(), current_block };
                report.adversarial = Some(a.run(adv, s, &elf, sys_rand_key).await?);
            }
            None => bail!("the ELF bytes the simulation executed were not kept"),
        }
    }
    drop(broker);

    let text = serde_json::to_string_pretty(&report)?;
    match &opts.out {
        Some(path) => std::fs::write(path, text + "\n").with_context(|| format!("writing {}", path.display()))?,
        None => println!("{text}"),
    }
    drop(host);
    if report.outcome != "simulated" {
        let v = report.verdict.as_ref().map(|v| format!("{:?} at {}", v.reason, v.step)).unwrap_or_else(|| report.outcome.into());
        bail!("a miner with this configuration would skip this job: {v}");
    }
    if let Some(a) = &report.adversarial {
        if a.verdict != "pass" {
            bail!("the adversarial run's verdict is {}", a.verdict);
        }
    }
    Ok(())
}

/// The scheme mutators this build knows, by scheme id: scheme 1 (`eth-block`), from the reference
/// prelude's witness codec.
pub fn scheme_registry() -> SchemeRegistry {
    zkminer_witness_host::adversarial::default_registry()
}

/// One adversarial run's shared state.
struct Adversary<'a> {
    p: &'a Prepared,
    host: &'a SimHost,
    ctx: &'a HostContext,
    token: &'a AbortToken,
    opts: &'a WitnessSimOptions,
    client: Option<&'a ChainClient>,
    current_block: u64,
}

impl Adversary<'_> {
    async fn run(&self, adv: &AdversarialOptions, s: &Simulated, elf: &[u8], sys_rand_key: [u8; 32]) -> Result<AdversarialReport> {
        let started = Instant::now();
        let deadline = started + adv.budget;
        let p = self.p;
        // W as the bundle holds it: the bytes every attack starts from.
        let w = {
            let (store, bundle) = (self.host.store.clone(), s.bundle);
            tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                use std::io::Read;
                let mut f = store.open_w(&bundle).map_err(|e| anyhow::anyhow!("reading W back: {e}"))?;
                let mut w = Vec::new();
                f.read_to_end(&mut w)?;
                Ok(w)
            })
            .await??
        };
        anyhow::ensure!(
            B256::from(zkminer_witness::manifest::sha256(&w)) == s.w_sha256,
            "the W read back is not the W the bundle records"
        );
        let prefix = guest_input_prefix(p.descriptor.journalFields, p.job_id, p.prover);
        let statement = if prefix.is_some() { &s.journal[PREFIX_BYTES.min(s.journal.len())..] } else { &s.journal[..] };
        let seed = seed_for(&w, 0x7a6b_6d69_6e65_7231);

        // The mutations: the scheme's structured ones first (they say the most), then the generic.
        let mut mutations = Vec::new();
        let registry = scheme_registry();
        let scheme_id = adv.scheme.or_else(|| scheme_id_of(statement));
        let scheme = match scheme_id {
            None => SchemeReport { id: None, name: None, status: "no scheme id in the header (pass --scheme)".into() },
            Some(id) => match registry.get(id) {
                None => SchemeReport { id: Some(id), name: None, status: "no structured mutations registered for this scheme".into() },
                Some(m) => {
                    // What the scheme needs from outside W (a parent header), through the job's own
                    // evm-rpc source, as a builder's fetches go.
                    let answers = match m.requests(&w) {
                        Ok(calls) if !calls.is_empty() => self.scheme_answers(&calls).await,
                        _ => Vec::new(),
                    };
                    let fetched = answers.iter().filter(|a| a.is_some()).count();
                    match m.mutations(&w, &SchemeContext { statement, seed, answers: &answers }, SCHEME_MUTATIONS) {
                        Ok(ms) => {
                            let n = ms.len();
                            mutations.extend(ms);
                            SchemeReport {
                                id: Some(id),
                                name: Some(m.name().into()),
                                status: format!("{n} structured mutations ({fetched} of {} fetched answers used)", answers.len()),
                            }
                        }
                        Err(e) => SchemeReport { id: Some(id), name: Some(m.name().into()), status: e },
                    }
                }
            },
        };
        // The generic ones keep at least a quarter of the room, so neither kind crowds the other out.
        let max = adv.max_mutations.min(MAX_MUTATIONS);
        let generic = generic_mutations(&w, seed, adv.flips);
        mutations.truncate(max.saturating_sub(generic.len().min(max / 4)));
        mutations.extend(generic);
        let mut seen = std::collections::HashSet::new();
        mutations.retain(|m| seen.insert(m.w.clone()));
        mutations.truncate(max);
        let judge = Judge { descriptor: &p.descriptor, job_id: p.job_id, prover: p.prover, baseline_journal: &s.journal };
        let baseline = Baseline {
            ctx: self.ctx,
            token: self.token,
            elf,
            judge,
            prefix,
            w: &w,
            po2: *self.opts.po2s.first().expect("a po2"),
            keccak_po2: self.opts.keccak_po2,
            sys_rand_key,
            max_cycles: s.limits.maxGuestCycles,
        };
        let results = run_mutations(&baseline, mutations, deadline).await;
        let host_inputs = host_input_checks(&baseline, rand::random(), deadline).await;
        let differential = self.differential(adv, s, deadline).await;

        let mut failures = Vec::new();
        for m in &results {
            if let MutationOutcome::SoundnessFailure { first_difference, .. } = &m.outcome {
                failures.push(format!(
                    "mutation {} ({}): the journal changed at byte {first_difference} and still satisfies the binding",
                    m.id, m.description
                ));
            }
        }
        for h in &host_inputs {
            if h.dependent {
                failures.push(format!(
                    "host input {:?}: the journal depends on it ({} vs {}), a value the prover controls",
                    h.input, h.values[0], h.values[1]
                ));
            }
        }
        if differential.soundness_failure {
            failures.push("differential: two providers gave different journals that both satisfy the binding".into());
        }
        let mut notes = Vec::new();
        if results.iter().any(|m| m.kind == "append" && m.outcome == MutationOutcome::IdenticalJournal) {
            notes.push(
                "the guest accepted W with trailing bytes and committed the same journal: sound, but a prelude's \
                 finish() asserting W was consumed in full (plan §8.3) would refuse it"
                    .to_string(),
            );
        }
        let verdict = adversarial_verdict(&results, &host_inputs, &differential).to_string();
        Ok(AdversarialReport {
            verdict,
            budget_secs: adv.budget.as_secs(),
            elapsed_secs: started.elapsed().as_secs_f64(),
            run_seed: format!("{seed:#018x}"),
            scheme,
            framings: framings(&w).iter().map(|f| format!("{} ({} items)", f.name, f.items.len())).collect(),
            counts: counts(&results),
            mutations: results,
            host_inputs,
            differential,
            soundness_failures: failures,
            notes,
        })
    }

    /// The answers to a scheme's calls, through the job's first `evm-rpc/v1` capability.
    async fn scheme_answers(&self, calls: &[RpcCall]) -> Vec<Option<serde_json::Value>> {
        let Ok(env) = decode(&self.p.descriptor.inputData) else { return vec![None; calls.len()] };
        let Some(cap) = env.capabilities.iter().position(|c| matches!(c, CapabilityKind::EvmRpcV1 { .. })) else {
            return vec![None; calls.len()];
        };
        let sources = env.job.sources.iter().map(|c| (c.class, c.config.to_vec())).collect();
        fetch_through_job(&self.ctx.broker, self.p.caller, sources, cap as u32, calls).await
    }

    /// The whole pipeline against each of two providers (one po2: the journals are compared, not the
    /// po2s), each from a broker configuration holding only that provider.
    async fn differential(&self, adv: &AdversarialOptions, s: &Simulated, deadline: Instant) -> DifferentialReport {
        let p = self.p;
        let mut report = DifferentialReport { runs: Vec::new(), w_same: None, journal_same: None, soundness_failure: false, note: None };
        let parsed = std::fs::read_to_string(&p.broker_config)
            .map_err(|e| e.to_string())
            .and_then(|t| toml::from_str::<toml::Value>(&t).map_err(|e| e.to_string()));
        let parsed = match parsed {
            Ok(v) => v,
            Err(e) => {
                report.note = Some(format!("the broker configuration could not be read: {e}"));
                return report;
            }
        };
        let chain = decode(&p.descriptor.inputData).ok().and_then(|e| {
            e.capabilities.iter().find_map(|c| match c {
                CapabilityKind::EvmRpcV1 { chain_id, .. } => Some(*chain_id),
                _ => None,
            })
        });
        let providers = match pick_providers(&parsed, chain, adv.providers.as_deref()) {
            Ok(v) => v,
            Err(e) => {
                report.note = Some(format!("not run: {e}"));
                return report;
            }
        };
        let mut outcomes: Vec<Option<(B256, Vec<u8>, bool)>> = Vec::new();
        for alias in providers {
            let mut run = ProviderRun { alias: alias.clone(), outcome: "not_run".into(), verdict: None, w_sha256: None, journal_sha256: None };
            if Instant::now() >= deadline || self.token.reason().is_some() {
                report.runs.push(run);
                outcomes.push(None);
                continue;
            }
            let attempt = async {
                let dir = self.host.work.join(format!("provider-{}", report.runs.len()));
                std::fs::create_dir_all(dir.join("spool"))?;
                let path = dir.join("broker.toml");
                std::fs::write(&path, single_provider_config(&parsed, &alias, &dir.join("spool"))?)?;
                let broker = self.host.broker(&p.config, &path).await?;
                let (hooks, ctx) = hooks_and_context(
                    p,
                    self.host,
                    &broker,
                    self.client.cloned(),
                    self.token,
                    vec![*self.opts.po2s.first().expect("a po2")],
                    self.opts.keccak_po2,
                    self.ctx.sys_rand_key,
                    self.opts.execute_timeout,
                );
                let remaining = deadline.saturating_duration_since(Instant::now());
                let r = tokio::time::timeout(remaining, run_pipeline(p, &ctx, &hooks, self.current_block)).await;
                drop(broker);
                Ok::<_, anyhow::Error>(r)
            };
            match attempt.await {
                Ok(Ok(Ok(sim))) => {
                    run.outcome = "simulated".into();
                    run.w_sha256 = Some(sim.w_sha256);
                    run.journal_sha256 = Some(B256::from(zkminer_witness::manifest::sha256(&sim.journal)));
                    outcomes.push(Some((sim.w_sha256, sim.journal.clone(), true)));
                }
                Ok(Ok(Err(skip))) => {
                    run.outcome = "skipped".into();
                    run.verdict = verdict_report(&skip);
                    outcomes.push(None);
                }
                Ok(Err(_)) => {
                    run.outcome = "not_run".into();
                    report.note = Some("the run's time ran out during a provider run".into());
                    outcomes.push(None);
                }
                Err(e) => {
                    run.outcome = "not_run".into();
                    report.note = Some(format!("a provider run could not start: {}", redact_urls(&format!("{e:#}"))));
                    outcomes.push(None);
                }
            }
            report.runs.push(run);
        }
        if let [Some(a), Some(b)] = outcomes.as_slice() {
            report.w_same = Some(a.0 == b.0);
            report.journal_same = Some(a.1 == b.1);
            // Both published bundles satisfied the binding (the pipeline checks it before publishing).
            report.soundness_failure = a.1 != b.1;
        }
        // The baseline journal against the provider runs, for the report's reader.
        if report.journal_same == Some(true) {
            if let Some(Some(a)) = outcomes.first() {
                if a.1 != s.journal {
                    report.note = Some("both providers agree, but not with the main run's journal".into());
                }
            }
        }
        report
    }
}
