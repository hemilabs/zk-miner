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
//! verified by the store; then the claim gate's DA check, the exact fulfil against `[witness]
//! fulfil_da_cap_bytes`. The limits are the miner's (`pipeline::host_maxima` of this configuration's
//! `[witness]`, the artifact budget `manifest::ArtifactBudget`), and so are the sandbox and broker
//! self-tests, which must pass first. So a simulation cannot pass where a miner with this
//! configuration would refuse; it can only check less: what depends on the chain (the claimability
//! `eth_call`, the submission form, the deployment pins, admission, the reservation, the DA backlog,
//! the deadline margin, prove resources), what `--builder` and `--elf` replace, and a guest-cycle
//! maximum a miner derives from its own cards are listed under `notChecked`.
//!
//! What differs, deliberately: the retention store is a throwaway one under the cache directory (on
//! a real filesystem: the store refuses tmpfs), removed at the end, and so is the broker's spool
//! (never a running miner's); the guest ELF's image id is checked by the execute worker (an ELF
//! that is not the job's program skips at the execute step, `ElfImageIdMismatch`, where the miner's
//! measure worker would skip it before the builder ran). The `sys_rand` seed is the public rule's,
//! as a miner's.
//!
//! **Outputs (§16):** fuel, fetches, bytes, the builder's peak memory, `|W|`, cycles in the
//! `maxGuestCycles` unit and the journal per po2, the pinned bytes and the binding's mutation check,
//! the estimated fulfil DA size, and this host's admission parameters; one JSON document.
//!
//! **`--adversarial`** (see `zkminer_witness_host::adversarial`): first the binding's coverage, which
//! must pin the whole journal header `[0, H)` with a non-zero `expectedJournalHash` (`H` from a
//! scheme-1 `W`'s word count, or `--header-bytes`), else the verdict is `fail`; then re-execution
//! under two `sys_rand` seeds (the public rule's, which every run uses, and a random one), two po2s
//! and two keccak po2s; a differential run of the whole pipeline against two `evm-rpc` providers of
//! the broker configuration (`--providers`, default the first two serving the job's chain), each
//! from a broker configuration holding only that provider; and last the job's scheme's mutations of
//! `W` (by the scheme id in the journal header, or `--scheme`) and the generic ones, each with a
//! share of the time left. Every re-execution runs under the attack's cycle cap: this host's
//! configured maximum, else [`ATTACK_CYCLE_MULTIPLE`] × the job's `maxGuestCycles`. All within
//! `--adversarial-secs`, every execute and broker start bounded by what is left of it; anything not
//! run, a sweep that ran no mutation, and (unless the binding is FULL) one without structured
//! mutations make the verdict `incomplete`. A `W` above `--adversarial-max-w-bytes` is refused: the
//! mutations are made one at a time, but this process holds `W`, one changed `W` and what making it
//! takes: about 4 × `|W|` for the generic mutations, up to about 32 × `|W|` for a scheme-1 `W` of many
//! small trie nodes (its decoded proofs).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use alloy::primitives::{keccak256, Address, B256};
use anyhow::{bail, Context, Result};
use serde::Serialize;

use zkminer_chain::client::ChainClient;
use zkminer_chain::da::{
    conservative_fulfil_tx, da_bytes_upper_bound, estimate_fulfil_da_bytes, Backlog, DaCapPolicy, Decision, SealSpec,
    STANDARD_FULFIL_DA_BYTES,
};
use zkminer_chain::jobs::{fulfill_gas_formula, fulfill_job_hashed_calldata, HashedFulfil};
use zkminer_config::ZkMinerConfig;
use zkminer_contracts::bindings::JobDescriptor;
use zkminer_witness::binding::{guest_input_prefix, PREFIX_BYTES};
use zkminer_witness::envelope::{decode, CapabilityKind, Limits};
use zkminer_witness::manifest::ArtifactBudget;
use zkminer_witness::verdict::SkipReason;
use zkminer_witness_broker::client::ArtifactCharge;
use zkminer_witness_host::abort::{AbortReason, AbortToken};
use zkminer_witness_host::adversarial::{
    fetch_through_job, framings, generic_mutations, host_input_checks, run_mutations, scheme_id_of, seed_for, Baseline,
    CycleLimits, HostInputResult, Judge, Mutation, MutationOutcome, MutationResult, RpcCall, SchemeContext,
    SchemeRegistry,
};
use zkminer_witness_host::broker_proc::BrokerProcess;
use zkminer_witness_host::paths;
use zkminer_witness_host::pipeline::{
    eviction_by_age, execute_worker_build, host_maxima, po2_list, simulate_witness_job,
    ArtifactOrigin, CycleJudging, HookFuture, HostContext, ImageIdFn, JobInput, PipelineHooks,
    Simulated, Skip, DEFAULT_MAX_ARTIFACT_BYTES, MAX_HOST_GUEST_CYCLES,
};
use zkminer_witness_host::spawner::Spawner;
use zkminer_witness_store::{ExpectedIdentity, Store, StoreIdentityInit, StoreOptions};

use super::simulate::redact_urls;
use super::witness_tools::{check_binding, BindingReport, CheckInput, DescriptorFile};

/// The default `--adversarial-max-w-bytes`.
pub const DEFAULT_ADVERSARIAL_MAX_W_BYTES: u64 = 8 << 20;
/// Without a configured cycle maximum, the attack's cycle cap is this multiple of the job's
/// `maxGuestCycles`.
pub const ATTACK_CYCLE_MULTIPLE: u64 = 4;
/// A mutation's execute gets at least this many times the unchanged `W`'s execute at one po2...
const MUTATION_FLOOR_RUNS: u32 = 4;
/// ...and at least this long (a worker's start).
const MUTATION_FLOOR_MIN: Duration = Duration::from_secs(5);

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
    /// The largest `W` attacked (`--adversarial-max-w-bytes`).
    pub max_w_bytes: u64,
}

/// One descriptor-file simulation.
#[derive(Debug, Clone)]
pub struct WitnessSimOptions {
    pub descriptor: PathBuf,
    pub builder: Option<PathBuf>,
    pub elf: Option<PathBuf>,
    pub prover: Option<Address>,
    /// `--po2`: the sizes to execute at, each judged as a miner judges its cards' sizes. `None`:
    /// [`po2_plan`]'s.
    pub po2s: Option<Vec<u8>>,
    pub keccak_po2: u8,
    pub broker_config: Option<PathBuf>,
    pub execute_worker: Option<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub execute_timeout: Duration,
    pub out: Option<PathBuf>,
    /// This host's `maxGuestCycles` maximum (`--max-guest-cycles`), over `[witness]
    /// max_guest_cycles`.
    pub max_guest_cycles: Option<u64>,
    /// The journal header's length (`--header-bytes`), for a `W` of no registered scheme.
    pub header_bytes: Option<usize>,
    pub adversarial: Option<AdversarialOptions>,
}

// ---------------------------------------------------------------------------------------------
// The report.

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerdictReport {
    pub reason: SkipReason,
    /// `static_gates`, `artifact`, `builder`, `execute`, `binding`, `publish` (`Step::as_str`), or
    /// `claim_gate`.
    pub step: String,
    /// `never`, `once_jittered`, `backoff`, `on_host_change`, `deferred` (`Retry::as_str`).
    pub retry: String,
    /// `backoff`'s attempts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_max_attempts: Option<u8>,
    pub blames_caller: bool,
    pub detail: String,
}

impl VerdictReport {
    fn new(reason: SkipReason, step: &str, detail: &str) -> Self {
        let v = reason.verdict();
        VerdictReport {
            reason,
            step: step.to_string(),
            retry: v.retry.as_str().to_string(),
            retry_max_attempts: v.retry.max_attempts(),
            blames_caller: v.blames_caller,
            detail: redact_urls(detail),
        }
    }
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
    /// The guest's `sys_rand` calls past its runtime's own draw (any is refused: no proof binds the
    /// seed); `null` when no call was seen at all.
    pub sys_rand_draws: Option<u64>,
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
    /// Within this configuration's operator cap, `[witness] fulfil_da_cap_bytes` (§5.5): the claim
    /// gate skips the job otherwise (`FulfilDaTooLarge`).
    pub within_cap: bool,
    pub cap_bytes: u64,
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
    /// The maximum this run was judged by (`--max-guest-cycles`, `[witness] max_guest_cycles`, or
    /// 2^34 when neither names one).
    pub host_max_guest_cycles: String,
    /// Where `hostMaxGuestCycles` came from: `--max-guest-cycles`, `[witness] max_guest_cycles`, or
    /// `unset`: a miner without the setting derives its maximum from its cards and proving timeout
    /// (a CPU slot about 3M), which is not checked here.
    pub host_max_source: &'static str,
}

/// `maxGuestCycles` at each executed po2 (§7.1: judged over the po2s the prover may use).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CycleLimitReport {
    /// The job's `maxGuestCycles` (a decimal string).
    pub max_guest_cycles: String,
    /// The po2s the guest halted within it at, and those it went over it at.
    pub within_at: Vec<u8>,
    pub over_at: Vec<u8>,
    /// The po2s it is judged at, as a miner judges its cards' sizes: `--po2`'s, or this
    /// configuration's cards'. Empty when neither names one: a job over at some po2s only is then
    /// served by a miner whose cards prove at the others, and skipped by one proving at those.
    pub judged_at: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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
pub struct CoverageReport {
    /// The journal header's length `H`, and where it came from (`scheme <id> W`, `--header-bytes`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_source: Option<String>,
    /// `[0, H)` is pinned and `expectedJournalHash` is non-zero.
    pub ok: bool,
    /// FULL: the router hashes the whole journal, so a changed `W` gives the honest journal or one
    /// it refuses, whatever the guest does; a mutation this host could not run to a journal (its
    /// cycle maximum, the execute timeout) leaves nothing undecided.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub whole_journal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdversarialReport {
    /// `pass`, `fail` (a binding that leaves the header free, a soundness failure or a host-input
    /// dependence), or `incomplete` (something not run or inconclusive, or the run refused).
    pub verdict: String,
    /// Why nothing was attacked (`W` above `--adversarial-max-w-bytes`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
    /// The binding's coverage of the journal header, checked first.
    pub binding_coverage: CoverageReport,
    /// The sized-cycle cap every re-execution runs under (a decimal string), and where it came from:
    /// this host's maximum when one is configured, else a bounded multiple of the job's
    /// `maxGuestCycles`. Past it a run is inconclusive.
    pub attack_cycle_cap: String,
    pub attack_cycle_cap_source: String,
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
    /// The po2s executed, and where they came from: `--po2`, this configuration's cards, or every
    /// job size.
    pub po2s: Vec<u8>,
    pub po2_source: String,
    pub keccak_po2: u8,
    /// The `sys_rand` rule the executions were seeded by, as `zkminer simulate`'s other reports
    /// name it: a miner's own executions and proofs are seeded alike.
    pub sys_rand_rule: &'static str,
    pub execute_build: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder: Option<BuilderReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<WitnessFacts>,
    pub per_po2: Vec<Po2Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycles: Option<CyclesReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycle_limit: Option<CycleLimitReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal: Option<JournalReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<BindingReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfil: Option<FulfilReport>,
    pub admission: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timings: Option<Timings>,
    /// What this simulation did not check, and a miner would.
    pub not_checked: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adversarial: Option<AdversarialReport>,
    pub zkminer_version: &'static str,
    pub protocol_version: u32,
}

fn verdict_report(s: &Skip) -> Option<VerdictReport> {
    match s {
        Skip::Verdict { reason, step, detail } => Some(VerdictReport::new(*reason, step.as_str(), detail)),
        Skip::Aborted { .. } => None,
    }
}

/// What a descriptor-file simulation cannot check, the job not being on chain (§5.3, §5.2 step 7).
const NOT_CHECKED: [&str; 8] = [
    "claimability eth_call (exclusivity, bids, cooldown, pauses, stake)",
    "submission form",
    "deployment core pins",
    "admission (caller allowlist, lanes, credit)",
    "reservation against the price",
    "the DA backlog at claim time (above the hold level the fulfil must also fit the live cap; only the operator cap is checked)",
    "deadline margin and proving time",
    "prove resources (segment disk, host RAM, VRAM)",
];
/// With `--builder`: the artifact did not come the miner's way.
const NOT_CHECKED_BUILDER: &str =
    "builder availability via builderURIs or an operator mirror (--builder replaced the fetch)";
/// With `--elf`: the ELF did not come the miner's way.
const NOT_CHECKED_ELF: &str = "the ELF from the ProgramRegistry (--elf replaced the registry read and the download)";
/// Without a configured maximum: the miner's own is card-derived.
const NOT_CHECKED_CYCLES: &str =
    "guest cycles against a miner's own maximum, derived from its cards and proving timeout \
     (give --max-guest-cycles or [witness] max_guest_cycles)";

/// The parts of the report that depend on this host's configuration only.
fn admission_parameters(
    config: &ZkMinerConfig,
    maxima: &zkminer_witness::envelope::HostMaxima,
    cycles_source: &str,
) -> serde_json::Value {
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
        "maxGuestCyclesSource": cycles_source,
        "maxArtifactBytes": DEFAULT_MAX_ARTIFACT_BYTES,
        "maxArtifactChunks": ArtifactBudget::for_max_bytes(DEFAULT_MAX_ARTIFACT_BYTES).max_chunks,
        "note": "this configuration's values (the published defaults unless it overrides them), but maxGuestCycles \
                 when maxGuestCyclesSource is `unset`; other miners may differ"
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
    /// This run's `maxGuestCycles` maximum (see [`CyclesReport::host_max_source`]).
    max_guest_cycles: u64,
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
            max_guest_cycles: host_max_guest_cycles(config, opts).0,
        })
    }

    /// `broker_config` as this run's own, written into the work directory: `spool_dir` moved there
    /// (a simulation never shares a running miner's spool, its quota or its held-lock reserve), and
    /// with `alias` only that `[[evm_rpc]]` entry (a differential run's provider).
    fn own_broker_config(
        &self,
        broker_config: &BrokerToml,
        name: &str,
        alias: Option<&str>,
    ) -> Result<PathBuf> {
        let dir = self.work.join(name);
        std::fs::create_dir_all(dir.join("spool"))
            .with_context(|| format!("creating {}", dir.display()))?;
        let text = broker_config_for(
            &broker_config.value,
            &broker_config.dir,
            alias,
            &dir.join("spool"),
        )?;
        let path = dir.join("broker.toml");
        write_private(&path, &text)?;
        Ok(path)
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
        cycle_judging: CycleJudging,
        keccak_po2: u8,
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
            host_maxima: host_maxima(w, self.max_guest_cycles),
            po2s,
            cycle_judging,
            keccak_po2,
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
/// artifact charge recorded and held to the miner's per-job budget, the ELF from the ProgramRegistry
/// when no `--elf` is given.
struct SimHooks {
    token: AbortToken,
    charges: Mutex<Vec<ArtifactCharge>>,
    budget: ArtifactBudget,
    client: Option<ChainClient>,
    program_id: B256,
    /// The ELF the run executes: `--elf`'s, or what [`PipelineHooks::guest_elf`] fetched.
    fetched_elf: Arc<Mutex<Option<Vec<u8>>>>,
    /// Each executed po2 against `maxGuestCycles` ([`PipelineHooks::executed_po2`]).
    executed: Mutex<Vec<(u8, Option<u64>)>>,
}

impl PipelineHooks for SimHooks {
    fn claimable(&self) -> HookFuture<'_, Result<(), SkipReason>> {
        Box::pin(async { Ok(()) })
    }

    /// The miner's per-job artifact budget: a manifest of more chunks (or more bytes) than it admits
    /// is `NotAdmitted` there, deferred for ever.
    fn admit_artifact_charge(&self, charge: ArtifactCharge) -> HookFuture<'_, bool> {
        let ok = self.budget.admits(charge.length, charge.chunks);
        self.charges.lock().unwrap_or_else(|p| p.into_inner()).push(charge);
        Box::pin(async move { ok })
    }

    fn abort_token(&self) -> &AbortToken {
        &self.token
    }

    fn executed_po2(&self, po2: u8, cycles: Option<u64>) {
        self.executed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((po2, cycles));
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

/// `broker_config` with a spool directory of its own and, given `alias`, only that `[[evm_rpc]]`
/// entry. The copy is written elsewhere, so every relative `key_file` (which the broker reads from
/// the configuration's own directory) is made absolute against `dir`, the original's directory.
fn broker_config_for(
    broker_config: &toml::Value,
    dir: &Path,
    alias: Option<&str>,
    spool: &Path,
) -> Result<String> {
    let mut v = broker_config.clone();
    let t = v.as_table_mut().context("the broker configuration is not a table")?;
    let absolute = |entry: &mut toml::Value| {
        if let Some(k) = entry.get_mut("key_file") {
            if let Some(p) = k.as_str().map(Path::new).filter(|p| p.is_relative()) {
                *k = toml::Value::String(dir.join(p).display().to_string());
            }
        }
    };
    for table in ["evm_rpc", "blob_mirror"] {
        for entry in t
            .get_mut(table)
            .and_then(|e| e.as_array_mut())
            .into_iter()
            .flatten()
        {
            absolute(entry);
        }
    }
    if let Some(artifacts) = t.get_mut("artifacts") {
        absolute(artifacts);
        if let Some(mirror) = artifacts.get_mut("mirror") {
            absolute(mirror);
        }
    }
    if let Some(alias) = alias {
        let kept: Vec<toml::Value> = t
            .get("evm_rpc")
            .and_then(|e| e.as_array())
            .map(|a| a.iter().filter(|e| e.get("alias").and_then(|x| x.as_str()) == Some(alias)).cloned().collect())
            .unwrap_or_default();
        t.insert("evm_rpc".into(), toml::Value::Array(kept));
    }
    t.insert("spool_dir".into(), toml::Value::String(spool.display().to_string()));
    Ok(toml::to_string(&v)?)
}

/// Writes `text` to a new file only this user can read (a broker configuration may carry endpoint
/// keys).
fn write_private(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(text.as_bytes()).with_context(|| format!("writing {}", path.display()))
}

/// The broker configuration file, parsed, and the directory its relative `key_file`s are read from.
struct BrokerToml {
    value: toml::Value,
    /// The file's directory, absolute.
    dir: PathBuf,
}

/// The broker configuration file, parsed.
fn read_broker_config(path: &Path) -> Result<BrokerToml> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value = toml::from_str(&text)
        .with_context(|| format!("{} is not a broker configuration", path.display()))?;
    let file = std::path::absolute(path).with_context(|| format!("{}", path.display()))?;
    let dir = file.parent().unwrap_or(Path::new("/")).to_path_buf();
    Ok(BrokerToml { value, dir })
}

/// This run's `maxGuestCycles` maximum and where it came from.
fn host_max_guest_cycles(config: &ZkMinerConfig, opts: &WitnessSimOptions) -> (u64, &'static str) {
    match (opts.max_guest_cycles, config.witness.max_guest_cycles) {
        (Some(c), _) => (c, "--max-guest-cycles"),
        (None, Some(c)) => (c, "[witness] max_guest_cycles"),
        (None, None) => (MAX_HOST_GUEST_CYCLES, "unset"),
    }
}

/// The po2s a simulation executes, and those `maxGuestCycles` is judged at as a miner judges its
/// cards' sizes (§7.1: over the po2s the prover may use).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Po2Plan {
    pub po2s: Vec<u8>,
    /// Over at one of these, the job is skipped (as it is when over at every size executed).
    pub required: Vec<u8>,
    pub source: String,
    /// Who proves at `required`, in the report's words.
    pub provers: &'static str,
}

/// `--po2`'s sizes, judged at every one; else the sizes this configuration's cards prove at
/// ([`configured_card_po2s`]); else every job size, judged at [`RISC0_DEFAULT_JOB_PO2`]: the size
/// every card without a calibration or an operator's size proves at, so a miner that names no sizes
/// skips a job over the limit there.
///
/// [`RISC0_DEFAULT_JOB_PO2`]: zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2
pub fn po2_plan(asked: Option<&[u8]>, cards: Option<(Vec<u8>, String)>) -> Po2Plan {
    use zkminer_prover_protocol::{RISC0_DEFAULT_JOB_PO2, RISC0_JOB_PO2_MAX, RISC0_JOB_PO2_MIN};
    match (asked, cards) {
        (Some(a), _) => Po2Plan {
            po2s: a.to_vec(),
            required: a.to_vec(),
            source: "--po2".into(),
            provers: "--po2 says the prover",
        },
        (None, Some((c, source))) => Po2Plan {
            po2s: c.clone(),
            required: c,
            source,
            provers: "this configuration",
        },
        (None, None) => Po2Plan {
            po2s: (RISC0_JOB_PO2_MIN..=RISC0_JOB_PO2_MAX).collect(),
            required: vec![RISC0_DEFAULT_JOB_PO2],
            source: format!(
                "every job size, judged at po2 {RISC0_DEFAULT_JOB_PO2}: this configuration names no card sizes, and \
                 every card without a calibration or an operator's size proves at {RISC0_DEFAULT_JOB_PO2} (--po2 \
                 gives a prover's sizes)"
            ),
            provers: "a miner whose cards have no calibrated or configured size",
        },
    }
}

/// The sizes this configuration's risc0 cards prove jobs at, sized as the miner sizes them
/// (`benchmark::risc0_job_po2`): each risc0 row of `suite` (the benchmark cache, while this
/// hardware still matches it) at its `prover.risc0_job_po2` size, else its calibration or the
/// default size; and each other card `prover.risc0_job_po2` names. `None` when neither names a card.
///
/// The miner also sizes a card by its VRAM, which the benchmark cache does not record and this does
/// not read: a card under 14 GiB proves at its calibrated size (below the default when the default
/// failed there), or no job at all uncalibrated. Such a row counts at the size a card of 14 GiB or
/// more would prove at, and the source names, card by card, the size it would have under 14 GiB
/// wherever that differs, so a reader with a smaller card knows to give its size with `--po2`.
pub fn configured_card_po2s(
    config: &ZkMinerConfig,
    suite: Option<&zkminer_prover::benchmark::BenchmarkSuite>,
) -> Option<(Vec<u8>, String)> {
    use zkminer_prover::benchmark::{risc0_job_po2, RISC0_JOB_MIN_VRAM_BYTES};
    use zkminer_prover_protocol::{BACKEND_RISC0, RISC0_JOB_PO2_MAX, RISC0_JOB_PO2_MIN};
    let overrides = &config.prover.risc0_job_po2;
    let mut cards: Vec<(String, u8)> = Vec::new();
    // Cards whose size would differ under 14 GiB of VRAM: (device, that size, None for no jobs).
    let mut small: Vec<(String, Option<u8>)> = Vec::new();
    let mut from = Vec::new();
    for row in suite
        .iter()
        .flat_map(|s| &s.device_benchmarks)
        .filter(|d| d.prover_backend == BACKEND_RISC0)
    {
        let over = overrides.get(&row.device_id).copied();
        if let Some(po2) = risc0_job_po2(over, Some(row), None) {
            if !cards.iter().any(|(d, _)| *d == row.device_id) {
                cards.push((row.device_id.clone(), po2));
                // A CPU slot has no VRAM: the miner sizes it as one of unknown VRAM.
                let under = risc0_job_po2(over, Some(row), Some(RISC0_JOB_MIN_VRAM_BYTES - 1));
                if row.device_id != "cpu" && under != Some(po2) {
                    small.push((row.device_id.clone(), under));
                }
            }
        }
    }
    if !cards.is_empty() {
        from.push("the benchmark cache");
    }
    for (device, po2) in overrides {
        if !cards.iter().any(|(d, _)| d == device) {
            cards.push((
                device.clone(),
                (*po2).clamp(RISC0_JOB_PO2_MIN, RISC0_JOB_PO2_MAX),
            ));
        }
    }
    if !overrides.is_empty() {
        from.push("prover.risc0_job_po2");
    }
    if cards.is_empty() {
        return None;
    }
    cards.sort();
    let mut po2s: Vec<u8> = cards.iter().map(|(_, p)| *p).collect();
    po2s.sort_unstable();
    po2s.dedup();
    let list = cards
        .iter()
        .map(|(d, p)| match small.iter().find(|(s, _)| s == d) {
            Some((_, Some(q))) => format!("{d} at po2 {p} ({q} if it has under 14 GiB of VRAM)"),
            Some((_, None)) => format!("{d} at po2 {p} (no jobs if it has under 14 GiB of VRAM)"),
            None => format!("{d} at po2 {p}"),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let vram = if small.is_empty() {
        String::new()
    } else {
        "; the benchmark cache does not record VRAM, which the miner also sizes a card by: give a smaller \
         card's size with --po2"
            .to_string()
    };
    Some((
        po2s,
        format!(
            "this configuration's cards: {list} (from {}){vram}",
            from.join(" and ")
        ),
    ))
}

/// The benchmark cache `zkminer run` sizes its cards by, when there is one (read without probing
/// the GPUs when there is not).
fn cached_benchmark() -> Option<zkminer_prover::benchmark::BenchmarkSuite> {
    zkminer_prover::benchmark::benchmark_cache_path()
        .is_file()
        .then(zkminer_prover::benchmark::load_cached_benchmark)
        .flatten()
}

/// The `maxGuestCycles` part of the report, from each executed po2's outcome.
fn cycle_limit_report(
    max_guest_cycles: u64,
    executed: &[(u8, Option<u64>)],
    plan: &Po2Plan,
) -> Option<CycleLimitReport> {
    if executed.is_empty() {
        return None;
    }
    let mut within_at: Vec<u8> = executed
        .iter()
        .filter(|(_, c)| c.is_some())
        .map(|(p, _)| *p)
        .collect();
    let mut over_at: Vec<u8> = executed
        .iter()
        .filter(|(_, c)| c.is_none())
        .map(|(p, _)| *p)
        .collect();
    within_at.sort_unstable();
    over_at.sort_unstable();
    let note = if over_at.is_empty() {
        None
    } else if within_at.is_empty() {
        Some(format!(
            "over maxGuestCycles at every po2 executed ({}): a miner skips this job",
            po2_list(&over_at)
        ))
    } else {
        let required_over: Vec<u8> = over_at
            .iter()
            .copied()
            .filter(|p| plan.required.contains(p))
            .collect();
        Some(if !required_over.is_empty() {
            format!(
                "over maxGuestCycles at po2 {}, which {} proves at: a miner proving there skips this job",
                po2_list(&required_over),
                plan.provers
            )
        } else {
            format!(
                "over maxGuestCycles at po2 {} and within it at po2 {}: whether a miner serves this job depends on \
                 the segment size its cards prove at (one proving at po2 {} skips it); --po2 judges at given sizes",
                po2_list(&over_at),
                po2_list(&within_at),
                po2_list(&over_at)
            )
        })
    };
    Some(CycleLimitReport {
        max_guest_cycles: max_guest_cycles.to_string(),
        within_at,
        over_at,
        judged_at: plan.required.clone(),
        note,
    })
}

/// The journal header's length the binding must pin: a registered scheme's `W` declares it (read
/// from its first bytes), else `--header-bytes`; with both, the larger. With its source.
fn header_length(w_head: &[u8], asked: Option<usize>) -> (Option<usize>, Option<String>) {
    let declared = scheme_registry().header_bytes(w_head);
    match (declared, asked) {
        (Some((id, h)), Some(a)) if a != h => {
            (Some(h.max(a)), Some(format!("scheme {id} W ({h}) and --header-bytes ({a}): the larger")))
        }
        (Some((id, h)), _) => (Some(h), Some(format!("scheme {id} W"))),
        (None, Some(a)) => (Some(a), Some("--header-bytes".into())),
        (None, None) => (None, None),
    }
}

/// The first bytes of the bundle's `W`, enough for a scheme's magic and counts.
fn w_head(store: &Store, bundle: &zkminer_witness_store::BundleRef) -> Vec<u8> {
    use std::io::Read;
    let mut head = Vec::with_capacity(64);
    if let Ok(f) = store.open_w(bundle) {
        let _ = f.take(64).read_to_end(&mut head);
    }
    head
}

/// What a successful simulation is reported with besides itself.
struct SuccessFacts<'a> {
    declared: &'a Limits,
    host_max_cycles: u64,
    host_max_source: &'static str,
    charges: Vec<(u64, u32)>,
    /// The journal header's length the binding must pin ([`header_length`]).
    header_bytes: Option<usize>,
}

/// Fills `r` from a published simulation.
fn fill_success(r: &mut WitnessReport, s: &Simulated, d: &JobDescriptor, f: SuccessFacts<'_>) {
    let SuccessFacts { declared, host_max_cycles, host_max_source, charges, header_bytes } = f;
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
        .map(|p| Po2Report {
            po2: p.po2,
            cycles: p.cycles.to_string(),
            segment_bytes: p.segment_bytes,
            peak_host_bytes: p.peak_host_bytes,
            sys_rand_draws: p.sys_rand_draws,
        })
        .collect();
    r.cycles = Some(CyclesReport {
        declared_max_guest_cycles: declared.maxGuestCycles.to_string(),
        measured: s.per_po2.iter().map(|p| p.cycles).max().map(|c| c.to_string()),
        host_max_guest_cycles: host_max_cycles.to_string(),
        host_max_source,
    });
    let statement = if s.prefix { &s.journal[PREFIX_BYTES.min(s.journal.len())..] } else { &s.journal[..] };
    let report = check_binding(&CheckInput {
        journal_fields: d.journalFields,
        expected_journal_hash: Some(d.expectedJournalHash),
        proof_system_id: d.proofSystemId,
        program_id: d.programId,
        statement,
        header_bytes,
        words: &[],
        assigned_prover: d.assignedProver,
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
/// else the RPC-free upper bound, held to the claim gate's operator cap `cap_bytes` as the miner's
/// `DaCapPolicy` holds it (the backlog is not on this side: `notChecked`).
async fn fulfil_report(
    client: Option<&ChainClient>,
    chain_id: u64,
    router: Address,
    job_id: B256,
    d: &JobDescriptor,
    journal: &[u8],
    cap_bytes: u64,
) -> FulfilReport {
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
        within_cap: da_cap_check(cap_bytes, estimated).is_none(),
        cap_bytes,
        gas: fulfill_gas_formula(0, calldata_bytes, journal.len()),
    }
}

/// The claim gate's DA check (`DaCapPolicy::fulfil_fits`) at a backlog below the hold level: `Some`
/// with the miner's skip text when the fulfil is over the operator cap.
fn da_cap_check(cap_bytes: u64, estimated: u64) -> Option<String> {
    let policy = match DaCapPolicy::new(cap_bytes) {
        Ok(p) => p,
        Err(e) => return Some(format!("{e:#}")),
    };
    match policy.fulfil_fits(estimated, Backlog::Known(0)) {
        Decision::Fits { .. } => None,
        Decision::Skip(s) => Some(format!("{s:?}")),
    }
}

/// What the mutation sweep was set to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MutationsRan {
    /// `--max-mutations` (capped at [`MAX_MUTATIONS`]).
    max: usize,
    /// The job's scheme had structured mutations, and they were made.
    structured: bool,
}

/// Whether the scheme report says its structured mutations were made.
fn scheme_ran(scheme: &SchemeReport) -> bool {
    scheme.name.is_some() && scheme.status.starts_with("structured mutations first")
}

/// The attack's sized-cycle cap: this host's configured maximum (`--max-guest-cycles`, `[witness]
/// max_guest_cycles`), else [`ATTACK_CYCLE_MULTIPLE`] times the job's `maxGuestCycles` (never past
/// [`MAX_HOST_GUEST_CYCLES`]): without one, 2^34 let a single mutation that loops run for hours.
fn attack_cycle_cap((host, source): (u64, &'static str), max_guest_cycles: u64) -> (u64, String) {
    if source == "unset" {
        let cap = max_guest_cycles
            .saturating_mul(ATTACK_CYCLE_MULTIPLE)
            .min(MAX_HOST_GUEST_CYCLES)
            .max(1);
        (cap, format!("{ATTACK_CYCLE_MULTIPLE} × the job's maxGuestCycles (no --max-guest-cycles or [witness] max_guest_cycles)"))
    } else {
        (host, source.to_string())
    }
}

/// The verdict of an adversarial run. Under FULL the router refuses every journal but the honest
/// one, so what the mutations could not decide leaves nothing undecided; under any other binding a
/// sweep that ran no mutation, or none of the scheme's structured ones, is incomplete.
fn adversarial_verdict(
    coverage: &CoverageReport,
    ran: MutationsRan,
    mutations: &[MutationResult],
    host: &[HostInputResult],
    diff: &DifferentialReport,
) -> &'static str {
    let failed = !coverage.ok
        || mutations.iter().any(|m| m.outcome.is_soundness_failure())
        || host.iter().any(|h| h.dependent)
        || diff.soundness_failure;
    let incomplete = mutations.iter().any(|m| match m.outcome {
        MutationOutcome::NotRun => true,
        MutationOutcome::Inconclusive { .. } => !coverage.whole_journal,
        _ => false,
    }) || ran.max == 0
        || (!ran.structured && !coverage.whole_journal)
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

/// The binding's coverage of the journal header, which an attack on `W` cannot judge: a header word
/// the binding leaves free is exploitable only with a consistent change of the rest of `W` (another
/// `k` and its proofs, another block and its header), which no mutation makes, so every mutation of
/// such a job is rejected and the attack would pass. `[0, H)` must be pinned and the expected hash
/// non-zero (§7.2).
fn coverage(binding: &BindingReport, expected: B256, source: Option<String>) -> CoverageReport {
    let h = binding.header_bytes;
    let failure = if expected == B256::ZERO {
        Some("NONE: expectedJournalHash is 0, so nothing binds the statement; any prover may prove any".to_string())
    } else if binding.mode == "full" {
        None
    } else if let Some(h) = h.filter(|&h| h > binding.statement_bytes) {
        Some(format!("the header is {h} bytes, longer than the {}-byte statement", binding.statement_bytes))
    } else if !binding.header_free.is_empty() {
        Some(format!(
            "the binding leaves {} of the header's {} bytes free ({:?}): each is a value the prover chooses, with a \
             W changed to match",
            binding.header_free.iter().map(|r| r.end - r.start).sum::<usize>(),
            h.unwrap_or(0),
            binding.header_free.iter().map(|r| (r.start, r.end)).collect::<Vec<_>>()
        ))
    } else if h.is_none() {
        Some(
            "the journal header's length is unknown (W is of no registered scheme): give --header-bytes, so that a \
             binding pinning fewer header words than the guest commits is caught"
                .to_string(),
        )
    } else {
        None
    };
    CoverageReport {
        header_bytes: h,
        header_source: source,
        ok: failure.is_none(),
        failure,
        whole_journal: binding.mode == "full" && expected != B256::ZERO,
    }
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
    cycle_judging: CycleJudging,
    keccak_po2: u8,
    execute_timeout: Duration,
) -> (SimHooks, HostContext) {
    let slot = Arc::new(Mutex::new(p.elf.clone()));
    let hooks = SimHooks {
        token: token.clone(),
        charges: Mutex::new(Vec::new()),
        budget: ArtifactBudget::for_max_bytes(DEFAULT_MAX_ARTIFACT_BYTES),
        client,
        program_id: p.descriptor.programId,
        fetched_elf: slot.clone(),
        executed: Mutex::new(Vec::new()),
    };
    let mut ctx = host.context(
        broker,
        &p.config,
        po2s,
        cycle_judging,
        keccak_po2,
        execute_timeout,
    );
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
    let broker_toml = read_broker_config(&p.broker_config)?;
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
    let (host_max_cycles, host_max_source) = host_max_guest_cycles(&p.config, &opts);
    let plan = match &opts.po2s {
        Some(asked) => po2_plan(Some(asked), None),
        None => po2_plan(
            None,
            configured_card_po2s(&p.config, cached_benchmark().as_ref()),
        ),
    };
    let mut not_checked = NOT_CHECKED.to_vec();
    if opts.builder.is_some() {
        not_checked.push(NOT_CHECKED_BUILDER);
    }
    if opts.elf.is_some() {
        not_checked.push(NOT_CHECKED_ELF);
    }
    if host_max_source == "unset" {
        not_checked.push(NOT_CHECKED_CYCLES);
    }
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
        po2s: plan.po2s.clone(),
        po2_source: plan.source.clone(),
        keccak_po2: opts.keccak_po2,
        sys_rand_rule: zkminer_prover_protocol::sys_rand::SYS_RAND_RULE,
        execute_build: host.execute_build.clone(),
        builder: None,
        witness: None,
        per_po2: Vec::new(),
        cycles: None,
        cycle_limit: None,
        journal: None,
        binding: None,
        fulfil: None,
        admission: admission_parameters(&p.config, &host_maxima(w, host_max_cycles), host_max_source),
        timings: None,
        not_checked,
        adversarial: None,
        zkminer_version: env!("CARGO_PKG_VERSION"),
        protocol_version: zkminer_prover_protocol::PROTOCOL_VERSION,
    };

    let broker = host.broker(&p.config, &host.own_broker_config(&broker_toml, "main", None)?).await?;
    let (hooks, ctx) = hooks_and_context(
        &p,
        &host,
        &broker,
        client.clone(),
        &token,
        plan.po2s.clone(),
        // Each po2 on its own, so the report names every one over maxGuestCycles.
        CycleJudging::PerPo2 {
            required: plan.required.clone(),
        },
        opts.keccak_po2,
        opts.execute_timeout,
    );
    let result = run_pipeline(&p, &ctx, &hooks, current_block).await;
    let declared = decode(&p.descriptor.inputData).map(|e| e.job.limits).ok();
    if let Some(declared) = &declared {
        let executed = hooks
            .executed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        report.cycle_limit = cycle_limit_report(declared.maxGuestCycles, &executed, &plan);
    }
    let mut header_source = None;
    let simulated = match result {
        Ok(s) => {
            report.outcome = "simulated";
            let charges = hooks.charges.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|c| (c.length, c.chunks)).collect();
            let (header_bytes, source) = header_length(&w_head(&host.store, &s.bundle), opts.header_bytes);
            header_source = source;
            if let Some(declared) = &declared {
                let facts = SuccessFacts { declared, host_max_cycles, host_max_source, charges, header_bytes };
                fill_success(&mut report, &s, &p.descriptor, facts);
            }
            let fulfil = fulfil_report(
                client.as_ref(),
                p.config.chain.chain_id,
                p.router,
                p.job_id,
                &p.descriptor,
                &s.journal,
                w.fulfil_da_cap_bytes,
            )
            .await;
            // The claim gate's DA check (§5.2 step 7): the miner skips a fulfil over its cap.
            if let Some(why) = da_cap_check(fulfil.cap_bytes, fulfil.estimated_da_bytes) {
                report.outcome = "skipped";
                report.verdict = Some(VerdictReport::new(SkipReason::FulfilDaTooLarge, "claim_gate", &why));
            }
            report.fulfil = Some(fulfil);
            Some(s)
        }
        Err(skip) => {
            report.outcome = if matches!(skip, Skip::Aborted { .. }) { "aborted" } else { "skipped" };
            report.verdict = verdict_report(&skip);
            None
        }
    };

    // A job the miner would skip is not attacked: its verdict is the answer.
    if let (Some(adv), Some(s), "simulated") = (&opts.adversarial, &simulated, report.outcome) {
        let elf = hooks.fetched_elf.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let binding = report.binding.clone();
        match (elf, binding) {
            (Some(elf), Some(binding)) => {
                let a = Adversary {
                    p: &p,
                    host: &host,
                    ctx: &ctx,
                    token: &token,
                    opts: &opts,
                    po2s: s.per_po2.iter().map(|x| x.po2 as u8).collect(),
                    client: client.as_ref(),
                    current_block,
                    broker_toml: &broker_toml,
                };
                let coverage = coverage(&binding, p.descriptor.expectedJournalHash, header_source);
                report.adversarial = Some(a.run(adv, s, &elf, coverage).await?);
            }
            (None, _) => bail!("the ELF bytes the simulation executed were not kept"),
            (_, None) => bail!("the simulation has no binding report"),
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
        let over_cap = report
            .verdict
            .as_ref()
            .is_some_and(|v| v.reason == SkipReason::GuestCyclesAboveLimit);
        match (&report.cycle_limit, over_cap) {
            (Some(c), true) if !plan.required.is_empty() => {
                let over: Vec<u8> = c.over_at.iter().copied().filter(|p| plan.required.contains(p)).collect();
                bail!(
                    "a miner proving at po2 {} ({}) would skip this job: {v}, over maxGuestCycles {} at po2 {}",
                    po2_list(&plan.required),
                    plan.source,
                    c.max_guest_cycles,
                    po2_list(&over)
                );
            }
            (Some(c), true) => bail!(
                "every po2 executed ({}) is over maxGuestCycles {}: a miner would skip this job: {v}",
                po2_list(&c.over_at),
                c.max_guest_cycles
            ),
            _ => bail!("a miner with this configuration would skip this job: {v}"),
        }
    }
    // Served at some sizes only: the verdict is the prover's segment size, so say so.
    if let Some(note) = report
        .cycle_limit
        .as_ref()
        .filter(|c| !c.over_at.is_empty())
        .and_then(|c| c.note.as_ref())
    {
        eprintln!("zkminer simulate: {note}");
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
    /// The po2s the simulation ran within `maxGuestCycles` at: every attack executes at these.
    po2s: Vec<u8>,
    client: Option<&'a ChainClient>,
    current_block: u64,
    /// The broker configuration, parsed: each provider run writes its own from it.
    broker_toml: &'a BrokerToml,
}

/// A token that fires when `main` does or at `deadline`, whichever is first; the task watching for
/// it is aborted with the returned handle.
fn deadline_token(main: &AbortToken, deadline: Instant) -> (AbortToken, tokio::task::JoinHandle<()>) {
    let t = AbortToken::new();
    let (fire, main) = (t.clone(), main.clone());
    let watcher = tokio::spawn(async move {
        tokio::select! {
            r = main.aborted() => {
                fire.abort(r);
            }
            _ = tokio::time::sleep_until(deadline.into()) => {
                fire.abort(AbortReason::Deadline);
            }
        }
    });
    (t, watcher)
}

impl Adversary<'_> {
    async fn run(
        &self,
        adv: &AdversarialOptions,
        s: &Simulated,
        elf: &[u8],
        coverage: CoverageReport,
    ) -> Result<AdversarialReport> {
        let started = Instant::now();
        let deadline = started + adv.budget;
        let p = self.p;
        let empty_differential = || DifferentialReport {
            runs: Vec::new(),
            w_same: None,
            journal_same: None,
            soundness_failure: false,
            note: None,
        };
        let mut failures = Vec::new();
        if let Some(f) = &coverage.failure {
            failures.push(format!("binding: {f}"));
        }
        // A W too large to attack here: every mutation is made from it, in this unsandboxed process.
        if s.w_len > adv.max_w_bytes {
            let refused = format!(
                "W is {} bytes, above --adversarial-max-w-bytes ({}): raise it to attack a W this large",
                s.w_len, adv.max_w_bytes
            );
            return Ok(AdversarialReport {
                verdict: if coverage.ok { "incomplete" } else { "fail" }.into(),
                refused: Some(refused),
                binding_coverage: coverage,
                attack_cycle_cap: String::new(),
                attack_cycle_cap_source: String::new(),
                budget_secs: adv.budget.as_secs(),
                elapsed_secs: started.elapsed().as_secs_f64(),
                run_seed: String::new(),
                scheme: SchemeReport { id: None, name: None, status: "not run".into() },
                framings: Vec::new(),
                counts: MutationCounts::default(),
                mutations: Vec::new(),
                host_inputs: Vec::new(),
                differential: empty_differential(),
                soundness_failures: failures,
                notes: Vec::new(),
            });
        }
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
        let max = adv.max_mutations.min(MAX_MUTATIONS);

        // The mutations, made one at a time as they run: the scheme's structured ones first (they
        // say the most), then the generic ones, which keep at least a quarter of the room so neither
        // kind crowds the other out.
        let generic = generic_mutations(&w, seed, adv.flips);
        let registry = scheme_registry();
        let scheme_id = adv.scheme.or_else(|| scheme_id_of(statement));
        let mut structured: Option<zkminer_witness_host::adversarial::Mutations<'_>> = None;
        let scheme = match scheme_id {
            None => SchemeReport { id: None, name: None, status: "no scheme id in the header (pass --scheme)".into() },
            Some(id) => match registry.get(id) {
                None => SchemeReport { id: Some(id), name: None, status: "no structured mutations registered for this scheme".into() },
                Some(m) => {
                    // What the scheme needs from outside W (the parent's header), through the job's
                    // own evm-rpc source, as a builder's fetches go.
                    let answers = match m.requests(&w) {
                        Ok(calls) if !calls.is_empty() => self.scheme_answers(&calls, deadline).await,
                        _ => Vec::new(),
                    };
                    let fetched = answers.iter().filter(|a| a.is_some()).count();
                    match m.mutations(&w, &SchemeContext { statement, seed, answers: &answers }) {
                        Ok(ms) => {
                            structured = Some(ms);
                            SchemeReport {
                                id: Some(id),
                                name: Some(m.name().into()),
                                status: format!(
                                    "structured mutations first ({fetched} of {} fetched answers used)",
                                    answers.len()
                                ),
                            }
                        }
                        Err(e) => SchemeReport { id: Some(id), name: Some(m.name().into()), status: e },
                    }
                }
            },
        };
        let scheme_room = max.saturating_sub(generic.len().min(max / 4)).min(SCHEME_MUTATIONS);
        let plan: Box<dyn Iterator<Item = Mutation<'_>> + Send + '_> = match structured {
            Some(ms) => Box::new(ms.take(scheme_room).chain(generic)),
            None => Box::new(generic.into_iter()),
        };
        let judge = Judge { descriptor: &p.descriptor, job_id: p.job_id, prover: p.prover, baseline_journal: &s.journal };
        let (attack_cap, attack_cap_source) = attack_cycle_cap(
            host_max_guest_cycles(&p.config, self.opts),
            s.limits.maxGuestCycles,
        );
        // The unchanged W's execute at one po2, as the pipeline timed it: what a mutation that runs
        // like it needs.
        let per_po2 = s.timings.execute / u32::try_from(s.per_po2.len().max(1)).unwrap_or(1);
        let baseline = Baseline {
            ctx: self.ctx,
            token: self.token,
            elf,
            judge,
            prefix,
            w: &w,
            po2: *self.po2s.first().expect("a po2 within the cap"),
            po2s: &self.po2s,
            keccak_po2: self.opts.keccak_po2,
            cycles: CycleLimits {
                host: attack_cap,
                job: s.limits.maxGuestCycles,
            },
            deadline,
            mutation_floor: (per_po2 * MUTATION_FLOOR_RUNS).max(MUTATION_FLOOR_MIN),
        };
        // The host inputs and the providers first: a few runs each, and each a whole class of
        // failure; the mutations then share what is left.
        let host_inputs = host_input_checks(&baseline, rand::random()).await;
        let differential = self.differential(adv, s, deadline).await;
        let results = run_mutations(&baseline, plan, max).await;

        for m in &results {
            if let MutationOutcome::SoundnessFailure { first_difference, .. } = &m.outcome {
                failures.push(format!(
                    "mutation {} ({}): the journal changed at byte {first_difference} and still satisfies the binding{}",
                    m.id,
                    m.description,
                    if m.over_job_cycles { " (past the job's maxGuestCycles, which the router does not check)" } else { "" }
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
        let over = results.iter().filter(|m| m.over_job_cycles).count();
        if over > 0 {
            notes.push(format!(
                "{over} mutation(s) ran past the job's maxGuestCycles ({}): a miner skips such a W, but the router does not \
                 check cycles, so each was judged on its journal under the attack's cycle cap ({attack_cap})",
                s.limits.maxGuestCycles
            ));
        }
        let structured = scheme_ran(&scheme);
        if max == 0 {
            notes.push("--max-mutations 0: no mutation of W was run".to_string());
        } else if !structured && !coverage.whole_journal {
            notes.push(format!(
                "no structured mutations ran ({}): the generic ones alone change bytes, not a consistent W (another \
                 proof, another block), so the attack is incomplete under this binding",
                scheme.status
            ));
        }
        let undecided = results.iter().filter(|m| matches!(m.outcome, MutationOutcome::Inconclusive { .. })).count();
        if coverage.whole_journal && undecided > 0 {
            notes.push(format!(
                "{undecided} mutation(s) did not run to a journal here; under FULL the router refuses every journal but the \
                 honest one, so they leave nothing undecided"
            ));
        }
        let ran = MutationsRan { max, structured };
        let verdict =
            adversarial_verdict(&coverage, ran, &results, &host_inputs, &differential).to_string();
        Ok(AdversarialReport {
            verdict,
            refused: None,
            binding_coverage: coverage,
            attack_cycle_cap: attack_cap.to_string(),
            attack_cycle_cap_source: attack_cap_source,
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
    async fn scheme_answers(&self, calls: &[RpcCall], deadline: Instant) -> Vec<Option<serde_json::Value>> {
        let Ok(env) = decode(&self.p.descriptor.inputData) else { return vec![None; calls.len()] };
        let Some(cap) = env.capabilities.iter().position(|c| matches!(c, CapabilityKind::EvmRpcV1 { .. })) else {
            return vec![None; calls.len()];
        };
        let sources = env.job.sources.iter().map(|c| (c.class, c.config.to_vec())).collect();
        fetch_through_job(&self.ctx.broker, self.p.caller, sources, cap as u32, calls, deadline).await
    }

    /// The whole pipeline against each of two providers (one po2: the journals are compared, not the
    /// po2s), each from a broker configuration holding only that provider. Each run, its broker's
    /// start included, ends at the deadline: a token fires there and kills the run's sandboxes.
    async fn differential(&self, adv: &AdversarialOptions, s: &Simulated, deadline: Instant) -> DifferentialReport {
        let p = self.p;
        let mut report = DifferentialReport { runs: Vec::new(), w_same: None, journal_same: None, soundness_failure: false, note: None };
        let chain = decode(&p.descriptor.inputData).ok().and_then(|e| {
            e.capabilities.iter().find_map(|c| match c {
                CapabilityKind::EvmRpcV1 { chain_id, .. } => Some(*chain_id),
                _ => None,
            })
        });
        let providers = match pick_providers(&self.broker_toml.value, chain, adv.providers.as_deref()) {
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
            let (token, watcher) = deadline_token(self.token, deadline);
            let attempt = async {
                let path = self.host.own_broker_config(
                    self.broker_toml,
                    &format!("provider-{}", report.runs.len()),
                    Some(&alias),
                )?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                let broker = tokio::time::timeout(remaining, self.host.broker(&p.config, &path))
                    .await
                    .map_err(|_| anyhow::anyhow!("the broker did not start within the run's time"))??;
                let remaining = deadline.saturating_duration_since(Instant::now());
                let (hooks, ctx) = hooks_and_context(
                    p,
                    self.host,
                    &broker,
                    self.client.cloned(),
                    &token,
                    vec![*self.po2s.first().expect("a po2 within the cap")],
                    CycleJudging::EveryPo2,
                    self.opts.keccak_po2,
                    self.opts.execute_timeout.min(remaining),
                );
                let r = run_pipeline(p, &ctx, &hooks, self.current_block).await;
                drop(broker);
                Ok::<_, anyhow::Error>(r)
            };
            let attempt = attempt.await;
            watcher.abort();
            match attempt {
                Ok(Ok(sim)) => {
                    run.outcome = "simulated".into();
                    run.w_sha256 = Some(sim.w_sha256);
                    run.journal_sha256 = Some(B256::from(zkminer_witness::manifest::sha256(&sim.journal)));
                    outcomes.push(Some((sim.w_sha256, sim.journal.clone(), true)));
                }
                Ok(Err(Skip::Aborted { reason, .. })) => {
                    run.outcome = "not_run".into();
                    report.note = Some(match reason {
                        AbortReason::Deadline => "the run's time ran out during a provider run".into(),
                        r => format!("a provider run was aborted: {r:?}"),
                    });
                    outcomes.push(None);
                }
                Ok(Err(skip)) => {
                    run.outcome = "skipped".into();
                    run.verdict = verdict_report(&skip);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::witness_tools::ByteRange;
    use zkminer_witness::binding::journal_fields_for_header;

    fn binding(fields: B256, expected: B256, statement: &[u8], header_bytes: Option<usize>) -> BindingReport {
        check_binding(&CheckInput {
            journal_fields: fields,
            expected_journal_hash: Some(expected),
            proof_system_id: zkminer_chain::auction::risc_zero_groth16_v1_id(),
            program_id: B256::ZERO,
            statement,
            header_bytes,
            words: &[],
            assigned_prover: Address::repeat_byte(0xb0),
        })
    }

    #[test]
    fn the_po2_plan_judges_at_the_provers_sizes_when_known() {
        let cards = || Some((vec![19, 20], "this configuration's cards: …".to_string()));
        // --po2: executed and judged at every one, whatever the cards.
        let p = po2_plan(Some(&[16, 22]), cards());
        assert_eq!(
            (p.po2s, p.required, p.source.as_str()),
            (vec![16, 22], vec![16, 22], "--po2")
        );
        // The cards' sizes, as the miner executes and judges them.
        let p = po2_plan(None, cards());
        assert_eq!((p.po2s, p.required), (vec![19, 20], vec![19, 20]));
        // Neither: every job size executed, judged at the default size every uncalibrated card
        // proves at, as a miner without card sizes judges it.
        let p = po2_plan(None, None);
        assert_eq!(p.po2s, (16..=22).collect::<Vec<u8>>());
        assert_eq!(
            p.required,
            vec![zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2]
        );
        assert!(
            p.source.starts_with("every job size, judged at po2 20"),
            "{p:?}"
        );
        let r = cycle_limit_report(100, &[(18, Some(90)), (20, None)], &p).unwrap();
        assert!(r
            .note
            .unwrap()
            .contains("over maxGuestCycles at po2 20, which a miner whose cards have no"));
    }

    /// The miner sizes a card under 14 GiB of VRAM below the default (or gives it no jobs); the
    /// benchmark cache does not record VRAM, so the source says what such a card would prove at.
    #[test]
    fn a_card_size_that_depends_on_vram_is_named() {
        use zkminer_prover::benchmark::{risc0_job_po2, BenchmarkSuite, DeviceBenchmark};
        let gib = 1u64 << 30;
        // Calibrated: po2 20 proved, 21 failed (ceiling 19).
        let calibrated: DeviceBenchmark = serde_json::from_value(serde_json::json!({
            "device_id": "gpu0", "device_label": "gpu0", "prover_backend": "risc0",
            "throughput": 1.0, "power_watts": 1.0, "optimal_po2": 20, "max_feasible_po2": 19,
            "po2_samples": [{"po2": 20, "total_cycles": 1, "segment_count": 1, "duration_secs": 1.0, "throughput": 1.0}],
        }))
        .unwrap();
        let uncalibrated: DeviceBenchmark = serde_json::from_value(serde_json::json!({
            "device_id": "gpu1", "device_label": "gpu1", "prover_backend": "risc0",
            "throughput": 1.0, "power_watts": 1.0,
        }))
        .unwrap();
        assert_eq!(
            risc0_job_po2(None, Some(&calibrated), Some(12 * gib)),
            Some(19)
        );
        assert_eq!(
            risc0_job_po2(None, Some(&uncalibrated), Some(12 * gib)),
            None
        );
        let config = ZkMinerConfig::default();
        let suite = BenchmarkSuite {
            device_benchmarks: vec![calibrated, uncalibrated],
            ..Default::default()
        };
        let (po2s, source) = configured_card_po2s(&config, Some(&suite)).unwrap();
        assert_eq!(po2s, vec![20], "judged as cards of 14 GiB or more");
        assert!(
            source.contains("gpu0 at po2 20 (19 if it has under 14 GiB of VRAM)"),
            "{source}"
        );
        assert!(
            source.contains("gpu1 at po2 20 (no jobs if it has under 14 GiB of VRAM)"),
            "{source}"
        );
        assert!(
            source.contains("give a smaller card's size with --po2"),
            "{source}"
        );
        // An operator's size is the card's whatever its VRAM: nothing to name.
        let mut config = ZkMinerConfig::default();
        config.prover.risc0_job_po2 =
            std::collections::HashMap::from([("gpu0".into(), 18), ("gpu1".into(), 18)]);
        let (po2s, source) = configured_card_po2s(&config, Some(&suite)).unwrap();
        assert_eq!(po2s, vec![18]);
        assert!(!source.contains("VRAM"), "{source}");
    }

    #[test]
    fn card_sizes_come_from_the_benchmark_cache_and_the_configured_sizes() {
        use zkminer_prover::benchmark::{BenchmarkSuite, DeviceBenchmark};
        let mut config = ZkMinerConfig::default();
        assert_eq!(configured_card_po2s(&config, None), None);
        let row = |device: &str, backend: &str| -> DeviceBenchmark {
            serde_json::from_value(serde_json::json!({
                "device_id": device, "device_label": device, "prover_backend": backend,
                "throughput": 1.0, "power_watts": 1.0,
            }))
            .unwrap()
        };
        let suite = BenchmarkSuite {
            device_benchmarks: vec![
                row("gpu0", "risc0"),
                row("gpu1", "sp1"),
                row("cpu", "risc0"),
            ],
            ..Default::default()
        };
        // Uncalibrated risc0 rows prove at the default size; an SP1 row is no risc0 card.
        let (po2s, source) = configured_card_po2s(&config, Some(&suite)).unwrap();
        assert_eq!(po2s, vec![20]);
        assert!(
            source
                .contains("cpu at po2 20, gpu0 at po2 20 (no jobs if it has under 14 GiB of VRAM)")
                && !source.contains("gpu1"),
            "{source}"
        );
        // prover.risc0_job_po2 sizes its card, names one the cache lacks, and is held to 16..=22.
        config.prover.risc0_job_po2 =
            std::collections::HashMap::from([("gpu0".into(), 19), ("gpu-rocm0".into(), 23)]);
        let (po2s, source) = configured_card_po2s(&config, Some(&suite)).unwrap();
        assert_eq!(po2s, vec![19, 20, 22]);
        assert!(
            source.contains("gpu0 at po2 19") && source.contains("gpu-rocm0 at po2 22"),
            "{source}"
        );
        assert!(
            source.ends_with("(from the benchmark cache and prover.risc0_job_po2)"),
            "{source}"
        );
        let (po2s, _) = configured_card_po2s(&config, None).unwrap();
        assert_eq!(po2s, vec![19, 22]);
    }

    #[test]
    fn the_cycle_limit_note_says_what_the_verdict_depends_on() {
        let unknown = po2_plan(None, None);
        let r = cycle_limit_report(100, &[(20, Some(90)), (16, None)], &unknown).unwrap();
        assert_eq!(
            (r.over_at.clone(), r.within_at.clone()),
            (vec![16], vec![20])
        );
        let note = r.note.unwrap();
        assert!(
            note.contains("po2 16") && note.contains("depends on the segment size"),
            "{note}"
        );
        let all = cycle_limit_report(100, &[(16, None), (20, None)], &unknown).unwrap();
        assert!(all.note.unwrap().contains("every po2"));
        assert!(cycle_limit_report(100, &[(20, Some(1))], &unknown)
            .unwrap()
            .note
            .is_none());
        assert!(cycle_limit_report(100, &[], &unknown).is_none());
        let asked = po2_plan(Some(&[16, 20]), None);
        let r = cycle_limit_report(100, &[(16, None), (20, Some(9))], &asked).unwrap();
        assert_eq!(r.judged_at, vec![16, 20]);
        assert!(r.note.unwrap().contains("skips this job"));
    }

    #[test]
    fn the_attack_fails_unless_the_whole_header_is_pinned() {
        let header = [7u8; 160];
        let mut statement = header.to_vec();
        statement.extend_from_slice(&[1; 64]);
        // The whole 160-byte header: covered.
        let all = binding(journal_fields_for_header(160, true).unwrap(), keccak256(header), &statement, Some(160));
        let c = coverage(&all, keccak256(header), Some("scheme 1 W".into()));
        assert!(c.ok && c.failure.is_none(), "{c:?}");
        // Only the scheme word: the other four words are the prover's.
        let one =
            binding(journal_fields_for_header(32, true).unwrap(), keccak256(&header[..32]), &statement, Some(160));
        assert_eq!(one.header_free, vec![ByteRange { start: 32, end: 160 }]);
        let c = coverage(&one, keccak256(&header[..32]), None);
        assert!(!c.ok && c.failure.as_deref().unwrap().contains("128 of the header's 160 bytes free"), "{c:?}");
        // The same binding, the header's length unknown: not shown to be covered.
        let unknown = binding(journal_fields_for_header(32, true).unwrap(), keccak256(&header[..32]), &statement, None);
        assert!(coverage(&unknown, keccak256(&header[..32]), None).failure.unwrap().contains("--header-bytes"));
        // NONE (assigned): nothing binds the statement.
        let marker = journal_fields_for_header(32, true).unwrap();
        let marker_only = zkminer_witness::binding::clear_marker(marker) ^ marker;
        let none = binding(marker_only, B256::ZERO, &statement, Some(160));
        assert!(coverage(&none, B256::ZERO, None).failure.unwrap().starts_with("NONE"));
        // FULL pins everything, whatever H.
        let full = binding(B256::ZERO, B256::repeat_byte(3), &statement, None);
        assert!(coverage(&full, B256::repeat_byte(3), None).ok);
        // The verdict follows the coverage before anything else.
        let diff = DifferentialReport {
            runs: Vec::new(),
            w_same: None,
            journal_same: None,
            soundness_failure: false,
            note: None,
        };
        let ran = MutationsRan {
            max: 256,
            structured: true,
        };
        assert_eq!(
            adversarial_verdict(
                &coverage(&one, keccak256(&header[..32]), None),
                ran,
                &[],
                &[],
                &diff
            ),
            "fail"
        );
        // A mutation this host could not run to a journal decides nothing under FULL, and leaves
        // FIELDS incomplete.
        let host = HostInputResult {
            input: zkminer_witness_host::adversarial::HostInput::SysRandSeed,
            values: ["a".into(), "b".into()],
            journal_sha256: [None, None],
            dependent: false,
            note: None,
            ran: true,
        };
        let hosts = [host];
        let run = |alias: &str| ProviderRun {
            alias: alias.into(),
            outcome: "simulated".into(),
            verdict: None,
            w_sha256: None,
            journal_sha256: None,
        };
        let agreed = DifferentialReport {
            runs: vec![run("a"), run("b")],
            w_same: Some(true),
            journal_same: Some(true),
            soundness_failure: false,
            note: None,
        };
        let capped = MutationResult {
            id: "flip@3^0x80".into(),
            kind: "flip".into(),
            description: "d".into(),
            w_bytes: Some(4),
            cycles: None,
            over_job_cycles: false,
            outcome: MutationOutcome::Inconclusive { why: "ran past this host's maximum".into() },
        };
        let full_cov = coverage(&full, B256::repeat_byte(3), None);
        assert!(full_cov.whole_journal);
        assert_eq!(
            adversarial_verdict(
                &full_cov,
                ran,
                std::slice::from_ref(&capped),
                &hosts,
                &agreed
            ),
            "pass"
        );
        let fields_cov = coverage(&all, keccak256(header), None);
        assert_eq!(
            adversarial_verdict(
                &fields_cov,
                ran,
                std::slice::from_ref(&capped),
                &hosts,
                &agreed
            ),
            "incomplete"
        );
        assert_eq!(
            adversarial_verdict(&fields_cov, ran, &[], &hosts, &agreed),
            "pass"
        );
        // No mutation run at all (--max-mutations 0) is never a pass, under any binding.
        let none = MutationsRan {
            max: 0,
            structured: true,
        };
        assert_eq!(
            adversarial_verdict(&fields_cov, none, &[], &hosts, &agreed),
            "incomplete"
        );
        assert_eq!(
            adversarial_verdict(&full_cov, none, &[], &hosts, &agreed),
            "incomplete"
        );
        // Without the scheme's structured mutations (no scheme registered, or W not of it): incomplete,
        // unless FULL decides every journal.
        let generic = MutationsRan {
            max: 256,
            structured: false,
        };
        assert_eq!(
            adversarial_verdict(&fields_cov, generic, &[], &hosts, &agreed),
            "incomplete"
        );
        assert_eq!(
            adversarial_verdict(&full_cov, generic, &[], &hosts, &agreed),
            "pass"
        );
        assert!(scheme_ran(&SchemeReport {
            id: Some(1),
            name: Some("eth-block".into()),
            status: "structured mutations first (2 of 2 fetched answers used)".into()
        }));
        assert!(!scheme_ran(&SchemeReport {
            id: Some(0x77),
            name: None,
            status: "no structured mutations registered for this scheme".into()
        }));
        assert!(!scheme_ran(&SchemeReport {
            id: Some(1),
            name: Some("eth-block".into()),
            status: "not a scheme-1 W".into()
        }));
        // A cycle maximum the operator set is the attack's; without one, a bounded multiple of the job's.
        assert_eq!(
            attack_cycle_cap((1 << 30, "--max-guest-cycles"), 1 << 20),
            (1 << 30, "--max-guest-cycles".into())
        );
        let (cap, source) = attack_cycle_cap((MAX_HOST_GUEST_CYCLES, "unset"), 1 << 20);
        assert_eq!(cap, ATTACK_CYCLE_MULTIPLE << 20);
        assert!(
            source.starts_with("4 × the job's maxGuestCycles"),
            "{source}"
        );
        assert_eq!(
            attack_cycle_cap((MAX_HOST_GUEST_CYCLES, "unset"), u64::MAX).0,
            MAX_HOST_GUEST_CYCLES
        );
    }

    #[test]
    fn the_da_cap_is_the_configurations() {
        assert_eq!(da_cap_check(2_048, 2_048), None);
        let over = da_cap_check(2_048, 3_010).expect("over the cap");
        assert!(over.contains("OverOperatorCap"), "{over}");
        assert_eq!(da_cap_check(4_000, 3_010), None, "a raised cap admits it");
    }

    #[test]
    fn the_header_length_comes_from_w_or_the_flag() {
        let mut w = b"HPW\x01\x01\x00\x05".to_vec();
        w.extend_from_slice(&[0; 32]);
        assert_eq!(header_length(&w, None), (Some(160), Some("scheme 1 W".into())));
        assert_eq!(header_length(&w, Some(192)).0, Some(192), "the larger");
        assert_eq!(header_length(b"echo", Some(32)), (Some(32), Some("--header-bytes".into())));
        assert_eq!(header_length(b"echo", None), (None, None));
    }

    #[test]
    fn every_broker_configuration_gets_a_spool_of_its_own() {
        let cfg: toml::Value = toml::from_str(
            "spool_dir = \"/home/miner/.zkminer/spool\"\n[[evm_rpc]]\nalias = \"a\"\nurl = \"https://a.example\"\n\
             [[evm_rpc]]\nalias = \"b\"\nurl = \"https://b.example\"\n",
        )
        .unwrap();
        let main: toml::Value = toml::from_str(
            &broker_config_for(
                &cfg,
                Path::new("/etc/b"),
                None,
                Path::new("/work/main/spool"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(main["spool_dir"].as_str(), Some("/work/main/spool"));
        assert_eq!(main["evm_rpc"].as_array().unwrap().len(), 2);
        let one: toml::Value = toml::from_str(
            &broker_config_for(
                &cfg,
                Path::new("/etc/b"),
                Some("b"),
                Path::new("/work/p1/spool"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(one["spool_dir"].as_str(), Some("/work/p1/spool"));
        assert_eq!(one["evm_rpc"].as_array().unwrap().len(), 1);
        assert_eq!(one["evm_rpc"][0]["alias"].as_str(), Some("b"));
        // Written for this user only, never over an existing file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.toml");
        write_private(&path, "x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(write_private(&path, "y").is_err());
    }

    /// A broker configuration whose `key_file`s are relative to its own directory (as the broker
    /// reads them) loads where it is, and still does once copied into a run's work directory: every
    /// relative `key_file` of the copy is the original's, made absolute.
    #[test]
    fn a_relative_key_file_survives_the_copy() {
        use std::os::unix::fs::PermissionsExt;
        use zkminer_witness_broker::config::BrokerConfig;
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        for (name, key) in [("base.key", "secret-key"), ("art.key", "art-key")] {
            let path = a.path().join(name);
            std::fs::write(&path, format!("{key}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let text = format!(
            "chain_rpc_host = \"rpc.example.org\"\nspool_dir = \"{}\"\n[[evm_rpc]]\nalias = \"base-own\"\n\
             url = \"https://base.example.net/v2/{{key}}\"\nchain_id = 8453\narchive = true\nmax_proof_age = 100000\n\
             method_sets = [\"state-read\"]\nkey_file = \"base.key\"\n[[evm_rpc]]\nalias = \"absolute\"\n\
             url = \"https://abs.example.net/v2/{{key}}\"\nchain_id = 8453\nmethod_sets = [\"state-read\"]\n\
             key_file = \"{}\"\n[artifacts]\nalias = \"hemi\"\nurl = \"https://hemi.example.net/\"\nchain_id = 743111\n\
             key_file = \"./art.key\"\nkey_header = \"x-api-key\"\n",
            a.path().join("spool").display(),
            a.path().join("base.key").display(),
        );
        let original = a.path().join("broker.toml");
        std::fs::write(&original, &text).unwrap();
        let mode = zkminer_netguard::NetMode::Public;
        BrokerConfig::load(&original, mode).expect("the operator's own file loads");
        let parsed = read_broker_config(&original).unwrap();
        assert_eq!(parsed.dir, a.path());
        let copied = b.path().join("broker.toml");
        write_private(
            &copied,
            &broker_config_for(&parsed.value, &parsed.dir, None, &b.path().join("spool")).unwrap(),
        )
        .unwrap();
        let again = BrokerConfig::load(&copied, mode).map_err(|e| e.to_string());
        assert!(again.is_ok(), "the copy loads too: {again:?}");
        let v: toml::Value = toml::from_str(&std::fs::read_to_string(&copied).unwrap()).unwrap();
        let base = a.path().join("base.key").display().to_string();
        assert_eq!(v["evm_rpc"][0]["key_file"].as_str(), Some(base.as_str()));
        assert_eq!(
            v["evm_rpc"][1]["key_file"].as_str(),
            Some(base.as_str()),
            "an absolute one is kept"
        );
        let art = a.path().join("./art.key").display().to_string();
        assert_eq!(v["artifacts"]["key_file"].as_str(), Some(art.as_str()));
    }

    #[test]
    fn verdicts_use_stable_names() {
        let v = VerdictReport::new(SkipReason::FulfilDaTooLarge, "claim_gate", "d");
        assert_eq!((v.step.as_str(), v.retry.as_str(), v.retry_max_attempts), ("claim_gate", "backoff", Some(8)));
        let s = Skip::Verdict {
            reason: SkipReason::BindingMismatch,
            step: zkminer_witness_host::pipeline::Step::Binding,
            detail: "x".into(),
        };
        let v = verdict_report(&s).unwrap();
        assert_eq!((v.step.as_str(), v.retry.as_str(), v.retry_max_attempts), ("binding", "once_jittered", None));
        let json = serde_json::to_value(&v).unwrap();
        assert!(json.get("retryMaxAttempts").is_none());
    }
}
