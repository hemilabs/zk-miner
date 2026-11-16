//! The pre-claim pipeline for one witness job (docs/witness-construction-jobs.md §5.2 steps 1–8):
//! everything a miner does on its own host before a witness job may be locked, and nothing that
//! signs or sends.
//!
//! [`simulate_witness_job`] runs, in order:
//!
//! 1. **Static gates** (§5.3): the envelope decodes strictly; builder type 1 (WASM); the risc0
//!    Groth16 proof system; a binding this host serves (FULL, FIELDS, the journal-prefix marker, NONE
//!    only when assigned to this prover; never the SP1 proof-nonce marker); the limits within the
//!    host's maxima (§7.1: `maxWitnessBytes` and `maxGuestCycles` reject, the builder-side limits
//!    clamp); every capability provisioned by the broker; then run.rs's chain gates through
//!    [`PipelineHooks::claimable`] (claimability `eth_call`, submission form, deployment, admission).
//!    Only then the guest ELF ([`PipelineHooks::guest_elf`], unless [`JobInput::elf`] carries it):
//!    nothing is downloaded for a job the static gates refuse.
//! 2. **The builder artifact** (§13.4): the operator mirror, then the job's `hemi-code` locators in
//!    envelope order, at most one of them read past its manifest. The broker answers from its
//!    artifact cache before any read (on the mirror request only when a mirror is configured) and
//!    verifies `sha256 == builderId`; the cost is admitted through
//!    [`PipelineHooks::admit_artifact_charge`] before any chunk is read; the bytes are re-hashed here.
//! 3. **The builder** (§9, §10): the sandboxed runner, `W` streamed into a new bundle version of the
//!    retention store ([`Store::begin_bundle_evicting`]). Any failure drops the writer, which
//!    discards the version.
//! 4. **Execute** (§5.4, §10.1): `W` sealed (read-only, fsynced), `sha256(prefix ‖ W)` streamed from
//!    the sealed file, the `sys_rand` seed derived (the key never leaves this process), and the
//!    sandboxed CPU worker run once at every po2 of the host's set, in its own cgroup, with
//!    `maxGuestCycles` as its cycle cap. Every po2 must halt with 0 and commit the same journal of at
//!    most 32,768 bytes, within `maxGuestCycles`, under an image id equal to `programId`.
//! 5. **Binding** (§7.2): the router's own check (`zkminer_chain::binding`) at every po2, with the
//!    real prover address for prefix jobs.
//! 6. **Publish** (§15.1): the ELF retained under its image id, then the bundle record with every
//!    field of §15.1, verified by the store against what was written, fsynced and renamed into place.
//!
//! The abort token ([`PipelineHooks::abort_token`]) is checked between steps and raced against each
//! of them; a sandbox in flight (the runner, the execute worker) has its cgroup killed when it fires.
//!
//! What stays in run.rs: the remaining claim-gate limits (DA size, gas, reservation, deadline
//! margin, prove resources from [`Simulated::per_po2`]), single flight per jobId, pinning at lock
//! time, revalidation, the lock, the prove dispatch and recovery.

use std::fs::File;
use std::future::Future;
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_primitives::{keccak256, Address, B256};
use alloy_sol_types::SolValue;
use sha2::{Digest, Sha256};
use zkminer_chain::auction::risc_zero_groth16_v1_id;
use zkminer_chain::binding::{check_journal_binding, marker, JOURNAL_PREFIX_MARKER, PROOF_NONCE_MARKER};
use zkminer_chain::descriptor::compute_descriptor_hash;
use zkminer_contracts::bindings::JobDescriptor;
use zkminer_prover::witness_exec::{run_witness_execute, CgroupSpec, WitnessExecError};
use zkminer_prover_protocol::{
    sys_rand, WitnessExecuteFailure, WitnessExecuteRequest, WitnessExecuteResponse, GUEST_EXIT_HALTED,
    RISC0_JOB_PO2_MAX, RISC0_JOB_PO2_MIN,
};
use zkminer_witness::binding::{guest_input_prefix, input_sha256, MAX_JOURNAL_BYTES, PREFIX_BYTES};
use zkminer_witness::bundle::{BundleV1, GuestExit, Po2Result, BUNDLE_FORMAT_VERSION};
use zkminer_witness::context::{build_context, encode_context, DescriptorFields};
use zkminer_witness::cycles;
use zkminer_witness::envelope::{
    decode, effective_limits, usable_builder_sources, BuilderSource, BuilderType, CapabilityKind, Envelope,
    EnvelopeError, HostMaxima, Limits, MethodSet,
};
use zkminer_witness::ipc::{ArtifactFailure, ArtifactSource, JobBudget};
use zkminer_witness::verdict::SkipReason;
use zkminer_witness_broker::client::{ArtifactCharge, ArtifactRequest, BrokerClient, JobRegistration};
use zkminer_witness_broker::egress::sanitize_log;
use zkminer_witness_store::{BundleMeta, BundleRef, BundleWriter, Reject, Store, StoreError};

use crate::abort::{AbortReason, AbortToken};
use crate::builder_run::{run_builder_abortable, BuilderRun, WitnessSink};
use crate::spawner::Spawner;

/// risc0's image-id computation (or a lookup of ids the caller already verified): `None` when the
/// bytes are not an ELF it knows.
pub type ImageIdFn = Arc<dyn Fn(&[u8]) -> Option<B256> + Send + Sync>;
/// The eviction value of an unpinned bundle (lowest evicted first, §15.2).
pub type EvictionValueFn = Arc<dyn Fn(&BundleMeta) -> u64 + Send + Sync>;
/// A hook's answer.
pub type HookFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The `pids.max` of an execute cgroup: the worker runs in two tasks (its main thread and the
/// executor's segment thread); the rest is slack.
pub const EXECUTE_PIDS_MAX: u32 = 4;
/// The `cpu.weight` of simulation sandboxes (§10.2: a low-priority cgroup).
pub const SIMULATION_CPU_WEIGHT: u32 = 20;
/// The longest diagnostic text a [`Skip`] carries.
pub const MAX_DETAIL_BYTES: usize = 4_096;
/// How often a fired abort token re-sends `cgroup.kill` until the execute worker is gone (the
/// worker's cgroup may not exist yet when the token fires).
const EXECUTE_KILL_RETRY: Duration = Duration::from_millis(50);

/// Everything the pipeline needs from the host: long-lived processes and handles, and its
/// configuration. Holds the `sys_rand` key, which is only ever used here to derive seeds: no
/// sandbox, log or record sees it (the bundle records its fingerprint).
pub struct HostContext {
    pub spawner: Spawner,
    pub broker: Arc<BrokerClient>,
    pub store: Arc<Store>,
    /// The delegated cgroup directory sandboxes are created in.
    pub cgroup_root: PathBuf,
    /// The builder runner (`zkminer-witness-builder`).
    pub builder_binary: PathBuf,
    /// The risc0 CPU worker, run with `--witness-execute` (`zkminer-prove-risc0-cpu`).
    pub execute_binary: PathBuf,
    /// `[witness]` maxima and builder clamps; the hard ceilings of §9.1 apply on top.
    pub host_maxima: HostMaxima,
    /// The po2 of every card that may prove a witness job: each is executed (§5.1 rule 2).
    pub po2s: Vec<u8>,
    /// `RISC0_KECCAK_PO2` of the provers (guest-visible, §5.4).
    pub keccak_po2: u8,
    pub sys_rand_key: [u8; 32],
    /// The build id of every prove worker that may prove a bundle (§15.1), as
    /// [`risc0_build_id`] names it. The bundle records these and the execute worker's own (from its
    /// response).
    pub worker_builds: Vec<String>,
    /// `memory.max` of one execute (`[witness] execute_memory_bytes`).
    pub execute_memory_bytes: u64,
    /// Wall clock of one execute (all po2s); past it the worker's cgroup is killed.
    pub execute_timeout: Duration,
    /// The largest builder artifact this host reads (the broker also caps it at its
    /// `[artifacts] max_builder_bytes`).
    pub max_artifact_bytes: u64,
    /// Verifies the guest ELF's image id when it is retained ([`Store::put_elf`]). CPU-heavy for a
    /// real computation: it runs on a blocking thread.
    pub image_id_fn: ImageIdFn,
    /// Which unpinned bundles go first when the store needs room for a new one.
    pub eviction_value: EvictionValueFn,
}

/// The default eviction value: the block a bundle was created at (oldest first).
pub fn eviction_by_age() -> EvictionValueFn {
    Arc::new(|m: &BundleMeta| m.record.as_ref().map(|r| r.created_at_block).unwrap_or(0))
}

/// One job, as run.rs has it before simulation.
pub struct JobInput<'a> {
    pub job_id: B256,
    /// The descriptor decoded from the submit transaction, already checked against
    /// `descriptor_hash` (re-checked here).
    pub descriptor: &'a JobDescriptor,
    pub descriptor_hash: B256,
    pub submit_tx_hash: B256,
    /// The job's caller (its submitter).
    pub caller: Address,
    /// This host's staked prover: the address in the journal prefix and in the bundle key.
    pub prover: Address,
    /// The HemiProve chain id and router (the builder context's `hemiChainId`/`router`; `hemi-code`
    /// locators for another chain are ignored).
    pub chain_id: u64,
    pub router: Address,
    /// The guest ELF, with its image id checked against `programId`; `None` to have
    /// [`PipelineHooks::guest_elf`] fetch it once the static gates have passed.
    pub elf: Option<&'a [u8]>,
    /// The current block number (the bundle's `created_at_block`).
    pub current_block: u64,
}

/// The decisions that depend on the chain and on admission, which stay in run.rs.
pub trait PipelineHooks: Send + Sync {
    /// The chain-side static gates of §5.3 (the claimability `eth_call` of `claimJob(jobId, 0, 0)`,
    /// its price against the reservation, the submission form, the deployment's core pins, admission
    /// and the self-test). Called once, after every local static gate and the provisioning check have
    /// passed and before any artifact or builder work; `Err` skips the job with that reason.
    fn claimable(&self) -> HookFuture<'_, Result<(), SkipReason>>;

    /// §13.4 step 3: a `hemi-code` read that is not cached will read `charge.length` bytes in
    /// `charge.chunks` chunk reads (plus the manifest). `true` admits it; `false` ends the attempt
    /// with [`SkipReason::NotAdmitted`] before any chunk is read.
    fn admit_artifact_charge(&self, charge: ArtifactCharge) -> HookFuture<'_, bool>;

    /// Fired by run.rs on `JobCancelled`, `JobClaimed` by another prover, `BidSubmitted` and the
    /// governance events that end an attempt.
    fn abort_token(&self) -> &AbortToken;

    /// §5.2 step 3: the guest ELF (today's ELF path), its image id checked against `programId`.
    /// Called once, after the static gates passed and before the artifact, when [`JobInput::elf`] is
    /// `None`; `Err` skips the job with that verdict.
    fn guest_elf(&self) -> HookFuture<'_, Result<Vec<u8>, (SkipReason, String)>> {
        Box::pin(async { Err((SkipReason::HostInternal, "no guest ELF source".to_string())) })
    }
}

/// The build id a witness bundle records for a risc0 worker: its SDK and worker versions as its
/// `Hello` (or a witness execute's response) names them.
pub fn risc0_build_id(sdk_version: &str, worker_version: &str) -> String {
    format!("risc0/{sdk_version}/{worker_version}")
}

/// Where in the pipeline a job was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    StaticGates,
    Artifact,
    Builder,
    Execute,
    Binding,
    Publish,
}

/// Why a simulation produced no bundle. Nothing was published; a bundle version that was being
/// written was discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// A §16 verdict: record it under its retry policy ([`SkipReason::verdict`]). `detail` is
    /// diagnostic text for logs (sanitized, at most [`MAX_DETAIL_BYTES`]); it can carry builder or
    /// guest output, so nothing may branch on it.
    Verdict { reason: SkipReason, step: Step, detail: String },
    /// The abort token fired: the attempt was abandoned, and nothing about the job is judged.
    Aborted { reason: AbortReason, step: Step },
}

impl Skip {
    fn new(reason: SkipReason, step: Step, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Skip::Verdict { reason, step, detail: sanitize_log(detail.as_bytes(), MAX_DETAIL_BYTES) }
    }

    /// The verdict, unless the attempt was aborted.
    pub fn reason(&self) -> Option<SkipReason> {
        match self {
            Skip::Verdict { reason, .. } => Some(*reason),
            Skip::Aborted { .. } => None,
        }
    }

    pub fn step(&self) -> Step {
        match self {
            Skip::Verdict { step, .. } | Skip::Aborted { step, .. } => *step,
        }
    }
}

impl std::fmt::Display for Skip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Skip::Verdict { reason, step, detail } => write!(f, "skipped at {step:?}: {reason:?} ({detail})"),
            Skip::Aborted { reason, step } => write!(f, "aborted at {step:?}: {reason:?}"),
        }
    }
}

/// Where the builder artifact came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactOrigin {
    Mirror,
    HemiCode { manifest: Address },
}

/// What the builder run cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderStats {
    pub artifact_origin: ArtifactOrigin,
    pub artifact_bytes: u64,
    /// Served from the broker's cache, with no endpoint reads.
    pub artifact_cached: bool,
    pub fetches: u32,
    pub fetch_bytes: u64,
    /// `None` when the runner could not know it (see `BuilderSummary::fuel_used`).
    pub fuel_used: Option<u64>,
    pub compile_ms: Option<u32>,
    pub run_ms: Option<u32>,
    /// The run's wall time as the miner saw it (job registration to `EndJob`).
    pub wall: Duration,
}

/// Wall time per step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timings {
    pub static_gates: Duration,
    pub artifact: Duration,
    pub builder: Duration,
    pub execute: Duration,
    pub publish: Duration,
    pub total: Duration,
}

/// One po2's execution, beyond what the bundle records: what the claim gate's prove-resources check
/// needs (§15.3: segment disk, host RAM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutedPo2 {
    pub po2: u32,
    /// Sized cycles (the `maxGuestCycles` unit).
    pub cycles: u64,
    pub segment_bytes: u64,
    /// The execute worker's peak resident set after this po2 (a process-wide high-water mark).
    pub peak_host_bytes: u64,
}

/// A published, unpinned bundle whose journals satisfy the binding at every po2 of the host's set.
#[derive(Debug, Clone)]
pub struct Simulated {
    pub bundle: BundleRef,
    /// The record as published.
    pub record: BundleV1,
    /// The journal (identical at every po2).
    pub journal: Vec<u8>,
    pub per_po2: Vec<ExecutedPo2>,
    pub w_len: u64,
    pub w_sha256: B256,
    /// `sha256(prefix ‖ W)`.
    pub input_sha256: B256,
    pub prefix: bool,
    /// The effective (clamped) limits the job ran under.
    pub limits: Limits,
    pub builder: BuilderStats,
    pub timings: Timings,
    /// The execute worker's build ([`risc0_build_id`]), which the bundle records with the prove
    /// workers'.
    pub execute_build: String,
}

/// `abi.encode(descriptor)`: what a bundle records as `descriptor_hex`.
pub fn descriptor_abi(d: &JobDescriptor) -> Vec<u8> {
    d.abi_encode()
}

/// The descriptor hash of `abi.encode(descriptor)` bytes, `None` unless they are the canonical
/// encoding of a descriptor: the store's `descriptor_hash_fn` for witness bundles.
pub fn descriptor_hash_of_abi(bytes: &[u8]) -> Option<B256> {
    let d = JobDescriptor::abi_decode(bytes).ok()?;
    (d.abi_encode() == bytes).then(|| compute_descriptor_hash(&d))
}

/// The bundle's `sys_rand_key_fingerprint` for `key`.
pub fn key_fingerprint(key: &[u8; 32]) -> B256 {
    B256::from(sys_rand::key_fingerprint(key))
}

static JOB_SEQ: AtomicU64 = AtomicU64::new(0);

/// The broker job key and sandbox name of one attempt: unique per attempt, so a broker that still
/// holds an earlier attempt's registration never refuses this one.
fn attempt_key(job: &JobInput<'_>) -> B256 {
    let mut b = Vec::with_capacity(26 + 32 + 32 + 20 + 8 + 4);
    b.extend_from_slice(b"zkminer/witness/attempt/v1");
    b.extend_from_slice(job.job_id.as_slice());
    b.extend_from_slice(job.descriptor_hash.as_slice());
    b.extend_from_slice(job.prover.as_slice());
    b.extend_from_slice(&JOB_SEQ.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    b.extend_from_slice(&std::process::id().to_be_bytes());
    keccak256(&b)
}

/// The last (at most) `n` bytes of `s`, cut at a character boundary.
fn tail(s: &str, n: usize) -> &str {
    let mut at = s.len().saturating_sub(n);
    while !s.is_char_boundary(at) {
        at += 1;
    }
    &s[at..]
}

fn short(b: B256) -> String {
    hex::encode(&b.0[..6])
}

/// The token's reason, or a step's `Aborted` once it fired.
fn check_abort(token: &AbortToken, step: Step) -> Result<(), Skip> {
    match token.reason() {
        Some(reason) => Err(Skip::Aborted { reason, step }),
        None => Ok(()),
    }
}

/// Races `fut` against the token; the token wins a tie.
async fn abortable<T>(token: &AbortToken, step: Step, fut: impl Future<Output = T>) -> Result<T, Skip> {
    tokio::select! {
        biased;
        reason = token.aborted() => Err(Skip::Aborted { reason, step }),
        v = fut => Ok(v),
    }
}

/// Runs `f` on a blocking thread (store I/O, hashing, the image id).
async fn blocking<T: Send + 'static>(step: Step, f: impl FnOnce() -> T + Send + 'static) -> Result<T, Skip> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Skip::new(SkipReason::HostInternal, step, format!("blocking task: {e}")))
}

/// A store error as a verdict: a full store is `RetentionFull`; a witness past the writer's limit is
/// the builder's; anything else is this host's.
fn store_reason(e: &StoreError) -> SkipReason {
    match e {
        StoreError::RetentionFull(_) => SkipReason::RetentionFull,
        StoreError::Rejected(Reject::WitnessTooLarge { .. }) => SkipReason::BuilderWitnessTooLarge,
        _ => SkipReason::HostInternal,
    }
}

fn store_skip(e: &StoreError, step: Step) -> Skip {
    Skip::new(store_reason(e), step, format!("retention store: {e}"))
}

// ---------------------------------------------------------------------------------------------
// Step 1: static gates.

/// What the static gates established.
struct Gated {
    envelope: Envelope,
    limits: Limits,
    prefix: Option<[u8; PREFIX_BYTES]>,
    po2s: Vec<u8>,
}

/// How an envelope error is judged: malformed bytes, or well-formed but out of range.
pub fn envelope_reason(e: &EnvelopeError) -> SkipReason {
    use EnvelopeError::*;
    match e {
        NotWitnessJob | Undecodable | BodyTooLarge | NonCanonical => SkipReason::EnvelopeMalformed,
        UnknownBuilderType | TooManyUris | UriTooLong | ParamsTooLong | SourcesCount | ConfigTooLong | UnknownClass
        | BadConfig | UnknownMethodSet | RequestBytesOutOfRange => SkipReason::EnvelopeOutOfRange,
    }
}

/// Whether this host serves the job's binding (§5.3): FULL, FIELDS and the journal-prefix marker;
/// NONE (no `expectedJournalHash`, with or without the prefix) only when the job is assigned to this
/// prover; never the SP1 proof-nonce marker, which binds a seal this host does not produce.
pub fn binding_served(d: &JobDescriptor, prover: Address) -> Result<(), &'static str> {
    match marker(d.journalFields) {
        None | Some(JOURNAL_PREFIX_MARKER) => {}
        Some(PROOF_NONCE_MARKER) => return Err("the SP1 proof-nonce marker"),
        Some(_) => return Err("an unknown journalFields marker"),
    }
    if d.expectedJournalHash == B256::ZERO && d.assignedProver != prover {
        return Err("a NONE binding not assigned to this prover");
    }
    Ok(())
}

/// The host's po2 set, sorted and unique, each a job po2 the worker accepts.
fn host_po2s(po2s: &[u8]) -> Result<Vec<u8>, String> {
    let mut v = po2s.to_vec();
    v.sort_unstable();
    v.dedup();
    if v.is_empty() {
        return Err("the host's po2 set is empty".into());
    }
    if let Some(p) = v.iter().find(|p| !(RISC0_JOB_PO2_MIN..=RISC0_JOB_PO2_MAX).contains(p)) {
        return Err(format!("po2 {p} is outside {RISC0_JOB_PO2_MIN}..={RISC0_JOB_PO2_MAX}"));
    }
    Ok(v)
}

async fn static_gates(ctx: &HostContext, job: &JobInput<'_>, hooks: &dyn PipelineHooks) -> Result<Gated, Skip> {
    const S: Step = Step::StaticGates;
    let token = hooks.abort_token();
    let skip = |r, d: &str| Skip::new(r, S, d);
    let po2s = host_po2s(&ctx.po2s).map_err(|e| skip(SkipReason::HostInternal, &e))?;
    if !(14..=18).contains(&ctx.keccak_po2) {
        return Err(skip(SkipReason::HostInternal, "the keccak po2 is outside 14..=18"));
    }
    let d = job.descriptor;
    if compute_descriptor_hash(d) != job.descriptor_hash {
        return Err(skip(SkipReason::HostInternal, "the descriptor does not hash to descriptorHash"));
    }
    let envelope = decode(&d.inputData).map_err(|e| skip(envelope_reason(&e), &e.to_string()))?;
    if envelope.builder_type != BuilderType::Wasm {
        return Err(skip(SkipReason::UnsupportedBuilderType, "only builder type 1 (WASM) is served"));
    }
    if d.proofSystemId != risc_zero_groth16_v1_id() {
        return Err(skip(SkipReason::UnsupportedProofSystem, "only risczero.groth16.v1 is served"));
    }
    binding_served(d, job.prover).map_err(|why| skip(SkipReason::UnsupportedBinding, why))?;
    let limits = effective_limits(&envelope.job.limits, &ctx.host_maxima)
        .map_err(|e| skip(SkipReason::LimitsAboveHostMaxima, &e.to_string()))?;
    if envelope.capabilities.iter().any(|c| matches!(c, CapabilityKind::EvmRpcV1 { method_set: MethodSet::StateTrace, .. })) {
        return Err(skip(SkipReason::CapabilityNotProvisioned, "state-trace is not served in this phase"));
    }
    let sources: Vec<(B256, Vec<u8>)> = envelope.job.sources.iter().map(|c| (c.class, c.config.to_vec())).collect();
    let provisioned = abortable(token, S, ctx.broker.check_provisioned(sources))
        .await?
        .map_err(|e| skip(SkipReason::HostInternal, &format!("broker CheckProvisioned: {e}")))?;
    if let Some(i) = provisioned.iter().position(|ok| !ok) {
        return Err(skip(SkipReason::CapabilityNotProvisioned, &format!("capability {i} is not provisioned")));
    }
    check_abort(token, S)?;
    abortable(token, S, hooks.claimable()).await?.map_err(|r| skip(r, "the chain gates (run.rs)"))?;
    let prefix = guest_input_prefix(d.journalFields, job.job_id, job.prover);
    Ok(Gated { envelope, limits, prefix, po2s })
}

// ---------------------------------------------------------------------------------------------
// Step 2: the builder artifact.

struct Artifact {
    bytes: Vec<u8>,
    cached: bool,
    origin: ArtifactOrigin,
}

/// How one source's failure counts toward the job's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceOutcome {
    /// Present and permanently bad for this job (structure, chunks, hash, another artifact).
    Bad,
    /// No manifest code (unpublished, reorged away, wrong address): transient, at most three
    /// retries per job.
    Empty,
    /// Larger than this host reads.
    TooLarge,
    /// The operator's side: endpoint errors, timeouts, a mirror that misbehaved.
    Operator,
    /// Not available here: no artifact endpoint, no mirror, the mirror does not have it.
    Absent,
}

fn source_outcome(f: ArtifactFailure, mirror: bool) -> SourceOutcome {
    use ArtifactFailure::*;
    match f {
        ManifestInvalid { .. } | ChunkInvalid { .. } | HashMismatch { .. } | IdMismatch => SourceOutcome::Bad,
        EmptyManifest => SourceOutcome::Empty,
        // A mirror's oversize body is unverified: the operator's mirror, not the job.
        TooLarge if mirror => SourceOutcome::Operator,
        TooLarge => SourceOutcome::TooLarge,
        NotConfigured | MirrorMissing => SourceOutcome::Absent,
        Endpoint | MirrorMismatch | Budget => SourceOutcome::Operator,
    }
}

/// The job's verdict when no source yielded the artifact: an operator-side failure anywhere may
/// clear (`OperatorEndpoint`); an empty manifest or no usable source is `ArtifactUnavailable`; a
/// manifest too large for this host is the host's limit; only when every `hemi-code` source tried
/// is present and bad is it `ArtifactAllSourcesBad`.
fn artifact_reason(mirror: SourceOutcome, hemi_code: &[SourceOutcome]) -> SkipReason {
    let all = std::iter::once(mirror).chain(hemi_code.iter().copied());
    let any = |o: SourceOutcome| all.clone().any(|x| x == o);
    if any(SourceOutcome::Operator) {
        SkipReason::OperatorEndpoint
    } else if any(SourceOutcome::Empty) || hemi_code.is_empty() || hemi_code.contains(&SourceOutcome::Absent) {
        SkipReason::ArtifactUnavailable
    } else if any(SourceOutcome::TooLarge) {
        SkipReason::LimitsAboveHostMaxima
    } else {
        SkipReason::ArtifactAllSourcesBad
    }
}

async fn obtain_artifact(
    ctx: &HostContext,
    job: &JobInput<'_>,
    envelope: &Envelope,
    job_key: B256,
    hooks: &dyn PipelineHooks,
) -> Result<Artifact, Skip> {
    const S: Step = Step::Artifact;
    let token = hooks.abort_token();
    let builder_id = envelope.job.builderId;
    let builder_type = BuilderType::Wasm.as_u8();
    let request = |source| ArtifactRequest {
        job_key,
        caller: job.caller,
        source,
        builder_type,
        expected_sha256: Some(builder_id),
        max_bytes: ctx.max_artifact_bytes,
        held_lock: false,
    };
    let control = |e| Skip::new(SkipReason::HostInternal, S, format!("broker FetchArtifact: {e}"));

    // The operator mirror (the broker answers from its cache first).
    let mirror = abortable(
        token,
        S,
        ctx.broker.fetch_artifact(request(ArtifactSource::Mirror { builder_type, builder_id }), |_| async { true }),
    )
    .await?
    .map_err(control)?;
    let mirror = match mirror {
        Ok(a) => return verify_artifact(ctx, a, builder_id, ArtifactOrigin::Mirror),
        Err(f) => {
            tracing::debug!(job = %job.job_id, failure = ?f, "builder artifact: not from the mirror");
            source_outcome(f, true)
        }
    };

    // `hemi-code`, in envelope order; at most one locator is read past its manifest.
    let (usable, ignored) = usable_builder_sources(&envelope.job, job.chain_id);
    if !ignored.is_empty() {
        tracing::debug!(job = %job.job_id, ?ignored, "builder artifact: ignored builderURIs");
    }
    let mut outcomes = Vec::new();
    for BuilderSource::HemiCode(loc) in usable {
        let mut charged = false;
        let fetched = abortable(
            token,
            S,
            ctx.broker.fetch_artifact(request(ArtifactSource::HemiCode { chain_id: loc.chain_id, manifest: loc.manifest }), |c| {
                charged = true;
                hooks.admit_artifact_charge(c)
            }),
        )
        .await?
        .map_err(control)?;
        match fetched {
            Ok(a) => return verify_artifact(ctx, a, builder_id, ArtifactOrigin::HemiCode { manifest: loc.manifest }),
            // Only the charge hook refuses with `Budget`.
            Err(ArtifactFailure::Budget) if charged => {
                return Err(Skip::new(SkipReason::NotAdmitted, S, "the artifact read was not admitted"));
            }
            Err(f) => {
                tracing::info!(job = %job.job_id, manifest = %loc.manifest, failure = ?f, "builder artifact: hemi-code source failed");
                outcomes.push(source_outcome(f, false));
                if charged {
                    break;
                }
            }
        }
    }
    let reason = artifact_reason(mirror, &outcomes);
    Err(Skip::new(reason, S, format!("no source yielded the artifact (mirror {mirror:?}, hemi-code {outcomes:?})")))
}

/// Reads the broker's sealed memfd and re-hashes it: the bytes the runner gets are `builderId`'s.
fn verify_artifact(
    ctx: &HostContext,
    a: zkminer_witness_broker::client::FetchedArtifact,
    builder_id: B256,
    origin: ArtifactOrigin,
) -> Result<Artifact, Skip> {
    let bad = |d: String| Skip::new(SkipReason::HostInternal, Step::Artifact, d);
    if a.len > ctx.max_artifact_bytes {
        return Err(bad(format!("the broker served {} bytes, above the {}-byte cap", a.len, ctx.max_artifact_bytes)));
    }
    let len = usize::try_from(a.len).map_err(|_| bad("artifact length".into()))?;
    let mut bytes = vec![0u8; len];
    // `pread`: a cached artifact's offset is shared with the broker.
    a.memfd.read_exact_at(&mut bytes, 0).map_err(|e| bad(format!("reading the artifact memfd: {e}")))?;
    let sha = B256::from(<[u8; 32]>::from(Sha256::digest(&bytes)));
    if sha != builder_id || a.sha256 != builder_id {
        return Err(bad("the broker served an artifact that does not hash to builderId".into()));
    }
    Ok(Artifact { bytes, cached: a.cached, origin })
}

// ---------------------------------------------------------------------------------------------
// Step 3: the builder, W into the store.

/// The store's writer as the builder's W sink; keeps the typed error.
struct StoreSink {
    writer: BundleWriter,
    error: Option<StoreError>,
}

impl WitnessSink for StoreSink {
    fn write(&mut self, chunk: &[u8]) -> Result<(), String> {
        self.writer.write_w(chunk).map_err(|e| {
            let msg = e.to_string();
            self.error = Some(e);
            msg
        })
    }
}

/// `prefix ‖ W` hashing that also hashes `W` alone.
struct Tee {
    file: File,
    w: Sha256,
}

impl Read for Tee {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read(buf)?;
        self.w.update(&buf[..n]);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------------------------
// Steps 4–5: execute and check.

/// Checks an execute response against the job (§5.2 steps 6–7): the image id is `programId`; every
/// po2 of the request halted with 0; one journal at every po2; cycles within `maxGuestCycles`; the
/// journal within the 32,768-byte cap. Returns the journal.
fn check_execution(
    resp: &WitnessExecuteResponse,
    po2s: &[u8],
    program_id: B256,
    max_guest_cycles: u64,
) -> Result<Vec<u8>, (SkipReason, String)> {
    if B256::from(resp.image_id) != program_id {
        return Err((SkipReason::ElfImageIdMismatch, format!("the ELF's image id is 0x{}", hex::encode(resp.image_id))));
    }
    for r in &resp.results {
        if r.exit_kind != GUEST_EXIT_HALTED || r.exit_code != 0 {
            return Err((
                SkipReason::GuestFailed,
                format!("po2 {}: the guest ended with exit kind {} code {}", r.po2, r.exit_kind, r.exit_code),
            ));
        }
    }
    let got: Vec<u8> = resp.results.iter().map(|r| r.po2).collect();
    if got != po2s {
        return Err((SkipReason::HostInternal, format!("executed po2s {got:?}, requested {po2s:?}")));
    }
    let first = &resp.results[0];
    if let Some(r) = resp.results.iter().find(|r| (r.journal_len, r.journal_sha256) != (first.journal_len, first.journal_sha256)) {
        return Err((SkipReason::JournalsDifferAcrossPo2, format!("po2 {} and po2 {} commit different journals", first.po2, r.po2)));
    }
    if !cycles::within_limit(resp.results.iter().map(|r| r.cycles), max_guest_cycles) {
        let max = cycles::max_over_po2s(resp.results.iter().map(|r| r.cycles)).unwrap_or(0);
        return Err((SkipReason::GuestCyclesAboveLimit, format!("{max} sized cycles, maxGuestCycles {max_guest_cycles}")));
    }
    if first.journal_len as usize > MAX_JOURNAL_BYTES {
        return Err((SkipReason::JournalTooLarge, format!("a {}-byte journal", first.journal_len)));
    }
    Ok(first.journal.clone())
}

/// How an execute that produced no response is judged.
fn execute_reason(e: &WitnessExecError) -> SkipReason {
    use WitnessExecuteFailure as F;
    match e {
        // The guest's cycles are capped by `maxGuestCycles`: running out of the operator's time or
        // memory is this host's resources, not the job.
        WitnessExecError::Timeout { .. } | WitnessExecError::OomKilled { .. } => SkipReason::ProveResources,
        WitnessExecError::Exit { failure: Some(f), .. } => match f {
            F::InvalidElf | F::GuestFault | F::Unprovable | F::Panicked => SkipReason::GuestFailed,
            F::CycleLimit => SkipReason::GuestCyclesAboveLimit,
            F::BadRequest | F::InputMismatch | F::Sandbox | F::Internal | F::Unsupported => SkipReason::HostInternal,
        },
        _ => SkipReason::HostInternal,
    }
}

fn execute_detail(e: &WitnessExecError) -> String {
    let tail = e.log_tail().map(|t| sanitize_log(t.as_bytes(), MAX_DETAIL_BYTES / 2)).unwrap_or_default();
    format!("{e}; log tail: {tail}")
}

/// Runs the sandboxed execute on a thread of its own (the worker's `PR_SET_PDEATHSIG` is tied to the
/// spawning thread, which stays until the worker is gone), killing its cgroup when the token fires.
async fn execute(
    ctx: &HostContext,
    token: &AbortToken,
    req: WitnessExecuteRequest,
    w: File,
    cgroup_name: String,
) -> Result<WitnessExecuteResponse, Skip> {
    const S: Step = Step::Execute;
    let kill_path = ctx.cgroup_root.join(&cgroup_name).join("cgroup.kill");
    let spec = CgroupSpec {
        name: cgroup_name,
        memory_max: ctx.execute_memory_bytes,
        pids_max: EXECUTE_PIDS_MAX,
        cpu_max: None,
        cpu_weight: SIMULATION_CPU_WEIGHT,
    };
    let (binary, root, timeout) = (ctx.execute_binary.clone(), ctx.cgroup_root.clone(), ctx.execute_timeout);
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("witness-execute".into())
        .spawn(move || {
            let r = run_witness_execute(&binary, &root, spec, &req, w.as_fd(), timeout);
            drop(w);
            let _ = tx.send(r);
        })
        .map_err(|e| Skip::new(SkipReason::HostInternal, S, format!("spawning the execute thread: {e}")))?;
    let mut finished = None;
    let mut aborted = None;
    tokio::select! {
        biased;
        r = &mut rx => finished = Some(r),
        reason = token.aborted() => aborted = Some(reason),
    }
    if let Some(reason) = aborted {
        // Until the worker is gone: its cgroup may not exist yet when the token fires.
        loop {
            let _ = std::fs::write(&kill_path, "1");
            tokio::select! {
                _ = &mut rx => break,
                _ = tokio::time::sleep(EXECUTE_KILL_RETRY) => {}
            }
        }
        return Err(Skip::Aborted { reason, step: S });
    }
    let result = finished
        .expect("one branch completed")
        .map_err(|_| Skip::new(SkipReason::HostInternal, S, "the execute thread died"))?;
    result.map_err(|e| Skip::new(execute_reason(&e), S, execute_detail(&e)))
}

// ---------------------------------------------------------------------------------------------
// The pipeline.

/// Simulates one witness job before any lock (§5.2 steps 1–8): see the module docs. On success the
/// bundle is published (unpinned: run.rs pins it at lock time); on any failure nothing is.
pub async fn simulate_witness_job(
    ctx: &HostContext,
    job: &JobInput<'_>,
    hooks: &dyn PipelineHooks,
) -> Result<Simulated, Skip> {
    let started = Instant::now();
    let token = hooks.abort_token();
    let mut timings = Timings::default();
    let d = job.descriptor;
    let program_id = d.programId;

    // 1. Static gates.
    check_abort(token, Step::StaticGates)?;
    let Gated { envelope, limits, prefix, po2s } = static_gates(ctx, job, hooks).await?;
    let fetched_elf;
    let elf: &[u8] = match job.elf {
        Some(e) => e,
        None => {
            fetched_elf = abortable(token, Step::StaticGates, hooks.guest_elf())
                .await?
                .map_err(|(r, d)| Skip::new(r, Step::StaticGates, format!("the guest ELF: {d}")))?;
            &fetched_elf
        }
    };
    timings.static_gates = started.elapsed();
    let job_key = attempt_key(job);
    tracing::info!(job = %job.job_id, attempt = %short(job_key), ?po2s, prefix = prefix.is_some(), "witness job: static gates passed");

    // 2. The builder artifact.
    check_abort(token, Step::Artifact)?;
    let t = Instant::now();
    let artifact = obtain_artifact(ctx, job, &envelope, job_key, hooks).await?;
    timings.artifact = t.elapsed();

    // 3. The builder, W into a new bundle version.
    const B: Step = Step::Builder;
    check_abort(token, B)?;
    let t = Instant::now();
    let fields = DescriptorFields {
        program_id,
        proof_system_id: d.proofSystemId,
        expected_journal_hash: d.expectedJournalHash,
        journal_fields: d.journalFields,
    };
    let context = encode_context(&build_context(job.chain_id, job.router, &fields, &envelope.job));
    let writer = {
        let (store, value) = (ctx.store.clone(), ctx.eviction_value.clone());
        let (job_id, descriptor_hash, prover, max) = (job.job_id, job.descriptor_hash, job.prover, limits.maxWitnessBytes);
        blocking(B, move || store.begin_bundle_evicting(job_id, descriptor_hash, prover, max, &*value))
            .await?
            .map_err(|e| store_skip(&e, B))?
    };
    let registration = JobRegistration {
        job_key,
        caller: job.caller,
        sources: envelope.job.sources.iter().map(|c| (c.class, c.config.to_vec())).collect(),
        budget: JobBudget {
            max_fetches: limits.maxFetches,
            max_fetch_bytes: limits.maxFetchBytes,
            max_request_bytes: limits.maxRequestBytes,
            max_response_bytes: limits.maxResponseBytes,
        },
        held_lock: false,
    };
    let run = BuilderRun {
        binary: &ctx.builder_binary,
        cgroup_root: &ctx.cgroup_root,
        job_key,
        module: &artifact.bytes,
        context: &context,
        limits: &limits,
    };
    let (result, sink) = run_builder_abortable(
        &ctx.spawner,
        &ctx.broker,
        &run,
        registration,
        StoreSink { writer, error: None },
        token,
    )
    .await
    .map_err(|e| Skip::new(SkipReason::HostInternal, B, format!("builder run: {e:#}")))?;
    let StoreSink { writer, error } = sink;
    if result.aborted {
        return Err(Skip::Aborted { reason: token.reason().unwrap_or(AbortReason::Shutdown), step: B });
    }
    if let Some(e) = error {
        return Err(store_skip(&e, B));
    }
    if let Some(reason) = result.verdict {
        let detail = format!("outcome {:?}; log: {}", result.outcome, tail(&result.log, MAX_DETAIL_BYTES / 2));
        return Err(Skip::new(reason, B, detail));
    }
    if result.w_bytes != writer.written() {
        return Err(Skip::new(SkipReason::HostInternal, B, "W read and W stored differ in length"));
    }
    let summary = result.summary;
    let builder_stats = BuilderStats {
        artifact_origin: artifact.origin,
        artifact_bytes: artifact.bytes.len() as u64,
        artifact_cached: artifact.cached,
        fetches: result.stats.map(|s| s.fetches).unwrap_or(0),
        fetch_bytes: result.stats.map(|s| s.fetch_bytes).unwrap_or(0),
        fuel_used: summary.map(|s| s.fuel_used).filter(|&f| f != zkminer_witness::ipc::FUEL_USED_UNKNOWN),
        compile_ms: summary.map(|s| s.compile_ms),
        run_ms: summary.map(|s| s.run_ms),
        wall: result.elapsed,
    };
    drop(artifact);
    timings.builder = t.elapsed();
    tracing::info!(job = %job.job_id, w_len = writer.written(), fetches = builder_stats.fetches, "witness job: builder done");

    // 4. Seal W, hash prefix ‖ W from the sealed file, execute at every po2.
    const E: Step = Step::Execute;
    check_abort(token, E)?;
    let t = Instant::now();
    let (writer, w_file, input, w_sha256, w_len) = blocking(E, move || {
        let mut writer = writer;
        let file = writer.seal_w().map_err(|e| store_skip(&e, E))?;
        let mut tee = Tee { file, w: Sha256::new() };
        let (input, len) = input_sha256(prefix.as_ref(), &mut tee)
            .map_err(|e| Skip::new(SkipReason::HostInternal, E, format!("hashing the sealed W: {e}")))?;
        let w_sha = B256::from(<[u8; 32]>::from(tee.w.finalize()));
        Ok::<_, Skip>((writer, tee.file, input, w_sha, len))
    })
    .await??;
    if w_len != writer.written() {
        return Err(Skip::new(SkipReason::HostInternal, E, "the sealed W is not what was written"));
    }
    let seed = sys_rand::risc0_seed(&ctx.sys_rand_key, &program_id.0, &input.0);
    let req = WitnessExecuteRequest {
        elf: elf.to_vec(),
        prefix: prefix.map(|p| p.to_vec()).unwrap_or_default(),
        w_len,
        input_sha256: input.0,
        sys_rand_seed: seed,
        po2s: po2s.clone(),
        keccak_po2: ctx.keccak_po2,
        max_cycles: Some(limits.maxGuestCycles),
    };
    let resp = execute(ctx, token, req, w_file, format!("wexec-{}", short(job_key))).await?;
    let journal = check_execution(&resp, &po2s, program_id, limits.maxGuestCycles).map_err(|(r, d)| Skip::new(r, E, d))?;
    timings.execute = t.elapsed();
    let execute_build = risc0_build_id(&resp.sdk_version, &resp.worker_version);
    let mut worker_builds: Vec<String> = ctx.worker_builds.iter().cloned().chain([execute_build.clone()]).collect();
    worker_builds.sort();
    worker_builds.dedup();
    let execute_ms_per_po2 = (timings.execute.as_millis() as u64).div_ceil(po2s.len().max(1) as u64);

    // 5. The binding at every po2, as the router judges it, with the real prover.
    const BI: Step = Step::Binding;
    for r in &resp.results {
        check_journal_binding(d, &journal, job.job_id, job.prover)
            .map_err(|m| Skip::new(SkipReason::BindingMismatch, BI, format!("po2 {}: {m}", r.po2)))?;
    }

    // 6. Publish: the ELF, then the bundle.
    const P: Step = Step::Publish;
    check_abort(token, P)?;
    let t = Instant::now();
    let hold = {
        let (store, image_id_fn, elf) = (ctx.store.clone(), ctx.image_id_fn.clone(), elf.to_vec());
        blocking(P, move || store.put_elf(program_id, &elf, &*image_id_fn)).await?.map_err(|e| match e {
            StoreError::Rejected(Reject::Record(_)) => {
                Skip::new(SkipReason::HostInternal, P, format!("the image-id function refused the verified ELF: {e}"))
            }
            e => store_skip(&e, P),
        })?
    };
    let per_po2: Vec<ExecutedPo2> = resp
        .results
        .iter()
        .map(|r| ExecutedPo2 {
            po2: u32::from(r.po2),
            cycles: r.cycles,
            segment_bytes: r.segment_bytes,
            peak_host_bytes: r.peak_host_bytes,
        })
        .collect();
    let journal_hex = hex::encode(&journal);
    let record = BundleV1 {
        format_version: BUNDLE_FORMAT_VERSION,
        job_id: job.job_id,
        descriptor_hash: job.descriptor_hash,
        prover: job.prover,
        version: writer.version(),
        descriptor_hex: hex::encode(descriptor_abi(d)),
        submit_tx_hash: job.submit_tx_hash,
        prefix: prefix.is_some(),
        image_id: program_id,
        po2_results: resp
            .results
            .iter()
            .map(|r| Po2Result {
                po2: u32::from(r.po2),
                journal_hex: journal_hex.clone(),
                journal_sha256: B256::from(r.journal_sha256),
                cycles: r.cycles,
                exit: GuestExit::Halted(0),
                segment_bytes: r.segment_bytes,
            })
            .collect(),
        input_sha256: input,
        w_sha256,
        w_len,
        sys_rand_key_fingerprint: key_fingerprint(&ctx.sys_rand_key),
        keccak_po2: u32::from(ctx.keccak_po2),
        worker_builds,
        created_at_block: job.current_block,
        builder_id: envelope.job.builderId,
        caller: job.caller,
        execute_ms_per_po2: Some(execute_ms_per_po2),
        elf_sha256: Some(hold.sha256()),
    };
    let bundle = {
        let record = record.clone();
        blocking(P, move || writer.finish(&record, &descriptor_hash_of_abi)).await?.map_err(|e| store_skip(&e, P))?
    };
    // The published version now references the ELF.
    drop(hold);
    timings.publish = t.elapsed();
    timings.total = started.elapsed();
    tracing::info!(
        job = %job.job_id,
        version = bundle.version,
        w_len,
        journal_len = journal.len(),
        total_ms = timings.total.as_millis() as u64,
        "witness job: bundle published"
    );
    Ok(Simulated {
        bundle,
        record,
        journal,
        per_po2,
        w_len,
        w_sha256,
        input_sha256: input,
        prefix: prefix.is_some(),
        limits,
        builder: builder_stats,
        timings,
        execute_build,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkminer_prover_protocol::WitnessExecutePo2;

    fn descriptor(expected: B256, fields: B256, assigned: Address) -> JobDescriptor {
        JobDescriptor {
            programId: B256::repeat_byte(1),
            proofSystemId: risc_zero_groth16_v1_id(),
            callbackContract: Address::ZERO,
            assignedProver: assigned,
            tag: B256::ZERO,
            inputData: vec![1, 2, 3].into(),
            callbackExtraData: Default::default(),
            extraVerifierData: vec![9].into(),
            expectedJournalHash: expected,
            journalFields: fields,
        }
    }

    fn slot0(v: u32) -> B256 {
        let mut w = B256::ZERO;
        w.0[..4].copy_from_slice(&v.to_be_bytes());
        w
    }

    #[test]
    fn served_bindings() {
        let me = Address::repeat_byte(7);
        let h = B256::repeat_byte(3);
        assert!(binding_served(&descriptor(h, B256::ZERO, Address::ZERO), me).is_ok(), "FULL");
        assert!(binding_served(&descriptor(h, slot0(32), Address::ZERO), me).is_ok(), "FIELDS");
        assert!(binding_served(&descriptor(h, slot0(JOURNAL_PREFIX_MARKER), Address::ZERO), me).is_ok(), "prefix");
        assert!(binding_served(&descriptor(h, slot0(PROOF_NONCE_MARKER), me), me).is_err(), "SP1 nonce");
        assert!(binding_served(&descriptor(B256::ZERO, B256::ZERO, Address::ZERO), me).is_err(), "open NONE");
        assert!(binding_served(&descriptor(B256::ZERO, B256::ZERO, Address::repeat_byte(8)), me).is_err());
        assert!(binding_served(&descriptor(B256::ZERO, B256::ZERO, me), me).is_ok(), "NONE assigned to us");
        assert!(binding_served(&descriptor(B256::ZERO, slot0(JOURNAL_PREFIX_MARKER), Address::ZERO), me).is_err());
    }

    #[test]
    fn descriptor_bytes_round_trip_to_the_hash() {
        let d = descriptor(B256::repeat_byte(3), slot0(8), Address::ZERO);
        let bytes = descriptor_abi(&d);
        assert_eq!(descriptor_hash_of_abi(&bytes), Some(compute_descriptor_hash(&d)));
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(descriptor_hash_of_abi(&longer), None);
        assert_eq!(descriptor_hash_of_abi(&bytes[..bytes.len() - 1]), None);
    }

    #[test]
    fn artifact_verdicts() {
        use SourceOutcome::*;
        assert_eq!(artifact_reason(Absent, &[Bad]), SkipReason::ArtifactAllSourcesBad);
        assert_eq!(artifact_reason(Absent, &[Bad, Bad]), SkipReason::ArtifactAllSourcesBad);
        assert_eq!(artifact_reason(Absent, &[Bad, Empty]), SkipReason::ArtifactUnavailable);
        assert_eq!(artifact_reason(Absent, &[]), SkipReason::ArtifactUnavailable, "no usable source");
        assert_eq!(artifact_reason(Absent, &[Absent]), SkipReason::ArtifactUnavailable, "no artifact endpoint");
        assert_eq!(artifact_reason(Operator, &[Bad]), SkipReason::OperatorEndpoint);
        assert_eq!(artifact_reason(Absent, &[Bad, Operator]), SkipReason::OperatorEndpoint);
        assert_eq!(artifact_reason(Absent, &[TooLarge]), SkipReason::LimitsAboveHostMaxima);
        assert_eq!(source_outcome(ArtifactFailure::IdMismatch, false), Bad);
        assert_eq!(source_outcome(ArtifactFailure::HashMismatch { at_or_below_safe: false }, false), Bad);
        assert_eq!(source_outcome(ArtifactFailure::TooLarge, true), Operator);
        assert_eq!(source_outcome(ArtifactFailure::MirrorMissing, true), Absent);
    }

    fn po2(p: u8, journal: &[u8], cycles: u64) -> WitnessExecutePo2 {
        WitnessExecutePo2 {
            po2: p,
            cycles,
            journal: journal.to_vec(),
            journal_len: journal.len() as u32,
            journal_sha256: Sha256::digest(journal).into(),
            exit_kind: GUEST_EXIT_HALTED,
            exit_code: 0,
            segment_bytes: 1,
            peak_host_bytes: 1,
        }
    }

    #[test]
    fn execution_checks() {
        let id = B256::repeat_byte(5);
        let resp = |results| WitnessExecuteResponse {
            image_id: id.0,
            results,
            sdk_version: "risc0-zkvm 3.1.0".into(),
            worker_version: "0.1.0".into(),
        };
        let ok = resp(vec![po2(16, b"j", 100), po2(18, b"j", 120)]);
        assert_eq!(check_execution(&ok, &[16, 18], id, 120).unwrap(), b"j");
        assert_eq!(check_execution(&ok, &[16, 18], id, 119).unwrap_err().0, SkipReason::GuestCyclesAboveLimit);
        assert_eq!(check_execution(&ok, &[16, 18], B256::ZERO, 1 << 30).unwrap_err().0, SkipReason::ElfImageIdMismatch);
        let differ = resp(vec![po2(16, b"a", 1), po2(18, b"b", 1)]);
        assert_eq!(check_execution(&differ, &[16, 18], id, 10).unwrap_err().0, SkipReason::JournalsDifferAcrossPo2);
        let mut failed = po2(16, b"", 1);
        failed.exit_code = 1;
        assert_eq!(check_execution(&resp(vec![failed]), &[16, 18], id, 10).unwrap_err().0, SkipReason::GuestFailed);
        let mut big = po2(16, b"", 1);
        big.journal_len = MAX_JOURNAL_BYTES as u32 + 1;
        assert_eq!(check_execution(&resp(vec![big]), &[16], id, 10).unwrap_err().0, SkipReason::JournalTooLarge);
    }

    #[test]
    fn execute_failures_are_judged_by_kind() {
        let exit = |f: WitnessExecuteFailure| WitnessExecError::Exit { code: f.code(), failure: Some(f), log_tail: String::new() };
        assert_eq!(execute_reason(&exit(WitnessExecuteFailure::GuestFault)), SkipReason::GuestFailed);
        assert_eq!(execute_reason(&exit(WitnessExecuteFailure::CycleLimit)), SkipReason::GuestCyclesAboveLimit);
        assert_eq!(execute_reason(&exit(WitnessExecuteFailure::InputMismatch)), SkipReason::HostInternal);
        assert_eq!(
            execute_reason(&WitnessExecError::OomKilled { memory_max: 1, log_tail: String::new() }),
            SkipReason::ProveResources
        );
        assert_eq!(execute_reason(&WitnessExecError::Signaled { signal: 31, log_tail: String::new() }), SkipReason::HostInternal);
    }

    #[test]
    fn host_po2_sets() {
        assert_eq!(host_po2s(&[20, 16, 20]).unwrap(), vec![16, 20]);
        assert!(host_po2s(&[]).is_err());
        assert!(host_po2s(&[15]).is_err());
        assert!(host_po2s(&[23]).is_err());
    }
}
