//! The witness runtime (Linux): what serves witness-construction jobs in a running miner
//! (docs/witness-construction-jobs.md §5.2, §15, §17, §18).
//!
//! - **Startup** ([`WitnessRuntime::start`]): the retention store is opened whenever `[retention]` is
//!   configured (held witness locks are proven from it even with serving off). Serving needs
//!   `[witness] enabled`, a configuration that validates now, a usable `sys_rand` key, the delegated
//!   cgroup, the spawner thread, the sandboxed binaries, a passing sandbox self-test, the broker
//!   process and its own self-test. Any failure leaves serving off with
//!   `PAGE: WITNESS-DISABLED <reason>`; inline jobs are unaffected. Serving starts in the background
//!   (the brain does not wait for it), each self-test is bounded, and they run again hourly and
//!   switch serving off (aborting running simulations) and back on with their result.
//! - **Routing and single flight** ([`WitnessRuntime::route`]): one task per jobId, from the first
//!   simulation to the terminal state; a job with a live verdict, or a pending or held claim of
//!   ours, is not simulated again. A witness job this host does not serve is set aside by the brain
//!   (`Route::WitnessUnserved`).
//! - **Simulation**: `pipeline::simulate_witness_job`, with [`Hooks`] supplying the chain gates
//!   (submission form, deployment, claimability, governance, the reservation), the guest ELF (fetched
//!   only after those passed, its image id derived on a measure worker), the artifact budget and the
//!   abort token (the governance watcher's `JobCancelled`, `JobClaimed` by another prover and
//!   `BidSubmitted`, serving switched off, and shutdown). A bundle already published for the job is
//!   reused after revalidation instead of simulating again.
//! - **The claim gate** (the proving-time estimate against the per-attempt watchdog and the window,
//!   the operator's session cap, funds, segment disk reserved for the job, host RAM, the
//!   reservation), the **lock** (revalidate at the cards' current po2 set, re-check pause, risc0,
//!   serving, a jammed signer, funds and a free card, pin with the lock's evidence, journal,
//!   claimability, claim), the **prove** (only at an executed po2, never on a quarantined device,
//!   by a pending verifier swap's `readyAt`; a journal divergence is re-versioned once and proven on
//!   the slot that diverged), the **fulfil** (`fulfillJobHashed` under the DA nonce rule), and the
//!   **terminal cleanup** (unpin, delete).
//! - **Recovery**: the store's pins are the index of witness locks; a periodic pass re-drives the
//!   held ones from their bundles, unpins locks that provably ended (a terminal read, a risen reopen
//!   count, a read at or after the lock block showing another prover, or a claim that never landed
//!   by chain time), deletes bundles of terminal jobs, and, once a full pass has completed and the
//!   brain's first complete recovery pass has handed every witness lock over and each is pinned,
//!   enables eviction. A lock with no readable pin is found by the brain's chain scan and re-pinned
//!   from the store's latest version for it.
//! - **Post-lock failures** (§16): a lock released after it failed records a final verdict for its
//!   job, a tally for its caller (admission stops at a limit) and one for the device and failure
//!   class (a device with two of a class proves no witness lock), all persisted in the store.
//!
//! Lanes: pre-claim chain reads run in `Lane::PreClaim`, the lock transaction (and the claimability
//! read right before it) in `Lane::Lock`, and everything for a lock already held in
//! `Lane::HeldLock`. Witness locks never feed the program-wide marks (the vkey-mismatch and
//! unsatisfiable-binding marks, the divergence breaker): post-lock failures are counted per caller.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use alloy::primitives::{keccak256, Address, Bytes, B256};
use alloy::sol_types::SolValue;
use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use zkminer_chain::auction::{risc_zero_groth16_v1_id, PROVER_GRACE_SECS};
use zkminer_chain::binding::check_journal_binding;
use zkminer_chain::client::ChainClient;
use zkminer_chain::da::{
    estimate_fulfil_da_bytes, Backlog, BacklogReader, BacklogReading, BacklogSource, DaCapPolicy, Decision,
    NonceRuleConfig, SealSpec,
};
use zkminer_chain::descriptor::{compute_descriptor_hash, fetch_job_descriptor_checked_with_form, FetchedDescriptor, SubmissionForm};
use zkminer_chain::governance::{AbortReason as GovAbort, GovernanceConfig, GovernanceView, GovernanceWatcher};
use zkminer_chain::jobs::{
    fulfill_gas_formula, ClaimOutcome, ClaimQuote, FulfilDa, HashedFulfil, JOB_STATUS_FULFILLED, JOB_STATUS_LOCKED,
    JOB_STATUS_OPEN, MAX_JOURNAL_BYTES, MAX_REOPEN_COUNT,
};
use zkminer_chain::rpc_meter::{with_lane, Lane};
use zkminer_config::witness::{effective_summary, rate_expiry, validate, SandboxModeConfig, WitnessConfig};
use zkminer_config::witness::RetentionConfig;
use zkminer_config::ZkMinerConfig;
use zkminer_contracts::bindings::{JobDescriptor, JobRecord};
use zkminer_prover::dispatcher::{JournalDivergence, WitnessProveOutcome};
use zkminer_prover::engine::ProofOutput;
use zkminer_prover_protocol::{WitnessProve, GUEST_EXIT_HALTED};
use zkminer_tui::state::{LogLevel, MinerJobStatus, SharedState, TrackedJob};
use zkminer_witness::bundle::{BundleV1, GuestExit, PinRecord, Po2Result};
use zkminer_witness::envelope::HostMaxima;
use zkminer_witness::verdict::{PostLockFailureClass, SkipReason, VerdictRecord};
use zkminer_witness_broker::client::{ArtifactCharge, BrokerClient};
use zkminer_witness_host::abort::{AbortReason, AbortToken};
use zkminer_witness_host::broker_proc::BrokerProcess;
use zkminer_witness_host::paths;
use zkminer_witness_host::pipeline::{
    descriptor_hash_of_abi, eviction_by_age, key_fingerprint, risc0_build_id, simulate_witness_job, HookFuture,
    HostContext, ImageIdFn, JobInput, PipelineHooks, Simulated, Skip,
};
use zkminer_witness_host::spawner::Spawner;
use zkminer_witness_host::store_open::open_store;
use zkminer_witness_store::{
    revalidate, BundleKey, BundleRef, HostProfile, Store, StoreError, TerminalProof, TerminalState, BUNDLE_JSON_ALLOWANCE,
};

use super::super as run;
use super::policy::{
    caller_admitted, caller_tally_key, card_room, deadline_fits, device_tally_key, divergence_reusable,
    estimate_prove_secs, fixed_allowance_secs, funds_cover, gate_refusal_reason, host_max_guest_cycles,
    is_witness_input, not_claimable_reason, parse_session_cap, pin_lock_gone, proving_cutoff, rate_secs_left,
    reservation_wei, segment_need, segments_fit, session_cap_admits, short, tally_count, verdict_plan,
    verdict_set_aside, watchdog_admits, witness_prove_sizes, ArtifactBudget, Blame, PinFacts, PinRead, ProvePlan,
    ReservationInputs, POST_LOCK_CALLER_LIMIT, POST_LOCK_CLASSES, POST_LOCK_DEVICE_LIMIT,
    POST_LOCK_TALLY_TTL_SECS, RISC0_CPU_CONSERVATIVE_CPS, SERVING_OFF_SET_ASIDE, UNSERVED_SET_ASIDE,
};
use super::{known_class, note_class, Class, Route};
use crate::journal::WitnessBundleRef;

/// The largest builder artifact this host reads (the broker's default `[artifacts]
/// max_builder_bytes`; the broker also enforces its own).
const MAX_ARTIFACT_BYTES: u64 = 4 << 20;
/// Wall clock of one sandboxed execute (every po2 of the host's set).
const EXECUTE_TIMEOUT: Duration = Duration::from_secs(600);
/// How often the sandbox and broker self-tests run again.
const SELF_TEST_EVERY: Duration = Duration::from_secs(3600);
/// Bound on one self-test (sandbox or broker): one that does not finish is a failure, so a wedged
/// broker or spawner never holds serving (or the miner's start) hostage.
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(120);
/// How often the retention store is reconciled with the chain.
const STORE_PASS_EVERY: Duration = Duration::from_secs(300);
/// Simulations at once (each runs a builder and executes the guest at every po2, on the CPU).
const MAX_CONCURRENT_SIMULATIONS: usize = 2;
/// Descriptor reads for classification at once.
const MAX_CONCURRENT_CLASSIFICATIONS: usize = 4;
/// A classification that failed is tried again after this long (the job stays off the inline path
/// meanwhile: the inline path could not read its descriptor either).
const CLASSIFY_RETRY: Duration = Duration::from_secs(30);
/// Bound on one descriptor or ELF fetch before a simulation.
const FETCH_BUDGET: Duration = Duration::from_secs(120);
/// risc0's default keccak po2, used unless `RISC0_KECCAK_PO2` says otherwise (the workers read the
/// same variable).
const DEFAULT_KECCAK_PO2: u8 = 17;
/// `jobs().status` of a cancelled job (Open 0, Locked 1, Fulfilled 2, Cancelled 3).
const JOB_STATUS_CANCELLED: u8 = 3;
/// Job records one store pass reads at most (the rest wait for the next pass).
const STORE_PASS_MAX_READS: usize = 64;
/// `PAGE: RETENTION-LOW` above this share of the store's byte quota.
const RETENTION_LOW_SHARE: f64 = 0.8;
/// Reads of a just-fulfilled job's record before its terminal cleanup is left to the store pass (a
/// lagging replica may still show it Locked).
const TERMINAL_READS: u32 = 4;
/// Bound on deriving one ELF's image id, waiting for a measure worker included (the derivation is
/// milliseconds of work; the measure workers may all be busy measuring inline jobs).
const IMAGE_ID_TIMEOUT: Duration = Duration::from_secs(120);
/// How often a derivation that found every measure worker busy tries again.
const IMAGE_ID_RETRY: Duration = Duration::from_millis(250);
/// A device (its PCI bus id, or the slot for a card without one) named for the post-lock tallies.
fn device_of_slot(slot: &str) -> String {
    zkminer_prover::engine::worker_pool()
        .and_then(|p| p.bus_id_for_slot(slot))
        .unwrap_or_else(|| slot.to_string())
}
/// Bounds on the per-job memories of the runtime (the oldest are dropped past them).
const PER_JOB_CAP: usize = 16_384;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now_unix() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

fn shutting_down() -> bool {
    run::SHUTTING_DOWN.load(Ordering::SeqCst)
}

/// Runs store I/O, hashing and image-id derivation off the async runtime.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f).await.map_err(|e| anyhow!("blocking task: {e}"))
}

/// What the runtime knows of a job's task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Before the lock: aborted by the governance watcher's events and by shutdown.
    Simulating,
    /// Between the card check right before the claim intent and the claim: the task has taken a
    /// card for its proof (it counts against the cards like a held lock), and is still aborted like
    /// a simulation until the claim is sent. Back to `Simulating` when it does not claim.
    Claiming,
    /// A lock is held (or being recovered): never aborted, driven to a terminal state or released.
    Locked,
}

impl Phase {
    /// Whether the task holds a card: a lock held or being claimed.
    fn holds_card(self) -> bool {
        matches!(self, Phase::Claiming | Phase::Locked)
    }

    /// Whether an abort token still reaches the task (nothing of its claim is on chain yet).
    fn abortable(self) -> bool {
        matches!(self, Phase::Simulating | Phase::Claiming)
    }
}

struct Task {
    token: AbortToken,
    phase: Phase,
}

/// Takes a card for `jid`'s claim, in one step with the check that one is free: under the tasks
/// lock, a task that is simulating becomes `Claiming` only while the inline jobs needing a card
/// (`cards`, the brain's latest view) and every task already holding one leave room under the cap.
/// Two simulations that finish together can then never both claim the host's last card. `true` also
/// when the task already holds one; `false` when no card is free, the brain has not said yet, or
/// `jid` has no task.
fn take_card(tasks: &mut HashMap<B256, Task>, cards: Option<(usize, usize)>, jid: B256) -> bool {
    match tasks.get(&jid).map(|t| t.phase) {
        None => return false,
        Some(p) if p.holds_card() => return true,
        Some(_) => {}
    }
    let held = tasks.values().filter(|t| t.phase.holds_card()).count();
    if !cards.is_some_and(|(inline, max)| card_room(inline, held, max)) {
        return false;
    }
    if let Some(t) = tasks.get_mut(&jid) {
        t.phase = Phase::Claiming;
    }
    true
}

/// Gives back the card [`take_card`] took for `jid` when its claim is not sent (a held lock keeps
/// its card).
fn give_back_card(tasks: &mut HashMap<B256, Task>, jid: B256) {
    if let Some(t) = tasks.get_mut(&jid) {
        if t.phase == Phase::Claiming {
            t.phase = Phase::Simulating;
        }
    }
}

/// Gives back the card a claim took ([`take_card`]) when the claim is not sent, however
/// [`WitnessRuntime::lock`] returns.
struct CardTaken<'a> {
    rt: &'a WitnessRuntime,
    jid: B256,
}

impl Drop for CardTaken<'_> {
    fn drop(&mut self) {
        self.rt.give_back_card(self.jid);
    }
}

/// Removes a job's task entry when its task ends, however it ends (a panic included), so a job is
/// never left looking in flight.
struct TaskEntry {
    rt: Arc<WitnessRuntime>,
    job_id: B256,
}

impl Drop for TaskEntry {
    fn drop(&mut self) {
        lock(&self.rt.tasks).remove(&self.job_id);
    }
}

/// The brain's ends of its bookkeeping: a witness lock holds an `in_flight` slot from its lock to
/// its end, like an inline one.
#[derive(Clone)]
struct BrainLink {
    held: mpsc::UnboundedSender<(B256, u128, u64)>,
    done: mpsc::UnboundedSender<B256>,
}

/// The started serving side: the spawner thread, the broker, the binaries.
struct Serving {
    spawner: Spawner,
    broker: Mutex<BrokerProcess>,
    broker_client: Arc<BrokerClient>,
    /// The miner's connector: every connection the broker makes (review r2 F5).
    connector: Arc<zkminer_witness_broker::connector::Connector>,
    cgroup_root: PathBuf,
    builder_binary: PathBuf,
    execute_binary: PathBuf,
    probe_binary: PathBuf,
}

/// One job ready for the claim gate: a freshly simulated bundle, or a retained one revalidated.
struct Candidate {
    bundle: BundleRef,
    record: BundleV1,
    journal: Vec<u8>,
    /// Per executed po2: (po2, sized cycles, segment bytes, the execute's peak host bytes or 0).
    per_po2: Vec<(u32, u64, u64, u64)>,
    /// Seconds the simulation took (0 for a retained bundle: already paid).
    simulation_secs: f64,
    /// Seconds one po2's execute took (for the prove's execute allowance).
    execute_secs_per_po2: u64,
    elf: Vec<u8>,
}

impl Candidate {
    fn from_sim(s: Simulated, elf: Vec<u8>) -> Self {
        let n = s.per_po2.len().max(1) as u64;
        let execute_ms = s.record.execute_ms_per_po2.unwrap_or_else(|| (s.timings.execute.as_millis() as u64).div_ceil(n));
        Self {
            bundle: s.bundle,
            journal: s.journal,
            per_po2: s.per_po2.iter().map(|p| (p.po2, p.cycles, p.segment_bytes, p.peak_host_bytes)).collect(),
            simulation_secs: (s.timings.builder + s.timings.execute).as_secs_f64(),
            execute_secs_per_po2: execute_ms.div_ceil(1000),
            record: s.record,
            elf,
        }
    }

    fn cycles(&self) -> u64 {
        self.per_po2.iter().map(|p| p.1).max().unwrap_or(0)
    }
}

/// What the claim gate established.
struct GateOk {
    reservation: u128,
    /// The job's `fulfillmentTimeout` (from its record): a lock taken now ends this long after.
    window: u64,
    /// The fulfil's gas limit the gate funded.
    fulfil_gas: u64,
}

/// A held witness lock, as the prove and fulfil steps need it.
struct LockCtx {
    job_id: B256,
    caller: Address,
    descriptor: JobDescriptor,
    bundle: BundleRef,
    record: BundleV1,
    elf: Vec<u8>,
    lock_block: u64,
    lock_deadline: u64,
    locked_collateral: u128,
    cycles: u64,
    /// The slot of the last proof attempt that failed, and how (for the post-lock tallies).
    failure: Option<(Option<String>, PostLockFailureClass)>,
}

/// The chain gates' inputs for one job (§5.3).
#[derive(Clone)]
struct ChainGateInput {
    job_id: B256,
    proof_system_id: B256,
    caller: Address,
    form: SubmissionForm,
    /// The job's `fulfillmentTimeout`: a lock taken now ends `window` + grace from now.
    window: u64,
    /// The simulation's expected CPU seconds, for the pre-simulation reservation.
    expected_simulation_secs: f64,
}

pub(crate) struct WitnessRuntime {
    client: ChainClient,
    state: SharedState,
    journal: run::SharedJournal,
    witness: WitnessConfig,
    retention: Option<RetentionConfig>,
    rate_expires: Option<i64>,
    secret_path: PathBuf,
    store: Mutex<Option<Arc<Store>>>,
    serving: Mutex<Option<Arc<Serving>>>,
    /// The last self-test passed (and serving started).
    enabled: AtomicBool,
    gov: GovernanceView,
    backlog: BacklogSource,
    da_policy: DaCapPolicy,
    tasks: Mutex<HashMap<B256, Task>>,
    /// Classifications in flight (`None`) or to retry after an instant.
    classifying: Mutex<HashMap<B256, Option<Instant>>>,
    descriptors: Mutex<HashMap<B256, FetchedDescriptor>>,
    /// Unix seconds until which a job's verdict holds (a cache of the store's verdicts).
    verdict_until: Mutex<HashMap<B256, u64>>,
    blame: Mutex<Blame>,
    image_ids: Arc<Mutex<HashMap<B256, B256>>>,
    /// Segment bytes reserved per witness proof planned or running.
    segment_reserved: Mutex<HashMap<B256, u64>>,
    brain: Mutex<Option<BrainLink>>,
    sim_slots: Arc<tokio::sync::Semaphore>,
    classify_slots: Arc<tokio::sync::Semaphore>,
    proving_timeout: Duration,
    sys_rand_key: [u8; 32],
    keccak_po2: u8,
    scan_complete: AtomicBool,
    /// Jobs a one-off notice was logged for (not admitted, needs claim_predicate_jobs).
    noticed: Mutex<HashSet<(B256, &'static str)>>,
    store_pass_running: AtomicBool,
    /// The execute worker's build, from its latest response here (`None` until one ran).
    execute_build: Mutex<Option<String>>,
    /// The brain's view of the cards, each tick: inline jobs still needing a card, and the cap.
    cards: Mutex<Option<(usize, usize)>>,
    /// The brain's first complete recovery pass has handed over every witness lock it found.
    brain_recovered: AtomicBool,
    /// Witness locks recovery handed over whose bundle is not pinned yet: eviction waits for them.
    unpinned_recoveries: Mutex<HashSet<B256>>,
    /// Image-id derivations that could not run (no measure worker free within the bound).
    image_id_unavailable: Arc<AtomicU64>,
    /// Callers' post-lock failure counts as last read or written here, with when they expire.
    post_lock_callers: Mutex<HashMap<Address, (u8, u64)>>,
    /// Post-lock tallies when no store is open (counted for this process only).
    tallies: Mutex<HashMap<B256, (u8, u64)>>,
}

impl WitnessRuntime {
    // ── startup ───────────────────────────────────────────────────────────────

    /// Builds the runtime when `[witness] enabled` or a `[retention]` store is configured (not in
    /// watch-only, which never runs builders and holds no locks). See the module docs.
    pub(crate) async fn start(
        config: &ZkMinerConfig,
        config_path: Option<&Path>,
        client: &ChainClient,
        state: &SharedState,
        journal: &run::SharedJournal,
        proving_timeout: Duration,
    ) -> Option<Arc<Self>> {
        let w = &config.witness;
        if run::watch_only() {
            if w.enabled {
                tracing::info!("witness jobs: watch-only never runs builders; each is reported, not simulated");
            }
            return None;
        }
        if !w.enabled && config.retention.is_none() {
            return None;
        }
        // The key every risc0 worker of this miner was handed (run.rs loads it once): the seed the
        // execute runs under must be the one the prove worker derives. A key for this run only
        // (the file unusable) refuses serving: a bundle must stay provable after a restart.
        let (sys_rand_key, key_err) = match zkminer_prover::worker::risc0_sys_rand_key() {
            Some((key, false)) => (key, None),
            Some((key, true)) => (
                key,
                Some(std::io::Error::other("the workers were given a key for this run only")),
            ),
            None => zkminer_prover_protocol::sys_rand::host_key(dirs::home_dir().as_deref()),
        };
        let backlog = match config.dev_da_backlog_bytes() {
            Some(b) => {
                tracing::warn!(
                    "[dev] da_backlog_bytes = {b}: witness claim gates and fulfils use this fixed DA \
                     backlog instead of reading the chain (a local test network only)"
                );
                BacklogSource::Fixed(BacklogReading::fixed(Backlog::Known(b), Some(0)))
            }
            None => BacklogSource::Reader(Arc::new(BacklogReader::default())),
        };
        let mut da_policy = DaCapPolicy::new(w.fulfil_da_cap_bytes).unwrap_or_default();
        da_policy.hold_backlog_bytes = w.da_backlog_hold_bytes;

        let watcher = GovernanceWatcher::new(
            client.clone(),
            GovernanceConfig::new(client.address, vec![risc_zero_groth16_v1_id()]),
        );
        let gov = watcher.view();
        tokio::spawn(with_lane(Lane::Default, async move {
            if let Err(e) = watcher.run().await {
                tracing::error!("witness: the governance watcher stopped: {e:#}");
            }
        }));

        let keccak_po2 = std::env::var("RISC0_KECCAK_PO2")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(DEFAULT_KECCAK_PO2);
        let rt = Arc::new(Self {
            client: client.clone(),
            state: state.clone(),
            journal: journal.clone(),
            witness: w.clone(),
            retention: config.retention.clone(),
            rate_expires: w.hemi_per_eth_expires.as_deref().and_then(|s| rate_expiry(s).ok()),
            secret_path: config_path.map(PathBuf::from).unwrap_or_else(ZkMinerConfig::default_path),
            store: Mutex::new(None),
            serving: Mutex::new(None),
            enabled: AtomicBool::new(false),
            gov,
            backlog,
            da_policy,
            tasks: Mutex::new(HashMap::new()),
            classifying: Mutex::new(HashMap::new()),
            descriptors: Mutex::new(HashMap::new()),
            verdict_until: Mutex::new(HashMap::new()),
            blame: Mutex::new(Blame::default()),
            image_ids: Arc::new(Mutex::new(HashMap::new())),
            segment_reserved: Mutex::new(HashMap::new()),
            brain: Mutex::new(None),
            sim_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SIMULATIONS)),
            classify_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CLASSIFICATIONS)),
            proving_timeout,
            sys_rand_key,
            keccak_po2,
            scan_complete: AtomicBool::new(false),
            noticed: Mutex::new(HashSet::new()),
            store_pass_running: AtomicBool::new(false),
            execute_build: Mutex::new(None),
            cards: Mutex::new(None),
            brain_recovered: AtomicBool::new(false),
            unpinned_recoveries: Mutex::new(HashSet::new()),
            image_id_unavailable: Arc::new(AtomicU64::new(0)),
            post_lock_callers: Mutex::new(HashMap::new()),
            tallies: Mutex::new(HashMap::new()),
        });
        rt.open_store().await;
        if w.enabled {
            // §19: the effective configuration, whether or not serving then starts.
            tracing::info!("{}", effective_summary(w, config.retention.as_ref(), config.broker.as_ref()));
            // In the background: the self-tests and the broker start take seconds (minutes, bounded,
            // when something is wedged), and the brain and every inline job go on meanwhile.
            let (rt2, config) = (rt.clone(), config.clone());
            tokio::spawn(async move { rt2.start_serving(&config, key_err).await });
        } else {
            tracing::info!(
                "witness serving is off ([witness] enabled = false): witness jobs are not simulated; \
                 witness locks already held are still proven from the retention store"
            );
        }
        tokio::spawn(rt.clone().abort_loop());
        tokio::spawn(rt.clone().self_test_loop());
        Some(rt)
    }

    /// Opens the retention store (never creating it). Unavailable: every witness lock is kept,
    /// paged, and the store is tried again on each store pass.
    async fn open_store(&self) {
        let Some(r) = self.retention.clone() else { return };
        let (chain, router, prover) = (self.client.chain_id, self.client.hemi_prove, self.client.address);
        match blocking(move || open_store(&r, chain, router, prover)).await {
            Ok(Ok(s)) => {
                let report = s.open_report();
                tracing::info!(
                    "witness: retention store at {} open (uuid {}, {} leftover writes removed)",
                    s.root().display(),
                    s.identity().store_uuid,
                    report.tmp_entries_removed
                );
                *lock(&self.store) = Some(Arc::new(s));
            }
            Ok(Err(e)) => tracing::error!(
                "PAGE: RETENTION-UNAVAILABLE the retention store cannot be opened ({e}): every witness \
                 lock is kept, none is proven until it opens; retried every {} s",
                STORE_PASS_EVERY.as_secs()
            ),
            Err(e) => tracing::error!("PAGE: RETENTION-UNAVAILABLE opening the retention store: {e:#}"),
        }
    }

    fn disable(&self, why: String) {
        self.enabled.store(false, Ordering::SeqCst);
        tracing::error!(
            "PAGE: WITNESS-DISABLED {} — witness jobs are not simulated or claimed; inline jobs are \
             unaffected",
            zkminer_chain::programs::sanitize_log(&why)
        );
        // §19: switching serving off aborts the running simulations; held locks continue.
        self.abort_simulations(AbortReason::Disabled);
    }

    /// Fires every running simulation's abort token (a held lock's task is never aborted).
    fn abort_simulations(&self, reason: AbortReason) {
        for (jid, t) in lock(&self.tasks).iter() {
            if t.phase.abortable() && t.token.abort(reason) {
                tracing::info!("witness job {}: simulation aborted ({reason:?})", short(*jid));
            }
        }
    }

    async fn start_serving(self: &Arc<Self>, config: &ZkMinerConfig, key_err: Option<std::io::Error>) {
        let w = &config.witness;
        if let Err(e) = validate(w, config.retention.as_ref(), config.broker.as_ref(), chrono::Utc::now().timestamp()) {
            return self.disable(e.to_string());
        }
        // §5.3: witness jobs only on a deployment whose core code this host verified.
        if zkminer_chain::deployment::code_pins_skipped() {
            return self.disable(
                "ZKMINER_SKIP_CODE_PINS is set: the deployment's core code is not verified, and witness \
                 jobs are served only on a verified deployment"
                    .into(),
            );
        }
        if let Some(e) = key_err {
            return self.disable(format!(
                "the risc0 sys_rand key file is unusable ({e}): a witness bundle must stay provable \
                 after a restart"
            ));
        }
        let Some(broker_section) = config.broker.clone() else {
            return self.disable("no [broker] section".into());
        };
        let root = match blocking(zkminer_witness_sandbox::delegated_root).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return self.disable(format!("the delegated cgroup: {e}")),
            Err(e) => return self.disable(format!("the delegated cgroup: {e:#}")),
        };
        let spawner = match Spawner::new() {
            Ok(s) => s,
            Err(e) => return self.disable(format!("the spawner thread: {e}")),
        };
        if lock(&self.store).is_none() {
            return self.disable("the retention store is unavailable".into());
        }
        if let Some(r) = &self.retention {
            if let Err(e) = std::fs::create_dir_all(&r.segment_dir) {
                return self.disable(format!("the segment directory {}: {e}", r.segment_dir.display()));
            }
        }
        let bin = |configured: Option<&Path>, name: &str| -> Result<PathBuf, String> {
            let p = paths::binary(configured, name).map_err(|e| format!("locating {name}: {e}"))?;
            if p.is_file() {
                Ok(p)
            } else {
                Err(format!("{} does not exist", p.display()))
            }
        };
        let binaries = (|| {
            Ok::<_, String>((
                bin(w.builder_binary.as_deref(), paths::BUILDER_BINARY)?,
                bin(w.execute_binary.as_deref(), paths::EXECUTE_BINARY)?,
                bin(broker_section.binary.as_deref(), paths::BROKER_BINARY)?,
                bin(None, zkminer_witness_sandbox::probe::PROBE_BINARY)?,
            ))
        })();
        let (builder_binary, execute_binary, broker_binary, probe_binary) = match binaries {
            Ok(b) => b,
            Err(e) => return self.disable(e),
        };
        if let Err(why) = bounded_self_test("sandbox", self.sandbox_self_test(&spawner, &probe_binary)).await {
            return self.disable(why);
        }
        let broker = match BrokerProcess::start(
            &spawner,
            &broker_binary,
            &broker_section.config,
            &root,
            broker_section.memory_bytes,
            config,
        ) {
            Ok(b) => b,
            Err(e) => return self.disable(format!("starting the broker: {e:#}")),
        };
        let broker_client = broker.client.clone();
        let connector = broker.connector.clone();
        if let Err(why) = bounded_self_test("broker", broker_self_test(&broker_client, &connector)).await {
            return self.disable(why);
        }
        *lock(&self.serving) = Some(Arc::new(Serving {
            spawner,
            broker: Mutex::new(broker),
            broker_client,
            connector,
            cgroup_root: root,
            builder_binary,
            execute_binary,
            probe_binary,
        }));
        self.enabled.store(true, Ordering::SeqCst);
        tracing::info!(
            "witness serving is on: {} allowlisted caller(s), sandbox and broker self-tests passed",
            w.callers.len()
        );
    }

    async fn sandbox_self_test(&self, spawner: &Spawner, probe: &Path) -> Result<(), String> {
        let mode = match self.witness.sandbox_mode {
            SandboxModeConfig::System => zkminer_witness_sandbox::SandboxMode::System,
            SandboxModeConfig::Rootless => zkminer_witness_sandbox::SandboxMode::Rootless,
        };
        let (probe, secret) = (probe.to_path_buf(), self.secret_path.clone());
        let report = spawner
            .run_async(move || zkminer_witness_sandbox::self_test(mode, &probe, &secret))
            .await
            .map_err(|e| format!("the spawner thread: {e}"))?;
        if report.passed() {
            tracing::info!("witness: sandbox self-test passed ({} checks)", report.checks.len());
            Ok(())
        } else {
            Err(report
                .failures()
                .map(|c| format!("{}: {}", c.name, c.detail))
                .collect::<Vec<_>>()
                .join("; "))
        }
    }

    /// Re-runs both self-tests every hour; serving follows their result (§10.3).
    async fn self_test_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(SELF_TEST_EVERY).await;
            let Some(s) = lock(&self.serving).clone() else { continue };
            let (exited, cut_off) = {
                let mut b = lock(&s.broker);
                (b.exited(), b.cut_off())
            };
            let result = match exited {
                _ if cut_off => Err("the connector cut the broker off (it broke the connector protocol) and killed it".into()),
                Some(status) => Err(format!("the broker exited ({status})")),
                None => match bounded_self_test("sandbox", self.sandbox_self_test(&s.spawner, &s.probe_binary)).await {
                    Err(why) => Err(why),
                    Ok(()) => bounded_self_test("broker", broker_self_test(&s.broker_client, &s.connector)).await,
                },
            };
            match result {
                Ok(()) => {
                    if !self.enabled.swap(true, Ordering::SeqCst) {
                        tracing::warn!("witness serving is back on: the hourly self-tests passed");
                    }
                }
                Err(why) => self.disable(why),
            }
        }
    }

    fn serving(&self) -> Option<Arc<Serving>> {
        if !self.enabled.load(Ordering::SeqCst) {
            return None;
        }
        let s = lock(&self.serving).clone()?;
        // A broker the connector cut off is treated as compromised: no more witness work until
        // the next self-test (which then fails) or a restart.
        if lock(&s.broker).cut_off() {
            self.disable("the connector cut the broker off (it broke the connector protocol) and killed it".into());
            return None;
        }
        Some(s)
    }

    fn serving_enabled(&self) -> bool {
        self.serving().is_some()
    }

    fn store(&self) -> Option<Arc<Store>> {
        lock(&self.store).clone()
    }

    // ── the brain ─────────────────────────────────────────────────────────────

    /// The brain's bookkeeping channels; also starts the store passes (which may re-drive held
    /// locks, so only once the brain can account for them).
    pub(crate) fn attach_brain(
        self: &Arc<Self>,
        held: mpsc::UnboundedSender<(B256, u128, u64)>,
        done: mpsc::UnboundedSender<B256>,
    ) {
        let first = lock(&self.brain).replace(BrainLink { held, done }).is_none();
        if first {
            tokio::spawn(self.clone().store_pass_loop());
        }
    }

    /// Every job a witness task owns (recovery leaves them alone).
    pub(crate) fn owned_jobs(&self) -> HashSet<B256> {
        lock(&self.tasks).keys().copied().collect()
    }

    /// Whether a witness task owns `jid` now (recovery re-checks it right before it releases a lock:
    /// a task may have taken the job since its pass began).
    pub(crate) fn owns(&self, jid: B256) -> bool {
        lock(&self.tasks).contains_key(&jid)
    }

    /// The brain's view of the cards this tick: inline jobs still needing a card, and the
    /// concurrency cap. A witness lock is taken only while a card is free for it (see
    /// [`card_room`]).
    pub(crate) fn note_cards(&self, inline_needing: usize, max_concurrent: usize) {
        *lock(&self.cards) = Some((inline_needing, max_concurrent));
    }

    /// Witness locks held (or being recovered) or being claimed here: each holds a card.
    fn witness_locks(&self) -> usize {
        lock(&self.tasks).values().filter(|t| t.phase.holds_card()).count()
    }

    /// Whether a card is free for one more witness lock (false until the brain has said). Advisory
    /// (whether to start a simulation): the claim takes its card with [`Self::take_card`].
    fn card_free(&self) -> bool {
        let witness_locks = self.witness_locks();
        lock(&self.cards).is_some_and(|(inline, max)| card_room(inline, witness_locks, max))
    }

    /// [`take_card`] on this runtime's tasks and the brain's latest view of the cards.
    fn take_card(&self, jid: B256) -> bool {
        let cards = *lock(&self.cards);
        take_card(&mut lock(&self.tasks), cards, jid)
    }

    /// [`give_back_card`] on this runtime's tasks.
    fn give_back_card(&self, jid: B256) {
        give_back_card(&mut lock(&self.tasks), jid);
    }

    /// The brain finished a recovery pass (`deferred`: cut short). After its first complete one,
    /// every witness lock it found has been handed to [`Self::drive_recovered`]; eviction then waits
    /// only for those to be pinned (§15.2: nothing is evicted before one full recovery scan).
    pub(crate) fn note_recovery_pass(&self, deferred: bool) {
        if !deferred && !self.brain_recovered.swap(true, Ordering::SeqCst) {
            tracing::info!("witness: the brain's recovery pass handed over every witness lock it found");
        }
    }

    /// Whether a lock of ours is a witness lock this runtime knows: the journal references its
    /// bundle, or the store holds a pin for it.
    pub(crate) fn is_witness_lock(&self, job_id: B256) -> bool {
        if lock(&self.journal).witness_bundle(job_id).is_some() {
            return true;
        }
        self.store().is_some_and(|s| s.pins().iter().any(|p| p.job_id == job_id))
    }

    /// Fires every simulation's abort token (shutdown). Held locks are left to the drain.
    pub(crate) fn shutdown(&self) {
        self.abort_simulations(AbortReason::Shutdown);
    }

    /// See [`super::route`].
    pub(crate) fn route(self: &Arc<Self>, job: &TrackedJob, descriptor_hash: B256, claim_predicate_jobs: bool) -> Route {
        let jid = job.info.job_id;
        if lock(&self.tasks).contains_key(&jid) {
            return Route::Witness;
        }
        match known_class(jid) {
            Some(Class::Inline) => Route::Inline,
            Some(Class::Witness) => self.offer(job, descriptor_hash, claim_predicate_jobs),
            None => {
                if !self.serving_enabled() || !caller_admitted(&self.witness.callers, job.info.caller) {
                    return Route::Inline;
                }
                self.classify(job, descriptor_hash, claim_predicate_jobs);
                Route::Witness
            }
        }
    }

    /// Reads an allowlisted caller's job's descriptor (with its submission form) to tell a witness
    /// job from an inline one.
    fn classify(self: &Arc<Self>, job: &TrackedJob, descriptor_hash: B256, claim_predicate_jobs: bool) {
        let jid = job.info.job_id;
        {
            let mut c = lock(&self.classifying);
            match c.get(&jid) {
                Some(None) => return,
                Some(Some(t)) if Instant::now() < *t => return,
                _ => {}
            }
            if c.len() >= PER_JOB_CAP {
                c.retain(|_, v| v.is_none());
            }
            c.insert(jid, None);
        }
        let (rt, job) = (self.clone(), job.clone());
        tokio::spawn(async move {
            let _permit = rt.classify_slots.clone().acquire_owned().await;
            let fetched = with_lane(
                Lane::PreClaim,
                tokio::time::timeout(
                    FETCH_BUDGET,
                    fetch_job_descriptor_checked_with_form(&rt.client, jid, descriptor_hash),
                ),
            )
            .await;
            match fetched {
                Ok(Ok(f)) => {
                    lock(&rt.classifying).remove(&jid);
                    if is_witness_input(&f.descriptor.inputData) {
                        note_class(jid, Class::Witness);
                        {
                            let mut d = lock(&rt.descriptors);
                            if d.len() >= PER_JOB_CAP {
                                d.clear();
                            }
                            d.insert(jid, f);
                        }
                        tracing::info!("witness job {}: classified (caller {})", short(jid), job.info.caller);
                        rt.offer(&job, descriptor_hash, claim_predicate_jobs);
                    } else {
                        note_class(jid, Class::Inline);
                    }
                }
                Ok(Err(e)) if e.downcast_ref::<zkminer_chain::descriptor::UndecodableDescriptor>().is_some() => {
                    // Not decodable from its submit transaction: never a witness job this host can
                    // serve. The inline path makes its own verdict.
                    lock(&rt.classifying).remove(&jid);
                    note_class(jid, Class::Inline);
                }
                Ok(Err(e)) => {
                    tracing::debug!("witness: classifying {} failed ({e:#}); retrying", short(jid));
                    lock(&rt.classifying).insert(jid, Some(Instant::now() + CLASSIFY_RETRY));
                }
                Err(_) => {
                    lock(&rt.classifying).insert(jid, Some(Instant::now() + CLASSIFY_RETRY));
                }
            }
        });
    }

    /// A one-off notice per job and kind.
    fn notice(&self, jid: B256, kind: &'static str) -> bool {
        let mut n = lock(&self.noticed);
        if n.len() >= PER_JOB_CAP {
            n.clear();
        }
        n.insert((jid, kind))
    }

    /// Starts a known witness job's task unless one runs, a verdict holds, or it is not served, and
    /// says how the brain treats the job meanwhile: a job this host does not serve now is set aside
    /// ([`Route::WitnessUnserved`]), as the inline path sets aside one it cannot claim.
    fn offer(self: &Arc<Self>, job: &TrackedJob, descriptor_hash: B256, claim_predicate_jobs: bool) -> Route {
        let jid = job.info.job_id;
        let unserved = |wait| Route::WitnessUnserved { wait };
        if !caller_admitted(&self.witness.callers, job.info.caller) {
            if self.notice(jid, "not-admitted") {
                tracing::info!(
                    "witness job {}: caller {} is not on [witness] callers — not simulated",
                    short(jid),
                    job.info.caller
                );
            }
            return unserved(UNSERVED_SET_ASIDE);
        }
        if !self.serving_enabled() {
            return unserved(SERVING_OFF_SET_ASIDE);
        }
        if shutting_down() {
            return Route::Witness;
        }
        if !claim_predicate_jobs {
            if self.notice(jid, "predicate") {
                tracing::info!(
                    "witness job {}: witness jobs are journal-bound, and claim_predicate_jobs is off — \
                     not simulated",
                    short(jid)
                );
            }
            return unserved(UNSERVED_SET_ASIDE);
        }
        let now = now_unix();
        if let Some(until) = lock(&self.verdict_until).get(&jid).copied().filter(|t| *t > now) {
            return unserved(verdict_set_aside(until, now));
        }
        // A claim of ours may be pending or held (a journal entry, or a pin): recovery's, never
        // simulated again (§15.2 single flight: a pinned job is never re-simulated).
        if run::journal_has(&self.journal, jid) || self.is_witness_lock(jid) {
            return Route::Witness;
        }
        if let Some(n) = self.caller_post_lock_failures(job.info.caller) {
            if n >= POST_LOCK_CALLER_LIMIT {
                if self.notice(jid, "post-lock") {
                    tracing::warn!(
                        "witness job {}: caller {} has {n} post-lock witness failure(s) in the last {} days — \
                         not admitted",
                        short(jid),
                        job.info.caller,
                        POST_LOCK_TALLY_TTL_SECS / 86_400
                    );
                }
                return unserved(UNSERVED_SET_ASIDE);
            }
        }
        // Not now, and not the job's doing: no card free (inline work or witness locks fill them),
        // or the host's prove-worker builds are not all known yet.
        if !self.card_free() || self.worker_builds().is_none() {
            return Route::Witness;
        }
        let token = AbortToken::new();
        {
            let mut t = lock(&self.tasks);
            if t.contains_key(&jid) {
                return Route::Witness;
            }
            t.insert(jid, Task { token: token.clone(), phase: Phase::Simulating });
        }
        let (rt, job) = (self.clone(), job.clone());
        tokio::spawn(async move {
            let _entry = TaskEntry { rt: rt.clone(), job_id: jid };
            let locked = rt.simulate_and_lock(&job, descriptor_hash, &token).await;
            match locked {
                Some(l) => rt.run_locked(l).await,
                // Not locked: whatever the gate reserved for the proof goes.
                None => {
                    lock(&rt.segment_reserved).remove(&jid);
                }
            }
        });
        Route::Witness
    }

    /// Fires a running simulation's abort token (the governance watcher's events).
    fn abort_simulation(&self, jid: B256, reason: AbortReason) {
        if let Some(t) = lock(&self.tasks).get(&jid) {
            if t.phase.abortable() && t.token.abort(reason) {
                tracing::info!("witness job {}: simulation aborted ({reason:?})", short(jid));
            }
        }
    }

    async fn abort_loop(self: Arc<Self>) {
        use tokio::sync::broadcast::error::RecvError;
        let mut rx = self.gov.subscribe_aborts();
        loop {
            match rx.recv().await {
                Ok(a) => self.abort_simulation(a.job_id, host_abort(a.reason)),
                Err(RecvError::Lagged(_)) => {
                    let running: Vec<B256> = lock(&self.tasks).keys().copied().collect();
                    for jid in running {
                        if let Some(r) = self.gov.abort_reason(jid) {
                            self.abort_simulation(jid, host_abort(r));
                        }
                    }
                }
                Err(RecvError::Closed) => return,
            }
        }
    }

    // ── simulation ────────────────────────────────────────────────────────────

    /// The host's po2 set now: every enabled risc0 card's job size.
    async fn host_po2s(&self) -> Vec<u8> {
        run::risc0_job_sizes(&run::current_risc0_cards(&self.state, true).await)
    }

    /// How a witness proof on this host is planned (§5.2 step 7): over every enabled risc0 card
    /// that may prove it, the slowest rate (its benchmark row at its size, else the floor for its
    /// kind: a card with no row is never left out) and the largest fixed allowance (its measured
    /// Groth16 wrap, else the allowance for its kind; a CPU slot's wrap is minutes), with the
    /// operator's `deadline_safety_margin`. `po2s` (the host's sizes) only seed the floor when no
    /// card is enabled.
    async fn prove_plan(&self, po2s: &[u8]) -> ProvePlan {
        let cards = run::current_risc0_cards(&self.state, true).await;
        let st = self.state.read().await;
        let margin = st.runtime_settings.deadline_safety_margin;
        let suite = st.benchmark_results.as_ref().filter(|s| !run::is_synthetic_suite(s));
        let per_card = cards.iter().map(|c| {
            let row = suite.and_then(|s| {
                s.device_benchmarks
                    .iter()
                    .find(|d| d.device_id == c.device && d.prover_backend == zkminer_prover_protocol::BACKEND_RISC0)
            });
            let cpu = c.device == "cpu";
            let measured = row
                .map(|r| zkminer_prover::benchmark::risc0_job_throughput(r, c.po2))
                .filter(|t| t.is_finite() && *t > 0.0);
            let cps = measured.unwrap_or_else(|| {
                if cpu {
                    RISC0_CPU_CONSERVATIVE_CPS
                } else {
                    run::risc0_conservative_cps(&[c.po2])
                }
            });
            (cps, fixed_allowance_secs(row.and_then(|r| r.wrap_secs()), cpu))
        });
        ProvePlan::over(per_card.collect::<Vec<_>>(), margin).unwrap_or(ProvePlan {
            cps: run::risc0_conservative_cps(po2s),
            fixed_secs: fixed_allowance_secs(None, false),
            margin: if margin.is_finite() && margin >= 1.0 { margin } else { 1.0 },
        })
    }

    /// The build of every risc0 prove worker that may prove a witness bundle here (§15.1): each prove
    /// slot's, as its worker named it at its last handshake, published at spawn and read without
    /// waiting on a busy slot. A slot whose worker has never started has no build to record (it
    /// cannot prove; if it starts with another build, revalidation at the lock sees it). `None` when
    /// no slot's build is known yet: nothing is recorded or compared against a placeholder.
    fn prove_worker_builds(&self) -> Option<Vec<String>> {
        let pool = zkminer_prover::engine::worker_pool()?;
        let mut builds: Vec<String> = pool
            .worker_builds(zkminer_prover_protocol::BACKEND_RISC0)
            .into_iter()
            .filter_map(|(_slot, build)| build.map(|(sdk, worker)| risc0_build_id(&sdk, &worker)))
            .collect();
        builds.sort();
        builds.dedup();
        (!builds.is_empty()).then_some(builds)
    }

    /// [`Self::prove_worker_builds`] and the execute worker's build once one ran here (its journals
    /// are the bundle's): what revalidation compares a bundle with (§15.2).
    fn worker_builds(&self) -> Option<Vec<String>> {
        let mut builds = self.prove_worker_builds()?;
        builds.extend(lock(&self.execute_build).clone());
        builds.sort();
        builds.dedup();
        Some(builds)
    }

    /// The host as it is now, for revalidation; `None` while a worker build is unknown.
    fn host_profile(&self, po2s: &[u8]) -> Option<HostProfile> {
        Some(HostProfile {
            po2s: po2s.iter().map(|p| u32::from(*p)).collect(),
            sys_rand_key_fingerprint: key_fingerprint(&self.sys_rand_key),
            keccak_po2: u32::from(self.keccak_po2),
            worker_builds: self.worker_builds()?,
        })
    }

    /// risc0's image id of an ELF, derived on a risc0 measure worker (cached by the ELF's keccak),
    /// waiting up to [`IMAGE_ID_TIMEOUT`] for one to be free. `None` without a measure pool (deriving
    /// on a prove worker could cost it a proof), or when none came free in time: that is counted in
    /// `image_id_unavailable`, so a caller can tell "could not derive now" from "not this image id".
    /// A held lock's reads need no derivation (its bundle records the ELF's digest).
    fn image_id_fn(&self) -> ImageIdFn {
        let cache = self.image_ids.clone();
        let unavailable = self.image_id_unavailable.clone();
        Arc::new(move |elf: &[u8]| {
            let key = keccak256(elf);
            if let Some(id) = lock(&cache).get(&key) {
                return Some(*id);
            }
            let give_up = || {
                unavailable.fetch_add(1, Ordering::SeqCst);
                None
            };
            let Some(pool) = zkminer_prover::engine::worker_pool() else { return give_up() };
            if pool.measure_worker_count(zkminer_prover_protocol::BACKEND_RISC0).filter(|n| *n > 0).is_none() {
                return give_up();
            }
            let deadline = Instant::now() + IMAGE_ID_TIMEOUT;
            let id = loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match pool.derive_program_id(zkminer_prover_protocol::BACKEND_RISC0, elf, Some(left.max(Duration::from_secs(5)))) {
                    Ok(d) => break B256::from(d.program_id),
                    Err(e) => {
                        let busy = e.downcast_ref::<zkminer_prover_protocol::types::MeasureSlotsBusy>().is_some()
                            || e.downcast_ref::<zkminer_prover_protocol::types::HostMemoryShortage>().is_some_and(|h| !h.attempted)
                            || e.downcast_ref::<zkminer_prover_protocol::types::MeasureWorkerGone>().is_some();
                        if busy && Instant::now() + IMAGE_ID_RETRY < deadline {
                            std::thread::sleep(IMAGE_ID_RETRY);
                            continue;
                        }
                        tracing::warn!("witness: deriving an ELF's image id failed: {e:#}");
                        // The worker refused the bytes: not an ELF it knows (a verdict on them).
                        if e.downcast_ref::<zkminer_prover_protocol::types::ProgramIdRefused>().is_some() {
                            return None;
                        }
                        return give_up();
                    }
                }
            };
            let mut c = lock(&cache);
            if c.len() >= 1024 {
                c.clear();
            }
            c.insert(key, id);
            Some(id)
        })
    }

    fn host_context(
        &self,
        serving: &Serving,
        store: &Arc<Store>,
        po2s: Vec<u8>,
        plan: &ProvePlan,
        worker_builds: Vec<String>,
    ) -> HostContext {
        let w = &self.witness;
        let c = &w.builder_clamps;
        HostContext {
            spawner: serving.spawner.clone(),
            broker: serving.broker_client.clone(),
            store: store.clone(),
            cgroup_root: serving.cgroup_root.clone(),
            builder_binary: serving.builder_binary.clone(),
            execute_binary: serving.execute_binary.clone(),
            host_maxima: HostMaxima {
                max_witness_bytes: w.max_witness_bytes,
                max_guest_cycles: w
                    .max_guest_cycles
                    .unwrap_or_else(|| host_max_guest_cycles(plan, self.proving_timeout.as_secs())),
                max_fetches: c.fetches,
                max_fetch_bytes: c.fetch_bytes,
                max_request_bytes: c.request_bytes,
                max_response_bytes: c.response_bytes,
                max_builder_fuel: c.fuel,
                max_builder_memory_bytes: c.memory_bytes,
                max_builder_seconds: c.seconds,
            },
            po2s,
            keccak_po2: self.keccak_po2,
            sys_rand_key: self.sys_rand_key,
            worker_builds,
            execute_memory_bytes: w.execute_memory_bytes,
            execute_timeout: EXECUTE_TIMEOUT,
            max_artifact_bytes: MAX_ARTIFACT_BYTES,
            image_id_fn: self.image_id_fn(),
            eviction_value: eviction_by_age(),
        }
    }

    /// A verdict for `jid` that holds now, read from the store when the in-memory cache has none.
    async fn verdict_holds(&self, store: &Arc<Store>, jid: B256) -> bool {
        let now = now_unix();
        if lock(&self.verdict_until).get(&jid).is_some_and(|t| *t > now) {
            return true;
        }
        let s = store.clone();
        match blocking(move || s.verdict(jid)).await {
            Ok(Ok(Some(v))) if v.expires_at > now => {
                lock(&self.verdict_until).insert(jid, v.expires_at);
                tracing::debug!("witness job {}: verdict {:?} holds until {}", short(jid), v.reason, v.expires_at);
                true
            }
            _ => false,
        }
    }

    /// Persists a skip verdict under its retry class (§15.2, §16) and counts a final one against the
    /// caller when the reason blames the caller.
    async fn record_verdict(&self, jid: B256, caller: Address, reason: SkipReason, detail: &str) {
        let store = self.store();
        let prior = match &store {
            Some(s) => {
                let s = s.clone();
                blocking(move || s.verdict(jid)).await.ok().and_then(|r| r.ok()).flatten().map_or(0, |v| v.attempts)
            }
            None => 0,
        };
        let plan = verdict_plan(reason, prior, rand::random::<f64>());
        let now = now_unix();
        let expires_at = now.saturating_add(plan.ttl_secs);
        {
            let mut v = lock(&self.verdict_until);
            if v.len() >= PER_JOB_CAP {
                v.retain(|_, t| *t > now);
            }
            v.insert(jid, expires_at);
        }
        if let Some(s) = store {
            let rec = VerdictRecord {
                job_id: jid,
                reason,
                attempts: plan.attempts,
                recorded_at: now,
                expires_at,
                wasmtime_version: None,
            };
            match blocking(move || s.put_verdict(&rec)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!("witness job {}: verdict not persisted: {e}", short(jid)),
                Err(e) => tracing::warn!("witness job {}: verdict not persisted: {e:#}", short(jid)),
            }
        }
        let blamed = lock(&self.blame).note_verdict(caller, reason, &plan);
        tracing::info!(
            "witness job {}: skipped — {reason:?} (attempt {}, {} for {} s){}: {}",
            short(jid),
            plan.attempts,
            if plan.final_verdict { "final" } else { "retried" },
            plan.ttl_secs,
            blamed.map_or(String::new(), |n| format!("; caller {caller} now has {n} failed job(s)")),
            zkminer_chain::programs::sanitize_log(detail)
        );
    }

    /// The chain-side static gates (§5.3), in the pre-claim lane: allowlist, submission form,
    /// deployment, serving, rate, the claimability `eth_call`, governance, the reservation.
    async fn chain_gates(&self, g: &ChainGateInput) -> Result<ClaimQuote, SkipReason> {
        with_lane(Lane::PreClaim, async {
            if !caller_admitted(&self.witness.callers, g.caller) {
                return Err(SkipReason::NotAdmitted);
            }
            if !matches!(g.form, SubmissionForm::Direct { .. }) {
                return Err(SkipReason::UnsupportedSubmission);
            }
            if !run::DEPLOYMENT_VERIFIED.load(Ordering::SeqCst)
                || zkminer_chain::deployment::code_pins_skipped()
                || !run::risc0_claimable()
            {
                return Err(SkipReason::DeploymentNotVerified);
            }
            if !self.serving_enabled() {
                return Err(SkipReason::WitnessDisabled);
            }
            if self.rate_expired() {
                return Err(SkipReason::WitnessDisabled);
            }
            let quote = self
                .client
                .claimability(g.job_id, self.client.address)
                .await
                .map_err(|nc| {
                    tracing::info!("witness job {}: not claimable ({nc})", short(g.job_id));
                    not_claimable_reason(&nc)
                })?;
            let deadline = zkminer_chain::client::chain_now()
                .saturating_add(g.window)
                .saturating_add(PROVER_GRACE_SECS);
            self.gov
                .witness_lock_gate(g.job_id, g.proof_system_id, deadline)
                .map_err(|r| {
                    tracing::info!("witness job {}: governance holds it ({r})", short(g.job_id));
                    gate_refusal_reason(&r)
                })?;
            let (_, max_fee) = self.client.base_fees().await;
            let reservation = reservation_wei(&self.reservation_inputs(
                self.client.fulfill_gas_limit,
                max_fee,
                0.0,
                g.expected_simulation_secs,
                0.0,
            ));
            if quote.price_floor < reservation {
                tracing::info!(
                    "witness job {}: price {} below the reservation {} (HEMI wei)",
                    short(g.job_id),
                    quote.price_floor,
                    reservation
                );
                return Err(SkipReason::BelowReservation);
            }
            Ok(quote)
        })
        .await
    }

    fn reservation_inputs(
        &self,
        fulfil_gas: u64,
        max_fee_per_gas: u128,
        prove_secs: f64,
        simulation_secs: f64,
        retained_gib_hours: f64,
    ) -> ReservationInputs {
        let prices = self.witness.unit_prices.as_ref();
        ReservationInputs {
            fulfil_gas,
            max_fee_per_gas,
            hemi_per_eth: self.witness.hemi_per_eth.unwrap_or(0.0),
            prove_secs,
            simulation_secs,
            retained_gib_hours,
            cpu_second_hemi: prices.map_or(0.0, |p| p.cpu_second_hemi),
            gib_hour_retained_hemi: prices.map_or(0.0, |p| p.gib_hour_retained_hemi),
            k: self.witness.k,
        }
    }

    /// `[witness] hemi_per_eth_expires` has passed (`PAGE: RATE-EXPIRED`; held locks continue).
    fn rate_expired(&self) -> bool {
        match self.rate_expires {
            Some(t) if rate_secs_left(t, chrono::Utc::now().timestamp()) > 0 => false,
            _ => {
                tracing::error!(
                    "PAGE: RATE-EXPIRED [witness] hemi_per_eth_expires has passed (or is unset): no \
                     witness job is admitted until it is renewed; held witness locks continue"
                );
                true
            }
        }
    }

    /// A bundle already published for this job and prover that is current on this host: reused
    /// instead of simulating again (§15.2 single flight; re-locks reuse their bundle). Not before the
    /// execute worker's build is known here (a simulation in this process learns it), and never one
    /// that does not record its execute time (the prove's execute allowance).
    async fn retained_candidate(&self, store: &Arc<Store>, jid: B256, dh: B256, po2s: &[u8]) -> Option<Candidate> {
        lock(&self.execute_build).as_ref()?;
        let profile = self.host_profile(po2s)?;
        let (s, prover, idf) = (store.clone(), self.client.address, self.image_id_fn());
        blocking(move || {
            let r = s.latest(jid, dh, prover).ok()?;
            let (record, elf) = s.verify_with_elf(&r, &descriptor_hash_of_abi, &*idf).ok()?;
            let execute_ms = record.execute_ms_per_po2?;
            if !revalidate(&record, &profile).is_current() {
                return None;
            }
            let journal = hex::decode(&record.po2_results.first()?.journal_hex).ok()?;
            Some(Candidate {
                bundle: r,
                journal,
                per_po2: record.po2_results.iter().map(|p| (p.po2, p.cycles, p.segment_bytes, 0)).collect(),
                simulation_secs: 0.0,
                execute_secs_per_po2: execute_ms.div_ceil(1000),
                record,
                elf,
            })
        })
        .await
        .ok()
        .flatten()
    }

    /// Why new witness work must not start now, though nothing is wrong with any job: the operator
    /// paused claiming (or the miner drives held locks only), or switched risc0 off.
    async fn claims_held(&self) -> Option<&'static str> {
        if run::held_locks_only() {
            return Some("the miner drives held locks only");
        }
        let st = self.state.read().await;
        if st.paused {
            return Some("claiming is paused");
        }
        if st.runtime_settings.disabled_backends.contains(zkminer_prover_protocol::BACKEND_RISC0) {
            return Some("risc0 is switched off");
        }
        None
    }

    /// Everything before a witness lock (§5.2 steps 0–9). `None` when the job is not locked now.
    async fn simulate_and_lock(self: &Arc<Self>, job: &TrackedJob, dh: B256, token: &AbortToken) -> Option<LockCtx> {
        let jid = job.info.job_id;
        let caller = job.info.caller;
        let store = self.store()?;
        let serving = self.serving()?;
        // A pending or held claim of ours is recovery's: a pinned job is never simulated again, and
        // the builder never runs after a lock (§5.1, §15.2).
        if run::journal_has(&self.journal, jid) || self.is_witness_lock(jid) {
            return None;
        }
        if let Some(why) = self.claims_held().await {
            tracing::debug!("witness job {}: not simulated now ({why})", short(jid));
            return None;
        }
        if self.verdict_holds(&store, jid).await {
            return None;
        }
        // §16: a caller with too many post-lock failures is not admitted (read from the store, so a
        // restart forgets nothing; routing then sets its jobs aside).
        if self.caller_post_lock_failures_now(caller).await >= POST_LOCK_CALLER_LIMIT {
            return None;
        }
        // The governance watcher must be synced before any of its gates means anything; a host-side
        // wait, never a verdict on the job.
        if let Some(r) = self.gov.sync_refusal() {
            tracing::debug!("witness job {}: waiting for the governance watcher ({r})", short(jid));
            return None;
        }
        if self.rate_expired() {
            return None;
        }
        let _permit = self.sim_slots.clone().acquire_owned().await.ok()?;
        if token.is_aborted() || shutting_down() {
            return None;
        }
        // The job's record: still Open, the window a lock gets, the callback's gas.
        let (rec, _) = match with_lane(Lane::PreClaim, self.client.read_job_record(jid, None)).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("witness job {}: job record unreadable ({e:#})", short(jid));
                return None;
            }
        };
        if rec.status != JOB_STATUS_OPEN || rec.prover != Address::ZERO || rec.descriptor_hash != dh {
            return None;
        }
        // The descriptor and its submission form, from the submit transaction.
        let cached = lock(&self.descriptors).remove(&jid);
        let fetched = match cached {
            Some(f) => f,
            None => match with_lane(
                Lane::PreClaim,
                tokio::time::timeout(FETCH_BUDGET, fetch_job_descriptor_checked_with_form(&self.client, jid, dh)),
            )
            .await
            {
                Ok(Ok(f)) => f,
                Ok(Err(e)) if e.downcast_ref::<zkminer_chain::descriptor::UndecodableDescriptor>().is_some() => {
                    self.record_verdict(jid, caller, SkipReason::UnsupportedSubmission, &format!("{e:#}")).await;
                    return None;
                }
                Ok(Err(e)) => {
                    self.record_verdict(jid, caller, SkipReason::OperatorEndpoint, &format!("descriptor: {e:#}")).await;
                    return None;
                }
                Err(_) => {
                    self.record_verdict(jid, caller, SkipReason::OperatorEndpoint, "descriptor fetch timed out").await;
                    return None;
                }
            },
        };
        let d = fetched.descriptor.clone();
        if !is_witness_input(&d.inputData) {
            note_class(jid, Class::Inline);
            return None;
        }
        if fetched.tx_from.is_some_and(|f| f != caller) {
            self.record_verdict(jid, caller, SkipReason::UnsupportedSubmission, "the submit transaction's sender is not the job's caller").await;
            return None;
        }
        let po2s = self.host_po2s().await;
        if po2s.is_empty() {
            self.record_verdict(jid, caller, SkipReason::ProveResources, "no enabled risc0 card has a job size").await;
            return None;
        }
        let plan = self.prove_plan(&po2s).await;
        let Some(prove_builds) = self.prove_worker_builds() else {
            tracing::debug!("witness job {}: no risc0 prove worker has named its build yet", short(jid));
            return None;
        };
        let gate_input = ChainGateInput {
            job_id: jid,
            proof_system_id: d.proofSystemId,
            caller,
            form: fetched.form.clone(),
            window: rec.fulfillment_timeout,
            expected_simulation_secs: f64::from(self.witness.builder_clamps.seconds.min(60)),
        };

        let (candidate, quote) = match self.retained_candidate(&store, jid, dh, &po2s).await {
            Some(c) => {
                tracing::info!("witness job {}: reusing its retained bundle v{}", short(jid), c.bundle.version);
                match self.chain_gates(&gate_input).await {
                    Ok(q) => (c, q),
                    Err(r) => {
                        self.record_verdict(jid, caller, r, "the chain gates").await;
                        return None;
                    }
                }
            }
            None => {
                let ctx = self.host_context(&serving, &store, po2s.clone(), &plan, prove_builds);
                let hooks = Hooks {
                    rt: self.clone(),
                    gate: gate_input.clone(),
                    token: token.clone(),
                    budget: ArtifactBudget::for_max_bytes(MAX_ARTIFACT_BYTES),
                    quote: Mutex::new(None),
                    program_id: d.programId,
                    elf: Mutex::new(None),
                };
                let current_block = self.client.head_block_cached().await.unwrap_or(0);
                let input = JobInput {
                    job_id: jid,
                    descriptor: &d,
                    descriptor_hash: dh,
                    submit_tx_hash: fetched.submit_tx,
                    caller,
                    prover: self.client.address,
                    chain_id: self.client.chain_id,
                    router: self.client.hemi_prove,
                    // Fetched by the hook once the static gates have passed (§5.2 step 3).
                    elf: None,
                    current_block,
                };
                tracing::info!("witness job {}: simulating (po2 {po2s:?})", short(jid));
                match simulate_witness_job(&ctx, &input, &hooks).await {
                    Ok(sim) => {
                        let quote = lock(&hooks.quote).take();
                        let elf = lock(&hooks.elf).take();
                        let (Some(quote), Some(elf)) = (quote, elf) else {
                            tracing::error!("witness job {}: simulated without a claimability quote or its ELF", short(jid));
                            return None;
                        };
                        *lock(&self.execute_build) = Some(sim.execute_build.clone());
                        tracing::info!(
                            "witness job {}: simulated — bundle v{}, |W| {} bytes, journal {} bytes",
                            short(jid),
                            sim.bundle.version,
                            sim.w_len,
                            sim.journal.len()
                        );
                        (Candidate::from_sim(sim, elf), quote)
                    }
                    Err(Skip::Verdict { reason, step, detail }) => {
                        self.record_verdict(jid, caller, reason, &format!("{step:?}: {detail}")).await;
                        return None;
                    }
                    Err(Skip::Aborted { reason, step }) => {
                        tracing::info!("witness job {}: simulation aborted at {step:?} ({reason:?})", short(jid));
                        return None;
                    }
                }
            }
        };
        if token.is_aborted() || shutting_down() {
            return None;
        }
        let gate = match self.claim_gate(jid, &d, &rec, &candidate, &plan, quote.price_floor).await {
            Ok(g) => g,
            Err((reason, detail)) => {
                self.record_verdict(jid, caller, reason, &format!("claim gate: {detail}")).await;
                return None;
            }
        };
        self.lock(job, d, &fetched, candidate, gate, rec.reopen_count, token).await
    }

    // ── the claim gate (§5.2 step 7) ──────────────────────────────────────────

    async fn claim_gate(
        &self,
        jid: B256,
        d: &JobDescriptor,
        rec: &JobRecord,
        c: &Candidate,
        plan: &ProvePlan,
        price: u128,
    ) -> Result<GateOk, (SkipReason, String)> {
        with_lane(Lane::PreClaim, async {
            if c.journal.len() > MAX_JOURNAL_BYTES {
                return Err((SkipReason::JournalTooLarge, format!("{} bytes", c.journal.len())));
            }
            if !run::risc0_claimable() {
                return Err((SkipReason::VerifierSelectorMismatch, "the risc0 adapter is not verified claimable".into()));
            }
            // The exact fulfil's DA size, against the operator cap and the backlog.
            let fulfil = HashedFulfil::from_descriptor(d);
            let est = estimate_fulfil_da_bytes(&self.client, jid, &fulfil, &c.journal, &SealSpec::risc0_groth16())
                .await
                .map_err(|e| (SkipReason::OperatorEndpoint, format!("DA estimate: {e:#}")))?;
            let reading = self.backlog.read(&self.client).await;
            if let Decision::Skip(s) = self.da_policy.fulfil_fits(est.estimated_bytes, reading.backlog) {
                return Err((SkipReason::FulfilDaTooLarge, format!("{s:?}")));
            }
            // Gas, by the guide's formula (at least the configured floor), and the ETH to pay it.
            let fulfil_gas = fulfill_gas_formula(rec.callback_gas_limit, est.calldata_len, c.journal.len())
                .max(self.client.fulfill_gas_limit);
            let (_, max_fee) = self.client.base_fees().await;
            if let Ok(bal) = self.client.get_eth_balance().await {
                if !funds_cover(bal, fulfil_gas, max_fee, self.held_locks()) {
                    return Err((
                        SkipReason::NotAdmitted,
                        format!("ETH balance {bal} wei does not fund this claim and every held fulfil"),
                    ));
                }
            }
            // The operator's risc0 session cap (the prove worker applies it), on the sized cycles.
            let cycles = c.cycles();
            let cap = parse_session_cap(std::env::var("ZKMINER_RISC0_MAX_SESSION_CYCLES").ok().as_deref());
            if !session_cap_admits(cycles, cap) {
                return Err((
                    SkipReason::LimitsAboveHostMaxima,
                    format!("{cycles} sized cycles, over ZKMINER_RISC0_MAX_SESSION_CYCLES {}", cap.unwrap_or(0)),
                ));
            }
            // The proving time: every attempt inside the watchdog, and the margin before D.
            let prove_secs = estimate_prove_secs(cycles, plan, c.execute_secs_per_po2);
            let timeout = self.proving_timeout.as_secs();
            if !watchdog_admits(prove_secs, timeout) {
                // This host's limit (a raised `proving_timeout_secs` or a faster card changes it).
                return Err((
                    SkipReason::LimitsAboveHostMaxima,
                    format!("about {prove_secs} s to prove, at or over the {timeout} s per-attempt proving timeout"),
                ));
            }
            if !deadline_fits(rec.fulfillment_timeout, prove_secs, run::DEADLINE_FULFILL_MARGIN_SECS, run::MIN_ATTEMPT_BUDGET_SECS) {
                return Err((
                    SkipReason::DeadlineMargin,
                    format!("about {prove_secs} s to prove in a {} s window", rec.fulfillment_timeout),
                ));
            }
            // Prove resources: segment disk (reserved now, for this job, against every other proof
            // planned or running), then host RAM through the dispatcher's ledger.
            let need = segment_need(c.per_po2.iter().map(|p| p.2));
            if let Some(dir) = self.retention.as_ref().map(|r| r.segment_dir.clone()) {
                let mut reserved = lock(&self.segment_reserved);
                let others: u64 = reserved.iter().filter(|(j, _)| **j != jid).map(|(_, b)| *b).sum();
                match free_bytes(&dir) {
                    Ok(free) if segments_fit(need, others, free) => {
                        reserved.insert(jid, need);
                    }
                    Ok(free) => {
                        return Err((
                            SkipReason::ProveResources,
                            format!("segments need {need} bytes beside {others} reserved; {free} free under {}", dir.display()),
                        ))
                    }
                    Err(e) => return Err((SkipReason::ProveResources, format!("segment directory {}: {e}", dir.display()))),
                }
            }
            if let (Some(pool), Some(available), Some(total)) = (
                zkminer_prover::engine::worker_pool(),
                zkminer_prover::memory::mem_available_bytes(),
                zkminer_prover::memory::mem_total_bytes(),
            ) {
                let peak = c
                    .per_po2
                    .iter()
                    .map(|p| p.3)
                    .max()
                    .unwrap_or(0)
                    .max(zkminer_prover::memory::unmeasured_peak_for(zkminer_prover_protocol::BACKEND_RISC0))
                    .saturating_add(c.record.w_len);
                if !zkminer_prover::memory::can_admit(
                    peak,
                    0,
                    pool.reserved_host_memory(),
                    available,
                    total,
                    zkminer_prover::memory::DEFAULT_HOST_RESERVE_BYTES,
                ) {
                    return Err((SkipReason::ProveResources, format!("host RAM: a {peak}-byte proof does not fit now")));
                }
            }
            // The reservation, with the measured terms (§17.2).
            let gib = c.record.w_len as f64 / f64::from(1u32 << 30);
            let hours = (rec.fulfillment_timeout as f64 + PROVER_GRACE_SECS as f64) / 3600.0;
            let reservation = reservation_wei(&self.reservation_inputs(fulfil_gas, max_fee, prove_secs as f64, c.simulation_secs, gib * hours));
            if price < reservation {
                return Err((SkipReason::BelowReservation, format!("price {price} below the reservation {reservation}")));
            }
            tracing::info!(
                "witness job {}: claim gate passed — fulfil {} estimated DA bytes, {fulfil_gas} gas, ~{prove_secs} s to prove \
                 ({} c/s, {} s fixed, margin {:.2}; watchdog {timeout} s)",
                short(jid),
                est.estimated_bytes,
                plan.cps.round(),
                plan.fixed_secs,
                plan.margin
            );
            Ok(GateOk { reservation, window: rec.fulfillment_timeout, fulfil_gas })
        })
        .await
    }

    /// Locks held here, inline and witness, besides any being claimed now: the journal's entries
    /// (each a claim of ours, pending or held).
    fn held_locks(&self) -> usize {
        lock(&self.journal).entries.len()
    }

    // ── the lock (§5.2 step 9) ────────────────────────────────────────────────

    /// Drops what a claim that provably did not land left: the claim intent and the pin. When an
    /// earlier claim of ours is unresolved (`prior`), both stay: that claim may have landed, and its
    /// lock would then be proven from this pin (recovery decides from the chain).
    async fn abandon_intent(&self, jid: B256, bundle: BundleRef, prior: bool) {
        lock(&self.segment_reserved).remove(&jid);
        if prior {
            return;
        }
        run::journal_update(&self.journal, |j| j.remove(jid));
        if let Some(s) = self.store() {
            let _ = blocking(move || s.unpin(bundle.job_id, bundle.descriptor_hash, bundle.prover)).await;
        }
    }

    /// Why a witness lock must not be taken right now, though the job passed every gate: re-checked
    /// right before the claim intent and again before the claim, as the inline path re-checks before
    /// it bonds collateral (a pause, a jammed signer, funds, a card, serving switched off). The card
    /// is taken for `jid` here, in one step with its check ([`take_card`]); the caller gives it back
    /// when it does not claim.
    async fn lock_held_back(&self, jid: B256, fulfil_gas: u64) -> Option<String> {
        if let Some(why) = self.claims_held().await {
            return Some(why.to_string());
        }
        if !self.serving_enabled() {
            return Some("witness serving is off".into());
        }
        if self.client.signer_is_jammed() {
            return Some(format!("the signer is jammed at nonce {:?}", self.client.jammed_nonce()));
        }
        if self.client.funds_short() {
            return Some("a recent send was refused for insufficient funds".into());
        }
        let (_, max_fee) = self.client.base_fees().await;
        match self.client.get_eth_balance().await {
            Ok(bal) if !funds_cover(bal, fulfil_gas, max_fee, self.held_locks()) => {
                return Some(format!("ETH balance {bal} wei does not fund this claim and every held fulfil"));
            }
            Ok(_) => {}
            Err(e) => return Some(format!("the ETH balance is unreadable ({e:#})")),
        }
        let slots: Vec<String> = run::current_risc0_cards(&self.state, true).await.into_iter().map(|c| c.slot).collect();
        if !slots.is_empty() && self.quarantined(&slots).await.len() == slots.len() {
            return Some("every risc0 card is quarantined for witness proofs (post-lock failures)".into());
        }
        // Last, with nothing awaited after it: the card, checked and taken at once.
        if !self.take_card(jid) {
            return Some("no card is free for its proof (inline work or witness locks fill them)".into());
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    async fn lock(
        self: &Arc<Self>,
        job: &TrackedJob,
        d: JobDescriptor,
        fetched: &FetchedDescriptor,
        c: Candidate,
        gate: GateOk,
        reopen_count: u8,
        token: &AbortToken,
    ) -> Option<LockCtx> {
        let jid = job.info.job_id;
        let caller = job.info.caller;
        let store = self.store()?;
        // 1. Revalidate the bundle against the host as it is now: the cards' po2 set read again here,
        //    not the one the simulation began with.
        let (s, b, idf) = (store.clone(), c.bundle, self.image_id_fn());
        match blocking(move || s.verify(&b, &descriptor_hash_of_abi, &*idf)).await {
            Ok(Ok(r)) if r == c.record => {}
            Ok(Ok(_)) => {
                self.record_verdict(jid, caller, SkipReason::HostInternal, "the bundle changed under its version").await;
                return None;
            }
            Ok(Err(e)) => {
                self.record_verdict(jid, caller, SkipReason::HostInternal, &format!("revalidation: {e}")).await;
                return None;
            }
            Err(e) => {
                self.record_verdict(jid, caller, SkipReason::HostInternal, &format!("revalidation: {e:#}")).await;
                return None;
            }
        }
        let po2s = self.host_po2s().await;
        let Some(profile) = self.host_profile(&po2s) else {
            tracing::debug!("witness job {}: a worker build is not known; not locked now", short(jid));
            return None;
        };
        let reval = revalidate(&c.record, &profile);
        if !reval.is_current() {
            self.record_verdict(jid, caller, SkipReason::HostInternal, &format!("the bundle is not current on this host: {reval:?}"))
                .await;
            return None;
        }
        if token.is_aborted() || shutting_down() {
            return None;
        }
        // The card this claim takes (below) goes back however the claim is not sent; a lock held
        // keeps it (`Phase::Locked`).
        let _card = CardTaken { rt: &**self, jid };
        if let Some(why) = self.lock_held_back(jid, gate.fulfil_gas).await {
            // Not the job's doing: a short, deferred verdict, and the bundle stays for the next try.
            tracing::info!("witness job {}: not locked now — {}", short(jid), zkminer_chain::programs::sanitize_log(&why));
            self.record_verdict(jid, caller, SkipReason::NotAdmitted, &why).await;
            return None;
        }
        // 2. Pin it, before the claim intent is journaled and before the lock is signed, with the
        //    lock instance it is for and the chain time (§15.2: a pin goes only on evidence). The
        //    instance is read at or after the head, so a lagging replica cannot record an earlier
        //    one (a later read's higher count would then look like proof the claim's lock ended).
        let head = self.client.head_block_cached().await.unwrap_or(c.record.created_at_block);
        let reopen_count = match with_lane(Lane::Lock, self.client.read_job_record(jid, Some(head))).await {
            Ok((now, _)) if now.status == JOB_STATUS_OPEN && now.prover == Address::ZERO => now.reopen_count.max(reopen_count),
            Ok(_) => {
                tracing::info!("witness job {}: no longer Open at the lock", short(jid));
                return None;
            }
            Err(e) => {
                tracing::debug!("witness job {}: its record is unreadable at the lock ({e:#}); not locked now", short(jid));
                return None;
            }
        };
        let pinned_at_unix = zkminer_chain::client::chain_now_floor();
        let (s, b) = (store.clone(), c.bundle);
        let pinned = blocking(move || {
            let mut rec = s.pin_record(&b, head)?;
            rec.reopen_count = Some(reopen_count);
            rec.pinned_at_unix = pinned_at_unix;
            s.pin(&rec).map(|()| rec)
        })
        .await;
        let pin = match pinned {
            Ok(Ok(rec)) => rec,
            Ok(Err(e)) => {
                self.record_verdict(jid, caller, SkipReason::HostInternal, &format!("pinning: {e}")).await;
                return None;
            }
            Err(e) => {
                self.record_verdict(jid, caller, SkipReason::HostInternal, &format!("pinning: {e:#}")).await;
                return None;
            }
        };
        tracing::info!("WITNESS-LOCK {}: bundle v{} pinned", short(jid), c.bundle.version);
        // 3. The claim intent, with the bundle it will be proven from.
        let prior = run::journal_has(&self.journal, jid);
        let wref = bundle_ref(&c.bundle);
        let executed: Vec<u8> = c.per_po2.iter().filter_map(|p| u8::try_from(p.0).ok()).collect();
        run::journal_update(&self.journal, |j| {
            j.record_claim_intent(jid, 0, Some(fetched.submit_tx));
            j.record_witness_bundle(jid, wref);
            j.note_measured_po2s(jid, &executed);
        });
        if token.is_aborted() || shutting_down() {
            self.abandon_intent(jid, c.bundle, prior).await;
            return None;
        }
        // 4. The claimability call again, right before the lock, and the governance gate.
        let quote = match with_lane(Lane::Lock, self.client.claimability(jid, self.client.address)).await {
            Ok(q) => q,
            Err(nc) => {
                self.abandon_intent(jid, c.bundle, prior).await;
                tracing::info!("witness job {}: not claimable at the lock ({nc})", short(jid));
                self.record_verdict(jid, caller, not_claimable_reason(&nc), &format!("at the lock: {nc}")).await;
                return None;
            }
        };
        if quote.price_floor < gate.reservation {
            self.abandon_intent(jid, c.bundle, prior).await;
            self.record_verdict(jid, caller, SkipReason::BelowReservation, "the price fell below the reservation").await;
            return None;
        }
        let deadline = zkminer_chain::client::chain_now().saturating_add(gate.window).saturating_add(PROVER_GRACE_SECS);
        if let Err(r) = self.gov.witness_lock_gate(jid, d.proofSystemId, deadline) {
            self.abandon_intent(jid, c.bundle, prior).await;
            self.record_verdict(jid, caller, gate_refusal_reason(&r), &format!("at the lock: {r}")).await;
            return None;
        }
        if token.is_aborted() || shutting_down() {
            self.abandon_intent(jid, c.bundle, prior).await;
            return None;
        }
        if let Some(why) = self.lock_held_back(jid, gate.fulfil_gas).await {
            self.abandon_intent(jid, c.bundle, prior).await;
            tracing::info!("witness job {}: not locked now — {}", short(jid), zkminer_chain::programs::sanitize_log(&why));
            self.record_verdict(jid, caller, SkipReason::NotAdmitted, &why).await;
            return None;
        }
        // From here the task holds (or may hold) a lock: no abort reaches it, and it counts against
        // the cards.
        if let Some(t) = lock(&self.tasks).get_mut(&jid) {
            t.phase = Phase::Locked;
        }
        {
            let mut s = self.state.write().await;
            s.add_log(LogLevel::Info, format!("Claiming witness job {}...", short(jid)));
        }
        // 5. The claim, alone, exactly as the inline path claims (floors at a mined block, the
        //    high-water mark, the receipt, the re-read of jobs().prover).
        let outcome = with_lane(Lane::Lock, self.client.claim_job_idempotent(jid, gate.reservation)).await;
        let lock_block = match outcome {
            Ok(ClaimOutcome::Claimed(r)) => r.block,
            Ok(ClaimOutcome::LostRace) => {
                if prior {
                    tracing::warn!("witness job {}: another prover reads as holding it while an earlier claim of ours is unresolved; recovery decides", short(jid));
                    run::request_recovery();
                } else {
                    self.abandon_intent(jid, c.bundle, prior).await;
                    tracing::info!("witness job {}: claimed by another prover first", short(jid));
                }
                return None;
            }
            Err(e) if e.downcast_ref::<zkminer_chain::revert::ClaimNotSent>().is_some() => {
                tracing::warn!("witness job {}: claim not sent ({e:#}); retried later", short(jid));
                self.abandon_intent(jid, c.bundle, prior).await;
                return None;
            }
            Err(e) => {
                if let Some(f) = e.downcast_ref::<zkminer_chain::revert::ClaimFailure>() {
                    if f.definitely_not_locked {
                        let reason = f.reason.clone();
                        self.abandon_intent(jid, c.bundle, prior).await;
                        self.record_verdict(jid, caller, SkipReason::NotClaimable, &format!("claim refused: {reason}")).await;
                        return None;
                    }
                }
                // The claim may have mined: keep the intent and the pin; recovery decides from the
                // chain and drives the lock from its pin if it is ours.
                run::journal_update(&self.journal, |j| j.note_claim_unconfirmed(jid));
                tracing::warn!("witness job {}: claim outcome unconfirmed ({e:#}); kept pinned for recovery", short(jid));
                run::request_recovery();
                return None;
            }
        };
        run::note_lock_block(jid, lock_block);
        // 6. The post-claim view, pinned at or after the lock block: the effective deadline.
        let mut view = with_lane(Lane::HeldLock, self.client.get_job_status_view_at(jid, lock_block)).await;
        for _ in 0..run::DEADLINE_READ_RETRIES {
            if matches!(&view, Ok(v) if run::effective_cutoff(v) != 0) {
                break;
            }
            tokio::time::sleep(run::DEADLINE_READ_RETRY_DELAY).await;
            view = with_lane(Lane::HeldLock, self.client.get_job_status_view_at(jid, lock_block)).await;
        }
        let view = match view {
            Ok(v) if run::effective_cutoff(&v) != 0 => v,
            _ => {
                tracing::warn!("witness job {}: locked at block {lock_block}, deadline unreadable; recovery drives it", short(jid));
                run::request_recovery();
                return None;
            }
        };
        let lock_deadline = run::effective_cutoff(&view);
        // The pin learns where the lock was seen, and its instance: a read at or after the block
        // showing another prover, or a higher count, is proof the lock is gone (best effort; without
        // it the pin stays until other evidence).
        self.note_pin_lock(&store, pin, lock_block, view.reopenCount).await;
        let locked_collateral = with_lane(Lane::HeldLock, self.client.read_job_record(jid, Some(lock_block)))
            .await
            .map(|(r, _)| r.locked_collateral)
            .unwrap_or(0);
        run::journal_update(&self.journal, |j| {
            j.mark_claimed(jid, None, lock_deadline);
            j.note_lock_seen(jid, Some(lock_block), view.reopenCount);
        });
        {
            let mut s = self.state.write().await;
            s.open_jobs.retain(|j| j.info.job_id != jid);
            let mut info = job.info.clone();
            info.lock_deadline = lock_deadline;
            s.active_jobs.push(TrackedJob {
                info,
                status: MinerJobStatus::Queued,
                current_price: view.currentAuctionPrice.to::<u128>(),
                gpu_bus_id: None,
                prover_backend: String::new(),
                estimated_cycles: c.cycles(),
            });
            s.add_log(LogLevel::Success, format!("Witness job {} claimed", short(jid)));
        }
        tracing::info!("WITNESS-LOCK {}: claimed at block {lock_block} (deadline {lock_deadline})", short(jid));
        Some(LockCtx {
            job_id: jid,
            caller,
            descriptor: d,
            bundle: c.bundle,
            cycles: c.cycles(),
            record: c.record,
            elf: c.elf,
            lock_block,
            lock_deadline,
            locked_collateral,
            failure: None,
        })
    }

    /// Re-pins `pin` with the block the lock was seen at and its reopen count (best effort).
    async fn note_pin_lock(&self, store: &Arc<Store>, mut pin: PinRecord, lock_block: u64, reopen_count: u8) {
        if lock_block == 0 || (pin.lock_block == lock_block && pin.reopen_count == Some(reopen_count)) {
            return;
        }
        pin.lock_block = lock_block;
        pin.reopen_count = Some(reopen_count);
        let (s, jid) = (store.clone(), pin.job_id);
        match blocking(move || s.pin(&pin)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!("witness lock {}: recording the lock block in its pin failed ({e})", short(jid)),
            Err(e) => tracing::warn!("witness lock {}: recording the lock block in its pin failed ({e:#})", short(jid)),
        }
    }

    // ── a held lock ───────────────────────────────────────────────────────────

    /// Proves and fulfils a held witness lock; on a failure that is not a hand-back, releases it and
    /// records the post-lock failure (§16).
    async fn run_locked(self: &Arc<Self>, mut l: LockCtx) {
        let jid = l.job_id;
        let caller = l.caller;
        let link = lock(&self.brain).clone();
        let _slot = link.map(|b| {
            let _ = b.held.send((jid, l.locked_collateral, l.cycles));
            run::SlotGuard(jid, b.done)
        });
        let result = with_lane(Lane::HeldLock, self.prove_and_fulfil(&mut l)).await;
        lock(&self.segment_reserved).remove(&jid);
        let bundle = l.bundle;
        match result {
            Ok(()) => {}
            Err(e) if e.downcast_ref::<run::HandBack>().is_some() => {
                let h = e.downcast_ref::<run::HandBack>().map(|h| h.0.clone()).unwrap_or_default();
                tracing::warn!("KEEP: witness lock {} {}", short(jid), zkminer_chain::programs::sanitize_log(&h));
                let mut s = self.state.write().await;
                s.active_jobs.retain(|j| j.info.job_id != jid);
                s.add_log(LogLevel::Warn, format!("Witness job {} kept: {}", short(jid), zkminer_chain::programs::sanitize_log(&h)));
                drop(s);
                run::request_recovery();
            }
            Err(e) => {
                let msg = zkminer_chain::programs::sanitize_log(&format!("{e:#}"));
                let (slot, class) = l.failure.clone().unwrap_or_else(|| (None, failure_class(&e)));
                tracing::error!("witness lock {} failed after the lock ({msg}); releasing", short(jid));
                self.state.write().await.add_log(LogLevel::Error, format!("Witness job {} failed: {msg}", short(jid)));
                // Before the release: a restart between the two must not lock the job again.
                self.record_post_lock_failure(jid, caller, slot.as_deref().map(device_of_slot), class).await;
                if run::journal_has(&self.journal, jid) {
                    with_lane(Lane::HeldLock, run::release_and_clean(&self.client, &self.state, &self.journal, jid)).await;
                } else {
                    self.state.write().await.active_jobs.retain(|j| j.info.job_id != jid);
                }
                // Released (or gone): the reopen count rose, so the pin goes; the bundle stays a cache
                // (the job's final verdict keeps it from being locked again).
                if !run::journal_has(&self.journal, jid) {
                    if let Some(s) = self.store() {
                        let _ = blocking(move || s.unpin(bundle.job_id, bundle.descriptor_hash, bundle.prover)).await;
                    }
                }
            }
        }
    }

    /// A witness lock of `jid` failed after the lock (§16): a final verdict for the job (its bundle
    /// is never locked again, across restarts), and the caller's and the device's tallies, kept in
    /// the store. Never fed to the host-wide program marks.
    async fn record_post_lock_failure(&self, jid: B256, caller: Address, device: Option<String>, class: PostLockFailureClass) {
        self.record_verdict(jid, caller, SkipReason::PostLockFailure, &format!("{class:?}")).await;
        let n = self.bump_tally(caller_tally_key(caller)).await;
        lock(&self.post_lock_callers).insert(caller, (n, now_unix().saturating_add(POST_LOCK_TALLY_TTL_SECS)));
        tracing::error!(
            "witness lock {}: post-lock failure ({class:?}{}) — caller {caller} has {n} in the last {} days{}",
            short(jid),
            device.as_deref().map_or(String::new(), |d| format!(" on {d}")),
            POST_LOCK_TALLY_TTL_SECS / 86_400,
            if n >= POST_LOCK_CALLER_LIMIT { "; its witness jobs are no longer admitted" } else { "" }
        );
        if let Some(d) = device {
            let k = self.bump_tally(device_tally_key(&d, class)).await;
            if k >= POST_LOCK_DEVICE_LIMIT {
                tracing::error!(
                    "PAGE: WITNESS-DEVICE-QUARANTINED {d}: {k} post-lock witness failures of class {class:?} in the \
                     last {} days — it proves no witness lock until they age out (inline jobs are unaffected)",
                    POST_LOCK_TALLY_TTL_SECS / 86_400
                );
            }
        }
    }

    /// Adds one to a post-lock tally (a store verdict record under a key that is never a job id) and
    /// returns the count. An expired tally starts again. Without a store, counted in memory.
    async fn bump_tally(&self, key: B256) -> u8 {
        let now = now_unix();
        let Some(store) = self.store() else {
            let mut m = lock(&self.tallies);
            let e = m.entry(key).or_insert((0, 0));
            let n = tally_count(e.0, e.1, now).saturating_add(1);
            *e = (n, now.saturating_add(POST_LOCK_TALLY_TTL_SECS));
            return n;
        };
        let result = blocking(move || {
            let prior = store.verdict(key).ok().flatten().map_or(0, |v| tally_count(v.attempts, v.expires_at, now));
            let n = prior.saturating_add(1);
            let rec = VerdictRecord {
                job_id: key,
                reason: SkipReason::PostLockFailure,
                attempts: n,
                recorded_at: now,
                expires_at: now.saturating_add(POST_LOCK_TALLY_TTL_SECS),
                wasmtime_version: None,
            };
            store.put_verdict(&rec).map(|()| n).map_err(|e| (n, e))
        })
        .await;
        match result {
            Ok(Ok(n)) => n,
            Ok(Err((n, e))) => {
                tracing::warn!("witness: a post-lock failure tally was not persisted: {e}");
                n
            }
            Err(e) => {
                tracing::warn!("witness: a post-lock failure tally was not persisted: {e:#}");
                1
            }
        }
    }

    /// A post-lock tally's count now (0 when there is none, or it expired).
    async fn tally(&self, key: B256) -> u8 {
        let now = now_unix();
        let Some(store) = self.store() else {
            return lock(&self.tallies).get(&key).map_or(0, |(n, t)| tally_count(*n, *t, now));
        };
        blocking(move || store.verdict(key).ok().flatten().map_or(0, |v| tally_count(v.attempts, v.expires_at, now)))
            .await
            .unwrap_or(0)
    }

    /// The caller's post-lock failures as last read here (`None` when not read yet).
    fn caller_post_lock_failures(&self, caller: Address) -> Option<u8> {
        let now = now_unix();
        lock(&self.post_lock_callers).get(&caller).map(|(n, t)| tally_count(*n, *t, now))
    }

    /// The caller's post-lock failures read from the store (and remembered for routing).
    async fn caller_post_lock_failures_now(&self, caller: Address) -> u8 {
        let n = self.tally(caller_tally_key(caller)).await;
        let mut m = lock(&self.post_lock_callers);
        if m.len() >= PER_JOB_CAP {
            m.clear();
        }
        m.insert(caller, (n, now_unix().saturating_add(POST_LOCK_TALLY_TTL_SECS)));
        n
    }

    /// The slots among `slots` whose device is quarantined: a post-lock witness failure tally of
    /// some class at [`POST_LOCK_DEVICE_LIMIT`] (§16).
    async fn quarantined(&self, slots: &[String]) -> HashSet<String> {
        let mut out = HashSet::new();
        for slot in slots {
            let device = device_of_slot(slot);
            for class in POST_LOCK_CLASSES {
                if self.tally(device_tally_key(&device, class)).await >= POST_LOCK_DEVICE_LIMIT {
                    out.insert(slot.clone());
                    break;
                }
            }
        }
        out
    }

    /// The time a held lock must be proven by: its deadline, or a pending verifier swap's `readyAt`
    /// for its proof system when that comes first (§5.5).
    fn proving_cutoff(&self, l: &LockCtx) -> u64 {
        let ready = self.gov.state().pending_switch(l.descriptor.proofSystemId).map(|p| p.ready_at);
        proving_cutoff(l.lock_deadline, ready)
    }

    async fn prove_and_fulfil(self: &Arc<Self>, l: &mut LockCtx) -> Result<()> {
        let jid = l.job_id;
        let mut card = run::CardRelease(Some(jid));
        let Some(store) = self.store() else {
            tracing::error!("PAGE: RETENTION-UNAVAILABLE witness lock {} is kept: the retention store is unavailable", short(jid));
            return Err(run::HandBack("the retention store is unavailable".into()).into());
        };
        if let Err(e) = run::ensure_deadline_room(l.lock_deadline, run::DEADLINE_FULFILL_MARGIN_SECS) {
            if self.client.job_clock_stopped(l.descriptor.proofSystemId).await {
                return Err(run::HandBack(format!("{e:#} while the job's clock is stopped")).into());
            }
            l.failure = Some((None, PostLockFailureClass::ProveTimeEstimate));
            return Err(e);
        }
        run::journal_update(&self.journal, |j| j.mark_proving(jid));
        self.state.write().await.add_log(LogLevel::Info, format!("Proving witness job {}...", short(jid)));
        let (proof, slot) = self.prove(&store, l).await?;
        card.release();
        tracing::info!("WITNESS-LOCK {}: proved ({} cycles, {:.1} s)", short(jid), proof.cycles, proof.duration.as_secs_f64());
        self.fulfil(l, proof, slot).await
    }

    /// A bundle problem on a held lock (§15.2): unavailable keeps the lock; missing or corrupt pages
    /// `BUNDLE-MISSING` and keeps it too — recovery's room rule releases it before `D + G` minus the
    /// release margin. Salvage (rebuilding `W`) is not implemented: the lock is released then. A
    /// read that failed only because no image id could be derived just now is unavailability, not a
    /// verdict on the bundle (`derivation_unavailable`).
    fn bundle_trouble(&self, jid: B256, lock_deadline: u64, e: &StoreError, derivation_unavailable: bool) -> anyhow::Error {
        if e.is_unavailable() || e.is_full() {
            tracing::error!("PAGE: RETENTION-UNAVAILABLE witness lock {} is kept: {e}", short(jid));
        } else if derivation_unavailable {
            tracing::warn!(
                "witness lock {} is kept: its ELF's image id could not be derived just now (no measure worker \
                 came free); retried",
                short(jid)
            );
        } else {
            tracing::error!(
                "PAGE: BUNDLE-MISSING witness lock {} (D+G {lock_deadline}): {e}; kept until its window \
                 closes, then released (no salvage in this release)",
                short(jid)
            );
        }
        run::HandBack(format!("its bundle: {e}")).into()
    }

    fn segment_dir(&self, jid: B256) -> PathBuf {
        let root = self.retention.as_ref().map(|r| r.segment_dir.clone()).unwrap_or_else(std::env::temp_dir);
        root.join(format!("{:x}", jid).trim_start_matches("0x").chars().take(16).collect::<String>())
    }

    /// Execute, compare, prove (§15.3), only on a card at an executed po2 and never on a quarantined
    /// device. Returns the proof and the slot it ran on. Before every `Err` that is not a hand-back,
    /// `l.failure` says on which slot and how it failed (the post-lock tallies).
    async fn prove(self: &Arc<Self>, store: &Arc<Store>, l: &mut LockCtx) -> Result<(ProofOutput, Option<String>)> {
        use zkminer_prover_protocol::types::{GpuMemoryShortage, HostMemoryShortage, ProofDeadlineReached, WorkerProofError};
        let jid = l.job_id;
        let pool = zkminer_prover::engine::worker_pool().ok_or_else(|| anyhow!("no worker pool available"))?;
        let psid = l.descriptor.proofSystemId;
        let segment_dir = self.segment_dir(jid);
        let (mut attempt, mut host_waits, mut gpu_waits) = (0u32, 0u32, 0u32);
        let mut excluded: Vec<String> = Vec::new();
        let mut diverged = false;
        let mut warned_no_card = false;
        // After a divergence, the re-versioned bundle is proven on the slot that diverged: it is the
        // one whose execution the new version records.
        let mut only_slot: Option<String> = None;
        loop {
            attempt += 1;
            run::refresh_lock_deadline(&self.client, &self.journal, jid, &mut l.lock_deadline).await;
            let cutoff = self.proving_cutoff(l);
            let abort_at = match run::deadline_proof_budget(cutoff) {
                None => None,
                Some(b) if b < Duration::from_secs(run::MIN_ATTEMPT_BUDGET_SECS) => {
                    if !shutting_down() && cutoff == l.lock_deadline && self.client.job_clock_stopped(psid).await {
                        tokio::time::sleep(run::FULFIL_RETRY_WAIT).await;
                        attempt = attempt.saturating_sub(1);
                        continue;
                    }
                    l.failure = Some((None, PostLockFailureClass::ProveTimeEstimate));
                    bail!(
                        "abandoning witness lock {} before its {}: only {} s of proving budget left",
                        short(jid),
                        if cutoff < l.lock_deadline { "verifier swap's readyAt" } else { "deadline" },
                        b.as_secs()
                    );
                }
                Some(b) => Some(Instant::now() + b),
            };
            let disabled = run::operator_disabled_slots(&self.state).await;
            let all: Vec<(String, u8)> = run::current_risc0_cards(&self.state, false)
                .await
                .into_iter()
                .filter(|c| !disabled.contains(&c.slot))
                .filter(|c| only_slot.as_ref().is_none_or(|s| *s == c.slot))
                .map(|c| (c.slot, c.po2))
                .collect();
            let slots: Vec<String> = all.iter().map(|(s, _)| s.clone()).collect();
            let quarantined = self.quarantined(&slots).await;
            let cards: Vec<(String, u8)> = all.into_iter().filter(|(s, _)| !quarantined.contains(s)).collect();
            let executed: Vec<u32> =
                l.record.po2_results.iter().filter(|r| r.exit == GuestExit::Halted(0)).map(|r| r.po2).collect();
            let sizes = witness_prove_sizes(&cards, &executed);
            if sizes.is_empty() {
                if shutting_down() {
                    return Err(run::HandBack(format!("no enabled card proves at an executed po2 {executed:?}")).into());
                }
                if !warned_no_card {
                    warned_no_card = true;
                    tracing::warn!(
                        "witness lock {} waits for a card at an executed po2 {executed:?}{}{} (it is never proven \
                         at another size); released before its deadline otherwise",
                        short(jid),
                        only_slot.as_ref().map_or(String::new(), |s| format!(" on {s}, where it diverged")),
                        if quarantined.is_empty() { String::new() } else { format!(", not on quarantined {quarantined:?}") }
                    );
                }
                attempt = attempt.saturating_sub(1);
                tokio::time::sleep(run::no_card_wait(run::deadline_proof_budget(cutoff))).await;
                continue;
            }
            let (s, b) = (store.clone(), l.bundle);
            let input_path = match blocking(move || s.w_path(&b)).await? {
                Ok(p) => p,
                Err(e) => return Err(self.bundle_trouble(jid, l.lock_deadline, &e, false)),
            };
            let first = l
                .record
                .po2_results
                .iter()
                .find(|r| r.exit == GuestExit::Halted(0))
                .ok_or_else(|| anyhow!("the bundle has no provable po2"))?;
            let wp = WitnessProve {
                input_path: input_path.to_string_lossy().into_owned(),
                prefix: l.record.input_prefix().map(|p| p.to_vec()).unwrap_or_default(),
                input_sha256: l.record.input_sha256.0,
                w_len: l.record.w_len,
                expect_journal_sha256: first.journal_sha256.0,
                segment_dir: segment_dir.to_string_lossy().into_owned(),
            };
            lock(&self.segment_reserved).insert(jid, segment_need(l.record.po2_results.iter().map(|r| r.segment_bytes)));
            // The configured cap (`prover.proving_timeout_secs`), not the inline path's tightened
            // estimate: a watchdog kill costs a witness lock its proof. The claim gate admitted the
            // lock only if its realistic estimate (the CPU wrap included) fits this cap; the deadline
            // budget (`abort_at`) still bounds every attempt.
            let timeout = self.proving_timeout;
            let (elf, sizes2, excl, dis, program_id) = (l.elf.clone(), sizes.clone(), excluded.clone(), disabled.clone(), l.record.image_id.0);
            let progress = self.progress_callback(jid);
            let (res, used) = tokio::task::spawn_blocking(move || {
                let mut used = None;
                let size_on = |slot: &str| sizes2.get(slot).copied();
                let r = pool.prove_witness_min_vram(
                    zkminer_prover_protocol::BACKEND_RISC0,
                    &elf,
                    &wp,
                    None,
                    Some(timeout),
                    Some(progress),
                    None,
                    &excl,
                    &dis,
                    &mut used,
                    abort_at,
                    Some(&size_on as zkminer_prover::dispatcher::SlotPo2<'_>),
                    Some(program_id),
                    None,
                    0,
                );
                (r, used)
            })
            .await
            .map_err(|e| anyhow!("prove task panicked: {e}"))?;
            match res {
                Ok(WitnessProveOutcome::Proved(p)) => return Ok((p, used)),
                Ok(WitnessProveOutcome::JournalDiverged(dv)) => {
                    let po2 = used.as_ref().and_then(|s| sizes.get(s)).copied();
                    tracing::error!(
                        "PAGE: JOURNAL-DIVERGED witness lock {}: the proving execute at po2 {po2:?} committed a \
                         {}-byte journal the bundle does not record",
                        short(jid),
                        dv.journal_len
                    );
                    if diverged {
                        l.failure = Some((used, PostLockFailureClass::JournalDiverged));
                        bail!("a second journal divergence on witness lock {}: releasing", short(jid));
                    }
                    diverged = true;
                    if let Err(e) = self.reversion(store, l, &dv, po2).await {
                        if e.downcast_ref::<run::HandBack>().is_none() {
                            l.failure = Some((used, PostLockFailureClass::JournalDiverged));
                        }
                        return Err(e);
                    }
                    only_slot = used;
                    attempt = attempt.saturating_sub(1);
                    continue;
                }
                Err(e) => {
                    let msg = zkminer_chain::programs::sanitize_log(&format!("{e:#}"));
                    if e.downcast_ref::<ProofDeadlineReached>().is_some() {
                        if run::refresh_lock_deadline(&self.client, &self.journal, jid, &mut l.lock_deadline).await
                            && run::deadline_proof_budget(self.proving_cutoff(l))
                                .is_some_and(|b| b >= Duration::from_secs(run::MIN_ATTEMPT_BUDGET_SECS))
                        {
                            attempt = attempt.saturating_sub(1);
                            continue;
                        }
                        l.failure = Some((used, PostLockFailureClass::ProveTimeEstimate));
                        bail!("proving stopped for witness lock {} (deadline): {msg}", short(jid));
                    }
                    if let Some(shortage) = e.downcast_ref::<GpuMemoryShortage>() {
                        if let Some(k) = used.clone() {
                            if !shortage.ours_in_the_way && !excluded.contains(&k) {
                                excluded.push(k);
                            }
                        }
                        if gpu_waits < run::MAX_GPU_MEMORY_WAITS {
                            gpu_waits += 1;
                            attempt = attempt.saturating_sub(1);
                            tokio::time::sleep(Duration::from_secs(run::GPU_MEMORY_BACKOFF_SECS)).await;
                            continue;
                        }
                    } else if let Some(shortage) = e.downcast_ref::<HostMemoryShortage>() {
                        if !shortage.attempted && host_waits < run::MAX_HOST_MEMORY_WAITS {
                            host_waits += 1;
                            attempt = attempt.saturating_sub(1);
                            tokio::time::sleep(Duration::from_secs(run::HOST_MEMORY_BACKOFF_SECS)).await;
                            continue;
                        }
                    } else if e.downcast_ref::<WorkerProofError>().is_some_and(|w| w.is_input_mismatch()) {
                        // The retained W failed its hash at the worker: check the bundle as §15.2 says.
                        let (s, b, idf) = (store.clone(), l.bundle, self.image_id_fn());
                        if let Err(se) = blocking(move || s.verify(&b, &descriptor_hash_of_abi, &*idf)).await? {
                            return Err(self.bundle_trouble(jid, l.lock_deadline, &se, false));
                        }
                        l.failure = Some((used, PostLockFailureClass::ProverCrash));
                        bail!("the worker refused the bundle's input although it verifies: {msg}");
                    } else if let Some(k) = used.clone() {
                        if !excluded.contains(&k) {
                            excluded.push(k);
                        }
                    }
                    if attempt < run::MAX_PROVE_ATTEMPTS {
                        tracing::warn!("witness lock {}: proof attempt {attempt} failed ({msg}); retrying", short(jid));
                        continue;
                    }
                    l.failure = Some((used, failure_class(&e)));
                    bail!("proving witness lock {} failed after {attempt} attempt(s): {msg}", short(jid));
                }
            }
        }
    }

    /// The job's row on the dashboard follows its proof (Queued → Proving, and the card).
    fn progress_callback(&self, jid: B256) -> zkminer_prover::dispatcher::ProveProgress {
        let state = self.state.clone();
        let runtime = tokio::runtime::Handle::current();
        Box::new(move |_p: f64, slot_key: &str| {
            let bus = zkminer_prover::engine::worker_pool().and_then(|p| p.bus_id_for_slot(slot_key));
            let (state, slot_key) = (state.clone(), slot_key.to_string());
            runtime.spawn(async move {
                let mut st = state.write().await;
                if let Some(j) = st.active_jobs.iter_mut().find(|j| j.info.job_id == jid) {
                    if matches!(j.status, MinerJobStatus::Queued) {
                        j.status = MinerJobStatus::Proving { progress: 0.0, elapsed_secs: 0 };
                    }
                    j.gpu_bus_id = bus;
                    j.prover_backend = slot_key;
                }
            });
        })
    }

    /// A journal divergence (§15.3): the new journal is checked against the binding and the
    /// claim-gate limits; if it passes, a new bundle version is written and pinned (the old `W`, by
    /// hard link) and the proof is dispatched again, once, on the slot that diverged. Otherwise `Err`:
    /// the lock is released. A store that cannot write the new version now is §15.2's: the lock is
    /// kept (a hand-back), never released over it.
    ///
    /// After the lock, the DA check is the operator cap alone: the fulfil's nonce rule waits out a
    /// high backlog (§5.5), so a transient DA reading never releases a held lock.
    async fn reversion(&self, store: &Arc<Store>, l: &mut LockCtx, dv: &JournalDivergence, po2: Option<u8>) -> Result<()> {
        let jid = l.job_id;
        let po2 = po2.ok_or_else(|| anyhow!("the diverged proof's po2 is unknown"))?;
        let halted = dv.exit_kind == GUEST_EXIT_HALTED && dv.exit_code == 0;
        if !divergence_reusable(halted, dv.journal.len(), dv.journal_len) {
            bail!("the diverged execution is not provable (exit {} code {}, {} bytes)", dv.exit_kind, dv.exit_code, dv.journal_len);
        }
        if <[u8; 32]>::from(Sha256::digest(&dv.journal)) != dv.journal_sha256 {
            bail!("the diverged journal does not hash to what the worker reported");
        }
        check_journal_binding(&l.descriptor, &dv.journal, jid, self.client.address)
            .map_err(|m| anyhow!("the diverged journal does not satisfy the binding ({m})"))?;
        let fulfil = HashedFulfil::from_descriptor(&l.descriptor);
        let est = match estimate_fulfil_da_bytes(&self.client, jid, &fulfil, &dv.journal, &SealSpec::risc0_groth16()).await {
            Ok(est) => est,
            // An unreadable estimate is the endpoint's, not the journal's: keep the lock.
            Err(e) => return Err(run::HandBack(format!("the diverged journal's DA size is unreadable ({e:#})")).into()),
        };
        if est.estimated_bytes > self.da_policy.cap_bytes() {
            bail!(
                "the diverged journal's fulfil is {} estimated DA bytes, over the {}-byte cap",
                est.estimated_bytes,
                self.da_policy.cap_bytes()
            );
        }
        if !session_cap_admits(dv.cycles, parse_session_cap(std::env::var("ZKMINER_RISC0_MAX_SESSION_CYCLES").ok().as_deref())) {
            bail!("the diverged execution ({} cycles) is over ZKMINER_RISC0_MAX_SESSION_CYCLES", dv.cycles);
        }
        let plan = self.prove_plan(&[po2]).await;
        let execute_secs = l.record.execute_ms_per_po2.unwrap_or(0).div_ceil(1000);
        let need = estimate_prove_secs(dv.cycles, &plan, execute_secs);
        if !watchdog_admits(need, self.proving_timeout.as_secs()) {
            bail!(
                "the diverged execution ({} cycles, ~{need} s) does not fit the {} s proving timeout",
                dv.cycles,
                self.proving_timeout.as_secs()
            );
        }
        if run::deadline_proof_budget(self.proving_cutoff(l)).is_some_and(|b| b.as_secs() < need) {
            bail!("the diverged execution ({} cycles, ~{need} s) no longer fits the lock's window", dv.cycles);
        }
        let old = l.record.at(u32::from(po2)).cloned().ok_or_else(|| anyhow!("po2 {po2} is not in the bundle"))?;
        let deadline = l.lock_deadline;
        let trouble = |e: &StoreError| self.bundle_trouble(jid, deadline, e, false);
        let (s, b) = (store.clone(), l.bundle);
        let writer = match blocking(move || s.begin_version_from(&b)).await? {
            Ok(w) => w,
            Err(e) => return Err(trouble(&e)),
        };
        let mut record = l.record.clone();
        record.version = writer.version();
        record.po2_results = vec![Po2Result {
            po2: u32::from(po2),
            journal_hex: hex::encode(&dv.journal),
            journal_sha256: B256::from(dv.journal_sha256),
            cycles: dv.cycles,
            exit: GuestExit::Halted(0),
            segment_bytes: old.segment_bytes,
        }];
        let rec2 = record.clone();
        let new_ref = match blocking(move || writer.finish(&rec2, &descriptor_hash_of_abi)).await? {
            Ok(r) => r,
            Err(e) => return Err(trouble(&e)),
        };
        // The new version's pin keeps the lock evidence of the one it replaces.
        let (s, head) = (store.clone(), self.client.head_block_cached().await.unwrap_or(0));
        let old_pin = self.pin_of(store, &l.bundle);
        let (reopen_count, lock_block) = (old_pin.as_ref().and_then(|p| p.reopen_count), l.lock_block);
        let pinned = blocking(move || {
            let mut rec = s.pin_record(&new_ref, head)?;
            rec.reopen_count = reopen_count;
            rec.lock_block = lock_block;
            rec.pinned_at_unix = zkminer_chain::client::chain_now_floor();
            s.pin(&rec)
        })
        .await?;
        if let Err(e) = pinned {
            return Err(trouble(&e));
        }
        let wref = bundle_ref(&new_ref);
        run::journal_update(&self.journal, |j| j.record_witness_bundle(jid, wref));
        tracing::warn!(
            "witness lock {}: re-versioned to bundle v{} at po2 {po2} after the divergence; proving it once more",
            short(jid),
            new_ref.version
        );
        l.bundle = new_ref;
        l.record = record;
        l.cycles = dv.cycles;
        Ok(())
    }

    /// The readable pin of `r`'s key, if any.
    fn pin_of(&self, store: &Arc<Store>, r: &BundleRef) -> Option<PinRecord> {
        store
            .pins()
            .into_iter()
            .find(|p| p.job_id == r.job_id && p.descriptor_hash == r.descriptor_hash && p.prover == r.prover)
    }

    /// `fulfillJobHashed` under the DA rules (§5.5), retried by class until the job settles or its
    /// window closes, as the inline fulfil is.
    async fn fulfil(self: &Arc<Self>, l: &mut LockCtx, proof: ProofOutput, proved_on: Option<String>) -> Result<()> {
        use zkminer_chain::revert::{FulfilClass, FulfilFailure};
        let jid = l.job_id;
        // A proof the router would refuse is the proving device's failure; a fulfil that cannot land
        // in time is the chain's (gas, RPC, blockspace).
        let proof_defect = Some((proved_on.clone(), PostLockFailureClass::Gpu));
        let chain = Some((None, PostLockFailureClass::GasOrRpc));
        if proof.journal.len() > MAX_JOURNAL_BYTES {
            l.failure = proof_defect;
            bail!("the proof's journal is {} bytes, over the cap", proof.journal.len());
        }
        if let Err(why) = check_journal_binding(&l.descriptor, &proof.journal, jid, self.client.address) {
            l.failure = proof_defect;
            bail!("the proof's journal does not satisfy the binding ({why}); releasing instead of publishing it");
        }
        let selector = run::risc0_seal_selector();
        let mut seal = Vec::with_capacity(selector.len() + proof.seal.len());
        seal.extend_from_slice(&selector);
        seal.extend_from_slice(&proof.seal);
        run::journal_update(&self.journal, |j| j.mark_fulfilling(jid));
        {
            let mut s = self.state.write().await;
            if let Some(j) = s.active_jobs.iter_mut().find(|j| j.info.job_id == jid) {
                j.status = MinerJobStatus::Submitting;
            }
            s.add_log(LogLevel::Info, format!("Submitting witness fulfilment for {}...", short(jid)));
        }
        let clear_submitting = |why: &'static str| {
            let state = self.state.clone();
            async move {
                let mut s = state.write().await;
                if let Some(j) = s.active_jobs.iter_mut().find(|j| j.info.job_id == jid) {
                    j.status = MinerJobStatus::Skipped { reason: why.into() };
                }
            }
        };
        let da = FulfilDa { rule: NonceRuleConfig::default(), backlog: self.backlog.clone() };
        let hashed = HashedFulfil::from_descriptor(&l.descriptor);
        let psid = l.descriptor.proofSystemId;
        let public_values = Bytes::from(proof.journal.clone());
        let seal = Bytes::from(seal);
        loop {
            run::refresh_lock_deadline(&self.client, &self.journal, jid, &mut l.lock_deadline).await;
            let min = Duration::from_secs(run::MIN_ATTEMPT_BUDGET_SECS);
            let budget = match run::deadline_proof_budget(l.lock_deadline) {
                None => None,
                Some(b) if b < min && run::clock_stopped_or_unknown(&self.client, psid, b).await => {
                    if self.client.job_clock_stopped(psid).await {
                        Some(min * 2)
                    } else {
                        Some(b)
                    }
                }
                Some(b) if b < min => {
                    clear_submitting("fulfil window closing — releasing").await;
                    l.failure = chain.clone();
                    bail!("the fulfil window of witness lock {} is closing ({} s left); releasing", short(jid), b.as_secs());
                }
                Some(b) => Some(b),
            };
            let sent = self
                .client
                .fulfill_job_hashed(jid, hashed.clone(), public_values.clone(), seal.clone(), budget, Some(l.lock_block), Some(&da))
                .await;
            let e = match sent {
                Ok(()) => break,
                Err(e) => e,
            };
            let published_unconfirmed =
                e.downcast_ref::<FulfilFailure>().is_some_and(|f| f.published && f.class == FulfilClass::Unknown);
            let (class, reason) = match e.downcast_ref::<FulfilFailure>() {
                Some(f) => (f.class, f.reason.clone()),
                None => (FulfilClass::Unknown, zkminer_chain::programs::sanitize_log(&format!("{e:#}"))),
            };
            match class {
                FulfilClass::ProofDefect => {
                    clear_submitting("proof rejected — releasing").await;
                    l.failure = proof_defect.clone();
                    bail!("fulfil rejected ({reason}); releasing");
                }
                FulfilClass::VerifierFailed => match self.client.verifier_failure_has_governance_cause(psid).await {
                    Ok(false) => {
                        clear_submitting("verifier rejected the proof — releasing").await;
                        l.failure = proof_defect.clone();
                        bail!("fulfil rejected by the verifier (VerifierCallFailed, no governance cause); releasing");
                    }
                    Ok(true) => tracing::warn!("KEEP: witness lock {} VerifierCallFailed while paused or disabled", short(jid)),
                    Err(err) => tracing::warn!("KEEP: witness lock {} VerifierCallFailed, governance unreadable ({err:#})", short(jid)),
                },
                FulfilClass::Keep => tracing::warn!("KEEP: witness lock {} fulfil held ({reason})", short(jid)),
                FulfilClass::Stale => {
                    tracing::warn!("LOCK-LOST: witness lock {} — {reason}", short(jid));
                    run::journal_update(&self.journal, |j| j.remove(jid));
                    if let Some(n) = self.client.take_abandoned_nonce(jid) {
                        self.client.abort_nonce(n);
                    }
                    let mut s = self.state.write().await;
                    s.active_jobs.retain(|j| j.info.job_id != jid);
                    drop(s);
                    self.unpin_or_clean(jid, l.bundle, None).await;
                    return Ok(());
                }
                FulfilClass::Late => {
                    tracing::error!("PAGE: LOCK-LATE: witness lock {} — {reason}; the lock will be slashed", short(jid));
                    clear_submitting("past the fulfil window").await;
                    l.failure = chain.clone();
                    bail!("the fulfil window of witness lock {} passed: {reason}", short(jid));
                }
                FulfilClass::Gas | FulfilClass::Unknown => {
                    tracing::warn!("witness lock {}: fulfil not settled ({reason}); retrying", short(jid))
                }
            }
            if shutting_down() && matches!(class, FulfilClass::Keep | FulfilClass::VerifierFailed) {
                clear_submitting("shutdown during a held fulfil").await;
                return Err(run::HandBack(format!("shutdown while the fulfil is held: {reason}")).into());
            }
            match run::deadline_proof_budget(l.lock_deadline) {
                Some(b) if b <= run::FULFIL_RETRY_WAIT + min => {
                    if run::refresh_lock_deadline(&self.client, &self.journal, jid, &mut l.lock_deadline).await {
                        continue;
                    }
                    if run::clock_stopped_or_unknown(&self.client, psid, b).await {
                        tokio::time::sleep(run::FULFIL_RETRY_WAIT).await;
                        continue;
                    }
                    clear_submitting("fulfil window closing — releasing").await;
                    l.failure = chain.clone();
                    bail!("the fulfil window of witness lock {} is closing; releasing", short(jid));
                }
                _ if published_unconfirmed => tokio::time::sleep(Duration::from_secs(1)).await,
                _ => tokio::time::sleep(run::FULFIL_RETRY_WAIT).await,
            }
        }
        // Settled.
        run::journal_update(&self.journal, |j| j.remove(jid));
        {
            let mut s = self.state.write().await;
            let completed = s.active_jobs.iter().find(|j| j.info.job_id == jid).cloned();
            s.active_jobs.retain(|j| j.info.job_id != jid);
            if let Some(mut cj) = completed {
                cj.status = MinerJobStatus::Fulfilled { payout: 0 };
                s.completed_jobs.push(cj);
                if s.completed_jobs.len() > 500 {
                    let excess = s.completed_jobs.len() - 500;
                    s.completed_jobs.drain(0..excess);
                }
            }
            s.add_log(LogLevel::Success, format!("Witness job {} fulfilled on-chain", short(jid)));
        }
        tracing::info!("WITNESS-LOCK {}: fulfilled with fulfillJobHashed", short(jid));
        self.unpin_or_clean(jid, l.bundle, Some(l.lock_block)).await;
        Ok(())
    }

    /// After a lock ended: on an authoritative terminal read, unpin and delete the job's bundles
    /// (§15.2); otherwise only unpin once the job reads Open or another prover's (our lock is gone).
    /// A read that fails leaves everything to the next store pass.
    async fn unpin_or_clean(&self, jid: B256, bundle: BundleRef, min_block: Option<u64>) {
        let Some(store) = self.store() else { return };
        for i in 0..TERMINAL_READS {
            let Ok((rec, at)) = with_lane(Lane::HeldLock, self.client.read_job_record(jid, min_block)).await else {
                return;
            };
            if let Some(state) = terminal_state(&rec) {
                self.delete_terminal(&store, jid, state, at).await;
                return;
            }
            if rec.prover != self.client.address || rec.status == JOB_STATUS_OPEN {
                let s = store.clone();
                if let Ok(Ok(true)) = blocking(move || s.unpin(bundle.job_id, bundle.descriptor_hash, bundle.prover)).await {
                    tracing::info!("witness job {}: unpinned (our lock ended; the bundle stays a cache)", short(jid));
                }
                return;
            }
            // Still Locked by us on this replica: a fulfil just mined may not show yet.
            if i + 1 < TERMINAL_READS {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    /// Unpins every pin of a terminal job and deletes its bundles.
    async fn delete_terminal(&self, store: &Arc<Store>, jid: B256, state: TerminalState, read_at_block: u64) {
        let s = store.clone();
        let result = blocking(move || {
            for p in s.pins().into_iter().filter(|p| p.job_id == jid) {
                s.unpin(p.job_id, p.descriptor_hash, p.prover)?;
            }
            s.delete_job(jid, &TerminalProof { job_id: jid, state, read_at_block })
        })
        .await;
        match result {
            Ok(Ok(r)) => tracing::info!(
                "WITNESS-LOCK {}: bundle deleted ({state:?} at block {read_at_block}; {} version(s), {} bytes)",
                short(jid),
                r.versions_removed,
                r.freed.bytes
            ),
            Ok(Err(e)) => tracing::warn!("witness job {}: deleting its bundle failed ({e}); the store pass retries", short(jid)),
            Err(e) => tracing::warn!("witness job {}: deleting its bundle failed ({e:#})", short(jid)),
        }
    }

    // ── recovery ──────────────────────────────────────────────────────────────

    /// Re-drives a witness lock of ours from its bundle (single flight). `false` when a task owns it.
    /// Until its bundle is found and pinned, eviction waits for it (§15.2).
    pub(crate) fn drive_recovered(self: &Arc<Self>, jid: B256) -> bool {
        {
            let mut t = lock(&self.tasks);
            if t.contains_key(&jid) {
                return false;
            }
            t.insert(jid, Task { token: AbortToken::new(), phase: Phase::Locked });
        }
        lock(&self.unpinned_recoveries).insert(jid);
        let rt = self.clone();
        tokio::spawn(async move {
            let _entry = TaskEntry { rt: rt.clone(), job_id: jid };
            if let Some(l) = with_lane(Lane::HeldLock, rt.recover_lock(jid)).await {
                rt.run_locked(l).await;
            }
        });
        true
    }

    /// A recovered lock needs no more protection from eviction: pinned, gone, or its bundle missing.
    fn recovery_resolved(&self, jid: B256) {
        lock(&self.unpinned_recoveries).remove(&jid);
    }

    /// A held witness lock's context, from the store (§15.2): the pin, else the journal's bundle
    /// reference, else the store's latest version for (job, descriptor, prover) — the store is the
    /// authoritative index, and a lock whose pin is unreadable or gone is proven from what the store
    /// holds; its descriptor, ELF, po2 set and journals come from the bundle, never from the chain or
    /// the lock journal. The version proven is pinned (again) with the lock's evidence.
    async fn recover_lock(self: &Arc<Self>, jid: B256) -> Option<LockCtx> {
        let us = self.client.address;
        let (rec, at) = self.client.read_job_record(jid, None).await.ok()?;
        if rec.prover != us || rec.status != JOB_STATUS_LOCKED {
            self.recovery_resolved(jid);
            return None;
        }
        let Some(store) = self.store() else {
            tracing::error!(
                "PAGE: RETENTION-UNAVAILABLE witness lock {} is kept: the retention store is unavailable; \
                 it is released only as its window closes",
                short(jid)
            );
            return None;
        };
        let pin = store
            .pins()
            .into_iter()
            .filter(|p| p.job_id == jid && p.prover == us && p.descriptor_hash == rec.descriptor_hash)
            .max_by_key(|p| p.bundle_version);
        let pinned = pin.as_ref().map(|p| BundleKey::of_pin(p).at(p.bundle_version));
        let from_journal = lock(&self.journal)
            .witness_bundle(jid)
            .filter(|w| w.prover == us && w.descriptor_hash == rec.descriptor_hash)
            .map(|w| BundleKey::new(w.job_id, w.descriptor_hash, w.prover).at(w.version));
        let (s, idf) = (store.clone(), self.image_id_fn());
        let unavailable_before = self.image_id_unavailable.load(Ordering::SeqCst);
        let dh = rec.descriptor_hash;
        let verified = blocking(move || {
            let mut tried = Vec::new();
            let mut last: Option<StoreError> = None;
            for r in [pinned, from_journal].into_iter().flatten() {
                if tried.contains(&r) {
                    continue;
                }
                tried.push(r);
                match s.verify_with_elf(&r, &descriptor_hash_of_abi, &*idf) {
                    Ok((record, elf)) => return Ok((r, record, elf)),
                    // An unavailable store is not a reason to look elsewhere.
                    Err(e) if e.is_unavailable() => return Err(e),
                    Err(e) => last = Some(e),
                }
            }
            match s.latest(jid, dh, us) {
                Ok(r) if !tried.contains(&r) => s.verify_with_elf(&r, &descriptor_hash_of_abi, &*idf).map(|(record, elf)| (r, record, elf)),
                // The latest is one already tried, and its failure (set when it was) is the answer.
                Ok(r) => Err(last.unwrap_or_else(|| StoreError::Missing { path: s.root().join(format!("v{}", r.version)) })),
                Err(e) => Err(last.unwrap_or(e)),
            }
        })
        .await
        .ok()?;
        let (bref, record, elf) = match verified {
            Ok(v) => v,
            Err(e) => {
                let derivation = e.is_corrupt() && self.image_id_unavailable.load(Ordering::SeqCst) != unavailable_before;
                let _ = self.bundle_trouble(jid, rec.lock_deadline.saturating_add(PROVER_GRACE_SECS), &e, derivation);
                if !(e.is_unavailable() || e.is_full() || derivation) {
                    if e.is_missing() {
                        tracing::error!(
                            "PAGE: BUNDLE-MISSING witness lock {} (D+G {}) has no bundle in the store at {}: kept until \
                             its window closes, then released",
                            short(jid),
                            rec.lock_deadline.saturating_add(PROVER_GRACE_SECS),
                            store.root().display()
                        );
                    }
                    // Nothing in the store to protect for it.
                    self.recovery_resolved(jid);
                }
                return None;
            }
        };
        let descriptor = hex::decode(&record.descriptor_hex).ok().and_then(|b| JobDescriptor::abi_decode(&b).ok())?;
        if compute_descriptor_hash(&descriptor) != rec.descriptor_hash {
            tracing::error!("PAGE: BUNDLE-MISSING witness lock {}: its bundle's descriptor is not the job's", short(jid));
            self.recovery_resolved(jid);
            return None;
        }
        // Pin what is proven, with the lock's evidence (a read here shows it ours and Locked at `at`).
        let needs_pin = pin.as_ref().is_none_or(|p| {
            p.bundle_version != bref.version || p.lock_block == 0 || p.reopen_count != Some(rec.reopen_count)
        });
        if needs_pin {
            let (s, b) = (store.clone(), bref);
            let reopen = rec.reopen_count;
            let pinned_at_unix = pin.as_ref().map_or_else(zkminer_chain::client::chain_now_floor, |p| p.pinned_at_unix);
            let res = blocking(move || {
                let mut r = s.pin_record(&b, at)?;
                r.reopen_count = Some(reopen);
                r.lock_block = at;
                r.pinned_at_unix = pinned_at_unix;
                s.pin(&r)
            })
            .await;
            match res {
                Ok(Ok(())) => {
                    if pin.is_none() {
                        tracing::warn!("witness lock {}: had no readable pin; pinned bundle v{} from the store", short(jid), bref.version);
                    }
                    self.recovery_resolved(jid);
                }
                Ok(Err(e)) => tracing::warn!("witness lock {}: pinning its bundle failed ({e}); eviction waits", short(jid)),
                Err(e) => tracing::warn!("witness lock {}: pinning its bundle failed ({e:#}); eviction waits", short(jid)),
            }
        } else {
            self.recovery_resolved(jid);
        }
        let view = self.client.get_job_status_view_at(jid, at).await.ok()?;
        let lock_deadline = run::effective_cutoff(&view);
        let wref = bundle_ref(&bref);
        run::journal_update(&self.journal, |j| {
            if !j.entries.contains_key(&jid) {
                j.mark_claimed(jid, None, lock_deadline);
            }
            j.record_witness_bundle(jid, wref);
            j.note_lock_seen(jid, Some(at), view.reopenCount);
        });
        let cycles = record.po2_results.iter().map(|r| r.cycles).max().unwrap_or(0);
        {
            let mut s = self.state.write().await;
            if !s.active_jobs.iter().any(|j| j.info.job_id == jid) {
                s.active_jobs.push(TrackedJob {
                    info: zkminer_chain::jobs::JobInfo {
                        job_id: jid,
                        program_id: descriptor.programId,
                        caller: rec.caller,
                        status: rec.status,
                        reopen_count: rec.reopen_count,
                        descriptor_hash: rec.descriptor_hash,
                        lock_deadline,
                        prover: rec.prover,
                        locked_collateral: rec.locked_collateral,
                        fulfillment_timeout: rec.fulfillment_timeout,
                        ..Default::default()
                    },
                    status: MinerJobStatus::Queued,
                    current_price: rec.settled_price,
                    gpu_bus_id: None,
                    prover_backend: String::new(),
                    estimated_cycles: cycles,
                });
            }
        }
        tracing::info!("WITNESS-LOCK {}: recovered from bundle v{}; re-driving", short(jid), bref.version);
        Some(LockCtx {
            job_id: jid,
            caller: rec.caller,
            descriptor,
            bundle: bref,
            record,
            elf,
            lock_block: at,
            lock_deadline,
            locked_collateral: 0,
            cycles,
            failure: None,
        })
    }

    async fn store_pass_loop(self: Arc<Self>) {
        loop {
            if !self.store_pass_running.swap(true, Ordering::SeqCst) {
                self.store_pass().await;
                self.store_pass_running.store(false, Ordering::SeqCst);
            }
            tokio::time::sleep(STORE_PASS_EVERY).await;
            if shutting_down() {
                return;
            }
        }
    }

    /// The store's reconciliation with the chain (§15.2): drive held witness locks, unpin locks that
    /// provably ended ([`pin_lock_gone`]), delete bundles of terminal jobs, and once a complete pass
    /// has run and the brain's recovery has handed over (and this runtime pinned) every witness lock,
    /// enable eviction and evict; page a low or unavailable store. Reads for pins (possible held
    /// locks) go in the held-lock lane; reads for unpinned bundles in the pre-claim lane.
    async fn store_pass(self: &Arc<Self>) {
        if self.store().is_none() {
            self.open_store().await;
        }
        let Some(store) = self.store() else { return };
        let us = self.client.address;
        if store.is_poisoned() {
            tracing::error!(
                "PAGE: RETENTION-UNAVAILABLE the retention store is poisoned (a write failed after it became \
                 visible): held witness locks are still proven from their pinned bundles (every byte re-verified); \
                 nothing is pinned, unpinned, deleted or evicted, and no new witness lock is taken until the \
                 miner restarts — check the disk"
            );
            let owned = self.owned_jobs();
            for pin in store.pins().into_iter().filter(|p| p.prover == us && !owned.contains(&p.job_id)) {
                if let Ok((rec, _)) = with_lane(Lane::HeldLock, self.client.read_job_record(pin.job_id, None)).await {
                    if rec.prover == us && rec.status == JOB_STATUS_LOCKED && self.drive_recovered(pin.job_id) {
                        tracing::info!("witness lock {}: held, re-driven from its pinned bundle", short(pin.job_id));
                    }
                }
            }
            return;
        }
        let s = store.clone();
        let scan = match blocking(move || s.scan()).await {
            Ok(Ok(scan)) => scan,
            Ok(Err(e)) => {
                tracing::error!("PAGE: RETENTION-UNAVAILABLE the retention store scan failed ({e}): every witness lock is kept");
                return;
            }
            Err(e) => {
                tracing::error!("PAGE: RETENTION-UNAVAILABLE the retention store scan failed ({e:#})");
                return;
            }
        };
        let mut complete = scan.unreadable_pins.is_empty();
        for k in &scan.unreadable_pins {
            tracing::error!(
                "PAGE: BUNDLE-MISSING the pin of witness job {} cannot be read; its bundles are kept (a held lock \
                 is proven from the store's latest version)",
                short(k.job_id)
            );
        }
        let mut reads = 0usize;
        let owned = self.owned_jobs();
        let mut pinned_jobs: HashSet<B256> = HashSet::new();
        for pin in &scan.pins {
            pinned_jobs.insert(pin.job_id);
            if owned.contains(&pin.job_id) {
                continue;
            }
            if reads >= STORE_PASS_MAX_READS {
                complete = false;
                break;
            }
            reads += 1;
            // At or after the pin's block (and the lock's): an earlier replica says nothing about it.
            let min_block = pin.pinned_at_block.max(pin.lock_block);
            let Ok((rec, at)) =
                with_lane(Lane::HeldLock, self.client.read_job_record(pin.job_id, Some(min_block))).await
            else {
                complete = false;
                continue;
            };
            if rec.prover == us && rec.status == JOB_STATUS_LOCKED && pin.prover == us {
                if self.drive_recovered(pin.job_id) {
                    tracing::info!("witness lock {}: held, found by the store pass; re-driving", short(pin.job_id));
                }
            } else if let Some(state) = terminal_state(&rec) {
                self.delete_terminal(&store, pin.job_id, state, at).await;
            } else {
                let facts = PinFacts {
                    reopen_count: pin.reopen_count,
                    lock_block: pin.lock_block,
                    pinned_at_block: pin.pinned_at_block,
                    pinned_at_unix: pin.pinned_at_unix,
                };
                let read = PinRead { status: rec.status, prover: rec.prover, reopen_count: rec.reopen_count, at_block: at };
                let now = zkminer_chain::client::chain_now_floor();
                if pin_lock_gone(&facts, &read, us, now, run::CLAIM_INTENT_MAX_AGE_SECS) {
                    let (s, p) = (store.clone(), pin.clone());
                    if let Ok(Ok(true)) = blocking(move || s.unpin(p.job_id, p.descriptor_hash, p.prover)).await {
                        tracing::info!(
                            "witness job {}: unpinned (status {}, prover {}, reopen {}): the lock it was taken for is \
                             gone; the bundle stays a cache",
                            short(pin.job_id),
                            rec.status,
                            rec.prover,
                            rec.reopen_count
                        );
                    }
                } else {
                    tracing::debug!(
                        "witness job {}: pin kept (status {}, prover {}): no proof yet that its lock is gone",
                        short(pin.job_id),
                        rec.status,
                        rec.prover
                    );
                }
            }
        }
        // Bundles of jobs with no pin: deleted once their job is terminal (bounded per pass).
        let mut unpinned: Vec<B256> = scan
            .bundles
            .iter()
            .map(|m| m.bundle.job_id)
            .filter(|j| !pinned_jobs.contains(j) && !owned.contains(j))
            .collect();
        unpinned.sort();
        unpinned.dedup();
        for jid in unpinned {
            if reads >= STORE_PASS_MAX_READS {
                break;
            }
            reads += 1;
            if let Ok((rec, at)) = with_lane(Lane::PreClaim, self.client.read_job_record(jid, None)).await {
                if let Some(state) = terminal_state(&rec) {
                    self.delete_terminal(&store, jid, state, at).await;
                }
            }
        }
        // A handed-over lock that recovery could not pin, and that provably ended since (a terminal
        // read, or the journal's evidence: a risen reopen count, another prover at or after the lock
        // block), has nothing left to protect. An unpinned read alone may lag: it keeps waiting.
        let waiting: Vec<B256> = lock(&self.unpinned_recoveries).iter().copied().filter(|j| !owned.contains(j)).collect();
        for jid in waiting {
            if reads >= STORE_PASS_MAX_READS {
                break;
            }
            reads += 1;
            if let Ok((rec, _)) = with_lane(Lane::HeldLock, self.client.read_job_record(jid, None)).await {
                let ended = terminal_state(&rec).is_some()
                    || (!(rec.prover == us && rec.status == JOB_STATUS_LOCKED)
                        && run::lock_ownership(&self.client, &self.journal, jid, rec.reopen_count).await
                            == run::LockOwnership::Gone);
                if ended {
                    self.recovery_resolved(jid);
                }
            }
        }
        // Eviction (§15.2: "nothing is evicted until this process has completed one full recovery
        // scan"): this pass read every pin, the brain's recovery has handed over every witness lock
        // it found on chain or in the journal, and each of those is pinned.
        let handed = self.brain_recovered.load(Ordering::SeqCst);
        let waiting = lock(&self.unpinned_recoveries).len();
        if complete && handed && waiting == 0 && !self.scan_complete.swap(true, Ordering::SeqCst) {
            store.mark_recovery_scan_complete();
            tracing::info!("witness: the retention store's recovery scan is complete; eviction is enabled");
        } else if !store.recovery_scan_complete() {
            tracing::debug!(
                "witness: eviction waits (pass complete {complete}, brain recovery done {handed}, {waiting} recovered \
                 lock(s) not pinned yet)"
            );
        }
        if store.recovery_scan_complete() {
            let (s, target) = (store.clone(), self.witness.max_witness_bytes.saturating_add(BUNDLE_JSON_ALLOWANCE));
            match blocking(move || s.evict_to(target, &*eviction_by_age())).await {
                Ok(Ok(r)) if !r.evicted.is_empty() => {
                    tracing::info!("witness: evicted {} unpinned bundle version(s), {} bytes", r.evicted.len(), r.freed.bytes)
                }
                Ok(Err(e)) => tracing::warn!("witness: eviction failed: {e}"),
                _ => {}
            }
        }
        // An expired verdict still carries its attempt count, which the next skip of its job builds
        // on (a one-retry verdict is final on the second failure): drop verdicts only once they have
        // been expired for as long as a final verdict lasts.
        let s = store.clone();
        let _ = blocking(move || s.expire_verdicts(super::policy::verdict_drop_cutoff(now_unix()))).await;
        let quota = store.options().quota_bytes;
        let used = store.usage().bytes;
        if quota > 0 && used as f64 >= RETENTION_LOW_SHARE * quota as f64 {
            tracing::error!(
                "PAGE: RETENTION-LOW the retention store holds {used} of its {quota}-byte quota: a full store \
                 stops witness locks"
            );
        }
    }
}

// ── the pipeline's hooks ──────────────────────────────────────────────────────

/// What run.rs supplies to one simulation: the chain gates, the guest ELF, the artifact budget, the
/// abort token.
struct Hooks {
    rt: Arc<WitnessRuntime>,
    gate: ChainGateInput,
    token: AbortToken,
    budget: ArtifactBudget,
    /// The claimability quote the chain gates read, for the claim gate.
    quote: Mutex<Option<ClaimQuote>>,
    /// The job's `programId`, which the ELF's image id must equal.
    program_id: B256,
    /// The guest ELF once fetched, for the lock (its prove dispatch).
    elf: Mutex<Option<Vec<u8>>>,
}

impl PipelineHooks for Hooks {
    fn claimable(&self) -> HookFuture<'_, Result<(), SkipReason>> {
        Box::pin(async move {
            let q = self.rt.chain_gates(&self.gate).await?;
            *lock(&self.quote) = Some(q);
            Ok(())
        })
    }

    fn admit_artifact_charge(&self, charge: ArtifactCharge) -> HookFuture<'_, bool> {
        let ok = self.budget.admits(charge.length, charge.chunks);
        if !ok {
            tracing::info!(
                "witness job {}: the builder artifact ({} bytes in {} chunks) is over the per-job budget ({} bytes, {} chunks)",
                short(self.gate.job_id),
                charge.length,
                charge.chunks,
                self.budget.max_bytes,
                self.budget.max_chunks
            );
        }
        Box::pin(async move { ok })
    }

    fn abort_token(&self) -> &AbortToken {
        &self.token
    }

    /// Today's ELF path (after the static gates, §5.2 step 3), then the image id derived on a
    /// measure worker (waiting for one) and checked against `programId`: the bundle's retention of
    /// the ELF later hits the derived id, so no builder or execute runs for an ELF that cannot be
    /// retained.
    fn guest_elf(&self) -> HookFuture<'_, Result<Vec<u8>, (SkipReason, String)>> {
        Box::pin(async move {
            let rt = &self.rt;
            let fetched = with_lane(
                Lane::PreClaim,
                tokio::time::timeout(
                    FETCH_BUDGET,
                    run::fetch_or_download_elf(&rt.client, &rt.state, self.program_id, None, false),
                ),
            )
            .await;
            let elf = match fetched {
                Ok(Ok(elf)) => elf,
                Ok(Err(e)) => return Err((SkipReason::ElfUnavailable, format!("{e:#}"))),
                Err(_) => return Err((SkipReason::ElfUnavailable, "ELF fetch timed out".into())),
            };
            let (idf, bytes) = (rt.image_id_fn(), elf.clone());
            let before = rt.image_id_unavailable.load(Ordering::SeqCst);
            let id = blocking(move || idf(&bytes)).await.map_err(|e| (SkipReason::HostInternal, format!("{e:#}")))?;
            match id {
                Some(id) if id == self.program_id => {
                    *lock(&self.elf) = Some(elf.clone());
                    Ok(elf)
                }
                Some(id) => Err((SkipReason::ElfImageIdMismatch, format!("the ELF's image id is {id}"))),
                None if rt.image_id_unavailable.load(Ordering::SeqCst) != before => Err((
                    SkipReason::HostInternal,
                    "the ELF's image id could not be derived now (no risc0 measure worker came free)".into(),
                )),
                None => Err((SkipReason::ElfImageIdMismatch, "the ELF is not one risc0 derives an image id for".into())),
            }
        })
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn host_abort(r: GovAbort) -> AbortReason {
    match r {
        GovAbort::Cancelled { .. } => AbortReason::JobCancelled,
        GovAbort::ClaimedByOther { .. } => AbortReason::JobClaimed,
        GovAbort::BidSubmitted { .. } => AbortReason::BidSubmitted,
    }
}

/// How a held lock's proof failed, from its typed errors (never from text, §16): the class its
/// device's tally counts.
fn failure_class(e: &anyhow::Error) -> PostLockFailureClass {
    use zkminer_prover_protocol::types::{ErrorKind, GpuMemoryShortage, HostMemoryShortage, ProofDeadlineReached, WorkerProofError};
    if e.downcast_ref::<ProofDeadlineReached>().is_some() {
        PostLockFailureClass::ProveTimeEstimate
    } else if e.downcast_ref::<GpuMemoryShortage>().is_some() || e.downcast_ref::<HostMemoryShortage>().is_some() {
        PostLockFailureClass::ResourceLimit
    } else if let Some(w) = e.downcast_ref::<WorkerProofError>() {
        match w.kind {
            _ if w.is_gpu_oom() => PostLockFailureClass::ResourceLimit,
            ErrorKind::ResourceExhausted => PostLockFailureClass::ResourceLimit,
            ErrorKind::ProofFailed => PostLockFailureClass::Gpu,
            ErrorKind::InputMismatch => PostLockFailureClass::BundleLoss,
            _ => PostLockFailureClass::ProverCrash,
        }
    } else if e.downcast_ref::<zkminer_chain::revert::FulfilFailure>().is_some() {
        PostLockFailureClass::GasOrRpc
    } else {
        PostLockFailureClass::ProverCrash
    }
}

fn bundle_ref(r: &BundleRef) -> WitnessBundleRef {
    WitnessBundleRef { job_id: r.job_id, descriptor_hash: r.descriptor_hash, prover: r.prover, version: r.version }
}

/// The job's terminal state on an authoritative read (§15.2): Fulfilled, Cancelled, or Open at the
/// reopen limit.
fn terminal_state(rec: &JobRecord) -> Option<TerminalState> {
    match rec.status {
        JOB_STATUS_FULFILLED => Some(TerminalState::Fulfilled),
        JOB_STATUS_CANCELLED => Some(TerminalState::Cancelled),
        JOB_STATUS_OPEN if rec.reopen_count >= MAX_REOPEN_COUNT => Some(TerminalState::ReopenLimit),
        _ => None,
    }
}

/// Bytes available to this user on the filesystem holding `dir`.
fn free_bytes(dir: &Path) -> std::io::Result<u64> {
    let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).map_err(|_| std::io::Error::other("path contains NUL"))?;
    // SAFETY: statvfs fills a plain struct.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// A self-test bounded by [`SELF_TEST_TIMEOUT`]: one that does not finish is a failure.
async fn bounded_self_test(name: &str, test: impl std::future::Future<Output = Result<(), String>>) -> Result<(), String> {
    match tokio::time::timeout(SELF_TEST_TIMEOUT, test).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(why)) => Err(format!("the {name} self-test failed: {why}")),
        Err(_) => Err(format!("the {name} self-test did not finish in {} s", SELF_TEST_TIMEOUT.as_secs())),
    }
}

/// The broker's self-test from inside its sandbox and its connector's in this process (both must
/// pass).
async fn broker_self_test(client: &BrokerClient, connector: &Arc<zkminer_witness_broker::connector::Connector>) -> Result<(), String> {
    match zkminer_witness_host::broker_proc::self_test(client, connector).await {
        Ok(r) if r.ok => Ok(()),
        Ok(r) => Err(r
            .checks
            .iter()
            .filter(|(_, ok)| !ok)
            .map(|(c, _)| format!("{c:?}"))
            .collect::<Vec<_>>()
            .join(", ")),
        Err(e) => Err(format!("{e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_states_are_authoritative_reads_only() {
        let rec = |status, reopen_count| JobRecord { status, reopen_count, ..Default::default() };
        assert_eq!(terminal_state(&rec(JOB_STATUS_FULFILLED, 0)), Some(TerminalState::Fulfilled));
        assert_eq!(terminal_state(&rec(JOB_STATUS_CANCELLED, 0)), Some(TerminalState::Cancelled));
        assert_eq!(terminal_state(&rec(JOB_STATUS_OPEN, MAX_REOPEN_COUNT)), Some(TerminalState::ReopenLimit));
        assert_eq!(terminal_state(&rec(JOB_STATUS_OPEN, 1)), None, "a risen reopen count only unpins");
        assert_eq!(terminal_state(&rec(JOB_STATUS_LOCKED, 0)), None);
    }

    fn task(phase: Phase) -> Task {
        Task { token: AbortToken::new(), phase }
    }

    /// Two simulations finished at once on a one-card host: both passed the advisory card check,
    /// and both used to claim (the check and the mark were apart, with awaits between). The card is
    /// now checked and taken in one step, so only one claims; the other gets it once the first gives
    /// it back (its claim not sent) or its lock ends.
    #[test]
    fn two_simulations_cannot_both_claim_the_last_card() {
        let (a, b) = (B256::repeat_byte(0xa), B256::repeat_byte(0xb));
        let one_card = Some((0, 1));
        let mut tasks: HashMap<B256, Task> = [(a, task(Phase::Simulating)), (b, task(Phase::Simulating))].into();
        assert!(take_card(&mut tasks, one_card, a));
        assert_eq!(tasks[&a].phase, Phase::Claiming);
        assert!(!take_card(&mut tasks, one_card, b), "the card is taken");
        assert!(take_card(&mut tasks, one_card, a), "the claim's second check keeps its own card");
        give_back_card(&mut tasks, a);
        assert_eq!(tasks[&a].phase, Phase::Simulating);
        assert!(take_card(&mut tasks, one_card, b), "given back: the other claims");
        tasks.get_mut(&b).unwrap().phase = Phase::Locked;
        give_back_card(&mut tasks, b);
        assert_eq!(tasks[&b].phase, Phase::Locked, "a held lock keeps its card");
        assert!(!take_card(&mut tasks, one_card, a));
        tasks.remove(&b);
        assert!(take_card(&mut tasks, one_card, a), "the lock ended");
        // Inline work needing a card, and no word from the brain yet.
        assert!(!take_card(&mut tasks, Some((1, 2)), b), "no task for it");
        tasks.insert(b, task(Phase::Simulating));
        assert!(!take_card(&mut tasks, Some((1, 2)), b), "a's claim and one inline job fill two cards");
        assert!(!take_card(&mut tasks, None, b));
    }

    /// The same race with real threads: of many simulations finishing together on a one-card host,
    /// exactly one takes the card.
    #[test]
    fn concurrent_claims_take_one_card_once() {
        let jobs: Vec<B256> = (1..=8u8).map(B256::repeat_byte).collect();
        let tasks = Arc::new(Mutex::new(jobs.iter().map(|j| (*j, task(Phase::Simulating))).collect::<HashMap<_, _>>()));
        let barrier = Arc::new(std::sync::Barrier::new(jobs.len()));
        let won: usize = jobs
            .iter()
            .map(|j| {
                let (tasks, barrier, j) = (tasks.clone(), barrier.clone(), *j);
                std::thread::spawn(move || {
                    barrier.wait();
                    take_card(&mut lock(&tasks), Some((0, 1)), j)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum();
        assert_eq!(won, 1);
        assert_eq!(lock(&tasks).values().filter(|t| t.phase == Phase::Claiming).count(), 1);
    }

    #[test]
    fn a_claiming_task_is_still_aborted_and_holds_a_card() {
        assert!(Phase::Claiming.abortable() && Phase::Simulating.abortable() && !Phase::Locked.abortable());
        assert!(Phase::Claiming.holds_card() && Phase::Locked.holds_card() && !Phase::Simulating.holds_card());
    }

    #[test]
    fn governance_aborts_map_to_simulation_aborts() {
        let a = Address::repeat_byte(1);
        assert_eq!(host_abort(GovAbort::Cancelled { caller: a }), AbortReason::JobCancelled);
        assert_eq!(host_abort(GovAbort::ClaimedByOther { prover: a }), AbortReason::JobClaimed);
        assert_eq!(host_abort(GovAbort::BidSubmitted { bidder: a }), AbortReason::BidSubmitted);
    }
}
