//! The witness runtime (Linux): what serves witness-construction jobs in a running miner
//! (docs/witness-construction-jobs.md §5.2, §15, §17, §18).
//!
//! - **Startup** ([`WitnessRuntime::start`]): the retention store is opened whenever `[retention]` is
//!   configured (held witness locks are proven from it even with serving off). Serving needs
//!   `[witness] enabled`, a configuration that validates now, the delegated cgroup, the spawner
//!   thread, the sandboxed binaries, a passing sandbox self-test, the broker process and its own
//!   self-test. Any failure leaves serving off with
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
//!   count, a read at or after the lock block showing another prover, or a claim that never landed:
//!   a read from a block mined past the claim-intent age since the pin), deletes bundles of terminal
//!   jobs, and, once a full pass has completed and the
//!   brain's first recovery pass with a complete chain scan has handed over every witness lock it
//!   decided and each is pinned, enables eviction (sparing the bundles of the jobs that pass left
//!   undecided). A lock with no readable pin is found by the brain's chain scan and re-pinned
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
    fulfill_gas_formula, ClaimOutcome, ClaimQuote, FulfilDa, HashedFulfil, JobInfo, JOB_STATUS_FULFILLED, JOB_STATUS_LOCKED,
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
use zkminer_witness::verdict::{PostLockFailureClass, SkipReason, VerdictRecord};
use zkminer_witness_broker::client::{ArtifactCharge, BrokerClient};
use zkminer_witness_host::abort::{AbortReason, AbortToken};
use zkminer_witness_host::broker_proc::BrokerProcess;
use zkminer_witness_host::paths;
use zkminer_witness_host::pipeline::{
    descriptor_hash_of_abi, eviction_by_age, execute_worker_build, risc0_build_id,
    simulate_witness_job, sys_rand_rule, CycleJudging, HookFuture, HostContext, ImageIdFn,
    JobInput, PipelineHooks, Simulated, Skip,
};
use zkminer_witness_host::spawner::Spawner;
use zkminer_witness_host::store_open::open_store;
use zkminer_witness_store::{
    revalidate, BundleKey, BundleRef, HostProfile, Store, StoreError, TerminalProof, TerminalState, BUNDLE_JSON_ALLOWANCE,
};

use super::super as run;
use super::policy::{
    caller_admitted, caller_tally_key, card_room, claims_held_reason, deadline_fits, device_caller_tally_key,
    device_tally_key, divergence_reusable, elf_image_id_outcome, eligible_cards, estimate_prove_secs,
    fixed_allowance_secs, host_max_guest_cycles_over, CardPlan,
    fulfils_besides, funds_cover, gate_refusal_reason, held_lock_prove_sizes, host_max_guest_cycles,
    is_witness_input, lasts_until_terminal, not_claimable_reason, parse_session_cap, pin_lock_gone,
    pin_read_needs_time, proving_cutoff, rate_secs_left, reservation_wei, segment_need, session_cap_admits, short,
    tally_count, verdict_expires_at, verdict_plan, verdict_set_aside, watchdog_admits, ArtifactBudget, Blame,
    PinFacts, PinRead, ProvePlan, ReservationInputs, POST_LOCK_CALLER_LIMIT, POST_LOCK_CLASSES,
    POST_LOCK_DEVICE_LIMIT, POST_LOCK_TALLY_TTL_SECS, RISC0_CPU_CONSERVATIVE_CPS, SERVING_OFF_SET_ASIDE,
    UNSERVED_SET_ASIDE, VERDICT_UNTIL_TERMINAL,
};
use super::{known_class, note_class, Class, Route};
use crate::journal::WitnessBundleRef;

/// The largest builder artifact this host reads (the broker also enforces its own).
const MAX_ARTIFACT_BYTES: u64 = zkminer_witness_host::pipeline::DEFAULT_MAX_ARTIFACT_BYTES;
/// Wall clock of one sandboxed execute (every po2 of the host's set).
const EXECUTE_TIMEOUT: Duration = zkminer_witness_host::pipeline::DEFAULT_EXECUTE_TIMEOUT;
/// Wall clock of the execute worker's build handshake (it loads its binary and answers).
const EXECUTE_BUILD_TIMEOUT: Duration = Duration::from_secs(60);
/// How often the sandbox and broker self-tests run again (and a serving start that failed is tried
/// again).
const SELF_TEST_EVERY: Duration = Duration::from_secs(3600);
/// How often the configuration file is read again for `[witness] enabled` (the kill switch, §20.4).
const CONFIG_CHECK_EVERY: Duration = Duration::from_secs(15);
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
    /// The brain's recovery is releasing the lock ([`WitnessRuntime::claim_release`]): nothing else
    /// drives it meanwhile. Holds no card.
    Releasing,
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
    /// The card (benchmark device id) [`take_card`] booked for its proof, while it holds one: no
    /// other witness claim takes that card meanwhile. `None`: any card (the job fits every one).
    card: Option<String>,
}

impl Task {
    fn new(token: AbortToken, phase: Phase) -> Self {
        Task { token, phase, card: None }
    }
}

/// Takes a card for `jid`'s claim, in one step with the check that one is free: under the tasks
/// lock, a task that is simulating becomes `Claiming` only while the inline jobs needing a card
/// (`cards`, the brain's latest view) and every task already holding one leave room under the cap,
/// and, when the job fits only some cards (`fits`, benchmark device ids, fastest first; empty: any
/// card), one of those is neither proving an inline job (`busy`, the brain's view) nor booked by
/// another witness claim. That card is booked for it. A count alone claimed a job that fits only
/// the busy 5090 while the 4070 was free, and its proof waited there past its cutoff. Two
/// simulations that finish together can then never both claim the host's last card. `true` also
/// when the task already holds one; `false` when no card is free, the brain has not said yet, or
/// `jid` has no task.
fn take_card(tasks: &mut HashMap<B256, Task>, cards: Option<(usize, usize)>, busy: &[String], jid: B256, fits: &[String]) -> bool {
    match tasks.get(&jid).map(|t| t.phase) {
        None => return false,
        Some(p) if p.holds_card() => return true,
        Some(_) => {}
    }
    let held = tasks.values().filter(|t| t.phase.holds_card()).count();
    if !cards.is_some_and(|(inline, max)| card_room(inline, held, max)) {
        return false;
    }
    let card = if fits.is_empty() {
        None
    } else {
        let booked: Vec<&String> = tasks.values().filter(|t| t.phase.holds_card()).filter_map(|t| t.card.as_ref()).collect();
        match fits.iter().find(|d| !busy.contains(d) && !booked.contains(d)) {
            Some(d) => Some(d.clone()),
            None => return false,
        }
    };
    if let Some(t) = tasks.get_mut(&jid) {
        t.phase = Phase::Claiming;
        t.card = card;
    }
    true
}

/// Gives back the card [`take_card`] took for `jid` when its claim is not sent (a held lock keeps
/// its card).
fn give_back_card(tasks: &mut HashMap<B256, Task>, jid: B256) {
    if let Some(t) = tasks.get_mut(&jid) {
        if t.phase == Phase::Claiming {
            t.phase = Phase::Simulating;
            t.card = None;
        }
    }
}

/// What a release of a lock by the brain's recovery finds in the witness runtime
/// ([`WitnessRuntime::claim_release`]).
pub(crate) enum ReleaseClaim {
    /// A witness task owns the job (it drives the lock, or a store pass just took it up): no release
    /// beside it.
    Owned,
    /// Not a witness lock this runtime knows of.
    NotWitness,
    /// A witness lock, now the release's: until it is dropped no store pass re-drives the job.
    Witness(WitnessRelease),
}

/// A witness lock the brain's recovery is releasing; its job's task entry goes when this is dropped.
pub(crate) struct WitnessRelease {
    rt: Arc<WitnessRuntime>,
    jid: B256,
}

impl WitnessRelease {
    /// Records the job's post-lock verdict, before the release is sent (§16): the job is not locked
    /// here again until it is terminal, a restart included.
    pub(crate) async fn record_verdict(&self, why: &str) {
        self.rt.record_release_verdict(self.jid, why).await;
    }
}

impl Drop for WitnessRelease {
    fn drop(&mut self) {
        let mut tasks = lock(&self.rt.tasks);
        if tasks.get(&self.jid).is_some_and(|t| t.phase == Phase::Releasing) {
            tasks.remove(&self.jid);
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

/// How witness proofs on this host are planned: each card that may prove one, with the operator's
/// `deadline_safety_margin` (see `prove_plan`).
struct WitnessPlan {
    /// Every enabled risc0 card that may prove a witness job.
    cards: Vec<CardPlan>,
    margin: f64,
    /// The plan when no card is enabled (the floor rate at the host's sizes).
    floor: ProvePlan,
}

impl WitnessPlan {
    /// Over every card: the slowest rate and the largest fixed allowance.
    fn all(&self) -> ProvePlan {
        ProvePlan::over(self.cards.iter().map(|c| (c.cps, c.fixed_secs)), self.margin).unwrap_or(self.floor)
    }

    /// The plan a proof of `cycles` (its execute `execute_secs`) is sized at, and the cards it may run
    /// on, fastest first: those whose own estimate fits the watchdog and `fits_window`
    /// ([`eligible_cards`]), and the plan over them. No card fits: the plan over every card, which the
    /// gates then refuse, as before, and no cards (any card may take it).
    fn for_job(
        &self,
        cycles: u64,
        execute_secs: u64,
        proving_timeout_secs: u64,
        fits_window: impl Fn(u64) -> bool,
    ) -> (ProvePlan, Vec<CardPlan>) {
        let eligible =
            eligible_cards(&self.cards, self.margin, cycles, execute_secs, proving_timeout_secs, fits_window);
        match ProvePlan::over(eligible.iter().map(|c| (c.cps, c.fixed_secs)), self.margin) {
            Some(plan) => (plan, eligible),
            None => (self.all(), Vec::new()),
        }
    }

    /// The host's `maxGuestCycles` when the operator sets none: the most any card can prove inside the
    /// watchdog, or the floor plan's without a card.
    fn max_guest_cycles(&self, proving_timeout_secs: u64) -> u64 {
        if self.cards.is_empty() {
            host_max_guest_cycles(&self.floor, proving_timeout_secs)
        } else {
            host_max_guest_cycles_over(&self.cards, self.margin, proving_timeout_secs)
        }
    }
}

/// What the claim gate established.
struct GateOk {
    reservation: u128,
    /// The job's `fulfillmentTimeout` (from its record): a lock taken now ends this long after.
    window: u64,
    /// The fulfil's gas limit the gate funded.
    fulfil_gas: u64,
    /// What the claim may lock, and whose job it is, for the collateral cap (`run::collateral`).
    exposure: run::collateral::Exposure,
    /// The cards (benchmark device ids) it fits, fastest first; empty: any card. Its claim needs one
    /// of them free ([`take_card`]).
    fits: Vec<String>,
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
    /// How the lock failed, for the post-lock tallies (set before every `Err` that is not a hand-back).
    failure: Option<LockFailure>,
}

/// A held witness lock's proof, and where it ran.
struct Proved {
    proof: ProofOutput,
    slot: Option<String>,
    /// Its device was quarantined then (no other card proved the lock).
    on_quarantined: bool,
}

/// How a held witness lock failed (§16): the class, the device it failed on, and whether the caller's
/// tally counts it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LockFailure {
    /// The slot the failing proof attempt (or the rejected proof) ran on: its device is tallied.
    slot: Option<String>,
    class: PostLockFailureClass,
    /// Whether the caller's tally counts it: only when a proof attempt of the caller's guest ran on a
    /// device that was not quarantined then. Not when no attempt ran (no card proved it, the window
    /// had no room left), when the device was quarantined (the device's doing), or when a pending
    /// verifier swap's `readyAt` cut the lock short (governance's).
    caller: bool,
}

impl LockFailure {
    /// A failure on `slot` (quarantined or not when the attempt ran) of the caller's guest.
    fn on(slot: Option<String>, class: PostLockFailureClass, quarantined: &HashSet<String>) -> Self {
        let caller = slot.as_ref().is_some_and(|s| !quarantined.contains(s));
        Self { slot, class, caller }
    }

    /// A failure no device or caller caused: this host's (no card, no time left) or governance's.
    fn host(class: PostLockFailureClass) -> Self {
        Self { slot: None, class, caller: false }
    }

    /// A failure on the chain side after a proof (gas, RPC, blockspace), counted for the caller as
    /// every post-lock failure was.
    fn chain() -> Self {
        Self { slot: None, class: PostLockFailureClass::GasOrRpc, caller: true }
    }
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
    brain: Mutex<Option<BrainLink>>,
    sim_slots: Arc<tokio::sync::Semaphore>,
    classify_slots: Arc<tokio::sync::Semaphore>,
    proving_timeout: Duration,
    keccak_po2: u8,
    scan_complete: AtomicBool,
    /// Jobs a one-off notice was logged for (not admitted, needs claim_predicate_jobs).
    noticed: Mutex<HashSet<(B256, &'static str)>>,
    store_pass_running: AtomicBool,
    /// The execute worker's build, from its handshake when serving started, before any guest ran in
    /// it (`None` until serving started): never from a response of a process that ran a guest.
    execute_build: Mutex<Option<String>>,
    /// The brain's view of the cards, each tick: inline jobs still needing a card, and the cap.
    cards: Mutex<Option<(usize, usize)>>,
    /// The cards (benchmark device ids) inline jobs are proving on, each tick (the brain's view).
    busy_cards: Mutex<Vec<String>>,
    /// A brain recovery pass with a complete chain scan has handed over every witness lock it decided.
    brain_recovered: AtomicBool,
    /// Witness locks recovery handed over whose bundle is not pinned yet: eviction waits for them.
    unpinned_recoveries: Mutex<HashSet<B256>>,
    /// Jobs the brain's latest complete recovery pass left undecided: their bundles are spared from
    /// eviction (re-applied to a store opened later).
    undecided: Mutex<HashSet<B256>>,
    /// Image-id derivations that could not run (no measure worker free within the bound).
    image_id_unavailable: Arc<AtomicU64>,
    /// Callers' post-lock failure counts as last read or written here, with when they expire.
    post_lock_callers: Mutex<HashMap<Address, (u8, u64)>>,
    /// Post-lock tallies when no store is open (counted for this process only).
    tallies: Mutex<HashMap<B256, (u8, u64)>>,
    /// The miner is shutting down ([`Self::shutdown`]): held locks are the drain's, nothing re-drives one.
    stopping: AtomicBool,
    /// What a serving start needs, kept for a retry: the configuration the miner started with (when it
    /// enables serving).
    serve: Mutex<Option<Arc<ZkMinerConfig>>>,
    /// A serving start is running.
    starting: AtomicBool,
    /// The configuration file says `[witness] enabled = false` now (the kill switch): serving stays
    /// off whatever the self-tests say, until it says `true` again.
    switched_off: AtomicBool,
    /// A sandbox self-test thread is running (one that did not finish in its bound keeps it).
    sandbox_test_running: Arc<AtomicBool>,
    /// Held across one post-lock failure's tally updates (each a read and a write of store records),
    /// so two failures recorded at once never both count the same caller as new on a device.
    tally_updates: tokio::sync::Mutex<()>,
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
        let rt = Arc::new(Self::new(
            client,
            state,
            journal,
            config,
            config_path.map(PathBuf::from).unwrap_or_else(ZkMinerConfig::default_path),
            gov,
            backlog,
            da_policy,
            proving_timeout,
            keccak_po2,
        ));
        rt.open_store().await;
        if w.enabled {
            // §19: the effective configuration, whether or not serving then starts.
            tracing::info!("{}", effective_summary(w, config.retention.as_ref(), config.broker.as_ref()));
            // In the background: the self-tests and the broker start take seconds (minutes, bounded,
            // when something is wedged), and the brain and every inline job go on meanwhile. A start
            // that fails is tried again with the hourly self-tests.
            *lock(&rt.serve) = Some(Arc::new(config.clone()));
            let rt2 = rt.clone();
            tokio::spawn(async move { rt2.try_start_serving().await });
        } else {
            tracing::info!(
                "witness serving is off ([witness] enabled = false): witness jobs are not simulated; \
                 witness locks already held are still proven from the retention store"
            );
        }
        tokio::spawn(rt.clone().abort_loop());
        tokio::spawn(rt.clone().self_test_loop());
        tokio::spawn(rt.clone().config_watch_loop());
        Some(rt)
    }

    /// The runtime's state before anything starts: no store open, serving off, no task.
    #[allow(clippy::too_many_arguments)]
    fn new(
        client: &ChainClient,
        state: &SharedState,
        journal: &run::SharedJournal,
        config: &ZkMinerConfig,
        secret_path: PathBuf,
        gov: GovernanceView,
        backlog: BacklogSource,
        da_policy: DaCapPolicy,
        proving_timeout: Duration,
        keccak_po2: u8,
    ) -> Self {
        let w = &config.witness;
        Self {
            client: client.clone(),
            state: state.clone(),
            journal: journal.clone(),
            witness: w.clone(),
            retention: config.retention.clone(),
            rate_expires: w.hemi_per_eth_expires.as_deref().and_then(|s| rate_expiry(s).ok()),
            secret_path,
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
            brain: Mutex::new(None),
            sim_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SIMULATIONS)),
            classify_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CLASSIFICATIONS)),
            proving_timeout,
            keccak_po2,
            scan_complete: AtomicBool::new(false),
            noticed: Mutex::new(HashSet::new()),
            store_pass_running: AtomicBool::new(false),
            execute_build: Mutex::new(None),
            cards: Mutex::new(None),
            busy_cards: Mutex::new(Vec::new()),
            brain_recovered: AtomicBool::new(false),
            unpinned_recoveries: Mutex::new(HashSet::new()),
            undecided: Mutex::new(HashSet::new()),
            image_id_unavailable: Arc::new(AtomicU64::new(0)),
            post_lock_callers: Mutex::new(HashMap::new()),
            tallies: Mutex::new(HashMap::new()),
            stopping: AtomicBool::new(false),
            serve: Mutex::new(None),
            starting: AtomicBool::new(false),
            switched_off: AtomicBool::new(false),
            sandbox_test_running: Arc::new(AtomicBool::new(false)),
            tally_updates: tokio::sync::Mutex::new(()),
        }
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
                s.spare_jobs(lock(&self.undecided).iter().copied());
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

    /// Starts serving from the configuration the miner started with, unless a start is running, the
    /// configuration file switched serving off, or it was never enabled. `true` when it ran.
    async fn try_start_serving(self: &Arc<Self>) -> bool {
        let Some(config) = lock(&self.serve).clone() else { return false };
        if self.switched_off.load(Ordering::SeqCst) || self.starting.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.start_serving(&config).await;
        self.starting.store(false, Ordering::SeqCst);
        true
    }

    async fn start_serving(self: &Arc<Self>, config: &ZkMinerConfig) {
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
        if let Err(why) = bounded_self_test("sandbox", self.sandbox_self_test(&probe_binary)).await {
            return self.disable(why);
        }
        // The execute worker's build, asked before any requester's guest runs in it: what every bundle
        // records as the build its journals came from, and what a retained bundle is revalidated
        // against (so one published before a restart is reused, not simulated again).
        match execute_worker_build(&execute_binary, &root, EXECUTE_BUILD_TIMEOUT).await {
            Ok(build) => {
                tracing::info!("witness: the execute worker is {build}");
                *lock(&self.execute_build) = Some(build);
            }
            Err(e) => return self.disable(format!("the execute worker's build handshake: {e}")),
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
        if self.switched_off.load(Ordering::SeqCst) {
            tracing::warn!("witness serving did not start: [witness] enabled = false in the configuration now");
            return;
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

    /// The sandbox self-test, on a thread of its own (its probes die with that thread, which lives
    /// until they are reaped): one that does not finish in its bound never holds the spawner thread,
    /// which every builder, execute and broker start needs. While a test that did not finish still
    /// runs, the next one fails at once instead of piling threads up.
    async fn sandbox_self_test(&self, probe: &Path) -> Result<(), String> {
        let mode = match self.witness.sandbox_mode {
            SandboxModeConfig::System => zkminer_witness_sandbox::SandboxMode::System,
            SandboxModeConfig::Rootless => zkminer_witness_sandbox::SandboxMode::Rootless,
        };
        if self.sandbox_test_running.swap(true, Ordering::SeqCst) {
            return Err("the previous sandbox self-test has not finished".into());
        }
        let (probe, secret, running) = (probe.to_path_buf(), self.secret_path.clone(), self.sandbox_test_running.clone());
        let (tx, rx) = tokio::sync::oneshot::channel();
        let spawned = std::thread::Builder::new().name("witness-sandbox-self-test".into()).spawn(move || {
            let report = zkminer_witness_sandbox::self_test(mode, &probe, &secret);
            running.store(false, Ordering::SeqCst);
            let _ = tx.send(report);
        });
        if let Err(e) = spawned {
            self.sandbox_test_running.store(false, Ordering::SeqCst);
            return Err(format!("the sandbox self-test thread: {e}"));
        }
        let report = rx.await.map_err(|_| "the sandbox self-test thread is gone".to_string())?;
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

    /// Every hour, a [`Self::self_test_round`] (§10.3).
    async fn self_test_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(SELF_TEST_EVERY).await;
            if self.stopping() {
                return;
            }
            self.self_test_round().await;
        }
    }

    /// Serving follows the self-tests: a start that failed (or never finished) is tried again; once
    /// started, both self-tests run again and switch serving off or back on with their result.
    /// Nothing while the configuration file switched serving off.
    async fn self_test_round(self: &Arc<Self>) -> SelfTestRound {
        if self.switched_off.load(Ordering::SeqCst) {
            return SelfTestRound::SwitchedOff;
        }
        let Some(s) = lock(&self.serving).clone() else {
            if lock(&self.serve).is_none() {
                return SelfTestRound::NotEnabled;
            }
            tracing::warn!("witness serving did not start: trying again");
            return if self.try_start_serving().await { SelfTestRound::StartRetried } else { SelfTestRound::Starting };
        };
        let (exited, cut_off) = {
            let mut b = lock(&s.broker);
            (b.exited(), b.cut_off())
        };
        let result = match exited {
            _ if cut_off => Err("the connector cut the broker off (it broke the connector protocol) and killed it".into()),
            Some(status) => Err(format!("the broker exited ({status})")),
            None => match bounded_self_test("sandbox", self.sandbox_self_test(&s.probe_binary)).await {
                Err(why) => Err(why),
                Ok(()) => bounded_self_test("broker", broker_self_test(&s.broker_client, &s.connector)).await,
            },
        };
        // The execute worker's build again (its binary may have been replaced in place): new bundles
        // record it, and retained ones are revalidated against it.
        let result = match result {
            Ok(()) => match execute_worker_build(&s.execute_binary, &s.cgroup_root, EXECUTE_BUILD_TIMEOUT).await {
                Ok(build) => {
                    let before = lock(&self.execute_build).replace(build.clone());
                    if before.is_some_and(|b| b != build) {
                        tracing::warn!("witness: the execute worker is now {build}");
                    }
                    Ok(())
                }
                Err(e) => Err(format!("the execute worker's build handshake: {e}")),
            },
            Err(why) => Err(why),
        };
        match result {
            Ok(()) => {
                // Not over a kill switch thrown while the tests ran.
                if !self.switched_off.load(Ordering::SeqCst) && !self.enabled.swap(true, Ordering::SeqCst) {
                    tracing::warn!("witness serving is back on: the self-tests passed");
                }
                SelfTestRound::Passed
            }
            Err(why) => {
                self.disable(why);
                SelfTestRound::Failed
            }
        }
    }

    /// Reads `[witness] enabled` from the configuration file again every [`CONFIG_CHECK_EVERY`]
    /// (§20.4: the kill switch is hot). A file that is gone or does not parse changes nothing.
    async fn config_watch_loop(self: Arc<Self>) {
        let mut warned = false;
        loop {
            tokio::time::sleep(CONFIG_CHECK_EVERY).await;
            if self.stopping() {
                return;
            }
            let path = self.secret_path.clone();
            match blocking(move || configured_witness_enabled(&path)).await {
                Ok(Ok(enabled)) => {
                    warned = false;
                    self.apply_enabled(enabled);
                }
                Ok(Err(e)) => {
                    if !warned {
                        warned = true;
                        tracing::warn!(
                            "witness: the configuration file cannot be read again ({e:#}); [witness] enabled keeps \
                             its last value"
                        );
                    }
                }
                Err(_) => {}
            }
        }
    }

    /// `[witness] enabled` as the configuration file says it now. `false` switches serving off at once
    /// (no new admission, running simulations aborted, held locks continue) and keeps it off; `true`
    /// again runs the self-tests (or the start) now and serves on their result, for a miner started
    /// with serving enabled (one started with it off needs a restart).
    fn apply_enabled(self: &Arc<Self>, enabled: bool) {
        if !enabled {
            if !self.switched_off.swap(true, Ordering::SeqCst) && lock(&self.serve).is_some() {
                self.enabled.store(false, Ordering::SeqCst);
                tracing::warn!(
                    "witness serving switched off ([witness] enabled = false): no new witness job is admitted, \
                     running simulations are aborted, held witness locks continue"
                );
                self.abort_simulations(AbortReason::Disabled);
            }
            return;
        }
        if !self.switched_off.swap(false, Ordering::SeqCst) {
            return;
        }
        if lock(&self.serve).is_none() {
            if self.notice(B256::ZERO, "enable-needs-restart") {
                tracing::warn!(
                    "[witness] enabled = true in the configuration, but this miner started with witness serving \
                     off: restart it to serve witness jobs"
                );
            }
            return;
        }
        tracing::warn!("witness serving switched back on ([witness] enabled = true): running the self-tests first");
        let rt = self.clone();
        tokio::spawn(async move {
            rt.self_test_round().await;
        });
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

    /// The brain's view of the cards this tick: inline jobs still needing a card, the concurrency
    /// cap, and the cards (benchmark device ids) inline jobs are proving on. A witness lock is taken
    /// only while a card is free for it (see [`card_room`] and [`take_card`]).
    pub(crate) fn note_cards(&self, inline_needing: usize, max_concurrent: usize, busy: Vec<String>) {
        *lock(&self.busy_cards) = busy;
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

    /// [`take_card`] on this runtime's tasks and the brain's latest view of the cards, for a job
    /// that fits `fits`.
    fn take_card(&self, jid: B256, fits: &[String]) -> bool {
        let cards = *lock(&self.cards);
        let busy = lock(&self.busy_cards).clone();
        take_card(&mut lock(&self.tasks), cards, &busy, jid, fits)
    }

    /// [`give_back_card`] on this runtime's tasks.
    fn give_back_card(&self, jid: B256) {
        give_back_card(&mut lock(&self.tasks), jid);
    }

    /// The brain finished a recovery pass. `scan_complete`: its chain scan covered the whole lookback
    /// window, so every lock of ours was either decided by it (each witness lock handed to
    /// [`Self::drive_recovered`]) or is among `undecided` (unreadable just now, a claim that may still
    /// be pending, the pass cut short). After the first such pass eviction waits only for the
    /// handed-over locks to be pinned (§15.2: nothing is evicted before one full recovery scan), and
    /// it spares the bundles of the undecided jobs until a later pass decides them: a pass deferred
    /// over one unreadable job no longer holds eviction back for every other bundle.
    pub(crate) fn note_recovery_pass(&self, scan_complete: bool, undecided: Vec<B256>) {
        if !scan_complete {
            return;
        }
        if let Some(store) = self.store() {
            store.spare_jobs(undecided.iter().copied());
        }
        *lock(&self.undecided) = undecided.into_iter().collect();
        if !self.brain_recovered.swap(true, Ordering::SeqCst) {
            tracing::info!("witness: the brain's recovery pass handed over every witness lock it decided");
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

    /// Takes a lock the brain's recovery is about to release (its room rule: too close to the deadline
    /// to drive) away from every other witness path, in one step with the check that no task owns it,
    /// so a store pass that re-drives it and the release never both go: whichever comes first wins.
    pub(crate) fn claim_release(self: &Arc<Self>, jid: B256) -> ReleaseClaim {
        let witness = self.is_witness_lock(jid) || known_class(jid) == Some(Class::Witness);
        let mut tasks = lock(&self.tasks);
        if tasks.contains_key(&jid) {
            return ReleaseClaim::Owned;
        }
        if !witness {
            return ReleaseClaim::NotWitness;
        }
        tasks.insert(jid, Task::new(AbortToken::new(), Phase::Releasing));
        ReleaseClaim::Witness(WitnessRelease { rt: self.clone(), jid })
    }

    /// Before a lock of `jid` is released other than by its own failure (the brain's room rule, a
    /// shutdown): a witness lock's job gets its post-lock verdict, so this host never locks it again
    /// until it is terminal (what ended the lock, a lost store or bundle or a held fulfil, may recur;
    /// each job is released here at most once). Nothing for an inline lock.
    pub(crate) async fn note_release(&self, jid: B256, why: &str) {
        if self.is_witness_lock(jid) || known_class(jid) == Some(Class::Witness) {
            self.record_release_verdict(jid, why).await;
        }
    }

    /// The post-lock verdict of a witness lock released without a failure of its proof: final for
    /// the job, counted against no caller or device. Once per job (a verdict already lasting until
    /// the job is terminal stays as it is).
    async fn record_release_verdict(&self, jid: B256, why: &str) {
        if let Some(s) = self.store() {
            let held = blocking(move || s.verdict(jid)).await.ok().and_then(|r| r.ok()).flatten();
            if held.is_some_and(|v| lasts_until_terminal(v.reason, v.expires_at)) {
                return;
            }
        }
        self.record_verdict(jid, Address::ZERO, SkipReason::PostLockFailure, why).await;
    }

    /// Fires every simulation's abort token (shutdown). Held locks are left to the drain: from here no
    /// store pass or recovery re-drives one beside it.
    pub(crate) fn shutdown(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        self.abort_simulations(AbortReason::Shutdown);
    }

    /// Shutdown has begun (this runtime's [`Self::shutdown`], or the miner's flag).
    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst) || shutting_down()
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
        // Not served while the operator holds new work back (risc0 switched off): set aside like a job
        // with serving off, instead of starting a task that only finds this out.
        if !self.serving_enabled() || self.claims_held_now().is_some() {
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
            t.insert(jid, Task::new(token.clone(), Phase::Simulating));
        }
        let (rt, job) = (self.clone(), job.clone());
        tokio::spawn(async move {
            let _entry = TaskEntry { rt: rt.clone(), job_id: jid };
            let locked = rt.simulate_and_lock(&job, descriptor_hash, &token).await;
            match locked {
                Some(l) => rt.run_locked(l).await,
                // Not locked: whatever the gate reserved for the proof goes.
                None => run::segment_disk::release(jid),
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

    /// How witness proofs on this host are planned (§5.2 step 7): every enabled risc0 card that may
    /// prove one, each with its rate (its benchmark row at its size, else the floor for its kind: a
    /// card with no row is never left out) and its fixed allowance (its measured Groth16 wrap, else
    /// the allowance for its kind; a CPU slot's wrap is minutes), with the operator's
    /// `deadline_safety_margin`. A job is sized on the cards it fits ([`WitnessPlan::for_job`]).
    /// `po2s` (the host's sizes) only seed the floor when no card is enabled.
    async fn prove_plan(&self, po2s: &[u8]) -> WitnessPlan {
        let cards = run::current_risc0_cards(&self.state, true).await;
        let vram: std::collections::HashMap<String, Option<u64>> = zkminer_prover::engine::worker_pool()
            .map(|p| p.risc0_slots().into_iter().map(|(slot, _, vram)| (slot, vram)).collect())
            .unwrap_or_default();
        let st = self.state.read().await;
        let margin = st.runtime_settings.deadline_safety_margin;
        let margin = if margin.is_finite() && margin >= 1.0 { margin } else { 1.0 };
        let suite = st.benchmark_results.as_ref().filter(|s| !run::is_synthetic_suite(s));
        let cards = cards
            .iter()
            .map(|c| {
                let row = suite.and_then(|s| {
                    s.device_benchmarks
                        .iter()
                        .find(|d| d.device_id == c.device && d.prover_backend == zkminer_prover_protocol::BACKEND_RISC0)
                });
                let cpu = c.device == "cpu";
                // Priced down above the largest size the card's VRAM holds, as admission prices it.
                let fit = zkminer_prover::benchmark::risc0_largest_fitting_po2(
                    vram.get(&c.slot).copied().flatten(),
                    c.slot.split(':').nth(1).unwrap_or(""),
                );
                let measured = row
                    .map(|r| zkminer_prover::benchmark::risc0_job_throughput(r, c.po2, fit))
                    .filter(|t| t.is_finite() && *t > 0.0);
                let cps = measured.unwrap_or_else(|| {
                    if cpu {
                        RISC0_CPU_CONSERVATIVE_CPS
                    } else {
                        run::risc0_conservative_cps(&[c.po2])
                    }
                });
                let fixed_secs = fixed_allowance_secs(row.and_then(|r| r.wrap_secs()), cpu);
                CardPlan { device: c.device.clone(), cps, fixed_secs }
            })
            .collect();
        WitnessPlan {
            cards,
            margin,
            floor: ProvePlan {
                cps: run::risc0_conservative_cps(po2s),
                fixed_secs: fixed_allowance_secs(None, false),
                margin,
            },
        }
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

    /// [`Self::prove_worker_builds`] and the execute worker's build (its handshake's; its journals are
    /// the bundle's): what revalidation compares a bundle with (§15.2).
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
            sys_rand_rule: sys_rand_rule(),
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
        plan: &WitnessPlan,
        worker_builds: Vec<String>,
        execute_build: String,
    ) -> HostContext {
        let w = &self.witness;
        HostContext {
            spawner: serving.spawner.clone(),
            broker: serving.broker_client.clone(),
            store: store.clone(),
            cgroup_root: serving.cgroup_root.clone(),
            builder_binary: serving.builder_binary.clone(),
            execute_binary: serving.execute_binary.clone(),
            host_maxima: zkminer_witness_host::pipeline::host_maxima(
                w,
                w.max_guest_cycles.unwrap_or_else(|| plan.max_guest_cycles(self.proving_timeout.as_secs())),
            ),
            po2s,
            // Any of its cards may prove the job: over the cap at one is a skip.
            cycle_judging: CycleJudging::EveryPo2,
            keccak_po2: self.keccak_po2,
            worker_builds,
            execute_build,
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
        let expires_at = verdict_expires_at(reason, plan.ttl_secs, now);
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
            "witness job {}: skipped — {reason:?} (attempt {}, {}){}: {}",
            short(jid),
            plan.attempts,
            match (plan.final_verdict, expires_at == VERDICT_UNTIL_TERMINAL) {
                (_, true) => "final until the job is terminal".to_string(),
                (true, false) => format!("final for {} s", plan.ttl_secs),
                (false, false) => format!("retried in {} s", plan.ttl_secs),
            },
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
    /// instead of simulating again (§15.2 single flight; re-locks and restarts reuse their bundle; no
    /// builder or data source runs again). Not before the execute worker's build is known (its
    /// handshake when serving starts), and never one that does not record its execute time (the
    /// prove's execute allowance).
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

    /// Why new witness work must not start now, though nothing is wrong with any job: a lock of
    /// this prover was slashed (the slash latch), the operator paused claiming (or the miner drives
    /// held locks only), or switched risc0 off.
    async fn claims_held(&self) -> Option<&'static str> {
        if run::slash_latch::tripped().is_some() {
            return Some(run::slash_latch::HOLD_SHORT);
        }
        let st = self.state.read().await;
        claims_held_reason(
            run::held_locks_only(),
            st.paused,
            st.runtime_settings.disabled_backends.contains(zkminer_prover_protocol::BACKEND_RISC0),
        )
    }

    /// [`Self::claims_held`] for the brain's routing, without waiting on the state: `None` while it
    /// is being written just now (the task's own check then decides).
    fn claims_held_now(&self) -> Option<&'static str> {
        if run::slash_latch::tripped().is_some() {
            return Some(run::slash_latch::HOLD_SHORT);
        }
        let st = self.state.try_read().ok()?;
        claims_held_reason(
            run::held_locks_only(),
            st.paused,
            st.runtime_settings.disabled_backends.contains(zkminer_prover_protocol::BACKEND_RISC0),
        )
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
        let execute_build = lock(&self.execute_build).clone()?;
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
                let ctx = self.host_context(&serving, &store, po2s.clone(), &plan, prove_builds, execute_build);
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
                    artifact: None,
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
        let gate = match self.claim_gate(&job.info, &d, &rec, &candidate, &plan, quote.price_floor).await {
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
        info: &JobInfo,
        d: &JobDescriptor,
        rec: &JobRecord,
        c: &Candidate,
        plan: &WitnessPlan,
        price: u128,
    ) -> Result<GateOk, (SkipReason, String)> {
        let jid = info.job_id;
        with_lane(Lane::PreClaim, async {
            if c.journal.len() > MAX_JOURNAL_BYTES {
                return Err((SkipReason::JournalTooLarge, format!("{} bytes", c.journal.len())));
            }
            // The collateral cap, as the inline gate applies it (`run::collateral`): what this job
            // alone may lock at its maximum price (its terms are fixed while it is Open: this host's
            // limit, looked at again when the host changes), and with its program's and caller's
            // unproven jobs here (not now).
            let exposure = self.collateral_exposure(info, price).await?;
            if let Some(refusal) = cap_refusal(run::collateral::check(jid, &exposure, self.collateral_cap().await)) {
                return Err(refusal);
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
                if !funds_cover(bal, fulfil_gas, max_fee, self.held_locks_besides(jid)) {
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
            // The proving time: every attempt inside the watchdog, and the margin before D, on the
            // cards this job fits (the dispatcher sends it to no other when it is proven).
            let timeout = self.proving_timeout.as_secs();
            let (plan, fits) = plan.for_job(cycles, c.execute_secs_per_po2, timeout, |need| {
                let (fulfil, attempt) = (run::DEADLINE_FULFILL_MARGIN_SECS, run::MIN_ATTEMPT_BUDGET_SECS);
                deadline_fits(rec.fulfillment_timeout, need, fulfil, attempt)
            });
            let plan = &plan;
            let prove_secs = estimate_prove_secs(cycles, plan, c.execute_secs_per_po2);
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
            // planned or running, inline ones included: `run::segment_disk`), then host RAM through
            // the dispatcher's ledger.
            let need = segment_need(c.per_po2.iter().map(|p| p.2));
            if let Some(dir) = self.retention.as_ref().map(|r| r.segment_dir.clone()) {
                run::segment_disk::try_reserve(jid, need, &dir).map_err(|e| (SkipReason::ProveResources, e))?;
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
                 ({} c/s, {} s fixed, margin {:.2}; watchdog {timeout} s; on {})",
                short(jid),
                est.estimated_bytes,
                plan.cps.round(),
                plan.fixed_secs,
                plan.margin,
                fits.iter().map(|c| c.device.as_str()).collect::<Vec<_>>().join(", ")
            );
            let fits = fits.into_iter().map(|c| c.device).collect();
            Ok(GateOk { reservation, window: rec.fulfillment_timeout, fulfil_gas, exposure, fits })
        })
        .await
    }

    /// Locks held here, inline and witness, other than `jid`'s: the journal's entries (each a claim
    /// of ours, pending or held) except its own, which this claim's intent (or an earlier claim of it
    /// still unresolved) has put there. Its fulfil is counted once, as this claim's.
    fn held_locks_besides(&self, jid: B256) -> usize {
        fulfils_besides(lock(&self.journal).entries.keys().copied(), jid)
    }

    /// What a claim of `info`'s job may lock: its collateral at its maximum price (or the quoted
    /// `price`, if higher) under its own snapshotted terms, as the inline gate sizes it.
    async fn collateral_exposure(&self, info: &JobInfo, price: u128) -> Result<run::collateral::Exposure, (SkipReason, String)> {
        run::prefetch_job_collateral_terms(&self.client, &[info.job_id]).await;
        let Some(terms) = run::job_collateral_terms(info.job_id) else {
            return Err((SkipReason::OperatorEndpoint, "its collateral terms (getJobSnapshots) are unreadable".into()));
        };
        Ok(run::claim_exposure(info, price, terms))
    }

    /// The collateral caps at the stake last read (each `None`: off, or the stake not known yet), with
    /// that read's locked figure while it is fresh, as the brain's claims are held to.
    async fn collateral_cap(&self) -> run::collateral::Caps {
        let s = self.state.read().await;
        run::collateral::caps_at(s.stake_info.as_ref(), run::collateral::fresh_reading(s.last_refresh))
    }

    // ── the lock (§5.2 step 9) ────────────────────────────────────────────────

    /// Drops what a claim that provably did not land left: the claim intent and the pin. When an
    /// earlier claim of ours is unresolved (`prior`), both stay: that claim may have landed, and its
    /// lock would then be proven from this pin (recovery decides from the chain).
    async fn abandon_intent(&self, jid: B256, bundle: BundleRef, prior: bool) {
        run::segment_disk::release(jid);
        run::collateral::forget(jid);
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
    async fn lock_held_back(&self, jid: B256, fulfil_gas: u64, fits: &[String]) -> Option<String> {
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
            Ok(bal) if !funds_cover(bal, fulfil_gas, max_fee, self.held_locks_besides(jid)) => {
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
        if !self.take_card(jid, fits) {
            return Some("no card it fits is free for its proof (inline work or witness locks fill them)".into());
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
        if let Some(why) = self.lock_held_back(jid, gate.fulfil_gas, &gate.fits).await {
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
        // From above: the never-confirmed rule counts the claim-intent age from here, so it must
        // never start early.
        let pinned_at_unix = zkminer_chain::client::chain_now();
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
        if let Some(why) = self.lock_held_back(jid, gate.fulfil_gas, &gate.fits).await {
            self.abandon_intent(jid, c.bundle, prior).await;
            tracing::info!("witness job {}: not locked now — {}", short(jid), zkminer_chain::programs::sanitize_log(&why));
            self.record_verdict(jid, caller, SkipReason::NotAdmitted, &why).await;
            return None;
        }
        // The collateral cap once more, deciding and counting the claim in one step: an inline claim
        // may have taken its program's or caller's share since the gate.
        if let Some((reason, why)) = cap_refusal(run::collateral::admit(jid, gate.exposure, self.collateral_cap().await)) {
            self.abandon_intent(jid, c.bundle, prior).await;
            tracing::info!("witness job {}: not locked now — {why}", short(jid));
            self.record_verdict(jid, caller, reason, &why).await;
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
                // The receipt proved the lock: its pin and journal entry learn where, so neither ever
                // takes this lock for a claim that did not land.
                self.note_pin_lock(&store, pin, lock_block, reopen_count).await;
                run::journal_update(&self.journal, |j| j.note_lock_seen(jid, Some(lock_block), reopen_count));
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
        // A lock held and not settled yet counts against its program's and caller's share of the
        // stake, and the stake's (a recovered one too), at what it locked.
        run::collateral::record(
            jid,
            run::collateral::Exposure {
                program: l.descriptor.programId,
                submitter: caller,
                collateral: l.locked_collateral.max(run::collateral::floor().unwrap_or(0)),
            },
        );
        // Where its lock is known (a recovered one's too), so a stake read at or after it is not
        // counted as missing it.
        if l.lock_block != 0 {
            run::collateral::note_lock_block(jid, l.lock_block);
        }
        let link = lock(&self.brain).clone();
        let _slot = link.map(|b| {
            let _ = b.held.send((jid, l.locked_collateral, l.cycles));
            run::SlotGuard(jid, b.done)
        });
        let result = with_lane(Lane::HeldLock, self.prove_and_fulfil(&mut l)).await;
        run::segment_disk::release(jid);
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
                let failure = l.failure.clone().unwrap_or(LockFailure { slot: None, class: failure_class(&e), caller: true });
                tracing::error!("witness lock {} failed after the lock ({msg}); releasing", short(jid));
                self.state.write().await.add_log(LogLevel::Error, format!("Witness job {} failed: {msg}", short(jid)));
                // Before the release: a restart between the two must not lock the job again.
                self.record_post_lock_failure(jid, caller, &failure).await;
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
    /// is never locked again, across restarts, until the job is terminal on chain), the caller's tally
    /// when the failure counts against it, and the device's: the distinct callers with a failure of
    /// its class there (a device reaching [`POST_LOCK_DEVICE_LIMIT`] takes no new witness lock). All
    /// kept in the store. Never fed to the host-wide program marks.
    async fn record_post_lock_failure(&self, jid: B256, caller: Address, f: &LockFailure) {
        let class = f.class;
        let device = f.slot.as_deref().map(device_of_slot);
        self.record_verdict(jid, caller, SkipReason::PostLockFailure, &format!("{class:?}")).await;
        let _updating = self.tally_updates.lock().await;
        let counted = if f.caller {
            let (n, until) = self.bump_tally(caller_tally_key(caller), true).await;
            lock(&self.post_lock_callers).insert(caller, (n, until));
            format!(
                "caller {caller} has {n} in the last {} days{}",
                POST_LOCK_TALLY_TTL_SECS / 86_400,
                if n >= POST_LOCK_CALLER_LIMIT { "; its witness jobs are no longer admitted" } else { "" }
            )
        } else {
            format!("not counted against caller {caller} (this host's, a quarantined device's or governance's)")
        };
        tracing::error!(
            "witness lock {}: post-lock failure ({class:?}{}) — {counted}",
            short(jid),
            device.as_deref().map_or(String::new(), |d| format!(" on {d}")),
        );
        if let Some(d) = device {
            // Each caller counts once per device and class: one caller's guest alone never
            // quarantines a device for everyone.
            let marker = device_caller_tally_key(&d, class, caller);
            let counted_before = self.tally(marker).await.0 > 0;
            self.bump_tally(marker, true).await;
            let (k, _) = self.bump_tally(device_tally_key(&d, class), !counted_before).await;
            if k >= POST_LOCK_DEVICE_LIMIT {
                tracing::error!(
                    "PAGE: WITNESS-DEVICE-QUARANTINED {d}: post-lock witness failures of class {class:?} from {k}                      callers in the last {} days — it takes no new witness lock until they age out (locks held                      keep proving; inline jobs are unaffected)",
                    POST_LOCK_TALLY_TTL_SECS / 86_400
                );
            }
        }
    }

    /// Counts one more post-lock failure in a tally (a store verdict record under a key that is never
    /// a job id; `increment` false only renews it) and returns the count and when it expires: 7 days
    /// from the latest. An expired tally starts again. Without a store, counted in memory.
    async fn bump_tally(&self, key: B256, increment: bool) -> (u8, u64) {
        let now = now_unix();
        let until = now.saturating_add(POST_LOCK_TALLY_TTL_SECS);
        let step = move |prior: u8| if increment { prior.saturating_add(1) } else { prior };
        let Some(store) = self.store() else {
            let mut m = lock(&self.tallies);
            let e = m.entry(key).or_insert((0, 0));
            let n = step(tally_count(e.0, e.1, now));
            *e = (n, until);
            return (n, until);
        };
        let result = blocking(move || {
            let prior = store.verdict(key).ok().flatten().map_or(0, |v| tally_count(v.attempts, v.expires_at, now));
            let n = step(prior);
            let rec = VerdictRecord {
                job_id: key,
                reason: SkipReason::PostLockFailure,
                attempts: n,
                recorded_at: now,
                expires_at: until,
                wasmtime_version: None,
            };
            store.put_verdict(&rec).map(|()| n).map_err(|e| (n, e))
        })
        .await;
        match result {
            Ok(Ok(n)) => (n, until),
            Ok(Err((n, e))) => {
                tracing::warn!("witness: a post-lock failure tally was not persisted: {e}");
                (n, until)
            }
            Err(e) => {
                tracing::warn!("witness: a post-lock failure tally was not persisted: {e:#}");
                (u8::from(increment), until)
            }
        }
    }

    /// A post-lock tally's count now and when it expires (0 when there is none, or it expired).
    async fn tally(&self, key: B256) -> (u8, u64) {
        let now = now_unix();
        let Some(store) = self.store() else {
            return lock(&self.tallies).get(&key).map_or((0, 0), |(n, t)| (tally_count(*n, *t, now), *t));
        };
        blocking(move || {
            store.verdict(key).ok().flatten().map_or((0, 0), |v| (tally_count(v.attempts, v.expires_at, now), v.expires_at))
        })
        .await
        .unwrap_or((0, 0))
    }

    /// The caller's post-lock failures as last read here (`None` when not read yet).
    fn caller_post_lock_failures(&self, caller: Address) -> Option<u8> {
        let now = now_unix();
        lock(&self.post_lock_callers).get(&caller).map(|(n, t)| tally_count(*n, *t, now))
    }

    /// The caller's post-lock failures read from the store, remembered for routing until the
    /// tally's own expiry.
    async fn caller_post_lock_failures_now(&self, caller: Address) -> u8 {
        let (n, until) = self.tally(caller_tally_key(caller)).await;
        let mut m = lock(&self.post_lock_callers);
        if m.len() >= PER_JOB_CAP {
            m.clear();
        }
        m.insert(caller, (n, until));
        n
    }

    /// The slots among `slots` whose device is quarantined: post-lock witness failures of some class
    /// from [`POST_LOCK_DEVICE_LIMIT`] distinct callers (§16).
    async fn quarantined(&self, slots: &[String]) -> HashSet<String> {
        let mut out = HashSet::new();
        for slot in slots {
            let device = device_of_slot(slot);
            for class in POST_LOCK_CLASSES {
                if self.tally(device_tally_key(&device, class)).await.0 >= POST_LOCK_DEVICE_LIMIT {
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
            // No room left before any attempt ran (a lock recovered late): not the caller's.
            l.failure = Some(LockFailure::host(PostLockFailureClass::ProveTimeEstimate));
            return Err(e);
        }
        run::journal_update(&self.journal, |j| j.mark_proving(jid));
        self.state.write().await.add_log(LogLevel::Info, format!("Proving witness job {}...", short(jid)));
        let proved = self.prove(&store, l).await?;
        card.release();
        let proof = &proved.proof;
        tracing::info!("WITNESS-LOCK {}: proved ({} cycles, {:.1} s)", short(jid), proof.cycles, proof.duration.as_secs_f64());
        self.fulfil(l, proved).await
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

    /// Execute, compare, prove (§15.3), only on a card at an executed po2: one whose device is not
    /// quarantined when any such card proves it, else a quarantined one (the quarantine applies to
    /// new locks, §16; a held lock keeps proving). Returns the proof and where it ran. Before every
    /// `Err` that is not a hand-back, `l.failure` says on which slot and how it failed, and whether
    /// the caller's tally counts it (the post-lock tallies).
    async fn prove(self: &Arc<Self>, store: &Arc<Store>, l: &mut LockCtx) -> Result<Proved> {
        use zkminer_prover_protocol::types::{GpuMemoryShortage, HostMemoryShortage, ProofDeadlineReached, WorkerProofError};
        let jid = l.job_id;
        let pool = zkminer_prover::engine::worker_pool().ok_or_else(|| anyhow!("no worker pool available"))?;
        let psid = l.descriptor.proofSystemId;
        let segment_dir = self.segment_dir(jid);
        let (mut attempt, mut host_waits, mut gpu_waits) = (0u32, 0u32, 0u32);
        let mut excluded: Vec<String> = Vec::new();
        let mut diverged = false;
        let mut warned_no_card = false;
        let mut warned_quarantined = false;
        // Whether a proof attempt of the guest ran on a card (else a release is the host's).
        let mut ran = false;
        // After a divergence, the re-versioned bundle is proven on the slot that diverged: it is the
        // one whose execution the new version records.
        let mut only_slot: Option<String> = None;
        loop {
            attempt += 1;
            run::refresh_lock_deadline(&self.client, &self.state, &self.journal, jid, &mut l.lock_deadline).await;
            let cutoff = self.proving_cutoff(l);
            let abort_at = match run::deadline_proof_budget(cutoff) {
                None => None,
                Some(b) if b < Duration::from_secs(run::MIN_ATTEMPT_BUDGET_SECS) => {
                    if !shutting_down() && cutoff == l.lock_deadline && self.client.job_clock_stopped(psid).await {
                        tokio::time::sleep(run::FULFIL_RETRY_WAIT).await;
                        attempt = attempt.saturating_sub(1);
                        continue;
                    }
                    // Out of time: the caller's guest only if an attempt of it ran, and never when a
                    // verifier swap's readyAt (governance) is what ends the budget.
                    l.failure = Some(LockFailure {
                        slot: None,
                        class: PostLockFailureClass::ProveTimeEstimate,
                        caller: ran && cutoff == l.lock_deadline,
                    });
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
            let executed: Vec<u32> =
                l.record.po2_results.iter().filter(|r| r.exit == GuestExit::Halted(0)).map(|r| r.po2).collect();
            let sizes = held_lock_prove_sizes(&all, &quarantined, &executed);
            if sizes.keys().any(|s| quarantined.contains(s)) && !warned_quarantined {
                warned_quarantined = true;
                tracing::warn!(
                    "witness lock {} is proven on a quarantined device ({:?}): no other card proves it at an \
                     executed po2, and the quarantine stops new locks only",
                    short(jid),
                    sizes.keys().collect::<Vec<_>>()
                );
            }
            if sizes.is_empty() {
                if shutting_down() {
                    return Err(run::HandBack(format!("no enabled card proves at an executed po2 {executed:?}")).into());
                }
                if !warned_no_card {
                    warned_no_card = true;
                    tracing::warn!(
                        "witness lock {} waits for a card at an executed po2 {executed:?}{} (it is never proven \
                         at another size); released before its deadline otherwise",
                        short(jid),
                        only_slot.as_ref().map_or(String::new(), |s| format!(" on {s}, where it diverged")),
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
            run::segment_disk::reserve(jid, segment_need(l.record.po2_results.iter().map(|r| r.segment_bytes)));
            // The configured cap (`prover.proving_timeout_secs`), not the inline path's tightened
            // estimate: a watchdog kill costs a witness lock its proof. The claim gate admitted the
            // lock only if its realistic estimate (the CPU wrap included) fits this cap; the deadline
            // budget (`abort_at`) still bounds every attempt.
            let timeout = self.proving_timeout;
            // The cards it fits in the time left, fastest first: the dispatcher sends it to no other
            // (none fits: any card, as before).
            let fits: Vec<String> = {
                let halted = l.record.po2_results.iter().filter(|r| r.exit == GuestExit::Halted(0));
                let cycles = halted.map(|r| r.cycles).max().unwrap_or(0);
                let execute_secs = l.record.execute_ms_per_po2.unwrap_or(0).div_ceil(1000);
                let budget = run::deadline_proof_budget(cutoff).map(|b| b.as_secs());
                let po2s: Vec<u8> = executed.iter().filter_map(|p| u8::try_from(*p).ok()).collect();
                let (_, fits) = self.prove_plan(&po2s).await.for_job(cycles, execute_secs, timeout.as_secs(), |need| {
                    budget.is_none_or(|b| need <= b)
                });
                fits.into_iter().map(|c| c.device).collect()
            };
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
                    zkminer_prover::dispatcher::JobCards { eligible: &fits, order: &fits },
                    0,
                );
                (r, used)
            })
            .await
            .map_err(|e| anyhow!("prove task panicked: {e}"))?;
            ran = true;
            let on = |class| Some(LockFailure::on(used.clone(), class, &quarantined));
            match res {
                Ok(WitnessProveOutcome::Proved(p)) => {
                    let on_quarantined = used.as_ref().is_some_and(|s| quarantined.contains(s));
                    return Ok(Proved { proof: p, slot: used, on_quarantined });
                }
                Ok(WitnessProveOutcome::JournalDiverged(dv)) => {
                    let po2 = used.as_ref().and_then(|s| sizes.get(s)).copied();
                    tracing::error!(
                        "PAGE: JOURNAL-DIVERGED witness lock {}: the proving execute at po2 {po2:?} committed a \
                         {}-byte journal the bundle does not record",
                        short(jid),
                        dv.journal_len
                    );
                    if diverged {
                        l.failure = on(PostLockFailureClass::JournalDiverged);
                        bail!("a second journal divergence on witness lock {}: releasing", short(jid));
                    }
                    diverged = true;
                    if let Err(e) = self.reversion(store, l, &dv, po2).await {
                        if e.downcast_ref::<run::HandBack>().is_none() {
                            l.failure = on(PostLockFailureClass::JournalDiverged);
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
                        if run::refresh_lock_deadline(&self.client, &self.state, &self.journal, jid, &mut l.lock_deadline).await
                            && run::deadline_proof_budget(self.proving_cutoff(l))
                                .is_some_and(|b| b >= Duration::from_secs(run::MIN_ATTEMPT_BUDGET_SECS))
                        {
                            attempt = attempt.saturating_sub(1);
                            continue;
                        }
                        let mut f = LockFailure::on(used.clone(), PostLockFailureClass::ProveTimeEstimate, &quarantined);
                        // A verifier swap's readyAt that ended the budget is governance's.
                        f.caller &= self.proving_cutoff(l) == l.lock_deadline;
                        l.failure = Some(f);
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
                        l.failure = on(PostLockFailureClass::ProverCrash);
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
                    l.failure = on(failure_class(&e));
                    bail!("proving witness lock {} failed after {attempt} attempt(s): {msg}", short(jid));
                }
            }
        }
    }

    /// The job's row on the dashboard follows its proof (Queued → Proving, and the card).
    fn progress_callback(&self, jid: B256) -> zkminer_prover::dispatcher::SlotProgress {
        let state = self.state.clone();
        let runtime = tokio::runtime::Handle::current();
        Box::new(
            move |_event: zkminer_prover_protocol::ProveEvent, slot_key: &str| {
                let bus =
                    zkminer_prover::engine::worker_pool().and_then(|p| p.bus_id_for_slot(slot_key));
                let (state, slot_key) = (state.clone(), slot_key.to_string());
                runtime.spawn(async move {
                    let mut st = state.write().await;
                    if let Some(j) = st.active_jobs.iter_mut().find(|j| j.info.job_id == jid) {
                        if matches!(j.status, MinerJobStatus::Queued) {
                            j.status = MinerJobStatus::Proving {
                                progress: 0.0,
                                elapsed_secs: 0,
                            };
                        }
                        j.gpu_bus_id = bus;
                        j.prover_backend = slot_key;
                    }
                });
            },
        )
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
        let execute_secs = l.record.execute_ms_per_po2.unwrap_or(0).div_ceil(1000);
        // On the cards it still fits, as it will be proven (see the prove call's `JobCards`).
        let budget = run::deadline_proof_budget(self.proving_cutoff(l)).map(|b| b.as_secs());
        let (plan, _) = self.prove_plan(&[po2]).await.for_job(
            dv.cycles,
            execute_secs,
            self.proving_timeout.as_secs(),
            |need| budget.is_none_or(|b| need <= b),
        );
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
        let pinned_at_unix = old_pin.as_ref().map_or_else(zkminer_chain::client::chain_now, |p| p.pinned_at_unix);
        let pinned = blocking(move || {
            let mut rec = s.pin_record(&new_ref, head)?;
            rec.reopen_count = reopen_count;
            rec.lock_block = lock_block;
            rec.pinned_at_unix = pinned_at_unix;
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
    /// window closes, as the inline fulfil is, and never past a pending verifier swap's `readyAt` for
    /// its proof system (a proof for the old verifier can then only be released): every attempt is
    /// budgeted by [`Self::proving_cutoff`], as the proof was.
    async fn fulfil(self: &Arc<Self>, l: &mut LockCtx, proved: Proved) -> Result<()> {
        use zkminer_chain::revert::{FulfilClass, FulfilFailure};
        let jid = l.job_id;
        let Proved { proof, slot: proved_on, on_quarantined } = proved;
        // A proof the router would refuse is the proving device's failure (the caller's guest's
        // unless that device was quarantined); a fulfil that cannot land in time is the chain's (gas,
        // RPC, blockspace).
        let proof_defect =
            Some(LockFailure { slot: proved_on.clone(), class: PostLockFailureClass::Gpu, caller: !on_quarantined });
        let chain = Some(LockFailure::chain());
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
        // A release because a verifier swap's readyAt comes first is governance's: no caller's.
        let swap_cut = Some(LockFailure::host(PostLockFailureClass::GasOrRpc));
        loop {
            run::refresh_lock_deadline(&self.client, &self.state, &self.journal, jid, &mut l.lock_deadline).await;
            let min = Duration::from_secs(run::MIN_ATTEMPT_BUDGET_SECS);
            let cutoff = self.proving_cutoff(l);
            let swap = cutoff < l.lock_deadline;
            let budget = match run::deadline_proof_budget(cutoff) {
                None => None,
                Some(b) if b < min && swap => {
                    clear_submitting("verifier swap pending — releasing").await;
                    l.failure = swap_cut.clone();
                    bail!(
                        "a verifier swap for witness lock {}'s proof system is ready in {} s: its proof can only be \
                         released then; releasing",
                        short(jid),
                        b.as_secs()
                    );
                }
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
                    self.client.settle_abandoned_nonce(jid).await;
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
            let cutoff = self.proving_cutoff(l);
            if cutoff < l.lock_deadline
                && run::deadline_proof_budget(cutoff).is_some_and(|b| b <= run::FULFIL_RETRY_WAIT + min)
            {
                clear_submitting("verifier swap pending — releasing").await;
                l.failure = swap_cut.clone();
                bail!("a verifier swap for witness lock {}'s proof system is ready before a retry could land; releasing", short(jid));
            }
            match run::deadline_proof_budget(l.lock_deadline) {
                Some(b) if b <= run::FULFIL_RETRY_WAIT + min => {
                    if run::refresh_lock_deadline(&self.client, &self.state, &self.journal, jid, &mut l.lock_deadline).await {
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

    /// Re-drives a witness lock of ours from its bundle (single flight). `false` when a task owns it,
    /// or once shutdown has begun (held locks are then the drain's: a lock re-driven during the drain
    /// would race its release). Until its bundle is found and pinned, eviction waits for it (§15.2).
    pub(crate) fn drive_recovered(self: &Arc<Self>, jid: B256) -> bool {
        if self.stopping() {
            return false;
        }
        {
            let mut t = lock(&self.tasks);
            if t.contains_key(&jid) {
                return false;
            }
            t.insert(jid, Task::new(AbortToken::new(), Phase::Locked));
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
            let pinned_at_unix = pin.as_ref().map_or_else(zkminer_chain::client::chain_now, |p| p.pinned_at_unix);
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
            if self.stopping() {
                return;
            }
            if !self.store_pass_running.swap(true, Ordering::SeqCst) {
                self.store_pass().await;
                self.store_pass_running.store(false, Ordering::SeqCst);
            }
            tokio::time::sleep(STORE_PASS_EVERY).await;
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
                let mut read = PinRead {
                    status: rec.status,
                    prover: rec.prover,
                    reopen_count: rec.reopen_count,
                    at_block: at,
                    at_timestamp: None,
                };
                // A claim never confirmed: the read counts only if its own block was mined late enough.
                if pin_read_needs_time(&facts, &read, us) {
                    read.at_timestamp = with_lane(Lane::HeldLock, self.client.block_timestamp(at)).await.ok();
                }
                if pin_lock_gone(&facts, &read, us, run::CLAIM_INTENT_MAX_AGE_SECS) {
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
        // Post-lock verdicts last until their job is terminal (an Open job never expires on chain, and
        // its bundle may be evicted long before): read each such job (bounded per pass, starting at a
        // random one so none waits forever) and drop its records with its bundles once it is.
        let s = store.clone();
        if let Ok(Ok(verdicts)) = blocking(move || s.verdicts()).await {
            let mut lasting: Vec<B256> = verdicts
                .iter()
                .filter(|v| lasts_until_terminal(v.reason, v.expires_at))
                .map(|v| v.job_id)
                .filter(|j| !owned.contains(j) && !pinned_jobs.contains(j))
                .collect();
            if !lasting.is_empty() {
                let start = rand::random::<u64>() as usize % lasting.len();
                lasting.rotate_left(start);
            }
            for jid in lasting {
                if reads >= STORE_PASS_MAX_READS {
                    break;
                }
                reads += 1;
                if let Ok((rec, at)) = with_lane(Lane::PreClaim, self.client.read_job_record(jid, None)).await {
                    if let Some(state) = terminal_state(&rec) {
                        self.delete_terminal(&store, jid, state, at).await;
                        lock(&self.verdict_until).remove(&jid);
                    }
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
        // scan"): this pass read every pin, a brain recovery pass with a complete chain scan has
        // handed over every witness lock it decided (the jobs it left undecided are spared in the
        // store), and each of those is pinned.
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
            let unavailable = rt.image_id_unavailable.load(Ordering::SeqCst) != before;
            elf_image_id_outcome(id, self.program_id, unavailable)?;
            *lock(&self.elf) = Some(elf.clone());
            Ok(elf)
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

/// The witness verdict for a collateral-cap refusal (`run::collateral`), `None` when admitted: a job
/// whose terms alone ask for more than one job may lock is over this host's limit (looked at again
/// when the host changes: a larger stake, another fraction); one over its program's or caller's share,
/// or the stake's, is not admitted now (deferred: the locks here settle soon). Neither is the
/// caller's doing.
fn cap_refusal(v: run::collateral::CapVerdict) -> Option<(SkipReason, String)> {
    let why = v.describe()?;
    Some((if v.is_final() { SkipReason::LimitsAboveHostMaxima } else { SkipReason::NotAdmitted }, why))
}


/// What one [`WitnessRuntime::self_test_round`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelfTestRound {
    /// The configuration file switched serving off.
    SwitchedOff,
    /// The miner did not start with serving enabled.
    NotEnabled,
    /// Serving had not started: the start was tried again.
    StartRetried,
    /// Serving had not started, and a start is running.
    Starting,
    Passed,
    Failed,
}

/// `[witness] enabled` as the configuration file at `path` says it now; an error when the file is gone
/// or does not parse (a missing file is not "the defaults": the kill switch never flips on a file
/// that is merely absent).
fn configured_witness_enabled(path: &Path) -> Result<bool> {
    if !path.is_file() {
        bail!("{} is not a file", path.display());
    }
    Ok(ZkMinerConfig::load(Some(path))?.witness.enabled)
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zkminer_witness_store::{ExpectedIdentity, StoreIdentityInit, StoreOptions};

    const TEST_CHAIN: u64 = 31_337;

    /// A JSON-RPC endpoint that answers `eth_chainId` (all a `ChainClient` reads to connect) and
    /// refuses everything else: these tests exercise the runtime's own bookkeeping, with no chain.
    async fn chainless_client() -> ChainClient {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    loop {
                        let mut chunk = [0u8; 4096];
                        let n = match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&chunk[..n]);
                        let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                        let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                        let len: usize = head
                            .split("content-length:")
                            .nth(1)
                            .and_then(|v| v.split("\r\n").next())
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        if buf.len() < end + 4 + len {
                            continue;
                        }
                        let req: serde_json::Value = serde_json::from_slice(&buf[end + 4..end + 4 + len]).unwrap();
                        let answer = |r: &serde_json::Value| match r["method"].as_str() {
                            Some("eth_chainId") => {
                                serde_json::json!({"jsonrpc": "2.0", "id": r["id"], "result": format!("{TEST_CHAIN:#x}")})
                            }
                            _ => serde_json::json!({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32601, "message": "no chain here"}}),
                        };
                        let resp = match &req {
                            serde_json::Value::Array(rs) => serde_json::Value::Array(rs.iter().map(answer).collect()),
                            r => answer(r),
                        };
                        let body = serde_json::to_vec(&resp).unwrap();
                        let hdr = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        );
                        if sock.write_all(hdr.as_bytes()).await.is_err() || sock.write_all(&body).await.is_err() {
                            return;
                        }
                        buf.drain(..end + 4 + len);
                    }
                });
            }
        });
        let mut c = ZkMinerConfig::default();
        c.chain.rpc_url = url;
        c.chain.chain_id = TEST_CHAIN;
        c.chain.max_requests_per_sec = Some(1000);
        c.contracts.hemi_prove = format!("{:#x}", Address::repeat_byte(0x11));
        c.contracts.hemi_prove_registry = format!("{:#x}", Address::repeat_byte(0x12));
        c.contracts.hemi_prove_staking = format!("{:#x}", Address::repeat_byte(0x13));
        c.contracts.hemi_token = format!("{:#x}", Address::repeat_byte(0x14));
        ChainClient::new_watch_only(&c, Address::repeat_byte(0x77)).await.unwrap()
    }

    /// A retention store in a fresh directory, removed when dropped.
    struct TestStore {
        dir: PathBuf,
        store: Arc<Store>,
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn test_store(client: &ChainClient) -> TestStore {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir()
            .join(format!("zkminer-witness-rt-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let (chain_id, router, prover) = (client.chain_id, client.hemi_prove, client.address);
        let id = Store::init(
            &dir,
            &StoreIdentityInit { chain_id, router, prover, require_dedicated_mount: false, allow_any_filesystem: true },
        )
        .unwrap();
        let store = Store::open(
            &dir,
            &ExpectedIdentity { chain_id, router, prover, store_uuid: id.store_uuid },
            StoreOptions {
                quota_bytes: 1 << 30,
                quota_inodes: 100_000,
                free_space_floor_bytes: 0,
                require_dedicated_mount: false,
                allow_any_filesystem: true,
            },
        )
        .unwrap();
        TestStore { dir, store: Arc::new(store) }
    }

    /// A runtime as `start` builds it (no serving, no tasks), with `store` open.
    /// The collateral cap's refusals as witness verdicts: a job over the cap by its own terms is over
    /// this host's limit, one over its program's or caller's share is deferred; neither is the
    /// caller's.
    #[test]
    fn a_collateral_cap_refusal_is_the_hosts_limit_or_deferred() {
        use run::collateral::CapVerdict;
        assert_eq!(cap_refusal(CapVerdict::Admit), None);
        let (reason, why) = cap_refusal(CapVerdict::OverJob { required: 600, cap: 500 }).unwrap();
        assert_eq!(reason, SkipReason::LimitsAboveHostMaxima);
        assert!(why.contains("one job may lock"), "{why}");
        for v in [
            CapVerdict::OverProgram { held: 400, required: 200, cap: 500 },
            CapVerdict::OverSubmitter { held: 400, required: 200, cap: 500 },
        ] {
            assert_eq!(cap_refusal(v).unwrap().0, SkipReason::NotAdmitted);
        }
        for (r, _) in [CapVerdict::OverJob { required: 2, cap: 1 }, CapVerdict::OverProgram { held: 1, required: 1, cap: 1 }]
            .into_iter()
            .filter_map(cap_refusal)
        {
            assert!(!r.verdict().blames_caller);
        }
    }

    async fn test_runtime(store: bool) -> (Arc<WitnessRuntime>, Option<TestStore>) {
        let client = chainless_client().await;
        let gov = GovernanceWatcher::new(client.clone(), GovernanceConfig::new(client.address, vec![])).view();
        let rt = WitnessRuntime::new(
            &client,
            &zkminer_tui::state::new_shared_state(),
            &Arc::new(Mutex::new(Default::default())),
            &ZkMinerConfig::default(),
            PathBuf::new(),
            gov,
            BacklogSource::Fixed(BacklogReading::fixed(Backlog::Known(0), Some(0))),
            DaCapPolicy::default(),
            Duration::from_secs(600),
            DEFAULT_KECCAK_PO2,
        );
        let ts = store.then(|| test_store(&client));
        *lock(&rt.store) = ts.as_ref().map(|t| t.store.clone());
        (Arc::new(rt), ts)
    }

    fn gpu_failure(slot: &str) -> LockFailure {
        LockFailure::on(Some(slot.into()), PostLockFailureClass::Gpu, &HashSet::new())
    }

    /// The brain's room rule released a witness lock it found too close to its deadline, with no
    /// verdict: the job reopened, and after a restart it could be locked again. And a store pass that
    /// re-drove the lock just as the brain spawned that release could not see it. The release now
    /// takes the job in the runtime first (a store pass then leaves it alone, and one that took it
    /// first wins), and records the job's verdict before the release is sent.
    #[tokio::test]
    async fn a_room_rule_release_owns_the_lock_and_records_a_verdict() {
        let (rt, s) = test_runtime(true).await;
        let jid = B256::repeat_byte(0x51);
        note_class(jid, Class::Witness);
        let ReleaseClaim::Witness(release) = rt.claim_release(jid) else { panic!("a witness lock") };
        assert!(rt.owns(jid));
        assert!(!rt.drive_recovered(jid), "the store pass cannot re-drive it meanwhile");
        assert!(matches!(rt.claim_release(jid), ReleaseClaim::Owned), "nor a second release");
        assert_eq!(rt.witness_locks(), 0, "a release holds no card");
        release.record_verdict("released by the recovery room rule").await;
        let v = s.as_ref().unwrap().store.verdict(jid).unwrap().unwrap();
        assert_eq!((v.reason, v.expires_at), (SkipReason::PostLockFailure, VERDICT_UNTIL_TERMINAL));
        assert_eq!(rt.caller_post_lock_failures_now(Address::ZERO).await, 0, "no caller is counted");
        drop(release);
        assert!(!rt.owns(jid));
        // The other way round: a store pass that took the lock first keeps it, and no release goes.
        let other = B256::repeat_byte(0x52);
        note_class(other, Class::Witness);
        lock(&rt.tasks).insert(other, task(Phase::Locked));
        assert!(matches!(rt.claim_release(other), ReleaseClaim::Owned));
        // An inline lock is not the runtime's.
        assert!(matches!(rt.claim_release(B256::repeat_byte(0x53)), ReleaseClaim::NotWitness));
        // A shutdown release records it too, once.
        let third = B256::repeat_byte(0x54);
        note_class(third, Class::Witness);
        rt.note_release(third, "released at shutdown").await;
        rt.note_release(third, "released at shutdown").await;
        assert_eq!(s.as_ref().unwrap().store.verdict(third).unwrap().unwrap().attempts, 1);
    }

    /// A brain pass that stayed deferred over one unreadable job (or a claim that might still be
    /// pending) never enabled eviction, so the store filled. A pass whose chain scan was complete now
    /// enables it, sparing only the bundles of the jobs it left undecided; a pass whose scan failed
    /// still does not (a lock of ours could be anywhere).
    #[tokio::test]
    async fn an_undecided_job_no_longer_holds_eviction_back() {
        let (rt, _s) = test_runtime(true).await;
        rt.note_recovery_pass(false, vec![]);
        assert!(!rt.brain_recovered.load(Ordering::SeqCst), "a failed chain scan hands over nothing");
        let undecided = B256::repeat_byte(0x81);
        rt.note_recovery_pass(true, vec![undecided]);
        assert!(rt.brain_recovered.load(Ordering::SeqCst));
        assert!(lock(&rt.undecided).contains(&undecided));
        rt.note_recovery_pass(true, vec![]);
        assert!(lock(&rt.undecided).is_empty(), "decided by a later pass");
    }

    /// `[witness] enabled = false` was read only at startup, although §20.4 calls it a hot kill
    /// switch. The configuration file is read again: `false` switches serving off at once (running
    /// simulations aborted) and keeps it off through the self-tests; `true` again resumes; a file that
    /// is gone changes nothing.
    #[tokio::test]
    async fn the_kill_switch_is_hot() {
        let (rt, _s) = test_runtime(false).await;
        *lock(&rt.serve) = Some(Arc::new(ZkMinerConfig::default()));
        rt.enabled.store(true, Ordering::SeqCst);
        let sim = AbortToken::new();
        lock(&rt.tasks).insert(B256::repeat_byte(0x91), Task::new(sim.clone(), Phase::Simulating));
        let held = AbortToken::new();
        lock(&rt.tasks).insert(B256::repeat_byte(0x92), Task::new(held.clone(), Phase::Locked));

        let dir = std::env::temp_dir().join(format!("zkminer-killswitch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "[witness]\nenabled = false\n").unwrap();
        assert!(!configured_witness_enabled(&path).unwrap());
        rt.apply_enabled(configured_witness_enabled(&path).unwrap());
        assert!(!rt.enabled.load(Ordering::SeqCst), "switched off at once");
        assert!(sim.is_aborted(), "a running simulation is aborted");
        assert!(!held.is_aborted(), "a held lock continues");
        assert_eq!(rt.self_test_round().await, SelfTestRound::SwitchedOff, "the self-tests do not switch it back on");
        assert!(!rt.try_start_serving().await, "nor does a start");
        std::fs::write(&path, "[witness]\nenabled = true\n").unwrap();
        rt.apply_enabled(configured_witness_enabled(&path).unwrap());
        assert!(!rt.switched_off.load(Ordering::SeqCst));
        std::fs::remove_file(&path).unwrap();
        assert!(configured_witness_enabled(&path).is_err(), "a missing file is not the defaults");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A serving start whose self-test timed out left serving off until a restart: the hourly loop
    /// skipped while nothing was serving. It now tries the start again.
    #[tokio::test]
    async fn the_hourly_round_retries_a_failed_start() {
        let (rt, _s) = test_runtime(false).await;
        assert_eq!(rt.self_test_round().await, SelfTestRound::NotEnabled);
        // A start that fails at once (this configuration does not validate): tried again each round.
        *lock(&rt.serve) = Some(Arc::new(ZkMinerConfig::default()));
        assert_eq!(rt.self_test_round().await, SelfTestRound::StartRetried);
        assert!(!rt.enabled.load(Ordering::SeqCst));
        assert_eq!(rt.self_test_round().await, SelfTestRound::StartRetried, "and again");
        rt.starting.store(true, Ordering::SeqCst);
        assert_eq!(rt.self_test_round().await, SelfTestRound::Starting, "never two starts at once");
    }

    /// A sandbox self-test that did not finish held the one spawner thread, so every later builder,
    /// execute and broker start queued behind it. It runs on a thread of its own, and while one that
    /// did not finish still runs, the next fails at once.
    #[tokio::test]
    async fn a_stuck_sandbox_self_test_holds_nothing_else() {
        let (rt, _s) = test_runtime(false).await;
        rt.sandbox_test_running.store(true, Ordering::SeqCst);
        let r = tokio::time::timeout(Duration::from_secs(5), rt.sandbox_self_test(Path::new("/nonexistent"))).await;
        assert_eq!(r.expect("returns at once"), Err("the previous sandbox self-test has not finished".to_string()));
        rt.sandbox_test_running.store(false, Ordering::SeqCst);
        // A probe that does not exist fails the test on its own thread, and frees it.
        let r = rt.sandbox_self_test(Path::new("/nonexistent/zkminer-witness-sandbox-probe")).await;
        assert!(r.is_err());
        assert!(!rt.sandbox_test_running.load(Ordering::SeqCst));
    }

    /// A store pass running as shutdown began re-drove held locks beside the drain's releases. Once
    /// shutdown has begun nothing re-drives a lock.
    #[tokio::test]
    async fn nothing_re_drives_a_lock_once_shutdown_began() {
        let (rt, _s) = test_runtime(false).await;
        rt.shutdown();
        assert!(!rt.drive_recovered(B256::repeat_byte(0x61)));
        assert!(rt.owned_jobs().is_empty());
    }

    /// One caller whose guest reliably fails during proving quarantined a one-card host for 7 days
    /// with two failures, and with it every other caller's witness jobs. A device is now quarantined
    /// by failures of a class from two distinct callers.
    #[tokio::test]
    async fn one_callers_failures_never_quarantine_a_device() {
        let (rt, _s) = test_runtime(true).await;
        let (a, b) = (Address::repeat_byte(0xa1), Address::repeat_byte(0xb1));
        let slots = vec!["gpu0".to_string()];
        for j in 1..=3u8 {
            rt.record_post_lock_failure(B256::repeat_byte(j), a, &gpu_failure("gpu0")).await;
        }
        assert!(rt.quarantined(&slots).await.is_empty(), "one caller alone");
        assert_eq!(rt.caller_post_lock_failures_now(a).await, 3, "the caller's own tally counts every one");
        rt.record_post_lock_failure(B256::repeat_byte(9), b, &gpu_failure("gpu0")).await;
        assert_eq!(rt.quarantined(&slots).await, slots.iter().cloned().collect(), "a second caller");
        assert!(rt.quarantined(&["gpu1".to_string()]).await.is_empty(), "another device");
    }

    /// A failure no attempt of the caller's guest caused (no card proved the lock, the window had no
    /// room, a quarantined device, a verifier swap) is not counted against the caller.
    #[tokio::test]
    async fn failures_the_caller_did_not_cause_are_not_its_strikes() {
        let (rt, _s) = test_runtime(true).await;
        let c = Address::repeat_byte(0xc1);
        rt.record_post_lock_failure(B256::repeat_byte(1), c, &LockFailure::host(PostLockFailureClass::ProveTimeEstimate))
            .await;
        let quarantined: HashSet<String> = ["gpu0".to_string()].into();
        let on_quarantined = LockFailure::on(Some("gpu0".into()), PostLockFailureClass::Gpu, &quarantined);
        assert!(!on_quarantined.caller);
        rt.record_post_lock_failure(B256::repeat_byte(2), c, &on_quarantined).await;
        assert_eq!(rt.caller_post_lock_failures_now(c).await, 0);
        // Each job still gets its final verdict.
        let store = rt.store().unwrap();
        for j in [1u8, 2] {
            let v = store.verdict(B256::repeat_byte(j)).unwrap().unwrap();
            assert_eq!((v.reason, v.expires_at), (SkipReason::PostLockFailure, VERDICT_UNTIL_TERMINAL));
        }
        rt.record_post_lock_failure(B256::repeat_byte(3), c, &gpu_failure("gpu1")).await;
        assert_eq!(rt.caller_post_lock_failures_now(c).await, 1);
    }

    /// The job's post-lock verdict lasted 8 days, and an Open job can be locked long after: it now
    /// lasts until the job is terminal, across restarts (it is in the store).
    #[tokio::test]
    async fn a_post_lock_verdict_holds_until_the_job_is_terminal() {
        let (rt, s) = test_runtime(true).await;
        let jid = B256::repeat_byte(0x42);
        rt.record_post_lock_failure(jid, Address::repeat_byte(1), &gpu_failure("gpu0")).await;
        let store = s.as_ref().unwrap().store.clone();
        assert_eq!(store.verdict(jid).unwrap().unwrap().expires_at, VERDICT_UNTIL_TERMINAL);
        lock(&rt.verdict_until).clear();
        assert!(rt.verdict_holds(&store, jid).await, "read back from the store, as after a restart");
        assert_eq!(
            verdict_set_aside(*lock(&rt.verdict_until).get(&jid).unwrap(), now_unix()),
            super::super::policy::MAX_SET_ASIDE
        );
    }

    /// The caller tally read for routing was remembered for 7 days from the read, whatever its own
    /// expiry: a caller stayed refused up to 7 days longer than its tally. It is now remembered until
    /// the tally's own expiry.
    #[tokio::test]
    async fn a_caller_tally_is_remembered_until_its_own_expiry() {
        let (rt, s) = test_runtime(true).await;
        let c = Address::repeat_byte(0xc2);
        let store = s.as_ref().unwrap().store.clone();
        let expires_at = now_unix() + 100;
        store
            .put_verdict(&VerdictRecord {
                job_id: caller_tally_key(c),
                reason: SkipReason::PostLockFailure,
                attempts: POST_LOCK_CALLER_LIMIT,
                recorded_at: now_unix(),
                expires_at,
                wasmtime_version: None,
            })
            .unwrap();
        assert_eq!(rt.caller_post_lock_failures_now(c).await, POST_LOCK_CALLER_LIMIT);
        assert_eq!(lock(&rt.post_lock_callers).get(&c).copied(), Some((POST_LOCK_CALLER_LIMIT, expires_at)));
        // Once that expiry passes, routing admits the caller again.
        lock(&rt.post_lock_callers).insert(c, (POST_LOCK_CALLER_LIMIT, now_unix()));
        assert_eq!(rt.caller_post_lock_failures(c), Some(0));
    }

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
        Task::new(AbortToken::new(), phase)
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
        assert!(take_card(&mut tasks, one_card, &[], a, &[]));
        assert_eq!(tasks[&a].phase, Phase::Claiming);
        assert!(!take_card(&mut tasks, one_card, &[], b, &[]), "the card is taken");
        assert!(take_card(&mut tasks, one_card, &[], a, &[]), "the claim's second check keeps its own card");
        give_back_card(&mut tasks, a);
        assert_eq!(tasks[&a].phase, Phase::Simulating);
        assert!(take_card(&mut tasks, one_card, &[], b, &[]), "given back: the other claims");
        tasks.get_mut(&b).unwrap().phase = Phase::Locked;
        give_back_card(&mut tasks, b);
        assert_eq!(tasks[&b].phase, Phase::Locked, "a held lock keeps its card");
        assert!(!take_card(&mut tasks, one_card, &[], a, &[]));
        tasks.remove(&b);
        assert!(take_card(&mut tasks, one_card, &[], a, &[]), "the lock ended");
        // Inline work needing a card, and no word from the brain yet.
        assert!(!take_card(&mut tasks, Some((1, 2)), &[], b, &[]), "no task for it");
        tasks.insert(b, task(Phase::Simulating));
        assert!(!take_card(&mut tasks, Some((1, 2)), &[], b, &[]), "a's claim and one inline job fill two cards");
        assert!(!take_card(&mut tasks, None, &[], b, &[]));
    }

    /// A job that fits only some cards claims only while one of them is free: not proving an inline
    /// job, and not booked by another witness claim. The count alone would let it claim.
    #[test]
    fn a_claim_needs_a_free_card_it_fits() {
        let (a, b) = (B256::repeat_byte(0xa), B256::repeat_byte(0xb));
        let two_cards = Some((0, 2));
        let (fast, slow) = ("gpu0".to_string(), "gpu1".to_string());
        let mut tasks: HashMap<B256, Task> = [(a, task(Phase::Simulating)), (b, task(Phase::Simulating))].into();
        // The 5090 proves an inline job: a job fitting only it waits, though a card is free by count.
        assert!(!take_card(&mut tasks, two_cards, std::slice::from_ref(&fast), a, std::slice::from_ref(&fast)));
        assert_eq!(tasks[&a].phase, Phase::Simulating);
        // One that fits both books the free 4070.
        assert!(take_card(&mut tasks, two_cards, std::slice::from_ref(&fast), a, &[fast.clone(), slow.clone()]));
        assert_eq!(tasks[&a].card.as_deref(), Some("gpu1"));
        // The 4070 booked: the next job fitting only it waits; the 5090 once free takes the other.
        assert!(!take_card(&mut tasks, two_cards, &[], b, std::slice::from_ref(&slow)));
        assert!(take_card(&mut tasks, two_cards, &[], b, &[fast.clone(), slow.clone()]));
        assert_eq!(tasks[&b].card.as_deref(), Some("gpu0"));
        // Given back, the booking goes with it.
        give_back_card(&mut tasks, a);
        assert_eq!(tasks[&a].card, None);
        assert!(take_card(&mut tasks, two_cards, &[], a, std::slice::from_ref(&slow)));
        // A job that fits any card (none named) goes by the count alone.
        tasks.insert(B256::repeat_byte(0xc), task(Phase::Simulating));
        assert!(!take_card(&mut tasks, two_cards, &[], B256::repeat_byte(0xc), &[]), "two cards, two held");
        assert!(take_card(&mut tasks, Some((0, 3)), &[], B256::repeat_byte(0xc), &[]));
        assert_eq!(tasks[&B256::repeat_byte(0xc)].card, None);
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
                    take_card(&mut lock(&tasks), Some((0, 1)), &[], j, &[])
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
