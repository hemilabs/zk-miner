//! Shared miner state accessible from both the TUI and background tasks.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use zkminer_chain::jobs::JobInfo;
use zkminer_chain::staking::{ProverStatistics, StakeInfo};
use zkminer_prover::benchmark::BenchmarkSuite;
use zkminer_prover::dispatcher::{BenchmarkProgressEvent, BenchmarkProgressKind};
use zkminer_prover::engine::BackendSource;

use crate::gpu_tuning::GpuTuningState;
use crate::hardware::{CpuStatSnapshot, HardwareInfo};

/// Which screen is currently active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Setup,
    Dashboard,
    Jobs,
    JobDetail,
    Wallet,
    Benchmark,
    Logs,
    Settings,
}

impl Screen {
    pub fn from_key(c: char) -> Option<Self> {
        match c {
            '1' => Some(Self::Dashboard),
            '2' => Some(Self::Jobs),
            '3' => Some(Self::JobDetail),
            '4' => Some(Self::Wallet),
            '5' => Some(Self::Benchmark),
            '6' => Some(Self::Logs),
            '7' => Some(Self::Settings),
            _ => None,
        }
    }

    pub fn title(&self) -> &str {
        match self {
            Self::Setup => "Setup",
            Self::Dashboard => "Dashboard",
            Self::Jobs => "Jobs",
            Self::JobDetail => "Job Detail",
            Self::Wallet => "Wallet",
            Self::Benchmark => "Benchmark",
            Self::Logs => "Logs",
            Self::Settings => "Settings",
        }
    }

    /// All screens shown in the tab bar (Setup is excluded — it's a special overlay).
    pub fn all() -> &'static [Screen] {
        &[
            Screen::Dashboard,
            Screen::Jobs,
            Screen::JobDetail,
            Screen::Wallet,
            Screen::Benchmark,
            Screen::Logs,
            Screen::Settings,
        ]
    }
}

// ---------------------------------------------------------------------------
// Setup / readiness tracking
// ---------------------------------------------------------------------------

/// Minimum HEMI stake required to prove (in wei). 100 HEMI.
pub const MIN_STAKE_WEI: u128 = 100 * 1_000_000_000_000_000_000;
/// Minimum staking age in seconds before the prover is eligible.
/// Mirrors `Constants.MIN_STAKING_AGE` in HemiProve Solidity (1 hour).
pub const MIN_STAKING_AGE_SECS: u64 = zkminer_chain::auction::MIN_STAKING_AGE;
/// Hemi Testnet chain ID. Re-exported from `zkminer_chain::staking` to keep one source of truth.
pub use zkminer_chain::staking::TESTNET_CHAIN_ID;
/// Default testnet mint amount: 1000 tHEMI (in wei).
pub const TESTNET_MINT_AMOUNT: u128 = 1_000 * 1_000_000_000_000_000_000;

/// Tracks what the miner still needs before it can accept jobs.
#[derive(Debug, Clone, Default)]
pub struct SetupStatus {
    /// Whether all checks have been performed at least once.
    pub checked: bool,
    /// The wallet has some ETH for gas.
    pub has_gas: bool,
    /// The wallet has HEMI tokens (balance > 0).
    pub has_hemi: bool,
    /// The wallet has an active stake >= MIN_STAKE_WEI.
    pub has_stake: bool,
    /// The stake is old enough to be eligible (>= MIN_STAKING_AGE_SECS).
    pub stake_mature: bool,
    /// The chain is a testnet with public mint capability.
    pub is_testnet: bool,
    /// Seconds remaining until stake is mature (0 if already mature or no stake).
    pub staking_age_remaining: u64,
    /// On-chain staking maturity in seconds for this deployment. 0 = unset, use
    /// the built-in default. Set from `chain.min_staking_age_secs` config so the
    /// countdown matches the deployment (the value is a Solidity compile-time
    /// constant with no on-chain getter, so it can't be read from the contract).
    pub min_staking_age_secs: u64,
    /// Whether the user has dismissed the setup wizard (skip to dashboard).
    pub dismissed: bool,
    /// In-progress operation description, if any.
    pub pending_action: Option<String>,
    /// Last error from a setup action.
    pub last_error: Option<String>,
    /// Currently highlighted step in the wizard (0-indexed).
    pub selected_step: usize,
    /// `s` was pressed once: the next `s` stakes (any other key disarms it).
    pub stake_armed: bool,
}

impl SetupStatus {
    /// Returns true if the miner is fully ready to prove.
    pub fn is_ready(&self) -> bool {
        self.has_gas && self.has_hemi && self.has_stake && self.stake_mature
    }

    /// Returns a short summary of what's blocking readiness.
    pub fn blocking_reason(&self) -> Option<String> {
        if !self.checked {
            return Some("Checking wallet status...".to_string());
        }
        if !self.has_gas {
            return Some("No ETH for gas fees".to_string());
        }
        if !self.has_hemi {
            return Some("No HEMI tokens".to_string());
        }
        if !self.has_stake {
            return Some("Stake below 100 HEMI minimum".to_string());
        }
        None
    }

    /// Update from current MinerState balances and stake info.
    pub fn refresh(&mut self, state: &MinerState) {
        self.refresh_from_balances(
            state.eth_balance,
            state.hemi_balance,
            state.stake_info.as_ref(),
        );
    }

    /// Update from individual balance/stake values (avoids borrow issues when
    /// the caller already holds a mutable reference to MinerState).
    pub fn refresh_from_balances(
        &mut self,
        eth_balance: u128,
        hemi_balance: u128,
        stake_info: Option<&StakeInfo>,
    ) {
        self.has_gas = eth_balance > 0;
        self.has_hemi = hemi_balance > 0;

        // The 1h MIN_STAKING_AGE claim gate was removed on-chain; a stake is
        // claimable from the next block after it lands (block.number > depositBlock),
        // which is always satisfied by the time we evaluate jobs. So maturity simply
        // tracks "has an active stake". `deposit_block` is a block number (not a
        // wall-clock timestamp), so no age countdown is computed.
        if let Some(stake) = stake_info {
            self.has_stake = stake.total_staked >= MIN_STAKE_WEI;
            self.stake_mature = self.has_stake;
        } else {
            self.has_stake = false;
            self.stake_mature = false;
        }
        self.staking_age_remaining = 0;

        self.checked = true;
    }
}

// ---------------------------------------------------------------------------
// Settings state
// ---------------------------------------------------------------------------

/// Which section of the settings screen is active.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SettingsSection {
    #[default]
    Devices,
    Backends,
    DeviceGrid,
    Parameters,
    Advanced,
    GpuTuning,
}

impl SettingsSection {
    pub fn next(self) -> Self {
        match self {
            Self::Devices => Self::Backends,
            Self::Backends => Self::DeviceGrid,
            Self::DeviceGrid => Self::Parameters,
            Self::Parameters => Self::Advanced,
            Self::Advanced => Self::GpuTuning,
            Self::GpuTuning => Self::Devices,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Devices => Self::GpuTuning,
            Self::Backends => Self::Devices,
            Self::DeviceGrid => Self::Backends,
            Self::Parameters => Self::DeviceGrid,
            Self::Advanced => Self::Parameters,
            Self::GpuTuning => Self::Advanced,
        }
    }
}

/// Runtime-tunable settings (seeded from ProverConfig defaults).
#[derive(Debug, Clone)]
pub struct RuntimeSettings {
    /// Disabled device identifiers: "cpu", "gpu0", etc.
    pub disabled_devices: HashSet<String>,
    /// Disabled backend identifiers: "risc0", "sp1", "openvm".
    pub disabled_backends: HashSet<String>,
    /// Per-(device, backend) overrides — disabled combos.
    pub disabled_device_backends: HashSet<(String, String)>,
    /// Whether advanced mode (po2 overrides) is enabled. The overrides apply only while it is.
    pub advanced_mode: bool,
    /// Per-(device, backend) po2 overrides, for this session.
    pub po2_overrides: HashMap<(String, String), u8>,
    /// Each card's risc0 job size from the config (`prover.risc0_job_po2`), by benchmark device id;
    /// a session override wins over it.
    pub risc0_job_po2_config: HashMap<String, u8>,
    // Tunables
    pub max_concurrent_proofs: usize,
    /// Seconds of work to keep queued ahead per GPU. 0 = look-ahead off (one job per GPU).
    pub queue_horizon_secs: u64,
    pub min_profit_threshold: f64,
    pub strategy: String,
    pub electricity_cost_kwh: f64,
    pub system_power_watts: f64,
    pub deadline_safety_margin: f64,
    pub token_price_usd: f64,
    pub gas_cost_usd: f64,
    /// The cap on one proof attempt, in seconds: a job whose attempt would take longer on the
    /// slowest card it could go to is not claimed. Read by the miner every pass; an attempt keeps
    /// the cap it started with.
    pub proving_timeout_secs: u64,
    /// Whether to claim journal-bound jobs (a non-zero `expectedJournalHash`). Each is claimed only
    /// when the journal its (program, input) measured satisfies its binding. Default TRUE; `false`
    /// claims only NONE jobs assigned to this prover.
    pub claim_predicate_jobs: bool,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            disabled_devices: HashSet::new(),
            disabled_backends: HashSet::new(),
            disabled_device_backends: HashSet::new(),
            advanced_mode: false,
            po2_overrides: HashMap::new(),
            risc0_job_po2_config: HashMap::new(),
            max_concurrent_proofs: 1,
            queue_horizon_secs: 0, // look-ahead off by default: one job per GPU
            min_profit_threshold: 10.0,
            strategy: "auto".to_string(),
            electricity_cost_kwh: 0.12,
            system_power_watts: 75.0,
            deadline_safety_margin: 1.5,
            token_price_usd: 0.80,
            gas_cost_usd: 0.01,
            proving_timeout_secs: 3600,
            claim_predicate_jobs: true,
        }
    }
}

/// UI cursor state for the settings screen.
#[derive(Debug, Clone, Default)]
pub struct SettingsUiState {
    pub active_section: SettingsSection,
    pub row_index: usize,
    /// Column index within the DeviceGrid section (selects backend).
    pub col_index: usize,
    /// Which GPU is selected in the GPU Tuning section (0 = first GPU).
    pub tuning_gpu_index: usize,
    /// Which control row within the selected GPU's tuning controls.
    pub tuning_row_index: usize,
    /// Which button is focused on the button row (0 = Apply, 1 = Reset).
    pub tuning_button_idx: usize,
}

/// Activity log entry.
#[derive(Debug, Clone)]
pub struct ActivityEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Success,
}

/// Job status in the miner context.
#[derive(Debug, Clone)]
pub enum MinerJobStatus {
    /// Job is open and being evaluated.
    Open,
    /// Claimed and holding collateral, but not yet started — waiting for a GPU.
    ///
    /// Distinct from `Proving` on purpose. Look-ahead queueing claims work BEFORE a device is
    /// free, so without this a queued job displayed as "Proving 0%" and the operator could not
    /// tell which jobs were actually on a card. `queued_behind` is how much work the planner
    /// expects to finish ahead of it.
    /// No payload: the admission that planned this job lives in the brain loop, while the
    /// status is set inside the per-job lifecycle task, and threading the placement through
    /// would couple the two for a cosmetic detail. The distinction that matters to an operator
    /// — is this job on a card, or waiting for one — needs no payload.
    Queued,
    /// We are actively proving this job.
    Proving { progress: f64, elapsed_secs: u64 },
    /// Proof is complete, submitting on-chain.
    Submitting,
    /// Job fulfilled successfully.
    Fulfilled { payout: u128 },
    /// Job was released.
    Released { penalty: u128 },
    /// The lock ran past its deadline and this miner slashed it itself (`by_us`; the keeper share
    /// comes back to it). Its collateral is lost.
    Slashed { by_us: bool },
    /// The lock was found gone after its deadline: a keeper's slash, or a release of ours that
    /// landed late; the job's state does not tell which.
    EndedPastDeadline,
    /// Job evaluation resulted in skip.
    Skipped { reason: String },
}

/// What a job this miner is claiming or holding is waiting on right now, when its status alone
/// would say something older: a claim or fulfil transaction the testnet has not confirmed yet (and
/// its retries), a wait for host or GPU memory, a retry after a failed attempt. Shown in place of
/// "queued, waiting for a GPU" or "submitting" while set, with how long it has been so.
#[derive(Debug, Clone)]
pub struct JobNote {
    pub kind: JobNoteKind,
    pub text: String,
    /// When this kind of wait began (a new text of the same kind keeps it).
    pub since: std::time::Instant,
}

/// Which stage a `JobNote` belongs to. A transaction's events update only a note of its own stage,
/// so one that arrives after the stage has moved on changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobNoteKind {
    /// The claim transaction.
    Claim,
    /// Between proving attempts: memory, a retry.
    Wait,
    /// The fulfil transaction.
    Submit,
    /// The release transaction.
    Release,
}

/// A job's measured cycle count: what the miner executed the guest at and sized the job on.
#[derive(Debug, Clone, PartialEq)]
pub struct JobMeasurement {
    /// The count the job is sized on: for risc0 the most across the sizes it was run at. `None`: it
    /// was executed and could not be measured (over the execute cycle cap, out of time, or a
    /// different journal at each size), so it is never claimed.
    pub cycles: Option<u64>,
    /// "risc0" or "sp1".
    pub backend: String,
    /// risc0: the segment sizes (po2) it was executed at; empty for SP1.
    pub po2s: Vec<u8>,
    /// How long the measuring execution took, in seconds.
    pub execute_secs: f64,
}

/// A job tracked by the miner.
#[derive(Debug, Clone)]
pub struct TrackedJob {
    pub info: JobInfo,
    pub status: MinerJobStatus,
    pub current_price: u128,
    /// Which GPU index is proving this job (None if CPU-only or not yet assigned).
    /// PCI bus id of the card proving this job, set when proving starts.
    ///
    /// Was `gpu_index: Option<u32>`, which was never assigned outside mock and
    /// so matched no GPU row in production: every card rendered "Idle" while it
    /// proved, and every CUDA proof was labelled "CPU". Keying on the bus id also
    /// avoids the trap in the obvious fix -- mock derived the old index by parsing
    /// "gpuN" (the prover's namespace) and compared it against `GpuInfo.index`
    /// (a display ordinal), which would have put the 5090's job on the AMD row.
    pub gpu_bus_id: Option<String>,
    /// Proving backend: "risc0", "sp1", "openvm", or "simulated".
    pub prover_backend: String,
    /// Estimated cycle count for the proof.
    pub estimated_cycles: u64,
}

/// Status of a prover backend worker.
#[derive(Debug, Clone)]
pub struct WorkerStatus {
    pub backend: String,
    pub source: BackendSource,
    pub healthy: bool,
    pub pid: Option<u32>,
    pub version: Option<String>,
}

/// A collateral verdict as computed by the brain. Mirrors `zkminer_chain::staking::Headroom`
/// plus the price it was computed against, which the dashboard needs to explain the number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadroomView {
    pub fundable: usize,
    pub wanted: usize,
    /// Collateral a single claim locks, at the price that actually blocked a job.
    pub per_claim: u128,
    /// Extra wei needed to fund one more slot. Meaningful only when `fundable < wanted`.
    pub shortfall: u128,
}

impl HeadroomView {
    pub fn is_starved(&self) -> bool {
        self.fundable < self.wanted
    }
}

/// What the brain's most recent pass did with the open work: claimed some, held every claim for one
/// reason, or looked at each job and declined it for its own. Published by the brain each pass so
/// the operator can see why a miner with open jobs is not claiming them without reading debug logs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimOutlook {
    /// The pass stopped before looking at any job (paused, benchmark running, RPC rate-limited, no
    /// ETH for gas...): why. `None` when jobs were evaluated.
    pub held: Option<String>,
    /// Jobs looked at and not claimed, by reason, most common first.
    pub declined: Vec<(String, usize)>,
    /// Jobs this pass claimed.
    pub claimed: usize,
    /// Open jobs this pass did not reach (already set aside, backing off, or past the claim limit).
    pub not_evaluated: usize,
}

impl ClaimOutlook {
    /// How many reasons the one-line summary names before folding the rest into "N other".
    const SHOWN_REASONS: usize = 4;

    /// What the summary says, without its counts (which move every pass): the headless log repeats
    /// the line when this changes.
    pub fn summary_key(&self) -> String {
        match &self.held {
            Some(why) => format!("held:{}", why.replace(|c: char| c.is_ascii_digit(), "")),
            None => {
                // Sorted: two reasons swapping rank as counts move is not news.
                let mut reasons: Vec<&str> =
                    self.declined.iter().map(|(w, _)| w.as_str()).collect();
                reasons.sort_unstable();
                format!(
                    "claiming:{} declined:{}",
                    self.claimed > 0,
                    reasons.join("|")
                )
            }
        }
    }

    /// One line for the dashboard and the headless log, e.g. "2 claiming · 6 below the profit
    /// threshold, 3 measuring cycles".
    pub fn summary(&self) -> String {
        if let Some(why) = &self.held {
            return format!("not claiming: {why}");
        }
        let mut parts = Vec::new();
        if self.claimed > 0 {
            // Handed to the claim path this pass; it can still drop or refuse them.
            parts.push(format!("{} claiming", self.claimed));
        }
        let mut reasons: Vec<String> = self
            .declined
            .iter()
            .take(Self::SHOWN_REASONS)
            .map(|(why, n)| format!("{n} {why}"))
            .collect();
        let rest: usize = self
            .declined
            .iter()
            .skip(Self::SHOWN_REASONS)
            .map(|(_, n)| n)
            .sum();
        if rest > 0 {
            reasons.push(format!("{rest} other"));
        }
        if !reasons.is_empty() {
            parts.push(format!("not claimed: {}", reasons.join(", ")));
        }
        if self.not_evaluated > 0 {
            parts.push(format!("{} not re-checked this pass", self.not_evaluated));
        }
        if parts.is_empty() {
            return "waiting for jobs".to_string();
        }
        parts.join(" · ")
    }
}

/// How to stop the miner, as asked for at the dashboard's quit prompt, by `zkminer stop`, or by a
/// signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopMode {
    /// Stop claiming, let the proofs in flight finish and be paid, then exit.
    Drain,
    /// Stop claiming and exit within minutes, leaving the locks held for the next start to finish
    /// (exit 75); a lock too close to its deadline to keep is released first.
    KeepLocks,
    /// Release every lock now (each pays its release penalty), then exit.
    Abandon,
    /// Exit at once without releasing anything.
    Force,
}

/// A question the dashboard is asking before it stops the miner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopPrompt {
    /// Quit was pressed with jobs held: drain, keep the locks, abandon, or cancel.
    Quit,
    /// Confirm one of the stop modes (asked during a stop already under way).
    Confirm(StopMode),
}

/// What the shutdown is doing, while the dashboard stays open through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownStage {
    Draining,
    KeepingLocks,
    Abandoning,
    /// Releasing workers and exiting.
    Finishing,
}

/// The shutdown as the dashboard shows it. Written by the CLI's shutdown ladder.
#[derive(Debug, Clone)]
pub struct ShutdownView {
    pub stage: ShutdownStage,
    /// What is happening right now (refreshed, not appended), e.g. "2 proofs still running".
    pub status: String,
    /// Everything the shutdown reported, in order. Printed to the terminal once the dashboard
    /// closes, so the verdict stays in the scrollback.
    pub lines: Vec<String>,
    /// The shutdown is over: the dashboard closes.
    pub done: bool,
}

impl ShutdownView {
    pub fn new(stage: ShutdownStage) -> Self {
        Self {
            stage,
            status: String::new(),
            lines: Vec::new(),
            done: false,
        }
    }
}

/// How many finished jobs the Jobs page lists below the open market.
pub const RECENT_ROWS: usize = 8;

/// The complete miner state, shared between TUI and background tasks.
#[derive(Debug)]
pub struct MinerState {
    // Wallet & staking
    pub address: String,
    pub eth_balance: u128,
    pub hemi_balance: u128,
    pub stake_info: Option<StakeInfo>,
    pub prover_stats: Option<ProverStatistics>,

    // Jobs
    pub open_jobs: Vec<TrackedJob>,
    pub active_jobs: Vec<TrackedJob>,
    pub completed_jobs: Vec<TrackedJob>,
    pub selected_job_index: usize,
    pub selected_job_id: Option<alloy_primitives::B256>,
    /// Why each open job was not claimed when the brain last evaluated it (see [`ClaimOutlook`]).
    /// Jobs it has not evaluated yet have no entry.
    pub job_why: std::collections::HashMap<alloy_primitives::B256, String>,
    /// The cycle count each job was measured at, once it has been, for open and claimed jobs alike
    /// (the Job Detail screen). A job with no entry has not been measured: its `job_why` says why.
    pub job_measurements: std::collections::HashMap<alloy_primitives::B256, JobMeasurement>,
    /// Each proving job's current attempt: when it started, on which slot, the worker's latest stage
    /// report (see `crate::progress`). A retry replaces it, so its progress and time start over.
    pub proving:
        std::collections::HashMap<alloy_primitives::B256, crate::progress::AttemptProgress>,
    /// What each job is waiting on now, where its status would say something older (`JobNote`).
    pub job_notes: std::collections::HashMap<alloy_primitives::B256, JobNote>,
    /// Locks this miner holds on-chain that nothing is proving or settling now (kept through a
    /// pause, past their deadline, a release that failed, a claim not confirmed), rebuilt from the
    /// claim journal every tick, with why (`kept_reasons`). Without them a lock holding collateral
    /// was in no list at all.
    pub kept_locks: Vec<TrackedJob>,
    pub kept_reasons: std::collections::HashMap<alloy_primitives::B256, String>,
    /// When each job in `completed_jobs` finished (unix seconds), for the Jobs page's history.
    pub finished_at: std::collections::HashMap<alloy_primitives::B256, u64>,
    /// The job the Jobs page's highlight is on (`jobs_cursor`): rows move between sections as jobs
    /// are claimed, held and finished, so a row number alone lands on another job.
    pub selected_row_id: Option<alloy_primitives::B256>,
    /// Each claimed job's proof system (zkVM and wrap), recorded at claim (`job_zkvm_text`).
    pub job_proof_systems:
        std::collections::HashMap<alloy_primitives::B256, zkminer_chain::auction::ProofSystem>,
    /// What the brain's most recent pass did with the open work, for the dashboard's claims line.
    pub claim_outlook: ClaimOutlook,

    // Benchmark
    pub benchmark_results: Option<BenchmarkSuite>,
    /// Each risc0 card's job segment size (po2), by benchmark device id, as the miner decided it
    /// (`zkminer_prover::benchmark::risc0_job_po2`): `None` for a card that proves no risc0 job.
    /// Published by the brain; empty until it runs.
    pub risc0_job_po2s: Vec<(String, Option<u8>)>,
    /// Cards whose running proof Windows is moving off the card to make room for another
    /// program's memory, by PCI bus id as the pool names it (`WorkerPool::bus_id_for_slot`), so
    /// the GPU row can say so. Published every 2 s; empty except under Windows.
    pub gpu_spills: std::collections::HashMap<String, zkminer_prover::dispatcher::GpuSpill>,
    pub benchmark_running: bool,
    /// The benchmark started at launch is still running. It has the cards, so no job is claimed.
    pub startup_benchmark_pending: bool,
    /// Why workers could not start, for the operator. Empty when all did.
    pub startup_problems: Vec<String>,
    /// The launch benchmark took the screen from the Setup wizard; a key returns there afterwards.
    pub return_to_setup_after_benchmark: bool,
    /// Which device is selected in the benchmark screen (0 = CPU, 1+ = GPUs).
    pub benchmark_selected_device: usize,
    /// Device currently being re-benchmarked (None = idle, Some = device_id).
    pub benchmark_device_in_progress: Option<String>,

    // UI state
    pub current_screen: Screen,
    pub activity_log: VecDeque<ActivityEntry>,
    /// Monotonic counter of total log entries ever added (survives eviction).
    pub log_total_added: u64,
    pub log_scroll: usize,
    pub log_filter: Option<String>,
    pub last_refresh: Option<chrono::DateTime<chrono::Utc>>,

    // Hardware
    pub hardware: HardwareInfo,
    pub cpu_stat_snapshot: CpuStatSnapshot,
    pub intel_gpu_energy: std::collections::HashMap<u32, crate::hardware::IntelGpuEnergySnapshot>,

    /// The collateral verdict, published by the brain each tick from the SAME
    /// `collateral_headroom()` call that drives the log warning.
    ///
    /// Published rather than recomputed on purpose. The dashboard has the raw numbers
    /// (Staked/Locked/Liquid) but deriving a verdict from them here would reproduce the
    /// three-different-meanings-of-"available" trap: the brain nets out the current tick's
    /// own reservations and subtracts in-flight locks a second time as a documented
    /// fail-safe, and a TUI that skipped either would show a green verdict while the miner
    /// logged starvation. `None` means the brain has not observed a collateral-blocked job,
    /// so no honest per-claim price is known — show nothing rather than guess.
    pub collateral_headroom: Option<HeadroomView>,

    // Status
    pub paused: bool,
    /// Set by the CLI's signal handler. The TUI event loop breaks on it so a SIGTERM
    /// exits the TUI *into* the shutdown ladder (drain -> abandon -> reap) instead of
    /// killing the process outright with collateral still held.
    pub shutdown_requested: bool,
    /// Set by `zkminer run`, whose shutdown runs while the dashboard stays open: quitting then asks
    /// how to stop (`stop_request`) instead of closing the dashboard. False in mock mode, where
    /// quit just closes it.
    pub stop_handled_by_miner: bool,
    /// A stop asked for at the dashboard, waiting for the miner to take it.
    pub stop_request: Option<StopMode>,
    /// The question the dashboard is asking before it stops the miner.
    pub stop_prompt: Option<StopPrompt>,
    /// The shutdown under way, if any.
    pub shutdown: Option<ShutdownView>,
    /// How long before a kept lock's cutoff the miner must be started again (its `RESTART_BY_SECS`):
    /// the quit prompt's "start it again by" is the earliest kept cutoff less this. 0 until the
    /// miner sets it.
    pub release_margin_secs: u64,
    /// A lock whose cutoff is within this of now is too close for a keep-locks stop to keep: it is
    /// released first. 0 until the miner sets it.
    pub keep_horizon_secs: u64,
    /// The slash latch while it is tripped (what tripped it, and when): no new claims until
    /// `zkminer resume-claims`. `None` when claims are allowed.
    pub claims_latched: Option<String>,
    pub block_number: u64,
    pub errors: Vec<String>,

    // RPC request meter (updated from ChainClient::rpc_meter each refresh)
    pub rpc_total: u64,
    pub rpc_last_minute: u64,

    // Heartbeat / visual tick
    pub tick_count: u64,
    pub block_just_updated: bool,

    // Settings
    pub runtime_settings: RuntimeSettings,
    pub settings_ui: SettingsUiState,

    // GPU tuning
    pub gpu_tuning: Vec<GpuTuningState>,

    /// Throughput captured before a GPU tuning re-benchmark: (device_id, cycles/sec).
    pub gpu_tuning_bench_before: Option<(String, f64)>,
    /// Result of last GPU tuning re-benchmark: (device_id, before c/s, after c/s).
    pub gpu_tuning_bench_result: Option<(String, f64, f64)>,

    // Worker status
    pub worker_status: Vec<WorkerStatus>,

    /// Real-time benchmark progress tracker (active during benchmark runs).
    pub benchmark_tracker: Option<BenchmarkTracker>,

    // Setup wizard
    pub setup_status: SetupStatus,
    /// Chain ID from config (used to detect testnet).
    pub chain_id: u64,
    /// `[dev] private_network` is in force: requesters' ELF URLs may reach this host's private
    /// network. The status bar says so on every frame.
    pub dev_private_network: bool,
}

/// Phase of a single benchmark program on a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramPhase {
    Pending,
    Running,
    Done,
    Failed,
}

/// Progress for a single benchmark program on a device.
#[derive(Debug, Clone)]
pub struct ProgramProgress {
    pub name: String,
    pub phase: ProgramPhase,
    pub throughput: Option<f64>,
    /// STARK proving time (protocol v4+): excludes the Groth16 wrap, which is `wrap_secs`.
    pub duration_secs: Option<f64>,
    /// Groth16 wrap time, when the worker measured it for this program. SP1 measures it on one
    /// program per card; see `BenchmarkEntry::wrap_secs`.
    pub wrap_secs: Option<f64>,
    pub cycles: Option<u64>,
    /// Prover backend that ran this program (e.g. "risc0", "sp1").
    pub prover_backend: Option<String>,
    /// Weight in zkOP/s scoring (0.0-1.0).
    pub weight: Option<f64>,
    /// Whether this program uses precompile acceleration.
    pub precompile: Option<bool>,
}

/// Progress for a single GPU device during benchmarking.
#[derive(Debug, Clone)]
pub struct DeviceProgress {
    pub slot_key: String,
    pub device_id: String,
    pub device_label: String,
    /// The card's model without vendor names and trademarks, e.g. "RTX 4090" or "Arc A770".
    pub short_name: String,
    /// The prover's per-vendor index of this card. Tells apart cards of the same model.
    pub ordinal: u32,
    /// Canonical PCI bus id of the card this row is measuring, when known.
    /// Join on this to find the physical card -- see `GpuInfo::benchmark_device_id`.
    pub pci_bus_id: Option<String>,
    /// GPU variant: "cuda", "rocm", "intel", "generic".
    pub gpu_tag: String,
    pub programs: Vec<ProgramProgress>,
    pub complete: bool,
    /// The slot finished without producing results.
    pub failed: bool,
    /// This row's scoring proof in zkOP/s (SP1 terms), once it has finished: what the card's score
    /// blends (`BenchmarkTracker::card_scores`).
    pub zkops: Option<f64>,
    /// Setting up and running the discarded warm-up proof, before the first program.
    pub warming_up: bool,
    /// What the card's one-time setup is doing now, while it is warming up.
    pub setup_status: Option<String>,
}

/// A zkVM's name as an operator knows it.
pub(crate) fn zkvm_label(backend: &str) -> &str {
    match backend {
        "risc0" => "RISC Zero",
        "sp1" => "SP1",
        "openvm" => "OpenVM",
        other => other,
    }
}

/// A proof system as the dashboard names it: the zkVM, then the wrap its seals use.
pub fn proof_system_name(system: zkminer_chain::auction::ProofSystem) -> &'static str {
    use zkminer_chain::auction::ProofSystem;
    match system {
        ProofSystem::Risc0Groth16 => "risc0:Groth16",
        ProofSystem::Sp1Groth16 => "sp1:Groth16",
        ProofSystem::Sp1Plonk => "sp1:PLONK",
        ProofSystem::OpenVmHalo2 => "openvm:Halo2",
    }
}

/// The width of a column of `proof_system_name`s: the longest there is, and 4 more.
pub fn proof_system_column_width() -> u16 {
    zkminer_chain::auction::ProofSystem::ALL
        .into_iter()
        .map(|system| proof_system_name(system).len())
        .max()
        .unwrap_or(0) as u16
        + 4
}

/// Shorten a driver-reported GPU name for places that have to fit several of them on one line.
pub(crate) fn short_gpu_name(name: &str) -> String {
    let cleaned = name.replace("(R)", "").replace("(TM)", "");
    let cleaned = cleaned.trim();
    let cleaned = cleaned.strip_suffix(" Graphics").unwrap_or(cleaned);
    let cleaned = ["NVIDIA ", "Intel ", "AMD "]
        .iter()
        .find_map(|vendor| cleaned.strip_prefix(vendor))
        .unwrap_or(cleaned);
    cleaned
        .strip_prefix("GeForce ")
        .unwrap_or(cleaned)
        .to_string()
}

impl DeviceProgress {
    /// The zkVM this row is measuring, from the slot key (`"risc0:cuda:0"` -> `"RISC Zero"`).
    pub fn backend_label(&self) -> &str {
        zkvm_label(self.slot_key.split(':').next().unwrap_or_default())
    }

    /// Extract the prover-side device index from the device_id (`"gpu0"` -> 0).
    ///
    /// This is the PROVER's per-vendor index. It is NOT `GpuInfo.index`, which is
    /// a display ordinal over all DRM cards; matching the two is what showed the
    /// idle AMD card's telemetry while an NVIDIA card was benchmarking. Use
    /// `resolve_gpu` to find the physical card.
    pub fn device_index(&self) -> Option<u32> {
        self.device_id
            .strip_prefix("gpu")
            .and_then(|s| s.parse().ok())
    }

    /// Find the physical card this row is measuring, by PCI bus id.
    ///
    /// Returns `None` rather than guessing when the bus id is unknown (a worker
    /// from an older build) or matches no detected card -- callers must render
    /// that as "no telemetry", never as a neighbouring card's values.
    pub fn resolve_gpu<'a>(
        &self,
        gpus: &'a [crate::hardware::GpuInfo],
    ) -> Option<&'a crate::hardware::GpuInfo> {
        let bus = self.pci_bus_id.as_deref().filter(|b| !b.is_empty())?;
        gpus.iter().find(|g| g.pci_bus_id == bus)
    }
}

/// One GPU's score on the benchmark screen.
#[derive(Debug, Clone, PartialEq)]
pub struct CardScore {
    pub name: String,
    pub gpu_tag: String,
    pub ordinal: u32,
    /// zkOP/s, blended over the zkVMs that have scored so far.
    pub zkops: Option<f64>,
    /// Every zkVM on it has finished.
    pub complete: bool,
    /// Every zkVM on it failed.
    pub failed: bool,
}

/// Tracks real-time benchmark progress across all GPUs.
#[derive(Debug, Clone, Default)]
pub struct BenchmarkTracker {
    pub devices: Vec<DeviceProgress>,
    pub all_complete: bool,
    /// When the benchmark started, on the monotonic clock: the wall clock can be set back during a
    /// run (a time sync correcting it), which made the elapsed time and ETA negative.
    pub started_at: Option<std::time::Instant>,
    /// Index of the currently active (benchmarking) device in the tabs.
    pub active_device_index: usize,
}

impl BenchmarkTracker {
    /// Record one benchmark event.
    pub fn apply(&mut self, event: &BenchmarkProgressEvent) {
        tracing::debug!("benchmark progress on {}: {:?}", event.slot_key, event.kind);
        let pos = self.device_position(event);
        match &event.kind {
            BenchmarkProgressKind::Queued => {}
            BenchmarkProgressKind::Started => {
                self.active_device_index = pos;
                self.devices[pos].warming_up = true;
            }
            BenchmarkProgressKind::WarmedUp => {
                let dev = &mut self.devices[pos];
                dev.warming_up = false;
                dev.setup_status = None;
                if let Some(first) = dev.programs.first_mut() {
                    if first.phase == ProgramPhase::Pending {
                        first.phase = ProgramPhase::Running;
                    }
                }
            }
            BenchmarkProgressKind::ProgramDone {
                entry,
                program_index,
                total_programs,
            } => self.on_program_done(pos, entry, *program_index, *total_programs),
            BenchmarkProgressKind::Finished { succeeded } => {
                let dev = &mut self.devices[pos];
                // A worker that never streams still succeeds with nothing reported per program, so
                // its running row is not a failure. After streamed results, it is one.
                let streamed = dev.programs.iter().any(|p| p.phase == ProgramPhase::Done);
                let unfinished = if *succeeded && !streamed {
                    ProgramPhase::Pending
                } else {
                    ProgramPhase::Failed
                };
                for prog in &mut dev.programs {
                    if prog.phase == ProgramPhase::Running {
                        prog.phase = unfinished.clone();
                    }
                }
                dev.complete = true;
                dev.failed = !*succeeded;
                dev.warming_up = false;
                dev.setup_status = None;
            }
        }
        self.all_complete = !self.devices.is_empty() && self.devices.iter().all(|d| d.complete);
    }

    /// The tracker row for this event's slot, creating it if this is the first event for the slot.
    fn device_position(&mut self, event: &BenchmarkProgressEvent) -> usize {
        if let Some(pos) = self
            .devices
            .iter()
            .position(|d| d.slot_key == event.slot_key)
        {
            return pos;
        }
        let idx = event.device_index.unwrap_or(0);
        // Must match `WorkerPool::benchmark_device_id` / the benchmark writer:
        // tag-qualified so a cuda and a rocm card at index 0 do not collide.
        let device_id =
            zkminer_prover::dispatcher::WorkerPool::gpu_device_id(&event.gpu_tag, &idx.to_string());
        let device_label = match event.gpu_name.as_deref() {
            Some(name) => format!("GPU{idx} {name}"),
            None => format!("GPU{idx}"),
        };
        let short_name = match event.gpu_name.as_deref() {
            Some(name) => short_gpu_name(name),
            None if event.gpu_tag == "generic" => "CPU".to_string(),
            None => format!("GPU{idx}"),
        };
        let programs = zkminer_prover::benchmark::BENCHMARK_PROGRAMS
            .iter()
            .map(|program| program.name)
            .chain([zkminer_prover_protocol::BENCH_ZKOP_MIX])
            .map(|name| ProgramProgress {
                name: name.into(),
                phase: ProgramPhase::Pending,
                throughput: None,
                duration_secs: None,
                wrap_secs: None,
                cycles: None,
                prover_backend: None,
                weight: None,
                precompile: None,
            })
            .collect();
        self.devices.push(DeviceProgress {
            slot_key: event.slot_key.clone(),
            device_id,
            device_label,
            short_name,
            ordinal: idx,
            pci_bus_id: event.pci_bus_id.clone(),
            gpu_tag: event.gpu_tag.clone(),
            programs,
            complete: false,
            failed: false,
            zkops: None,
            warming_up: false,
            setup_status: None,
        });
        self.devices.len() - 1
    }

    /// A compact name for this row: the card and the zkVM, numbered only when two rows would
    /// otherwise read the same (two RTX 4090s in one machine).
    pub fn display_name(&self, dev: &DeviceProgress) -> String {
        let same_model_elsewhere = self
            .devices
            .iter()
            .any(|d| d.short_name == dev.short_name && d.ordinal != dev.ordinal);
        if same_model_elsewhere {
            format!(
                "{} #{} {}",
                dev.short_name,
                dev.ordinal,
                dev.backend_label()
            )
        } else {
            format!("{} {}", dev.short_name, dev.backend_label())
        }
    }

    /// Each GPU's score so far, in the order its rows were queued: its zkVMs' scoring proofs
    /// blended (`zkminer_prover_protocol::blended_zkops`).
    pub fn card_scores(&self) -> Vec<CardScore> {
        let mut cards: Vec<CardScore> = Vec::new();
        let mut rates: Vec<(Option<f64>, Option<f64>)> = Vec::new();
        for dev in &self.devices {
            let pos = match cards
                .iter()
                .position(|c| c.gpu_tag == dev.gpu_tag && c.ordinal == dev.ordinal)
            {
                Some(pos) => pos,
                None => {
                    let same_model_elsewhere = self
                        .devices
                        .iter()
                        .any(|d| d.short_name == dev.short_name && d.ordinal != dev.ordinal);
                    cards.push(CardScore {
                        name: if same_model_elsewhere {
                            format!("{} #{}", dev.short_name, dev.ordinal)
                        } else {
                            dev.short_name.clone()
                        },
                        gpu_tag: dev.gpu_tag.clone(),
                        ordinal: dev.ordinal,
                        zkops: None,
                        complete: true,
                        failed: true,
                    });
                    rates.push((None, None));
                    cards.len() - 1
                }
            };
            let card = &mut cards[pos];
            card.complete &= dev.complete;
            card.failed &= dev.failed;
            match dev.slot_key.split(':').next() {
                Some("sp1") => rates[pos].0 = rates[pos].0.or(dev.zkops),
                Some("risc0") => rates[pos].1 = rates[pos].1.or(dev.zkops),
                _ => {}
            }
        }
        for (card, (sp1, risc0)) in cards.iter_mut().zip(rates) {
            card.zkops = zkminer_prover_protocol::blended_zkops(sp1, risc0);
        }
        cards
    }

    /// Updates what each warming-up card's setup is doing, from `status(slot key)`.
    pub fn refresh_setup_status(&mut self, status: impl Fn(&str) -> Option<String>) {
        for dev in self.devices.iter_mut().filter(|d| d.warming_up) {
            dev.setup_status = status(&dev.slot_key);
        }
    }

    /// The row being benchmarked right now, if any.
    pub fn active_device(&self) -> Option<&DeviceProgress> {
        self.devices
            .get(self.active_device_index)
            .filter(|d| !d.complete)
    }

    /// Update progress when a program completes on a device.
    fn on_program_done(
        &mut self,
        pos: usize,
        entry: &zkminer_prover_protocol::BenchmarkEntry,
        program_index: u32,
        total_programs: u32,
    ) {
        let dev = &mut self.devices[pos];
        dev.warming_up = false;
        dev.setup_status = None;

        // Mark the completed program
        if let Some(prog) = dev
            .programs
            .iter_mut()
            .find(|p| p.name == entry.program_name)
        {
            prog.phase = ProgramPhase::Done;
            prog.throughput = Some(entry.throughput);
            prog.duration_secs = Some(entry.duration_secs);
            prog.wrap_secs = entry.wrap_secs;
            prog.cycles = Some(entry.cycles);
            prog.prover_backend = Some(entry.prover_backend.clone());
            prog.weight = Some(entry.weight);
            prog.precompile = Some(entry.precompile);
        }

        if entry.program_name == zkminer_prover_protocol::BENCH_ZKOP_MIX {
            dev.zkops = Some(zkminer_prover_protocol::zkops_from_stark_secs(
                entry.duration_secs,
            ));
        }

        // Mark the next pending program as Running
        if (program_index as usize) < dev.programs.len() {
            if let Some(next) = dev.programs.get_mut(program_index as usize) {
                if next.phase == ProgramPhase::Pending {
                    next.phase = ProgramPhase::Running;
                }
            }
        }

        // Check if device is complete
        dev.complete = program_index >= total_programs;
    }

    /// Total completed programs across all devices.
    pub fn completed_count(&self) -> usize {
        self.devices
            .iter()
            .flat_map(|d| &d.programs)
            .filter(|p| p.phase == ProgramPhase::Done)
            .count()
    }

    /// Total programs across all devices.
    pub fn total_count(&self) -> usize {
        self.devices.iter().map(|d| d.programs.len()).sum()
    }
}

impl Default for MinerState {
    fn default() -> Self {
        Self {
            address: String::new(),
            eth_balance: 0,
            hemi_balance: 0,
            stake_info: None,
            prover_stats: None,
            open_jobs: Vec::new(),
            active_jobs: Vec::new(),
            job_notes: HashMap::new(),
            kept_locks: Vec::new(),
            kept_reasons: HashMap::new(),
            finished_at: HashMap::new(),
            selected_row_id: None,
            job_proof_systems: HashMap::new(),
            completed_jobs: Vec::new(),
            selected_job_index: 0,
            selected_job_id: None,
            job_why: std::collections::HashMap::new(),
            job_measurements: std::collections::HashMap::new(),
            proving: std::collections::HashMap::new(),
            claim_outlook: ClaimOutlook::default(),
            benchmark_results: None,
            risc0_job_po2s: Vec::new(),
            gpu_spills: std::collections::HashMap::new(),
            benchmark_running: false,
            startup_benchmark_pending: false,
            startup_problems: Vec::new(),
            return_to_setup_after_benchmark: false,
            benchmark_selected_device: 0,
            benchmark_device_in_progress: None,
            hardware: HardwareInfo::default(),
            cpu_stat_snapshot: CpuStatSnapshot::default(),
            intel_gpu_energy: std::collections::HashMap::new(),
            current_screen: Screen::Dashboard,
            activity_log: VecDeque::new(),
            log_total_added: 0,
            log_scroll: 0,
            collateral_headroom: None,
            log_filter: None,
            last_refresh: None,
            paused: false,
            shutdown_requested: false,
            stop_handled_by_miner: false,
            stop_request: None,
            stop_prompt: None,
            shutdown: None,
            release_margin_secs: 0,
            keep_horizon_secs: 0,
            claims_latched: None,
            block_number: 0,
            errors: Vec::new(),
            rpc_total: 0,
            rpc_last_minute: 0,
            tick_count: 0,
            block_just_updated: false,
            runtime_settings: RuntimeSettings::default(),
            settings_ui: SettingsUiState::default(),
            gpu_tuning: Vec::new(),
            gpu_tuning_bench_before: None,
            gpu_tuning_bench_result: None,
            worker_status: Vec::new(),
            benchmark_tracker: None,
            setup_status: SetupStatus::default(),
            chain_id: 0,
            dev_private_network: false,
        }
    }
}

/// Bundle of shared TUI state + chain client, used by the TUI app.
/// The chain client is stored separately from MinerState to avoid
/// Debug/Clone constraints on the state struct.
pub struct TuiContext {
    pub state: SharedState,
    pub chain_client: Option<zkminer_chain::client::ChainClient>,
}

impl TuiContext {
    pub fn new(state: SharedState) -> Self {
        Self {
            state,
            chain_client: None,
        }
    }

    pub fn with_client(mut self, client: zkminer_chain::client::ChainClient) -> Self {
        self.chain_client = Some(client);
        self
    }
}

/// How fresh the chain data is, for the connection badges: from the age of the last successful
/// state refresh (`MinerState::last_refresh`), so a lost RPC shows as lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainLink {
    /// Read within [`CHAIN_UP_SECS`].
    Up,
    /// Last read this many seconds ago, within [`CHAIN_DOWN_SECS`].
    Stale(u64),
    /// Never read, or not for [`CHAIN_DOWN_SECS`].
    Down,
}

/// A refresh younger than this is current (two refresh periods).
pub const CHAIN_UP_SECS: u64 = 30;
/// A refresh older than this is a lost chain.
pub const CHAIN_DOWN_SECS: u64 = 120;

impl ChainLink {
    /// The link for a last refresh at `last`, seen at `now`.
    pub fn of(
        last: Option<chrono::DateTime<chrono::Utc>>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let Some(last) = last else {
            return ChainLink::Down;
        };
        let age = (now - last).num_seconds().max(0) as u64;
        if age < CHAIN_UP_SECS {
            ChainLink::Up
        } else if age < CHAIN_DOWN_SECS {
            ChainLink::Stale(age)
        } else {
            ChainLink::Down
        }
    }
}

impl MinerState {
    /// The chain link now (`ChainLink::of` the last refresh).
    pub fn chain_link(&self) -> ChainLink {
        ChainLink::of(self.last_refresh, chrono::Utc::now())
    }
}

impl MinerState {
    /// How long a proving job has been proving, in seconds: live from when it started, or what its
    /// status last carried when the start was not seen.
    /// Note what `job_id` is waiting on (`JobNote`). The same kind keeps its start time.
    pub fn set_job_note(
        &mut self,
        job_id: alloy_primitives::B256,
        kind: JobNoteKind,
        text: impl Into<String>,
    ) {
        let since = match self.job_notes.get(&job_id) {
            Some(note) if note.kind == kind => note.since,
            _ => std::time::Instant::now(),
        };
        // Drop the notes of jobs no longer listed (fulfilled, released, handed back): a job leaves
        // the lists from many places, and none of them needs to know about notes.
        let listed: std::collections::HashSet<alloy_primitives::B256> = self
            .open_jobs
            .iter()
            .chain(self.active_jobs.iter())
            .chain(self.kept_locks.iter())
            .map(|j| j.info.job_id)
            .collect();
        self.job_notes
            .retain(|id, _| *id == job_id || listed.contains(id));
        self.job_notes.insert(
            job_id,
            JobNote {
                kind,
                text: text.into(),
                since,
            },
        );
    }

    /// Drop `job_id`'s note if it is of `kind`: that stage is over.
    /// Drop every note of `job_id`: its lifecycle ended, or it starts over (a re-driven lock), so
    /// nothing said about an earlier stage may show again.
    pub fn clear_job_notes(&mut self, job_id: alloy_primitives::B256) {
        self.job_notes.remove(&job_id);
    }

    pub fn clear_job_note(&mut self, job_id: alloy_primitives::B256, kind: JobNoteKind) {
        if self.job_notes.get(&job_id).is_some_and(|n| n.kind == kind) {
            self.job_notes.remove(&job_id);
        }
    }

    /// A transaction event from the chain client (`zkminer_chain::tx_events`): rewrite the job's
    /// note, if it is waiting on that transaction's stage. Events of a stage that has ended (no
    /// note, or another kind) are ignored.
    pub fn on_tx_event(
        &mut self,
        job_id: alloy_primitives::B256,
        kind: zkminer_chain::tx_events::TxKind,
        event: zkminer_chain::tx_events::TxEvent,
    ) {
        use zkminer_chain::tx_events::{TxEvent, TxKind};
        let (note_kind, what) = match kind {
            TxKind::Claim => (JobNoteKind::Claim, "claiming"),
            TxKind::Fulfil => (JobNoteKind::Submit, "submitting the proof"),
            TxKind::Release => (JobNoteKind::Release, "releasing"),
        };
        if self.job_notes.get(&job_id).map(|n| n.kind) != Some(note_kind) {
            return;
        }
        let text = match event {
            TxEvent::Sent { attempt, of } => {
                format!("{what}: waiting for the chain to confirm (try {attempt} of {of})")
            }
            TxEvent::Unconfirmed { attempt, of } => format!(
                "{what}: not confirmed yet, checking the chain before sending again (try {attempt} \
                 of {of})"
            ),
            TxEvent::SendFailed {
                attempt,
                of,
                rate_limited: true,
            } => format!(
                "{what}: the RPC is rate-limiting, sending again shortly (try {attempt} of {of})"
            ),
            TxEvent::SendFailed { attempt, of, .. } => {
                format!("{what}: the send failed, sending again (try {attempt} of {of})")
            }
        };
        self.set_job_note(job_id, note_kind, text);
    }

    /// What `job` is waiting on, with for how long, when there is a note for it and its status is
    /// one the note can speak for (not proving or finished).
    pub fn job_note_text(&self, job: &TrackedJob) -> Option<String> {
        if !matches!(
            job.status,
            MinerJobStatus::Open | MinerJobStatus::Queued | MinerJobStatus::Submitting
        ) {
            return None;
        }
        let note = self.job_notes.get(&job.info.job_id)?;
        Some(format!(
            "{}, {}",
            note.text,
            crate::screens::dashboard::format_duration(note.since.elapsed().as_secs())
        ))
    }

    /// Record `job_id`'s proof system, at claim. The records of jobs no longer listed go.
    pub fn note_proof_system(
        &mut self,
        job_id: alloy_primitives::B256,
        system: zkminer_chain::auction::ProofSystem,
    ) {
        let listed: std::collections::HashSet<alloy_primitives::B256> = self
            .open_jobs
            .iter()
            .chain(self.active_jobs.iter())
            .map(|j| j.info.job_id)
            .collect();
        self.job_proof_systems.retain(|id, _| listed.contains(id));
        self.job_proof_systems.insert(job_id, system);
    }

    /// The zkVM and wrap `job` proves with (`proof_system_name`), or, with no proof system recorded
    /// (a lock recovered after a restart), the zkVM its worker slot names.
    pub fn job_zkvm_text(&self, job: &TrackedJob) -> String {
        match self.job_proof_systems.get(&job.info.job_id) {
            Some(system) => proof_system_name(*system).to_string(),
            None => match job.prover_backend.split(':').next() {
                Some(backend) if !backend.is_empty() => backend.to_string(),
                _ => "—".to_string(),
            },
        }
    }

    pub fn proving_secs(&self, job: &TrackedJob) -> u64 {
        match self.proving.get(&job.info.job_id) {
            Some(attempt) => attempt.started.elapsed().as_secs(),
            None => match job.status {
                MinerJobStatus::Proving { elapsed_secs, .. } => elapsed_secs,
                _ => 0,
            },
        }
    }

    /// How far a proving job's current attempt is, in [0, 0.99], from its worker's stage reports
    /// weighed by the job's measured cycles and its card's benchmark (`crate::progress`). `None`
    /// when there is nothing to weigh them by: no measurement, or no benchmark row for the backend.
    pub fn proving_fraction(&self, job: &TrackedJob) -> Option<f64> {
        let attempt = self.proving.get(&job.info.job_id)?;
        let exp = self.expected_stage_secs(job, attempt)?;
        crate::progress::attempt_fraction(attempt, &exp, std::time::Instant::now())
    }

    /// The stage a proving job's current attempt is in, with its counts, e.g. "segment 40/91".
    pub fn proving_stage_label(&self, job: &TrackedJob) -> Option<String> {
        let attempt = self.proving.get(&job.info.job_id)?;
        let backend = attempt.slot.split(':').next().unwrap_or("");
        Some(crate::progress::stage_label(backend, attempt.report))
    }

    /// Raises each attempt's floor to what it shows now, so the bar never moves back between the
    /// worker's reports. Called as the dashboard refreshes.
    pub fn refresh_proving_floors(&mut self) {
        let now = std::time::Instant::now();
        let floors: Vec<(alloy_primitives::B256, f64)> = self
            .active_jobs
            .iter()
            .filter_map(|job| {
                let attempt = self.proving.get(&job.info.job_id)?;
                let exp = self.expected_stage_secs(job, attempt)?;
                Some((
                    job.info.job_id,
                    crate::progress::attempt_fraction(attempt, &exp, now)?,
                ))
            })
            .collect();
        for (id, f) in floors {
            if let Some(attempt) = self.proving.get_mut(&id) {
                attempt.floor = attempt.floor.max(f);
            }
        }
    }

    /// The expected seconds of each stage of `job` on the card of `attempt`: from the job's measured
    /// cycles, and the card's benchmark row for the backend, else the slowest row of that backend.
    /// Without a measurement (a lock recovered from a breadcrumb that did not record one) the `Prove`
    /// stage is left to its observed rate.
    fn expected_stage_secs(
        &self,
        job: &TrackedJob,
        attempt: &crate::progress::AttemptProgress,
    ) -> Option<crate::progress::StageSecs> {
        let mut parts = attempt.slot.split(':');
        let (backend, tag, index) = (parts.next()?, parts.next()?, parts.next()?);
        let measurement = self.job_measurements.get(&job.info.job_id);
        let cycles = measurement.and_then(|m| m.cycles);
        let device = zkminer_prover::dispatcher::WorkerPool::gpu_device_id(tag, index);
        let rows = &self.benchmark_results.as_ref()?.device_benchmarks;
        let of_backend = || rows.iter().filter(|r| r.prover_backend == backend);
        let row = of_backend().find(|r| r.device_id == device).or_else(|| {
            of_backend()
                .filter(|r| r.stark_rate().is_some())
                .min_by(|a, b| {
                    a.stark_rate()
                        .partial_cmp(&b.stark_rate())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        })?;
        let execute_secs = measurement.map(|m| m.execute_secs);
        crate::progress::expected_stage_secs(backend, cycles, execute_secs, row)
    }

    /// The Jobs page's rows, in order: the jobs this miner has claimed, then the open market less
    /// any job also among them (a claim the market list has not caught up with yet). Its selection
    /// (`selected_job_index`) indexes this list.
    /// The Jobs page's rows, in order: claimed jobs being worked on, locks held but not being
    /// worked on (`kept_locks`), the open market, then the most recent finished jobs (`RECENT_ROWS`),
    /// each job once.
    pub fn jobs_page_rows(&self) -> Vec<&TrackedJob> {
        let mut seen = std::collections::HashSet::new();
        let mut rows = Vec::new();
        for job in self
            .active_jobs
            .iter()
            .chain(self.kept_locks.iter())
            .chain(self.open_jobs.iter())
            .chain(self.recent_finished(RECENT_ROWS))
        {
            if seen.insert(job.info.job_id) {
                rows.push(job);
            }
        }
        rows
    }

    /// The Jobs page's highlighted row: the highlighted job's, wherever it moved, else the row number.
    pub fn jobs_cursor(&self) -> usize {
        let rows = self.jobs_page_rows();
        self.selected_row_id
            .and_then(|id| rows.iter().position(|j| j.info.job_id == id))
            .unwrap_or_else(|| self.selected_job_index.min(rows.len().saturating_sub(1)))
    }

    /// Move the Jobs page's highlight by `step` rows, onto that row's job.
    pub fn move_jobs_cursor(&mut self, step: isize) {
        let rows = self.jobs_page_rows();
        let last = rows.len().saturating_sub(1);
        let at = self.jobs_cursor().saturating_add_signed(step).min(last);
        let id = rows.get(at).map(|j| j.info.job_id);
        self.selected_job_index = at;
        self.selected_row_id = id;
    }

    /// Why a lock is held but not worked on, if it is one (`kept_locks`) and not being worked on.
    pub fn kept_reason(&self, job_id: alloy_primitives::B256) -> Option<&str> {
        if self.active_jobs.iter().any(|j| j.info.job_id == job_id) {
            return None;
        }
        self.kept_reasons.get(&job_id).map(String::as_str)
    }

    /// The `n` most recently finished jobs (fulfilled or released), newest first.
    pub fn recent_finished(&self, n: usize) -> impl Iterator<Item = &TrackedJob> {
        self.completed_jobs.iter().rev().take(n)
    }

    /// `job_id` is done (fulfilled, or released): its row leaves the claimed list for the history,
    /// with `status` and the time.
    pub fn record_finished(&mut self, job_id: alloy_primitives::B256, status: MinerJobStatus) {
        // Its claimed row, or its held row (a lock recovery released, with no claimed row).
        let mut row = if let Some(at) = self
            .active_jobs
            .iter()
            .position(|j| j.info.job_id == job_id)
        {
            self.active_jobs.remove(at)
        } else if let Some(at) = self.kept_locks.iter().position(|j| j.info.job_id == job_id) {
            self.kept_locks.remove(at)
        } else {
            return;
        };
        row.status = status;
        row.gpu_bus_id = None;
        self.completed_jobs.retain(|j| j.info.job_id != job_id);
        self.completed_jobs.push(row);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.finished_at.insert(job_id, now);
        // Not held any more: no held reason may make its history row read as one.
        self.kept_reasons.remove(&job_id);
        // Bounded, for a long run.
        const COMPLETED_JOBS_CAP: usize = 500;
        if self.completed_jobs.len() > COMPLETED_JOBS_CAP {
            let excess = self.completed_jobs.len() - COMPLETED_JOBS_CAP;
            self.completed_jobs.drain(0..excess);
            let kept: std::collections::HashSet<alloy_primitives::B256> =
                self.completed_jobs.iter().map(|j| j.info.job_id).collect();
            self.finished_at.retain(|id, _| kept.contains(id));
        }
        self.job_notes.remove(&job_id);
    }

    /// Map a GPU-tuning device id (see `gpu_tuning::tuning_device_id`) to the
    /// benchmark `device_id` for the same physical card.
    ///
    /// The two namespaces are deliberately different -- tuning keys on the PCI
    /// bus id because it needs no benchmark data, benchmarks key on the prover's
    /// own device id -- so anything comparing one to the other must go through
    /// here. Returns `None` when the card has no benchmark row.
    pub fn benchmark_id_for_tuning_id(&self, tuning_id: &str) -> Option<String> {
        let suite = self.benchmark_results.as_ref()?;
        let gpu = crate::gpu_tuning::find_gpu_by_tuning_id(&self.hardware.gpus, tuning_id)?;
        gpu.benchmark_device_id(suite)
    }

    /// Records why workers could not start, where the operator will see it.
    pub fn note_startup_problems(&mut self, problems: &[String]) {
        for problem in problems {
            self.add_log(LogLevel::Error, problem.clone());
        }
        self.startup_problems = problems.to_vec();
    }

    pub fn add_log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.activity_log.push_back(ActivityEntry {
            timestamp: chrono::Utc::now(),
            level,
            message: message.into(),
        });
        self.log_total_added += 1;
        // Keep last 1000 entries
        if self.activity_log.len() > 1000 {
            self.activity_log.pop_front();
        }
    }
}

pub type SharedState = Arc<RwLock<MinerState>>;

pub fn new_shared_state() -> SharedState {
    Arc::new(RwLock::new(MinerState::default()))
}

#[cfg(test)]
mod chain_link_tests {
    use super::ChainLink;

    #[test]
    fn the_badge_follows_the_age_of_the_last_refresh() {
        let now = chrono::Utc::now();
        let ago = |s: i64| Some(now - chrono::Duration::seconds(s));
        assert_eq!(ChainLink::of(ago(5), now), ChainLink::Up);
        assert_eq!(ChainLink::of(ago(45), now), ChainLink::Stale(45));
        assert_eq!(ChainLink::of(ago(119), now), ChainLink::Stale(119));
        assert_eq!(ChainLink::of(ago(120), now), ChainLink::Down);
        assert_eq!(ChainLink::of(None, now), ChainLink::Down);
    }
}

#[cfg(test)]
mod benchmark_tracker_tests {
    use super::ClaimOutlook;

    #[test]
    fn the_claims_summary_says_what_the_last_pass_did() {
        assert_eq!(ClaimOutlook::default().summary(), "waiting for jobs");
        let held = ClaimOutlook {
            held: Some("paused (press p to resume)".into()),
            declined: vec![("ignored".into(), 3)],
            ..ClaimOutlook::default()
        };
        assert_eq!(held.summary(), "not claiming: paused (press p to resume)");
        let o = ClaimOutlook {
            held: None,
            declined: vec![
                ("below the profit threshold".into(), 6),
                ("waiting for its cycle measurement".into(), 3),
                ("a".into(), 1),
                ("b".into(), 1),
                ("c".into(), 1),
                ("d".into(), 2),
            ],
            claimed: 2,
            not_evaluated: 4,
        };
        assert_eq!(
            o.summary(),
            "2 claiming · not claimed: 6 below the profit threshold, 3 waiting for its cycle \
             measurement, 1 a, 1 b, 3 other · 4 not re-checked this pass"
        );
    }

    use super::*;

    fn event(
        slot_key: &str,
        name: &str,
        index: u32,
        kind: BenchmarkProgressKind,
    ) -> BenchmarkProgressEvent {
        BenchmarkProgressEvent {
            slot_key: slot_key.to_string(),
            gpu_name: Some(name.to_string()),
            device_index: Some(index),
            pci_bus_id: None,
            gpu_tag: slot_key.split(':').nth(1).unwrap().to_string(),
            kind,
        }
    }

    fn program_done(name: &str, program_index: u32) -> BenchmarkProgressKind {
        BenchmarkProgressKind::ProgramDone {
            entry: zkminer_prover_protocol::BenchmarkEntry {
                program_name: name.to_string(),
                prover_backend: "risc0".to_string(),
                cycles: 1_000,
                duration_secs: 1.0,
                throughput: 1_000.0,
                weight: 0.1,
                precompile: false,
                wrap_secs: None,
            },
            program_index,
            total_programs: 6,
        }
    }

    const RTX: &str = "NVIDIA GeForce RTX 4090";
    const ARC: &str = "Intel(R) Arc(TM) A770 Graphics";

    fn queued() -> BenchmarkTracker {
        let mut tracker = BenchmarkTracker::default();
        for (key, name) in [
            ("risc0:cuda:0", RTX),
            ("sp1:cuda:0", RTX),
            ("risc0:intel:0", ARC),
        ] {
            tracker.apply(&event(key, name, 0, BenchmarkProgressKind::Queued));
        }
        tracker
    }

    #[test]
    fn the_whole_queue_is_known_before_the_first_result() {
        let mut tracker = queued();
        tracker.apply(&event(
            "risc0:cuda:0",
            RTX,
            0,
            BenchmarkProgressKind::Started,
        ));

        assert_eq!(tracker.devices.len(), 3);
        assert_eq!(tracker.total_count(), 18);
        let active = tracker.active_device().expect("a card is running");
        assert_eq!(tracker.display_name(active), "RTX 4090 RISC Zero");
        // Warming up: no program has started.
        assert!(active.warming_up);
        assert_eq!(active.programs[0].phase, ProgramPhase::Pending);

        tracker.apply(&event(
            "risc0:cuda:0",
            RTX,
            0,
            BenchmarkProgressKind::WarmedUp,
        ));
        let active = tracker.active_device().expect("a card is running");
        assert!(!active.warming_up);
        assert_eq!(active.programs[0].phase, ProgramPhase::Running);
        tracker.refresh_setup_status(|_| Some("not warming up any more".to_string()));
        let active = tracker.active_device().expect("a card is running");
        assert_eq!(active.setup_status, None);
        // The warm-up is never one of the rows.
        assert!(active
            .programs
            .iter()
            .all(|p| p.name != zkminer_prover_protocol::BENCH_WARMUP));
    }

    #[test]
    fn finishing_one_card_does_not_end_the_progress_view() {
        let mut tracker = queued();
        tracker.apply(&event(
            "risc0:cuda:0",
            RTX,
            0,
            BenchmarkProgressKind::Started,
        ));
        tracker.apply(&event(
            "risc0:cuda:0",
            RTX,
            0,
            program_done("chacha-mix", 6),
        ));
        tracker.apply(&event(
            "risc0:cuda:0",
            RTX,
            0,
            BenchmarkProgressKind::Finished { succeeded: true },
        ));

        assert!(tracker.devices[0].complete);
        assert!(!tracker.all_complete);
        assert!(tracker.active_device().is_none(), "between cards");

        tracker.apply(&event("sp1:cuda:0", RTX, 0, BenchmarkProgressKind::Started));
        let active = tracker.active_device().expect("the next card is running");
        assert_eq!(tracker.display_name(active), "RTX 4090 SP1");
    }

    #[test]
    fn a_failed_slot_is_marked_and_does_not_stall_the_run() {
        let mut tracker = BenchmarkTracker::default();
        let key = "sp1:cuda:0";
        tracker.apply(&event(key, RTX, 0, BenchmarkProgressKind::Queued));
        tracker.apply(&event(key, RTX, 0, BenchmarkProgressKind::Started));
        tracker.apply(&event(key, RTX, 0, BenchmarkProgressKind::WarmedUp));
        tracker.apply(&event(
            key,
            RTX,
            0,
            BenchmarkProgressKind::Finished { succeeded: false },
        ));

        assert!(tracker.devices[0].failed);
        assert_eq!(tracker.devices[0].programs[0].phase, ProgramPhase::Failed);
        assert!(tracker.all_complete);
    }

    #[test]
    fn a_slot_that_fails_while_warming_up_is_failed_with_no_program_blamed() {
        let mut tracker = BenchmarkTracker::default();
        let key = "sp1:cuda:0";
        tracker.apply(&event(key, RTX, 0, BenchmarkProgressKind::Started));
        tracker.apply(&event(
            key,
            RTX,
            0,
            BenchmarkProgressKind::Finished { succeeded: false },
        ));

        let dev = &tracker.devices[0];
        assert!(dev.failed && !dev.warming_up);
        assert!(dev
            .programs
            .iter()
            .all(|p| p.phase == ProgramPhase::Pending));
    }

    #[test]
    fn a_worker_that_does_not_stream_is_not_shown_as_failed() {
        let mut tracker = BenchmarkTracker::default();
        let key = "openvm:cuda:0";
        tracker.apply(&event(key, RTX, 0, BenchmarkProgressKind::Started));
        tracker.apply(&event(
            key,
            RTX,
            0,
            BenchmarkProgressKind::Finished { succeeded: true },
        ));

        assert!(!tracker.devices[0].failed);
        assert_eq!(tracker.devices[0].programs[0].phase, ProgramPhase::Pending);
    }

    #[test]
    fn the_score_comes_from_the_scoring_program_only() {
        let key = "sp1:cuda:0";
        let mut tracker = BenchmarkTracker::default();
        tracker.apply(&event(key, RTX, 0, program_done("chacha-mix", 6)));
        assert_eq!(tracker.devices[0].zkops, None);

        tracker.apply(&event(key, RTX, 0, program_done(zkminer_prover_protocol::BENCH_ZKOP_MIX, 7)));
        let expected = zkminer_prover_protocol::zkops_from_stark_secs(1.0);
        assert_eq!(tracker.devices[0].zkops, Some(expected));
    }

    #[test]
    fn a_card_scores_its_zkvms_blended() {
        use zkminer_prover_protocol::{blended_zkops, zkops_from_stark_secs, BENCH_ZKOP_MIX};
        let mut tracker = BenchmarkTracker::default();
        tracker.apply(&event(
            "risc0:cuda:0",
            RTX,
            0,
            BenchmarkProgressKind::Queued,
        ));
        tracker.apply(&event("sp1:cuda:0", RTX, 0, BenchmarkProgressKind::Queued));
        tracker.apply(&event("sp1:intel:0", ARC, 0, BenchmarkProgressKind::Queued));
        let rate = zkops_from_stark_secs(1.0);

        // One zkVM scored: the card's score is that one alone, not yet ticked.
        tracker.apply(&event(
            "risc0:cuda:0",
            RTX,
            0,
            program_done(BENCH_ZKOP_MIX, 6),
        ));
        let cards = tracker.card_scores();
        assert_eq!(cards.len(), 2, "one per GPU, not per zkVM");
        assert_eq!(cards[0].name, "RTX 4090");
        assert_eq!(cards[0].zkops, blended_zkops(None, Some(rate)));
        assert!(!cards[0].complete);

        // Both scored: blended, and complete.
        tracker.apply(&event(
            "sp1:cuda:0",
            RTX,
            0,
            program_done(BENCH_ZKOP_MIX, 6),
        ));
        let cards = tracker.card_scores();
        assert_eq!(cards[0].zkops, blended_zkops(Some(rate), Some(rate)));
        assert!(cards[0].complete && !cards[0].failed);
        assert_eq!(cards[1].name, "Arc A770");
        assert_eq!(cards[1].zkops, None);
    }

    #[test]
    fn identical_cards_are_numbered_and_different_ones_are_not() {
        let mut tracker = BenchmarkTracker::default();
        tracker.apply(&event("sp1:cuda:0", RTX, 0, BenchmarkProgressKind::Queued));
        tracker.apply(&event("sp1:cuda:1", RTX, 1, BenchmarkProgressKind::Queued));
        tracker.apply(&event("sp1:intel:0", ARC, 0, BenchmarkProgressKind::Queued));

        assert_eq!(tracker.display_name(&tracker.devices[0]), "RTX 4090 #0 SP1");
        assert_eq!(tracker.display_name(&tracker.devices[1]), "RTX 4090 #1 SP1");
        assert_eq!(tracker.display_name(&tracker.devices[2]), "Arc A770 SP1");
    }

    #[test]
    fn gpu_names_are_shortened_without_losing_the_model() {
        assert_eq!(short_gpu_name(RTX), "RTX 4090");
        assert_eq!(short_gpu_name(ARC), "Arc A770");
        assert_eq!(
            short_gpu_name("Intel(R) Arc(TM) Pro B70 Graphics"),
            "Arc Pro B70"
        );
        assert_eq!(short_gpu_name("AMD Radeon RX 9070 XT"), "Radeon RX 9070 XT");
    }
}
