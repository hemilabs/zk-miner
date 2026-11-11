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
    /// Job evaluation resulted in skip.
    Skipped { reason: String },
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

    // Benchmark
    pub benchmark_results: Option<BenchmarkSuite>,
    /// Each risc0 card's job segment size (po2), by benchmark device id, as the miner decided it
    /// (`zkminer_prover::benchmark::risc0_job_po2`): `None` for a card that proves no risc0 job.
    /// Published by the brain; empty until it runs.
    pub risc0_job_po2s: Vec<(String, Option<u8>)>,
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
    pub connected: bool,
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
    /// This row's zkOP/s, once its scoring program has finished.
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

/// Tracks real-time benchmark progress across all GPUs.
#[derive(Debug, Clone, Default)]
pub struct BenchmarkTracker {
    pub devices: Vec<DeviceProgress>,
    pub all_complete: bool,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
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
            completed_jobs: Vec::new(),
            selected_job_index: 0,
            selected_job_id: None,
            benchmark_results: None,
            risc0_job_po2s: Vec::new(),
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
            connected: false,
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

impl MinerState {
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
mod benchmark_tracker_tests {
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
