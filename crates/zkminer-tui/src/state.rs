//! Shared miner state accessible from both the TUI and background tasks.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use zkminer_chain::jobs::JobInfo;
use zkminer_chain::staking::{ProverStatistics, StakeInfo};
use zkminer_prover::benchmark::BenchmarkSuite;
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
        self.refresh_from_balances(state.eth_balance, state.hemi_balance, state.stake_info.as_ref());
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

        // [FIX-V1A3, 2026-07-08] The 1h MIN_STAKING_AGE claim gate was removed
        // on-chain; a stake is claimable from the next block after it lands
        // (block.number > depositBlock), which is always satisfied by the time
        // we evaluate jobs. So maturity simply tracks "has an active stake".
        // `deposit_block` is a block number (not a wall-clock timestamp), so no
        // age countdown is computed.
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
    /// Whether advanced mode (po2 overrides) is enabled.
    pub advanced_mode: bool,
    /// Per-(device, backend) po2 overrides.
    pub po2_overrides: HashMap<(String, String), u8>,
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
    /// Whether to claim jobs carrying a non-zero `expectedJournalHash` (Phase-2
    /// journal predicate). Default true (claim them). Set false to skip — a
    /// predicate job whose committed journal our proof can't reproduce reverts
    /// `JournalMismatch` at fulfill and risks a collateral slash on timeout,
    /// and zkminer does not yet simulate the predicate before claiming.
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
    pub benchmark_running: bool,
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
    pub duration_secs: Option<f64>,
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
    /// Canonical PCI bus id of the card this row is measuring, when known.
    /// Join on this to find the physical card -- see `GpuInfo::benchmark_device_id`.
    pub pci_bus_id: Option<String>,
    /// GPU variant: "cuda", "rocm", "intel", "generic".
    pub gpu_tag: String,
    pub programs: Vec<ProgramProgress>,
    pub complete: bool,
    /// Partial zkOP/s score computed from completed programs.
    pub partial_zkops: Option<f64>,
}

impl DeviceProgress {
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
    /// Update progress when a program completes on a device.
    pub fn on_progress(
        &mut self,
        slot_key: &str,
        gpu_name: Option<&str>,
        device_index: Option<u32>,
        pci_bus_id: Option<&str>,
        gpu_tag: &str,
        entry: &zkminer_prover_protocol::BenchmarkEntry,
        program_index: u32,
        total_programs: u32,
    ) {
        let idx = device_index.unwrap_or(0);
        // Must match `WorkerPool::benchmark_device_id` / the benchmark writer:
        // tag-qualified so a cuda and a rocm card at index 0 do not collide.
        let device_id = zkminer_prover::dispatcher::WorkerPool::gpu_device_id(
            gpu_tag,
            &idx.to_string(),
        );
        let device_label = match gpu_name {
            Some(name) => format!("GPU{idx} {name}"),
            None => format!("GPU{idx}"),
        };

        // Find or create device entry
        let dev = if let Some(pos) = self.devices.iter().position(|d| d.slot_key == slot_key) {
            &mut self.devices[pos]
        } else {
            let make_prog = |name: &str| ProgramProgress {
                name: name.into(),
                phase: ProgramPhase::Pending,
                throughput: None,
                duration_secs: None,
                cycles: None,
                prover_backend: None,
                weight: None,
                precompile: None,
            };
            let programs = vec![
                make_prog("fibonacci"),
                make_prog("sha256-chain"),
                make_prog("ecdsa-verify"),
                make_prog("bigint-mul"),
                make_prog("memory-merkle"),
                make_prog("chacha-mix"),
            ];
            self.active_device_index = self.devices.len();
            self.devices.push(DeviceProgress {
                slot_key: slot_key.to_string(),
                device_id,
                device_label,
                pci_bus_id: pci_bus_id.map(str::to_string),
                gpu_tag: gpu_tag.to_string(),
                programs,
                complete: false,
                partial_zkops: None,
            });
            self.devices.last_mut().unwrap()
        };

        // Mark the completed program
        if let Some(prog) = dev.programs.iter_mut().find(|p| p.name == entry.program_name) {
            prog.phase = ProgramPhase::Done;
            prog.throughput = Some(entry.throughput);
            prog.duration_secs = Some(entry.duration_secs);
            prog.cycles = Some(entry.cycles);
            prog.prover_backend = Some(entry.prover_backend.clone());
            prog.weight = Some(entry.weight);
            prog.precompile = Some(entry.precompile);
        }

        // Compute partial zkOP/s from completed programs
        let partial_results: Vec<zkminer_prover::benchmark::BenchmarkResult> = dev
            .programs
            .iter()
            .filter(|p| p.phase == ProgramPhase::Done)
            .filter_map(|p| {
                Some(zkminer_prover::benchmark::BenchmarkResult {
                    program_name: p.name.clone(),
                    prover_backend: p.prover_backend.clone().unwrap_or_default(),
                    cycles: p.cycles.unwrap_or(0),
                    duration: std::time::Duration::from_secs_f64(
                        p.duration_secs.unwrap_or(0.0),
                    ),
                    throughput: p.throughput.unwrap_or(0.0),
                    weight: p.weight.unwrap_or(0.0),
                    precompile: p.precompile.unwrap_or(false),
                })
            })
            .collect();
        if !partial_results.is_empty() {
            dev.partial_zkops =
                Some(zkminer_prover::benchmark::compute_zkops(&partial_results));
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

        // Check if all devices are complete
        self.all_complete = !self.devices.is_empty() && self.devices.iter().all(|d| d.complete);
    }

    /// Total completed programs across all devices.
    pub fn completed_count(&self) -> usize {
        self.devices.iter()
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
            benchmark_running: false,
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
