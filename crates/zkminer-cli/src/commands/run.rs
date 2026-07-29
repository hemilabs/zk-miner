use anyhow::Result;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use alloy::primitives::{Bytes, B256};
use tokio::sync::mpsc;
use zkminer_chain::client::ChainClient;
use zkminer_chain::descriptor::{fetch_job_descriptor_checked, verify_descriptor_hash};
use zkminer_chain::jobs::ClaimOutcome;
use zkminer_chain::monitor::{JobMonitor, MonitorEvent};
use zkminer_config::ZkMinerConfig;
use zkminer_config::wallet::load_signer;
use zkminer_prover::benchmark::{load_cached_benchmark, run_benchmark_gpu_only_streaming, save_benchmark};
use zkminer_prover::dispatcher::WorkerPool;
use zkminer_prover::engine::{backend_sources, init_worker_pool, BackendSource};
use zkminer_strategy::cost_model::CostParams;
use zkminer_strategy::evaluator::{evaluate_job, JobParams, Recommendation};
use zkminer_tui::state::{LogLevel, MinerJobStatus, TrackedJob, WorkerStatus, new_shared_state};

use crate::journal::JobJournal;

use zkminer_chain::adapter::AdapterInfo;

/// Safety margin (seconds) before lock_deadline beyond which we will not start
/// or continue work, to leave room for the fulfill tx to land before slashing.
const DEADLINE_FULFILL_MARGIN_SECS: u64 = 60;

/// Headroom (seconds) kept before a job's lock deadline for the abandon-and-release
/// path (#20). The proving watchdog is clamped so a proof that won't finish in time
/// is killed while there's still this much room for `releaseJob` to land (it reverts
/// at/after the deadline, stranding collateral until a slash).
///
/// This MUST comfortably exceed `TX_RECEIPT_TIMEOUT`: `release_job`'s rebroadcast/poll
/// machinery waits up to one receipt-timeout per attempt, so a margin smaller than
/// that can't fit even a single release attempt before the deadline — the rebroadcast
/// logic would be dead weight and every congested release would strand. We reserve one
/// full receipt-timeout plus a rebroadcast/poll cycle (+60s). The proving-budget cost
/// (jobs finish this much earlier) is the right trade: a stranded collateral lock is
/// permanent until a keeper slash, whereas the lost budget only skips a few short-
/// deadline jobs the feasibility gate would flag anyway.
const DEADLINE_RELEASE_MARGIN_SECS: u64 = zkminer_chain::tx::TX_RECEIPT_TIMEOUT.as_secs() + 60;

/// Below this much remaining proving budget it isn't worth starting another attempt
/// (#20) — abandon the job now, while `releaseJob` can still land, instead of
/// starting a proof that would be killed almost immediately.
const MIN_ATTEMPT_BUDGET_SECS: u64 = 30;

/// A freshly-claimed job always has a nonzero on-chain `lockDeadline`; reading 0 is
/// a lagging/load-balanced node that hasn't observed the claim block yet. Retry the
/// view read this many times (with this delay) before giving up — proceeding with a
/// 0 deadline would silently void EVERY deadline guard (gates + release margin).
const DEADLINE_READ_RETRIES: u32 = 3;
const DEADLINE_READ_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Fallback wall-time cap for the (normally deadline-bounded) descriptor/ELF fetch
/// when the deadline is somehow unknown. A stalled submitter-controlled storage URI
/// must never hang the lifecycle indefinitely (it would strand collateral AND
/// permanently wedge a concurrency slot), so bound it even without a deadline.
const FETCH_FALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// Max proving attempts per job. Retries cover the intermittent multi-segment
/// "invalid proof" race (nondeterministic — re-proving almost always succeeds)
/// and a worker OOM/death (retried on a higher-VRAM GPU).
const MAX_PROVE_ATTEMPTS: u32 = 3;

/// Max jobs locked in one `claimJobBatch` tx. Matches the contract's MAX_BATCH_SIZE
/// (10). The actual per-tick batch is further capped to free proving slots so we never
/// lock more than we can prove before their deadlines (the stranding failure mode).
/// Set `ZKMINER_NO_BATCH_CLAIM` to force the one-tx-per-job path (soak escape hatch).
const MAX_CLAIM_BATCH: usize = 10;

/// Classification of a single per-job reconcile read after a `claimJobBatch` tx.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ReconcileClass {
    /// View present AND prover == us → we hold it; prove/fulfill.
    Locked,
    /// View present AND prover != us AND != ZERO → someone else holds it; drop.
    NotOurs,
    /// Read absent (None), OR prover == ZERO (job still reads OPEN). Indistinguishable
    /// from a single read: either the sub-claim reverted (we don't hold it) OR a
    /// lagging/stale post-mine node hasn't indexed our lock yet. Treat as UNKNOWN —
    /// keep the breadcrumb + retry — because classifying a lagging-ZERO read of a job we
    /// DID lock as NotOurs would drop it → keeper slash (D1).
    Unknown,
}

/// Classify a reconcile read from the on-chain `prover` field. `prover == None` means
/// the view was absent/unreadable. Mirrors the single-claim poll, which treats
/// `prover == ZERO` as "keep polling, not lost".
fn classify_reconcile(prover: Option<alloy::primitives::Address>, us: alloy::primitives::Address) -> ReconcileClass {
    match prover {
        Some(p) if p == us => ReconcileClass::Locked,
        Some(p) if p != alloy::primitives::Address::ZERO => ReconcileClass::NotOurs,
        // Some(ZERO) or None → unknown.
        _ => ReconcileClass::Unknown,
    }
}

/// Committed-cycle count above which a job is treated as "large" and proactively
/// pinned to a high-VRAM GPU (only takes effect when the job commits a cycle
/// count; uncommitted jobs still get the reactive OOM→high-VRAM retry).
const LARGE_JOB_CYCLES: u64 = 150_000_000;

/// VRAM floor (30 GiB) for large jobs — includes 32 GB cards, excludes 24 GB
/// ones, keeping OOM-prone multi-segment proofs off the smaller GPUs.
const LARGE_JOB_MIN_VRAM_BYTES: u64 = 30 * 1024 * 1024 * 1024;

/// Default blocks to scan on startup for locked-but-unfulfilled jobs (recovery).
/// Covers well beyond the longest fulfillment window on typical block times;
/// override with `chain.recovery_lookback_blocks`.
const DEFAULT_RECOVERY_LOOKBACK_BLOCKS: u64 = 50_000;

/// Default blocks to rewind the monitor start so it backfills already-open jobs at
/// startup (not just newly-submitted ones). Override with `chain.monitor_backfill_blocks`.
const DEFAULT_MONITOR_BACKFILL_BLOCKS: u64 = 5_000;

/// Default job-monitor poll interval (seconds), roughly Hemi's block time — polling
/// faster just burns eth_blockNumber/eth_getLogs calls. Override with `chain.monitor_poll_secs`.
const DEFAULT_MONITOR_POLL_SECS: u64 = 10;

/// RISC Zero Groth16 seal selector (risc0 v3.0.x). On-chain verification requires
/// the seal to be `selector ++ abi.encode(a,b,c)` (260 bytes); the worker returns
/// the bare 256-byte proof, so the miner prepends this. It is the first 4 bytes of
/// the verifier-parameters digest and is fixed per risc0 version — override via
/// config for a testnet on a different version.
const RISC0_GROTH16_SELECTOR: [u8; 4] = [0x73, 0xc4, 0x57, 0xba];

/// The resolved seal selector for this run (config override, else the default).
static SEAL_SELECTOR: std::sync::OnceLock<[u8; 4]> = std::sync::OnceLock::new();

/// Parse a 4-byte hex selector like "0x73c457ba" (or "73c457ba").
fn parse_seal_selector(s: &str) -> Option<[u8; 4]> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    let bytes = (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16));
    let v: Result<Vec<u8>, _> = bytes.collect();
    v.ok().and_then(|b| <[u8; 4]>::try_from(b.as_slice()).ok())
}

/// The RISC Zero seal selector to prefix onto seals (config override or default).
fn risc0_seal_selector() -> [u8; 4] {
    *SEAL_SELECTOR.get().unwrap_or(&RISC0_GROTH16_SELECTOR)
}

/// True if a proving error is the intermittent multi-segment invalid-proof (the
/// proof failed its own segment verification). Nondeterministic, so re-proving
/// almost always succeeds. See the rocm-multiseg-invalid-proof investigation.
fn is_invalid_proof(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("verify segment") || m.contains("proof is invalid") || m.contains("prooffailed")
}

/// Fallback cycle estimate when the contract reports 0 and no registry data is
/// available. Tuned to the largest canonical benchmark (chacha-mix @ ~34M cycles)
/// so the evaluator errs on the side of declaring jobs infeasible rather than
/// under-estimating proving time and missing deadlines.
const FALLBACK_ESTIMATED_CYCLES: u64 = 34_000_000;

/// Fallback fee rate (5%) used only if the adapter query fails.
const FALLBACK_FEE_RATE_BPS: u16 = 500;

/// Fallback default collateral ratio (150%) matching
/// `Constants.GLOBAL_DEFAULT_COLLATERAL_BPS` in HemiProve Solidity.
const FALLBACK_DEFAULT_COLLATERAL_BPS: u128 = 15_000;

/// 1 HEMI in wei (18 decimals). Used to render collateral amounts in whole HEMI.
const ONE_HEMI_WEI: u128 = 1_000_000_000_000_000_000;

/// Minimum spacing between "insufficient collateral" warnings (#14). The brain
/// re-evaluates every 5s; without throttling it would warn every tick.
const COLLATERAL_WARN_EVERY: Duration = Duration::from_secs(120);

/// How recently a 429 must have been seen for the brain to pause claiming new
/// jobs (#19). A claim kicks off descriptor reconstruction (a heavy `getLogs`
/// burst), so piling on more work while the endpoint is rate-limiting only
/// deepens the backlog. In-flight jobs (prove/fulfill/recovery) are unaffected —
/// they run in their own tasks and must finish to release collateral. Sized a
/// little above the brain's 5s tick so a single 429 gates a few ticks, not one.
const RPC_BACKOFF_WINDOW: Duration = Duration::from_secs(30);
// [#10a] Hard ceiling: even while rate-limited, the state-refresh multicall runs at least
// this often so stake_info (→ the idle-recovery collateral gate) never freezes and strands.
const REFRESH_STALENESS_CEILING: Duration = Duration::from_secs(60);
// [#10 guard] The brain won't claim on collateral data older than this (~2× the 15s refresh
// period), so a silently-failing refresh can't drive claims on stale stake_info.
const CLAIM_FRESHNESS_MAX: Duration = Duration::from_secs(35);
// [#10c] After this much rate-limit quiet, the escalated claim-pause window decays to base.
const CLAIM_BACKOFF_DECAY: Duration = Duration::from_secs(90);

/// Minimum spacing between "backing off — RPC rate-limited" warnings (#19).
const RPC_BACKOFF_WARN_EVERY: Duration = Duration::from_secs(60);

/// Render a wei amount (18 decimals) as HEMI with 2 decimals, e.g. "0.50" or
/// "150.00". Whole-HEMI truncation would show sub-1-HEMI collateral as a
/// confusing "0 HEMI", so keep two fractional digits in operator-facing messages.
fn fmt_hemi(wei: u128) -> String {
    let whole = wei / ONE_HEMI_WEI;
    let cents = (wei % ONE_HEMI_WEI) / (ONE_HEMI_WEI / 100);
    format!("{whole}.{cents:02}")
}

pub async fn run(config_path: Option<&Path>, headless: bool) -> Result<()> {
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_for_chain()?;
    let signer = load_signer(&config.wallet)?;
    let client = ChainClient::new(&config, signer).await?;
    let state = new_shared_state();

    // Initialize worker pool (before TUI, after config load)
    let benchmark_timeout = if config.prover.benchmark_timeout_secs > 0 {
        Some(std::time::Duration::from_secs(config.prover.benchmark_timeout_secs))
    } else {
        None
    };
    let mut pool = WorkerPool::new(
        config
            .prover
            .worker_binaries
            .iter()
            .map(|(k, v)| (k.clone(), PathBuf::from(v)))
            .collect::<HashMap<_, _>>(),
        config
            .prover
            .worker_search_paths
            .iter()
            .map(PathBuf::from)
            .collect(),
        benchmark_timeout,
    );
    let connected = pool.discover_and_spawn();
    if !connected.is_empty() {
        tracing::info!("Connected subprocess workers: {}", connected.join(", "));
    }
    init_worker_pool(pool);

    // Hardware probe — runs on a blocking thread to avoid freezing the system.
    // NVML init + device queries + sysfs reads can take seconds on idle GPUs.
    let (hw, tuning) = tokio::task::spawn_blocking(|| {
        let hw = zkminer_tui::hardware::probe_static();
        let tuning: Vec<zkminer_tui::gpu_tuning::GpuTuningState> =
            zkminer_tui::gpu_tuning::probe_tuning_caps(&hw)
                .into_iter()
                .map(zkminer_tui::gpu_tuning::GpuTuningState::new)
                .collect();
        (hw, tuning)
    })
    .await
    .expect("hardware probe panicked");

    // Initialize state — brief write lock, no I/O.
    {
        let mut s = state.write().await;
        s.hardware = hw;
        s.gpu_tuning = tuning;

        // Populate worker status from backend_sources()
        s.worker_status = backend_sources()
            .iter()
            .map(|(name, source)| {
                let pool = zkminer_prover::engine::worker_pool();
                let info = pool.and_then(|p| p.worker_info(name));
                WorkerStatus {
                    backend: name.to_string(),
                    source: *source,
                    healthy: match source {
                        BackendSource::InProcess => true,
                        BackendSource::Subprocess => {
                            pool.map(|p| p.is_backend_healthy(name)).unwrap_or(false)
                        }
                        BackendSource::Simulated => true,
                    },
                    pid: info.as_ref().map(|i| i.pid),
                    version: info.and_then(|i| i.sdk_version),
                }
            })
            .collect();

        // Load cached benchmarks if available.
        // If no cache, benchmarks will run in the background after TUI starts.
        if let Some(suite) = load_cached_benchmark() {
            tracing::info!(
                "Loaded cached benchmarks (zkOP/s: {:.0})",
                suite.zkops
            );
            s.add_log(
                LogLevel::Info,
                format!("Loaded cached benchmarks (zkOP/s: {:.0})", suite.zkops),
            );
            s.benchmark_results = Some(suite);
        }

        // Seed runtime settings from config. max_concurrent_proofs == 0 means
        // "auto": run one job per detected proving GPU. A positive value pins it.
        let detected_gpus = zkminer_prover::engine::worker_pool()
            .map(|p| p.proving_gpu_count())
            .unwrap_or(1);
        let resolved = resolve_max_concurrent(config.prover.max_concurrent_proofs, detected_gpus);
        if config.prover.max_concurrent_proofs == 0 {
            tracing::info!("max_concurrent_proofs=auto → {resolved} (one job per detected GPU)");
        }
        s.runtime_settings.max_concurrent_proofs = resolved;

        // Resolve the RISC Zero groth16 seal selector (config override or the
        // built-in risc0 v3.0.x default) once, for on-chain seal prefixing.
        let sel = config
            .prover
            .risc0_groth16_selector
            .as_deref()
            .and_then(parse_seal_selector)
            .unwrap_or(RISC0_GROTH16_SELECTOR);
        let _ = SEAL_SELECTOR.set(sel);
        s.runtime_settings.min_profit_threshold = config.prover.min_profit_threshold;
        s.runtime_settings.deadline_safety_margin = config.prover.deadline_safety_margin;
        s.runtime_settings.strategy = config.prover.strategy.clone();
        s.runtime_settings.electricity_cost_kwh = config.prover.electricity_cost_kwh;
        s.runtime_settings.system_power_watts = config.prover.system_power_watts;
        s.runtime_settings.token_price_usd = config.prover.token_price_usd;
        s.runtime_settings.gas_cost_usd = config.prover.gas_cost_usd;
        // Default TRUE: claim predicate jobs (so they can be tested on testnet).
        s.runtime_settings.claim_predicate_jobs =
            config.chain.claim_predicate_jobs.unwrap_or(true);

        s.address = format!("{}", client.address);
        s.connected = true;
        s.chain_id = config.chain.chain_id;

        // [RPC startup coalescing] Hydrate head + ETH/HEMI balances + stake + prover-stats in
        // ONE Multicall3 round-trip instead of 6 sequential reads, de-peaking the boot burst
        // (which — with workers connecting and the recovery scan — is where the ~5/s cap bites).
        // Per-field degrade: a single reverting sub-call only drops its own value. Fail-safe:
        // on a TOTAL failure, stake_info stays None → the collateral gate reads it as 0 and
        // blocks claims (never over-commits), and the +7s refresh loop re-hydrates before the
        // brain's first claim eval.
        let hydrated;
        match client.get_refresh_batch().await {
            Ok(data) => {
                hydrated = true;
                if let Some(block) = data.head {
                    s.block_number = block;
                }
                if let Some(eth) = data.eth_balance {
                    s.eth_balance = eth.to::<u128>();
                }
                if let Some(hemi) = data.hemi_balance {
                    s.hemi_balance = hemi.to::<u128>();
                }
                if let Some(stake) = data.stake {
                    // #15: surface the collateral picture at startup and warn if most of it is
                    // locked (e.g. tied up in past-deadline jobs) — the usual cause of a miner
                    // that connects fine but then silently claims nothing.
                    let avail = fmt_hemi(stake.available_collateral);
                    let locked = fmt_hemi(stake.locked_collateral);
                    let total = fmt_hemi(stake.total_staked);
                    tracing::info!("Collateral: {avail} HEMI available, {locked} locked, {total} staked");
                    if stake.total_staked > 0 && stake.available_collateral < stake.total_staked / 10 {
                        tracing::warn!(
                            "Low available collateral: only {avail} of {total} HEMI staked is free \
                             ({locked} locked). The miner may be unable to claim jobs — stake more, or \
                             wait for locked collateral to release."
                        );
                        s.add_log(
                            LogLevel::Warn,
                            format!("Low available collateral: {avail}/{total} HEMI free ({locked} locked)"),
                        );
                    }
                    s.stake_info = Some(stake);
                    s.last_refresh = Some(chrono::Utc::now());
                }
                if let Some(stats) = data.stats {
                    s.prover_stats = Some(stats);
                }
            }
            Err(e) => {
                hydrated = false;
                tracing::warn!(
                    "startup state hydration failed ({e:#}); the refresh loop will populate it shortly"
                );
            }
        }

        // Initialize setup status for first-run detection
        let (eth, hemi, stake) = (s.eth_balance, s.hemi_balance, s.stake_info.clone());
        s.setup_status.is_testnet = config.chain.chain_id == zkminer_chain::staking::TESTNET_CHAIN_ID;
        s.setup_status.min_staking_age_secs = config.chain.min_staking_age_secs.unwrap_or(0);
        s.setup_status.refresh_from_balances(eth, hemi, stake.as_ref());

        // Show setup wizard if not ready (first-run experience). [review] Only when the
        // startup hydration actually SUCCEEDED — otherwise a transient RPC blip in the boot
        // second reads all-zero balances/None stake, which looks identical to "unconfigured"
        // and would drop a correctly-funded operator into the Setup wizard (which nothing
        // navigates back out of once the refresh loop fixes the underlying state).
        if !hydrated {
            s.add_log(
                LogLevel::Warn,
                "Could not read on-chain state at startup — retrying in the background",
            );
        } else if !s.setup_status.is_ready() {
            s.current_screen = zkminer_tui::state::Screen::Setup;
            s.add_log(LogLevel::Info, "Setup wizard started — complete steps to begin proving");
        } else {
            s.add_log(LogLevel::Info, "Miner initialized — ready to prove");
        }
    }

    // Start job monitor
    let (monitor_tx, mut monitor_rx) = mpsc::channel::<MonitorEvent>(100);
    let monitor = JobMonitor::new(client.clone())
        .with_backfill(
            config
                .chain
                .monitor_backfill_blocks
                .unwrap_or(DEFAULT_MONITOR_BACKFILL_BLOCKS),
        )
        .with_poll_interval(Duration::from_secs(
            config
                .chain
                .monitor_poll_secs
                .unwrap_or(DEFAULT_MONITOR_POLL_SECS)
                .max(1),
        ));

    let monitor_handle = tokio::spawn(async move {
        if let Err(e) = monitor.run(monitor_tx).await {
            tracing::error!("Monitor error: {}", e);
        }
    });

    // Background task: process monitor events
    let state_clone = state.clone();
    let event_handle = tokio::spawn(async move {
        while let Some(event) = monitor_rx.recv().await {
            let mut s = state_clone.write().await;
            match event {
                MonitorEvent::JobSubmitted {
                    job_id,
                    program_id,
                    proof_system_id,
                    min_price,
                    max_price,
                    fulfillment_timeout,
                    deposited_amount,
                    ..
                } => {
                    // [RPC #3] STATIC ingest gate: a job whose proofSystemId doesn't map to
                    // a backend this build supports can never be claimed by this miner —
                    // don't let it occupy a candidate slot in the per-tick Multicall3
                    // forever. STATIC ONLY (resolve_backend is a pure keccak map): NEVER
                    // gate here on dynamic worker health / sim-mode — the monitor is
                    // forward-only with a one-shot backfill and no re-discovery, so a job
                    // dropped during a transient unhealthy-worker window would be
                    // permanently lost. The dynamic gate stays per-tick in the eval loop.
                    if resolve_backend(proof_system_id).is_none() {
                        tracing::debug!(
                            "ingest: ignoring job {} with unsupported proof system 0x{}",
                            short_id(job_id),
                            alloy::hex::encode(proof_system_id)
                        );
                        continue;
                    }
                    s.add_log(
                        LogLevel::Info,
                        format!(
                            "New job: {}... price: {}-{} timeout: {}s",
                            &format!("{}", job_id)[..10],
                            min_price / 1_000_000_000_000_000_000,
                            max_price / 1_000_000_000_000_000_000,
                            fulfillment_timeout,
                        ),
                    );

                    // Add to open jobs list
                    s.open_jobs.push(TrackedJob {
                        info: zkminer_chain::jobs::JobInfo {
                            job_id,
                            program_id,
                            caller: alloy_primitives::Address::ZERO,
                            status: 0, // Open
                            reopen_count: 0,
                            descriptor_hash: alloy_primitives::B256::ZERO,
                            deposited_amount,
                            bonus_amount: 0,
                            lock_deadline: 0,
                            prover: alloy_primitives::Address::ZERO,
                            locked_collateral: 0,
                            ramp_up_start: 0,
                            elapsed_at_lock: 0,
                            settled_price: 0,
                            min_price,
                            max_price,
                            ramp_up_period: 0,
                            curve_type: 0,
                            fulfillment_timeout,
                            lock_collateral_bps: 0,
                            speed_premium: 0,
                            exclusivity_duration: 0,
                        },
                        status: MinerJobStatus::Open,
                        current_price: min_price,
                        gpu_index: None,
                        prover_backend: String::new(),
                        estimated_cycles: 0,
                    });
                }
                // [RPC #3] Event-driven pruning: a job claimed (by ANYONE — including our
                // own claim, where this is an idempotent no-op) or cancelled is no longer
                // an open candidate. Pruning it here — straight from log data, zero extra
                // requests — removes it from the per-tick Multicall3 candidate set BEFORE
                // the next tick has to spend a chunk slot discovering the same thing.
                // GUARD (review): touch ONLY open_jobs. Never in_flight or the journal —
                // those are owned by the lifecycle/batch-reconcile paths, and a foreign
                // JobClaimed for a job WE hold would otherwise corrupt strand protection.
                MonitorEvent::JobClaimed { job_id, prover, .. } => {
                    let before = s.open_jobs.len();
                    s.open_jobs.retain(|j| j.info.job_id != job_id);
                    if s.open_jobs.len() != before {
                        tracing::debug!(
                            "pruned claimed job {} from candidates (prover {})",
                            short_id(job_id),
                            prover
                        );
                    }
                }
                MonitorEvent::JobCancelled { job_id, .. } => {
                    let before = s.open_jobs.len();
                    s.open_jobs.retain(|j| j.info.job_id != job_id);
                    if s.open_jobs.len() != before {
                        tracing::debug!("pruned cancelled job {} from candidates", short_id(job_id));
                    }
                }
                MonitorEvent::Error(msg) => {
                    tracing::warn!("Monitor error: {}", msg);
                    s.add_log(LogLevel::Error, format!("Monitor: {}", msg));
                }
                _ => {}
            }
        }
    });

    // Periodic state refresh
    let refresh_client = client.clone();
    let state_refresh = state.clone();
    let refresh_handle = tokio::spawn(async move {
        // [RPC quick-win] Phase-offset the 15s state-refresh multicall by 7s so it does not
        // land in the same second as the monitor's 10s get_logs poll (their LCM collision
        // drops from every 30s to the 60s boundary). Fixed +7s startup delay only, zero
        // extra requests. Do NOT apply this offset to the monitor/brain loops.
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + std::time::Duration::from_secs(7),
            std::time::Duration::from_secs(15),
        );
        let meter = refresh_client.rpc_meter();
        let mut cycle: u64 = 0;
        // [#10a] Circuit-breaker state: the wall-clock instant of the last get_refresh_batch
        // ATTEMPT (success OR failure). Seeded to now so the first cycle isn't force-refreshed.
        let mut last_refresh_attempt = tokio::time::Instant::now();
        loop {
            interval.tick().await;
            // Update the RPC request meter every cycle (and log it periodically so
            // headless runs can see request volume), independent of the balance refresh.
            let (rpc_total, rpc_min) = (meter.total(), meter.last_minute());
            cycle = cycle.wrapping_add(1);
            if cycle % 4 == 0 {
                tracing::info!("rpc requests: {rpc_total} total, {rpc_min}/min");
            }
            {
                let mut s = state_refresh.write().await;
                s.rpc_total = rpc_total;
                s.rpc_last_minute = rpc_min;
            }
            // [#10a] 429 CIRCUIT-BREAKER: while the endpoint is rate-limiting, SKIP the
            // Multicall3 refresh — it would just deepen the backlog, and (the bug this
            // closes) its OWN 429 re-arms the backoff meter every 15s, keeping the brain's
            // claim-pause armed forever. The free meter update above still runs.
            // STALENESS CEILING: force a refresh ATTEMPT at least every REFRESH_STALENESS_CEILING
            // even during a storm (measured from the last ATTEMPT, so a sustained storm forces
            // ~1/ceiling, not 1/15s). NOTE: this bounds ATTEMPT cadence, NOT stake_info staleness
            // — a forced attempt that itself 429s updates nothing, so stake_info can stay frozen
            // for the whole storm. The idle-recovery gate is therefore made independently robust
            // to a stale stake_info (it scans when the read is stale; see [#10 must-fix] there),
            // rather than relying on this ceiling to keep the value fresh. On clear the next
            // non-rate-limited tick refreshes naturally (≤15s).
            if meter.rate_limited_within(RPC_BACKOFF_WINDOW)
                && last_refresh_attempt.elapsed() < REFRESH_STALENESS_CEILING
            {
                continue;
            }
            last_refresh_attempt = tokio::time::Instant::now();
            // One Multicall3 round-trip for head + ETH/HEMI balances + stake,
            // done OUTSIDE the state lock so we don't hold it during I/O.
            match refresh_client.get_refresh_batch().await {
                Ok(data) => {
                    let mut s = state_refresh.write().await;
                    // Apply each field only if its sub-call succeeded; a single
                    // failed read never wipes the others (they share one snapshot).
                    if let Some(block) = data.head {
                        if block != s.block_number {
                            s.block_just_updated = true;
                        }
                        s.block_number = block;
                    }
                    if let Some(eth) = data.eth_balance {
                        s.eth_balance = eth.to::<u128>();
                    }
                    if let Some(hemi) = data.hemi_balance {
                        s.hemi_balance = hemi.to::<u128>();
                    }
                    // [review must-fix] Stamp last_refresh ONLY when the stake sub-call
                    // actually returned — matching the startup path. `last_refresh` is the
                    // #10 claim-freshness gate's proxy for "how fresh is s.stake_info", and
                    // now that sub-calls are allowFailure=true a PARTIAL success (block+
                    // balances Ok, stake reverted) is genuinely reachable. Stamping it
                    // unconditionally would report "fresh" while stake_info is frozen —
                    // exactly what the gate exists to prevent — and would also make the
                    // idle-recovery stale-scan think the collateral read is current.
                    if let Some(stake) = data.stake {
                        s.stake_info = Some(stake);
                        s.last_refresh = Some(chrono::Utc::now());
                    }
                    if let Some(stats) = data.stats {
                        s.prover_stats = Some(stats);
                    }
                    // Refresh setup status (tracks staking maturity countdown, etc.)
                    let (e, h, st) = (s.eth_balance, s.hemi_balance, s.stake_info.clone());
                    s.setup_status.refresh_from_balances(e, h, st.as_ref());
                }
                Err(e) => {
                    tracing::debug!("state refresh batch failed: {e:#}");
                }
            }
        }
    });

    // Dedicated OS thread for hardware monitoring — completely isolated from
    // the tokio runtime. NVML device handles are cached to minimize ioctls.
    let hw_input = {
        let s = state.read().await;
        zkminer_tui::hardware::HwRefreshInput {
            hardware: s.hardware.clone(),
            cpu_stat_snapshot: s.cpu_stat_snapshot.clone(),
            intel_gpu_energy: s.intel_gpu_energy.clone(),
        }
    };
    let (_hw_monitor, hw_rx) = zkminer_tui::hardware::HwMonitor::spawn(
        hw_input,
        std::time::Duration::from_secs(2),
    );
    let state_hw = state.clone();
    let hw_handle = tokio::spawn(async move {
        let mut rx = hw_rx;
        while let Some(output) = rx.recv().await {
            let mut s = state_hw.write().await;
            zkminer_tui::hardware::apply_hw_snapshot(&mut s, output);
        }
    });

    // Benchmarks are user-triggered via [b] on the Benchmark screen.
    // Auto-benchmark at startup is disabled because GPU proving in VMs with
    // passthrough GPUs causes kernel time spikes that freeze the system.
    {
        let s = state.read().await;
        if s.benchmark_results.is_none() {
            tracing::info!("No cached benchmarks — press [b] on Benchmark screen to run");
        }
    }

    // Miner brain: evaluates open jobs, claims, proves, and fulfills.
    let brain_client = client.clone();
    let brain_state = state.clone();
    let proving_timeout = Duration::from_secs(config.prover.proving_timeout_secs.max(60));
    let cost_params = CostParams {
        electricity_cost_kwh: config.prover.electricity_cost_kwh,
        system_power_watts: config.prover.system_power_watts,
        hardware_cost_per_hour: 0.0,
        gas_cost_usd: config.prover.gas_cost_usd,
    };
    let min_profit_threshold = config.prover.min_profit_threshold;
    let deadline_safety_margin = config.prover.deadline_safety_margin;
    let token_price_usd = config.prover.token_price_usd;
    let skip_benchmark_gate = config.prover.skip_benchmark_gate;
    let recovery_lookback = config
        .chain
        .recovery_lookback_blocks
        .unwrap_or(DEFAULT_RECOVERY_LOOKBACK_BLOCKS);
    let brain_handle = tokio::spawn(async move {
        miner_brain(
            brain_client,
            brain_state,
            proving_timeout,
            cost_params,
            min_profit_threshold,
            deadline_safety_margin,
            token_price_usd,
            skip_benchmark_gate,
            recovery_lookback,
        )
        .await;
    });

    if headless {
        println!("zkminer running in headless mode. Press Ctrl+C to stop.");

        // Handle both SIGINT (Ctrl+C) and SIGTERM (systemd, docker)
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate())?;
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("\nReceived SIGINT, shutting down...");
                }
                _ = sigterm.recv() => {
                    println!("\nReceived SIGTERM, shutting down...");
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await?;
            println!("\nShutting down...");
        }
    } else {
        // Run interactive TUI with chain client for setup actions
        zkminer_tui::run_tui(state.clone(), Some(client.clone())).await?;
    }

    // Graceful shutdown sequence:
    // 1. Stop claiming new jobs
    {
        let mut s = state.write().await;
        s.paused = true;
    }

    // 2. Abort background tasks
    brain_handle.abort();
    monitor_handle.abort();
    event_handle.abort();
    refresh_handle.abort();
    hw_handle.abort();

    // 3. Shutdown worker pool (sends Shutdown to all workers, SIGKILL after 5s)
    if let Some(pool) = zkminer_prover::engine::worker_pool() {
        tracing::info!("Shutting down worker pool");
        pool.shutdown_all();
    }

    // 4. Release any claimed-but-unproven jobs on-chain
    let s = state.read().await;
    for job in &s.active_jobs {
        if matches!(job.status, MinerJobStatus::Proving { .. }) {
            tracing::info!("Releasing job {} on shutdown", job.info.job_id);
            if let Err(e) = client.release_job(job.info.job_id).await {
                tracing::error!("Failed to release job {}: {}", job.info.job_id, e);
            }
        }
    }

    Ok(())
}

/// Short (10-char) id for logs.
fn short_id(id: alloy::primitives::B256) -> String {
    let s = format!("{id}");
    s.chars().take(10).collect()
}

/// Conservative synthetic benchmark used when the user opts out of running
/// the benchmark suite at startup (`skip_benchmark_gate = true`). Throughput
/// is deliberately low — it mirrors a modest GPU tier — so the evaluator
/// errs on the side of declaring long jobs infeasible rather than claiming
/// jobs we can't complete. A real benchmark overrides this as soon as one
/// runs.
fn synthetic_conservative_benchmark() -> zkminer_prover::benchmark::BenchmarkSuite {
    use std::time::Duration;
    use zkminer_prover::benchmark::{BenchmarkResult, BenchmarkSuite};
    // 1 million cycles/sec — roughly CPU-tier. The evaluator will derive
    // feasibility from this; real measured throughput will replace it.
    let throughput_cps = 1_000_000.0;
    let program = |name: &str, cycles: u64, weight: f64, precompile: bool| -> BenchmarkResult {
        BenchmarkResult {
            program_name: name.to_string(),
            prover_backend: "risc0".to_string(),
            cycles,
            duration: Duration::from_secs_f64(cycles as f64 / throughput_cps),
            throughput: throughput_cps,
            weight,
            precompile,
        }
    };
    BenchmarkSuite {
        results: vec![
            program("fibonacci",      500_000,   0.10, false),
            program("sha256-chain",   2_000_000, 0.20, true),
            program("ecdsa-verify",   5_000_000, 0.25, true),
            program("bigint-mul",     1_000_000, 0.10, false),
            program("memory-merkle",  3_000_000, 0.15, true),
            program("chacha-mix",     34_000_000, 0.20, false),
        ],
        zkops: throughput_cps,
        ..Default::default()
    }
}

/// Resolve the effective concurrent-proof limit. A configured value of 0 means
/// "auto" — one job per detected proving GPU (at least 1). Any positive value is
/// an explicit override and is used as-is.
fn resolve_max_concurrent(configured: usize, detected_gpus: usize) -> usize {
    if configured == 0 {
        detected_gpus.max(1)
    } else {
        configured
    }
}

/// RAII guard that frees an in-flight concurrency slot when a per-job task ends —
/// on the normal path OR on panic — by sending the job_id back to the brain loop.
/// Without this, a panicking task would never report done and would permanently
/// shrink the usable GPU pool by one.
struct SlotGuard(B256, mpsc::UnboundedSender<B256>);
impl Drop for SlotGuard {
    fn drop(&mut self) {
        let _ = self.1.send(self.0);
    }
}

/// Core miner brain: evaluates open jobs, claims, proves, and fulfills.
///
/// On startup, loads the on-disk job journal and reconciles each claimed
/// entry against live chain state — releasing orphaned claims before the
/// fulfillment deadline or re-driving the fulfill step for jobs we still own.
/// Subsequently loops, invoking the full profitability evaluator to decide
/// whether to claim any newly-seen open jobs.
#[allow(clippy::too_many_arguments)]
async fn miner_brain(
    client: ChainClient,
    state: zkminer_tui::state::SharedState,
    proving_timeout: Duration,
    cost_params: CostParams,
    min_profit_threshold: f64,
    deadline_safety_margin: f64,
    token_price_usd: f64,
    skip_benchmark_gate: bool,
    recovery_lookback: u64,
) {
    // Load journal + recover previously-claimed jobs from prior runs. Recovery
    // reconciles the on-disk journal AND scans the chain for locked positions the
    // journal never captured (crash before write, cleared journal, other machine),
    // so it always runs — not only when the journal is non-empty.
    let journal: SharedJournal = Arc::new(Mutex::new(JobJournal::load()));
    {
        let n = journal.lock().unwrap_or_else(|p| p.into_inner()).entries.len();
        if n > 0 {
            tracing::info!("Loaded job journal with {n} claimed entries");
        }
    }
    // [#4 residual — review must-fix] CAPTURE whether startup recovery deferred under a
    // storm (do NOT discard it): seeding the loop's `recovery_deferred` from it arms the
    // sooner-retry floor for a STARTUP-time deferral too — otherwise a miner that restarts
    // mid-storm holding a deadline-imminent, None-view lock would wait the full ~5-min
    // periodic cadence and could be slashed, the exact window this mitigation closes.
    let mut recovery_deferred =
        recover_claimed_jobs(&client, &state, &journal, proving_timeout, recovery_lookback).await;

    // Per-proof-system adapter cache. Populated lazily; adapter parameters change
    // rarely, so a best-effort cache that never expires is acceptable. Repopulate
    // on miner restart.
    let mut adapter_cache: HashMap<alloy::primitives::B256, AdapterInfo> = HashMap::new();

    // Concurrency: run one job per detected GPU (bounded by max_concurrent_proofs).
    // `in_flight` maps each in-progress job to the collateral it committed on-chain,
    // so concurrent claims don't over-commit before stake_info next refreshes;
    // finished tasks report their job_id back on `done_rx`.
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<B256>();
    let mut in_flight: HashMap<B256, u128> = HashMap::new();
    // Throttle for the "skipping all jobs — insufficient collateral" warning (#14):
    // the brain re-evaluates every 5s, so warn at most once per COLLATERAL_WARN_EVERY.
    let mut last_collateral_warn: Option<std::time::Instant> = None;
    // 429-aware claiming (#19): when the RPC is actively rate-limiting, pause
    // claiming NEW jobs (in-flight prove/fulfill keep going). Throttled warn.
    let rpc_meter = client.rpc_meter();
    let mut last_rpc_backoff_warn: Option<std::time::Instant> = None;
    // [#10c] Escalating claim-pause. Repeated storm EPISODES widen the quiet period required
    // before claims resume (30→60→120s) so the miner doesn't jump back in the instant the
    // base window lapses and immediately re-trigger the storm. Decays after CLAIM_BACKOFF_DECAY
    // of quiet or on any successful claim.
    let mut claim_backoff_mult: u32 = 1; // effective window = RPC_BACKOFF_WINDOW * mult (cap 4)
    let mut last_storm_seen: Option<std::time::Instant> = None;

    // Wait for benchmarks and initial state to settle.
    tokio::time::sleep(Duration::from_secs(10)).await;

    // [D6] The governance-set per-job collateral floor. The on-chain claim floors
    // computeCollateral() with MIN_COLLATERAL_AMOUNT, so the gate must use the SAME
    // value — not an adapter's minStake (the prover-eligibility total-stake threshold,
    // a different and typically much larger quantity, which made the gate over-provision
    // small jobs). Constant per deployment → fetch once. Fall back to the deployed
    // testnet value (10 HEMI) if the read fails so the gate still uses a sane floor.
    const FALLBACK_MIN_COLLATERAL_AMOUNT: u128 = 10_000_000_000_000_000_000; // 10 HEMI
    let min_collateral_amount = match client.get_min_collateral_amount().await {
        Ok(v) => {
            tracing::info!("MIN_COLLATERAL_AMOUNT = {} (collateral gate floor)", fmt_hemi(v));
            v
        }
        Err(e) => {
            tracing::warn!(
                "MIN_COLLATERAL_AMOUNT read failed ({e:#}); using fallback {}",
                fmt_hemi(FALLBACK_MIN_COLLATERAL_AMOUNT)
            );
            FALLBACK_MIN_COLLATERAL_AMOUNT
        }
    };

    // [H3] Periodic recovery cadence. Startup recovery runs exactly once, so a job that
    // becomes held-but-undriven LATER in the session (a deferred release whose RPC failed,
    // an unknown batch job whose lifecycle exited, a lagging-read drop) would strand to a
    // keeper slash with no restart. We re-run recovery on a timer WHEN IDLE.
    const RECOVERY_EVERY_TICKS: u64 = 60; // ~5 min at a 5s tick
    // [#4 residual] When a recovery pass DEFERS work under a rate-limit storm, retry on this
    // much shorter floor instead of waiting the full idle cadence — so a None-view job with
    // an imminent deadline gets reconciled/released as soon as the storm eases, not up to
    // ~5 min later. Floored so it can't hammer a still-storming endpoint every tick.
    const RECOVERY_DEFERRED_RETRY_TICKS: u64 = 6; // ~30s base
    let mut tick_count: u64 = 0;
    // `recovery_deferred` is seeded above from the startup pass. Count consecutive deferrals
    // to BACK OFF the retry floor (6→12→24→48 ticks) so a long-lived storm is not re-scanned
    // (find_locked_jobs getLogs + batch views run at the top of every pass, uncapped by the
    // per-job single-shot probe) every 30s — decaying toward, but never past, the periodic
    // cadence. Resets the instant a pass completes without deferring.
    let mut consecutive_defers: u32 = recovery_deferred as u32;
    let mut last_recovery_tick: u64 = 0;

    // [nonce-review round 4] Nonce-gap watchdog. A hole at the mined frontier (an evicted
    // external tx, or a below-`next` abort-gap no organic reserve refilled) leaves our
    // higher-nonce txs queued forever with NO error surfaced — a total signer wedge that
    // neither resync nor reserve can heal. Every WEDGE_CHECK_TICKS we probe for the gap;
    // only when the SAME gap PERSISTS across two probes (so a transient reserved-but-unsent
    // nonce isn't mistaken for a hole) do we fill it with a self-transfer.
    const WEDGE_CHECK_TICKS: u64 = 12; // ~60s
    let mut last_gap: Option<u64> = None;

    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        tick_count = tick_count.wrapping_add(1);

        // Reap finished job tasks before re-evaluating the concurrency budget.
        while let Ok(jid) = done_rx.try_recv() {
            in_flight.remove(&jid);
        }

        // [nonce-review round 4] Nonce-gap watchdog (persistence-gated).
        if tick_count % WEDGE_CHECK_TICKS == 0 {
            match client.nonce_gap_frontier().await {
                Ok(Some(gap)) if last_gap == Some(gap) => {
                    // Same hole seen twice → real wedge → fill it.
                    match client.heal_nonce_gap().await {
                        Ok(true) => { last_gap = None; }
                        Ok(false) => {} // fill not confirmed; retry next window
                        Err(e) => tracing::warn!("nonce gap-fill failed: {e:#}"),
                    }
                }
                Ok(Some(gap)) => last_gap = Some(gap), // first sighting; confirm next window
                Ok(None) => last_gap = None,           // no gap
                Err(e) => tracing::debug!("nonce gap probe failed: {e:#}"),
            }
        }

        // [H3] Idle-gated periodic recovery. Only when NOTHING is in flight — the same
        // safe precondition as the startup pass, so it never double-drives a job an active
        // lifecycle already owns and never races the collateral/slot accounting. When the
        // miner is idle it has spare GPUs anyway, so recovering a stranded (collateral-
        // locked, deadline-ticking) job is strictly the best use of them. find_locked_jobs
        // re-discovers anything we still hold on-chain, so even a job dropped from the
        // journal by an earlier lagging read is re-driven here.
        // [#4 residual] Run on the periodic cadence OR, if a previous pass deferred work
        // under a storm, on the shorter deferred-retry floor. The idle gate is KEPT for both
        // (dropping it would let recovery double-drive a job an active lifecycle owns) — but
        // during a storm the miner is typically idle anyway, and this removes the up-to-5-min
        // wait that could let a deferred, deadline-critical lock slip to a slash.
        let due_periodic = tick_count % RECOVERY_EVERY_TICKS == 0;
        // Back-off floor: base << (consecutive_defers-1), capped at 8× (48 ticks ≈ 4 min).
        let retry_floor = RECOVERY_DEFERRED_RETRY_TICKS
            << consecutive_defers.saturating_sub(1).min(3);
        let due_deferred =
            recovery_deferred && tick_count.saturating_sub(last_recovery_tick) >= retry_floor;
        if in_flight.is_empty() && (due_periodic || due_deferred) {
            // Gate on ON-CHAIN LOCKED COLLATERAL, not the journal — but read its FRESHNESS
            // too. [#10 must-fix] A 429 storm FREEZES stake_info: the refresh circuit-breaker
            // skips, and a forced ceiling attempt that itself 429s updates nothing — so a
            // `locked==0` from a STALE snapshot is NOT authoritative and must not veto a scan
            // (else a job locked just before the storm, whose stake_info still reads 0,
            // strands to a keeper slash). Scan when: a deferred-retry is pending (find_locked_jobs
            // is the authoritative chain scan, self-limited by #4's backoff) OR we KNOW we hold
            // collateral OR we CAN'T tell (stale read). Only a FRESH read of locked==0 skips.
            let (locked, stake_fresh) = {
                let s = state.read().await;
                let locked = s.stake_info.as_ref().map(|si| si.locked_collateral).unwrap_or(0);
                let fresh = s.last_refresh.map_or(false, |t| {
                    (chrono::Utc::now() - t)
                        .to_std()
                        .map_or(false, |d| d < REFRESH_STALENESS_CEILING)
                });
                (locked, fresh)
            };
            if due_deferred || locked > 0 || !stake_fresh {
                tracing::debug!(
                    "recovery pass (idle, {} locked{}, {tick_count} ticks{})",
                    fmt_hemi(locked),
                    if stake_fresh { "" } else { " [stale — scanning to be safe]" },
                    if due_deferred && !due_periodic { ", deferred-retry" } else { "" }
                );
                last_recovery_tick = tick_count;
                recovery_deferred =
                    recover_claimed_jobs(&client, &state, &journal, proving_timeout, recovery_lookback).await;
                // Escalate the back-off on repeated deferrals; reset once a pass completes.
                consecutive_defers = if recovery_deferred {
                    consecutive_defers.saturating_add(1)
                } else {
                    0
                };
                continue; // collateral/slots may have changed — re-evaluate next tick
            } else {
                // FRESH read AND nothing locked on-chain ⇒ genuinely nothing to reconcile.
                // (A STALE read never reaches here — it scans above — so a storm can't clear
                // an already-proven deferral.)
                recovery_deferred = false;
                consecutive_defers = 0;
            }
        }

        let (paused, open_jobs, max_concurrent, benchmarks, stake_info) = {
            let s = state.read().await;
            (
                s.paused,
                s.open_jobs.clone(),
                s.runtime_settings.max_concurrent_proofs.max(1),
                s.benchmark_results.clone(),
                s.stake_info.clone(),
            )
        };

        if paused || open_jobs.is_empty() || in_flight.len() >= max_concurrent {
            continue;
        }

        // #19 / [#10c]: don't take on new jobs while the endpoint is rate-limiting. We only
        // reach here with open jobs and spare concurrency, so a 429 in the recent window
        // means claiming now would just deepen the backlog. In-flight jobs are unaffected —
        // their prove/fulfill tasks run elsewhere. The window ESCALATES (30→60→120s) across
        // repeated storm episodes so we don't oscillate in and out of a storm.
        {
            let now = std::time::Instant::now();
            // A distinct new episode = a 429 in the BASE window after >base-window quiet.
            let fresh_storm = rpc_meter.rate_limited_within(RPC_BACKOFF_WINDOW);
            if fresh_storm {
                let new_episode =
                    last_storm_seen.map_or(true, |t| now.duration_since(t) > RPC_BACKOFF_WINDOW);
                if new_episode {
                    claim_backoff_mult = (claim_backoff_mult * 2).min(4);
                }
                last_storm_seen = Some(now);
            } else if let Some(t) = last_storm_seen {
                // Sustained quiet → decay the escalation back to base.
                if t.elapsed() >= CLAIM_BACKOFF_DECAY {
                    claim_backoff_mult = 1;
                    last_storm_seen = None;
                }
            }
            let eff_window = RPC_BACKOFF_WINDOW * claim_backoff_mult;
            if rpc_meter.rate_limited_within(eff_window) {
                let due = last_rpc_backoff_warn
                    .map_or(true, |t| now.duration_since(t) >= RPC_BACKOFF_WARN_EVERY);
                if due {
                    last_rpc_backoff_warn = Some(now);
                    tracing::warn!(
                        "Backing off — RPC rate-limited/overloaded (429/503); pausing new claims \
                         for up to {}s ({} open, {} in flight). In-flight jobs keep proving/fulfilling.",
                        eff_window.as_secs(),
                        open_jobs.len(),
                        in_flight.len(),
                    );
                    let mut s = state.write().await;
                    s.add_log(
                        LogLevel::Warn,
                        format!(
                            "RPC rate-limited — pausing new claims ({} open job(s) waiting)",
                            open_jobs.len()
                        ),
                    );
                }
                continue;
            }
        }

        // [#10 guard] Freshness precondition: never claim on stale collateral data. If the
        // refresh multicall hasn't succeeded recently (silent non-429 failure, or the just-
        // cleared post-storm tick before the forced refresh landed), skip this tick rather
        // than size a claim's collateral against a frozen stake_info. The refresh loop
        // updates last_refresh at least every REFRESH_STALENESS_CEILING even under a storm.
        {
            let stale = {
                let s = state.read().await;
                s.last_refresh
                    .map_or(true, |t| (chrono::Utc::now() - t).to_std().map_or(true, |d| d > CLAIM_FRESHNESS_MAX))
            };
            if stale {
                // Throttled WARN (not debug): if the endpoint is HEALTHY but the refresh keeps
                // failing (e.g. a Multicall3/staking-binding mismatch), claiming is paused with
                // no other symptom — this is the one operator-visible signal for that "idle
                // despite open jobs" mode. Reuses the backoff-warn throttle.
                let now = std::time::Instant::now();
                if last_rpc_backoff_warn.map_or(true, |t| now.duration_since(t) >= RPC_BACKOFF_WARN_EVERY) {
                    last_rpc_backoff_warn = Some(now);
                    tracing::warn!(
                        "Pausing claims — collateral/state data is stale (last refresh >{}s ago); \
                         RPC or the state-refresh read may be failing. In-flight jobs unaffected.",
                        CLAIM_FRESHNESS_MAX.as_secs()
                    );
                }
                continue;
            }
        }

        let benchmarks = match benchmarks {
            Some(b) => b,
            None if skip_benchmark_gate => synthetic_conservative_benchmark(),
            None => {
                // No benchmarks yet — evaluator can't make a safe decision.
                continue;
            }
        };

        // Available collateral for NEW claims this tick = on-chain available MINUS our
        // in-flight reservations. This is deliberately FAIL-SAFE (it can under-count but
        // never over-commit), for a subtle reason:
        //
        // getAvailableCollateral already nets out EVERY on-chain lock — including a
        // fresh claim once the 15s stake refresh reflects it, AND collateral stranded in
        // past-deadline jobs that never sit in `in_flight`. Subtracting Σ(in_flight) on
        // top double-counts a fresh claim's collateral during the ~15s window before the
        // refresh catches up (and, because the D6 gate reserves at max_price, over-counts
        // that window by the reservation surplus). That over-conservatism idles GPUs when
        // collateral is genuinely tight (the D17 finding) — a THROUGHPUT cost, not a
        // safety one.
        //
        // An earlier attempt used `total − max(on_chain_locked, Σ in_flight)` to remove
        // the double-count. But the two views cover DIFFERENT job sets: a stranded lock is
        // in on_chain_locked but not in in_flight, so when the (max_price-inflated)
        // reservations dominate, max() silently DROPS the stranded lock → over-counts
        // available → over-commits → the on-chain tail sub-claim reverts (wasted gas). A
        // correct tight formula needs per-job "is this reservation reflected on-chain yet"
        // tracking (a stake-refresh generation stamped on each in_flight entry); until
        // then we keep the conservative form, because idle GPUs beat on-chain reverts.
        let mut available_collateral = stake_info
            .as_ref()
            .map(|si| si.available_collateral)
            .unwrap_or(0)
            .saturating_sub(in_flight.values().copied().sum::<u128>());

        // Highest-priced open jobs first; skip any already in flight.
        let mut candidates: Vec<_> = open_jobs
            .iter()
            .filter(|j| !in_flight.contains_key(&j.info.job_id))
            .collect();
        candidates.sort_by_key(|j| std::cmp::Reverse(j.current_price));

        // Fetch EVERY candidate's status in one Multicall3 request (was one
        // getJobStatusView per candidate — the biggest per-tick RPC burst). All
        // views come from one consistent block snapshot; the helper falls back to
        // per-job calls if the chain lacks Multicall3.
        let candidate_ids: Vec<alloy::primitives::B256> =
            candidates.iter().map(|j| j.info.job_id).collect();
        let views: std::collections::HashMap<
            alloy::primitives::B256,
            zkminer_contracts::bindings::JobStatusView,
        > = client
            .get_job_status_views_batch(&candidate_ids)
            .await
            .map(|rows| {
                rows.into_iter()
                    .filter_map(|(id, ov)| ov.map(|v| (id, v)))
                    .collect()
            })
            .unwrap_or_default();

        // #14: track whether we claimed anything this tick and, if not, the cheapest
        // job we had to skip purely for lack of available collateral — so an idle
        // miner tells the operator WHY (the per-job eval reason is DEBUG-only).
        let mut claimed_this_tick = false;
        let mut cheapest_collateral_block: Option<u128> = None;
        let mut collateral_blocked_count: usize = 0;

        // Claimable candidates collected this tick: (job, snapshot, required_collateral).
        // We lock them together in one claimJobBatch tx after the eval loop (unless just
        // one, or the escape hatch is set — then the single-claim path handles each).
        let mut batch: Vec<(TrackedJob, JobStatusSnapshot, u128)> = Vec::new();

        for job in &candidates {
            let jid = job.info.job_id;
            // Guard against a double-claim: open_jobs is pushed without dedup, and a job
            // claimed earlier in THIS tick was inserted into in_flight after the candidate
            // filter ran. Either way, claiming the same job twice spawns two lifecycle
            // tasks (wasted GPU + a redundant fulfill tx), so skip if already in flight.
            if in_flight.contains_key(&jid) {
                continue;
            }
            let view = match views.get(&jid) {
                Some(v) => v.clone(),
                None => {
                    tracing::debug!("Skipping {}: no status in batch (revert/RPC miss)", short_id(jid));
                    continue;
                }
            };
            // Drop from open_jobs if it's no longer an OPEN candidate: someone else claimed
            // it (prover != ZERO) OR it left the Open state entirely (status != 0 — e.g.
            // Cancelled, status 3, prover stays ZERO so the prover check alone never evicts
            // it and it would otherwise occupy a Multicall3 slot on every tick forever).
            if view.status != 0 || view.prover != alloy::primitives::Address::ZERO {
                let mut s = state.write().await;
                s.open_jobs.retain(|j| j.info.job_id != jid);
                continue;
            }
            let snapshot = JobStatusSnapshot::from_view(&view);
            // Proving-time budget if we claim now. getJobStatusView.timeRemaining is
            // only populated for LOCKED jobs (it's lockDeadline - now); for an OPEN
            // job it is 0. So for an unclaimed job, fall back to the fulfillmentTimeout
            // carried on the JobSubmitted event (job.info.fulfillment_timeout) — the
            // window we'd get to prove once we claim. Without this the deadline check
            // treats every open job as having ~0s left and never claims.
            let time_remaining = snapshot
                .time_remaining
                .max(job.info.fulfillment_timeout)
                .max(1);

            // Pre-claim backend gate: only claim a job whose proof system we can
            // actually prove. resolve_backend maps proofSystemId → backend name;
            // backend_sources() then tells us whether that backend is real here
            // (compiled in-process or served by a healthy subprocess worker).
            // Claiming an unsupported/unbuilt system would force a release later —
            // and a voluntary release burns a penalty (RELEASE_PENALTY_FLOOR_BPS
            // minimum), so a job we can never prove is a guaranteed loss. Skipping
            // costs nothing. In pure-simulated mode every backend reports present,
            // so this gate is a no-op there and doesn't break demo/test flows.
            match resolve_backend(snapshot.proof_system_id) {
                None => {
                    tracing::debug!(
                        "Skipping {}: unsupported proof system {}",
                        short_id(jid),
                        snapshot.proof_system_id
                    );
                    continue;
                }
                Some(backend) => {
                    // Snapshot the backend sources ONCE so `available` and `sim_mode`
                    // are computed from a single consistent view (a health flip between
                    // two separate calls could otherwise disagree).
                    let sources = zkminer_prover::engine::backend_sources();
                    let available = sources
                        .iter()
                        .any(|(name, source)| {
                            *name == backend
                                && !matches!(source, BackendSource::Simulated)
                        });
                    // `available` is false only when some real backend IS compiled
                    // in (so we're not in pure-sim mode) yet THIS backend is neither
                    // in-process nor served by a healthy worker.
                    let sim_mode = sources
                        .iter()
                        .all(|(_, source)| matches!(source, BackendSource::Simulated));
                    if !available && !sim_mode {
                        tracing::debug!(
                            "Skipping {}: no {} backend available to prove it",
                            short_id(jid),
                            backend
                        );
                        continue;
                    }
                }
            }

            // Adapter lookup — cached per proofSystemId. On RPC error we fall
            // back to conservative defaults matching HemiProve Constants so the
            // evaluator still produces a safe decision.
            // `adapter_ok` is true only when the on-chain query succeeded (a cached
            // entry is always a real query — fallbacks are never cached). We use it
            // below to decide whether `status` is trustworthy enough to gate on.
            let (adapter_info, adapter_ok) = match adapter_cache.get(&snapshot.proof_system_id) {
                Some(info) => (info.clone(), true),
                None => match client.get_adapter_info(snapshot.proof_system_id).await {
                    Ok(info) => {
                        adapter_cache.insert(snapshot.proof_system_id, info.clone());
                        (info, true)
                    }
                    Err(e) => {
                        tracing::warn!(
                            "adapter query for {} failed: {e:#} — using fallback defaults",
                            alloy::hex::encode(snapshot.proof_system_id),
                        );
                        (
                            AdapterInfo {
                                adapter: alloy::primitives::Address::ZERO,
                                status: 0,
                                default_collateral_bps: FALLBACK_DEFAULT_COLLATERAL_BPS,
                                min_stake: 0,
                                fee_rate_bps: FALLBACK_FEE_RATE_BPS,
                                cycle_attestation_mode: 0,
                            },
                            false,
                        )
                    }
                },
            };

            // Adapter status gate: claimJob reverts for Disabled(3) and any non-Active
            // /non-Deprecated status (contract HemiProveCore.claimJob). Active(1) and
            // Deprecated(2) are claimable. Only gate when we have a trusted status
            // (adapter_ok) — a fallback status of 0 means "query failed", not
            // "genuinely unregistered", and we'd rather attempt than skip on a
            // transient RPC error. CUSTOM_VERIFIER jobs bypass adapter status entirely,
            // but those resolve_backend()==None and were already skipped above.
            if adapter_ok && !matches!(adapter_info.status, 1 | 2) {
                tracing::debug!(
                    "Skipping {}: adapter status {} not claimable (need Active/Deprecated)",
                    short_id(jid),
                    adapter_info.status
                );
                continue;
            }

            // Estimated cycles: trust the on-chain `expectedCycles` when set; otherwise
            // use a conservative fallback tuned to the largest canonical benchmark so
            // the evaluator errs on the side of declaring infeasible jobs infeasible.
            let estimated_cycles = if snapshot.expected_cycles > 0 {
                snapshot.expected_cycles
            } else {
                FALLBACK_ESTIMATED_CYCLES
            };

            // Required collateral: compute from the auction formula.
            // Resolution order mirrors the contract (HemiProveBase._resolveCollateralBps):
            //   1. Per-job lockCollateralBps override (if non-zero)
            //   2. Adapter defaultCollateralRatio (if non-zero)
            //   3. Global GLOBAL_DEFAULT_COLLATERAL_BPS (15000)
            // [D16] Include tier 3: a registered-Active adapter can carry
            // defaultCollateralRatio == 0, which the contract resolves to the global
            // default. Without this fallback effective_bps would be 0 → the gate would
            // pass a job needing ~0 collateral → on-chain claim locks 150% → tail revert.
            // (Tier 1 per-job override is currently never populated — the event/view don't
            // expose lockCollateralBps — but the branch is kept for when they do; see D15.)
            let effective_bps = if job.info.lock_collateral_bps > 0 {
                job.info.lock_collateral_bps as u64
            } else if adapter_info.default_collateral_bps > 0 {
                adapter_info.default_collateral_bps as u64
            } else {
                zkminer_chain::auction::GLOBAL_DEFAULT_COLLATERAL_BPS
            };
            // Collateral gate uses an UPPER BOUND on what the on-chain claim will lock,
            // NOT the current-price estimate. The claim locks
            // compute_collateral(settledPrice), where settledPrice is the auction price
            // AT EXECUTION — several seconds after this candidate snapshot (batch
            // assembly + tx mining), by which point the ascending auction has ramped the
            // price HIGHER than snapshot.current_price. Gating on the current price
            // UNDER-provisions: the miner batches N jobs believing they fit, then the tail
            // claim reverts on-chain for insufficient collateral. The 2026-07-16 soak hit
            // this in 7 of 14 batches (all 2/3): available fell to ~371 HEMI (~2.7 jobs)
            // yet every job still evaluated collateral-sufficient (its current-price
            // estimate fit the stale available), so the brain optimistically batched 3 and
            // the 3rd sub-claim reverted. max_price is the auction ceiling, so collateral
            // at max_price is the most the claim can EVER lock — gating on it means a job
            // joins the batch only if we can cover it even after a full ramp, and the
            // running `available_collateral`/`in_flight` reservations stay conservative
            // across the 15s stake_info staleness window. (Trade-off: for jobs with a long
            // ramp claimed early this over-reserves and may idle a GPU when collateral is
            // genuinely tight — which is the correct, safe behaviour: you cannot prove what
            // you cannot collateralize. The real remedy for tight collateral is to stake
            // more or free stale locked collateral, not to over-commit.)
            let required_collateral = zkminer_chain::auction::compute_collateral(
                job.info.max_price.max(snapshot.current_price),
                effective_bps,
                min_collateral_amount, // [D6] governance floor, not adapter.min_stake
            );

            let params = JobParams {
                current_price: snapshot.current_price,
                bonus_amount: snapshot.bonus_amount,
                speed_premium: snapshot.speed_premium,
                // The evaluator's speed-bonus term is gated on fulfillment_timeout > 0,
                // but the view's timeRemaining (→ snapshot.fulfillment_timeout) is 0 for
                // an OPEN job, so the bonus was silently zeroed for every claim decision.
                // Use the constant window from the JobSubmitted event; the speed premium
                // the contract actually pays at fulfill was being forfeited in selection.
                fulfillment_timeout: if job.info.fulfillment_timeout > 0 {
                    job.info.fulfillment_timeout
                } else {
                    snapshot.fulfillment_timeout
                },
                time_remaining,
                estimated_cycles,
                required_collateral,
                available_collateral,
                token_price_usd,
                fee_rate_bps: adapter_info.fee_rate_bps,
                throughput: 0.0, // use suite average
                max_price: job.info.max_price.max(snapshot.current_price),
            };
            let eval = evaluate_job(
                &benchmarks,
                &cost_params,
                &params,
                min_profit_threshold,
                deadline_safety_margin,
            );
            tracing::debug!(
                "eval {}: rec={:?} profit={:.2} HEMI/day feasible={} collateral={} cycles={} time_left={}s",
                short_id(jid),
                eval.recommendation,
                eval.estimated_profit_hemi_per_day,
                eval.deadline_feasible,
                eval.collateral_sufficient,
                params.estimated_cycles,
                time_remaining,
            );
            // #14: count + remember the cheapest job blocked SOLELY by collateral —
            // i.e. under-collateralized but otherwise on-time. Requiring
            // `deadline_feasible` avoids telling the operator to stake more for jobs
            // that would miss their deadline anyway (the evaluator reports the
            // collateral reason first, before checking the deadline).
            if !eval.collateral_sufficient && eval.deadline_feasible {
                collateral_blocked_count += 1;
                cheapest_collateral_block = Some(
                    cheapest_collateral_block
                        .map_or(required_collateral, |c| c.min(required_collateral)),
                );
            }
            if matches!(eval.recommendation, Recommendation::Claim) {
                claimed_this_tick = true;
                // Reserve the slot + collateral NOW (like the single-claim path always
                // did): inserting into in_flight immediately makes the loop-top
                // `in_flight.contains_key` guard dedup a job that appears twice in
                // open_jobs, and keeps this tick's collateral math correct. Remove from
                // open_jobs so we don't re-pick it before the claim lands. The batch is
                // dispatched after the loop; a job that doesn't actually lock has its
                // slot freed (done_tx) by the dispatch.
                in_flight.insert(jid, required_collateral);
                available_collateral = available_collateral.saturating_sub(required_collateral);
                {
                    let mut s = state.write().await;
                    s.open_jobs.retain(|j| j.info.job_id != jid);
                }
                batch.push(((*job).clone(), snapshot, required_collateral));

                // Bound to free proving slots (never lock more than we can prove before
                // their deadlines) and to the contract's MAX_BATCH_SIZE. in_flight now
                // includes this tick's collected jobs, so its length is the capacity gate.
                if in_flight.len() >= max_concurrent || batch.len() >= MAX_CLAIM_BATCH {
                    break;
                }
            }
        }

        // ── Dispatch the collected claim batch ───────────────────────────────────
        if !batch.is_empty() {
            // [#10c] We passed the rate-limit pause + freshness gates and are claiming, so
            // the endpoint is healthy again → decay the escalated claim-pause window to base.
            claim_backoff_mult = 1;
            last_storm_seen = None;
            // Force the single-claim path (which claims inside the lifecycle task) when
            // the operator opted OUT of predicate jobs: only that path runs the
            // predicate gate (a descriptor fetch that skips a non-zero expectedJournalHash
            // job before locking). Batch claiming has no per-job predicate check, so it
            // must not be used while claim_predicate_jobs=false or we'd lock a predicate
            // job the operator excluded. (Default claim_predicate_jobs=true → batch freely.)
            let claim_predicate = state.read().await.runtime_settings.claim_predicate_jobs;
            let no_batch = std::env::var("ZKMINER_NO_BATCH_CLAIM").is_ok() || !claim_predicate;
            if batch.len() == 1 || no_batch {
                // Single job (or escape hatch): the well-tested per-job path claims
                // inside the lifecycle task (already_locked=false).
                for (job, snapshot, _collateral) in batch.drain(..) {
                    let jid = job.info.job_id;
                    // Already reserved in in_flight during collection.
                    tracing::info!(
                        "CLAIM {} (price {}, in_flight {}/{})",
                        short_id(jid), job.current_price, in_flight.len(), max_concurrent
                    );
                    spawn_lifecycle_task(
                        jid, job, snapshot, false, &client, &state, &journal, &done_tx,
                        proving_timeout,
                    );
                }
            } else {
                // Multi-job: reserve every slot + breadcrumb SYNCHRONOUSLY (so the next
                // tick's collateral/slot math already accounts for them), then run the
                // claimJobBatch tx in a BACKGROUND task so the brain loop stays
                // responsive — a flaky-RPC batch claim can retry for minutes, and
                // blocking here would stall done_rx reaping and new-job evaluation.
                let jids: Vec<B256> = batch.iter().map(|(j, _, _)| j.info.job_id).collect();
                // Slots already reserved in in_flight during collection; just record a
                // claim-intent breadcrumb per job BEFORE the tx (crash-recoverable).
                for (job, snap, _collateral) in &batch {
                    journal_update(&journal, |jj| {
                        jj.record_claim_intent(job.info.job_id, snap.lock_deadline)
                    });
                }
                tracing::info!(
                    "CLAIM BATCH: {} jobs, in_flight {}/{}",
                    jids.len(), in_flight.len(), max_concurrent
                );

                let batch_jobs = std::mem::take(&mut batch);
                let client_c = client.clone();
                let journal_c = journal.clone();
                let state_c = state.clone();
                let done_tx_c = done_tx.clone();
                tokio::spawn(async move {
                    // [D4] RAII slot-reclaim guard: every jid holds a reserved in_flight
                    // slot. If this task panics or early-returns before it has dispatched a
                    // job (to a lifecycle task, which then owns the slot via its own
                    // SlotGuard, or explicitly via done_tx), that slot would leak forever —
                    // permanent concurrency starvation. The guard frees any still-pending
                    // jid on Drop, so a panic anywhere (including inside the reconcile loop)
                    // cannot leak a slot. Each dispatched job is removed from `pending` so a
                    // clean run drops an empty guard.
                    struct SlotReclaim {
                        pending: std::collections::HashSet<B256>,
                        tx: tokio::sync::mpsc::UnboundedSender<B256>,
                    }
                    impl Drop for SlotReclaim {
                        fn drop(&mut self) {
                            for jid in self.pending.drain() {
                                let _ = self.tx.send(jid);
                            }
                        }
                    }
                    let mut reclaim = SlotReclaim {
                        pending: jids.iter().copied().collect(),
                        tx: done_tx_c.clone(),
                    };

                    let batch_result = client_c.claim_job_batch(&jids).await;

                    // Reconcile per-job outcomes (partial-completion / lost races aren't
                    // visible from the tx receipt). THREE outcomes, because dropping a
                    // breadcrumb for a job we actually hold would strand it to a slash:
                    //   locked     = view present AND prover == us               → prove/fulfill
                    //   not_ours   = view present AND prover != us AND != ZERO   → safe to drop
                    //   unknown    = None, read failed, OR prover == ZERO        → KEEP breadcrumb
                    //
                    // [D1] prover == ZERO means the job still reads OPEN: either the sub-claim
                    // reverted (we don't hold it) OR — indistinguishable from a single read — a
                    // lagging/stale post-mine RPC read of a job our claimJobBatch DID lock.
                    // Treating ZERO as "not ours" would drop the breadcrumb + free the slot for
                    // a job we hold on-chain → keeper slash. So ZERO is UNKNOWN: keep the
                    // breadcrumb and keep retrying, mirroring the single-claim poll (claim_job
                    // treats prover == ZERO as "keep polling, not lost"). A Multicall3 batch can
                    // also succeed overall yet return None for one job, so None is likewise
                    // unknown, never "not ours".
                    //
                    // [D2] Only `locked` is STICKY across retries: a claim is monotonic once
                    // mined (a job seen prover == us stays ours until we fulfill/release it, and
                    // no one else can claim a job we hold), so a later flaky None must never
                    // demote a confirmed-ours job. [R2:94] `not_ours` is NOT sticky — it is
                    // re-verified every retry. A single stale RPC-replica read of a DEFUNCT prior
                    // prover (on a job that was reopened and RE-claimed by us) would otherwise
                    // stick as not_ours and drop a job we actually hold. So we re-query every
                    // not-yet-locked job each pass and rebuild not_ours from the fresh read; a
                    // stale prover that later reads as us promotes to locked.
                    let mut locked: std::collections::HashSet<B256> = Default::default();
                    let mut not_ours: std::collections::HashSet<B256> = Default::default();
                    for reconcile_try in 0..3u32 {
                        let remaining: Vec<B256> = jids
                            .iter()
                            .copied()
                            .filter(|id| !locked.contains(id)) // re-query not_ours too
                            .collect();
                        if remaining.is_empty() {
                            break; // every job is confirmed ours
                        }
                        let mut not_ours_now: std::collections::HashSet<B256> = Default::default();
                        if let Ok(rows) = client_c.get_job_status_views_batch(&remaining).await {
                            for (id, ov) in rows {
                                match classify_reconcile(ov.as_ref().map(|v| v.prover), client_c.address) {
                                    ReconcileClass::Locked => { locked.insert(id); } // sticky
                                    ReconcileClass::NotOurs => { not_ours_now.insert(id); }
                                    ReconcileClass::Unknown => {} // keep the breadcrumb, retry
                                }
                            }
                        }
                        not_ours = not_ours_now; // latest read governs (not sticky)
                        if locked.len() + not_ours.len() == jids.len() {
                            break; // every job classified this pass
                        }
                        if reconcile_try < 2 {
                            tokio::time::sleep(Duration::from_secs(3)).await;
                        }
                    }
                    let unknown = jids.len() - locked.len() - not_ours.len();
                    if let Err(e) = &batch_result {
                        tracing::warn!("claimJobBatch tx error: {e:#} ({} locked via reconcile)", locked.len());
                    }
                    tracing::info!(
                        "CLAIM BATCH result: {}/{} locked, {} lost, {} unknown(driven in-session)",
                        locked.len(), jids.len(), not_ours.len(), unknown
                    );

                    for (job, snapshot, _collateral) in batch_jobs {
                        let jid = job.info.job_id;
                        // Dispatched now (to a lifecycle SlotGuard or done_tx below), so the
                        // reclaim guard must not also free it.
                        reclaim.pending.remove(&jid);
                        if locked.contains(&jid) {
                            // Slot already reserved in the brain; the lifecycle task's
                            // SlotGuard frees it on completion. already_locked=true so it
                            // skips the (idempotent no-op) claim and the predicate gate.
                            spawn_lifecycle_task(
                                jid, job, snapshot, true, &client_c, &state_c, &journal_c,
                                &done_tx_c, proving_timeout,
                            );
                        } else if not_ours.contains(&jid) {
                            // Confirmed NOT ours (view present, prover != us): free the
                            // reserved slot (done_tx → in_flight.remove next tick) and drop
                            // the breadcrumb.
                            journal_update(&journal_c, |jj| jj.remove(jid));
                            let _ = done_tx_c.send(jid);
                        } else {
                            // UNKNOWN (view None/unreadable or prover==ZERO after all
                            // retries). [D3] DRIVE it in-session instead of abandoning it to
                            // startup-only recovery (which never runs if the process doesn't
                            // restart before the deadline → a held job strands to a slash).
                            // spawn_lifecycle_task(already_locked=true) re-verifies ownership
                            // via claim_job_idempotent — a cheap view read that returns
                            // Claimed if we hold it (→ prove+fulfill, the recovery we want),
                            // LostRace if someone else holds it (→ drop, no proof wasted), or
                            // re-attempts the claim if it still reads open. The lifecycle's
                            // SlotGuard frees the reserved slot on ANY exit path, and the
                            // lifecycle manages the breadcrumb — so this is strictly safer
                            // than freeing the slot now and hoping for a restart.
                            tracing::warn!(
                                "Job {} claim unreconciled — driving lifecycle in-session (self-verifying)",
                                short_id(jid)
                            );
                            spawn_lifecycle_task(
                                jid, job, snapshot, true, &client_c, &state_c, &journal_c,
                                &done_tx_c, proving_timeout,
                            );
                        }
                    }
                });
            }
        }

        // #14: we evaluated open jobs but claimed none, purely for lack of collateral
        // → warn (throttled). The per-job eval reason is DEBUG-only, so without this an
        // idle miner gives no clue why. Only fires when at least one job was skipped
        // specifically for collateral (early skips / lost races don't trigger it).
        if !claimed_this_tick {
            if let Some(needed) = cheapest_collateral_block {
                let now = std::time::Instant::now();
                let due = last_collateral_warn
                    .map_or(true, |t| now.duration_since(t) >= COLLATERAL_WARN_EVERY);
                if due {
                    last_collateral_warn = Some(now);
                    let avail_hemi = fmt_hemi(available_collateral);
                    let needed_hemi = fmt_hemi(needed);
                    tracing::warn!(
                        "Not claiming — {} open job(s) blocked by insufficient collateral: {} HEMI \
                         available, cheapest needs {} HEMI. Stake more, or wait for locked collateral \
                         to release.",
                        collateral_blocked_count,
                        avail_hemi,
                        needed_hemi,
                    );
                    let mut s = state.write().await;
                    s.add_log(
                        LogLevel::Warn,
                        format!(
                            "Insufficient collateral: {avail_hemi} HEMI available, cheapest of {collateral_blocked_count} blocked job(s) needs {needed_hemi} HEMI"
                        ),
                    );
                }
            }
        }
    }
}

/// Snapshot of the fields we read from getJobStatusView at decision time.
#[derive(Debug, Clone)]
struct JobStatusSnapshot {
    status: u8,
    current_price: u128,
    bonus_amount: u128,
    speed_premium: u128,
    fulfillment_timeout: u64,
    lock_deadline: u64,
    time_remaining: u64,
    expected_cycles: u64,
    descriptor_hash: alloy::primitives::B256,
    proof_system_id: alloy::primitives::B256,
}

impl JobStatusSnapshot {
    fn from_view(v: &zkminer_contracts::bindings::JobStatusView) -> Self {
        // JobStatusView does not expose `fulfillmentTimeout` directly; for an
        // unclaimed job, `timeRemaining` is the auction/proving budget that
        // would apply if we claimed now, so use it as the fulfillment_timeout
        // proxy. Once a job is locked, `timeRemaining` shrinks toward the
        // real deadline which is what we want for the evaluator.
        let time_remaining = v.timeRemaining.to::<u64>();
        Self {
            status: v.status,
            current_price: v.currentAuctionPrice.to::<u128>(),
            bonus_amount: v.bonusAmount.to::<u128>(),
            speed_premium: v.speedPremium.to::<u128>(),
            fulfillment_timeout: time_remaining,
            lock_deadline: v.lockDeadline.to::<u64>(),
            time_remaining,
            expected_cycles: v.expectedCycles,
            descriptor_hash: v.descriptorHash,
            proof_system_id: v.proofSystemId,
        }
    }
}

/// Spawn the per-job lifecycle task (prove → fulfill; claims first UNLESS
/// `already_locked`). The caller inserts the job into `in_flight` before calling this
/// so the SlotGuard/done_rx slot accounting lives in one place; the guard frees the
/// slot on return OR panic. On lifecycle error, releases the on-chain claim (when we
/// hold it) to recover collateral and avoid a slash.
///
/// `already_locked` is passed straight through as `process_job_lifecycle`'s
/// `is_recovery` flag: it's true for jobs already locked on-chain (crash recovery, or
/// a `claimJobBatch` that locked them in the brain), so the task skips the predicate
/// gate + individual claim and goes straight to prove→fulfill.
#[allow(clippy::too_many_arguments)]
fn spawn_lifecycle_task(
    jid: B256,
    job: TrackedJob,
    snapshot: JobStatusSnapshot,
    already_locked: bool,
    client: &ChainClient,
    state: &zkminer_tui::state::SharedState,
    journal: &SharedJournal,
    done_tx: &mpsc::UnboundedSender<B256>,
    proving_timeout: Duration,
) {
    let client = client.clone();
    let state = state.clone();
    let journal = journal.clone();
    let done_tx = done_tx.clone();
    tokio::spawn(async move {
        // Frees the concurrency slot on return OR panic.
        let _slot = SlotGuard(jid, done_tx);
        let outcome = process_job_lifecycle(
            &client, &state, &journal, job, snapshot, proving_timeout, already_locked, None,
        )
        .await;
        if let Err(e) = outcome {
            tracing::error!("Job {} lifecycle error: {e:#}", short_id(jid));
            {
                let mut s = state.write().await;
                s.add_log(
                    zkminer_tui::state::LogLevel::Error,
                    format!("Job {} failed: {:#}", short_id(jid), e),
                );
            }
            // Release the on-chain claim to unlock collateral and avoid slashing. If we
            // never claimed (pre-claim error), there's no journal entry and
            // release_and_clean is skipped.
            if journal_has(&journal, jid) {
                release_and_clean(&client, &state, &journal, jid).await;
            } else {
                // No breadcrumb → release is skipped. [#45] If a fulfill nonetheless
                // stashed a nonce for this job, it would leak as a permanent nonce gap;
                // recycle it so the allocator stays gap-free.
                if let Some(n) = client.take_abandoned_nonce(jid) {
                    client.abort_nonce(n);
                }
                let mut s = state.write().await;
                s.active_jobs.retain(|j| j.info.job_id != jid);
            }
        }
    });
}

/// Full lifecycle: claim → fetch descriptor → fetch ELF → prove → fulfill.
async fn process_job_lifecycle(
    client: &ChainClient,
    state: &zkminer_tui::state::SharedState,
    journal: &SharedJournal,
    job: TrackedJob,
    snapshot: JobStatusSnapshot,
    proving_timeout: Duration,
    // False for freshly-discovered jobs (the predicate gate may skip them before
    // claiming). True for jobs we ALREADY hold the lock on — crash-recovery, or a
    // `claimJobBatch` that locked them in the brain — where we must skip the predicate
    // gate and the individual claim and go straight to prove→fulfill (else we strand/
    // slash a lock we already own). `claim_job_idempotent` also no-ops for these
    // (prover == self), so the "claim" step is a single cheap view read.
    is_recovery: bool,
    // [RPC #2] A descriptor the caller already fetched+verified (recovery does), to
    // skip the re-fetch at step 6. Always `None` for fresh jobs.
    prefetched_descriptor: Option<zkminer_contracts::bindings::JobDescriptor>,
) -> Result<()> {
    use zkminer_tui::state::{LogLevel, MinerJobStatus};

    let job_id = job.info.job_id;
    let program_id = job.info.program_id;

    // 0. Predicate-job gate. A job with a non-zero `expectedJournalHash` (Phase-2
    //    predicate) reverts `JournalMismatch` at fulfill unless our proof's public
    //    values reproduce the committed journal — and we'd be slashed on timeout.
    //    When `claim_predicate_jobs` is disabled, skip such jobs BEFORE locking
    //    collateral. Recovery jobs are already locked, so they are never skipped.
    if !is_recovery {
        let claim_predicate = state.read().await.runtime_settings.claim_predicate_jobs;
        if !claim_predicate {
            // Bound this pre-claim fetch: the job is already out of `open_jobs` and
            // holds an in_flight slot, so a black-holing storage URI here would wedge
            // that concurrency slot forever (the SlotGuard only fires when the task
            // ends). An open job's lock_deadline is 0, so this uses FETCH_FALLBACK_TIMEOUT.
            // [RPC #2] Checked fetch: fast path via the monitor-cached submit tx, and —
            // review requirement — the descriptor is now HASH-VERIFIED before the gate
            // acts on expectedJournalHash (previously unverified here: a wrongly-decoded
            // descriptor could silently skip a good job or claim an excluded one).
            let descriptor = with_deadline_budget(
                snapshot.lock_deadline,
                "predicate descriptor fetch",
                job_id,
                fetch_job_descriptor_checked(client, job_id, snapshot.descriptor_hash),
            )
            .await;
            match descriptor {
                Ok(d) if d.expectedJournalHash != alloy_primitives::B256::ZERO => {
                    let mut s = state.write().await;
                    s.open_jobs.retain(|j| j.info.job_id != job_id);
                    s.add_log(
                        LogLevel::Info,
                        format!(
                            "Skipping predicate job {} (claim_predicate_jobs=false)",
                            short_id(job_id)
                        ),
                    );
                    return Ok(());
                }
                Ok(_) => {} // non-predicate job — proceed to claim
                // [review] The gate's skip decision now rides on a hash-VERIFIED fetch, so
                // if the descriptor can't be verified (unreadable, or a future
                // descriptor-hash-formula drift) it degrades to "claim". That is safe today
                // (the formula is consistent; a mis-decoded predicate job is caught by the
                // unconditional step-6 verify → release), but it silently disables the
                // exclusion — so make it observable rather than mysterious.
                Err(e) => tracing::warn!(
                    "predicate gate: descriptor for {} unverifiable ({e:#}); claiming despite \
                     claim_predicate_jobs=false — predicate exclusion is not filtering this job",
                    short_id(job_id)
                ),
            }
        }
    }

    // 1. Record claim intent BEFORE sending the claim tx, so a crash mid-claim
    //    still leaves breadcrumbs for recovery.
    journal_update(journal, |j| j.record_claim_intent(job_id, snapshot.lock_deadline));

    {
        let mut s = state.write().await;
        s.add_log(LogLevel::Info, format!("Claiming job {}...", short_id(job_id)));
    }

    // 2. Claim (idempotent).
    match client.claim_job_idempotent(job_id).await {
        Ok(ClaimOutcome::Claimed) => {}
        Ok(ClaimOutcome::LostRace) => {
            journal_update(journal, |j| j.remove(job_id));
            let mut s = state.write().await;
            s.open_jobs.retain(|j| j.info.job_id != job_id);
            s.add_log(LogLevel::Info, format!("Job {} was claimed by someone else", short_id(job_id)));
            return Ok(());
        }
        Err(e) => {
            // Ambiguous failure: the claimJob tx may have MINED (locking collateral)
            // even though we couldn't confirm it — e.g. an RPC 429 on every receipt/
            // poll path. Do NOT drop the claim-intent breadcrumb here: keep it so the
            // lifecycle-error handler runs `release_and_clean`, which checks on-chain
            // ownership and releases the collateral if we actually hold the job (and
            // drops the stale breadcrumb otherwise). Dropping it now would strand the
            // collateral until the job hits its deadline, after which releaseJob
            // reverts ("At or past deadline") — a permanent leak.
            let mut s = state.write().await;
            s.open_jobs.retain(|j| j.info.job_id != job_id);
            return Err(anyhow::anyhow!("claim failed: {e:#}"));
        }
    }

    // 3. Read fresh view post-claim to learn the authoritative lock_deadline.
    // A confirmed-claimed job always has a nonzero lockDeadline; a 0 here means a
    // node behind the claim block. Retry briefly so we don't silently disable every
    // deadline guard for this job's whole life. If it stays 0, bail → release (the
    // claim-intent breadcrumb persists, so release_and_clean re-reads and releases).
    let mut view = client
        .get_job_status_view(job_id)
        .await
        .map_err(|e| anyhow::anyhow!("getJobStatusView after claim failed: {e:#}"))?;
    let mut lock_deadline = view.lockDeadline.to::<u64>();
    let mut deadline_reads = 0u32;
    while lock_deadline == 0 && deadline_reads < DEADLINE_READ_RETRIES {
        deadline_reads += 1;
        tracing::warn!(
            "Job {} reports lockDeadline=0 post-claim (node lagging?); retry {}/{}",
            short_id(job_id), deadline_reads, DEADLINE_READ_RETRIES
        );
        tokio::time::sleep(DEADLINE_READ_RETRY_DELAY).await;
        view = client
            .get_job_status_view(job_id)
            .await
            .map_err(|e| anyhow::anyhow!("getJobStatusView retry (lockDeadline=0) failed: {e:#}"))?;
        lock_deadline = view.lockDeadline.to::<u64>();
    }
    if lock_deadline == 0 {
        return Err(anyhow::anyhow!(
            "lockDeadline still 0 after claim for {} — releasing (cannot guard the deadline)",
            short_id(job_id)
        ));
    }
    journal_update(journal, |j| j.mark_claimed(job_id, None, lock_deadline));

    {
        let mut s = state.write().await;
        s.open_jobs.retain(|j| j.info.job_id != job_id);
        s.active_jobs.push(TrackedJob {
            info: job.info.clone(),
            status: MinerJobStatus::Proving { progress: 0.0, elapsed_secs: 0 },
            current_price: view.currentAuctionPrice.to::<u128>(),
            gpu_index: None,
            prover_backend: String::new(),
            estimated_cycles: view.expectedCycles,
        });
        s.add_log(LogLevel::Success, format!("Job {} claimed", short_id(job_id)));
    }

    // 4. Resolve backend from proof system id.
    let proof_system_id = view.proofSystemId;
    let backend = resolve_backend(proof_system_id).ok_or_else(|| {
        anyhow::anyhow!("Unsupported proof system: 0x{}", alloy::hex::encode(proof_system_id))
    })?;

    // 5. Deadline gate — bail out early if we can't hope to fulfill.
    // Release responsibility is on the caller (miner_brain / recover_claimed_jobs).
    ensure_deadline_room(lock_deadline, DEADLINE_FULFILL_MARGIN_SECS)?;

    // 6. Fetch the JobDescriptor (needed for fulfillJob and for inputData).
    // Deadline-bounded: a stalled RPC/storage endpoint must not hang past the point
    // where releaseJob can still land (see with_deadline_budget).
    // [RPC #2] Recovery already fetched+verified the descriptor — reuse it instead of
    // re-fetching (3-4 RPC saved per recovered job). The verify_descriptor_hash below
    // stays UNCONDITIONAL either way, re-checking against THIS view's fresh
    // descriptorHash at zero RPC cost.
    let descriptor = match prefetched_descriptor {
        Some(d) => d,
        None => {
            with_deadline_budget(lock_deadline, "descriptor reconstruction", job_id, async {
                fetch_job_descriptor_checked(client, job_id, view.descriptorHash)
                    .await
                    .map_err(|e| anyhow::anyhow!("descriptor reconstruction failed: {e:#}"))
            })
            .await?
        }
    };
    verify_descriptor_hash(&descriptor, view.descriptorHash)
        .map_err(|e| anyhow::anyhow!("descriptor hash mismatch: {e:#}"))?;
    // programId in descriptor must match what the JobSubmitted event told us.
    if descriptor.programId != program_id {
        return Err(anyhow::anyhow!(
            "descriptor.programId {} != event.programId {}",
            descriptor.programId, program_id,
        ));
    }

    // Surface predicate jobs (the default policy claims them). Fulfilling with a
    // proof whose public values don't reproduce the committed journal reverts
    // JournalMismatch (before any payment) and risks a slash on timeout.
    if descriptor.expectedJournalHash != alloy_primitives::B256::ZERO {
        let mut s = state.write().await;
        s.add_log(
            LogLevel::Warn,
            format!(
                "Job {} is a PREDICATE job — fulfill reverts JournalMismatch unless the proof journal matches the commitment (slash risk on timeout)",
                short_id(job_id)
            ),
        );
    }

    // 7. Obtain the ELF binary (deadline-bounded — see with_deadline_budget).
    let elf = with_deadline_budget(
        lock_deadline,
        "ELF fetch",
        job_id,
        fetch_or_download_elf(client, state, program_id),
    )
    .await?;

    // 8. Deadline gate 2.
    ensure_deadline_room(lock_deadline, DEADLINE_FULFILL_MARGIN_SECS)?;

    // 9. Prove.
    {
        let mut s = state.write().await;
        s.add_log(LogLevel::Info, format!("Proving job {} with {}...", short_id(job_id), backend));
    }
    journal_update(journal, |j| j.mark_proving(job_id));

    let pool = zkminer_prover::engine::worker_pool()
        .ok_or_else(|| anyhow::anyhow!("no worker pool available"))?;
    let input_bytes: Vec<u8> = descriptor.inputData.to_vec();

    // Proactive routing: a job that commits a large cycle count starts pinned to
    // a high-VRAM GPU (0 = uncommitted → no floor; the reactive path below still
    // catches an OOM on the first attempt).
    let mut min_vram: Option<u64> =
        (snapshot.expected_cycles >= LARGE_JOB_CYCLES).then_some(LARGE_JOB_MIN_VRAM_BYTES);
    // Fix #1: slot keys of workers that wedged/timed out on this job, so a retry
    // is steered to a *different* GPU instead of being re-pinned to a flaky one.
    let mut excluded: Vec<String> = Vec::new();

    // Fix #2: scale the proving-watchdog deadline to the job so a wedged GPU is
    // caught in minutes, not the full (large) configured timeout. Committed-cycle
    // jobs get a timeout proportional to their size; uncommitted jobs (cycles == 0,
    // can't estimate) fall back to the configured cap. Always <= proving_timeout,
    // so the separate deadline/recovery planning (which uses proving_timeout) is
    // unaffected. Uses a deliberately slow CPS floor + 4x margin so a legitimately
    // slow proof is never killed.
    let effective_timeout = {
        const CONSERVATIVE_CPS: u64 = 400_000;
        const TIMEOUT_MARGIN: u64 = 4;
        const MIN_PROVING_TIMEOUT_SECS: u64 = 90;
        let cap = proving_timeout.as_secs();
        if snapshot.expected_cycles > 0 {
            let est = snapshot.expected_cycles / CONSERVATIVE_CPS * TIMEOUT_MARGIN;
            Duration::from_secs(est.clamp(MIN_PROVING_TIMEOUT_SECS.min(cap), cap))
        } else {
            proving_timeout
        }
    };

    // Which worker slot actually produced the proof (#16) — captured on success so
    // the miner log ties a job to the physical GPU that proved it.
    let mut proved_on: Option<String> = None;
    let proof = {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            // Pre-deadline release margin (#20): compute the absolute instant past
            // which this job must stop proving to still release its collateral, and
            // bail early if too little time remains to even start. `abort_at` is
            // re-checked inside the dispatcher AFTER any GPU-queue / respawn wait, so
            // queue latency can't erase the release margin, and it clamps the wedge
            // watchdog. Recomputed each attempt because retries consume wall-clock;
            // once the budget runs dry, the next iteration bails here (so a
            // deadline-driven kill never fans out into pointless cross-GPU retries).
            let abort_at = match deadline_proof_budget(lock_deadline) {
                None => None,
                Some(budget) => {
                    if budget < Duration::from_secs(MIN_ATTEMPT_BUDGET_SECS) {
                        return Err(anyhow::anyhow!(
                            "abandoning {} before deadline to recover collateral: only {}s of \
                             proving budget left (keeping {}s release margin)",
                            short_id(job_id),
                            budget.as_secs(),
                            DEADLINE_RELEASE_MARGIN_SECS,
                        ));
                    }
                    Some(std::time::Instant::now() + budget)
                }
            };
            let elf_clone = elf.clone();
            let input_clone = input_bytes.clone();
            let backend_str = backend.to_string();
            let mv = min_vram;
            let excl = excluded.clone();
            // Per-device segment size (po2). Snapshot the inputs here, then build the
            // resolver INSIDE the blocking closure — the dispatcher only knows which
            // GPU it picked after VRAM/availability filtering, so po2 cannot be chosen
            // up front. With no calibration samples `Po2Profile::from_device_benchmark`
            // returns None and `resolve_po2` yields None, i.e. the SDK keeps choosing —
            // exactly the behaviour before this was wired up.
            let (po2_overrides, cached_bench) = {
                let s = state.read().await;
                (
                    s.runtime_settings.po2_overrides.clone(),
                    s.benchmark_results.clone(),
                )
            };
            // Mirror the evaluator's estimate (run.rs eval path): trust on-chain
            // `expectedCycles`, else the conservative fallback. Using the raw field
            // would leave this 0 for every job whose submitter sends CycleConfig
            // zeroed — which is ALL jobs from `testnet_submitter_cast.sh` — and
            // `resolve_po2` requires `estimated_cycles > 0`, so po2 selection would
            // silently never engage. Note `optimal_po2_for_job` is argmax(throughput)
            // and therefore independent of the magnitude; the value only has to be
            // non-zero to enable selection.
            let est_cycles = if snapshot.expected_cycles > 0 {
                snapshot.expected_cycles
            } else {
                FALLBACK_ESTIMATED_CYCLES
            };
            let (proof_result, used_slot) = match tokio::task::spawn_blocking(move || {
                let resolve_backend = backend_str.clone();
                let po2_for_device = move |device_id: &str| -> Option<u8> {
                    let profile = cached_bench
                        .as_ref()
                        .and_then(|suite| {
                            suite.device_benchmarks.iter().find(|d| {
                                d.device_id == device_id && d.prover_backend == resolve_backend
                            })
                        })
                        .and_then(zkminer_prover::benchmark::Po2Profile::from_device_benchmark);
                    zkminer_prover::engine::resolve_po2(
                        device_id,
                        &resolve_backend,
                        est_cycles,
                        &po2_overrides,
                        profile.as_ref(),
                    )
                };
                let mut used = None;
                let r = pool.prove_min_vram(
                    &backend_str,
                    &elf_clone,
                    &input_clone,
                    None,
                    Some(effective_timeout),
                    None,
                    mv,
                    &excl,
                    &mut used,
                    abort_at,
                    Some(&po2_for_device),
                );
                (r, used)
            })
            .await
            {
                Ok(pair) => pair,
                Err(e) => return Err(anyhow::anyhow!("prove task panicked: {e}")),
            };

            match proof_result {
                Ok(p) => {
                    proved_on = used_slot;
                    break p;
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    // A deadline abort is terminal: the same deadline binds every GPU,
                    // so retrying is pointless — return so the job is released while it
                    // still can be. (The dispatcher reports these distinctly.)
                    if msg.contains("deadline") {
                        return Err(anyhow::anyhow!(
                            "proving stopped for {} (deadline): {msg}",
                            short_id(job_id)
                        ));
                    }
                    let invalid = is_invalid_proof(&msg);
                    // A genuine GPU OOM means the job is too big for that card (retry on
                    // a bigger card). Everything else non-invalid is a worker-health /
                    // transient failure — wedge/EOF, a broken-pipe send failure, IPC
                    // stream corruption/protocol desync, or a respawn backoff. The
                    // dispatcher already killed/respawned the worker, so retry on a
                    // DIFFERENT card rather than abandoning a recoverable job (the old
                    // whitelist only retried wedge/EOF and dropped the rest).
                    let real_oom = zkminer_prover_protocol::types::is_gpu_oom(&msg);
                    let health_fail = !invalid && !real_oom;
                    if attempt < MAX_PROVE_ATTEMPTS {
                        if real_oom {
                            min_vram = Some(LARGE_JOB_MIN_VRAM_BYTES);
                        } else if health_fail {
                            // Steer the retry off this worker's GPU (never strands:
                            // if excluding empties the set, the full set is used).
                            if let Some(k) = used_slot {
                                if !excluded.contains(&k) {
                                    excluded.push(k);
                                }
                            }
                        }
                        // invalid ⇒ just re-prove (round-robin may pick another worker).
                        tracing::warn!(
                            "Proof attempt {attempt}/{} for {} failed ({}); retrying{}",
                            MAX_PROVE_ATTEMPTS,
                            short_id(job_id),
                            if invalid {
                                "invalid proof"
                            } else if real_oom {
                                "GPU OOM"
                            } else {
                                "worker unhealthy"
                            },
                            if real_oom {
                                " on a high-VRAM GPU"
                            } else if health_fail {
                                " on a different GPU"
                            } else {
                                ""
                            },
                        );
                        continue;
                    }
                    return Err(anyhow::anyhow!(
                        "proving failed after {attempt} attempt(s): {msg}"
                    ));
                }
            }
        }
    };

    if let Some(slot) = &proved_on {
        tracing::info!("Job {} proved on {}", short_id(job_id), slot);
    }
    {
        let mut s = state.write().await;
        if let Some(slot) = &proved_on {
            if let Some(j) = s.active_jobs.iter_mut().find(|j| j.info.job_id == job_id) {
                j.prover_backend = slot.clone();
            }
        }
        s.add_log(
            LogLevel::Success,
            format!(
                "Proof done for {} on {} ({:.1}s, {} cycles)",
                short_id(job_id),
                proved_on.as_deref().unwrap_or(backend),
                proof.duration.as_secs_f64(),
                proof.cycles,
            ),
        );
    }

    // 10. Deadline gate 3 — final check before we pay gas to fulfill. Then bound the
    // fulfill's WALL TIME the same way we bound proving (#20): `fulfill_job` retries
    // up to ~5× a 120s receipt wait, so under a 429 storm an unbounded fulfill can
    // cross lock_deadline, after which releaseJob ALSO reverts → collateral stranded.
    // If too little time remains to fulfill AND still keep a release margin, skip
    // fulfilling and release now while releaseJob can land.
    ensure_deadline_room(lock_deadline, DEADLINE_FULFILL_MARGIN_SECS)?;
    let fulfill_budget = match deadline_proof_budget(lock_deadline) {
        None => None, // unknown deadline — no bound (mirrors the prove path)
        Some(budget) => {
            if budget < Duration::from_secs(MIN_ATTEMPT_BUDGET_SECS) {
                return Err(anyhow::anyhow!(
                    "skipping fulfill for {} — only {}s before release cutoff; releasing to \
                     recover collateral",
                    short_id(job_id),
                    budget.as_secs(),
                ));
            }
            Some(budget)
        }
    };

    // 11. Fulfill on-chain.
    journal_update(journal, |j| j.mark_fulfilling(job_id));
    {
        let mut s = state.write().await;
        if let Some(j) = s.active_jobs.iter_mut().find(|j| j.info.job_id == job_id) {
            j.status = MinerJobStatus::Submitting;
        }
        s.add_log(LogLevel::Info, format!("Submitting fulfillment for {}...", short_id(job_id)));
    }
    // RISC Zero groth16 seals must be selector-prefixed for on-chain verification;
    // the worker returns the bare 256-byte proof, so prepend the 4-byte selector.
    let seal_bytes: Vec<u8> = if backend.to_string() == "risc0" {
        let selector = risc0_seal_selector();
        let mut s = Vec::with_capacity(selector.len() + proof.seal.len());
        s.extend_from_slice(&selector);
        s.extend_from_slice(&proof.seal);
        s
    } else {
        proof.seal.clone()
    };
    // [#45] Pass the deadline budget INTO fulfill_job rather than wrapping the call in a
    // `tokio::time::timeout` that would DROP the future mid-flight — a dropped fulfill
    // never runs its give-up path, orphaning its nonce (a permanent gap) and failing to
    // STASH it for release_job's displacement. fulfill_job enforces the budget in-loop and,
    // on give-up, stashes its pending nonce so the release below reuses it to displace the
    // stuck fulfill.
    let fulfill_result = client
        .fulfill_job(
            job_id,
            descriptor,
            Bytes::from(proof.journal.clone()),
            Bytes::from(seal_bytes),
            fulfill_budget,
        )
        .await;
    fulfill_result.map_err(|e| anyhow::anyhow!("fulfillJob failed: {e:#}"))?;

    // 12. Success — drop from journal and move to completed_jobs.
    journal_update(journal, |j| j.remove(job_id));
    {
        let mut s = state.write().await;
        let completed = s.active_jobs.iter().find(|j| j.info.job_id == job_id).cloned();
        s.active_jobs.retain(|j| j.info.job_id != job_id);
        if let Some(mut cj) = completed {
            cj.status = MinerJobStatus::Fulfilled { payout: 0 };
            s.completed_jobs.push(cj);
            // Bound completed_jobs — keep most recent COMPLETED_JOBS_CAP entries.
            // Prevents unbounded memory growth over long-running operation.
            const COMPLETED_JOBS_CAP: usize = 500;
            if s.completed_jobs.len() > COMPLETED_JOBS_CAP {
                let excess = s.completed_jobs.len() - COMPLETED_JOBS_CAP;
                s.completed_jobs.drain(0..excess);
            }
        }
        s.add_log(LogLevel::Success, format!("Job {} fulfilled on-chain", short_id(job_id)));
    }

    Ok(())
}

fn resolve_backend(proof_system_id: alloy::primitives::B256) -> Option<&'static str> {
    if proof_system_id == zkminer_chain::auction::risc_zero_v1_id() {
        Some("risc0")
    } else if proof_system_id == zkminer_chain::auction::sp1_v1_id() {
        Some("sp1")
    } else if proof_system_id == zkminer_chain::auction::openvm_v1_id() {
        Some("openvm")
    } else {
        None
    }
}

/// Remaining time we may spend proving a job before we must stop and release it,
/// keeping [`DEADLINE_RELEASE_MARGIN_SECS`] of room before `lock_deadline` so a
/// `releaseJob` still lands (it reverts at/after the deadline, stranding the
/// collateral until a slash). Returns `None` when the deadline is unknown (0) —
/// no clamp is applied. `Some(0)` means no budget is left at all.
fn deadline_proof_budget(lock_deadline: u64) -> Option<Duration> {
    if lock_deadline == 0 {
        return None;
    }
    let now = chrono::Utc::now().timestamp() as u64;
    Some(Duration::from_secs(
        lock_deadline.saturating_sub(now.saturating_add(DEADLINE_RELEASE_MARGIN_SECS)),
    ))
}

/// Run a pre-prove RPC/HTTP step (descriptor reconstruction, ELF fetch) bounded so
/// it cannot outlive the job's release margin. These steps run AFTER the claim locks
/// collateral but BEFORE the prove watchdog exists, and hit submitter-controlled
/// storage URIs — a black-hole/slow-loris server would otherwise hang the task
/// forever, stranding collateral past the deadline AND permanently wedging a
/// concurrency slot (the `SlotGuard` never fires). On timeout (or too little budget)
/// returns Err so the caller releases while `releaseJob` can still land.
async fn with_deadline_budget<T>(
    lock_deadline: u64,
    what: &str,
    job_id: alloy::primitives::B256,
    fut: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let budget = deadline_proof_budget(lock_deadline).unwrap_or(FETCH_FALLBACK_TIMEOUT);
    if budget < Duration::from_secs(MIN_ATTEMPT_BUDGET_SECS) {
        return Err(anyhow::anyhow!(
            "skipping {what} for {} — only {}s before release cutoff; releasing to recover collateral",
            short_id(job_id),
            budget.as_secs(),
        ));
    }
    match tokio::time::timeout(budget, fut).await {
        Ok(r) => r,
        Err(_) => Err(anyhow::anyhow!(
            "{what} for {} exceeded its {}s deadline budget (stalled endpoint?) — releasing to \
             recover collateral",
            short_id(job_id),
            budget.as_secs(),
        )),
    }
}

/// Ensure there is at least `margin_secs` of headroom before `lock_deadline`.
/// If `lock_deadline` is 0, no check is performed (we don't know the deadline yet).
fn ensure_deadline_room(lock_deadline: u64, margin_secs: u64) -> Result<()> {
    if lock_deadline == 0 {
        return Ok(());
    }
    let now = chrono::Utc::now().timestamp() as u64;
    if now.saturating_add(margin_secs) >= lock_deadline {
        anyhow::bail!(
            "deadline too close: now={}, lock_deadline={}, margin={}s",
            now, lock_deadline, margin_secs,
        );
    }
    Ok(())
}

async fn fetch_or_download_elf(
    client: &ChainClient,
    state: &zkminer_tui::state::SharedState,
    program_id: alloy::primitives::B256,
) -> Result<Vec<u8>> {
    let cache = zkminer_chain::programs::ElfCache::new();
    // Query the registry for the canonical content hash so we can verify cached
    // bytes. For SP1 `program_id` is the vkey (not keccak256(elf)), so we cannot
    // use program_id as the content hash. If the registry is unavailable (not
    // configured, or the program isn't registered — e.g. an advisory registry is
    // down), fall back to a cached ELF: the on-chain verifier binds programId to
    // the guest image id, so a wrong ELF cannot yield a passing proof anyway.
    let info = match client.get_program_info(program_id).await {
        Ok(info) => info,
        Err(e) => {
            if let Some(elf) = cache.get(&program_id, None) {
                tracing::warn!(
                    "ProgramRegistry unavailable ({e:#}); using cached ELF for {} ({} bytes)",
                    program_id,
                    elf.len(),
                );
                return Ok(elf);
            }
            return Err(anyhow::anyhow!(
                "ProgramRegistry query failed and no cached ELF for {}: {e:#}",
                program_id
            ));
        }
    };
    // First trusted URI's content hash — zero means "unspecified", skip verify.
    let expected_content_hash = info
        .storage_uris
        .iter()
        .map(|u| u.content_hash)
        .find(|h| *h != alloy::primitives::B256::ZERO);
    if let Some(elf) = cache.get(&program_id, expected_content_hash) {
        tracing::info!("Using cached ELF for {} ({} bytes)", program_id, elf.len());
        return Ok(elf);
    }
    {
        let mut s = state.write().await;
        s.add_log(
            LogLevel::Info,
            format!("Downloading ELF '{}' ({} URIs)", info.name, info.storage_uris.len()),
        );
    }
    let elf = zkminer_chain::programs::download_elf(&info.storage_uris, info.elf_hash)
        .await
        .map_err(|e| anyhow::anyhow!("ELF download failed: {e:#}"))?;
    if let Err(e) = cache.put(&program_id, &elf) {
        tracing::warn!("Failed to cache ELF: {e:#}");
    }
    Ok(elf)
}

async fn release_and_clean(
    client: &ChainClient,
    state: &zkminer_tui::state::SharedState,
    journal: &SharedJournal,
    job_id: alloy::primitives::B256,
) {
    // The breadcrumb may be ambiguous — a claim whose tx we never confirmed (it may
    // have reverted / never landed, or it may have mined and locked collateral).
    // Check on-chain ownership first so we don't fire a guaranteed-to-revert
    // releaseJob (wasted gas + extra RPC pressure during a 429 storm) on a job we
    // never actually locked. If the check itself fails (RPC), fall through and
    // attempt the release anyway — recovering collateral we might hold outweighs a
    // wasted tx, and a failed release is retained for startup recovery.
    if let Ok(view) = client.get_job_status_view(job_id).await {
        // JobStatus::Locked == 1. releaseJob reverts (JobNotLocked) on anything else,
        // so skip a guaranteed-revert tx when the job isn't ours OR is no longer Locked
        // — the latter catches the race where a fulfill we started actually landed just
        // as we gave up waiting (status now Fulfilled, but prover still == us).
        const JOB_STATUS_LOCKED: u8 = 1;
        let not_ours = view.prover != client.address;
        let not_locked = view.status != JOB_STATUS_LOCKED;
        if not_ours || not_locked {
            let why = if not_ours {
                if view.prover == alloy::primitives::Address::ZERO {
                    "never locked on-chain"
                } else {
                    "held by another prover"
                }
            } else {
                "no longer locked (fulfilled or released)"
            };
            journal_update(journal, |j| j.remove(job_id));
            // [#45] This path SKIPS release_job (the only stash consumer). If a fulfill
            // stashed its nonce for this job, drain it here or it becomes a permanent gap
            // that wedges the whole signer. The fulfill either mined (abort self-heals via
            // "nonce too low") or never landed (abort correctly recycles the gap).
            if let Some(n) = client.take_abandoned_nonce(job_id) {
                client.abort_nonce(n);
            }
            let mut s = state.write().await;
            s.active_jobs.retain(|j| j.info.job_id != job_id);
            s.add_log(
                LogLevel::Info,
                format!("Job {} {} — dropped stale claim breadcrumb", short_id(job_id), why),
            );
            return;
        }
        // releaseJob also reverts ("At or past deadline") once we're at/past
        // lock_deadline. Don't pay gas for that guaranteed revert on every call/
        // restart — retain the breadcrumb; when a keeper slashes the job, prover/status
        // flip and the not-ours/not-locked drop above purges it. (This is the already-
        // stranded case; only a slash frees the collateral now.)
        let now = chrono::Utc::now().timestamp() as u64;
        let lock_deadline = view.lockDeadline.to::<u64>();
        if lock_deadline != 0 && now >= lock_deadline {
            tracing::warn!(
                "Job {} is past its deadline ({} >= {}) — releaseJob would revert; retaining \
                 breadcrumb (collateral stranded until a keeper slash)",
                short_id(job_id), now, lock_deadline,
            );
            // [#45] Past-deadline SKIPS release_job — drain the fulfill stash so a stashed
            // nonce can't wedge the signer. (The stuck fulfill may still be pending at N;
            // recycling it lets a reuser evict/replace it, self-healing via "nonce too low"
            // if it later mines — far better than a permanent gap.)
            if let Some(n) = client.take_abandoned_nonce(job_id) {
                client.abort_nonce(n);
            }
            let mut s = state.write().await;
            s.active_jobs.retain(|j| j.info.job_id != job_id);
            s.add_log(
                LogLevel::Warn,
                format!("Job {} past deadline — cannot release (stranded until slash)", short_id(job_id)),
            );
            return;
        }
    }

    let release_ok = match client.release_job(job_id).await {
        Ok(()) => {
            journal_update(journal, |j| j.remove(job_id));
            true
        }
        Err(e) => {
            // Keep the journal entry so recovery on next startup can retry.
            tracing::error!(
                "release_job({}) RPC failed: {e:#} — journal entry retained for recovery",
                job_id,
            );
            false
        }
    };
    let mut s = state.write().await;
    s.active_jobs.retain(|j| j.info.job_id != job_id);
    if release_ok {
        s.add_log(LogLevel::Warn, format!("Released job {}", short_id(job_id)));
    } else {
        s.add_log(
            LogLevel::Error,
            format!("Release failed for {} — retained in journal, will retry on restart", short_id(job_id)),
        );
    }
}

/// Save the journal, logging a warning on error. All transitional state writes
/// go through this helper so that disk-full / permission errors are visible
/// rather than silently swallowed.
fn save_journal_or_warn(journal: &JobJournal) {
    if let Err(e) = journal.save() {
        tracing::warn!("journal.save() failed: {e:#} — recovery on next restart may be stale");
    }
}

/// The proving journal, shared across concurrent per-job tasks (one job per GPU).
type SharedJournal = Arc<Mutex<JobJournal>>;

/// Apply a mutation to the shared journal and persist it, holding the lock only
/// for the brief mutation (never across an `.await`). Recovers from a poisoned
/// lock (a panicked task) rather than cascading the panic.
fn journal_update(journal: &SharedJournal, f: impl FnOnce(&mut JobJournal)) {
    let mut j = journal.lock().unwrap_or_else(|p| p.into_inner());
    f(&mut j);
    save_journal_or_warn(&j);
}

/// True if the shared journal currently holds an entry for `job_id`.
fn journal_has(journal: &SharedJournal, job_id: B256) -> bool {
    journal
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .entries
        .contains_key(&job_id)
}

/// Reconcile a journal loaded from disk against live chain state.
///
/// For each entry: query getJobStatusView. If we no longer hold the lock
/// (someone else fulfilled, released-by-keeper, etc.) drop it from the
/// journal. If we do hold the lock, check the deadline: if there is enough
/// room try to resume by re-driving the fulfill path in a new task; if not,
/// release to cap the penalty.
/// Reconcile locked jobs. Returns `true` if the pass was cut short by a rate-limit storm
/// (some locked jobs left un-reconciled) so the caller can schedule a SOONER retry than the
/// idle ~5-min cadence — otherwise a None-view, imminent-deadline job could cross its
/// deadline before the next pass and be slashed.
async fn recover_claimed_jobs(
    client: &ChainClient,
    state: &zkminer_tui::state::SharedState,
    journal: &SharedJournal,
    proving_timeout: Duration,
    lookback_blocks: u64,
) -> bool {
    // Reconcile everything the journal is tracking, PLUS any job this miner has
    // locked on-chain that the journal doesn't know about (crash before the
    // journal write, a cleared journal, or a claim from a previous machine).
    let mut job_ids: Vec<B256> = journal
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .entries
        .keys()
        .cloned()
        .collect();
    match client.find_locked_jobs(lookback_blocks).await {
        Ok(onchain) => {
            let mut discovered = 0usize;
            for jid in onchain {
                if !job_ids.contains(&jid) {
                    job_ids.push(jid);
                    discovered += 1;
                }
            }
            if discovered > 0 {
                tracing::info!(
                    "recover: discovered {discovered} on-chain locked job(s) not in the journal"
                );
            }
        }
        Err(e) => tracing::warn!("recover: on-chain locked-job scan failed: {e:#}"),
    }
    if !job_ids.is_empty() {
        tracing::info!("recover: reconciling {} claimed/locked job(s)", job_ids.len());
    }

    // [M9] Fetch EVERY candidate's view in ONE (chunked) batch and FILTER to jobs we
    // currently hold Locked, up front. The prior code did a per-job getJobStatusView for
    // each of (potentially 100+) historically-claimed jobs every recovery pass — a
    // recurring RPC storm that 429s a rate-limited endpoint and starves live proving.
    // Terminal/not-ours jobs are dropped from the journal here using the batch views; only
    // the few still-Locked ones proceed to the serial, expensive re-drive, and the loop
    // REUSES the fetched view instead of re-reading it.
    let views_map: std::collections::HashMap<B256, zkminer_contracts::bindings::JobStatusView> =
        client
            .get_job_status_views_batch(&job_ids)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(jid, v)| v.map(|view| (jid, view)))
            .collect();

    const JOB_STATUS_LOCKED: u8 = 1;
    let before = job_ids.len();
    job_ids.retain(|jid| match views_map.get(jid) {
        // Ours AND still Locked → re-drive.
        Some(v) if v.prover == client.address && v.status == JOB_STATUS_LOCKED => true,
        // Present but settled / held by another prover → drop the stale breadcrumb.
        Some(_) => {
            journal_update(journal, |j| j.remove(*jid));
            false
        }
        // View unreadable (RPC miss / lagging node) → keep and re-read per-job (lag-tolerant).
        None => true,
    });
    if before != job_ids.len() {
        tracing::info!(
            "recover: dropped {} settled/not-ours; {} still Locked to re-drive",
            before - job_ids.len(),
            job_ids.len()
        );
    }

    // Deadline-sort the survivors (soonest-first), reusing the fetched views.
    job_ids.sort_by_key(|jid| {
        views_map
            .get(jid)
            .map(|v| {
                let d = v.lockDeadline.to::<u64>();
                if d == 0 { u64::MAX } else { d }
            })
            .unwrap_or(u64::MAX)
    });

    // [#4 residual mitigation] `deferred` = the pass broke under a storm (caller retries
    // sooner). `storm_probed` = we already spent our ONE single-shot re-read this pass, so
    // subsequent unreadable jobs defer without fanning out.
    let mut deferred = false;
    let mut storm_probed = false;
    for jid in job_ids {
        // Reuse the batched view; only re-read the rare unreadable ones.
        let view = match views_map.get(&jid) {
            Some(v) => v.clone(),
            None => {
                // [#4] A None view means the batch couldn't read this job. The deadline-sort
                // ranks None-view jobs LAST (u64::MAX), so every readable (Some) job with a
                // real deadline has ALREADY been driven by the time we reach one.
                let rate_limited = client
                    .rpc_meter()
                    .rate_limited_within(std::time::Duration::from_secs(5));
                // Under a storm, per-job re-reads are the amplifier this change exists to
                // kill. [#4 residual] But spend ONE bounded single-shot probe on the first
                // unreadable job so a genuinely time-critical locked job still gets a
                // release-to-avoid-slash chance — then defer the rest (they keep their
                // journal breadcrumbs and are retried on the SOONER cadence). Never a fanout.
                if rate_limited && storm_probed {
                    tracing::warn!(
                        "recover: rate-limited — deferring {} and any remaining unreadable jobs to a sooner retry",
                        jid
                    );
                    deferred = true;
                    break;
                }
                if rate_limited {
                    storm_probed = true;
                }
                match client.get_job_status_view(jid).await {
                    Ok(v) => v,
                    Err(e) => {
                        if rate_limited {
                            // The one probe was itself rate-limited → defer the rest and
                            // signal a sooner retry rather than grinding the storm.
                            tracing::warn!(
                                "recover: storm probe of {} failed ({e:#}) — deferring, will retry sooner",
                                jid
                            );
                            deferred = true;
                            break;
                        }
                        tracing::warn!("recover: view for {} failed: {e:#}", jid);
                        continue;
                    }
                }
            }
        };
        if view.prover != client.address {
            tracing::info!("recover: {} no longer ours (prover={})", jid, view.prover);
            journal_update(journal, |j| j.remove(jid));
            continue;
        }
        // Terminal status check. Contract JobStatus: Open=0, Locked=1,
        // Fulfilled=2, Released=3, Cancelled=4. Only Locked jobs can be
        // fulfilled; any other state means the job has settled (commonly
        // a crash between our fulfill tx landing and the following
        // `journal.remove`). Re-driving lifecycle on a non-Locked job
        // guarantees a revert cycle and wastes gas.
        if view.status != 1 {
            tracing::info!(
                "recover: {} has non-Locked status {} — dropping stale journal entry",
                jid, view.status,
            );
            journal_update(journal, |j| j.remove(jid));
            continue;
        }
        let lock_deadline = view.lockDeadline.to::<u64>();
        let now = chrono::Utc::now().timestamp() as u64;
        // Recovery needs much more headroom than a fresh-claim fulfill because
        // we must re-download ELF and re-prove from scratch. Use the proving
        // timeout as the prove-time budget plus fulfill margin.
        let recovery_margin = proving_timeout.as_secs() + DEADLINE_FULFILL_MARGIN_SECS;
        if lock_deadline > 0 && now + recovery_margin >= lock_deadline {
            tracing::warn!(
                "recover: {} past deadline room (now={} deadline={} margin={}s) — releasing",
                jid, now, lock_deadline, recovery_margin,
            );
            release_and_clean(client, state, journal, jid).await;
            continue;
        }

        // Attempt to re-drive the fulfill path. Reconstruct a TrackedJob from
        // the view. If this fails at any step the error path calls
        // release_and_clean via the outer brain loop.
        let job_info = zkminer_chain::jobs::JobInfo {
            job_id: jid,
            program_id: alloy::primitives::B256::ZERO, // unknown without the event; descriptor will fill it
            caller: view.caller,
            status: view.status,
            reopen_count: view.reopenCount,
            descriptor_hash: view.descriptorHash,
            deposited_amount: view.depositedAmount.to::<u128>(),
            bonus_amount: view.bonusAmount.to::<u128>(),
            lock_deadline,
            prover: view.prover,
            locked_collateral: 0,
            ramp_up_start: 0,
            elapsed_at_lock: view.auctionTimeElapsed.to::<u64>(),
            settled_price: view.settledPrice.to::<u128>(),
            min_price: 0,
            max_price: view.currentAuctionPrice.to::<u128>(),
            ramp_up_period: view.rampUpPeriod.to::<u64>(),
            curve_type: 0,
            fulfillment_timeout: view.timeRemaining.to::<u64>(),
            lock_collateral_bps: 0,
            speed_premium: view.speedPremium.to::<u128>(),
            exclusivity_duration: 0,
        };
        let snapshot = JobStatusSnapshot::from_view(&view);

        // We need program_id to fetch the ELF — derive from the descriptor.
        // [RPC #2] Checked fetch (fast path + verified); the descriptor is then handed
        // to process_job_lifecycle below so it is fetched ONCE per recovered job.
        let descriptor = match fetch_job_descriptor_checked(client, jid, view.descriptorHash).await {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("recover: descriptor fetch for {} failed: {e:#} — releasing", jid);
                release_and_clean(client, state, journal, jid).await;
                continue;
            }
        };
        if let Err(e) = verify_descriptor_hash(&descriptor, view.descriptorHash) {
            tracing::error!("recover: descriptor hash verify failed for {}: {e:#} — releasing", jid);
            release_and_clean(client, state, journal, jid).await;
            continue;
        }

        let mut tracked = TrackedJob {
            info: job_info,
            status: zkminer_tui::state::MinerJobStatus::Proving { progress: 0.0, elapsed_secs: 0 },
            current_price: view.currentAuctionPrice.to::<u128>(),
            gpu_index: None,
            prover_backend: String::new(),
            estimated_cycles: view.expectedCycles,
        };
        tracked.info.program_id = descriptor.programId;

        tracing::info!("recover: re-driving fulfill path for {}", jid);
        if let Err(e) = process_job_lifecycle(client, state, journal, tracked, snapshot, proving_timeout, true, Some(descriptor)).await {
            tracing::error!("recover: {} lifecycle failed: {e:#}", jid);
            release_and_clean(client, state, journal, jid).await;
        }
    }
    deferred
}

async fn spawn_streaming_benchmark(state: zkminer_tui::state::SharedState) {
    use zkminer_tui::state::{BenchmarkTracker, LogLevel};

    // Initialize tracker
    {
        let mut s = state.write().await;
        s.benchmark_running = true;
        s.benchmark_tracker = Some(BenchmarkTracker {
            devices: Vec::new(),
            all_complete: false,
            started_at: Some(chrono::Utc::now()),
            active_device_index: 0,
        });
        s.add_log(LogLevel::Info, "Starting GPU benchmarks...");
    }

    let state_for_progress = state.clone();
    let suite = tokio::task::spawn_blocking(move || {
        let (sync_tx, sync_rx) =
            std::sync::mpsc::channel::<zkminer_prover::dispatcher::BenchmarkProgressEvent>();

        // Bridge: forwards benchmark progress events to TUI state.
        // Uses tokio mpsc channel to avoid block_on deadlocks with limited workers.
        let (bridge_tx, mut bridge_rx) =
            tokio::sync::mpsc::channel::<zkminer_prover::dispatcher::BenchmarkProgressEvent>(32);
        let bridge_state = state_for_progress.clone();

        tokio::spawn(async move {
            while let Some(event) = bridge_rx.recv().await {
                let mut s = bridge_state.write().await;
                if let Some(tracker) = s.benchmark_tracker.as_mut() {
                    tracker.on_progress(
                        &event.slot_key,
                        event.gpu_name.as_deref(),
                        event.device_index,
                        &event.gpu_tag,
                        &event.entry,
                        event.program_index,
                        event.total_programs,
                    );
                }
                s.add_log(
                    LogLevel::Info,
                    format!(
                        "{}: {} done ({:.1}M c/s)",
                        event.slot_key,
                        event.entry.program_name,
                        event.entry.throughput / 1_000_000.0
                    ),
                );
            }
        });

        let bridge = std::thread::spawn(move || {
            while let Ok(event) = sync_rx.recv() {
                if bridge_tx.blocking_send(event).is_err() {
                    break;
                }
            }
        });

        let on_progress = move |event: zkminer_prover::dispatcher::BenchmarkProgressEvent| {
            let _ = sync_tx.send(event);
        };
        let suite = run_benchmark_gpu_only_streaming(&on_progress);
        drop(on_progress); // drops sync_tx, closing the channel
        let _ = bridge.join();
        suite
    })
    .await
    .unwrap_or_default();

    // Finalize
    let mut s = state.write().await;
    save_benchmark(&suite);
    let gpu_count = suite.device_benchmarks.len();
    s.benchmark_results = Some(suite);
    s.benchmark_running = false;
    s.benchmark_tracker = None;
    s.add_log(
        LogLevel::Success,
        format!("GPU benchmarks complete ({gpu_count} device entries)"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256};

    #[test]
    fn classify_reconcile_treats_zero_and_none_as_unknown() {
        let us = Address::with_last_byte(0xAB);
        let other = Address::with_last_byte(0xCD);
        // Held by us → Locked.
        assert_eq!(classify_reconcile(Some(us), us), ReconcileClass::Locked);
        // Held by a different, non-zero prover → definitively not ours.
        assert_eq!(classify_reconcile(Some(other), us), ReconcileClass::NotOurs);
        // [D1] prover == ZERO (job reads OPEN) → UNKNOWN, NOT NotOurs: a lagging
        // post-mine read of a job we actually locked must not be dropped to a slash.
        assert_eq!(classify_reconcile(Some(Address::ZERO), us), ReconcileClass::Unknown);
        // Absent/unreadable view → UNKNOWN (keep the breadcrumb, retry).
        assert_eq!(classify_reconcile(None, us), ReconcileClass::Unknown);
    }

    #[test]
    fn ensure_deadline_room_accepts_zero_deadline_as_unknown() {
        // A lock_deadline of 0 means we don't know the deadline yet; never block.
        assert!(ensure_deadline_room(0, 60).is_ok());
        assert!(ensure_deadline_room(0, 10_000).is_ok());
    }

    #[test]
    fn resolve_max_concurrent_auto_vs_explicit() {
        // 0 = auto → one job per detected GPU (min 1).
        assert_eq!(resolve_max_concurrent(0, 3), 3);
        assert_eq!(resolve_max_concurrent(0, 1), 1);
        assert_eq!(resolve_max_concurrent(0, 0), 1); // never 0
        // Positive = explicit override, regardless of GPU count.
        assert_eq!(resolve_max_concurrent(2, 3), 2);
        assert_eq!(resolve_max_concurrent(5, 1), 5);
    }

    #[test]
    fn ensure_deadline_room_rejects_when_deadline_too_close() {
        let now = chrono::Utc::now().timestamp() as u64;
        // Deadline 30s away with 60s margin → reject.
        assert!(ensure_deadline_room(now + 30, 60).is_err());
        // Deadline in the past → reject.
        assert!(ensure_deadline_room(now.saturating_sub(100), 60).is_err());
    }

    #[test]
    fn ensure_deadline_room_accepts_when_deadline_far_enough() {
        let now = chrono::Utc::now().timestamp() as u64;
        // Deadline 1 hour away with 60s margin → accept.
        assert!(ensure_deadline_room(now + 3600, 60).is_ok());
    }

    #[test]
    fn resolve_backend_maps_known_proof_systems() {
        assert_eq!(
            resolve_backend(zkminer_chain::auction::risc_zero_v1_id()),
            Some("risc0")
        );
        assert_eq!(
            resolve_backend(zkminer_chain::auction::sp1_v1_id()),
            Some("sp1")
        );
        assert_eq!(
            resolve_backend(zkminer_chain::auction::openvm_v1_id()),
            Some("openvm")
        );
    }

    #[test]
    fn resolve_backend_returns_none_for_unknown() {
        assert_eq!(resolve_backend(B256::ZERO), None);
        assert_eq!(resolve_backend(B256::repeat_byte(0xFF)), None);
    }

    #[test]
    fn short_id_formats_consistently() {
        // B256 Display emits "0x" + 64 hex chars. `short_id` takes first 10 chars.
        let all_zero = short_id(B256::ZERO);
        assert_eq!(all_zero.len(), 10);
        assert!(all_zero.starts_with("0x"));

        let all_ff = short_id(B256::repeat_byte(0xFF));
        assert_eq!(all_ff.len(), 10);
        assert!(all_ff.starts_with("0xff"));
    }

}
