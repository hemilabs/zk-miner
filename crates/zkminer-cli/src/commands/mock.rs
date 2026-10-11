use std::collections::HashMap;
use std::time::Duration;

use alloy_primitives::{Address, B256};
use anyhow::Result;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use zkminer_chain::auction::{self, CurveType};
use zkminer_chain::jobs::JobInfo;
use zkminer_chain::staking::{ProverStatistics, StakeInfo};
use zkminer_prover::benchmark::{
    load_cached_benchmark, run_benchmark_gpu_only_streaming, save_benchmark, BenchmarkSuite,
    DeviceBenchmark, PROVER_BACKENDS,
};
use zkminer_strategy::cost_model::CostParams;
use zkminer_strategy::evaluator::{self, JobParams, Recommendation};
use zkminer_tui::state::{new_shared_state, LogLevel, MinerJobStatus, SharedState, TrackedJob};

const ETHER: u128 = 1_000_000_000_000_000_000;

// Mock configuration (hardcoded)
const INITIAL_ETH: u128 = 2_500_000_000_000_000_000; // 2.5 ETH
const INITIAL_HEMI: u128 = 50_000 * ETHER;
const INITIAL_STAKE: u128 = 25_000 * ETHER;
const START_BLOCK: u64 = 1_234_000;
const MIN_JOB_INTERVAL_SECS: u64 = 8;
const MAX_JOB_INTERVAL_SECS: u64 = 25;
const GAS_FEE: u128 = 500_000_000_000_000; // 0.0005 ETH

// Strategy parameters (protocol constant, not user-configurable)
const PROTOCOL_FEE_BPS: u16 = 250; // 2.5% protocol fee

fn mock_address() -> Address {
    "0xd3adb33f00000000000000000000000000000001"
        .parse()
        .unwrap()
}

fn random_address(rng: &mut impl Rng) -> Address {
    let mut bytes = [0u8; 20];
    rng.fill(&mut bytes);
    Address::from(bytes)
}

fn random_b256(rng: &mut impl Rng) -> B256 {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    B256::from(bytes)
}

fn seed_state(state: &mut zkminer_tui::state::MinerState) {
    state.address = format!("{}", mock_address());
    state.connected = true;
    state.block_number = START_BLOCK;
    state.eth_balance = INITIAL_ETH;
    state.hemi_balance = INITIAL_HEMI.saturating_sub(INITIAL_STAKE);
    state.stake_info = Some(StakeInfo {
        total_staked: INITIAL_STAKE,
        locked_collateral: 0,
        available_collateral: INITIAL_STAKE,
        unstake_amount: 0,
        unstake_request_time: 0,
        deposit_block: 1_000_000,
    });
    state.prover_stats = Some(ProverStatistics {
        jobs_fulfilled: 0,
        jobs_slashed: 0,
        jobs_released: 0,
        total_earned: 0,
        first_fulfillment_at: 0,
        last_fulfillment_at: 0,
    });
    // Benchmarks loaded after seed_state returns (see run())
    state.add_log(LogLevel::Info, "Mock mode initialized");
    state.add_log(
        LogLevel::Info,
        format!("Prover address: {}", mock_address()),
    );
    state.add_log(
        LogLevel::Success,
        format!(
            "Staked: {} HEMI | Available: {} HEMI",
            INITIAL_STAKE / ETHER,
            INITIAL_STAKE / ETHER
        ),
    );
}

pub async fn run(headless: bool) -> Result<()> {
    let state = new_shared_state();

    // Spawn worker pool so GPU provers are available for real benchmarks.
    // This discovers binaries in ~/.zkminer/provers/, $PATH, etc.
    {
        let mut pool = zkminer_prover::dispatcher::WorkerPool::new(
            HashMap::new(),                            // no explicit binaries in mock mode
            Vec::new(),                                // default search paths
            Some(std::time::Duration::from_secs(600)), // 10 min benchmark timeout
        );
        let connected = pool.discover_and_spawn();
        if !connected.is_empty() {
            tracing::info!("Connected subprocess workers: {}", connected.join(", "));
        }
        zkminer_prover::engine::init_worker_pool(pool);
    }

    // Seed initial state
    {
        let mut s = state.write().await;
        seed_state(&mut s);
    }

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

    // Apply results under a brief write lock (no I/O).
    {
        let mut s = state.write().await;
        s.hardware = hw;
        s.gpu_tuning = tuning;

        // Populate worker status from backend_sources()
        s.worker_status = zkminer_prover::engine::backend_sources()
            .iter()
            .map(|(name, source)| {
                let pool = zkminer_prover::engine::worker_pool();
                let info = pool.and_then(|p| p.worker_info(name));
                zkminer_tui::state::WorkerStatus {
                    backend: name.to_string(),
                    source: *source,
                    healthy: match source {
                        zkminer_prover::engine::BackendSource::InProcess => true,
                        zkminer_prover::engine::BackendSource::Subprocess => {
                            pool.map(|p| p.is_backend_healthy(name)).unwrap_or(false)
                        }
                        zkminer_prover::engine::BackendSource::Simulated => true,
                    },
                    pid: info.as_ref().map(|i| i.pid),
                    version: info.and_then(|i| i.sdk_version),
                }
            })
            .collect();

        // Load cached benchmarks if available.
        // If no cache, benchmarks will run in the background after TUI starts.
        if let Some(suite) = load_cached_benchmark() {
            s.add_log(
                LogLevel::Info,
                format!("Loaded cached benchmarks (zkOP/s: {:.0})", suite.zkops),
            );
            s.benchmark_results = Some(suite);
        }
    }

    // Load cached benchmarks or skip — auto-benchmark is triggered by user
    // pressing [b] in the Benchmark screen, not at startup. GPU proving in
    // this VM causes kernel time spikes that freeze the system during benchmarks.
    {
        let s = state.read().await;
        if s.benchmark_results.is_none() {
            tracing::info!("No cached benchmarks — press [b] on Benchmark screen to run");
        }
    }

    // Spawn background tasks
    let block_handle = tokio::spawn(block_ticker(state.clone()));
    let job_handle = tokio::spawn(job_generator(state.clone()));
    let brain_handle = tokio::spawn(miner_brain(state.clone()));
    // Spawn dedicated OS thread for hardware monitoring — completely isolated
    // from the tokio runtime. NVML device handles are cached to minimize ioctls.
    let hw_input = {
        let s = state.read().await;
        zkminer_tui::hardware::HwRefreshInput {
            hardware: s.hardware.clone(),
            cpu_stat_snapshot: s.cpu_stat_snapshot.clone(),
            intel_gpu_energy: s.intel_gpu_energy.clone(),
        }
    };
    let (_hw_monitor, hw_rx) =
        zkminer_tui::hardware::HwMonitor::spawn(hw_input, Duration::from_secs(2));
    let hw_handle = tokio::spawn(hardware_receiver(state.clone(), hw_rx));

    if headless {
        println!("zkminer running in mock mode (headless). Press Ctrl+C to stop.");
        // In headless mode, print logs to stdout
        let log_state = state.clone();
        let log_handle = tokio::spawn(async move {
            let mut last_total_seen: u64 = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let s = log_state.read().await;
                // Use monotonic counter to determine how many new entries to print.
                // The deque is bounded at 1000, but log_total_added always increases.
                let new_count = (s.log_total_added - last_total_seen) as usize;
                let new_count = new_count.min(s.activity_log.len());
                for entry in s
                    .activity_log
                    .iter()
                    .rev()
                    .take(new_count)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                {
                    println!(
                        "[{}] {:?}: {}",
                        entry.timestamp.format("%H:%M:%S"),
                        entry.level,
                        entry.message
                    );
                }
                last_total_seen = s.log_total_added;
            }
        });

        tokio::signal::ctrl_c().await?;
        println!("\nShutting down...");
        log_handle.abort();
    } else {
        zkminer_tui::run_tui(state.clone(), None).await?;
    }

    block_handle.abort();
    job_handle.abort();
    brain_handle.abort();
    hw_handle.abort();

    Ok(())
}

/// Increments block_number every ~2 seconds (Hemi block time).
async fn block_ticker(state: SharedState) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        interval.tick().await;
        let mut s = state.write().await;
        s.block_number += 1;
        s.last_refresh = Some(chrono::Utc::now());
    }
}

/// Generates random jobs every 8-25 seconds.
async fn job_generator(state: SharedState) {
    let mut rng = StdRng::from_entropy();

    // Small delay before first job
    tokio::time::sleep(Duration::from_secs(3)).await;

    loop {
        let delay = rng.gen_range(MIN_JOB_INTERVAL_SECS..=MAX_JOB_INTERVAL_SECS);
        tokio::time::sleep(Duration::from_secs(delay)).await;

        let job_id = random_b256(&mut rng);
        let caller = random_address(&mut rng);

        let min_price_hemi: u128 = rng.gen_range(5..=50);
        let max_price_hemi: u128 = rng.gen_range((min_price_hemi + 10)..=250);
        let min_price = min_price_hemi * ETHER;
        let max_price = max_price_hemi * ETHER;

        let fulfillment_timeout: u64 = rng.gen_range(5..=30) * 60; // 5-30 min
        let ramp_up_period: u64 = rng.gen_range(10..=60) * 60; // 10-60 min
        let curve_type: u8 = if rng.gen_bool(0.7) { 0 } else { 1 }; // 70% linear
        let collateral_bps: u128 = 15000; // 150%
        let deposited = max_price + max_price / 5; // max_price + 20% buffer
        let bonus: u128 = rng.gen_range(0..=5) * ETHER;
        let speed_premium: u128 = rng.gen_range(0..=3) * ETHER;

        let block_number = {
            let s = state.read().await;
            s.block_number
        };

        // ramp_up_start = current block timestamp (approximate: block * 2s from genesis)
        let ramp_up_start = block_number * 2;

        let descriptor_hash = random_b256(&mut rng);

        // Derive required prover backend from descriptor hash (deterministic per job)
        let backend_idx = descriptor_hash.as_slice()[2] as usize % PROVER_BACKENDS.len();
        let required_backend = PROVER_BACKENDS[backend_idx].to_string();

        let job = TrackedJob {
            info: JobInfo {
                job_id,
                program_id: alloy::primitives::B256::ZERO, // mock mode
                caller,
                status: 0, // Open
                reopen_count: 0,
                descriptor_hash,
                deposited_amount: deposited,
                bonus_amount: bonus,
                lock_deadline: 0,
                prover: Address::ZERO,
                locked_collateral: 0,
                ramp_up_start,
                elapsed_at_lock: 0,
                settled_price: 0,
                min_price,
                max_price,
                ramp_up_period,
                curve_type,
                fulfillment_timeout,
                lock_collateral_bps: collateral_bps,
                speed_premium,
                exclusivity_duration: 0,
            },
            status: MinerJobStatus::Open,
            current_price: min_price, // starts at min, will be updated by brain
            gpu_bus_id: None,
            prover_backend: required_backend,
            estimated_cycles: 0,
        };

        let curve_label = if curve_type == 0 {
            "Linear"
        } else {
            "Quadratic"
        };

        let mut s = state.write().await;
        let backend_label = job.prover_backend.clone();
        s.open_jobs.push(job);
        s.add_log(
            LogLevel::Info,
            format!(
                "New job: {}... {} | price: {}-{} HEMI | timeout: {}m | curve: {}",
                &format!("{}", job_id)[..10],
                backend_label,
                min_price_hemi,
                max_price_hemi,
                fulfillment_timeout / 60,
                curve_label,
            ),
        );
    }
}

/// Main miner logic: evaluate, claim, prove, fulfill jobs.
///
/// Holds the state write lock for the entire iteration. This is acceptable
/// because all operations are pure in-memory computation (no I/O, no NVML
/// calls) — the lock is held for sub-millisecond durations. If this ever
/// gains I/O operations, refactor to snapshot → compute → apply pattern.
async fn miner_brain(state: SharedState) {
    let mut rng = StdRng::from_entropy();
    let mut prove_targets: HashMap<B256, u64> = HashMap::new();

    // Wait for first jobs to appear
    tokio::time::sleep(Duration::from_secs(5)).await;

    let mut interval = tokio::time::interval(Duration::from_secs(3));
    loop {
        interval.tick().await;

        let mut s = state.write().await;
        let current_block = s.block_number;
        let current_time = current_block * 2; // approximate timestamp

        // Phase 1: Update prices on open jobs
        for job in s.open_jobs.iter_mut() {
            let elapsed = current_time.saturating_sub(job.info.ramp_up_start);
            let curve = if job.info.curve_type == 0 {
                CurveType::Linear
            } else {
                CurveType::Quadratic
            };
            job.current_price = auction::compute_price(
                job.info.min_price,
                job.info.max_price,
                job.info.ramp_up_period,
                curve,
                elapsed,
            );
        }

        // Phase 2: Evaluate & claim (allow one job per device)
        // Collect device IDs already busy with an active job
        let busy_devices: Vec<Option<String>> =
            s.active_jobs.iter().map(|j| j.gpu_bus_id.clone()).collect();

        let max_concurrent = s.runtime_settings.max_concurrent_proofs;
        if !s.open_jobs.is_empty() && !s.paused && s.active_jobs.len() < max_concurrent {
            let benchmarks = s.benchmark_results.clone().unwrap_or_default();
            let available_collateral = s
                .stake_info
                .as_ref()
                .map(|si| si.available_collateral)
                .unwrap_or(0);

            // Read strategy parameters from runtime settings
            let min_profit = s.runtime_settings.min_profit_threshold;
            let safety_margin = s.runtime_settings.deadline_safety_margin;
            let token_price = s.runtime_settings.token_price_usd;
            let elec_cost = s.runtime_settings.electricity_cost_kwh;
            let gas_cost = s.runtime_settings.gas_cost_usd;
            let system_overhead = s.runtime_settings.system_power_watts;

            // Estimate cycles for each open job
            for job in s.open_jobs.iter_mut() {
                if job.estimated_cycles == 0 {
                    job.estimated_cycles = estimate_job_cycles(job);
                }
            }

            // Evaluate each (job, device) pair.
            // Only devices that support the job's required backend are considered.
            let mut best: Option<(usize, DeviceChoice, evaluator::JobEvaluation)> = None;

            for (idx, job) in s.open_jobs.iter().enumerate() {
                let required_collateral = auction::compute_collateral(
                    job.current_price,
                    job.info.lock_collateral_bps as u64,
                    ETHER,
                );

                // Only consider devices that benchmark this job's backend,
                // are not already busy, and are not disabled in settings
                let devices = devices_for_backend(&benchmarks, &job.prover_backend);

                // Skip if backend is disabled
                if s.runtime_settings
                    .disabled_backends
                    .contains(&job.prover_backend)
                {
                    continue;
                }

                for device in &devices {
                    if busy_devices.contains(&device.gpu_bus_id) {
                        continue;
                    }
                    // Skip disabled devices and device-backend combos
                    if s.runtime_settings
                        .disabled_devices
                        .contains(&device.device_id)
                    {
                        continue;
                    }
                    if s.runtime_settings
                        .disabled_device_backends
                        .contains(&(device.device_id.clone(), job.prover_backend.clone()))
                    {
                        continue;
                    }
                    let cost_params =
                        build_cost_params_for_device(elec_cost, gas_cost, system_overhead);
                    let params = JobParams {
                        current_price: job.current_price,
                        bonus_amount: job.info.bonus_amount,
                        speed_premium: job.info.speed_premium,
                        fulfillment_timeout: job.info.fulfillment_timeout,
                        time_remaining: job.info.fulfillment_timeout,
                        estimated_cycles: job.estimated_cycles,
                        required_collateral,
                        available_collateral,
                        token_price_usd: token_price,
                        fee_rate_bps: PROTOCOL_FEE_BPS,
                        throughput: device.throughput,
                        max_price: job.info.max_price,
                        // Name the card, so the duration above and the electricity charged
                        // describe the same device.
                        device_watts: device_watts_for(device),
                    };

                    let eval = evaluator::evaluate_job(
                        &benchmarks,
                        &cost_params,
                        &params,
                        min_profit,
                        safety_margin,
                    );

                    if eval.recommendation == Recommendation::Claim {
                        let dominated = best.as_ref().is_some_and(|(_, _, prev)| {
                            prev.estimated_profit_usd >= eval.estimated_profit_usd
                        });
                        if !dominated {
                            best = Some((idx, device.clone(), eval));
                        }
                    }
                }
            }

            if let Some((idx, device, eval)) = best {
                // Claim the winning job on the chosen device
                let mut job = s.open_jobs.remove(idx);
                let settled_price = job.current_price;
                let collateral = auction::compute_collateral(
                    settled_price,
                    job.info.lock_collateral_bps as u64,
                    ETHER,
                );

                job.info.settled_price = settled_price;
                job.info.locked_collateral = collateral;
                job.info.lock_deadline = current_time + job.info.fulfillment_timeout;
                job.info.prover = mock_address();
                job.info.elapsed_at_lock = current_time.saturating_sub(job.info.ramp_up_start);
                job.info.status = 1; // Locked
                job.status = MinerJobStatus::Proving {
                    progress: 0.0,
                    elapsed_secs: 0,
                };
                job.current_price = settled_price;
                job.gpu_bus_id = device.gpu_bus_id.clone();
                // prover_backend was already set at job creation (required backend)

                // Deduct collateral from available
                if let Some(ref mut stake) = s.stake_info {
                    stake.locked_collateral += collateral;
                    stake.available_collateral =
                        stake.total_staked.saturating_sub(stake.locked_collateral);
                }

                // In mock mode, force proving to take 1-5 minutes for visibility.
                // Real mode would use eval.estimated_proving_time_secs.
                let prove_time: u64 = rng.gen_range(60..=300);
                prove_targets.insert(job.info.job_id, prove_time);

                s.add_log(
                    LogLevel::Success,
                    format!(
                        "Claimed job {}... {} on {} | {} HEMI | {:.1}M cycles | ETA: {}s | {:.1} HEMI/day",
                        &format!("{}", job.info.job_id)[..10],
                        job.prover_backend,
                        device.device_id,
                        settled_price / ETHER,
                        job.estimated_cycles as f64 / 1_000_000.0,
                        prove_time,
                        eval.estimated_profit_hemi_per_day,
                    ),
                );

                s.active_jobs.push(job);
            } else {
                // Log the best skip reason for the highest-priced job.
                // Extract values before the mutable borrow for add_log.
                let skip_info = s
                    .open_jobs
                    .iter()
                    .max_by_key(|j| j.current_price)
                    .map(|top_job| {
                        let devices = devices_for_backend(&benchmarks, &top_job.prover_backend);
                        let required_collateral = auction::compute_collateral(
                            top_job.current_price,
                            top_job.info.lock_collateral_bps as u64,
                            ETHER,
                        );

                        // Use the fastest available device for this backend
                        let (throughput, device_watts, cost_params) = if let Some(d) =
                            devices.first()
                        {
                            (
                                d.throughput,
                                device_watts_for(d),
                                build_cost_params_for_device(elec_cost, gas_cost, system_overhead),
                            )
                        } else {
                            (benchmarks.average_throughput(), None, CostParams::default())
                        };

                        let params = JobParams {
                            current_price: top_job.current_price,
                            bonus_amount: top_job.info.bonus_amount,
                            speed_premium: top_job.info.speed_premium,
                            fulfillment_timeout: top_job.info.fulfillment_timeout,
                            time_remaining: top_job.info.fulfillment_timeout,
                            estimated_cycles: top_job.estimated_cycles,
                            required_collateral,
                            available_collateral,
                            token_price_usd: token_price,
                            fee_rate_bps: PROTOCOL_FEE_BPS,
                            throughput,
                            max_price: top_job.info.max_price,
                            device_watts,
                        };
                        let eval = evaluator::evaluate_job(
                            &benchmarks,
                            &cost_params,
                            &params,
                            min_profit,
                            safety_margin,
                        );
                        let reason = match &eval.recommendation {
                            Recommendation::Skip { reason } => reason.clone(),
                            Recommendation::WatchAndWait => "price may rise, watching".to_string(),
                            _ => "no profitable jobs".to_string(),
                        };
                        let job_id_short = format!("{}", top_job.info.job_id)[..10].to_string();
                        let backend = top_job.prover_backend.clone();
                        let cycles = top_job.estimated_cycles;
                        (
                            job_id_short,
                            backend,
                            reason,
                            cycles,
                            eval.estimated_proving_time_secs,
                        )
                    });

                if let Some((job_id_short, backend, reason, cycles, eta)) = skip_info {
                    s.add_log(
                        LogLevel::Warn,
                        format!(
                            "Skipped job {}... {} ({} | {:.1}M cycles | ETA: {:.0}s)",
                            job_id_short,
                            backend,
                            reason,
                            cycles as f64 / 1_000_000.0,
                            eta,
                        ),
                    );
                }
            }
        }

        // Phase 3: Progress proving jobs
        let mut proof_complete_logs: Vec<String> = Vec::new();
        for job in s.active_jobs.iter_mut() {
            if let MinerJobStatus::Proving {
                ref mut progress,
                ref mut elapsed_secs,
            } = job.status
            {
                *elapsed_secs += 3;
                if let Some(&target) = prove_targets.get(&job.info.job_id) {
                    *progress = (*elapsed_secs as f64 / target as f64).min(1.0);

                    if *progress >= 1.0 {
                        job.status = MinerJobStatus::Submitting;
                        proof_complete_logs.push(format!(
                            "Proof complete for {}... submitting on-chain",
                            &format!("{}", job.info.job_id)[..10],
                        ));
                    }
                }
            }
        }
        for msg in proof_complete_logs {
            s.add_log(LogLevel::Info, msg);
        }

        // Phase 4: Fulfill submitted jobs
        let mut to_fulfill: Vec<usize> = Vec::new();
        for (i, job) in s.active_jobs.iter().enumerate() {
            if matches!(job.status, MinerJobStatus::Submitting) {
                to_fulfill.push(i);
            }
        }

        // Process in reverse to maintain valid indices during removal
        for &i in to_fulfill.iter().rev() {
            let mut job = s.active_jobs.remove(i);
            let time_remaining = job.info.lock_deadline.saturating_sub(current_time);

            let (net_payout, _protocol_fee, _speed_bonus) = auction::estimate_prover_reward(
                job.info.settled_price,
                job.info.bonus_amount,
                job.info.speed_premium,
                time_remaining,
                job.info.fulfillment_timeout,
                PROTOCOL_FEE_BPS,
            );

            // Release collateral
            if let Some(ref mut stake) = s.stake_info {
                stake.locked_collateral = stake
                    .locked_collateral
                    .saturating_sub(job.info.locked_collateral);
                stake.available_collateral =
                    stake.total_staked.saturating_sub(stake.locked_collateral);
            }

            // Credit payout, deduct gas
            s.hemi_balance += net_payout;
            s.eth_balance = s.eth_balance.saturating_sub(GAS_FEE);

            // Update prover stats
            if let Some(ref mut stats) = s.prover_stats {
                stats.jobs_fulfilled += 1;
                stats.total_earned += net_payout;
                stats.last_fulfillment_at = current_time;
                if stats.first_fulfillment_at == 0 {
                    stats.first_fulfillment_at = current_time;
                }
            }

            prove_targets.remove(&job.info.job_id);

            job.status = MinerJobStatus::Fulfilled { payout: net_payout };

            s.add_log(
                LogLevel::Success,
                format!(
                    "Fulfilled job {}... payout: {:.2} HEMI",
                    &format!("{}", job.info.job_id)[..10],
                    net_payout as f64 / ETHER as f64,
                ),
            );

            s.completed_jobs.push(job);
        }

        // Phase 5: Expire stale open jobs
        let mut expired: Vec<usize> = Vec::new();
        for (i, job) in s.open_jobs.iter().enumerate() {
            let auction_end = job.info.ramp_up_start + job.info.ramp_up_period;
            let expiry = auction_end + job.info.fulfillment_timeout;
            if current_time > expiry {
                expired.push(i);
            }
        }
        for &i in expired.iter().rev() {
            let mut job = s.open_jobs.remove(i);
            job.status = MinerJobStatus::Skipped {
                reason: "auction expired".to_string(),
            };
            s.add_log(
                LogLevel::Warn,
                format!(
                    "Job {}... expired (auction window closed)",
                    &format!("{}", job.info.job_id)[..10],
                ),
            );
            s.completed_jobs.push(job);
        }

        // Keep completed_jobs from growing unbounded
        if s.completed_jobs.len() > 100 {
            let drain_count = s.completed_jobs.len() - 100;
            s.completed_jobs.drain(..drain_count);
        }
    }
}

/// Receives hardware telemetry from the dedicated monitor thread and
/// applies it to shared state under a brief write lock.
async fn hardware_receiver(
    state: SharedState,
    mut rx: tokio::sync::mpsc::Receiver<zkminer_tui::hardware::HwRefreshOutput>,
) {
    while let Some(output) = rx.recv().await {
        let mut s = state.write().await;
        zkminer_tui::hardware::apply_hw_snapshot(&mut s, output);
    }
}

// ---------------------------------------------------------------------------
// Strategy helpers
// ---------------------------------------------------------------------------

/// A candidate device for proving a specific job.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct DeviceChoice {
    /// Device identifier: "cpu", "gpu0", "gpu1", etc.
    device_id: String,
    /// Human-readable label.
    device_label: String,
    /// `None` = CPU, `Some(bus)` = the GPU's PCI bus id.
    ///
    /// Was a `gpu_index` parsed out of `"gpuN"` -- the PROVER's namespace -- and
    /// then compared against `GpuInfo.index`, a display ordinal. Those disagree on
    /// any mixed-vendor box, so the mock attributed jobs to the wrong card.
    gpu_bus_id: Option<String>,
    /// Prover backend this device will use.
    prover_backend: String,
    /// Throughput in cycles/sec for this (device, backend) pair.
    throughput: f64,
    /// Device power draw in watts.
    power_watts: f64,
}

impl DeviceChoice {
    fn from_benchmark(db: &DeviceBenchmark) -> Self {
        let gpu_bus_id = if db.device_id == "cpu" || db.pci_bus_id.is_empty() {
            None
        } else {
            Some(db.pci_bus_id.clone())
        };
        DeviceChoice {
            device_id: db.device_id.clone(),
            device_label: db.device_label.clone(),
            gpu_bus_id,
            prover_backend: db.prover_backend.clone(),
            throughput: db.throughput,
            power_watts: db.power_watts,
        }
    }
}

/// Get all devices capable of proving with the given backend, sorted by
/// throughput descending (fastest first).
fn devices_for_backend(benchmarks: &BenchmarkSuite, backend: &str) -> Vec<DeviceChoice> {
    let mut devices: Vec<DeviceChoice> = benchmarks
        .devices_for_backend(backend)
        .into_iter()
        .map(DeviceChoice::from_benchmark)
        .collect();
    devices.sort_by(|a, b| {
        b.throughput
            .partial_cmp(&a.throughput)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    devices
}

/// Build cost params for a specific device.
///
/// Carries only the fixed OVERHEAD in `base_overhead_watts`; `evaluate_job` adds the measured
/// CPU and the named card. This used to compose the total here instead — correctly, while the
/// production path did not — and that divergence is why the production bug survived. Composing
/// in one place means a caller can no longer forget.
fn build_cost_params_for_device(
    electricity_cost_kwh: f64,
    gas_cost_usd: f64,
    system_overhead_watts: f64,
) -> CostParams {
    CostParams {
        electricity_cost_kwh,
        base_overhead_watts: system_overhead_watts,
        hardware_cost_per_hour: 0.0,
        gas_cost_usd,
    }
}

/// The draw to charge for this device choice.
///
/// `Some(0.0)` for a CPU-only choice — its draw is already the suite's `cpu_power_watts`, and
/// saying `None` there would mean "no device named" and charge the mean card for a job that
/// touches no GPU. A GPU choice reports its own watts whether or not its `pci_bus_id` is known:
/// keying on the bus id discarded a measured figure for a card whose identity was simply not
/// recorded, while still using that card's throughput.
fn device_watts_for(device: &DeviceChoice) -> Option<f64> {
    if device.device_id == zkminer_prover::benchmark::CPU_DEVICE_ID {
        Some(0.0)
    } else {
        Some(device.power_watts)
    }
}

/// Estimate the cycle count for a job based on its on-chain parameters.
///
/// In production the cycle count comes from the job descriptor (program +
/// input size).  In mock mode we derive a deterministic estimate from the
/// max_price and descriptor_hash:
///
/// - Higher `max_price` → job submitter expects more compute → more cycles.
/// - `descriptor_hash` adds per-job variation (deterministic).
fn estimate_job_cycles(job: &TrackedJob) -> u64 {
    let price_hemi = job.info.max_price / ETHER;
    let base_cycles = price_hemi.max(5) as u64 * 100_000;

    // Deterministic variation from descriptor hash (0.5× – 2.5×)
    let h = job.info.descriptor_hash.as_slice();
    let hash_factor = (h[0] as u64 + h[1] as u64 * 256) % 200 + 50; // 50–249

    (base_cycles * hash_factor / 100).clamp(500_000, 50_000_000)
}

async fn spawn_streaming_benchmark(state: zkminer_tui::state::SharedState) {
    use zkminer_tui::state::{BenchmarkTracker, LogLevel};

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

        // Bridge thread: forwards benchmark progress events to TUI state.
        // Uses a tokio mpsc channel to avoid block_on deadlocks with limited
        // worker threads (block_on inside std::thread from spawn_blocking can
        // deadlock when all tokio workers are busy).
        let (bridge_tx, mut bridge_rx) =
            tokio::sync::mpsc::channel::<zkminer_prover::dispatcher::BenchmarkProgressEvent>(32);
        let bridge_state = state_for_progress.clone();

        // Async task to receive events and update state
        tokio::spawn(async move {
            while let Some(event) = bridge_rx.recv().await {
                let mut s = bridge_state.write().await;
                if let Some(tracker) = s.benchmark_tracker.as_mut() {
                    tracker.on_progress(
                        &event.slot_key,
                        event.gpu_name.as_deref(),
                        event.device_index,
                        event.pci_bus_id.as_deref(),
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

        // Sync-side bridge: forward from std::sync::mpsc to tokio::sync::mpsc
        let bridge = std::thread::spawn(move || {
            while let Ok(event) = sync_rx.recv() {
                if bridge_tx.blocking_send(event).is_err() {
                    break; // receiver dropped
                }
            }
        });

        let on_progress = move |event: zkminer_prover::dispatcher::BenchmarkProgressEvent| {
            let _ = sync_tx.send(event);
        };
        let suite = run_benchmark_gpu_only_streaming(&on_progress);
        drop(on_progress);
        let _ = bridge.join();
        suite
    })
    .await
    .unwrap_or_default();

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
