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
/// True if a proving error means the JOB's deadline is spent, which is terminal: the
/// same deadline binds every GPU, so retrying is pointless and the job must be released
/// while it still can be.
///
/// Matches the dispatcher's three actual emitters, NOT any message containing the word
/// "deadline". A bare substring test made this arm terminal for whatever text a worker
/// or a third-party library happened to write, and it swallows the common transient
/// failures -- a respawn backoff message, an EOF, a CUDA allocation error -- none of
/// which should end a job. See `dispatcher.rs` "deadline cutoff reached while queued",
/// "left before deadline cutoff after", and "job deadline reached mid-proof".
fn is_deadline_terminal(msg: &str) -> bool {
    msg.contains("deadline cutoff") || msg.contains("job deadline reached")
}

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
/// How long a DRAIN waits for in-flight proofs before escalating to ABANDON.
///
/// [F3] The earlier 900s was derived from a false premise. The 600s proving watchdog is PER
/// ATTEMPT and `MAX_PROVE_ATTEMPTS = 3`, and fulfil adds up to 5 x (120s receipt + 30s poll)
/// = 750s, so a HEALTHY worst case is ~2850s. At 900s the drain would abandon jobs that were
/// still progressing normally. Each lifecycle also self-bounds at
/// `lock_deadline - DEADLINE_RELEASE_MARGIN_SECS` and self-releases on error, so a job cannot
/// outlive its own deadline while held — this bound only stops an indefinite wait.
/// Set when the shutdown was triggered by SIGTERM (a supervisor) rather than SIGINT.
///
/// systemd's default `TimeoutStopSec` is 90s and `docker stop` is 10s; both then SIGKILL.
/// A drain that waits for a 1-5 minute proof therefore never reaches the release step, so
/// a supervised stop would release NOTHING — strictly worse than the pre-drain code, which
/// released within ~2s. Supervised stops get a short drain that auto-escalates.
static SUPERVISED_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Drain budget for a supervised (SIGTERM) stop. DERIVED, not picked: the smallest common
/// grace period is `docker stop` = 10s, and the ABANDON stage needs essentially all of it.
/// One `releaseJob` broadcast costs ~5-6 RPC round trips (`release_and_clean`'s status view,
/// then `release_job`'s `base_fees` + status view + estimateGas + sendRawTransaction), every
/// one of them paced by the process-global 4 req/s throttle and contending with the brain /
/// refresh / lifecycle tasks that keep running through shutdown, on an endpoint that 429s.
/// A drain cannot buy any of that back: proofs run 60-477s so nothing finishes in seconds,
/// and `Submitting` jobs are excluded from abandon [F2] anyway — so waiting for their fulfil
/// cannot change what gets released. Budget = grace - release budget <= 0.
/// Zero costs nothing when nothing is held: the loop still breaks at "drain complete" on its
/// first pass; the budget was only ever spent in the case that needs the time for releases.
const SUPERVISED_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::ZERO;

const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3000);

/// Extra drain grace granted ONLY when every outstanding job is `Submitting` — i.e. when the
/// ABANDON stage has nothing to release ([F2] excludes them) and waiting therefore costs the
/// release budget nothing. Sized to fit inside `docker stop`'s 10s grace: enough for a fulfil
/// that is mid pre-broadcast to reach the wire, or to give up and stash its nonce for the
/// lifecycle's own release. Without it a supervised stop (budget ZERO) exits before either,
/// leaving the job neither fulfilled nor released.
/// [O2] Cap on how long the ABANDON step waits for release RECEIPTS. The broadcasts have
/// already gone out; this only bounds the confirmation wait so the exit verdict, the worker
/// reap and the nonce heal are not stranded behind ~750s of retries that a supervisor's
/// SIGKILL would cut short anyway. Sized to sit inside systemd's 90s default with room for
/// the reap.
const RELEASE_JOIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(45);

/// [A3] Interactive stops have NO supervisor deadline, so the 45s supervised cap must not
/// apply: `release_job_with_nonce` runs 5 attempts x (120s receipt + 30s poll), meaning
/// attempt 2 cannot even start before ~150s. Capping at 45s abandons the release BEFORE the
/// first re-broadcast — earlier than the single-receipt-timeout give-up that jobs.rs:962-968
/// calls out as "the exact failure that leaves collateral locked". The operator can always
/// escalate with a third signal.
const INTERACTIVE_RELEASE_JOIN_BUDGET: std::time::Duration =
    std::time::Duration::from_secs(800);

const SUBMITTING_FULFIL_GRACE: std::time::Duration = std::time::Duration::from_secs(8);

/// Longest a claim-intent breadcrumb (`lock_deadline` still 0) can plausibly belong to a LIVE
/// claim: `claim_job` is 5 attempts x `TX_RECEIPT_TIMEOUT` (120s) plus the post-claim
/// `DEADLINE_READ_RETRIES`. Past this, a zero-deadline entry has no lifecycle behind it and
/// must not hold the drain open (see the drain union below).
const CLAIM_INTENT_MAX_AGE_SECS: u64 = 900;

/// Set once the shutdown sequence has begun. Deliberately NOT `state.paused`: the TUI's `p`
/// key toggles `paused` too (zkminer-tui/src/app.rs), and there it means only "stop claiming
/// new work" — gating RECOVERY on it would let an operator pause silently disable the only
/// path that still releases a job whose earlier release failed on RPC.
static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

const FALLBACK_ESTIMATED_CYCLES: u64 = 34_000_000;

/// Bound on a single cycle measurement. Execution is far cheaper than proving, but a hostile
/// or pathological guest must not hold a worker: the watchdog kills it at this point, and a
/// job we cannot execute inside the budget is one we should not claim either.
const MEASURE_TIMEOUT: Duration = Duration::from_secs(120);

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


/// Build the collateral-starvation warning.
///
/// A FUNCTION, not two inline format! calls, because there are two output channels (the
/// tracing log and the TUI log pane) and hand-maintaining the same sentence twice is
/// precisely how the positional args rotated in the log copy only — it printed
/// "4.25 GPU(s) will sit idle. Fix: run `zkminer stake 1`" while the TUI, on the same
/// tick, correctly said 4.25. Headless operators saw only the wrong one.
pub(crate) fn collateral_warning(
    fundable: usize,
    wanted: usize,
    available: u128,
    per_claim: u128,
    shortfall: u128,
) -> String {
    let stake_cmd = zkminer_chain::staking::fmt_hemi_ceil(shortfall);
    format!(
        "Only {fundable} of {wanted} GPU slot(s) fundable — {avail} HEMI available, a claim \
         locks up to {per} HEMI (short ~{stake_cmd}). {idle} GPU(s) will sit idle. \
         Fix: run `zkminer stake {stake_cmd}`.",
        avail = fmt_hemi(available),
        per = fmt_hemi(per_claim),
        idle = wanted.saturating_sub(fundable),
    )
}

pub async fn run(config_path: Option<&Path>, headless: bool) -> Result<()> {
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_for_chain()?;
    let queue_horizon_secs = config.prover.queue_horizon_secs;
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
        s.runtime_settings.queue_horizon_secs = config.prover.queue_horizon_secs;

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
                        gpu_bus_id: None,
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

    // [B2] The journal is the AUTHORITATIVE record of what we hold on-chain: a breadcrumb is
    // written BEFORE every claim tx and removed only on fulfil or successful release, so it
    // brackets the on-chain lock exactly. `active_jobs` does NOT — a job is pushed there only
    // AFTER the claim mines and the post-claim status view returns, so during that window a
    // job holds collateral while being invisible to both shutdown stages. Constructed here
    // (rather than inside `miner_brain`) so the shutdown path can read it.

    // Miner brain: evaluates open jobs, claims, proves, and fulfills.
    let brain_client = client.clone();
    let brain_state = state.clone();
    let journal: SharedJournal = Arc::new(Mutex::new(JobJournal::load()));
    let brain_journal = journal.clone();
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
            brain_journal,
            std::time::Duration::from_secs(queue_horizon_secs),
        )
        .await;
    });

    // Escalating shutdown. Each signal advances one stage:
    //   1st -> DRAIN   : stop claiming, let in-flight proofs FINISH and fulfil.
    //   2nd -> ABANDON : stop waiting, release what can still be released.
    //   3rd -> HARD    : exit immediately.
    // Counter lives in a watch channel so the drain loop can observe escalation while it
    // waits, rather than being committed to a mode chosen at the first signal.
    let (sig_tx, mut sig_rx) = tokio::sync::watch::channel(0u8);
    // Installed ONLY for headless. In TUI mode the terminal is in raw mode (ISIG cleared)
    // and `run_tui` exits on a KEY event, not a signal — a handler here would swallow
    // SIGTERM, leave the miner claiming through the supervisor's whole grace window, and
    // then die to SIGKILL having released nothing. Without it, SIGTERM keeps its default
    // disposition and terminates, which is what operators already rely on.
    // ...but the TUI only OWNS the keyboard until `run_tui` returns. After that the process
    // still has to drain, abandon and reap (up to DRAIN_TIMEOUT), and with no handler at all
    // that whole window has the DEFAULT disposition: the operator's Ctrl+C on an apparently
    // hung shutdown kills the process outright, skipping the release stage AND the worker
    // reap (leaking the SP1 gpu-server's VRAM). So gate installation on the TUI exiting
    // rather than skipping it entirely.
    #[cfg(unix)]
    let (tui_done_tx, tui_done_rx) = tokio::sync::oneshot::channel::<()>();
    #[cfg(unix)]
    {
        let sig_tx = sig_tx.clone();
        let sig_state = state.clone();
        tokio::spawn(async move {
            // [O1] Handlers are installed IMMEDIATELY — NOT after the TUI exits.
            //
            // The previous version awaited `tui_done_rx` here, but that only fires AFTER
            // `run_tui` returns. So for the whole TUI session — and TUI is the DEFAULT mode
            // — SIGTERM kept its default disposition and killed the process outright: no
            // pause, no drain, no ABANDON, no release_and_clean, no exit 75, no worker reap.
            // Every held job then rode to its 7200s lock deadline. That was strictly worse
            // than both the original code and the first patch.
            //
            // Instead we install now and, in TUI mode, set `shutdown_requested` so the TUI
            // event loop breaks and `run()` continues into the ladder. `run_tui` already
            // breaks on a Quit action, so this reuses an existing, tested exit path.
            let _ = &tui_done_rx; // kept only so the channel is not dropped early
            use tokio::signal::unix::{signal, SignalKind};
            // SIGINT must be a PERSISTENT `Signal`, not a fresh `tokio::signal::ctrl_c()`
            // future per loop iteration. tokio registers a listener by subscribing to a watch
            // channel, so a listener created AFTER the signal fired never observes it, and the
            // registry clears its pending bit whether or not anyone was listening. Every SIGINT
            // delivered while this task sits outside the `select!` (the store / println! /
            // send window below) would therefore be swallowed — and since tokio's SIGINT
            // handler stays installed process-wide it does not fall back to the default
            // disposition either, so the operator's escalating Ctrl+C would silently no-op.
            // `sigterm` is hoisted for exactly this reason; keep the two symmetric.
            let mut sigint = signal(SignalKind::interrupt()).ok();
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    // Fail CLOSED: dropping sig_tx here would look like "shut down now" to
                    // the waiter below and exit 0 immediately at startup.
                    tracing::error!("cannot install SIGTERM handler: {e} — SIGINT only");
                    loop {
                        match sigint.as_mut() {
                            Some(si) => {
                                si.recv().await;
                            }
                            None => {
                                tokio::signal::ctrl_c().await.ok();
                            }
                        }
                        // Two statements, NOT `send(borrow() + 1)`: the `Ref` returned by
                        // `borrow()` holds a read lock on the watch's inner RwLock until the
                        // end of the enclosing statement, and `send()` takes the write lock —
                        // same-thread read-then-write deadlocks, wedging the ONLY graceful
                        // stop left in this degraded mode.
                        let next = sig_tx.borrow().saturating_add(1);
                        let _ = sig_tx.send(next);
                    }
                }
            };
            // In TUI mode the quit KEY already advanced the ladder to stage 1 (DRAIN is
            // running by the time we get here), so the operator's first Ctrl+C must mean
            // ABANDON — not a second "draining" message that does nothing.
            let mut n = if headless { 0u8 } else { 1u8 };
            loop {
                // A supervisor (systemd/docker) sends exactly ONE catchable signal and then
                // SIGKILLs after its grace period — nobody is there to press Ctrl+C twice.
                // So SIGTERM gets a SHORT drain that auto-escalates to ABANDON, while SIGINT
                // (a human at a terminal, who can escalate) keeps the long drain.
                let supervised = match sigint.as_mut() {
                    Some(si) => tokio::select! {
                        _ = si.recv() => false,
                        _ = sigterm.recv() => true,
                    },
                    // SIGINT registration failed: degrade to a per-iteration listener rather
                    // than losing SIGINT entirely.
                    None => tokio::select! {
                        _ = tokio::signal::ctrl_c() => false,
                        _ = sigterm.recv() => true,
                    },
                };
                if supervised {
                    SUPERVISED_STOP.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                // [O1] Break the TUI out of its event loop so `run()` reaches the ladder.
                // No-op in headless (nothing reads it there).
                {
                    let mut st = sig_state.write().await;
                    st.shutdown_requested = true;
                    st.paused = true;
                }
                n = n.saturating_add(1);
                match n {
                    // [G3] Wording must match what actually happens: with
                    // SUPERVISED_DRAIN_TIMEOUT == ZERO a supervised stop abandons on the same
                    // tick, so promising "signal again to ABANDON" there would be a lie — and
                    // this line is the only thing the operator sees.
                    1 if supervised => println!(
                        "\nSUPERVISED STOP — releasing held jobs now (no drain: a supervisor \
                         will SIGKILL before any proof could finish)."
                    ),
                    1 => println!(
                        "\nDRAINING — finishing in-flight proofs, no new claims. \
                         Signal again to ABANDON (release jobs), a third time to force-exit."
                    ),
                    2 => println!("\nABANDONING — releasing jobs, nearest deadline first..."),
                    _ => {
                        eprintln!("\nForce exit — in-flight jobs left locked on-chain.");
                        // [F4] Reap workers first. SP1's `sp1-gpu-server` is a GRANDCHILD
                        // that does NOT die with us; measured precedent in this repo is
                        // 11.5 GB of VRAM still held after the parent exited.
                        //
                        // BOUNDED, because `shutdown_all` is not: its phase 4 takes a
                        // BLOCKING slot lock, while phases 2/3 skip any slot whose `pid` is
                        // momentarily 0 — the respawn/recycle window (dispatcher.rs, where
                        // the pid is zeroed before the handle is dropped and only restored
                        // after `ensure_alive`). Such a worker is never signalled, so the
                        // lock it holds is not released until its whole proof finishes (up
                        // to the 600s watchdog) — and since the "Force exit" print used to
                        // sit AFTER this call, the third Ctrl+C produced no output and never
                        // exited. The third signal must terminate regardless: reap off-thread
                        // and cap the wait (a normal reap takes ~2.2s).
                        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
                        std::thread::spawn(move || {
                            if let Some(pool) = zkminer_prover::engine::worker_pool() {
                                pool.shutdown_all();
                            }
                            let _ = done_tx.send(());
                        });
                        if done_rx.recv_timeout(std::time::Duration::from_secs(10)).is_err() {
                            eprintln!(
                                "worker reap did not finish in 10s — exiting anyway; check for \
                                 an orphaned sp1-gpu-server holding VRAM."
                            );
                        }
                        std::process::exit(130);
                    }
                }
                let _ = sig_tx.send(n);
            }
        });
    }

    if headless {
        println!("zkminer running in headless mode. Press Ctrl+C to stop.");
        // Wait for the FIRST signal.
        #[cfg(unix)]
        while *sig_rx.borrow() == 0 {
            if sig_rx.changed().await.is_err() {
                break;
            }
        }
        // [F7] Non-unix has no signal task; fall back to plain Ctrl-C so headless does not
        // park forever waiting on a channel nothing ever sends to.
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await?;
            println!("\nShutting down...");
        }
    } else {
        // Run interactive TUI with chain client for setup actions.
        // Do NOT `?` here. `run_tui` is fallible at RUNTIME, not just at setup (the in-loop
        // `terminal.draw()?`, and the raw-mode/alternate-screen restore at the operator's
        // `q`), and every step of the shutdown sequence below — paused/SHUTTING_DOWN, the
        // drain, the ABANDON/`release_and_clean` stage, the EX_TEMPFAIL verdict and the
        // worker reap — lives after this line. Propagating the error returns straight out of
        // `run()`, leaving held jobs Locked on-chain with nothing alive to release them (they
        // then ride past the lock deadline, after which releaseJob reverts permanently) and
        // the SP1 gpu-server grandchild holding its VRAM. Log and fall through instead.
        let tui_result = zkminer_tui::run_tui(state.clone(), Some(client.clone())).await;
        // Terminal is restored (raw mode off) and the TUI no longer owns the keyboard —
        // release the signal handler so the drain below still has the abandon/force ladder.
        #[cfg(unix)]
        let _ = tui_done_tx.send(());
        if let Err(e) = tui_result {
            tracing::error!("TUI exited with an error: {e:#} — continuing into shutdown");
        }
    }

    // ---- Shutdown -----------------------------------------------------------------
    // 1. Stop taking on new work. Per-job lifecycles are INDEPENDENT spawned tasks (each
    //    holding its own SlotGuard), so pausing the brain stops new claims without
    //    disturbing work already under way.
    {
        let mut s = state.write().await;
        s.paused = true;
    }
    // Distinct from `paused` (which the TUI's `p` key also sets, meaning only "stop
    // claiming"): the shutdown-only gates below key off THIS flag.
    SHUTTING_DOWN.store(true, std::sync::atomic::Ordering::SeqCst);
    monitor_handle.abort();
    event_handle.abort();
    hw_handle.abort();
    // [B5] brain_handle is NOT aborted here. The claim of "per-job lifecycles are
    // independent spawned tasks" holds for the normal and batch paths (spawn_lifecycle_task)
    // but NOT for recovery: `recover_claimed_jobs` awaits `process_job_lifecycle` INLINE
    // inside `miner_brain`, so aborting the brain drops a recovered job mid-prove or
    // mid-fulfil. That job is already in `active_jobs` as Proving and nothing else can
    // advance or remove it, so the drain would burn its whole budget on a zombie and only
    // then release — crossing a lock deadline the pre-drain code would have met.
    //
    // `s.paused = true` already stops new claims, so letting the brain finish is safe. It is
    // aborted at the end, alongside the other survivors.
    let brain_deadline_note = "brain left running so inline recovery lifecycles can finish";
    tracing::debug!("{brain_deadline_note}");
    // `refresh_handle` is left running through the drain simply because it is harmless and
    // keeps balances/UI fresh. NOTE: it does NOT advance job status — status transitions
    // happen inside the per-job lifecycle (`active_jobs` mutation sites), so aborting it
    // would not stall the drain. Stated explicitly because an earlier version of this
    // comment claimed the opposite and would have misled a future edit.

    // 2. DRAIN — let in-flight proofs finish and fulfil.
    //
    //    The old sequence called `pool.shutdown_all()` HERE, before releasing. That kills
    //    the workers, so every in-flight proof was destroyed unconditionally — on the
    //    1-5 minute proofs this miner now runs that discarded up to five minutes of GPU
    //    work and the claim gas, even at 99% complete, and the job then had to be
    //    re-proved from scratch by the recovery path on the next start.
    let mut exit_code = 0i32;
    let supervised = SUPERVISED_STOP.load(std::sync::atomic::Ordering::SeqCst);
    let drain_budget = if supervised { SUPERVISED_DRAIN_TIMEOUT } else { DRAIN_TIMEOUT };
    if supervised {
        tracing::warn!(
            "supervised stop (SIGTERM): draining {}s then releasing — a supervisor will \
             SIGKILL before a full drain could finish",
            drain_budget.as_secs()
        );
    }
    let drain_deadline = std::time::Instant::now() + drain_budget;
    let mut abandoned = false;
    loop {
        if *sig_rx.borrow() >= 2 {
            tracing::warn!("drain interrupted by second signal — abandoning");
            abandoned = true;
            break;
        }
        // Union of what the UI thinks is in flight AND what the journal says we hold
        // on-chain. The journal alone is authoritative for "collateral is locked"; without
        // it the loop declares "drain complete" while a claim is mid-flight. [B2]
        let (mut outstanding, submitting_now): (Vec<B256>, std::collections::HashSet<B256>) = {
            let s = state.read().await;
            (
                s.active_jobs
                    .iter()
                    .filter(|j| {
                        matches!(
                            j.status,
                            MinerJobStatus::Proving { .. } | MinerJobStatus::Submitting
                        )
                    })
                    .map(|j| j.info.job_id)
                    .collect(),
                s.active_jobs
                    .iter()
                    .filter(|j| matches!(j.status, MinerJobStatus::Submitting))
                    .map(|j| j.info.job_id)
                    .collect(),
            )
        };
        let now_s = chrono::Utc::now().timestamp().max(0) as u64;
        // A zero-deadline breadcrumb that is too old to be a live claim: see the filter below.
        let mut stale_intent = false;
        {
            // std::sync::Mutex — guard must not cross an await; scope it tightly.
            let held: Vec<B256> = {
                let j = journal.lock().unwrap_or_else(|e| e.into_inner());
                // Past-deadline entries are STRANDED, not draining. `release_and_clean`
                // deliberately RETAINS their breadcrumb (releaseJob would revert) and only a
                // keeper slash ever clears it, so an unfiltered union can never become empty
                // on a miner that has ever stranded a job: the drain would burn its whole
                // budget waiting on a job that has been dead for hours, delaying the abandon
                // of jobs that CAN still be released. The abandon stage below skips these for
                // exactly the same reason.
                // An UNKNOWN deadline (0) is only "still draining" while a claim could
                // genuinely still be in flight. Every breadcrumb is born at 0 (an open job's
                // pre-claim snapshot deadline is 0) and only `mark_claimed` backfills it, while
                // `release_and_clean`'s unconfirmed-claim arm deliberately RETAINS such an entry
                // after dropping the job from `active_jobs` — and recovery is gated off during
                // shutdown, so nothing can ever advance it. Since the nearest-deadline cut below
                // cannot see a 0 either, keeping one here pins `outstanding` non-empty for the
                // WHOLE budget: an interactive stop hangs for the full DRAIN_TIMEOUT with
                // nothing actually in flight. Age it out instead — but it may still hold
                // collateral (the claim tx can mine after we gave up), so hand it to ABANDON
                // (which re-reads the chain) rather than exiting clean.
                j.iter()
                    .filter(|e| {
                        if e.lock_deadline == 0 {
                            let age = now_s.saturating_sub(e.claimed_at.max(0) as u64);
                            let live = age <= CLAIM_INTENT_MAX_AGE_SECS;
                            if !live {
                                stale_intent = true;
                            }
                            live
                        } else {
                            e.lock_deadline > now_s
                        }
                    })
                    .map(|e| e.job_id)
                    .collect()
            };
            for id in held {
                if !outstanding.contains(&id) {
                    outstanding.push(id);
                }
            }
        }
        // A stale zero-deadline breadcrumb has no lifecycle behind it and is INVISIBLE to the
        // nearest-deadline cut below (which filters `d > now_s`), so it must never leave by the
        // CLEAN exit — that is the one drain exit that skips ABANDON, and ABANDON's on-chain
        // re-check is the only thing that can still release it.
        // But ONLY once nothing else is genuinely draining. Staleness is not urgency: such an
        // entry is created by the ordinary RPC-failed-claim path (`release_and_clean` RETAINS a
        // `Claiming` breadcrumb whose view reads prover == ZERO) and its only GC — recovery —
        // is idle-gated AND skipped during shutdown, so on the miner that produced it the entry
        // survives the whole session. Escalating unconditionally therefore aborted EVERY
        // subsequent drain on iteration 1, discarding in-flight proofs seconds from fulfilling
        // — for a lock that, having just aged out at CLAIM_INTENT_MAX_AGE_SECS (900s), still
        // has most of its window left, far more than DRAIN_TIMEOUT + the release margin.
        // `outstanding` already EXCLUDES stale entries (the filter above returns `live ==
        // false`), so this condition means "the stale intent is the only thing we know about",
        // and every OTHER exit from this loop already sets `abandoned = true`.
        if stale_intent && outstanding.is_empty() {
            tracing::warn!(
                "drain cut short — a stale claim-intent breadcrumb (deadline unknown, so \
                 invisible to the nearest-deadline cut) may still hold collateral; abandoning \
                 so it gets an on-chain re-check and release"
            );
            abandoned = true;
            break;
        }
        if outstanding.is_empty() {
            // `outstanding` deliberately EXCLUDES past-deadline breadcrumbs (see the filter
            // above) — those are STRANDED collateral, not draining work. "Nothing in flight"
            // is therefore not the same as "nothing held", and in TUI mode this println is the
            // only shutdown verdict an operator ever sees (tracing goes to a file), so an
            // unconditional all-clear here asserts the opposite of the on-chain truth on every
            // clean stop of a miner that has ever stranded a job.
            let retained = {
                let j = journal.lock().unwrap_or_else(|e| e.into_inner());
                j.iter().count()
            };
            if retained == 0 {
                tracing::info!("drain complete — no jobs in flight, journal empty");
                if !headless {
                    println!("Shutdown clean — no jobs held, no collateral at risk.");
                }
            } else {
                tracing::warn!(
                    "drain complete — no jobs in flight, but {retained} past-deadline journal \
                     breadcrumb(s) remain: that collateral is STILL LOCKED until a keeper slash"
                );
                if !headless {
                    println!(
                        "Drain complete — nothing in flight, but {retained} past-deadline \
                         breadcrumb(s) remain: that collateral is STILL LOCKED until a keeper \
                         slash — details in ~/.zkminer/logs/zkminer.log"
                    );
                }
            }
            break;
        }
        // Never drain past the point where the nearest still-releasable job could still be
        // released — `releaseJob` reverts at the lock deadline. The drain budget itself is
        // deadline-blind, and its justification (each lifecycle self-bounds at
        // `lock_deadline - DEADLINE_RELEASE_MARGIN_SECS`) does NOT cover a journal entry with
        // no live lifecycle behind it: a release that failed on RPC retains the breadcrumb
        // but drops the job from `active_jobs`, and recovery is gated off during shutdown, so
        // nothing can advance it. Waiting that out converts a releasable lock into a
        // permanent strand.
        // Only entries the ABANDON stage would actually act on may cut the drain short. [F2]
        // excludes `Submitting` jobs from the release list, so tripping on one aborts the drain
        // for a job abandon then refuses to release — and the exit below kills the in-flight
        // fulfil AND the lifecycle's own self-release, which fires at exactly this instant
        // (fulfill's budget expires at `lock_deadline - DEADLINE_RELEASE_MARGIN_SECS`).
        let soonest = {
            let j = journal.lock().unwrap_or_else(|e| e.into_inner());
            j.iter()
                .filter(|e| !submitting_now.contains(&e.job_id))
                .map(|e| e.lock_deadline)
                .filter(|d| *d > now_s)
                .min()
        };
        if let Some(d) = soonest {
            if now_s.saturating_add(DEADLINE_RELEASE_MARGIN_SECS) >= d {
                tracing::warn!(
                    "drain cut short — nearest held lock deadline is {}s away (< {}s release \
                     margin) — abandoning now while releaseJob can still land",
                    d.saturating_sub(now_s),
                    DEADLINE_RELEASE_MARGIN_SECS,
                );
                abandoned = true;
                break;
            }
        }
        // [F2] `Submitting` jobs are excluded from the ABANDON release list, so the DRAIN is
        // the ONLY stage that can still free their collateral — by letting the fulfil land
        // (or give up, stashing its nonce so the lifecycle's own release can displace it).
        // `Submitting` is set BEFORE `fulfill_job`, whose pre-broadcast nonce reserve / fee
        // read / status view are all paced by the global RPC throttle, so a ZERO supervised
        // budget `process::exit`s the fulfil before it ever reaches the wire — the job ends
        // up neither fulfilled NOR released, and an operator-initiated stop is not restarted
        // by the [F5] exit code either. Grant a small grace, but ONLY when every outstanding
        // job is `Submitting`: then `doomed` is empty and this costs the release budget
        // nothing. A mixed set still exits at once — releasable collateral outranks a fulfil.
        let effective_deadline = if !submitting_now.is_empty()
            && outstanding.iter().all(|id| submitting_now.contains(id))
        {
            drain_deadline + SUBMITTING_FULFIL_GRACE
        } else {
            drain_deadline
        };
        if std::time::Instant::now() >= effective_deadline {
            tracing::warn!(
                "drain timeout ({}s) with {} job(s) still in flight — abandoning",
                drain_budget.as_secs(),
                outstanding.len()
            );
            abandoned = true;
            break;
        }
        tracing::info!(
            "draining: {} job(s) in flight ({}) — signal again to abandon",
            outstanding.len(),
            outstanding.iter().map(|j| short_id(*j)).collect::<Vec<_>>().join(", ")
        );
        // In TUI mode every line above goes to ~/.zkminer/logs/zkminer.log and NOTHING to the
        // terminal, so the operator sees a blank screen for up to DRAIN_TIMEOUT and cannot tell
        // a working drain from a wedged process — the usual response is a kill that strands
        // collateral. The TUI has already restored the terminal by this point (the signal
        // ladder above prints here too), so stdout is safe.
        if !headless {
            println!(
                "draining: {} job(s) still proving — Ctrl+C to abandon and release now",
                outstanding.len()
            );
        }
        // Clamp the poll to the remaining budget. `drain_deadline` is only tested at loop
        // TOP, so an unclamped 5s quantum rounds the 6s supervised budget up to 10s — i.e.
        // `docker stop`'s ENTIRE grace period — and SIGKILL lands at the instant the loop
        // first decides to abandon, so a supervised stop releases nothing (and never reaches
        // the worker reap either). Zero is fine: the next iteration falls straight into the
        // deadline branch above.
        let poll = std::time::Duration::from_secs(5)
            .min(effective_deadline.saturating_duration_since(std::time::Instant::now()));
        tokio::select! {
            _ = tokio::time::sleep(poll) => {}
            _ = sig_rx.changed() => {}
        }
    }

    // 3. ABANDON — release whatever is still ours, NEAREST DEADLINE FIRST.
    //
    //    Ordering is the whole game for collateral: `releaseJob` reverts once a job is past
    //    its lock deadline, and the collateral is then locked until a keeper slashes. Every
    //    second spent on a job with hours of headroom is a second not spent on one about to
    //    expire, so releasing in deadline order is what actually minimises loss.
    if abandoned {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Source of truth is the JOURNAL [B2]: it covers the claim window that `active_jobs`
        // misses. `Submitting` jobs are deliberately EXCLUDED [F2] — they already have a
        // valid proof and a fulfil in flight; releasing one races its own fulfil for the
        // signer's nonce and can strand exactly what it was trying to save.
        let submitting: std::collections::HashSet<B256> = {
            let s = state.read().await;
            s.active_jobs
                .iter()
                .filter(|j| matches!(j.status, MinerJobStatus::Submitting))
                .map(|j| j.info.job_id)
                .collect()
        };
        let mut doomed: Vec<(u64, B256)> = {
            let j = journal.lock().unwrap_or_else(|e| e.into_inner());
            j.iter()
                .filter(|e| !submitting.contains(&e.job_id))
                .map(|e| (e.lock_deadline, e.job_id))
                .collect()
        };
        if !submitting.is_empty() {
            tracing::info!(
                "{} job(s) already submitting a proof — not releasing (their fulfil is in \
                 flight; releasing would race it)",
                submitting.len()
            );
        }
        // Unknown (0) sorts LAST, not first: reading 0 as "expired at the epoch" would put
        // the least-known jobs ahead of ones with a real, imminent deadline.
        doomed.sort_by_key(|(d, _)| if *d == 0 { u64::MAX } else { *d });
        let mut released = 0usize;
        let mut stranded = 0usize;
        // At most ONE frontier fetch for the whole burst, and it must be BOUNDED. This loop
        // had ZERO network awaits by design — see the "SPAWN, don't await in-line" rule below
        // — and past-deadline jobs sort FIRST, so anything slow here runs AHEAD of every
        // still-savable release. A supervised stop gives the abandon stage the entire grace
        // (SUPERVISED_DRAIN_TIMEOUT is ZERO) and nothing wraps this ladder in an outer
        // timeout, so an unbounded fetch against a black-holing endpoint means no releaseJob
        // is ever broadcast and every held collateral rides to its deadline. The mined
        // frontier only advances, so one fetch covers every stash in the burst.
        let mut stash_frontier_synced = false;
        let mut releasing: Vec<(B256, tokio::task::JoinHandle<()>)> = Vec::new();
        for (deadline, jid) in doomed {
            // [F2] Re-read the live status per job: `submitting` was snapshotted BEFORE this
            // loop and the per-job lifecycles are still running, so a job that was Proving at
            // snapshot time can enter its fulfil while we are in here. `release_and_clean`'s
            // on-chain guard only catches a fulfil that already MINED (status != Locked), not
            // one that is merely pending — whose nonce a fresh releaseJob would queue behind.
            let now_submitting = {
                let s = state.read().await;
                s.active_jobs
                    .iter()
                    .any(|j| j.info.job_id == jid && matches!(j.status, MinerJobStatus::Submitting))
            };
            if now_submitting {
                tracing::info!(
                    "job {} entered fulfil during abandon — not releasing (would race its own \
                     fulfil for the signer's nonce)",
                    short_id(jid)
                );
                continue;
            }
            if deadline != 0 && deadline <= now {
                // Already expired: `releaseJob` would revert. Skip it rather than burn the
                // budget of a job that CAN still be saved.
                tracing::error!(
                    "job {} already past its lock deadline — collateral stranded until a \
                     keeper slash; not attempting release",
                    short_id(jid)
                );
                // [#45] No release will EVER be attempted for this job — `releaseJob` would
                // revert past the deadline — and `release_job_with_nonce` is the only consumer
                // of the abandoned-fulfill stash. So a stashed nonce here has no future owner:
                // it is in no set at all (not stashed for anyone, not in `freed`, no abort
                // record), which is exactly the invisible-hole shape that wedges every higher
                // nonce. The sibling arms in the recovery path carry this same drain.
                //
                // Deliberately NOT done in the `now_submitting` arm above: there the job's
                // lifecycle is ALIVE and its release path is the intended consumer, so draining
                // would break the fulfill->release displacement handoff the stash exists for.
                if let Some(n) = client.take_abandoned_nonce(jid) {
                    // Learn the mined frontier BEFORE recycling. The stash may already be
                    // consumed on-chain — a past-deadline fulfill that mined as a revert still
                    // has status 1, so neither state poll sees it and no receipt means no
                    // `commit_nonce`. Without this, the abort inserts a dead nonce into
                    // `freed`, and because past-deadline jobs sort FIRST in this
                    // deadline-ordered burst, `reserve_locked` hands it straight to the
                    // NEAREST-deadline live release, whose send is then rejected "nonce too
                    // low". With the `consumed_below` watermark in place the abort then
                    // correctly no-ops instead.
                    //
                    // BOUNDED and once per burst: on timeout we degrade to exactly the
                    // pre-amendment behaviour, which costs one attempt of five inside an
                    // already-spawned concurrent release — cheap, and recoverable by that
                    // task's own nonce-error arm. Paying for it with the whole grace period
                    // is not. Cancellation is safe: `resync_nonce` mutates the allocator only
                    // after the RPC returns, so a dropped future changes no state.
                    if !stash_frontier_synced {
                        stash_frontier_synced = true;
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_millis(1_500),
                            client.resync_nonce(),
                        )
                        .await;
                    }
                    client.abort_nonce(n);
                }
                stranded += 1;
                continue;
            }
            if deadline == 0 {
                // Not "0s left" — the sort above deliberately ranked this LAST as the least
                // urgent, and the expired-skip above declined to call it expired.
                tracing::info!(
                    "releasing job {} (deadline unknown — claim never confirmed)",
                    short_id(jid)
                );
            } else {
                tracing::info!(
                    "releasing job {} ({}s of deadline left)",
                    short_id(jid),
                    deadline.saturating_sub(now)
                );
            }
            // [F1] `release_and_clean`, not the raw client call: it re-checks the on-chain
            // status (so a job that fulfilled underneath us is not released), re-reads the
            // authoritative deadline, drains the abandoned-nonce stash, and clears the
            // journal entry — none of which the raw call does.
            //
            // SPAWN, don't await in-line. `release_job` retries up to 5 x (120s receipt +
            // 30s state poll) ~= 750s for ONE job, and `await_receipt` parks >= 6s before its
            // first poll — while a supervised stop is SIGKILLed 10s (docker) / 90s (systemd)
            // after SIGTERM. Serialised, only the FIRST job's releaseJob ever reaches the
            // wire and every other held job strands; BROADCASTING is what frees the
            // collateral (the tx mines whether or not we survive to see the receipt). Spawn
            // order stays nearest-deadline-first and the client's `tx_lock` still serialises
            // the actual sends — exactly as concurrent per-job lifecycles already do.
            //
            // Reserve the nonce HERE, though, not inside the task. A single signer's txs mine
            // in strict NONCE order (a tx at n+1 sits in the queued pool until n mines), so
            // the nonce IS the on-chain priority. Reserved inside the task it is assigned
            // whenever that task's first throttled RPC happens to resolve — scheduling and
            // 429-retry order, uncorrelated with the deadline sort above — so a job with
            // hours of headroom can take the lower nonce and block the release of one about
            // to strand. Reserving in this loop restores what the serialised version had.
            // (In-memory fast path once the allocator is synced; a recycled gap is handed out
            // first, which only ever LOWERS the urgent job's nonce.)
            let pre_nonce = client.reserve_nonce().await.ok();
            let (c, st, jr) = (client.clone(), state.clone(), journal.clone());
            releasing.push((
                jid,
                tokio::spawn(async move {
                    release_and_clean_with_nonce(&c, &st, &jr, jid, pre_nonce).await;
                }),
            ));
        }
        let release_txs_attempted = releasing.len();
        // [O2] BOUND the join. Each `release_and_clean` is up to 5 attempts x (120s receipt +
        // 30s poll) ~= 750s; joining them serially blocked everything downstream — the exit-75
        // verdict, the worker reap (SP1's gpu-server keeps ~11.5 GB) and the nonce heal. Under
        // a supervisor the SIGKILL landed INSIDE this join, so none of them ever ran.
        //
        // What matters for collateral is that the release tx is BROADCAST, which has already
        // happened concurrently by the time we get here; waiting for receipts is a nicety.
        // So cap the total wait and carry on — a job whose receipt we never saw is simply
        // reported as still-held, which is exactly what the exit-75 path is for.
        let join_budget = if supervised {
            RELEASE_JOIN_BUDGET
        } else {
            INTERACTIVE_RELEASE_JOIN_BUDGET
        };
        let join_deadline = std::time::Instant::now() + join_budget;
        for (jid, handle) in releasing {
            let left = join_deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                tracing::warn!(
                    "release-join budget exhausted; not waiting on job {} (its tx is already \
                     broadcast — the journal is the source of truth for whether it landed)",
                    short_id(jid)
                );
            } else if tokio::time::timeout(left, handle).await.is_err() {
                tracing::warn!("release of job {} did not confirm within budget", short_id(jid));
            }
            // `release_and_clean` returns (); the JOURNAL is its outcome signal — it removes
            // the breadcrumb only when the lock is provably gone (released, or no longer/
            // never ours). A retained entry means the collateral is STILL LOCKED (release tx
            // failed, or the job turned out to be past its on-chain deadline). Counting those
            // as "released" made the shutdown summary claim success on precisely the cases
            // that lose stake.
            if journal_has(&journal, jid) {
                tracing::error!(
                    "job {} NOT released — collateral still locked on-chain (see the preceding \
                     line for why)",
                    short_id(jid)
                );
                stranded += 1;
            } else {
                released += 1;
            }
        }

        // Every doomed job took a nonce at spawn time above, but the release is NOT
        // guaranteed to be sent: `release_and_clean_with_nonce`'s three skip arms (lock not
        // provably gone / not ours / past the on-chain deadline) and `release_job_with_nonce`'s
        // own already-released early return all RECYCLE their nonce instead. Recycling only
        // refills the on-chain sequence when a LATER reservation picks the nonce up — and
        // these were all handed out in one burst before any task's first RPC resolved, so a
        // skipped one leaves a HOLE BELOW the releaseJob txs we did broadcast. A signer's txs
        // mine in strict nonce order, so those releases would sit in the queued pool unmined,
        // and the process exits a few lines below with nothing left alive to heal the gap —
        // the very collateral they were freeing then rides to its lock deadline, after which
        // releaseJob reverts permanently. Fill it now; `heal_nonce_gap` self-checks and is a
        // no-op (Ok(false)) when there is no gap.
        //
        // GUARD (`heal_nonce_gap`'s own doc): heal only a PROVEN hole. `nonce_gap_frontier`'s
        // branch (B) (`is_freed` / `recently_aborted`) does NO pending check by design — it is
        // meant to DISPLACE a stuck tx of ours — and `release_job_with_nonce`'s give-up path
        // RECYCLES the nonce of a releaseJob it actually BROADCAST. Healing that nonce is not
        // filling a hole: it replaces our own still-mineable release with a 0-value self-
        // transfer (heal bids >= 4x base; the release ladder tops out far below that), and we
        // `process::exit` a few lines below with nothing left alive to re-send it — stranding
        // exactly the nearest-deadline job. `recently_aborted` is also sticky for 600s AFTER
        // another task re-reserves the nonce, so a still-running lifecycle's live tx trips it
        // too. When something is executable at the frontier there is no wedge to heal: the
        // queued releases cascade as soon as it mines.
        // [A4] Was `frontier_has_executable_tx()`, i.e. "anything executable at the mined
        // frontier => don't heal". That excluded the case this whole block exists for: the
        // skipped release leaves a hole ABOVE the frontier (our own broadcast release is
        // executable AT it), so the probe said "busy" and we never healed, and the queued
        // releases rode to their lock deadlines. `nonce_gap_safe_to_fill` keeps the original
        // protection — it still refuses to displace an executable tx at the frontier — while
        // allowing a hole above it, where by construction there is nothing to displace.
        let heal_target = if release_txs_attempted > 0 {
            match client.nonce_gap_safe_to_fill().await {
                Ok(t) => t,
                // Can't prove it's safe → never displace anything.
                Err(e) => {
                    tracing::warn!("post-abandon nonce frontier probe failed: {e:#} — not healing");
                    None
                }
            }
        } else {
            None
        };
        // [D3] `pending` reports only the LOWEST hole, and `heal_nonce_gap` fills one. With
        // two or more skipped releases — routine when several jobs are doomed — plugging the
        // first leaves the next one blocking every release above it, and we exit immediately
        // with nothing alive to notice. The live watchdog walks holes one per ~2 min, which is
        // fine for a running process and useless here. Loop, bounded: each pass is a handful
        // of RPCs plus (for an above-frontier fill) no receipt wait, so this stays well inside
        // the shutdown budget.
        const MAX_SHUTDOWN_HEALS: usize = 3;
        // [#6b] Bound in TIME as well as passes: a frontier-hole pass can still consume the
        // full 30s HEAL_RECEIPT_BUDGET, and the shutdown budget is already 45s join + reap
        // against a 90s supervisor kill. Overrunning costs the worker reap (SP1's gpu-server
        // holds ~11.5 GB) and the exit-75 verdict — worse than an unfilled hole, which
        // recovery re-drives on the next start.
        const HEAL_LOOP_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);
        let heal_deadline = std::time::Instant::now() + HEAL_LOOP_BUDGET;
        let mut heal_target = heal_target;
        let mut healed = 0usize;
        while healed < MAX_SHUTDOWN_HEALS {
            // [#1] Fill the nonce the GATE approved. `heal_nonce_gap()` re-derives from the
            // ungated detector, which in a documented state nominates a different nonce —
            // the executable releaseJob at the frontier.
            let Some(target) = heal_target else { break };
            // Pass the REMAINING budget down. A hard-coded 30s receipt wait inside this 20s
            // budget is not a race but arithmetic: the first frontier pass always overruns and
            // always fails this check, making the walk single-shot in exactly the shape it was
            // written for — and pushing shutdown past the supervisor's kill, so the worker reap
            // and the exit-75 verdict never run.
            let left = heal_deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                tracing::warn!(
                    "post-abandon heal budget spent with nonce {target} still open — leaving \
                     it to recovery on the next start"
                );
                break;
            }
            healed += 1;
            // The VETTED path: refuse if the nonce was re-reserved since the gate approved
            // it. Ok(false) then breaks the loop, which is the right response.
            match client.heal_owned_nonce_gap_at(target, left).await {
                Ok(zkminer_chain::client::OwnedHealOutcome::Filled) => {
                    tracing::warn!(
                        "filled a nonce gap left by a skipped release — the releaseJob tx(es) \
                         we broadcast can now mine"
                    );
                    // Re-probe: there may be another hole above the one just plugged. Any
                    // error or ambiguity ends the loop rather than risking a spin.
                    heal_target = client.nonce_gap_safe_to_fill().await.unwrap_or(None);
                }
                // A live owner took the nonce after the gate approved it. That owner will
                // plug it, so this is NOT a reason to stop — the blocker is now the hole
                // ABOVE it, and stopping here strands every release queued behind that one
                // with most of the budget unspent.
                Ok(zkminer_chain::client::OwnedHealOutcome::RefusedNotOurs) => {
                    heal_target = client.nonce_gap_safe_to_fill().await.unwrap_or(None);
                    if heal_target == Some(target) {
                        // The gate re-nominated the same nonce we just refused; walking again
                        // would spin. Leave it to recovery on the next start.
                        break;
                    }
                }
                // Sent but not confirmed — retrying only re-broadcasts at an escalating fee
                // while the clock runs down.
                Ok(zkminer_chain::client::OwnedHealOutcome::Unconfirmed) => break,
                // The ONLY Err path is `send_transaction` itself, so this means "that one
                // broadcast did not reach the node" (a 429, or the HTTP timeout) — not that
                // the hole is unhealable. On the owned path the arm has already restored the
                // `freed` entry, so the state is clean for an immediate retry, and the loop is
                // bounded by MAX_SHUTDOWN_HEALS and the deadline. Breaking here threw away the
                // rest of the budget on a transient failure, during a burst where 429s are the
                // expected condition.
                Err(e) => {
                    tracing::warn!(
                        "post-abandon nonce gap fill at {target} failed to send: {e:#} — \
                         retrying within the remaining budget"
                    );
                    heal_target = client.nonce_gap_safe_to_fill().await.unwrap_or(None);
                }
            }
        }
        if heal_target.is_some() {
            tracing::warn!(
                "post-abandon: stopped after {healed} gap fill(s) with a hole still open — \
                 remaining queued release(s) will be re-driven by recovery on the next start"
            );
        }

        // [F5] Leave a machine-readable verdict and a NON-ZERO exit when anything is still
        // held: every path previously returned Ok(()) -> exit 0, so `Restart=on-failure`
        // saw success and did NOT restart — disabling the recovery path that is the actual
        // remedy for a held job.
        let (still_held, recoverable) = {
            let j = journal.lock().unwrap_or_else(|e| e.into_inner());
            let total = j.iter().count();
            // Only entries a RESTART could still act on gate the exit code. A past-deadline
            // breadcrumb is retained deliberately until a keeper slash flips the on-chain
            // status, so counting it would make EX_TEMPFAIL permanently true on any miner
            // that has ever stranded a job — a restart request that carries no information.
            // Unknown (0) counts as recoverable: fail toward letting recovery re-read chain.
            let rec = j
                .iter()
                .filter(|e| e.lock_deadline == 0 || e.lock_deadline > now)
                .count();
            (total, rec)
        };
        tracing::warn!(
            "shutdown summary: {released} released, {stranded} still locked (past deadline or \
             failed release), {still_held} breadcrumb(s) in the journal ({recoverable} \
             recoverable on restart)"
        );
        // Mirror the verdict to the terminal: in TUI mode this is the ONLY way an operator
        // learns that collateral was stranded rather than released (see the drain note above).
        if !headless {
            println!(
                "shutdown summary: {released} released, {stranded} STILL LOCKED (past deadline \
                 or failed release), {still_held} journal breadcrumb(s) ({recoverable} \
                 recoverable on restart) — details in ~/.zkminer/logs/zkminer.log"
            );
        }
        if recoverable > 0 {
            // EX_TEMPFAIL. Keep it — but it only produces an AUTO-restart when the signal did
            // NOT come from the supervisor's own stop job (`kill -TERM $MAINPID`, a wrapper, a
            // liveness-probe kill). systemd never restarts a unit it stopped itself
            // (`systemctl stop` leaves it `failed`), `docker stop` disables the restart policy
            // until the container is started again, and k8s only SIGTERMs a container whose pod
            // is already terminating — and SIGTERM is the ONLY thing that sets SUPERVISED_STOP.
            // So on the supervised path this code is a VERDICT, not a remedy: recovery runs on
            // the next START, and a human has to perform it. Say so where the human is looking.
            exit_code = 75;
            tracing::error!(
                "{recoverable} job(s) still hold collateral — START THE MINER AGAIN to run \
                 recovery. A supervisor-initiated stop (systemctl stop / docker stop / pod \
                 delete) will NOT auto-restart despite exit 75, and the lock is unrecoverable \
                 once its deadline passes."
            );
            if !headless {
                println!(
                    "{recoverable} job(s) STILL HOLD COLLATERAL — start the miner again to run \
                     recovery; a supervisor will not necessarily restart it for you."
                );
            }
        }
    }

    // 4. Only now tear down the workers. Releasing needs nothing but the job id, so keeping
    //    them alive until this point costs nothing and lets the drain path finish real work.
    // BOUNDED, for the same reason as the [F4] hard-kill reap: `shutdown_all` phase 4 takes a
    // BLOCKING slot lock while phases 2/3 skip any slot whose `pid` is momentarily 0 (the
    // dispatcher's respawn/recycle window), so it can block for a whole proof (up to the 600s
    // watchdog). On a SUPERVISED stop there is no third signal to reach the bounded copy, and
    // the [F5] exit code below is gated behind this call — an unbounded reap means the
    // supervisor SIGKILLs us before EX_TEMPFAIL is ever delivered and the sp1-gpu-server
    // grandchild keeps its VRAM anyway. Off-thread so it also can't block a runtime worker.
    {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            if let Some(pool) = zkminer_prover::engine::worker_pool() {
                tracing::info!("shutting down worker pool");
                pool.shutdown_all();
            }
            let _ = done_tx.send(());
        });
        if tokio::time::timeout(std::time::Duration::from_secs(10), done_rx).await.is_err() {
            tracing::warn!(
                "worker reap did not finish in 10s — exiting anyway; check for an orphaned \
                 sp1-gpu-server holding VRAM."
            );
        }
    }
    brain_handle.abort();
    refresh_handle.abort();

    if exit_code != 0 {
        std::process::exit(exit_code);
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

/// `f64::min`-fold helper: an empty fold yields INFINITY, which downstream would read as
/// "infinitely fast" rather than "unknown". Collapse any non-finite result to a caller-chosen
/// sentinel so the unknown case stays explicit.
trait FiniteOr {
    fn pipe_finite_or(self, fallback: f64) -> f64;
}
impl FiniteOr for f64 {
    fn pipe_finite_or(self, fallback: f64) -> f64 {
        if self.is_finite() { self } else { fallback }
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
    journal: SharedJournal,
    // Startup value, for the banner only. The loop reads the LIVE setting each tick so the
    // settings screen can change it — do not use this for decisions.
    initial_queue_horizon: Duration,
) {
    // Journal is owned by `run()` (see [B2]) so the shutdown path can read it. Recovery
    // reconciles the on-disk journal AND scans the chain for locked positions the
    // journal never captured (crash before write, cleared journal, other machine),
    // so it always runs — not only when the journal is non-empty.
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
    const WEDGE_CHECK_TICKS: u64 = 12; // ~60s between probes (iteration count, see below)
    /// A nominated hole must survive at least this long in WALL CLOCK before it is filled.
    const WEDGE_MIN_PERSIST: std::time::Duration = std::time::Duration::from_secs(45);
    // (nonce, when it was FIRST seen) — see the WEDGE_MIN_PERSIST gate below.
    let mut last_gap: Option<(u64, std::time::Instant)> = None;
    // [queue] Per-device backlog, so look-ahead admission can ask "when would this job
    // actually START" instead of assuming now. Self-correcting: entries decay with the wall
    // clock and are dropped on completion, so a wrong estimate cannot accumulate.
    // [cycles] Descriptor hash -> MEASURED cycle count, from executing the guest.
    //
    // Keyed on the descriptor hash, not the program id: cycles depend on the INPUT as well as
    // the program, and the descriptor hash covers both. Same descriptor => same execution =>
    // same count, so one measurement is valid forever.
    //
    // This exists because `expectedCycles` is submitter-declared and, on the observed market,
    // always zero (298/298 jobs) — leaving a 34e6 constant that is ~8x below the measured
    // median. Declaring it honestly costs the submitter a bond that scales with the count
    // (~1 HEMI per 9M cycles), so an empty field is the rational default and will stay that
    // way. Measuring it ourselves is the only reliable source.
    // Shared so the background measurement task below can populate it while the brain runs.
    let measured_cycles: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<alloy::primitives::B256, u64>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    // Descriptors already being measured, so N sightings of the same job spawn ONE execution.
    let measuring: std::sync::Arc<
        std::sync::Mutex<std::collections::HashSet<alloy::primitives::B256>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let mut queue_model = zkminer_strategy::queue::QueueModel::new();
    let mut queue_last_tick = std::time::Instant::now();
    if !initial_queue_horizon.is_zero() {
        tracing::info!(
            "queue look-ahead: up to {}s of work queued per GPU (deadline-checked from the \
             start time each job would actually get)",
            initial_queue_horizon.as_secs()
        );
    }

    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        tick_count = tick_count.wrapping_add(1);

        // Reap finished job tasks before re-evaluating the concurrency budget.
        while let Ok(jid) = done_rx.try_recv() {
            in_flight.remove(&jid);
            queue_model.settle(&jid.0);
        }
        {
            // Advance the backlog model by real elapsed time, not by tick count: the brain
            // loop awaits `recover_claimed_jobs` inline and can stall for minutes, and a
            // count-based decay would leave stale work blocking a device that is long idle.
            let now = std::time::Instant::now();
            queue_model.tick(now.duration_since(queue_last_tick));
            queue_last_tick = now;
        }

        // [nonce-review round 4] Nonce-gap watchdog (persistence-gated).
        // [A1] Not during shutdown. The ABANDON stage guards its own heal with
        // `frontier_has_executable_tx` precisely because a heal bids >= 4x base and would
        // replace our own still-mineable releaseJob with a 0-value self-transfer — stranding
        // exactly the nearest-deadline job it was trying to save. That guard was applied to
        // one of the two heal call sites; this is the other one, and the brain deliberately
        // keeps running through the drain, so it can fire mid-abandon. The abandon stage does
        // its own guarded heal, so skipping here loses nothing.
        if tick_count % WEDGE_CHECK_TICKS == 0 && !SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
            // [#6a] Persist on ELAPSED TIME, not on two sightings.
            //
            // `WEDGE_CHECK_TICKS` counts loop ITERATIONS of a 5s `tokio::time::interval`
            // whose default missed-tick behaviour is Burst, and `recover_claimed_jobs` awaits
            // `process_job_lifecycle` INLINE in this same loop. A long recovery pass therefore
            // replays the whole backlog at one instant, and two "sightings 60s apart" can land
            // microseconds apart. That voids the invariant the ungated watchdog heal rests on
            // — "a legit unsent reservation is sent within a tick, so a wedge that survives
            // ~90s is a real hole" — and turns the persistence gate into no gate at all.
            // A SEND-FREE EXIT from the exhausted-fee-cap state.
            //
            // `exhausted` is derived from purely local state (the recorded fee floor), and
            // the only thing that can invalidate it is chain truth. But the bail arms give
            // up BEFORE `tx.send()`, so no job path will ever learn that the resident tx
            // finally mined -- the very send that ended the 2026-08-14 incident at
            // 02:42:22 ("nonce too low: next nonce 11592" -> resync) no longer happens.
            // Without this, a jam that used to self-heal in 4h24m self-heals only if some
            // concurrent task happens to draw a fresh nonce and observe an error.
            //
            // One `eth_getTransactionCount(latest)` per WEDGE_CHECK_TICKS is enough:
            // `resync` prunes `fee_floor`, `freed`, `aborted_at` AND `undisplaceable`
            // below the mined frontier, so the moment the resident mines both the
            // exhaustion and the jam evaporate. Deliberately NOT inside the bail arms:
            // those run inside the `tx_lock` block expression and would hold the signer
            // lock across an RPC.
            // UNCONDITIONAL, deliberately not gated on `signer_is_jammed()`. Gating the
            // probe on the jam made the only thing that can DISPROVE the jam conditional
            // on believing in it -- and since the TTL sweep inside `is_jammed` deletes the
            // record at 120s while nothing can re-create it, the sweep that opened the
            // gate also switched the probe off. One `eth_getTransactionCount(latest)` per
            // WEDGE_CHECK_TICKS is cheaper than the `nonce_gap_frontier` read below.
            let jammed_before = client.jammed_nonce();
            match client.resync_nonce().await {
                Ok(chain) => {
                    if let Some(j) = jammed_before {
                        if chain > j {
                            // AUTHORITATIVE clear. The TTL is only a backstop for "the
                            // probe could not run"; chain truth outranks it.
                            client.clear_jammed_nonce(j);
                            tracing::info!(
                                "signer jam at nonce {j} cleared — the frontier has passed it \
                                 (chain={chain})"
                            );
                        } else {
                            // Chain truth CONFIRMS the jam is still real, so refresh the
                            // record. Without this the TTL means "time since first seen"
                            // and the gate silently forgets a live wedge after 120s.
                            client.refresh_jammed_nonce(j);
                        }
                    }
                }
                Err(e) => tracing::warn!("nonce resync probe failed: {e:#}"),
            }

            match client.nonce_gap_frontier().await {
                Ok(Some(gap)) => match last_gap {
                    Some((g, first_seen))
                        if g == gap && first_seen.elapsed() >= WEDGE_MIN_PERSIST =>
                    {
                        // [#1] Same hole, and it has genuinely persisted → fill THIS nonce.
                        match client.heal_nonce_gap_at(gap).await {
                            Ok(true) => last_gap = None,
                            Ok(false) => {} // fill not confirmed; retry next window
                            Err(e) => tracing::warn!("nonce gap-fill failed: {e:#}"),
                        }
                    }
                    // Same hole but not yet old enough. KEEP the original instant — load
                    // bearing: refreshing it would let a tick burst reset the clock forever.
                    Some((g, _)) if g == gap => {}
                    _ => last_gap = Some((gap, std::time::Instant::now())),
                },
                Ok(None) => last_gap = None, // no gap
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
                // [B5] Do not START a new recovery pass once shutdown has begun. Recovery
                // drives `process_job_lifecycle` INLINE, so a pass begun here would add work
                // the drain then has to wait for — and the `paused` gate below is checked
                // AFTER this block, so it does not cover us.
                // Gate on SHUTTING_DOWN, not `paused`: `paused` is also the TUI's operator
                // pause toggle, and recovery is the ONLY thing that still releases a job whose
                // earlier release failed on RPC (its breadcrumb is retained but it is gone from
                // `active_jobs`). Keying this on `paused` let a routine operator pause silently
                // disable that rescue until the lock deadline passed.
                if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
                    tracing::info!("recovery skipped — shutting down");
                    recovery_deferred = false;
                } else {
                    recovery_deferred =
                        recover_claimed_jobs(&client, &state, &journal, proving_timeout, recovery_lookback).await;
                }
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

        let (paused, open_jobs, max_concurrent, queue_horizon, benchmarks, stake_info) = {
            let s = state.read().await;
            (
                s.paused,
                s.open_jobs.clone(),
                s.runtime_settings.max_concurrent_proofs.max(1),
                // LIVE, not the startup value: the settings screen can change this while the
                // miner runs, exactly like max_concurrent_proofs. Reading the constructor
                // parameter here would leave the control decorative.
                std::time::Duration::from_secs(s.runtime_settings.queue_horizon_secs),
                s.benchmark_results.clone(),
                s.stake_info.clone(),
            )
        };

        if paused || open_jobs.is_empty() {
            continue;
        }
        // The hard concurrency cap still applies: look-ahead queues CLAIMS, it does not run
        // more proofs at once. With the horizon at zero this is exactly the old gate.
        // The 3x ceiling is EARNED by look-ahead admission, so it must ride the same
        // predicate. Gating the ceiling on the horizon alone while gating admission on the
        // horizon AND having device rows left a wedge: no gpu benchmark rows means the planner
        // never runs, yet the ceiling was still tripled — 3x capacity with nothing checking
        // start time, which is strictly worse than the feature being off. Reachable on this
        // box from a single NVIDIA driver bump: the benchmark cache is fingerprinted on driver
        // version, a mismatch discards it, and the synthetic fallback carries no device rows.
        //
        // `.any(gpu)` and not `!is_empty()`: the suite on this rig has three cpu rows, which
        // the slot builder drops.
        let planner_active = !queue_horizon.is_zero()
            && benchmarks.as_ref().is_some_and(|b| {
                b.device_benchmarks.iter().any(|d| d.device_id.starts_with("gpu"))
            });
        let claim_ceiling = if !planner_active {
            max_concurrent
        } else {
            // Enough headroom to hold the horizon's worth of work in reserve, bounded so a
            // mis-estimate cannot run away and lock unbounded collateral.
            max_concurrent.saturating_mul(3)
        };
        if in_flight.len() >= claim_ceiling {
            continue;
        }

        // Do not take on new collateral while the signer is JAMMED by an undisplaceable
        // nonce: nothing at or above it can mine, so a claim bonds collateral that no
        // fulfill and no release can free. On 2026-08-14 a 4h24m jam let three jobs age
        // past their lock deadline exactly this way, and past the deadline `releaseJob`
        // REVERTS, so the collateral is stranded outright.
        //
        // Gated HERE, before the candidate loop, rather than after it: the loop DELETES
        // each admitted job from `state.open_jobs` (which is fed by a forward-only monitor
        // stream with no re-discovery), so discarding a built batch permanently drops
        // those jobs -- and since candidates are sorted by descending price, it drops the
        // most valuable ones first, for the life of the process. Gating early also skips
        // the per-tick Multicall3 and adapter reads that would be spent building a batch
        // we would only throw away.
        //
        // This gates only NEW work. Jobs already held keep being driven: their fulfill can
        // still land the moment the jam clears, and that is the outcome worth protecting.
        if client.signer_is_jammed() {
            if tick_count % WEDGE_CHECK_TICKS == 0 {
                tracing::warn!(
                    "signer jammed at nonce {:?} — not claiming new work until it clears; \
                     held jobs continue",
                    client.jammed_nonce()
                );
            }
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

        // [queue] GPU rows of the benchmark suite, as (dispatcher-visible id, cycles/sec).
        // Keyed on the BENCHMARK device id (`gpu0`), not the dispatcher's (`risc0:cuda:0`):
        // the model only needs stable, distinct keys, and these are what carry a throughput.
        // A GPU with no benchmark row still appears, with 0.0, so the planner falls back to
        // the suite average rather than silently excluding it.
        let device_throughputs: Vec<(String, f64)> = {
            let mut v: Vec<(String, f64)> = Vec::new();
            for d in &benchmarks.device_benchmarks {
                if !d.device_id.starts_with("gpu") {
                    continue; // CPU rows are not proving slots here
                }
                match v.iter_mut().find(|(id, _)| *id == d.device_id) {
                    // Several backends per device; keep the fastest, which is what the
                    // dispatcher would pick for this job.
                    Some((_, t)) => *t = t.max(d.throughput),
                    None => v.push((d.device_id.clone(), d.throughput)),
                }
            }
            v
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
        // [headroom] Collateral reserved by claims made THIS tick. `stake_info` is a
        // tick-start snapshot and is never re-read, so it does not reflect them; pairing it
        // with a post-claim `in_flight.len()` would count each claim twice.
        let mut reserved_this_tick: u128 = 0;
        // [headroom] Was ANY job affordable on collateral alone? NOT the same as
        // `claimed_this_tick`: `Recommendation::Claim` also requires profit, risk and
        // deadline feasibility, so a rich wallet that skips on profit would otherwise report
        // "0 of N slots fundable — stake more".
        let mut any_affordable = false;
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
            // Preference order: the submitter's declaration, then our own MEASUREMENT, then
            // the constant. A measured value beats the constant by ~8x in accuracy; the
            // declaration is preferred only because it is backed by the submitter's bond.
            let estimated_cycles = if snapshot.expected_cycles > 0 {
                snapshot.expected_cycles
            } else if let Some(c) = measured_cycles
                .lock()
                .ok()
                .and_then(|m| m.get(&snapshot.descriptor_hash).copied())
            {
                c
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
            // [headroom] Collateral alone was enough for this job, whatever else decided it.
            // Distinguishes "we have no money" from "we declined on profit/risk/deadline".
            if eval.collateral_sufficient {
                any_affordable = true;
            }
            if !eval.collateral_sufficient && eval.deadline_feasible {
                collateral_blocked_count += 1;
                cheapest_collateral_block = Some(
                    cheapest_collateral_block
                        .map_or(required_collateral, |c| c.min(required_collateral)),
                );
            }
            // [queue] Look-ahead admission. `evaluate_job` above answered "is this job worth
            // doing and could it finish if it started NOW". That second half is exactly the
            // assumption queueing breaks, so re-ask it against the start time the job would
            // actually get. With `queue_horizon_secs = 0` the planner admits only an idle
            // device, which is the historical one-job-per-GPU behaviour.
            //
            // Refusing here is NOT the same as `Recommendation::Skip`: the job may be perfectly
            // profitable and simply not fit our queue yet, so it must not count toward the
            // collateral-starvation signals below.
            // The planner is ACTIVE only when look-ahead is on AND we actually know what the
            // devices can do. Both guards are load-bearing:
            //   * horizon 0 is the documented default and must behave exactly as before;
            //   * `device_throughputs` is EMPTY in three shipped configurations — a fresh
            //     install (skip_benchmark_gate defaults true, so the synthetic suite carries
            //     no device rows and nothing auto-benchmarks headless), a CPU-only rig, and
            //     any cached suite predating the field.
            // Without this, `plan_admission` returned NoUsableDevice for every job forever and
            // the miner claimed NOTHING, at the default config, visible only in a debug line.
            // [round-2] Never queue AHEAD on a job whose cycle count we do not know.
            //
            // Measured across two soaks: 298 of 298 evaluations had `expected_cycles == 0`, so
            // `estimated_cycles` was always FALLBACK_ESTIMATED_CYCLES (34e6). That estimates
            // 14.9s on gpu0 against a real median of 123s — 8x under. The committed backlog
            // then decays to zero within a few brain ticks while the proof runs for another
            // ~100-290s, so `slots()` reports a busy card as idle, `HorizonFull` and
            // `DeadlineInfeasible` become unreachable, and the ONLY surviving bound is the
            // tripled ceiling. That is 3x depth gated by a start-now check — exactly the
            // shape that loses collateral.
            //
            // A declared cycle count is the planner's whole input. Without one, fall through
            // to the pre-feature idle-device rule rather than queue on a fiction.
            // Measured counts as measurable: the planner needs a real number, and it does not
            // care whether the submitter declared it or we executed the guest ourselves.
            let measurable = snapshot.expected_cycles > 0
                || measured_cycles
                    .lock()
                    .map(|m| m.contains_key(&snapshot.descriptor_hash))
                    .unwrap_or(false);

            // [cycles] Never measured this descriptor and the submitter did not declare one?
            // Run the guest through the RISC-V executor in the background to learn its TRUE
            // cycle count, so the NEXT sighting of this descriptor can be planned on a real
            // number instead of the 34e6 constant. Deliberately does not block this tick:
            // the job in front of us is claimed (or not) on today's information, and the
            // measurement improves every future decision about the same work. The market
            // recycles a small set of descriptors, so one execution each buys accurate
            // sizing for everything that follows.
            if !measurable {
                let dh = snapshot.descriptor_hash;
                let fresh = measuring.lock().map(|mut m| m.insert(dh)).unwrap_or(false);
                if fresh {
                    let (c2, st2, cache, inflight) = (
                        client.clone(),
                        state.clone(),
                        measured_cycles.clone(),
                        measuring.clone(),
                    );
                    let pid = job.info.program_id;
                    tokio::spawn(async move {
                        let outcome = measure_cycles(&c2, &st2, jid, dh, pid).await;
                        match outcome {
                            Ok(cycles) => {
                                tracing::info!(
                                    "measured {} cycles for descriptor {} by execution — \
                                     future jobs with this descriptor will be sized on it",
                                    cycles,
                                    short_id(dh)
                                );
                                if let Ok(mut m) = cache.lock() {
                                    m.insert(dh, cycles);
                                }
                            }
                            Err(e) => tracing::debug!(
                                "cycle measurement for {} failed: {e:#}",
                                short_id(dh)
                            ),
                        }
                        // Always clear the in-flight marker, so a transient failure does not
                        // permanently prevent a retry.
                        if let Ok(mut m) = inflight.lock() {
                            m.remove(&dh);
                        }
                    });
                }
            }
            // A bypassed claim occupies a GPU without being committed to the model, so the
            // model then UNDER-reports that device and the planner would place a later job as
            // though the card were idle — void at depth 1, not just depth 2. Refuse to plan
            // against a model we know is incomplete rather than plan against a fiction.
            let model_complete = queue_model.outstanding() == in_flight.len();
            let admission = if planner_active
                && measurable
                && model_complete
                && matches!(eval.recommendation, Recommendation::Claim)
            {
                let slots = queue_model.slots(&device_throughputs);
                match zkminer_strategy::queue::plan_admission(
                    &slots,
                    queue_horizon,
                    params.estimated_cycles,
                    std::time::Duration::from_secs(time_remaining),
                    deadline_safety_margin,
                    // Fallback for a GPU with no benchmark row. Deliberately NOT
                    // `average_throughput()`: that averages the 18 canonical results
                    // INCLUDING cpu rows and comes out at ~3.03M cycles/s on this rig —
                    // 2.11x the 4090's measured 1.44M. An unbenchmarked GPU would be modelled
                    // as more than twice as fast as the slowest real card, so its estimate
                    // would be under half the true duration and the deadline check would
                    // admit work that cannot finish. Use the SLOWEST known GPU instead: for
                    // an unknown device, pessimistic is the only safe direction.
                    // NB: 0.0 when nothing is known, NOT infinity — an empty `min` fold
                    // yields INFINITY, which would make every estimate zero-duration and
                    // admit without limit. `plan_admission` treats 0.0 as NoUsableDevice and
                    // refuses, which is the correct answer when we cannot estimate at all.
                    device_throughputs
                        .iter()
                        .map(|(_, t)| *t)
                        .filter(|t| t.is_finite() && *t > 0.0)
                        .fold(f64::INFINITY, f64::min)
                        .pipe_finite_or(0.0),
                ) {
                    Ok(a) => Some(a),
                    Err(reason) => {
                        // HorizonFull is the healthy saturated state; log the others, which
                        // mean we are being offered work this rig cannot serve.
                        if !matches!(reason, zkminer_strategy::queue::Rejection::HorizonFull) {
                            tracing::debug!(
                                "queue: not admitting {} ({:?}, cycles={}, {}s left)",
                                short_id(jid), reason, params.estimated_cycles, time_remaining,
                            );
                        }
                        None
                    }
                }
            } else {
                None
            };

            // When the planner is inactive the old gate is the whole gate: `claim_ceiling`
            // equals `max_concurrent`, so this is byte-for-byte the pre-feature behaviour.
            // A BYPASSED claim never faced `plan_admission`, so it has not earned the
            // look-ahead headroom and must be held to the pre-feature cap.
            //
            // The previous version asserted exactly this in prose and did not deliver it:
            // `claim_ceiling` rides `planner_active`, which is per-TICK, while `measurable` is
            // per-JOB. On the only market ever observed — 298/298 jobs declaring zero cycles —
            // turning the horizon on gave `claim_ceiling = max_concurrent * 3` with
            // `plan_admission` never called and `queue_model` permanently empty: 3x claim depth and ZERO
            // admission checking, strictly worse than the feature being off. That is the shape
            // the round-2 fold graded critical and believed it had closed.
            let queue_bypass = !planner_active || !measurable;
            if (admission.is_some() || (queue_bypass && in_flight.len() < max_concurrent))
                && matches!(eval.recommendation, Recommendation::Claim)
            {
                claimed_this_tick = true;
                // Reserve the slot + collateral NOW (like the single-claim path always
                // did): inserting into in_flight immediately makes the loop-top
                // `in_flight.contains_key` guard dedup a job that appears twice in
                // open_jobs, and keeps this tick's collateral math correct. Remove from
                // open_jobs so we don't re-pick it before the claim lands. The batch is
                // dispatched after the loop; a job that doesn't actually lock has its
                // slot freed (done_tx) by the dispatch.
                in_flight.insert(jid, required_collateral);
                // [queue] Commit the admission to the backlog model, paired with the
                // `in_flight` insert so the two can never disagree about what is outstanding.
                // Without this the backlog stays at zero, every device looks idle, and the
                // horizon check admits without limit — the one bug that would turn look-ahead
                // into unbounded collateral lock-up. `settle` runs off the same done channel
                // that removes from `in_flight`, and the dispatch path frees a job that fails
                // to lock via `done_tx`, so both maps drain together.
                if let Some(a) = &admission {
                    // The FINISH OFFSET, not the work duration. `tick` decays every entry by
                    // elapsed wall time, which is only meaningful for "time until this job
                    // finishes"; storing work duration and SUMMING made a device holding k
                    // jobs shed k seconds of modelled backlog per wall second, so the
                    // planner's one invariant — feasible from the start it would actually get
                    // — was void at any depth >= 2, i.e. the feature's own steady state.
                    queue_model.commit(jid.0, &a.device_id, a.finishes_in);
                }
                reserved_this_tick = reserved_this_tick.saturating_add(required_collateral);
                available_collateral = available_collateral.saturating_sub(required_collateral);
                {
                    let mut s = state.write().await;
                    s.open_jobs.retain(|j| j.info.job_id != jid);
                }
                batch.push(((*job).clone(), snapshot, required_collateral));

                // Bound to free proving slots (never lock more than we can prove before
                // their deadlines) and to the contract's MAX_BATCH_SIZE. in_flight now
                // includes this tick's collected jobs, so its length is the capacity gate.
                if in_flight.len() >= claim_ceiling || batch.len() >= MAX_CLAIM_BATCH {
                    break;
                }
            }
        }

        // ── Dispatch the collected claim batch ───────────────────────────────────
        // [B5] Re-check `paused` HERE. The snapshot taken at the top of this tick is many
        // awaits old (the candidate status multicall + per-system adapter fetches), and since
        // [B5] the brain is no longer aborted when shutdown begins — so a signal landing
        // inside that window would let this straddling tick lock BRAND NEW collateral during
        // the drain, which a 6s supervised budget can never fulfil. Nothing on-chain has
        // happened yet (the breadcrumb and the tx both come after this point), so dropping
        // the batch just returns the reserved slots.
        if !batch.is_empty() && state.read().await.paused {
            tracing::info!(
                "shutdown began mid-tick — dropping {} pending claim(s), nothing locked",
                batch.len()
            );
            // Put the candidates BACK. `state.open_jobs` is fed by a forward-only monitor
            // stream with no re-discovery (see the collection loop), so a job removed here
            // and not restored is gone for the life of the process -- and candidates are
            // price-sorted descending, so this drops the most valuable ones first.
            {
                let mut s = state.write().await;
                for (job, _, _) in batch.drain(..) {
                    let jid = job.info.job_id;
                    if !s.open_jobs.iter().any(|j| j.info.job_id == jid) {
                        s.open_jobs.push(job);
                    }
                    let _ = done_tx.send(jid); // free the reserved in_flight slot
                }
            }
            continue;
        }
        // Do not take on new collateral while the signer is JAMMED by an undisplaceable
        // nonce. Nothing at or above that nonce can mine, so a claim here bonds collateral
        // that no fulfill and no release can free -- on 2026-08-14 a 4h24m jam at nonce
        // 11589 let three jobs age past their lock deadline exactly this way, and past the
        // deadline releaseJob reverts, so the collateral is stranded outright.
        //
        // This gates only NEW work. Jobs already held keep being driven: their fulfill can
        // still land the moment the jam clears, and that is the outcome worth protecting.
        // Defence in depth: the primary gate is above the candidate loop. Reaching here
        // means the jam arrived DURING this tick's collection, so the batch is already
        // built and those jobs are already out of `open_jobs`.
        if !batch.is_empty() && client.signer_is_jammed() {
            tracing::warn!(
                "signer jammed at nonce {:?} mid-tick — dropping {} pending claim(s) rather \
                 than bonding collateral we cannot release; held jobs continue",
                client.jammed_nonce(),
                batch.len()
            );
            {
                let mut s = state.write().await;
                for (job, _, _) in batch.drain(..) {
                    let jid = job.info.job_id;
                    if !s.open_jobs.iter().any(|j| j.info.job_id == jid) {
                        s.open_jobs.push(job);
                    }
                    let _ = done_tx.send(jid);
                }
            }
            continue;
        }
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

                    // [B5] Shutdown began between the brain's pre-dispatch `paused` gate and
                    // this task's first RPC (spawn scheduling + `claim_job_batch`'s throttled
                    // pre-send round trips are seconds wide). Nothing is on-chain yet, so drop
                    // the intent breadcrumbs and bail BEFORE the broadcast: a claim landing now
                    // locks brand-new collateral on an exiting process, and ABANDON cannot free
                    // it (`release_and_clean` deliberately RETAINS a `Claiming` breadcrumb whose
                    // claim tx is still pending), so it would ride to its lock deadline.
                    if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
                        tracing::warn!(
                            "shutdown began before claimJobBatch broadcast — dropping {} pending \
                             claim(s), nothing locked",
                            jids.len()
                        );
                        for jid in &jids {
                            journal_update(&journal_c, |jj| jj.remove(*jid));
                        }
                        return; // `reclaim` still holds every jid → its Drop frees the slots
                    }

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

                    // [B5] Shutdown began while this speculative batch was in flight. The
                    // brain-side gate only stops a batch that has not been SPAWNED yet;
                    // nothing stopped one already running, and this task lives ~100s (the
                    // 90s claim wall cap plus the 3x3s reconcile). Do NOT dispatch lifecycles
                    // now: the `unknown` branch below re-attempts a FRESH claim
                    // (`claim_job_idempotent` claims when the view still reads open), locking
                    // brand-new collateral on a process that is about to exit, and a `locked`
                    // job cannot finish a multi-minute prove inside the drain budget. Every
                    // breadcrumb is already recorded, so the abandon path (and, failing that,
                    // recovery after the EX_TEMPFAIL restart) releases whatever we hold.
                    if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
                        tracing::warn!(
                            "shutdown began mid-batch-claim — not dispatching {} lifecycle(s); \
                             held job(s) left to the abandon path",
                            batch_jobs.len()
                        );
                        for (job, _, _) in &batch_jobs {
                            // Confirmed NOT ours: drop the breadcrumb so it can't inflate the
                            // recoverable count. Locked/unknown keep theirs.
                            if not_ours.contains(&job.info.job_id) {
                                journal_update(&journal_c, |jj| jj.remove(job.info.job_id));
                            }
                        }
                        // `reclaim` still holds every jid, so its Drop frees the slots.
                        return;
                    }
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
        // [headroom] Was `if !claimed_this_tick`, which only ever detected TOTAL starvation:
        // in PARTIAL starvation the miner still funds one claim, so the flag was true on
        // essentially every tick and the warning was suppressed. Live on 2026-08-08 that hid a
        // 4.25 HEMI shortfall for hours — 2 GPUs, in_flight never above 1/2, 2,851 DEBUG skips
        // and ZERO warnings, while 444,804 HEMI sat unstaked in the wallet.
        //
        // The capacity test below fires on partial starvation too. It is computed from the
        // ON-CHAIN available figure, NOT the loop residual in scope here: `locked` already
        // includes live in-flight locks (measured: in_flight 2/2 -> locked = baseline + 2x),
        // and the brain deliberately subtracts them AGAIN as the documented D17 fail-safe, so
        // the residual under-reports by up to a full reservation and would over-warn.
        // Whether the headroom branch produced a verdict this tick; see the legacy warning
        // below for why that suppresses it.
        let mut headroom_reported = false;
        {
            let on_chain_avail = stake_info
                .as_ref()
                .map(|si| si.available_collateral)
                .unwrap_or(0);
            // Never advise staking for slots no GPU can serve: `resolve_max_concurrent`
            // returns an explicit config value as-is and does not clamp to detected cards.
            // `proving_gpu_count()` floors at 1, so a CPU-only box and a 1-GPU box are
            // indistinguishable here — that floor is why we never advise staking for more
            // than one slot on a box that reports one.
            let detected = zkminer_prover::engine::worker_pool()
                .map(|p| p.proving_gpu_count())
                .unwrap_or(1)
                .max(1);
            let slots_wanted = max_concurrent.min(detected);
            if let Some(per_claim) = cheapest_collateral_block {
                let h = zkminer_chain::staking::collateral_headroom(
                    // Net out this tick's own reservations so `available` and `funded`
                    // describe the same instant (defect 1).
                    on_chain_avail.saturating_sub(reserved_this_tick),
                    per_claim,
                    in_flight.len(),
                    slots_wanted,
                    any_affordable,
                );
                // NOTE: `cheapest_collateral_block.is_some()` proves ONE job was blocked on
                // collateral — it does NOT prove the market was otherwise unaffordable. That
                // is what `any_affordable` is for.
                // Publish EVERY tick, not only when starved and not throttled: this is a
                // status line, not an alert. Throttling it would leave a stale verdict on
                // screen after the operator fixes the shortfall, and clearing it only on the
                // warning path would leave "1 of 2" showing forever once the warning
                // rate-limiter kicked in.
                headroom_reported = true;
                {
                    let mut st = state.write().await;
                    st.collateral_headroom = Some(zkminer_tui::state::HeadroomView {
                        fundable: h.fundable,
                        wanted: h.wanted,
                        per_claim,
                        shortfall: h.shortfall,
                    });
                }
                if h.is_starved() {
                    let now = std::time::Instant::now();
                    let due = last_collateral_warn
                        .map_or(true, |t| now.duration_since(t) >= COLLATERAL_WARN_EVERY);
                    if due {
                        last_collateral_warn = Some(now);
                        let stake_cmd = zkminer_chain::staking::fmt_hemi_ceil(h.shortfall);
                        tracing::warn!(
                            "{}",
                            collateral_warning(
                                h.fundable, h.wanted, on_chain_avail, per_claim, h.shortfall,
                            )
                        );
                        let mut st = state.write().await;
                        st.add_log(
                            LogLevel::Warn,
                            format!(
                                "Only {fundable}/{wanted} GPU slots fundable — run \
                                 `zkminer stake {stake_cmd}`",
                                fundable = h.fundable,
                                wanted = h.wanted,
                                stake_cmd = stake_cmd
                            ),
                        );
                    }
                }
            }
        }
        // The legacy total-starvation warning. It shares `last_collateral_warn` with the
        // headroom branch above, and the headroom branch runs FIRST — so whenever headroom
        // warned, this is throttled out, and the only ticks it can still reach are the ones
        // where headroom was NOT starved. It therefore used to appear exclusively next to a
        // green "Slots fundable 2/2" verdict, quoting a DIFFERENT number for the same word:
        // its `available_collateral` is the brain's D17 residual, while the dashboard's
        // Liquid figure beside it is the on-chain value. Two answers for "available", in one
        // frame, with the alarming one attached to the healthy verdict.
        //
        // Suppressed when a headroom verdict exists: that verdict is strictly better
        // information (it knows how many slots are wanted and what the marginal ask is), and
        // when it says "not starved" the right conclusion is that this tick's block was a
        // transient reservation, not something the operator should stake against.
        if !claimed_this_tick && !headroom_reported {
            if let Some(needed) = cheapest_collateral_block {
                let now = std::time::Instant::now();
                let due = last_collateral_warn
                    .map_or(true, |t| now.duration_since(t) >= COLLATERAL_WARN_EVERY);
                if due {
                    last_collateral_warn = Some(now);
                    // Labelled "spendable now" rather than "available": this is the residual
                    // after the D17 fail-safe subtraction, deliberately smaller than both the
                    // on-chain figure and the dashboard's Liquid line.
                    let avail_hemi = fmt_hemi(available_collateral);
                    let needed_hemi = fmt_hemi(needed);
                    tracing::warn!(
                        "Not claiming — {} open job(s) blocked by insufficient collateral: {} HEMI \
                         spendable now (after reserving for jobs in flight), cheapest needs {} HEMI. \
                         Stake more, or wait for locked collateral to release.",
                        collateral_blocked_count,
                        avail_hemi,
                        needed_hemi,
                    );
                    let mut s = state.write().await;
                    s.add_log(
                        LogLevel::Warn,
                        format!(
                            "Insufficient collateral: {avail_hemi} HEMI spendable now, cheapest of {collateral_blocked_count} blocked job(s) needs {needed_hemi} HEMI"
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

    // [B5] Shutdown can begin between `spawn_lifecycle_task` and here. The brain's
    // pre-dispatch `paused` gate only closes the window up to the SPAWN; this task is
    // independent (`brain_handle.abort()` never reaches it, and it is not aborted at all) and
    // runs concurrently with the whole shutdown, so without this a signal landing here
    // broadcasts a fresh `claimJob` mid-drain — locking BRAND NEW collateral on a process
    // that is exiting. Worse, for the whole window between the spawn and the breadcrumb at
    // step 1 (which, with `claim_predicate_jobs=false`, is the predicate descriptor fetch —
    // bounded only by FETCH_FALLBACK_TIMEOUT, and a config that also FORCES this path) the
    // job is in neither `active_jobs` nor the journal, so the drain union reads straight past
    // it and exits "drain complete"/0. Mirrors the batch path's guard. Nothing is on-chain
    // yet, and `is_recovery` jobs are ALREADY locked so they must still be driven.
    if !is_recovery && SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
        tracing::warn!(
            "shutdown began before claiming {} — dropping, nothing locked",
            short_id(job_id)
        );
        let mut s = state.write().await;
        s.open_jobs.retain(|j| j.info.job_id != job_id);
        return Ok(());
    }

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

    // [B5] Re-check HERE, not only at the top of this fn. The guard above runs BEFORE the
    // predicate gate, whose `fetch_job_descriptor_checked` is bounded only by
    // FETCH_FALLBACK_TIMEOUT (an open job's snapshot deadline is 0, so `deadline_proof_budget`
    // yields no clamp) — and `claim_predicate_jobs=false` FORCES every claim onto that path.
    // For that whole window the job is in neither `active_jobs` nor the journal, so the drain
    // union reads straight past it, logs "drain complete"/exit 0 and skips ABANDON — while
    // this task then broadcasts a brand-new claimJob that nothing is left alive to release
    // (and exit 0 means `Restart=on-failure` never runs recovery either). Nothing is on-chain
    // yet and there is no await between this load and the breadcrumb below, so dropping is
    // free. `is_recovery` jobs are ALREADY locked and must still be driven.
    if !is_recovery && SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
        tracing::warn!(
            "shutdown began during the predicate gate for {} — dropping, nothing locked",
            short_id(job_id)
        );
        let mut s = state.write().await;
        s.open_jobs.retain(|j| j.info.job_id != job_id);
        return Ok(());
    }

    // 1. Record claim intent BEFORE sending the claim tx, so a crash mid-claim
    //    still leaves breadcrumbs for recovery.
    journal_update(journal, |j| j.record_claim_intent(job_id, snapshot.lock_deadline));

    {
        let mut s = state.write().await;
        s.add_log(LogLevel::Info, format!("Claiming job {}...", short_id(job_id)));
    }

    // [B5] The two shutdown gates above are both `!is_recovery`, but the batch reconcile
    // dispatches its UNKNOWN class with already_locked=true precisely BECAUSE ownership could
    // not be established — and for those `claim_job_idempotent` broadcasts a FRESH claimJob
    // whenever its pre-flight view still reads open. Nothing gates the window between that
    // dispatch and here (a throttled pre-flight read plus `claim_job`'s retry ladder), so a
    // signal landing in it locks BRAND-NEW collateral on an exiting process — and ABANDON
    // cannot free it, because `release_and_clean` correctly RETAINS a pending-claim breadcrumb
    // rather than releasing a job that reads open. Confirm ownership on-chain before claiming
    // once shutdown has begun; if we cannot PROVE we hold it, leave it — the breadcrumb
    // written above stays for ABANDON and for restart recovery. (The job is not in
    // `active_jobs` yet — that push is at step 3 — so returning here leaves no zombie in the
    // drain union.) Jobs we genuinely hold proceed exactly as before, at the cost of one extra
    // view read during shutdown only.
    if is_recovery && SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
        let held = matches!(
            client.get_job_status_view(job_id).await,
            Ok(v) if v.prover == client.address
        );
        if !held {
            tracing::warn!(
                "shutdown began before {} was confirmed ours — not (re)claiming; left to the \
                 abandon path",
                short_id(job_id)
            );
            let mut s = state.write().await;
            s.open_jobs.retain(|j| j.info.job_id != job_id);
            return Ok(());
        }
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
        // The monitor ingest hardcodes `lock_deadline: 0` (run.rs ~489), so without this
        // backfill EVERY in-session job carries deadline 0 and the shutdown path's
        // "nearest deadline first" release ordering sorts on all-zero keys — i.e. does not
        // order anything, and its past-deadline skip can never fire. `lock_deadline` here is
        // the authoritative value read from the post-claim status view a few lines above.
        let mut claimed_info = job.info.clone();
        claimed_info.lock_deadline = lock_deadline;
        s.active_jobs.push(TrackedJob {
            info: claimed_info,
            // Queued, not Proving: this job holds collateral but has not started. Showing it
            // as "Proving 0%" made a look-ahead queue indistinguishable from real work on a
            // card, which is precisely what an operator needs to see.
            status: MinerJobStatus::Queued,
            current_price: view.currentAuctionPrice.to::<u128>(),
            gpu_bus_id: None,
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
        // Cloned for the progress callback below, which runs on the blocking thread.
        let state_for_prove_progress = state.clone();
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
                // [queue] Flip Queued -> Proving the moment the dispatcher actually starts
                // work. Until now `on_progress` was unused and the status was set to
                // `Proving { progress: 0.0 }` at CLAIM time, so a job waiting for a card was
                // indistinguishable from one running on it — which is exactly the thing
                // look-ahead queueing makes common. This runs on the blocking thread, so a
                // blocking write is correct here; `try_write` and skip on contention, because
                // a missed cosmetic transition must never stall a proof.
                let started_state = state_for_prove_progress.clone();
                let started_id = job_id;
                // Exactly ONE Progress message is sent per proof (at start), so unlike a
                // progress STREAM a single missed lock strands the job in `Queued` for its
                // whole run with no second chance. Retry briefly rather than fire-and-forget.
                // Deliberately NOT `blocking_write()`: we are on a blocking thread so it would
                // be legal, but if any async holder of this lock is itself awaiting this proof
                // we would deadlock a real proof to fix a cosmetic label. A bounded retry
                // cannot deadlock and lands the transition in practice.
                let started_pool = pool.clone();
                let mark_started = move |_p: f64, slot_key: &str| {
                    // Which physical card took this job. Resolved through the pool
                    // rather than any index, so the dashboard can attribute the job
                    // to the right GPU row on a mixed-vendor box.
                    let bus = started_pool.bus_id_for_slot(slot_key);
                    for _ in 0..40 {
                        if let Ok(mut st) = started_state.try_write() {
                            if let Some(j) =
                                st.active_jobs.iter_mut().find(|j| j.info.job_id == started_id)
                            {
                                if matches!(j.status, zkminer_tui::state::MinerJobStatus::Queued) {
                                    j.status = zkminer_tui::state::MinerJobStatus::Proving {
                                        progress: 0.0,
                                        elapsed_secs: 0,
                                    };
                                }
                                if j.gpu_bus_id.is_none() {
                                    j.gpu_bus_id = bus.clone();
                                }
                            }
                            return;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                };
                let r = pool.prove_min_vram(
                    &backend_str,
                    &elf_clone,
                    &input_clone,
                    None,
                    Some(effective_timeout),
                    Some(Box::new(mark_started)),
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
                    // Match the dispatcher's ACTUAL deadline strings, not any message
                    // containing the word. A bare `contains("deadline")` makes this arm
                    // terminal for any text a worker or a third-party library happens to
                    // write, and commit 1 makes the poll-loop bail a common path on a
                    // single-key box, so the blast radius was about to grow.
                    if is_deadline_terminal(&msg) {
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
                        // BOTH non-invalid classes steer OFF the card that just failed.
                        //
                        // The OOM arm used to set a VRAM floor INSTEAD of excluding, and
                        // `LARGE_JOB_MIN_VRAM_BYTES` exceeds every card on this hardware
                        // (30 GiB vs 16303 and 24564 MiB). So the floor emptied the
                        // candidate set, `prove_min_vram` restored the FULL key set, and
                        // the retry landed straight back on the card that had just OOMed
                        // -- which, with the other card already excluded, left one key
                        // and took the single-key shortcut into an instant respawn-backoff
                        // bail. Observed in soak20 at 10:38:43.897 -> 10:38:44.580.
                        //
                        // Excluding cannot strand a job: `prove_min_vram` restores the
                        // full set when pruning empties it.
                        if !invalid {
                            if let Some(k) = used_slot.clone() {
                                if !excluded.contains(&k) {
                                    excluded.push(k);
                                }
                            }
                        }
                        // Kept as a PREFERENCE for a bigger card, never as a substitute
                        // for steering off the one that failed.
                        if real_oom {
                            min_vram = Some(LARGE_JOB_MIN_VRAM_BYTES);
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
    if let Err(e) = fulfill_result {
        // [F2] `Submitting` is the shutdown's proxy for "a fulfil is IN FLIGHT": the drain
        // excludes such a job from its nearest-deadline cut and ABANDON refuses to release it.
        // The fulfil is OVER here, and the only remaining releaser is this task's own
        // `release_and_clean` below — which the shutdown never joins and `process::exit` kills
        // mid-flight (release_job retries for up to ~750s). Leaving the status at `Submitting`
        // therefore makes the one job whose fulfil just failed the one job ABANDON will not
        // release. Clear it so both stages see the job again.
        {
            let mut s = state.write().await;
            if let Some(j) = s.active_jobs.iter_mut().find(|j| j.info.job_id == job_id) {
                j.status = MinerJobStatus::Skipped { reason: "fulfil failed — releasing".into() };
            }
        }
        return Err(anyhow::anyhow!("fulfillJob failed: {e:#}"));
    }

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

/// Measure a job's TRUE cycle count by running its guest through the RISC-V executor.
///
/// No proof is produced and no GPU is used — this is the simulator, so it costs execution time
/// rather than proving time, and it must not contend with the proofs it exists to schedule.
///
/// Why this is needed at all: every scheduling decision (deadline feasibility, the look-ahead
/// queue, the proving timeout) is sized from `expectedCycles` on the descriptor. That field is
/// SUBMITTER-DECLARED and, across 298 of 298 observed jobs, zero — because declaring it
/// honestly costs a `cycleCommitCollateral` bond that scales with the count (measured on-chain
/// at roughly 1 HEMI per 9M cycles). An empty field is therefore the rational default for a
/// submitter and will stay that way, leaving a hardcoded 34e6 constant that is ~8x below the
/// measured median. Executing the guest ourselves is the only reliable source.
async fn measure_cycles(
    client: &ChainClient,
    state: &zkminer_tui::state::SharedState,
    job_id: alloy::primitives::B256,
    descriptor_hash: alloy::primitives::B256,
    program_id: alloy::primitives::B256,
) -> anyhow::Result<u64> {
    // Cheap availability probe FIRST. The fetches below can hit the chain, and under load
    // most measurement attempts are skipped for a busy worker — doing the RPC work only to
    // throw it away wastes a throttled connection the proving path needs.
    {
        let pool = zkminer_prover::engine::worker_pool()
            .ok_or_else(|| anyhow::anyhow!("no worker pool available"))?;
        if !pool.has_idle_worker("risc0") {
            anyhow::bail!("no idle risc0 worker; deferring cycle measurement");
        }
    }

    // Both of these are locally cached after the first sighting of a program, so a repeat
    // descriptor costs no chain traffic.
    let descriptor = fetch_job_descriptor_checked(client, job_id, descriptor_hash).await?;
    let elf = fetch_or_download_elf(client, state, program_id).await?;
    let input: Vec<u8> = descriptor.inputData.to_vec();

    let pool = zkminer_prover::engine::worker_pool()
        .ok_or_else(|| anyhow::anyhow!("no worker pool available"))?;

    // Blocking: the worker protocol is synchronous. Bounded by the watchdog inside
    // `execute_cycles` so a non-terminating guest cannot wedge a worker forever.
    tokio::task::spawn_blocking(move || {
        pool.execute_cycles("risc0", &elf, &input, Some(MEASURE_TIMEOUT))
    })
    .await
    .map_err(|e| anyhow::anyhow!("cycle measurement task panicked: {e}"))?
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
    release_and_clean_with_nonce(client, state, journal, job_id, None).await
}

/// As [`release_and_clean`], but with a nonce the caller already reserved (see
/// `ChainClient::release_job_with_nonce`). Every path that skips the release recycles it.
async fn release_and_clean_with_nonce(
    client: &ChainClient,
    state: &zkminer_tui::state::SharedState,
    journal: &SharedJournal,
    job_id: alloy::primitives::B256,
    pre_nonce: Option<u64>,
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
            // [D1] `prover == ZERO` (the job still reads OPEN) does NOT prove our claim never
            // landed: the claimJob(Batch) tx may still be pending, or this node may simply be
            // behind the claim block — the same lag `DEADLINE_READ_RETRIES` exists for, and
            // the reason `classify_reconcile` treats ZERO as UNKNOWN rather than NotOurs. A
            // journal entry still in `Claiming` means exactly "claim sent, never confirmed",
            // so dropping the breadcrumb here is irreversible: the tx mines seconds later,
            // collateral locks, and nothing tracks it — not the drain/abandon union, and not
            // the next startup (with the entry gone `recoverable` is 0, so the EX_TEMPFAIL
            // restart that would run the on-chain recovery scan never fires). RETAIN it; a
            // claim that genuinely lost is GC'd by the next recovery pass, which re-reads the
            // view and drops it via the `Some(_)` arm.
            //
            // The same rule holds for an entry PAST `Claiming`: `mark_claimed` only runs
            // after a post-claim view returned a NONZERO lockDeadline (and recovery's only
            // after a view proved `prover == us && Locked`), so a Claimed/Proving/Fulfilling
            // entry has POSITIVELY OBSERVED the collateral locked — a later ZERO read is a
            // lagging replica far more often than a real reopen. Retain while the recorded
            // deadline could still be met; a genuinely slashed/reopened job is past its
            // deadline and is still dropped by this arm exactly as before.
            let (unconfirmed_claim, deadline_live) = {
                let j = journal.lock().unwrap_or_else(|p| p.into_inner());
                match j.entries.get(&job_id) {
                    Some(e) => (
                        e.state == crate::journal::JournalState::Claiming,
                        e.lock_deadline == 0
                            || e.lock_deadline > chrono::Utc::now().timestamp().max(0) as u64,
                    ),
                    None => (false, false),
                }
            };
            if view.prover == alloy::primitives::Address::ZERO
                && (unconfirmed_claim || deadline_live)
            {
                tracing::warn!(
                    "Job {} shows no on-chain prover but our lock is not provably gone — \
                     retaining breadcrumb (claim tx may still be pending, or this read is \
                     from a lagging node; recovery reconciles it)",
                    short_id(job_id)
                );
                // [#45] This arm SKIPS release_job too, and release_job is the only consumer
                // of the abandoned-fulfill stash. The sibling arms below drain it; this one
                // was added later and did not. A leaked stash nonce carries NO abort record
                // and is not in `freed`, so it is exactly the hole shape the shutdown gate
                // refuses to fill — every broadcast release above it then strands.
                if let Some(n) = client.take_abandoned_nonce(job_id) {
                    client.abort_nonce(n);
                }
                // Skipping the release — recycle the caller's pre-reserved nonce so it
                // cannot become a permanent gap in the signer's sequence.
                if let Some(n) = pre_nonce {
                    client.abort_nonce(n);
                }
                let mut s = state.write().await;
                s.active_jobs.retain(|j| j.info.job_id != job_id);
                return;
            }
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
            // "nonce too low", or — once `commit`/`resync` has raised the `consumed_below`
            // watermark — the abort simply no-ops) or never landed (abort correctly recycles
            // the gap).
            if let Some(n) = client.take_abandoned_nonce(job_id) {
                client.abort_nonce(n);
            }
            if let Some(n) = pre_nonce {
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
        // Persist the authoritative deadline into the breadcrumb. A fresh claim records intent
        // with the PRE-claim snapshot (0 for an open job) and `mark_claimed` never runs if the
        // lifecycle died before its post-claim view read, so an entry can sit at 0 forever —
        // and once the lifecycle is gone nothing else ever writes it. Every shutdown decision
        // keys off this field (the drain's stranded filter, the nearest-deadline cut, the
        // abandon ordering, the EX_TEMPFAIL gate), and all of them mis-handle 0.
        if lock_deadline != 0 {
            journal_update(journal, |j| {
                if let Some(e) = j.entries.get_mut(&job_id) {
                    e.lock_deadline = lock_deadline;
                }
            });
        }
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
            if let Some(n) = pre_nonce {
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

    let release_ok = match client.release_job_with_nonce(job_id, pre_nonce).await {
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
    // [D1] Breadcrumbs whose claim tx could still be LIVE. `prover == ZERO` (the job reads
    // OPEN) is UNKNOWN, never "not ours": a claim still pending and a lagging post-mine read
    // are indistinguishable from it — the rule `classify_reconcile` and `release_and_clean`
    // already apply. Dropping such an entry is irreversible: the tx mines seconds later,
    // collateral locks, and NOTHING tracks it (the drain/abandon union and the EX_TEMPFAIL
    // gate read only `active_jobs ∪ journal`, so the miner exits 0 and is never restarted
    // into the recovery scan that is the only remedy). Bound it by the same age the drain
    // uses, so a claim that genuinely lost is still GC'd once it ages out.
    let live_claim_intent: std::collections::HashSet<B256> = {
        let now_s = chrono::Utc::now().timestamp().max(0) as u64;
        let j = journal.lock().unwrap_or_else(|p| p.into_inner());
        j.iter()
            .filter(|e| {
                // The age bound covers an UNCONFIRMED claim (deadline still unknown). But an
                // entry that got past `Claiming` has POSITIVELY OBSERVED the lock —
                // `mark_claimed` only runs after a view returned a nonzero lockDeadline — and
                // such a job is routinely older than this bound (a proof plus fulfil retries
                // alone exceed 900s). On the same ZERO read `release_and_clean` RETAINS those
                // (`deadline_live`); without the second clause here recovery instead DELETES
                // the breadcrumb of a job we may well still hold, and the shutdown ladder then
                // cannot see the lock at all (drain, abandon and the EX_TEMPFAIL gate read only
                // `active_jobs ∪ journal`, so the miner exits 0 and is never restarted into the
                // scan that is the only remedy). A genuinely slashed/reopened job is still GC'd
                // by the settled arm once its recorded deadline passes.
                now_s.saturating_sub(e.claimed_at.max(0) as u64) <= CLAIM_INTENT_MAX_AGE_SECS
                    || e.lock_deadline > now_s
            })
            .map(|e| e.job_id)
            .collect()
    };
    let before = job_ids.len();
    job_ids.retain(|jid| match views_map.get(jid) {
        // Ours AND still Locked → re-drive. Persist a breadcrumb NOW for anything
        // `find_locked_jobs` discovered that the journal lacks (cleared journal, crash before
        // the journal write, a claim from a previous machine). The only other writer is
        // `process_job_lifecycle` step 1, which never runs for the ids left behind when the
        // loop below breaks on shutdown / defers under a storm — and the drain union, the
        // abandon list and the EX_TEMPFAIL gate ALL read only `active_jobs ∪ journal`, so an
        // unjournaled lock is never released and does not even raise the restart exit code.
        // This view has just PROVEN the collateral is ours and locked.
        Some(v) if v.prover == client.address && v.status == JOB_STATUS_LOCKED => {
            let d = v.lockDeadline.to::<u64>();
            if !journal_has(journal, *jid) {
                tracing::warn!(
                    "recover: {} is locked to us with no journal entry — recording breadcrumb \
                     so the shutdown drain/abandon can see it",
                    jid
                );
                journal_update(journal, |j| j.mark_claimed(*jid, None, d));
            } else if d != 0 {
                // Backfill the authoritative deadline onto an EXISTING breadcrumb too. An
                // entry whose `mark_claimed` never ran (crash between the claim tx and the
                // post-claim view read; every claimJobBatch job until its lifecycle reaches
                // step 3) sits at 0 forever — and 0 is INVISIBLE to the drain's
                // nearest-deadline cut (it filters `d > now`), so the drain can burn its whole
                // budget straight through this job's real deadline. The view in hand has just
                // proven the lock, and the loop below may `break` on shutdown before anything
                // else would have fixed it. Field-level write, not `mark_claimed`: that would
                // also regress a Proving/Fulfilling entry's state back to Claimed.
                journal_update(journal, |j| {
                    if let Some(e) = j.entries.get_mut(jid) {
                        e.lock_deadline = d;
                    }
                });
            }
            true
        }
        // [D1] Reads OPEN (prover == ZERO) while our claim could still be in flight →
        // UNKNOWN, not "not ours". KEEP the breadcrumb (see above) but do not re-drive it
        // this pass; a later pass GCs it once it ages out.
        Some(v)
            if v.prover == alloy::primitives::Address::ZERO
                && live_claim_intent.contains(jid) =>
        {
            tracing::warn!(
                "recover: {} reads OPEN but our claim may still be pending — retaining \
                 breadcrumb",
                jid
            );
            false
        }
        // Present but settled / held by another prover → drop the stale breadcrumb.
        Some(_) => {
            journal_update(journal, |j| j.remove(*jid));
            // [#45] Same rule as the serial not-ours / non-Locked arms below (and the one this
            // [M9] batch pre-filter largely bypasses): dropping the breadcrumb means no
            // `release_job` will ever run for this job again, and that is the ONLY consumer of
            // the abandoned-nonce stash. Leaking one leaves a hole with no local trace
            // (`is_freed`/`recently_aborted` both false) that wedges the whole signer.
            if let Some(n) = client.take_abandoned_nonce(*jid) {
                client.abort_nonce(n);
            }
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
        // [B5] Shutdown can begin MID-PASS: the gate at the call site only stops a pass from
        // STARTING. `process_job_lifecycle` is awaited INLINE below, so without this re-check
        // a pass already in flight keeps launching fresh multi-minute proves after `paused`,
        // and the drain blocks on them until jobs the abandon path could have released right
        // now are past their lock deadline (releaseJob then reverts = permanent loss).
        // Break, don't continue: the remaining ids keep their journal breadcrumbs and are
        // released nearest-deadline-first by the abandon path.
        // SHUTTING_DOWN, not `paused` — the TUI's `p` key sets `paused` too, and aborting a
        // recovery pass on it would skip the past-deadline `release_and_clean` below for jobs
        // whose collateral is actively ticking down.
        if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
            tracing::info!(
                "recover: shutdown began mid-pass — leaving remaining locked job(s) to the \
                 abandon path"
            );
            break;
        }
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
            // [D1] ZERO = the job reads OPEN = UNKNOWN, not "not ours" — keep the breadcrumb
            // while our claim could still be live (see `live_claim_intent` above); a later
            // pass GCs it once it ages out.
            if view.prover == alloy::primitives::Address::ZERO && live_claim_intent.contains(&jid)
            {
                tracing::warn!(
                    "recover: {} reads OPEN but our claim may still be pending — retaining \
                     breadcrumb",
                    jid
                );
                continue;
            }
            tracing::info!("recover: {} no longer ours (prover={})", jid, view.prover);
            journal_update(journal, |j| j.remove(jid));
            // [#45] Dropping the breadcrumb means no `release_job` will ever run for this job
            // again — and that is the only consumer of the abandoned-nonce stash. Drain it or
            // a fulfill that gave up leaves a permanent gap that wedges the whole signer.
            if let Some(n) = client.take_abandoned_nonce(jid) {
                client.abort_nonce(n);
            }
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
            // [#45] Same as the not-ours arm above: no release_job will run for this job
            // again, so a stashed fulfill nonce would leak as a permanent gap.
            if let Some(n) = client.take_abandoned_nonce(jid) {
                client.abort_nonce(n);
            }
            continue;
        }
        let lock_deadline = view.lockDeadline.to::<u64>();
        // [B5] Ownership is now PROVEN by the re-read above (prover == us, status == Locked) —
        // but this id can have reached the loop via the `None => true` arm (the whole batch
        // view was unreadable, e.g. a 429 storm) and, if `find_locked_jobs` discovered it, have
        // NO journal entry at all. The pre-loop retain arm writes a breadcrumb for exactly this
        // case; the per-job re-read path did not. The shutdown gates below `break` on the
        // promise that "the remaining ids keep their journal breadcrumbs" — without this write
        // that promise is false and the lock is invisible to the drain union, the abandon list
        // and the EX_TEMPFAIL gate (all read `active_jobs ∪ journal`), so it is never released
        // and does not even raise the restart exit code.
        if !journal_has(journal, jid) {
            tracing::warn!(
                "recover: {} is locked to us with no journal entry — recording breadcrumb so \
                 the shutdown drain/abandon can see it",
                jid
            );
            journal_update(journal, |j| j.mark_claimed(jid, None, lock_deadline));
        }
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
            gpu_bus_id: None,
            prover_backend: String::new(),
            estimated_cycles: view.expectedCycles,
        };
        tracked.info.program_id = descriptor.programId;

        // [B5] The gate at the top of this iteration is many awaits old by now: the per-job
        // view re-read above and `fetch_job_descriptor_checked` (a cold-cache getLogs
        // reconstruction, throttled and retried under a 429 storm) can span tens of seconds.
        // `process_job_lifecycle` deliberately does NOT re-check for `is_recovery` jobs, so
        // without this a shutdown landing in that window drives a whole fresh lifecycle — and
        // if ABANDON has already released this job, step 2's `claim_job_idempotent` sees
        // prover == ZERO and RE-CLAIMS it, locking brand-new collateral on an exiting process.
        // Break, not continue: remaining ids keep their breadcrumbs for the abandon path.
        if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
            tracing::info!(
                "recover: shutdown began during descriptor fetch — leaving {} and any remaining \
                 locked job(s) to the abandon path",
                jid
            );
            break;
        }
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

    /// Commit 3. The dispatcher's three REAL deadline strings are terminal...
    #[test]
    fn the_dispatchers_real_deadline_strings_are_terminal() {
        for m in [
            "aborting proof: deadline cutoff reached while queued for a worker",
            "aborting proof on risc0:cuda:0: only 4s left before deadline cutoff after queuing",
            "proof on risc0:cuda:1 stopped: job deadline reached mid-proof (releasing to recover collateral)",
        ] {
            assert!(is_deadline_terminal(m), "should be terminal: {m}");
        }
    }

    /// ...and the transient failures that a bare `contains("deadline")` would have
    /// swallowed are NOT. The backoff string is the one that terminated all four jobs
    /// soak20 lost, so it must stay retryable.
    #[test]
    fn transient_failures_are_not_treated_as_deadline_terminal() {
        for m in [
            "Backoff: waiting 4.52991749s before respawning /home/user/.zkminer/provers/zkminer-prove-risc0-cuda",
            "Worker risc0:cuda:0 process died (EOF)",
            "allocation failed on evaluated: 1728053248 bytes",
            "failed to run groth16 prove operation: cudaGetLastError() failed: \"out of memory\"",
        ] {
            assert!(!is_deadline_terminal(m), "should be retryable: {m}");
        }
    }

    /// Commit 2's premise, pinned: the VRAM floor the OOM arm sets exceeds EVERY card on
    /// this hardware (16303 MiB / 24564 MiB), so using it INSTEAD of excluding the failed
    /// slot emptied the candidate set, `prove_min_vram` restored the full set, and the
    /// retry landed back on the card that had just OOMed. The floor is now a preference
    /// applied ALONGSIDE exclusion, never a substitute for it.
    #[test]
    fn the_large_job_vram_floor_is_inert_on_this_hardware() {
        const MIB: u64 = 1024 * 1024;
        for card_mib in [16_303u64, 24_564] {
            assert!(
                LARGE_JOB_MIN_VRAM_BYTES > card_mib * MIB,
                "a {card_mib} MiB card cannot satisfy a {} MiB floor — so the floor alone \
                 steers nowhere and exclusion is what must do the steering",
                LARGE_JOB_MIN_VRAM_BYTES / MIB
            );
        }
    }

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

#[cfg(test)]
mod collateral_warning_tests {
    use super::{collateral_warning, ONE_HEMI_WEI};
    use zkminer_chain::staking::fmt_hemi_ceil;

    /// Pins the arguments in place. The positional version of this sentence rotated its last
    /// two args and told the operator to stake 1 HEMI when they were 4.25 short.
    #[test]
    fn names_the_shortfall_as_the_stake_amount_not_the_gpu_count() {
        // The 2026-08-08 incident: 145.75 available, 150.00 per claim, 1 of 2 slots fundable.
        let msg = collateral_warning(1, 2, 145_750_000_000_000_000_000, 150 * ONE_HEMI_WEI,
                                     4_250_000_000_000_000_000);
        assert!(msg.contains("Fix: run `zkminer stake 4.25`"), "got: {msg}");
        assert!(msg.contains("1 GPU(s) will sit idle"), "GPU count must be a count: {msg}");
        assert!(msg.contains("Only 1 of 2 GPU slot(s) fundable"), "got: {msg}");
        assert!(msg.contains("145.75 HEMI available"), "got: {msg}");
        assert!(msg.contains("locks up to 150.00 HEMI"), "got: {msg}");
        // The bug verbatim, so it can never come back.
        assert!(!msg.contains("stake 1`"), "remediation is the GPU count again: {msg}");
        assert!(!msg.contains("4.25 GPU"), "shortfall leaked into the GPU count: {msg}");
    }

    /// At the soak's ~50 HEMI per_claim the rotated version undershot by ~35x.
    #[test]
    fn remediation_scales_with_per_claim_not_with_gpu_count() {
        let msg = collateral_warning(0, 2, 0, 50 * ONE_HEMI_WEI, 50 * ONE_HEMI_WEI);
        assert!(msg.contains("zkminer stake 50.00"), "got: {msg}");
        assert!(msg.contains("2 GPU(s) will sit idle"), "got: {msg}");
    }

    /// Whatever the warning prints must be enough when typed back in.
    #[test]
    fn the_printed_remediation_always_covers_the_shortfall() {
        for shortfall in [1u128, ONE_HEMI_WEI - 1, 4_250_000_000_000_000_001,
                          149_999_999_999_999_999_999, 333_333_333_333_333_333] {
            let printed = fmt_hemi_ceil(shortfall);
            assert!(collateral_warning(1, 2, 0, 150 * ONE_HEMI_WEI, shortfall)
                        .contains(&format!("zkminer stake {printed}")));
            let cents: u128 = printed.replace('.', "").parse().unwrap();
            assert!(cents * (ONE_HEMI_WEI / 100) >= shortfall,
                "printed {printed} is short of {shortfall} wei");
        }
    }
}
