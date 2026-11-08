use alloy::primitives::{Bytes, B256};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use zkminer_chain::client::ChainClient;
use zkminer_chain::descriptor::{fetch_job_descriptor_checked, verify_descriptor_hash};
use zkminer_chain::jobs::ClaimOutcome;
use zkminer_chain::monitor::{JobMonitor, MonitorEvent};
use zkminer_config::wallet::load_signer;
use zkminer_config::ZkMinerConfig;
use zkminer_prover::benchmark::{
    load_cached_benchmark, run_benchmark_gpu_only_streaming, save_benchmark,
};
use zkminer_prover::dispatcher::WorkerPool;
use zkminer_prover::engine::{backend_sources, init_worker_pool, BackendSource};
use zkminer_strategy::cost_model::CostParams;
use zkminer_strategy::evaluator::{evaluate_job, JobParams, Recommendation};
use zkminer_tui::state::{new_shared_state, LogLevel, MinerJobStatus, TrackedJob, WorkerStatus};

use crate::journal::JobJournal;

use zkminer_chain::adapter::AdapterInfo;

/// Safety margin (seconds) before lock_deadline beyond which we will not start
/// or continue work, to leave room for the fulfill tx to land before slashing.
const DEADLINE_FULFILL_MARGIN_SECS: u64 = 60;

/// Headroom (seconds) kept before a job's lock deadline for the abandon-and-release
/// path. The proving watchdog is clamped so a proof that won't finish in time
/// is killed while there's still this much room for `releaseJob` to land (it reverts
/// at/after the deadline, stranding collateral until a slash).
///
/// It reserves the WHOLE release ladder (`RELEASE_LADDER_SECS`: every fee-bumped same-nonce rung
/// with its receipt wait and state poll) plus 60 s of RPC slack, so a release whose first rungs are
/// dropped or out-bid still has rungs left before the window closes at D+G — a margin that fits one
/// rung strands every congested release (a 100% slash instead of the flat release penalty). The
/// proving-budget cost (jobs finish this much earlier) is the right trade: the penalty is flat, so
/// releasing earlier costs nothing, whereas a stranded lock is lost.
const DEADLINE_RELEASE_MARGIN_SECS: u64 = zkminer_chain::jobs::RELEASE_LADDER_SECS + 60;

/// The shortest lock window the contract allows: MIN_FULFILLMENT_TIMEOUT (300 s) + PROVER_GRACE.
const MIN_JOB_WINDOW_SECS: u64 = 300 + zkminer_chain::auction::PROVER_GRACE_SECS;

/// No new claims while the host clock and the chain's differ by more than this (see the claim gate).
/// Far above a header's normal lag (a 12 s block plus RPC latency), and well below the skew at which
/// a fresh lock on the shortest window (300 s + the 30-min PROVER_GRACE) would already look due for
/// release (about 1,470 s with the host ahead).
const MAX_CLAIM_CLOCK_SKEW_SECS: u64 = 300;

/// Below this much remaining proving budget it isn't worth starting another attempt
/// — abandon the job now, while `releaseJob` can still land, instead of
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
/// How long to wait before re-offering a job that was refused for host RAM.
///
/// Long enough that the proof in flight has a chance to finish and release its pages — a proof is
/// minutes, so sub-second retries just spin — and short enough to re-offer several times inside a
/// fulfilment window. Not an attempt: see the shortage arm in the proving retry loop.
const HOST_MEMORY_BACKOFF_SECS: u64 = 15;

/// How many free host-RAM waits one job may take before a shortage starts costing attempts.
///
/// `MAX_HOST_MEMORY_WAITS * HOST_MEMORY_BACKOFF_SECS` is the longest a job will sit waiting for the
/// host before it goes back to the ordinary attempt budget — generous enough to outlast a proof in
/// flight, bounded so a permanently short host cannot hold a claim until its deadline.
const MAX_HOST_MEMORY_WAITS: u32 = 20;

/// How long to wait before retrying a job refused because the card's VRAM is held — by another
/// process, or by one of our own workers of the other backend that could not be recycled to make room
/// (its slot was busy, or its memory had not come back yet).
///
/// Shorter than the host-RAM backoff because the remedy is different in kind. A host-RAM shortage
/// clears when OUR proof in flight finishes, which takes minutes; foreign VRAM clears when a human
/// closes something, which can happen at any moment, and a busy sibling within seconds to a couple of
/// minutes (a cycle measurement holds one for up to `MEASURE_TIMEOUT`). Retrying sooner also re-reads
/// the OTHER card, which may have been busy with our own work on the previous attempt and free now.
const GPU_MEMORY_BACKOFF_SECS: u64 = 5;

/// How many free waits one job may take for held VRAM before it starts costing attempts.
///
/// Bounded for the same reason as `MAX_HOST_MEMORY_WAITS`: a refusal that refunds its attempt means
/// `MAX_PROVE_ATTEMPTS` no longer bounds the loop on its own, so a permanently occupied card must not
/// be able to hold a claim until its deadline.
const MAX_GPU_MEMORY_WAITS: u32 = 24;

/// How long a claimed risc0 job waits between looks for a card that can prove it, when none enabled
/// here has a job size. Unbounded in count: the job's deadline budget ends the wait in time to release.
const NO_RISC0_CARD_WAIT: Duration = Duration::from_secs(60);

/// Max claims spawned per brain tick (each is its own single-claim lifecycle). Further capped to
/// free proving slots so we never lock more than we can prove before their deadlines (the
/// stranding failure mode).
const MAX_CLAIM_BATCH: usize = 10;

/// The least time between brain passes when one is started early by a freed card (`CARD_FREED`)
/// rather than by the tick.
const MIN_EARLY_PASS_SPACING: Duration = Duration::from_secs(1);


/// Committed-cycle count above which a job is treated as "large" and proactively
/// pinned to a high-VRAM GPU (only takes effect when the job commits a cycle
/// count; uncommitted jobs still get the reactive OOM→high-VRAM retry).
const LARGE_JOB_CYCLES: u64 = 150_000_000;

/// VRAM floor (30 GiB) for large jobs — includes 32 GB cards, excludes 24 GB
/// ones, keeping OOM-prone multi-segment proofs off the smaller GPUs.
const LARGE_JOB_MIN_VRAM_BYTES: u64 = 30 * 1024 * 1024 * 1024;

/// Default blocks to scan on startup for locked-but-unfulfilled jobs (recovery; floored at the
/// deployment's first block). A lock can stay live for `fulfillmentTimeout` (<= 7 d) + PROVER_GRACE
/// (30 min) + a downtime extension (<= 24 h) + pause credit; the reference daemon's LOCK_LOOKBACK is
/// (7 d + 24 h + grace + 7 d) / 12 s = 108,150 blocks. Override with `chain.recovery_lookback_blocks`.
const DEFAULT_RECOVERY_LOOKBACK_BLOCKS: u64 = 108_150;

/// Default blocks to rewind the monitor start so it backfills already-open jobs at startup (not just
/// newly-submitted ones). Open jobs do not expire on their own, so by default the monitor rewinds to
/// the deployment's first block (`ChainClient::scan_from_block`; the monitor floors there). Override
/// with `chain.monitor_backfill_blocks` (0 = forward-only).
const DEFAULT_MONITOR_BACKFILL_BLOCKS: u64 = u64::MAX;

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
    let bytes = (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16));
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
/// The 600s proving watchdog is PER
/// ATTEMPT and `MAX_PROVE_ATTEMPTS = 3`, and fulfil adds up to 5 x (120s receipt + 30s poll)
/// = 750s, so a HEALTHY worst case is ~2850s. A shorter budget would abandon jobs that were
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
/// and `Submitting` jobs are excluded from abandon anyway — so waiting for their fulfil
/// cannot change what gets released. Budget = grace - release budget <= 0.
/// Zero costs nothing when nothing is held: the loop still breaks at "drain complete" on its
/// first pass; the budget was only ever spent in the case that needs the time for releases.
const SUPERVISED_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::ZERO;

const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3000);

/// Extra drain grace granted ONLY when every outstanding job is `Submitting` — i.e. when the
/// ABANDON stage has nothing to release (`Submitting` jobs are excluded) and waiting therefore costs the
/// release budget nothing. Sized to fit inside `docker stop`'s 10s grace: enough for a fulfil
/// that is mid pre-broadcast to reach the wire, or to give up and stash its nonce for the
/// lifecycle's own release. Without it a supervised stop (budget ZERO) exits before either,
/// leaving the job neither fulfilled nor released.
/// Cap on how long the ABANDON step waits for release RECEIPTS. The broadcasts have
/// already gone out; this only bounds the confirmation wait so the exit verdict, the worker
/// reap and the nonce heal are not stranded behind ~750s of retries that a supervisor's
/// SIGKILL would cut short anyway. Sized to sit inside systemd's 90s default with room for
/// the reap.
const RELEASE_JOIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(45);

/// Interactive stops have NO supervisor deadline, so the 45s supervised cap must not
/// apply: `release_job_with_nonce` runs 5 attempts x (120s receipt + 30s poll), meaning
/// attempt 2 cannot even start before ~150s. Capping at 45s abandons the release BEFORE the
/// first re-broadcast — earlier than the single-receipt-timeout give-up that jobs.rs:962-968
/// calls out as "the exact failure that leaves collateral locked". The operator can always
/// escalate with a third signal.
const INTERACTIVE_RELEASE_JOIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(800);

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

/// `zkminer run --watch-only`: every check up to the claim runs against the live market, and the
/// claim itself is replaced by a read-only preview that is logged. Nothing is signed or sent, no
/// lock is driven or released, and the job journal is never written. Set once, before the brain
/// starts.
static WATCH_ONLY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn watch_only() -> bool {
    WATCH_ONLY.load(std::sync::atomic::Ordering::SeqCst)
}

/// The options of `zkminer run --watch-only`.
pub struct WatchOnly {
    /// The prover address to watch as; the configured key's address when `None`.
    pub address: Option<alloy::primitives::Address>,
}

/// A lifecycle error on a lock we HOLD that must NOT be released: a pause or a Disabled adapter
/// (handoff §9 "never release because of a pause, a disable or a blacklist"), or an RPC failure that
/// left the lock's state unreadable ("never release on an RPC error without revert data"). The
/// spawn handler leaves the journal breadcrumb in place and asks the recovery pass to re-drive the
/// job from chain state instead of calling `release_and_clean`.
#[derive(Debug)]
struct HandBack(String);

impl std::fmt::Display for HandBack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "handed back to recovery: {}", self.0)
    }
}
impl std::error::Error for HandBack {}

/// Set when a lock was handed back to recovery (a pause KEEP, an unreadable post-claim state). The
/// brain then runs a recovery pass within `RECOVERY_REQUEST_FLOOR_TICKS` instead of waiting for the
/// periodic cadence.
static RECOVERY_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn request_recovery() {
    RECOVERY_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Locks KEPT through a protocol pause after their lifecycle failed. Recovery does not re-drive
/// these while the pause lasts (the same failure would just repeat) and re-drives or releases them
/// once it lifts. Bounded by the journal (only held locks are ever inserted).
static PAUSE_KEPT: std::sync::Mutex<Option<std::collections::HashSet<B256>>> =
    std::sync::Mutex::new(None);

fn note_pause_kept(job_id: B256) {
    let mut g = PAUSE_KEPT.lock().unwrap_or_else(|p| p.into_inner());
    g.get_or_insert_with(Default::default).insert(job_id);
}

fn take_pause_kept(job_id: B256) -> bool {
    let mut g = PAUSE_KEPT.lock().unwrap_or_else(|p| p.into_inner());
    g.as_mut().is_some_and(|s| s.remove(&job_id))
}

fn is_pause_kept(job_id: B256) -> bool {
    let g = PAUSE_KEPT.lock().unwrap_or_else(|p| p.into_inner());
    g.as_ref().is_some_and(|s| s.contains(&job_id))
}

/// Whether the risczero.groth16.v1 proof system passed verification (adapter registered and
/// claimable, audited code, SELECTOR equal to our seal prefix), and the adapter it verified. New
/// claims for it are refused while false; locks we already hold are still driven (fulfilled, kept or
/// released) — a failed check must never strand them. Re-checked periodically by the brain, so an
/// adapter swap or disable during a run is noticed.
static RISC0_VERIFIED_ADAPTER: std::sync::Mutex<Option<alloy::primitives::Address>> =
    std::sync::Mutex::new(None);

fn risc0_claimable() -> bool {
    DEPLOYMENT_VERIFIED.load(std::sync::atomic::Ordering::SeqCst) && risc0_adapter_verified()
}

fn risc0_adapter_verified() -> bool {
    RISC0_VERIFIED_ADAPTER
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_some()
}

/// The same for sp1.groth16.v1 (adapter registered and claimable, audited SP1Groth16VerifierAdapter and
/// circuit v6.1.0 verifier, `VERIFIER_HASH()` prefixing our seals), and the adapter it verified.
static SP1_VERIFIED_ADAPTER: std::sync::Mutex<Option<alloy::primitives::Address>> =
    std::sync::Mutex::new(None);

fn sp1_claimable() -> bool {
    DEPLOYMENT_VERIFIED.load(std::sync::atomic::Ordering::SeqCst) && sp1_adapter_verified()
}

fn sp1_adapter_verified() -> bool {
    SP1_VERIFIED_ADAPTER
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_some()
}

/// The first 4 bytes of every SP1 circuit v6.1.0 Groth16 seal (`VERIFIER_HASH()[0:4]`), which the SP1
/// worker's `proof.bytes()` already carries.
fn sp1_seal_prefix() -> [u8; 4] {
    let h = zkminer_chain::deployment::pins::SP1_V6_1_0_GROTH16_VERIFIER_HASH;
    [h[0], h[1], h[2], h[3]]
}

/// An SP1 Groth16 seal: the verifier hash prefix (4), the exit code, the vk root and the proof nonce
/// (32 each), then the 256-byte Groth16 proof.
const SP1_GROTH16_SEAL_LEN: usize = 4 + 3 * 32 + 256;

/// One miner per home directory: two would recover, prove and release the same locks, collide on
/// nonces, and overwrite each other's job journal (`~/.zkminer/job_journal.json`) — e.g. a second
/// one started while the first is still draining. An exclusive `flock` on `~/.zkminer/miner.lock`,
/// held for the life of the process (the kernel drops it when the process exits, however it exits;
/// the descriptor is close-on-exec, so no worker inherits it). Watch-only takes none: it never
/// writes the journal or sends anything.
pub(crate) fn hold_instance_lock() -> Result<()> {
    static LOCK: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();
    let dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zkminer");
    // Private to this user: anyone who can open the lock file can hold it (flock needs no write
    // access), and a held lock keeps a restarted miner from recovering its locks.
    {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&dir)
            .with_context(|| format!("create {}", dir.display()))?;
    }
    let path = dir.join("miner.lock");
    let file = {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?
    };
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
            "another zkminer is already running from {} (it holds {}) — two would drive the same \
             locks; stop it first (a stopping miner may still be draining)",
            dir.display(),
            path.display()
        ),
        Err(std::fs::TryLockError::Error(e)) => {
            return Err(e).with_context(|| format!("lock {}", path.display()))
        }
    }
    let _ = LOCK.set(file);
    Ok(())
}

/// Whether new claims on a job of `proof_system_id` from `submitter` for `program_id` are held right
/// now: the deployment or (risc0) the proof system failed verification, or the post-claim divergence
/// breaker holds them.
fn claims_held_for(
    proof_system_id: B256,
    submitter: alloy::primitives::Address,
    program_id: B256,
) -> bool {
    let backend = resolve_backend(proof_system_id);
    !DEPLOYMENT_VERIFIED.load(std::sync::atomic::Ordering::SeqCst)
        || (backend == Some("risc0") && !risc0_claimable())
        || (backend == Some("sp1") && !sp1_claimable())
        || backend.is_some_and(|b| divergence_blocks_claim(submitter, program_id, b))
}

/// Whether the deployment itself last passed `verify_deployment` (this chain's live stack, wired to
/// itself, running the audited code). Like the proof-system check, a failure only stops NEW claims:
/// locks we already hold sit in this router's custody and are still driven, and a miner that refused
/// to start would leave them to a 100% slash — after a governance upgrade, on every restart. Re-run
/// on the proof-system cadence, so an upgrade during a run stops claims too.
static DEPLOYMENT_VERIFIED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// How often a deployment that failed its check is checked again.
const DEPLOYMENT_RETRY: Duration = Duration::from_secs(60);

/// Run `verify_deployment` and record the outcome (see [`DEPLOYMENT_VERIFIED`]): a pass sets it, a
/// definite refusal clears it, and an RPC error leaves it as it was — one 429 among its reads says
/// nothing about the deployment.
async fn reverify_deployment(client: &ChainClient) -> Result<Vec<String>> {
    let r = client.verify_deployment().await;
    match &r {
        Ok(_) => DEPLOYMENT_VERIFIED.store(true, std::sync::atomic::Ordering::SeqCst),
        Err(e)
            if e.downcast_ref::<zkminer_chain::deployment::DeploymentRefused>()
                .is_some() =>
        {
            DEPLOYMENT_VERIFIED.store(false, std::sync::atomic::Ordering::SeqCst)
        }
        Err(_) => {}
    }
    r
}

/// Run `verify_proof_system` for risc0 and record the outcome (see [`RISC0_VERIFIED_ADAPTER`]).
async fn reverify_risc0(client: &ChainClient) -> Result<alloy::primitives::Address> {
    let r = client
        .verify_proof_system(
            zkminer_chain::auction::ProofSystem::Risc0Groth16,
            risc0_seal_selector(),
        )
        .await;
    let mut g = RISC0_VERIFIED_ADAPTER.lock().unwrap_or_else(|p| p.into_inner());
    match &r {
        Ok(a) => *g = Some(*a),
        // Only a definite refusal clears the verdict: one 429 says nothing about the adapter.
        Err(e) if e.downcast_ref::<zkminer_chain::deployment::ProofSystemRefused>().is_some() => *g = None,
        Err(_) => {}
    }
    r
}

/// Run `verify_proof_system` for SP1 Groth16 and record the outcome (see [`SP1_VERIFIED_ADAPTER`]).
async fn reverify_sp1(client: &ChainClient) -> Result<alloy::primitives::Address> {
    let r = client
        .verify_proof_system(
            zkminer_chain::auction::ProofSystem::Sp1Groth16,
            sp1_seal_prefix(),
        )
        .await;
    let mut g = SP1_VERIFIED_ADAPTER
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    match &r {
        Ok(a) => *g = Some(*a),
        Err(e)
            if e.downcast_ref::<zkminer_chain::deployment::ProofSystemRefused>()
                .is_some() =>
        {
            *g = None
        }
        Err(_) => {}
    }
    r
}

const FALLBACK_ESTIMATED_CYCLES: u64 = 34_000_000;

/// Conservative throughput (cycles/sec) the live claim gate sizes feasibility on when it has NO
/// genuine per-device benchmark row for the job's backend on a REAL (non-simulated) rig — e.g. a
/// cached suite predating device rows. Without this, a 0.0 throughput falls through to the evaluator's
/// OPTIMISTIC suite average, re-opening deadline claim-bait (a deadline-tight flood that fits the mean
/// but not the slow card is admitted, then missed -> penalized release). A low floor sizes
/// pessimistically so such jobs are refused rather than admitted-then-doomed. Matches the prove
/// watchdog's CONSERVATIVE_CPS.
const CONSERVATIVE_SIZING_CPS: f64 = 400_000.0;

/// Sentinel cycle count for a program the executor could not measure because the guest is too heavy
/// or non-terminating (it tripped the execute cycle cap). Sized so that at ANY realistic GPU
/// throughput (≤ ~3e8 cycles/s) the implied duration exceeds the evaluator's hard `INFEASIBLE`
/// sentinel (~100 years / 3.15e9 s) — 1e18 / 3e8 ≈ 3.3e9 s — so the job is unconditionally rejected,
/// not merely deadline-infeasible for typical deadlines. Still far below u64::MAX (1.8e19) and the
/// f64 duration range, so no overflow downstream.
const UNMEASURABLE_CYCLES: u64 = 1_000_000_000_000_000_000; // 1e18


/// One cached measurement for a (backend, size, program, input): its cycle count, the execute's peak
/// host RSS, and — for a NON-deterministic unmeasurable verdict — when to retry.
///
/// The cycle count and the peak live in ONE value, keyed identically, so they EVICT TOGETHER (finding
/// C-8). Two independently-bounded maps diverged under a flood of distinct measurements — each
/// `bounded_insert` picks its own victim — so a victim job's peak could be evicted while its cycle
/// count survived, and the H1 claim gate then read a MISSING peak as 0 ("unknown, do not gate") and
/// waved through an SP1 job whose execute would OOM beside the warm server. Merging them (the same
/// EVICT-TOGETHER pattern [`DescInfo`] uses for its over-cap bit) makes the STORAGE atomic: both
/// fields are evicted together. For the READ to be equally atomic the claim gate must take every field
/// of every size in a SINGLE lock hold — see [`resolve_measured_at`] — rather than separate reads,
/// between which a concurrent eviction could still drop an entry and desync the peak to 0.
#[derive(Clone)]
struct Measured {
    /// Measured guest cycles, or [`UNMEASURABLE_CYCLES`] for an infeasible/unmeasurable verdict.
    cycles: u64,
    /// The execute's peak host-RAM footprint in bytes (finding H1); 0 = unknown (older worker,
    /// off-Linux, portable executor) or an unmeasurable verdict. Read at the claim gate and threaded
    /// into the prove reservation (finding RH2).
    peak_host_bytes: u64,
    /// For a WALL-CLOCK-TIMEOUT unmeasurable verdict — the ONLY strike-out that is plausibly caused by
    /// transient host load rather than the program itself — the instant after which the entry is
    /// dropped and the pair re-measured. `None` for everything else: a real measurement, AND every
    /// submitter-REACHABLE / deterministic infeasible verdict (cycle-cap trip, image-id/vkey mismatch,
    /// over-cap payload, guest panic/trap, ELF-fetch failure/timeout), which stays permanent because a
    /// retry TTL on a submitter-craftable failure reopens a perpetual re-measurement DoS. This is the
    /// UNMEASURABLE TTL (finding: UNMEASURABLE had no TTL), scoped down after review to the one
    /// non-submitter-controllable case. A real measurement whose worker reported no journal expires
    /// too (`MEASURED_NO_JOURNAL_TTL`), so its journal-bound jobs are re-measured rather than wait on
    /// it forever.
    retry_after: Option<std::time::Instant>,
    /// keccak256 of the risc0 ELF whose image-id the measure worker verified equals this program's
    /// `programId` (a successful risc0 execute proves the sized bytes ARE the registered program; the
    /// worker refuses to size a mismatched image-id). `Some` ONLY for a real risc0 measurement — SP1 is
    /// bound by the mandatory registry `elf_hash` instead, and every infeasible verdict carries `None`.
    ///
    /// It lives in THIS merged entry, co-evicting with `cycles`, so the ELF-byte binding a claim will
    /// enforce on its re-fetch (see `fetch_or_download_elf`) can NEVER be evicted independently of the
    /// measurement the claim rides on: a claim proceeds iff a measurement resolves, and that resolve
    /// (see [`resolve_measured_at`]) hands back a size's hash (each was image-id verified) in the SAME
    /// lock hold. risc0 carries no
    /// registry `elf_hash`, so without this binding a submitter who swaps the stored ELF after we
    /// measure — once our cached copy is evicted — has the swapped bytes re-downloaded unverified, which
    /// reach prove, force a penalized RELEASE, and permanently blacklist a feasible program. An earlier
    /// fix held this in a SEPARATE program-keyed map; its independent random eviction (same cap as this
    /// cache) let the hash be dropped while the measurement survived, re-opening the window — hence the
    /// move into the measurement entry.
    verified_elf_hash: Option<alloy::primitives::B256>,
    /// The journal this execution committed, which a journal-bound job's binding is checked against
    /// before it is claimed (`zkminer_chain::binding`). In THIS entry for the same reason as
    /// `verified_elf_hash`: a claim that resolves a measurement gets that measurement's journal in the
    /// same lock hold, or none. `Some` only for a real measurement whose worker reported the whole
    /// journal; `None` for every infeasible verdict.
    journal: Option<std::sync::Arc<[u8]>>,
    /// How long the measuring execute took, in whole seconds rounded up; 0 for a verdict, or not
    /// known. In this entry so it co-evicts with `cycles`: see [`execute_allowance_secs`].
    execute_secs: u64,
}

/// A resolved measurement's journal, with the keccak of the input it was executed on.
type MeasuredJournal = Option<(alloy::primitives::B256, std::sync::Arc<[u8]>)>;

/// Bound on the journal bytes the measured cache holds. A cached journal is at most
/// `MAX_JOURNAL_BYTES` (longer ones are infeasible verdicts), so the entry cap alone would allow
/// ~3 GiB of them; past this bound other entries are evicted, and an evicted pair is re-measured.
const MEASURED_JOURNAL_BYTES_CAP: usize = 64 * 1024 * 1024;

/// How long a real measurement that came back without its journal (a worker that could not vouch
/// for it, such as one seeding `sys_rand` with a key for its process alone) sizes jobs before the
/// pair is re-measured. It never makes a journal-bound job claimable; this only bounds how long those
/// jobs wait for a measurement that does. Not submitter-reachable: an over-cap journal is a permanent
/// infeasible verdict instead.
const MEASURED_NO_JOURNAL_TTL: Duration = Duration::from_secs(10 * 60);

// A worker reports every journal a fulfil could carry, so every claimable job has one to check.
const _: () = assert!(
    zkminer_prover_protocol::types::EXECUTE_JOURNAL_MAX_BYTES
        >= zkminer_chain::jobs::MAX_JOURNAL_BYTES
);

/// A measurement's key: (backend tag, segment size, programId, keccak256(inputData)). The backend tag
/// is load-bearing: `programId`, `inputData` AND `proofSystemId` are all submitter-chosen, so without
/// it a cheap risc0 measurement of (P, I) would size an SP1 job carrying the same (P, I) — which the
/// SP1 worker then cannot prove (release penalty). See [`backend_tag`]. So is the size (risc0's po2,
/// [`NO_PO2`] for SP1): a guest can tell the size it runs at, so a measurement at one size says
/// nothing about a proof at another.
type MeasureKey = (u8, u8, alloy::primitives::B256, alloy::primitives::B256);

/// The segment size of a measurement on a backend that has none (SP1).
const NO_PO2: u8 = 0;

/// The sizes a job of `backend` is measured at: each risc0 card size in `risc0_sizes`, or [`NO_PO2`].
fn measure_sizes(backend: &str, risc0_sizes: &[u8]) -> Vec<u8> {
    if backend == zkminer_prover_protocol::BACKEND_RISC0 {
        risc0_sizes.to_vec()
    } else {
        vec![NO_PO2]
    }
}

/// Measured results by [`MeasureKey`]. See the declaration in `run`.
type MeasuredCache =
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<MeasureKey, Measured>>>;

/// How long a WALL-CLOCK-TIMEOUT UNMEASURABLE verdict is cached before the pair is re-measured. A
/// guest that legitimately runs ~just-under the 120 s measure budget can time out for
/// `MEASURE_TIMEOUT_STRIKES` consecutive ticks purely under transient host load and — without a TTL —
/// be blacklisted for the life of the process, a feasible job lost to a transient. Long enough that a
/// guest crafted to deterministically time out at ~120 s is not re-measured often (and its
/// re-measurement is bounded by the 2-slot measure budget regardless), short enough that a transient
/// clears within an operator's attention span. ONLY the wall-clock-timeout verdict expires; every
/// deterministic / submitter-reachable verdict is permanent (see [`Measured::retry_after`]).
const UNMEASURABLE_RETRY_TTL: Duration = Duration::from_secs(30 * 60);

/// How long a job the evaluator finds infeasible for this rig (it can't finish in its window, or its
/// risk is High) is set aside: the verdict holds while the job is Open, short of a re-benchmark.
const DETERMINISTIC_SKIP_TTL: Duration = Duration::from_secs(10 * 60);

/// Stable per-backend discriminant for the measured-cycles key. An unknown backend collapses to 255;
/// nothing is ever inserted under it (only risc0/sp1 measure), so a lookup simply misses.
fn backend_tag(backend: &str) -> u8 {
    match backend {
        "risc0" => 0,
        "sp1" => 1,
        _ => 255,
    }
}
/// Per-descriptor resolver entry: the input hash this descriptor carries, PLUS whether its full
/// fulfill payload (journal + this descriptor + seal) was found to exceed the on-chain cap. Both live
/// in ONE map keyed by descriptor hash so they EVICT TOGETHER — the over-cap verdict can neither
/// outlive nor be outlived by the resolver that makes the descriptor claimable. That closes the
/// fail-open where a separately-bounded, independently-evicting over-cap set let an over-cap descriptor
/// be claimed because its verdict was evicted while its resolver survived.
#[derive(Clone, Copy)]
struct DescInfo {
    input_hash: alloy::primitives::B256,
    over_cap: bool,
}

/// descriptor hash -> [`DescInfo`] (input-hash resolver + over-cap verdict). See the declaration in `run`.
type DescInputCache = std::sync::Arc<
    std::sync::Mutex<
        std::collections::HashMap<alloy::primitives::B256, DescInfo>,
    >,
>;

/// Insert into a `HashMap` bounded to `cap` entries: when full and the key is new, evict one existing
/// entry first. A flood of distinct keys therefore cannot grow the long-lived brain task's heap
/// without limit. Eviction only forces a re-measure/re-resolve, never an under-size.
fn bounded_insert<K, V>(map: &mut std::collections::HashMap<K, V>, key: K, val: V, cap: usize)
where
    K: std::cmp::Eq + std::hash::Hash + Copy,
{
    if map.len() >= cap && !map.contains_key(&key) {
        if let Some(k) = map.keys().next().copied() {
            map.remove(&k);
        }
    }
    map.insert(key, val);
}

/// Keep the `cap` HIGHEST-`key` elements of `v`, dropping the `len - cap` lowest in O(n) (a single
/// `select_nth` partition); a no-op when already within `cap`. Reorders the retained elements, so the
/// caller must not depend on `v`'s order afterwards. Used to bound the Open-candidate set by VALUE
/// rather than by arrival age — see the `MAX_OPEN_JOBS` cap in the monitor ingest loop.
fn retain_top_by_key<T, K, F>(v: &mut Vec<T>, cap: usize, key: F)
where
    K: Ord,
    F: Fn(&T) -> K,
{
    if v.len() <= cap {
        return;
    }
    let excess = v.len() - cap;
    // Each key ONCE, up front: a key can read the clock and shared maps (`open_rank`), and one that
    // changed mid-selection would hand `select_nth_unstable_by` an inconsistent order.
    let mut keyed: Vec<(K, T)> = v.drain(..).map(|t| (key(&t), t)).collect();
    // Partition so the `excess` lowest-key elements occupy 0..excess (the pivot at excess-1 lands in
    // its sorted position, everything before it is <=, everything after >=), then drop them.
    keyed.select_nth_unstable_by(excess - 1, |a, b| a.0.cmp(&b.0));
    v.extend(keyed.into_iter().skip(excess).map(|(_, t)| t));
}

/// Cap how many Open candidates any single `caller` (the submitter address) may occupy, dropping
/// that caller's LOWEST-`current_price` jobs beyond `per_caller`. The global cap alone ranks purely
/// on `current_price = min_price`, which the SUBMITTER chooses — so one hostile address could flood
/// `>= MAX_OPEN_JOBS` high-priced jobs it will never let us claim and, because the monitor is
/// forward-only with no re-discovery, PERMANENTLY evict every other submitter's work. Bounding each
/// caller's footprint first means one address can only ever displace its OWN entries. A no-op (one
/// O(n) pass) when every caller is within cap; otherwise O(n log n) in the over-cap callers' jobs.
fn enforce_per_caller_cap(v: &mut Vec<TrackedJob>, per_caller: usize) {
    use std::collections::{HashMap, HashSet};
    let mut counts: HashMap<alloy::primitives::Address, usize> = HashMap::new();
    for j in v.iter() {
        *counts.entry(j.info.caller).or_insert(0) += 1;
    }
    // Cheap early-out: nobody is over the cap (the common case).
    if counts.values().all(|&c| c <= per_caller) {
        return;
    }
    // For each over-cap caller, drop all but its `per_caller` highest-priced jobs.
    let mut by_caller: HashMap<
        alloy::primitives::Address,
        Vec<(u128, usize, alloy::primitives::B256)>,
    > = HashMap::new();
    for (i, j) in v.iter().enumerate() {
        by_caller
            .entry(j.info.caller)
            .or_default()
            .push((j.current_price, i, j.info.job_id));
    }
    let mut to_drop: HashSet<alloy::primitives::B256> = HashSet::new();
    for (_caller, mut jobs) in by_caller {
        if jobs.len() <= per_caller {
            continue;
        }
        // Highest price first, and among equal prices the NEWEST (later in `v`) first: an old
        // entry is likelier to be settled history than a live job. Everything past `per_caller`
        // is dropped.
        jobs.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
        for (_, _, jid) in jobs.into_iter().skip(per_caller) {
            to_drop.insert(jid);
        }
    }
    v.retain(|j| !to_drop.contains(&j.info.job_id));
}

/// Bound on the Open-candidate set (see the monitor ingest arm).
const MAX_OPEN_JOBS: usize = 4096;
/// Per-submitter share of [`MAX_OPEN_JOBS`].
const MAX_OPEN_JOBS_PER_CALLER: usize = 512;
/// Memory bound on the startup backfill's staged history (see [`admit_backfilled_jobs`]).
const MAX_STAGED_BACKFILL: usize = 65_536;

/// Admit the startup backfill into the Open set — only jobs that are STILL Open now.
///
/// The backfill replays every `JobSubmitted` since the deployment block, and nearly all of it is
/// settled history (fulfilled jobs emit nothing the monitor watches; replayed claims are suppressed
/// because a claim is not terminal). Feeding that history straight into the value- and per-caller-
/// capped Open set let settled jobs take the slots: a busy submitter's live jobs (the NONE jobs
/// assigned to us) were evicted on every restart, and the forward-only monitor never re-surfaces
/// them. So the history is staged OUTSIDE the Open set, status-read in bounded chunks (highest price
/// first, paced so the startup burst cannot starve the shared RPC), and only `Open && prover == 0`
/// jobs — or ones whose status could not be read, failing toward discovery — are admitted under the
/// usual caps.
async fn admit_backfilled_jobs(
    client: ChainClient,
    state: zkminer_tui::state::SharedState,
    mut staged: Vec<TrackedJob>,
) {
    const CHUNK: usize = 500;
    staged.sort_by_key(|j| std::cmp::Reverse(j.current_price));
    let total = staged.len();
    let mut admitted = 0usize;
    for chunk in staged.chunks(CHUNK) {
        let ids: Vec<B256> = chunk.iter().map(|j| j.info.job_id).collect();
        let open: std::collections::HashSet<B256> = match client.get_job_status_views_batch(&ids).await {
            Ok(rows) => rows
                .into_iter()
                .filter(|(_, v)| {
                    v.as_ref().is_none_or(|v| {
                        v.status == 0 && v.prover == alloy::primitives::Address::ZERO
                    })
                })
                .map(|(id, _)| id)
                .collect(),
            Err(e) => {
                tracing::warn!("backfill admission: status read failed ({e:#}) — admitting the chunk unpruned");
                ids.iter().copied().collect()
            }
        };
        {
            let mut s = state.write().await;
            let present: std::collections::HashSet<B256> =
                s.open_jobs.iter().map(|j| j.info.job_id).collect();
            for j in chunk {
                if open.contains(&j.info.job_id) && !present.contains(&j.info.job_id) {
                    watch_enqueue(j);
                    s.open_jobs.push(j.clone());
                    admitted += 1;
                }
            }
            enforce_per_caller_cap(&mut s.open_jobs, MAX_OPEN_JOBS_PER_CALLER);
            retain_top_by_key(&mut s.open_jobs, MAX_OPEN_JOBS, open_rank);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    tracing::info!("startup backfill: {admitted} of {total} historical job(s) are still Open and were admitted");
}

/// Cap on both the measured-cycles and descriptor->input-hash maps. Each measured entry costs a full
/// guest execution, so the cap is a backstop; the resolver map is cheap but bounded for the same
/// reason.
const MEASURED_CYCLES_CAP: usize = 100_000;

/// Insert a [`Measured`] value for the exact (backend, size, program, input), bounded to
/// `MEASURED_CYCLES_CAP` entries and to `MEASURED_JOURNAL_BYTES_CAP` journal bytes (but for this
/// pair's own entries). The single store point for the merged cache, so the cycle count and its peak
/// always evict together (finding C-8).
fn insert_measured_value(
    cache: &MeasuredCache,
    backend: &str,
    po2: u8,
    program_id: alloy::primitives::B256,
    input_hash: alloy::primitives::B256,
    value: Measured,
) {
    if let Ok(mut m) = cache.lock() {
        let key = (backend_tag(backend), po2, program_id, input_hash);
        bounded_insert(&mut m, key, value, MEASURED_CYCLES_CAP);
        let journal_bytes = |v: &Measured| v.journal.as_ref().map_or(0, |j| j.len());
        let excess = m
            .values()
            .map(journal_bytes)
            .sum::<usize>()
            .saturating_sub(MEASURED_JOURNAL_BYTES_CAP);
        if excess > 0 {
            // Largest journals first: a flood of near-cap journals evicts itself before the small
            // ones honest programs commit, and an entry that frees nothing is never a victim. Never
            // this pair's own entries at another size: a job is sized only when every size is
            // present, so evicting one would leave it re-measured for ever, one size at a time.
            let same_pair = |k: &MeasureKey| (k.0, k.2, k.3) == (key.0, key.2, key.3);
            let mut candidates: Vec<_> = m
                .iter()
                .filter(|(k, v)| !same_pair(k) && journal_bytes(v) > 0)
                .map(|(k, v)| (journal_bytes(v), *k))
                .collect();
            candidates.sort_unstable_by(|a, b| b.0.cmp(&a.0));
            let mut freed = 0;
            for (bytes, k) in candidates {
                if freed >= excess {
                    break;
                }
                m.remove(&k);
                freed += bytes;
            }
        }
    }
}

/// Insert a CYCLE-ONLY result (no captured peak, never-expiring). Used for a DETERMINISTIC
/// UNMEASURABLE sentinel (cap trip, image-id/vkey mismatch, over-cap payload) and in tests. A real
/// measurement that captured a peak uses [`insert_measurement`]; a non-deterministic unmeasurable
/// verdict uses [`insert_unmeasurable`].
fn insert_measured(
    cache: &MeasuredCache,
    backend: &str,
    po2: u8,
    program_id: alloy::primitives::B256,
    input_hash: alloy::primitives::B256,
    cycles: u64,
) {
    insert_measured_value(
        cache,
        backend,
        po2,
        program_id,
        input_hash,
        Measured {
            cycles,
            peak_host_bytes: 0,
            retry_after: None,
            verified_elf_hash: None,
            journal: None,
            execute_secs: 0,
        },
    );
}

/// Insert a real measurement: its cycle count, the execute's peak host footprint, and — for risc0 —
/// the keccak of the image-id-verified ELF, the journal and how long the execute took (0: not
/// known), stored in ONE value so they co-evict (finding C-8 and the independent-eviction residual).
/// Expires only without a journal (`MEASURED_NO_JOURNAL_TTL`). `verified_elf_hash` is `Some` only for
/// a real risc0 measurement; pass `None` for SP1 and for callers without a verified hash.
#[allow(clippy::too_many_arguments)]
fn insert_measurement(
    cache: &MeasuredCache,
    backend: &str,
    po2: u8,
    program_id: alloy::primitives::B256,
    input_hash: alloy::primitives::B256,
    cycles: u64,
    peak_host_bytes: u64,
    verified_elf_hash: Option<alloy::primitives::B256>,
    journal: Option<std::sync::Arc<[u8]>>,
    execute_secs: u64,
) {
    insert_measured_value(
        cache,
        backend,
        po2,
        program_id,
        input_hash,
        Measured {
            cycles,
            peak_host_bytes,
            retry_after: journal
                .is_none()
                .then(|| std::time::Instant::now() + MEASURED_NO_JOURNAL_TTL),
            verified_elf_hash,
            journal,
            execute_secs,
        },
    );
}

/// Insert a WALL-CLOCK-TIMEOUT UNMEASURABLE verdict with a retry deadline `UNMEASURABLE_RETRY_TTL`
/// out, so a job that only timed out under transient host load is re-measured rather than blacklisted
/// forever (the UNMEASURABLE TTL). Used ONLY for the wall-clock-timeout strike-out — every
/// deterministic / submitter-reachable verdict uses permanent [`insert_measured`] instead. (The SP1
/// "no registry elf_hash yet" decline is self-healing too, but via the program-keyed
/// [`SP1_ELF_HASH_MISSING`] cooldown checked before the descriptor scan, not this (program,input) entry.)
fn insert_unmeasurable(
    cache: &MeasuredCache,
    backend: &str,
    po2: u8,
    program_id: alloy::primitives::B256,
    input_hash: alloy::primitives::B256,
) {
    insert_measured_value(
        cache,
        backend,
        po2,
        program_id,
        input_hash,
        Measured {
            cycles: UNMEASURABLE_CYCLES,
            peak_host_bytes: 0,
            retry_after: Some(std::time::Instant::now() + UNMEASURABLE_RETRY_TTL),
            verified_elf_hash: None,
            journal: None,
            execute_secs: 0,
        },
    );
}

/// Descriptor hashes whose job, if claimed, is GUARANTEED to fail the on-chain fulfill payload-size
/// check: the guest journal plus the full submitter descriptor (inputData + callbackExtraData +
/// extraVerifierData) plus the proof seal exceed the fulfillJob calldata cap, so fulfill would
/// OOG-revert and the proof would be wasted on a release penalty. Keyed by DESCRIPTOR hash, not by
/// (program, input): the overflow depends on callbackExtraData/extraVerifierData, which are outside
/// the measurement cache key, so keying it by input would let one submitter's padded descriptor
/// wrongly skip a different slim job for the same program+input. Bounded like the other brain maps.
/// Record that a descriptor's fulfill payload is over the cap, as the `over_cap` bit on its
/// [`DescInfo`] resolver entry — creating the entry with a zero input hash if it has none yet (a
/// descriptor skipped before measurement is not claimable until a measurement exists anyway, and the
/// bit then co-evicts with the resolver). The candidate loop never claims a flagged descriptor.
fn mark_desc_unfulfillable(desc_input: &DescInputCache, descriptor_hash: alloy::primitives::B256) {
    if let Ok(mut m) = desc_input.lock() {
        match m.get_mut(&descriptor_hash) {
            Some(info) => info.over_cap = true,
            None => bounded_insert(
                &mut m,
                descriptor_hash,
                DescInfo {
                    input_hash: alloy::primitives::B256::ZERO,
                    over_cap: true,
                },
                MEASURED_CYCLES_CAP,
            ),
        }
    }
}

/// True if this descriptor was found to have an over-cap fulfill payload (see [`DescInfo`]).
fn desc_is_unfulfillable(desc_input: &DescInputCache, descriptor_hash: alloy::primitives::B256) -> bool {
    desc_input
        .lock()
        .map(|m| m.get(&descriptor_hash).map(|i| i.over_cap).unwrap_or(false))
        .unwrap_or(false)
}

/// Job ids whose submit transaction can NEVER be decoded into a JobDescriptor — the outer tx used an
/// unrecognized selector (an integrator proxy / multicall wrapper) or calldata too short to carry one
/// (see [`zkminer_chain::descriptor::UndecodableDescriptor`]). KEYED BY JOB ID, not by descriptorHash:
/// undecodability is a property of THIS job's immutable submit tx, while the on-chain descriptorHash
/// EXCLUDES the submitter (`compute_descriptor_hash` hashes only the 9 descriptor fields), so a
/// DIFFERENT submitter can mint a job carrying a byte-identical descriptor. Keying by descriptorHash
/// (as an earlier revision did, via the over-cap flag) let a proxy-wrapped decoy permanently EVICT an
/// honest, fully-decodable job that merely shared that descriptor — a cross-job over-block. The unique
/// job id skips only the undecodable job itself. Permanent (the submit tx is immutable) and bounded like
/// the other brain maps so a flood of distinct decoys cannot grow the heap.
static UNDECODABLE_JOBS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashSet<alloy::primitives::B256>>,
> = std::sync::OnceLock::new();

fn undecodable_jobs() -> &'static std::sync::Mutex<std::collections::HashSet<alloy::primitives::B256>>
{
    UNDECODABLE_JOBS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

/// Record a job this miner can PERMANENTLY never claim, so the candidate loop evicts it and the measure
/// path skips it instead of re-running the (up to `DEFAULT_DESCRIPTOR_LOOKBACK_BLOCKS`) descriptor scan
/// every tick over its whole open lifetime: its submit tx is undecodable, its descriptor carries a
/// binding marker this build cannot satisfy, it is a NONE job reserved for another prover, or the
/// journal its (program, input) measured does not satisfy its binding. Every one of these is a property
/// of the job's immutable descriptor (and its deterministic journal), and the key is the unique jobId
/// (never a descriptorHash an honest twin could share). See [`UNDECODABLE_JOBS`].
fn mark_job_undecodable(job_id: alloy::primitives::B256) {
    if let Ok(mut s) = undecodable_jobs().lock() {
        if s.len() >= MEASURED_CYCLES_CAP && !s.contains(&job_id) {
            if let Some(k) = s.iter().next().copied() {
                s.remove(&k);
            }
        }
        s.insert(job_id);
    }
}

/// True if this job's submit tx was found permanently undecodable (see [`mark_job_undecodable`]).
fn job_is_undecodable(job_id: alloy::primitives::B256) -> bool {
    undecodable_jobs()
        .lock()
        .map(|s| s.contains(&job_id))
        .unwrap_or(false)
}

/// How long an SP1 program observed with NO registry `elf_hash` is skipped before it is re-checked. A
/// missing elf_hash is TEMPORAL, not permanent: `registerProgram` takes no elfHash argument (the chain
/// cannot keccak an off-chain ELF), so the hash is set by a LATER call and a brand-new legit SP1 program
/// reads `elfHash == ZERO` in the window before that. A PERMANENT negative-cache would over-block such a
/// program for the whole process lifetime; this self-healing cooldown re-checks and heals once the hash
/// appears. Program-keyed and consulted BEFORE the descriptor scan, so re-checking a flood of no-hash
/// decoys costs at most one (mostly-cached) `get_program_info` per TTL each — never the heavy descriptor
/// scan or an execute. (An earlier revision kept this TTL in the (program,input) measured cache AFTER
/// the descriptor fetch, so every re-check re-ran the ~500k-block log scan: a sustained RPC DoS.)
const SP1_ELF_HASH_RECHECK_TTL: Duration = Duration::from_secs(10 * 60);

/// programId -> `Instant` until which an SP1 program observed with no registry `elf_hash` is skipped.
/// See [`SP1_ELF_HASH_RECHECK_TTL`]. Program-wide (the requirement does not depend on inputData), and
/// bounded like the other brain maps.
static SP1_ELF_HASH_MISSING: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<alloy::primitives::B256, std::time::Instant>>,
> = std::sync::OnceLock::new();

fn sp1_elf_hash_missing_map(
) -> &'static std::sync::Mutex<std::collections::HashMap<alloy::primitives::B256, std::time::Instant>>
{
    SP1_ELF_HASH_MISSING.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Record that an SP1 program currently has no registry `elf_hash`, skipping it for a self-healing
/// cooldown. See [`SP1_ELF_HASH_MISSING`].
fn mark_sp1_elf_hash_missing(program_id: alloy::primitives::B256) {
    if let Ok(mut m) = sp1_elf_hash_missing_map().lock() {
        bounded_insert(
            &mut m,
            program_id,
            std::time::Instant::now() + SP1_ELF_HASH_RECHECK_TTL,
            MEASURED_CYCLES_CAP,
        );
    }
}

/// True if an SP1 program was recently observed with no registry `elf_hash` and is still within its
/// re-check cooldown (see [`mark_sp1_elf_hash_missing`]). Self-healing: once the cooldown lapses this
/// returns false and the program is re-checked (and re-measured if its hash has since been set).
fn sp1_elf_hash_missing_recently(program_id: alloy::primitives::B256) -> bool {
    sp1_elf_hash_missing_map()
        .lock()
        .map(|m| {
            m.get(&program_id)
                .is_some_and(|&until| std::time::Instant::now() < until)
        })
        .unwrap_or(false)
}

/// jobId -> `Instant` until which a job observed assigned to ANOTHER prover is skipped WITHOUT
/// re-fetching its descriptor. Keyed by job, not descriptor: the window is the job's own (twin jobs
/// can share a descriptor and differ in their exclusivity). `assignedProver` is submitter-controlled, is NOT exposed by
/// `JobStatusView` (so the candidate filter cannot see it), and is only learned from a descriptor
/// fetch — so without this a flood of high-price jobs the submitter exclusively assigns elsewhere
/// re-spawns a measure task (descriptor fetch + immediate return) every tick, monopolizing the
/// per-tick measure budget and the RPC it rides, and starving measurement of legitimately-claimable
/// jobs. The skip is TIME-BOUNDED, not permanent: on-chain exclusivity expires, so after the cooldown
/// the job is re-evaluated and a now-open assignment is not missed. Bounded like the other brain maps.
type AssignedElsewhere = std::sync::Arc<
    std::sync::Mutex<std::collections::HashMap<alloy::primitives::B256, std::time::Instant>>,
>;

/// Cooldown before a job seen assigned to another prover is re-checked. A cooldown, not a blacklist:
/// exclusivity can lapse on-chain, so the job must become eligible again without a restart.
const ASSIGNED_ELSEWHERE_TTL: Duration = Duration::from_secs(90);

/// Mark a job as assigned-elsewhere for `wait` so it is not re-measured each tick. Bounded like the
/// measured cache so a flood of distinct decoys cannot grow the heap.
fn mark_assigned_elsewhere(cache: &AssignedElsewhere, job_id: B256, wait: Duration) {
    if let Ok(mut m) = cache.lock() {
        let until = std::time::Instant::now() + wait;
        bounded_insert(&mut m, job_id, until, MEASURED_CYCLES_CAP);
    }
}

/// Longest a FULL/FIELDS job assigned to another prover is set aside before its exclusivity is read
/// again.
const ASSIGNED_ELSEWHERE_MAX_WAIT: Duration = Duration::from_secs(3600);

/// How long a FULL/FIELDS job assigned to ANOTHER prover stays theirs: `None` once anyone may claim
/// it. The contract (`_checkExclusivityFromStorage`) enforces the assignment only while
/// `jobNow < rampUpStart + exclusivityDuration` — never when that is 0 — in job-local time, which a
/// pause only stretches, so a wait judged by the chain clock may end early (the claim quote then
/// refuses it) but never late. Clamped to [`ASSIGNED_ELSEWHERE_TTL`, `ASSIGNED_ELSEWHERE_MAX_WAIT`].
/// (A NONE job's assignment is for life and is handled apart.)
fn exclusivity_wait(ramp_up_start: u64, exclusivity_duration: u64, now: u64) -> Option<Duration> {
    if exclusivity_duration == 0 {
        return None;
    }
    let ends = ramp_up_start.saturating_add(exclusivity_duration);
    (ends > now).then(|| {
        Duration::from_secs(ends - now).clamp(ASSIGNED_ELSEWHERE_TTL, ASSIGNED_ELSEWHERE_MAX_WAIT)
    })
}

/// [`exclusivity_wait`] for a job, from its record now. An unreadable record is an error, for the
/// caller to treat as it can (the brain waits the minimum; watch-only retries).
async fn assigned_exclusivity_wait(client: &ChainClient, job_id: B256) -> Result<Option<Duration>> {
    let (rec, _) = client.read_job_record(job_id, None).await?;
    Ok(exclusivity_wait(
        rec.ramp_up_start,
        rec.exclusivity_duration,
        zkminer_chain::client::chain_now(),
    ))
}

/// True if this job is still within its assigned-elsewhere cooldown. An expired entry returns false
/// (and is dropped) so the job is re-evaluated once exclusivity may have lapsed.
fn assigned_elsewhere_recently(cache: &AssignedElsewhere, job_id: B256) -> bool {
    if let Ok(mut m) = cache.lock() {
        if let Some(&until) = m.get(&job_id) {
            if std::time::Instant::now() < until {
                return true;
            }
            m.remove(&job_id);
        }
    }
    false
}

/// (backend, program, input) -> length in bytes of the longest guest journal that (program, input)
/// produced at any segment size it was measured at. The journal is a deterministic function of
/// (program, input) at a size, so it is shared by EVERY descriptor for that pair. It is cached here when
/// a measurement executes so that a later descriptor for the
/// same pair — which short-circuits on the cached cycle count without re-executing — can still have
/// its full fulfill payload (journal + its own descriptor bytes + seal) checked against the cap.
/// Bounded like the measured-cycles cache.
type JournalLenCache = std::sync::Arc<
    std::sync::Mutex<
        std::collections::HashMap<(u8, alloy::primitives::B256, alloy::primitives::B256), u64>,
    >,
>;

fn insert_journal_len(
    cache: &JournalLenCache,
    backend: &str,
    program_id: alloy::primitives::B256,
    input_hash: alloy::primitives::B256,
    journal_len: u64,
) {
    if let Ok(mut m) = cache.lock() {
        // The longest at any segment size: the payload screens must hold wherever the job proves.
        let key = (backend_tag(backend), program_id, input_hash);
        let longest = m.get(&key).map_or(journal_len, |l| journal_len.max(*l));
        bounded_insert(&mut m, key, longest, MEASURED_CYCLES_CAP);
    }
}

fn get_journal_len(
    cache: &JournalLenCache,
    backend: &str,
    program_id: alloy::primitives::B256,
    input_hash: alloy::primitives::B256,
) -> Option<u64> {
    cache
        .lock()
        .ok()
        .and_then(|m| m.get(&(backend_tag(backend), program_id, input_hash)).copied())
}

/// The fulfillJob calldata carries the guest journal, the proof seal, and the submitter descriptor
/// (inputData + callbackExtraData + extraVerifierData) under a fixed gas limit. This is true only when
/// that payload is CERTAIN to exceed the cap: a minimal seal estimate (<= any real Groth16 seal) is
/// used, so it never false-positives a job that could actually fulfill. When it holds, proving the job
/// would waste a full proof on a fulfill guaranteed to OOG-revert, then force a penalized release.
const MAX_FULFILL_PAYLOAD_BYTES: usize = 128 * 1024;
const MIN_SEAL_BYTES: usize = 256;
fn fulfill_payload_over_cap(
    journal_len: u64,
    input_len: usize,
    callback_len: usize,
    extra_verifier_len: usize,
) -> bool {
    // The router also refuses any journal over MAX_JOURNAL_BYTES outright (`JournalTooLarge`, on every
    // fulfil path) — far below the calldata cap, so it must be screened on its own.
    if journal_len as usize > zkminer_chain::jobs::MAX_JOURNAL_BYTES {
        return true;
    }
    (journal_len as usize)
        .saturating_add(input_len)
        .saturating_add(callback_len)
        .saturating_add(extra_verifier_len)
        .saturating_add(MIN_SEAL_BYTES)
        > MAX_FULFILL_PAYLOAD_BYTES
}

/// `(programId, backend)` pairs whose on-chain `programId` cannot be satisfied by the ELF the submitter
/// serves UNDER THAT BACKEND: the prover derived the verifying key / image id and it did not equal
/// `programId`, so EVERY job for this program ON THIS BACKEND fails at PROVE — after the collateral-
/// locking claim — and releases at a penalty. SP1 cannot detect this before claiming (deriving the vkey
/// needs the minutes-long `setup`, far over the measure watchdog), so the binding is only proven on the
/// prove path. Recording a mismatch here caps the loss to the jobs already claimed in the batch in flight
/// when its first prove faults — ONE claim WAVE, not a release penalty per submitted job: once marked,
/// the claim gate, the measure gate, the batch-claim task, and each per-job lifecycle task all skip every
/// future job for it. Write-once per bad program, read once per candidate per tick — a process-wide static
/// like the other brain-wide flags, bounded like the measured cache so a flood of distinct decoys cannot
/// grow it.
///
/// KEYED BY BACKEND, not programId alone: `programId` and `proofSystemId` are INDEPENDENT, fully
/// submitter-controlled fields (`resolve_backend` maps proofSystemId→backend with no binding to
/// programId), and a risc0 image-id vs an SP1 vkey are different derivations of the same 32-byte space.
/// Keying by programId alone let a decoy declare a LEGIT risc0 program's public `programId` V with
/// `proofSystemId=sp1` and serve any valid SP1 ELF (vkey W != V, guaranteed — no collision): the SP1
/// prove-path vkey gate correctly faults ProgramMismatch and would mark V, PERMANENTLY over-blocking the
/// legit risc0 program under its real backend. The mismatch verdict is only authoritative for the backend
/// it was derived under, so we key by it: marking (V, "sp1") never blocks the legit (V, "risc0"), and a
/// legit program's ELF matches its programId under its OWN backend so (programId, its backend) is never
/// listed. A given programId has real traffic under exactly one backend, so the extra key dimension never
/// over-restricts honest work.
static VKEY_MISMATCH_PROGRAMS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashSet<(alloy::primitives::B256, &'static str)>>,
> = std::sync::OnceLock::new();

fn vkey_mismatch_programs(
) -> &'static std::sync::Mutex<std::collections::HashSet<(alloy::primitives::B256, &'static str)>> {
    VKEY_MISMATCH_PROGRAMS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

/// Record a `(programId, backend)` whose served ELF can never match its `programId` UNDER THAT BACKEND,
/// learned from the TYPED prove-path worker error (`WorkerProofError::is_program_mismatch`) —
/// authoritative and permanent, so the claim and measure gates skip/evict every future job for it. NOTE:
/// a pre-fulfill eth_call revert must NOT be recorded here — a revert is a non-authoritative,
/// non-deterministic signal (a reorg, a router pause, or a load-balanced RPC serving pre-claim state all
/// revert on a perfectly legitimate program), and a permanent breaker keyed on it would over-block honest
/// work forever. A sim revert uses the self-healing [`mark_program_sim_reverted`] cooldown instead.
fn mark_program_vkey_mismatch(program_id: alloy::primitives::B256, backend: &'static str) {
    if let Ok(mut s) = vkey_mismatch_programs().lock() {
        let key = (program_id, backend);
        // Bounded like the brain maps so a flood of distinct decoys cannot grow the heap.
        if s.len() >= MEASURED_CYCLES_CAP && !s.contains(&key) {
            if let Some(k) = s.iter().next().copied() {
                s.remove(&k);
            }
        }
        s.insert(key);
    }
}

/// True if a prior prove proved this `(programId, backend)`'s served ELF cannot satisfy it under that
/// backend (see [`mark_program_vkey_mismatch`]). Permanently unclaimable for THAT backend only.
fn program_vkey_mismatched(program_id: alloy::primitives::B256, backend: &'static str) -> bool {
    vkey_mismatch_programs()
        .lock()
        .map(|s| s.contains(&(program_id, backend)))
        .unwrap_or(false)
}

/// Convenience consult from a job's submitter-controlled `proofSystemId`: resolves the backend and
/// checks the `(programId, backend)` breaker. An unsupported proof system (resolve_backend == None) is
/// never claimed anyway (the backend gate skips it), so it is reported not-mismatched here.
fn program_vkey_mismatched_for(
    program_id: alloy::primitives::B256,
    proof_system_id: alloy::primitives::B256,
) -> bool {
    resolve_backend(proof_system_id).is_some_and(|b| program_vkey_mismatched(program_id, b))
}

/// Cooldown for a pre-fulfill eth_call sim-revert verdict. A revert is NOT an authoritative,
/// deterministic signal — a reorg that dropped our claim, a router pause window, an already-fulfilled
/// retry race, or a load-balanced RPC serving a block BEFORE our claim mined (a hazard this codebase
/// documents at `receipt_fulfilled_this_job`) all surface as `...reverted...` on a perfectly
/// legitimate program/job. So a sim-revert breaker must SELF-HEAL: skip for the cooldown (so a
/// genuinely-doomed flood is throttled to ~one claim+prove per window, not per job), then re-evaluate
/// so a transient revert never permanently over-blocks honest work. Mirrors `ASSIGNED_ELSEWHERE_TTL`.
const SIM_REVERT_TTL: Duration = Duration::from_secs(10 * 60);

/// `(programId, proofSystemId)` -> `Instant` until which jobs for that pair are skipped after a real
/// fulfil reverted `VerifierCallFailed` with NO governance cause (Registry not paused, adapter not
/// Disabled) — the locally-valid proof was rejected by the verifier, most likely because the served
/// ELF's vkey/image-id does not correspond to the on-chain `programId` on this deployment. Keyed by
/// the proof system too: an SP1 vkey is the programId under BOTH SP1 ids, but a seal for one wrapper is
/// not a seal for the other. A cooldown, not a permanent mark: the verifier's own reason never reaches
/// us (the router collapses every adapter failure into the bare `VerifierCallFailed`), so this cannot
/// PROVE a program-wide defect; the authoritative, permanent breaker remains the TYPED prove-path
/// [`mark_program_vkey_mismatch`]. Fed ONLY by that decoded selector — never by a pause, a gas
/// shortfall, a late or stale lock, or an RPC error. Bounded like the brain maps.
type SimRevertKey = (alloy::primitives::B256, alloy::primitives::B256);

static SIM_REVERT_PROGRAMS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<SimRevertKey, std::time::Instant>>,
> = std::sync::OnceLock::new();

fn sim_revert_programs(
) -> &'static std::sync::Mutex<std::collections::HashMap<SimRevertKey, std::time::Instant>> {
    SIM_REVERT_PROGRAMS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Throttle `(program_id, proof_system_id)` for `SIM_REVERT_TTL` (see [`SIM_REVERT_PROGRAMS`]).
fn mark_program_sim_reverted(
    program_id: alloy::primitives::B256,
    proof_system_id: alloy::primitives::B256,
) {
    if let Ok(mut m) = sim_revert_programs().lock() {
        bounded_insert(
            &mut m,
            (program_id, proof_system_id),
            std::time::Instant::now() + SIM_REVERT_TTL,
            MEASURED_CYCLES_CAP,
        );
    }
}

/// True if `(program_id, proof_system_id)` is still within its cooldown. An expired entry returns
/// false (and is dropped) so the pair's jobs are re-evaluated.
fn program_sim_reverted_recently(
    program_id: alloy::primitives::B256,
    proof_system_id: alloy::primitives::B256,
) -> bool {
    if let Ok(mut m) = sim_revert_programs().lock() {
        let key = (program_id, proof_system_id);
        if let Some(&until) = m.get(&key) {
            if std::time::Instant::now() < until {
                return true;
            }
            m.remove(&key);
        }
    }
    false
}

/// jobId -> `Instant` before which a claim refused for a TEMPORARY reason is not re-attempted: a live
/// price below our high-water floor or a live bid (`Wait`), a router/Registry pause (`Paused`), or a
/// free-stake shortfall (`StakeShort`). Keeps the job a candidate without re-quoting it every tick.
static CLAIM_RETRY_AFTER: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<alloy::primitives::B256, std::time::Instant>>,
> = std::sync::OnceLock::new();

fn claim_retry_after_map(
) -> &'static std::sync::Mutex<std::collections::HashMap<alloy::primitives::B256, std::time::Instant>>
{
    CLAIM_RETRY_AFTER.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Back off re-claiming `job_id` after a temporary refusal of `class`.
fn note_claim_retry_after(job_id: alloy::primitives::B256, class: zkminer_chain::revert::ClaimClass) {
    use zkminer_chain::revert::ClaimClass;
    // Escalating, like every other temporary pre-claim refusal: each re-dispatch holds a claim slot, so
    // a job that is perpetually refused (a decoy whose real collateral never fits) must decay rather
    // than take a slot ahead of honest work every minute.
    let base = match class {
        ClaimClass::StakeShort => 60,
        _ => 30,
    };
    note_preclaim_strike(job_id, base);
}
/// Post-claim FAILURE breaker. A claimed job whose (program, input) measured clean and then failed
/// after the lock — ANY terminal prove failure (a guest fault, a watchdog kill, a health failure, a
/// budget run-out) or an over-cap journal — pays the release penalty, and a submitter can assign NONE
/// jobs to us without our consent. The risc0 worker seeds the guest's `sys_rand` per (ELF, input), so
/// a guest's randomness no longer splits its measurement from its proof; but proving still runs paths
/// a measurement doesn't (the GPU, another segment size, more memory). Worker error text can carry
/// guest-chosen strings, so this is deliberately class-agnostic: it cannot be evaded by choosing how
/// to fail.
///
/// Each failure marks the submitter on an escalating TTL (1 h doubling to 24 h), and the program
/// (under its backend) once jobs from `PROGRAM_MARK_SUBMITTERS` DISTINCT submitters have failed on it
/// within `DIVERGENCE_MARK_MAX`: a program's id is public, so one submitter's heavy input must not
/// block it for everyone (that submitter is already held). Self-healing, because the same signal also
/// fires for a sick GPU, and never touching recovery (a lock we hold is still driven).
/// `DIVERGENCE_HOLD_COUNT` DISTINCT programs failing within `DIVERGENCE_WINDOW` (a Sybil spreading
/// failures over fresh programs and addresses, or our own hardware failing) page and hold new claims
/// for programs not already PROVEN by a successful fulfil in this process (and not marked since) — so
/// the hold cannot be used to stop honest, established work.
const DIVERGENCE_WINDOW: Duration = Duration::from_secs(3600);
const DIVERGENCE_HOLD_COUNT: usize = 3;
const DIVERGENCE_MARK_MAX: Duration = Duration::from_secs(24 * 3600);
const PROGRAM_MARK_SUBMITTERS: usize = 2;

#[derive(Default)]
struct DivergenceState {
    /// (strikes, blocked until) per program+backend and per submitter.
    programs: std::collections::HashMap<(B256, &'static str), (u32, std::time::Instant)>,
    submitters: std::collections::HashMap<alloy::primitives::Address, (u32, std::time::Instant)>,
    /// Recent failures, with the program that failed.
    recent: std::collections::VecDeque<(std::time::Instant, B256)>,
    /// Per program+backend, the submitters whose jobs on it failed, and when.
    failers: std::collections::HashMap<
        (B256, &'static str),
        Vec<(std::time::Instant, alloy::primitives::Address)>,
    >,
    /// Programs with a successful fulfil in this process and no recorded failure.
    proven: std::collections::HashSet<(B256, &'static str)>,
}

impl DivergenceState {
    fn distinct_recent(&mut self) -> usize {
        let now = std::time::Instant::now();
        self.recent.retain(|(t, _)| now.duration_since(*t) < DIVERGENCE_WINDOW);
        self.recent
            .iter()
            .map(|(_, p)| *p)
            .collect::<std::collections::HashSet<_>>()
            .len()
    }
}

static DIVERGENCE: std::sync::Mutex<Option<DivergenceState>> = std::sync::Mutex::new(None);

fn escalate_mark(prev: Option<u32>) -> (u32, std::time::Instant) {
    let strikes = prev.unwrap_or(0).saturating_add(1);
    let ttl = (DIVERGENCE_WINDOW * 2u32.saturating_pow((strikes - 1).min(8))).min(DIVERGENCE_MARK_MAX);
    (strikes, std::time::Instant::now() + ttl)
}

fn note_post_claim_divergence(
    program_id: alloy::primitives::B256,
    backend: &'static str,
    caller: alloy::primitives::Address,
    why: &str,
) {
    let mut g = DIVERGENCE.lock().unwrap_or_else(|p| p.into_inner());
    let st = g.get_or_insert_with(Default::default);
    let key = (program_id, backend);
    let now = std::time::Instant::now();
    let failers = if st.failers.len() < MEASURED_CYCLES_CAP || st.failers.contains_key(&key) {
        let f = st.failers.entry(key).or_default();
        f.retain(|(t, a)| now.duration_since(*t) < DIVERGENCE_MARK_MAX && *a != caller);
        f.push((now, caller));
        f.len()
    } else {
        PROGRAM_MARK_SUBMITTERS
    };
    if failers >= PROGRAM_MARK_SUBMITTERS {
        st.proven.remove(&key);
        if st.programs.len() < MEASURED_CYCLES_CAP || st.programs.contains_key(&key) {
            let prev = st.programs.get(&key).map(|e| e.0);
            st.programs.insert(key, escalate_mark(prev));
        }
    }
    if st.submitters.len() < MEASURED_CYCLES_CAP || st.submitters.contains_key(&caller) {
        let prev = st.submitters.get(&caller).map(|e| e.0);
        st.submitters.insert(caller, escalate_mark(prev));
    }
    st.recent.push_back((std::time::Instant::now(), program_id));
    let distinct = st.distinct_recent();
    tracing::error!(
        "POST-CLAIM FAILURE: program {} ({backend}) from submitter {caller} measured clean but failed \
         after the claim ({why}) — not claiming {} for a while",
        short_id(program_id),
        if failers >= PROGRAM_MARK_SUBMITTERS {
            "this program or submitter"
        } else {
            "this submitter's jobs"
        }
    );
    if distinct >= DIVERGENCE_HOLD_COUNT {
        tracing::error!(
            "PAGE: {distinct} programs failed after a clean measurement within {}s — claiming only \
             programs already proven in this session (hostile guests, or our own GPUs failing)",
            DIVERGENCE_WINDOW.as_secs()
        );
    }
}

/// A successful fulfil: the program is proven in this session (unless it is marked right now).
fn note_fulfil_success(program_id: alloy::primitives::B256, backend: &'static str) {
    let mut g = DIVERGENCE.lock().unwrap_or_else(|p| p.into_inner());
    let st = g.get_or_insert_with(Default::default);
    let key = (program_id, backend);
    let now = std::time::Instant::now();
    if st.programs.get(&key).is_none_or(|e| now >= e.1) && st.proven.len() < MEASURED_CYCLES_CAP {
        st.proven.insert(key);
    }
}

/// True if a new claim must be held (see [`note_post_claim_divergence`]).
fn divergence_blocks_claim(
    caller: alloy::primitives::Address,
    program_id: alloy::primitives::B256,
    backend: &'static str,
) -> bool {
    let mut g = DIVERGENCE.lock().unwrap_or_else(|p| p.into_inner());
    let Some(st) = g.as_mut() else {
        return false;
    };
    let now = std::time::Instant::now();
    let key = (program_id, backend);
    if st.programs.get(&key).is_some_and(|e| now < e.1) || st.submitters.get(&caller).is_some_and(|e| now < e.1) {
        return true;
    }
    st.distinct_recent() >= DIVERGENCE_HOLD_COUNT && !st.proven.contains(&key)
}

/// FULL/FIELDS-bound jobs seen while bound-job claiming is off. A property of the job's immutable
/// descriptor, cached by jobId after its ONE descriptor fetch: the candidate loop then skips the job
/// before the price-ordered measure budget, so a pile of high-priced bound decoys cannot starve an
/// honest job's measurement. Consulted with the live setting (fixed for a run today: the config's).
static BOUND_JOBS: std::sync::Mutex<Option<(std::collections::HashSet<B256>, std::collections::VecDeque<B256>)>> =
    std::sync::Mutex::new(None);

/// Record a bound job. Bounded FIFO (the oldest id is forgotten first), so a new bound job is ALWAYS
/// recorded, and pruned when the job leaves the Open set (`forget_job_bound`).
fn mark_job_bound(job_id: B256) {
    let mut g = BOUND_JOBS.lock().unwrap_or_else(|p| p.into_inner());
    let (set, order) = g.get_or_insert_with(Default::default);
    if set.insert(job_id) {
        order.push_back(job_id);
        while order.len() > MEASURED_CYCLES_CAP {
            if let Some(old) = order.pop_front() {
                set.remove(&old);
            }
        }
    }
}

fn forget_job_bound(job_id: B256) {
    let mut g = BOUND_JOBS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((set, order)) = g.as_mut() {
        if set.remove(&job_id) {
            order.retain(|j| *j != job_id);
        }
    }
}

fn job_is_bound(job_id: B256) -> bool {
    let g = BOUND_JOBS.lock().unwrap_or_else(|p| p.into_inner());
    g.as_ref().is_some_and(|(s, _)| s.contains(&job_id))
}

/// Each job's own collateral terms `(minCollateral, collateralBps)`, snapshotted at submit and read
/// with `getJobSnapshots` once per job. The claim locks `computeCollateral(price, collateralBps,
/// minCollateral)` from these, and a submitter may set collateralBps up to 50,000 (500%), so sizing
/// the claim gate from the adapter default under-reserved such a job by up to 3.3x. Immutable after
/// submit, so cached by jobId; bounded (an evicted entry is just read again).
static JOB_COLLATERAL_TERMS: std::sync::Mutex<
    Option<std::collections::HashMap<B256, (u128, u128)>>,
> = std::sync::Mutex::new(None);

/// Read the collateral terms of the `job_ids` not cached yet, in one pinned, validated batch (see
/// `get_job_snapshots_batch`): once per brain tick for its candidates, not one RPC per job inside
/// the candidate loop. A job left unread is simply skipped this tick.
async fn prefetch_job_collateral_terms(client: &ChainClient, job_ids: &[B256]) {
    let missing: Vec<B256> = {
        let g = JOB_COLLATERAL_TERMS
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        job_ids
            .iter()
            .filter(|j| g.as_ref().is_none_or(|m| !m.contains_key(*j)))
            .copied()
            .collect()
    };
    if missing.is_empty() {
        return;
    }
    let failure = match client.get_job_snapshots_batch(&missing).await {
        Ok(rows) => {
            let mut g = JOB_COLLATERAL_TERMS
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let m = g.get_or_insert_with(Default::default);
            let mut read = 0usize;
            for (jid, terms) in rows {
                if let Some((_, min_collateral, collateral_bps)) = terms {
                    if m.len() >= MEASURED_CYCLES_CAP {
                        m.clear();
                    }
                    m.insert(jid, (min_collateral, collateral_bps));
                    read += 1;
                }
            }
            (read == 0).then(|| "none of them could be read".to_string())
        }
        Err(e) => Some(format!("{e:#}")),
    };
    // Every claim needs them: say so if they keep failing (e.g. an RPC whose calls lag its own block
    // number), at most once a minute of brain ticks.
    static FAILS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    match failure {
        Some(why) if FAILS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 12 == 11 => {
            tracing::warn!(
                "jobs' collateral terms keep failing to read ({why}) — no new claims until they do"
            )
        }
        Some(why) => tracing::debug!("collateral terms unreadable this tick: {why}"),
        None => FAILS.store(0, std::sync::atomic::Ordering::Relaxed),
    }
}

fn job_collateral_terms(job_id: B256) -> Option<(u128, u128)> {
    JOB_COLLATERAL_TERMS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .and_then(|m| m.get(&job_id).copied())
}

/// PAGE lines waiting for the dashboard (see `PageToDashboard` in main.rs). Bounded: the oldest go.
static PAGES: std::sync::Mutex<std::collections::VecDeque<String>> =
    std::sync::Mutex::new(std::collections::VecDeque::new());

/// Queue a PAGE line for the dashboard's log.
pub(crate) fn note_page(msg: String) {
    let mut q = PAGES.lock().unwrap_or_else(|p| p.into_inner());
    if q.len() >= 64 {
        q.pop_front();
    }
    q.push_back(msg);
}

fn take_pages() -> Vec<String> {
    PAGES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .drain(..)
        .collect()
}

/// Most candidates the brain evaluates per tick.
const MAX_CANDIDATES_PER_TICK: usize = 256;

/// Cut a price-sorted candidate list to [`MAX_CANDIDATES_PER_TICK`]: the top three quarters by price,
/// the last quarter in rotation (from `rotation`, advanced) over everything below them. Jobs that stay
/// Open but that we never claim (a skip nobody backs off), priced above honest work by a submitter
/// who can post them for a refundable deposit, cannot then hold every slot on every tick and keep the
/// rest of the market from being evaluated at all.
fn cut_candidates<T: Copy>(candidates: &mut Vec<T>, rotation: &mut usize) {
    const PRICE_SLOTS: usize = MAX_CANDIDATES_PER_TICK * 3 / 4;
    if candidates.len() > MAX_CANDIDATES_PER_TICK {
        let rest = candidates.split_off(PRICE_SLOTS);
        let take = MAX_CANDIDATES_PER_TICK - PRICE_SLOTS;
        let start = *rotation % rest.len();
        candidates.extend(rest.iter().cycle().skip(start).take(take).copied());
        *rotation = start + take;
    }
}

/// The Open-set ranking key: a job settled as bound (FULL/FIELDS while bound-job claiming is off, by
/// its one descriptor fetch), or one set aside on a verdict that lasts (assigned elsewhere, too slow
/// to prove), ranks LAST, so a pile of high-priced decoys like these can never push a claimable job
/// out of the capped Open set. A job merely backing off a temporary refusal keeps its price: it is
/// the one just put back, and eviction from the Open set is for good.
fn open_rank(j: &TrackedJob) -> u128 {
    if job_is_bound(j.info.job_id) || job_set_aside(j.info.job_id) {
        0
    } else {
        j.current_price
    }
}


/// Programs whose registry lists no ELF source (unregistered, or registered without URIs), with when
/// that was seen. Every job of such a program is skipped by the candidate loop BEFORE the measure
/// budget for `NO_ELF_SOURCE_TTL`, so a flood of decoys on one unregistered program costs one
/// registry read per TTL, not a measure slot per job per tick. Self-healing: a later registration is
/// picked up after the TTL.
static NO_ELF_SOURCE: std::sync::Mutex<Option<std::collections::HashMap<B256, std::time::Instant>>> =
    std::sync::Mutex::new(None);
const NO_ELF_SOURCE_TTL: Duration = Duration::from_secs(600);

fn mark_program_no_elf_source(program_id: B256) {
    let mut g = NO_ELF_SOURCE.lock().unwrap_or_else(|p| p.into_inner());
    let m = g.get_or_insert_with(Default::default);
    bounded_insert(m, program_id, std::time::Instant::now(), MEASURED_CYCLES_CAP);
}

fn program_has_no_elf_source(program_id: B256) -> bool {
    let mut g = NO_ELF_SOURCE.lock().unwrap_or_else(|p| p.into_inner());
    let Some(m) = g.as_mut() else {
        return false;
    };
    match m.get(&program_id) {
        Some(t) if t.elapsed() < NO_ELF_SOURCE_TTL => true,
        Some(_) => {
            m.remove(&program_id);
            false
        }
        None => false,
    }
}

/// Back a job off for `wait`: the candidate loop skips it (measurement included) until then.
fn note_job_retry_after(job_id: alloy::primitives::B256, wait: Duration) {
    if let Ok(mut m) = claim_retry_after_map().lock() {
        let now = std::time::Instant::now();
        // Full: drop the expired first, so the bound evicts a live back-off (re-admitting a decoy
        // early) only when every entry is live.
        if m.len() >= MEASURED_CYCLES_CAP {
            m.retain(|_, until| *until > now);
        }
        bounded_insert(&mut m, job_id, now + wait, MEASURED_CYCLES_CAP);
    }
}

/// Consecutive TEMPORARY pre-claim failures per job (a descriptor or ELF fetch that failed but may
/// heal, a temporary claim refusal). Each one backs the job off, doubling to 30 min, so a job whose inputs keep failing to
/// fetch cannot hold a measure slot or a claim slot on every tick — yet stays a candidate, because
/// the monitor is forward-only and a dropped job never comes back.
static PRECLAIM_STRIKES: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<alloy::primitives::B256, u32>>,
> = std::sync::OnceLock::new();

fn note_transient_preclaim_failure(job_id: alloy::primitives::B256) -> u32 {
    note_preclaim_strike(job_id, 30)
}

fn note_preclaim_strike(job_id: alloy::primitives::B256, base_secs: u64) -> u32 {
    let strikes = PRECLAIM_STRIKES.get_or_init(|| std::sync::Mutex::new(Default::default()));
    let k = match strikes.lock() {
        Ok(mut m) => {
            let k = m.get(&job_id).copied().unwrap_or(0).saturating_add(1);
            bounded_insert(&mut m, job_id, k, MEASURED_CYCLES_CAP);
            k
        }
        Err(_) => 1,
    };
    let wait = Duration::from_secs(base_secs << (k - 1).min(6)).min(Duration::from_secs(1800));
    note_job_retry_after(job_id, wait);
    k
}

/// Consecutive pre-claim ELF failures after which a measured job is dropped: a withheld ELF must not
/// keep a job re-taking a claim slot forever. Counted on their OWN per-job counter (reset by an ELF
/// fetch success), so earlier temporary claim refusals cannot make one ELF failure terminal.
const MAX_PRECLAIM_ELF_FAILURES: u32 = 6;
/// Post-lock (recovered) ELF fetch failures after which the lock is released instead of re-driven.
const MAX_POSTLOCK_ELF_FAILURES: u32 = 3;

static PRECLAIM_ELF_FAILS: std::sync::Mutex<Option<std::collections::HashMap<B256, u32>>> =
    std::sync::Mutex::new(None);

fn note_preclaim_elf_failure(job_id: B256) -> u32 {
    let mut g = PRECLAIM_ELF_FAILS.lock().unwrap_or_else(|p| p.into_inner());
    let m = g.get_or_insert_with(Default::default);
    let k = m.get(&job_id).copied().unwrap_or(0).saturating_add(1);
    bounded_insert(m, job_id, k, MEASURED_CYCLES_CAP);
    k
}

fn clear_preclaim_elf_failures(job_id: B256) {
    let mut g = PRECLAIM_ELF_FAILS.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(m) = g.as_mut() {
        m.remove(&job_id);
    }
}

fn clear_preclaim_strikes(job_id: alloy::primitives::B256) {
    if let Some(m) = PRECLAIM_STRIKES.get() {
        if let Ok(mut m) = m.lock() {
            m.remove(&job_id);
        }
    }
}

/// Put a job the brain dispatched (and so removed from `open_jobs`) back into the Open set, under
/// the usual caps. For TEMPORARY refusals: the monitor is forward-only, so a job that is not put
/// back is lost for the life of the process.
async fn requeue_open_job(state: &zkminer_tui::state::SharedState, job: TrackedJob) {
    let mut s = state.write().await;
    if !s.open_jobs.iter().any(|j| j.info.job_id == job.info.job_id) {
        s.open_jobs.push(job);
        enforce_per_caller_cap(&mut s.open_jobs, MAX_OPEN_JOBS_PER_CALLER);
        retain_top_by_key(&mut s.open_jobs, MAX_OPEN_JOBS, open_rank);
    }
}

/// Jobs set aside on a verdict that lasts (assigned to another prover while its exclusivity runs,
/// too slow for the proving timeout), until when. Kept apart from the claim back-off map, which also
/// holds every temporary refusal, because the Open set's ranking reads only these.
static SET_ASIDE: std::sync::Mutex<Option<std::collections::HashMap<B256, std::time::Instant>>> =
    std::sync::Mutex::new(None);

/// Back a job off for `wait` (see [`note_job_retry_after`]) on a verdict that lasts, so it also
/// ranks last in the Open set (see [`open_rank`]).
fn set_job_aside(job_id: B256, wait: Duration) {
    note_job_retry_after(job_id, wait);
    let mut g = SET_ASIDE.lock().unwrap_or_else(|p| p.into_inner());
    let m = g.get_or_insert_with(Default::default);
    if m.len() >= MEASURED_CYCLES_CAP {
        let now = std::time::Instant::now();
        m.retain(|_, until| *until > now);
    }
    bounded_insert(
        m,
        job_id,
        std::time::Instant::now() + wait,
        MEASURED_CYCLES_CAP,
    );
}

fn job_set_aside(job_id: B256) -> bool {
    SET_ASIDE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .is_some_and(|m| {
            m.get(&job_id)
                .is_some_and(|&until| std::time::Instant::now() < until)
        })
}

fn claim_backing_off(job_id: alloy::primitives::B256) -> bool {
    if let Ok(mut m) = claim_retry_after_map().lock() {
        if let Some(&until) = m.get(&job_id) {
            if std::time::Instant::now() < until {
                return true;
            }
            m.remove(&job_id);
        }
    }
    false
}

/// Journal bindings that a real fulfil showed unsatisfiable (`JournalMismatch`): the job's WHOLE
/// binding — `(programId, proofSystemId, keccak256(inputData), expectedJournalHash, journalFields)`.
/// Every component is load-bearing on HemiProve v2:
///   * INPUT: satisfiability is a function of the committed journal, which is a function of
///     `(program, input)`. Omitting it lets an attacker copy a legit job's PUBLIC `(programId,
///     expectedJournalHash)` with a different, reverting input and false-skip the legit job.
///   * proofSystemId: the FULL hash is `keccak256(abi.encode(DOMAIN, proofSystemId, programId,
///     publicValues))`, so the same (program, input, hash) is satisfiable under one id and not under
///     another (e.g. the two SP1 ids share a vkey).
///   * journalFields: it selects FULL vs FIELDS and the byte ranges, and a marker in slot 0 moves the
///     check to `publicValues[64:]` — a decoy differing only here must not poison the honest tuple.
///
/// The map is a COOLDOWN, not a permanent set (a self-healing breaker for a flood of distinct jobIds
/// sharing one unsatisfiable binding), but a job the lifecycle meets while its entry is live is
/// dropped, not requeued: its siblings share the program and input of a guest whose bound journal
/// already failed. Fed by the decoded `JournalMismatch` selector and by the local binding check of a
/// proven journal. Bounded like the other brain maps.
type PredicateKey = (
    alloy::primitives::B256,
    alloy::primitives::B256,
    alloy::primitives::B256,
    alloy::primitives::B256,
    alloy::primitives::B256,
);

/// The breaker key for a descriptor: its whole journal binding (see [`PredicateKey`]).
fn predicate_key(d: &zkminer_contracts::bindings::JobDescriptor) -> PredicateKey {
    (
        d.programId,
        d.proofSystemId,
        alloy::primitives::keccak256(&d.inputData),
        d.expectedJournalHash,
        d.journalFields,
    )
}

static PREDICATE_UNSATISFIABLE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<PredicateKey, std::time::Instant>>,
> = std::sync::OnceLock::new();

fn predicate_unsatisfiable_set(
) -> &'static std::sync::Mutex<std::collections::HashMap<PredicateKey, std::time::Instant>> {
    PREDICATE_UNSATISFIABLE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Record a binding a real fulfil showed unsatisfiable, throttling it for `SIM_REVERT_TTL` so the
/// claim gate skips siblings carrying the exact binding (see [`PredicateKey`]).
fn mark_predicate_unsatisfiable(key: PredicateKey) {
    if let Ok(mut m) = predicate_unsatisfiable_set().lock() {
        bounded_insert(
            &mut m,
            key,
            std::time::Instant::now() + SIM_REVERT_TTL,
            MEASURED_CYCLES_CAP,
        );
    }
}

/// True if this binding is still within its unsatisfiable cooldown. An expired entry returns false
/// (and is dropped) so a binding whose revert was transient is re-evaluated.
fn predicate_unsatisfiable(key: &PredicateKey) -> bool {
    if let Ok(mut m) = predicate_unsatisfiable_set().lock() {
        if let Some(&until) = m.get(key) {
            if std::time::Instant::now() < until {
                return true;
            }
            m.remove(key);
        }
    }
    false
}

/// True if the descriptor carries a SUBMITTER-CONTROLLED per-job field that can make `fulfillJob`
/// revert for a reason OTHER than the program/predicate binding — a callback contract (which, in
/// strict callback mode, reverts the fulfill when it rejects), crafted `extraVerifierData`, or
/// `callbackExtraData`. A revert on such a job must NOT be attributed to the programId or the
/// (programId, input, expectedJournalHash) tuple: an attacker could post a decoy carrying a LEGIT
/// program's public programId and its legit ELF (the image-id / elf_hash bind passes — no forgery)
/// plus a reverting lever, and thereby throttle the legit program/tuple that honest requesters share.
/// Only a LEVER-FREE revert is attributable to the stable binding, so only those are negative-cached.
fn descriptor_carries_revert_lever(d: &zkminer_contracts::bindings::JobDescriptor) -> bool {
    d.callbackContract != alloy_primitives::Address::ZERO
        || !d.extraVerifierData.is_empty()
        || !d.callbackExtraData.is_empty()
}

/// The pre-claim verdict on a job's journal binding: does the journal its (program, input) measured
/// satisfy it, for `prover`? `None` when no whole journal measured on exactly this descriptor's input
/// is in hand — never a reason to claim. The journal is a deterministic function of (ELF, input) (the
/// risc0 worker seeds `sys_rand` per (ELF, input)), so a mismatch here is the `JournalMismatch` the
/// fulfil would revert after the lock.
fn measured_binding_verdict(
    d: &zkminer_contracts::bindings::JobDescriptor,
    measured: &MeasuredJournal,
    job_id: alloy::primitives::B256,
    prover: alloy::primitives::Address,
) -> Option<Result<(), zkminer_chain::binding::BindingMismatch>> {
    let (input_hash, journal) = measured.as_ref()?;
    if *input_hash != alloy::primitives::keccak256(&d.inputData) {
        return None;
    }
    Some(zkminer_chain::binding::check_journal_binding(
        d, journal, job_id, prover,
    ))
}

/// On the measure path: a journal-bound job whose measured journal does not satisfy its binding can
/// never be fulfilled by us (its descriptor is immutable and its journal deterministic), so it is
/// dropped for good, keyed by its unique jobId like the other permanent verdicts.
fn drop_if_measured_binding_fails(
    d: &zkminer_contracts::bindings::JobDescriptor,
    measured: &MeasuredJournal,
    job_id: alloy::primitives::B256,
    prover: alloy::primitives::Address,
) {
    if d.expectedJournalHash == alloy::primitives::B256::ZERO {
        return;
    }
    if let Some(Err(why)) = measured_binding_verdict(d, measured, job_id, prover) {
        tracing::info!(
            "job {}: its measured journal does not satisfy its binding ({why}) — never claiming it",
            short_id(job_id)
        );
        mark_job_undecodable(job_id);
    }
}

// The verified risc0 ELF keccak is stored IN the measured-cycles cache entry (see
// `Measured::verified_elf_hash` and [`resolve_measured_at`]) so it co-evicts with the
// measurement a claim rides on — never in a separate, independently-evicting map.

/// descriptor hash -> the submitter descriptor's payload length (inputData + callbackExtraData +
/// extraVerifierData), cached during measurement. The fulfill payload is journal + THIS sum + the proof
/// seal; the journal length is cached per (program, input) in [`JournalLenCache`], but the descriptor
/// portion is per-DESCRIPTOR and is only known while the descriptor is in hand. Caching it lets the
/// claim gate re-check a descriptor's full payload against the cap even when THIS descriptor was never
/// the one that executed — e.g. a sibling that lost the `measuring_inputs` dedup race and returned
/// before any journal existed, which otherwise reaches neither the short-circuit nor the post-execute
/// payload screen. Bounded like the measured cache.
type DescPayloadCache =
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<alloy::primitives::B256, u64>>>;

/// Cache THIS descriptor's payload length (see [`DescPayloadCache`]), bounded to `MEASURED_CYCLES_CAP`.
fn insert_desc_payload(
    cache: &DescPayloadCache,
    descriptor_hash: alloy::primitives::B256,
    payload_len: u64,
) {
    if let Ok(mut m) = cache.lock() {
        bounded_insert(&mut m, descriptor_hash, payload_len, MEASURED_CYCLES_CAP);
    }
}

/// True if THIS descriptor's full fulfill payload (the cached journal for its (program, input) + its
/// cached descriptor payload + a minimal seal) is CERTAIN to exceed the on-chain cap — so claiming and
/// proving it would waste a proof on a fulfill guaranteed to OOG-revert, then release at a penalty.
/// Returns false (does not block) whenever any input is not yet known, so it never false-skips a job
/// that could still fulfill. This is the claim-gate backstop for a descriptor whose own measure task
/// returned before checking its payload (notably the `measuring_inputs` race loser).
fn claim_payload_over_cap(
    desc_input: &DescInputCache,
    measured_journal: &JournalLenCache,
    desc_payload: &DescPayloadCache,
    backend: &str,
    program_id: alloy::primitives::B256,
    descriptor_hash: alloy::primitives::B256,
) -> bool {
    let Some(input_hash) = desc_input
        .lock()
        .ok()
        .and_then(|m| m.get(&descriptor_hash).map(|i| i.input_hash))
    else {
        return false;
    };
    let Some(journal_len) = get_journal_len(measured_journal, backend, program_id, input_hash) else {
        return false;
    };
    let Some(payload) = desc_payload
        .lock()
        .ok()
        .and_then(|m| m.get(&descriptor_hash).copied())
    else {
        return false;
    };
    // `payload` already sums inputData + callbackExtraData + extraVerifierData, so pass it as one term;
    // fulfill_payload_over_cap adds the minimal seal and compares to the cap.
    fulfill_payload_over_cap(journal_len, payload as usize, 0, 0)
}

/// (backend, size, program, input) -> consecutive measure-failure count. A wall-clock
/// watchdog SIGKILL during measurement is AMBIGUOUS (a genuinely-too-heavy guest vs. one merely starved
/// under transient host load), unlike the executor's clean cycle-cap trip. So it must NOT permanently
/// blacklist a triple on the first one; we only give up after `MEASURE_TIMEOUT_STRIKES` consecutive
/// timeouts. A success or a clean cap trip clears the tally. Bounded like the measured cache.
type MeasureStrikes = std::sync::Arc<std::sync::Mutex<std::collections::HashMap<MeasureKey, u8>>>;

/// Consecutive measure failures for one (backend, size, program, input) before it is treated as
/// unmeasurable. A genuinely-too-heavy guest times out every attempt and converges in this many ticks;
/// a transiently-starved feasible guest succeeds on a retry well before it.
const MEASURE_TIMEOUT_STRIKES: u8 = 3;

/// Increment and return a (backend, size, program, input)'s consecutive measure-failure count.
/// Bounded like the measured cache so a flood of distinct failing pairs cannot grow the brain's heap.
fn bump_measure_strikes(
    strikes: &MeasureStrikes,
    backend: &str,
    po2: u8,
    program_id: alloy::primitives::B256,
    input_hash: alloy::primitives::B256,
) -> u8 {
    let key = (backend_tag(backend), po2, program_id, input_hash);
    if let Ok(mut m) = strikes.lock() {
        let next = m.get(&key).copied().unwrap_or(0).saturating_add(1);
        bounded_insert(&mut m, key, next, MEASURED_CYCLES_CAP);
        next
    } else {
        // Poisoned: report a single strike so a lock mishap can never wrongly escalate to permanent.
        1
    }
}

/// Clear a (backend, size, program, input)'s failure tally — on a successful measurement (self-heal)
/// or once it has been permanently negative-cached (the tally is then moot).
fn clear_measure_strikes(
    strikes: &MeasureStrikes,
    backend: &str,
    po2: u8,
    program_id: alloy::primitives::B256,
    input_hash: alloy::primitives::B256,
) {
    if let Ok(mut m) = strikes.lock() {
        m.remove(&(backend_tag(backend), po2, program_id, input_hash));
    }
}

/// Record that `descriptor_hash` carries `input_hash`, so a later sighting can resolve its
/// measurement without re-fetching the descriptor. Bounded to `MEASURED_CYCLES_CAP` entries.
fn insert_desc_input(
    cache: &DescInputCache,
    descriptor_hash: alloy::primitives::B256,
    input_hash: alloy::primitives::B256,
) {
    if let Ok(mut m) = cache.lock() {
        // Preserve any over-cap verdict already recorded for this descriptor when (re)recording its
        // resolver, so learning the input hash never clears the fact that its payload is over the cap.
        let over_cap = m.get(&descriptor_hash).map(|i| i.over_cap).unwrap_or(false);
        bounded_insert(
            &mut m,
            descriptor_hash,
            DescInfo { input_hash, over_cap },
            MEASURED_CYCLES_CAP,
        );
    }
}

/// What a job is sized and claimed on: its (program, input) measured at each of its sizes (see
/// [`resolve_measured_at`]).
#[derive(Clone, Debug, PartialEq)]
struct ResolvedMeasurement {
    /// The most cycles at any size, or [`UNMEASURABLE_CYCLES`].
    cycles: u64,
    /// The highest execute peak host footprint (SP1; 0 = unknown).
    peak_host_bytes: u64,
    /// The keccak of an image-id-verified risc0 ELF one of its sizes was measured from.
    verified_elf_hash: Option<alloy::primitives::B256>,
    /// The journal, when every size reported it and it was the same at all of them.
    journal: MeasuredJournal,
    /// The slowest execute, in whole seconds.
    execute_secs: u64,
}

impl ResolvedMeasurement {
    fn unmeasurable() -> Self {
        Self {
            cycles: UNMEASURABLE_CYCLES,
            peak_host_bytes: 0,
            verified_elf_hash: None,
            journal: None,
            execute_secs: 0,
        }
    }
}

/// Resolve a sighting's measurement at every size in `sizes` (see [`measure_sizes`]), under ONE lock
/// hold (finding C-8: a concurrent eviction must not drop a field between two reads). `None` means
/// "not yet sized" and MUST block the claim: the descriptor's input hash is not learned yet, or a size
/// is not measured yet (an expired UNMEASURABLE TTL verdict is dropped here and counts as not yet).
/// An infeasible verdict at any size is the job's verdict, and so is a journal that differs between
/// sizes: a guest whose journal depends on the size it runs at is not claimed (the binding check sees
/// one journal, and any card may prove it). Otherwise the most cycles, the slowest execute and the
/// highest peak.
fn resolve_measured_at(
    measured: &MeasuredCache,
    desc_input: &DescInputCache,
    backend: &str,
    sizes: &[u8],
    program_id: alloy::primitives::B256,
    descriptor_hash: alloy::primitives::B256,
) -> Option<ResolvedMeasurement> {
    let input_hash = desc_input.lock().ok()?.get(&descriptor_hash)?.input_hash;
    let mut m = measured.lock().ok()?;
    let now = std::time::Instant::now();
    let mut entries = Vec::with_capacity(sizes.len());
    let mut missing = sizes.is_empty();
    for &po2 in sizes {
        let key = (backend_tag(backend), po2, program_id, input_hash);
        match m.get(&key) {
            Some(e) if e.retry_after.is_some_and(|until| now >= until) => {
                m.remove(&key);
                missing = true;
            }
            Some(e) => entries.push(e.clone()),
            None => missing = true,
        }
    }
    if entries.iter().any(|e| e.cycles >= UNMEASURABLE_CYCLES) {
        return Some(ResolvedMeasurement::unmeasurable());
    }
    if entries.is_empty() {
        return None;
    }
    let journals: Vec<&std::sync::Arc<[u8]>> =
        entries.iter().filter_map(|e| e.journal.as_ref()).collect();
    if journals.iter().any(|j| j[..] != journals[0][..]) {
        return Some(ResolvedMeasurement::unmeasurable());
    }
    if missing {
        return None;
    }
    let journal = (journals.len() == entries.len()).then(|| (input_hash, journals[0].clone()));
    // Any size's: each was image-id-verified, so each binds the claim's re-fetch to the registered
    // program (bytes that differ there are re-checked, and refused before the claim).
    let hash = entries.iter().find_map(|e| e.verified_elf_hash);
    Some(ResolvedMeasurement {
        cycles: entries.iter().map(|e| e.cycles).max().unwrap_or(0),
        peak_host_bytes: entries.iter().map(|e| e.peak_host_bytes).max().unwrap_or(0),
        verified_elf_hash: hash,
        journal,
        execute_secs: entries.iter().map(|e| e.execute_secs).max().unwrap_or(0),
    })
}

#[cfg(test)]
fn resolve_measured(
    measured: &MeasuredCache,
    desc_input: &DescInputCache,
    backend: &str,
    sizes: &[u8],
    program_id: alloy::primitives::B256,
    descriptor_hash: alloy::primitives::B256,
) -> Option<u64> {
    resolve_measured_at(
        measured,
        desc_input,
        backend,
        sizes,
        program_id,
        descriptor_hash,
    )
    .map(|r| r.cycles)
}

#[cfg(test)]
fn resolve_measured_peak(
    measured: &MeasuredCache,
    desc_input: &DescInputCache,
    backend: &str,
    sizes: &[u8],
    program_id: alloy::primitives::B256,
    descriptor_hash: alloy::primitives::B256,
) -> Option<u64> {
    resolve_measured_at(
        measured,
        desc_input,
        backend,
        sizes,
        program_id,
        descriptor_hash,
    )
    .map(|r| r.peak_host_bytes)
}

/// `(cycles, peak_host_bytes, journal, execute_secs)`.
#[cfg(test)]
fn resolve_measured_full(
    measured: &MeasuredCache,
    desc_input: &DescInputCache,
    backend: &str,
    sizes: &[u8],
    program_id: alloy::primitives::B256,
    descriptor_hash: alloy::primitives::B256,
) -> Option<(u64, u64, MeasuredJournal, u64)> {
    resolve_measured_at(
        measured,
        desc_input,
        backend,
        sizes,
        program_id,
        descriptor_hash,
    )
    .map(|r| (r.cycles, r.peak_host_bytes, r.journal, r.execute_secs))
}

/// `(cycles, verified_elf_hash, journal, execute_secs)`.
#[cfg(test)]
fn resolve_measured_with_hash(
    measured: &MeasuredCache,
    desc_input: &DescInputCache,
    backend: &str,
    sizes: &[u8],
    program_id: alloy::primitives::B256,
    descriptor_hash: alloy::primitives::B256,
) -> Option<(u64, Option<alloy::primitives::B256>, MeasuredJournal, u64)> {
    resolve_measured_at(
        measured,
        desc_input,
        backend,
        sizes,
        program_id,
        descriptor_hash,
    )
    .map(|r| (r.cycles, r.verified_elf_hash, r.journal, r.execute_secs))
}

/// Bound on a single cycle measurement. Execution is far cheaper than proving, but a hostile
/// or pathological guest must not hold a worker: the watchdog kills it at this point, and a
/// job we cannot execute inside the budget is one we should not claim either.
const MEASURE_TIMEOUT: Duration = Duration::from_secs(120);

/// Cycle count the PROVE path (watchdog timeout / min-VRAM routing / po2) sizes on. It
/// is the MEASURED count, never the submitter-declared `expected_cycles` alone: admission claims a job
/// only if feasible at `max(declared, measured)`, and the prove path must size on the SAME quantity or
/// a tiny declared value collapses the watchdog to its floor and SIGKILLs a job that was admitted
/// feasible on the larger measured count — a submitter-driven premature kill → release-penalty/slash.
/// `max(declared, measured)` can only hold the sizing at or ABOVE the real work (a larger value merely
/// detects a wedged GPU later, bounded by the configured cap — the safe direction). With no
/// measurement in hand (recovery, or a non-measurable backend) the declared value is still adversarial:
/// a nonzero one is floored at `FALLBACK_ESTIMATED_CYCLES` rather than trusted small, while a zero
/// declaration returns 0 so the caller keeps the old full-timeout fallback.
/// Is this measure error the dispatcher's GENUINE wall-clock watchdog timeout (finding RH-round2/4)?
///
/// A real timeout is the ONLY strike-out the measure path treats as possibly-transient (and so grants
/// a retry TTL rather than a permanent blacklist). It must be recognised by the TYPED, dispatcher-only
/// `MeasureWallClockTimeout` — never by substring-matching the error message, which carries
/// guest-controlled bytes a hostile guest could set to "wall-clock watchdog" to forge the TTL and
/// re-open the perpetual re-measurement DoS. Extracted as a free fn so the classification is unit-
/// testable without driving a worker.
fn is_measure_wall_clock_timeout(e: &anyhow::Error) -> bool {
    e.downcast_ref::<zkminer_prover_protocol::types::MeasureWallClockTimeout>()
        .is_some()
}

/// Was this measurement PREEMPTED by a committed proof reclaiming its resources (residual A)?
///
/// Like the wall-clock-timeout classifier, recognised by the TYPED, dispatcher-only
/// `MeasurePreempted` — never by substring — so a hostile guest cannot forge it. A preemption is
/// purely transient scheduling (the measurement was healthy and yielded to a bonded job), so the
/// caller must treat it exactly like `MeasureSlotsBusy`: no strike, no negative-cache, no retry TTL —
/// just re-measure next tick. Extracted as a free fn so the classification is unit-testable.
fn is_measure_preempted(e: &anyhow::Error) -> bool {
    e.downcast_ref::<zkminer_prover_protocol::types::MeasurePreempted>()
        .is_some()
}

fn prove_sizing_cycles(declared: u64, measured: Option<u64>) -> u64 {
    match measured {
        Some(m) => declared.max(m),
        None if declared > 0 => declared.max(FALLBACK_ESTIMATED_CYCLES),
        None => 0,
    }
}

/// Wall-clock bound on each pre-claim fetch (descriptor, ELF) on the measurement path.
/// The prove path bounds the SAME fetches with `with_deadline_budget`; the measure path had no bound,
/// so a submitter storage/descriptor source that stalls could pin a scarce measure-budget slot for
/// `num_uris × per-URI-timeout` (minutes), and because a claim now REQUIRES a measurement, a frozen
/// budget halts all claiming. A real descriptor read / few-MB ELF download completes in seconds; this
/// is generous for that while cutting a staller off. `download_elf` also caps the URI count.
const MEASURE_FETCH_BUDGET: Duration = Duration::from_secs(90);

/// Fallback fee rate (5%) used only if the adapter query fails.
const FALLBACK_FEE_RATE_BPS: u16 = 500;

/// Fallback default collateral ratio (150%) matching
/// `Constants.GLOBAL_DEFAULT_COLLATERAL_BPS` in HemiProve Solidity.
const FALLBACK_DEFAULT_COLLATERAL_BPS: u128 = 15_000;

/// 1 HEMI in wei (18 decimals). Used to render collateral amounts in whole HEMI.
const ONE_HEMI_WEI: u128 = 1_000_000_000_000_000_000;

/// Minimum spacing between "insufficient collateral" warnings. The brain
/// re-evaluates every 5s; without throttling it would warn every tick.
const COLLATERAL_WARN_EVERY: Duration = Duration::from_secs(120);

/// How recently a 429 must have been seen for the brain to pause claiming new
/// jobs. A claim kicks off descriptor reconstruction (a heavy `getLogs`
/// burst), so piling on more work while the endpoint is rate-limiting only
/// deepens the backlog. In-flight jobs (prove/fulfill/recovery) are unaffected —
/// they run in their own tasks and must finish to release collateral. Sized a
/// little above the brain's 5s tick so a single 429 gates a few ticks, not one.
const RPC_BACKOFF_WINDOW: Duration = Duration::from_secs(30);
// Hard ceiling: even while rate-limited, the state-refresh multicall runs at least
// this often so stake_info (→ the idle-recovery collateral gate) never freezes and strands.
const REFRESH_STALENESS_CEILING: Duration = Duration::from_secs(60);
// The brain won't claim on collateral data older than this (~2× the 15s refresh
// period), so a silently-failing refresh can't drive claims on stale stake_info.
const CLAIM_FRESHNESS_MAX: Duration = Duration::from_secs(35);
// After this much rate-limit quiet, the escalated claim-pause window decays to base.
const CLAIM_BACKOFF_DECAY: Duration = Duration::from_secs(90);

/// Minimum spacing between "backing off — RPC rate-limited" warnings.
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

pub async fn run(
    config_path: Option<&Path>,
    headless: bool,
    watch: Option<WatchOnly>,
) -> Result<()> {
    let config = ZkMinerConfig::load(config_path)?;
    config.validate_for_chain()?;
    if watch.is_none() {
        hold_instance_lock()?;
    }
    let queue_horizon_secs = config.prover.queue_horizon_secs;
    let client = match watch {
        Some(w) => {
            WATCH_ONLY.store(true, std::sync::atomic::Ordering::SeqCst);
            // The configured key only names the address to watch as: it is dropped here, and the
            // client signs with a throwaway key behind a transport that refuses every send.
            let address = match w.address {
                Some(a) => {
                    // No key is read, so `load_signer` does not scrub its variable: do it here, so
                    // no worker (whatever the variable is named) inherits it.
                    if config.wallet.key_source == "env" {
                        std::env::remove_var(&config.wallet.key_env_var);
                    }
                    a
                }
                None => load_signer(&config.wallet)?.address(),
            };
            // An ELF cache of its own: the inspector fetches every job's program, and pruning or
            // purging the shared `~/.zkminer/elfs` could cost a miner on this host an ELF it holds
            // a lock for.
            if let Some(home) = dirs::home_dir() {
                zkminer_chain::programs::set_elf_cache_dir(
                    home.join(".zkminer").join("watch").join("elfs"),
                );
            }
            tracing::warn!(
                "WATCH-ONLY as {address}: every check up to the claim runs, and each job is reported \
                 instead of claimed. Nothing is signed or sent; locks this address holds are left to \
                 the miner that took them."
            );
            ChainClient::new_watch_only(&config, address).await?
        }
        None => ChainClient::new(&config, load_signer(&config.wallet)?).await?,
    };

    // Before ANY transaction (handoff §13 tests 1-2): the configured stack must be the live
    // deployment for this chain, wired to itself (router.staking/registry/hemiToken), and running the
    // AUDITED code; and every proof system zkminer serves must be registered and wrap the audited
    // verifier whose seal prefix equals the one zkminer emits — otherwise every proof would revert
    // `VerifierCallFailed` after the collateral-locking claim.
    // Not fatal (see `DEPLOYMENT_VERIFIED`): no claims until it passes, but held locks are recovered.
    match reverify_deployment(&client).await {
        Ok(lines) => {
            for line in lines {
                tracing::info!("startup check — {line}");
            }
        }
        Err(e) => tracing::error!(
            "PAGE: deployment verification failed ({e:#}) — NOT claiming new jobs; locks already \
             held are still recovered and driven. Re-checked every {}s.",
            DEPLOYMENT_RETRY.as_secs()
        ),
    }
    // Resolve the RISC Zero groth16 seal selector (config override or the built-in risc0 v3.0.x
    // default) BEFORE verifying it against the live verifier: verifying the default while seals are
    // later prefixed with an override would pass the check and then revert every fulfil.
    let sel = match config.prover.risc0_groth16_selector.as_deref() {
        Some(s) => parse_seal_selector(s).ok_or_else(|| {
            anyhow::anyhow!("prover.risc0_groth16_selector {s:?} is not a 4-byte hex selector")
        })?,
        None => RISC0_GROTH16_SELECTOR,
    };
    let _ = SEAL_SELECTOR.set(sel);
    // NOT fatal: a held lock must still be recovered (fulfilled, kept through a Disabled window, or
    // released) when the adapter is disabled, swapped, or fails a pin. Exiting here would leave every
    // lock to a 100% slash. Claims for the proof system stay off until a re-check passes.
    match reverify_risc0(&client).await {
        Ok(adapter) => tracing::info!(
            "startup check — risczero.groth16.v1: adapter {adapter} registered, {}, SELECTOR 0x{}",
            if zkminer_chain::deployment::code_pins_skipped() {
                "adapter and verifier code NOT checked (ZKMINER_SKIP_CODE_PINS=1)"
            } else {
                "audited verifier"
            },
            alloy::hex::encode(risc0_seal_selector())
        ),
        Err(e) => tracing::error!(
            "PAGE: risczero.groth16.v1 verification failed ({e:#}) — NOT claiming risc0 jobs; locks \
             already held are still recovered and driven. Re-checked every few minutes."
        ),
    }
    // Not a PAGE: a deployment need not register SP1 at all.
    match reverify_sp1(&client).await {
        Ok(adapter) => tracing::info!(
            "startup check — sp1.groth16.v1: adapter {adapter} registered, {}, VERIFIER_HASH 0x{}…",
            if zkminer_chain::deployment::code_pins_skipped() {
                "adapter and verifier code NOT checked (ZKMINER_SKIP_CODE_PINS=1)"
            } else {
                "audited circuit v6.1.0 verifier"
            },
            alloy::hex::encode(sp1_seal_prefix())
        ),
        Err(e) => tracing::warn!(
            "sp1.groth16.v1 verification failed ({e:#}) — NOT claiming SP1 jobs. Re-checked every \
             few minutes."
        ),
    }
    let state = new_shared_state();

    // Initialize worker pool (before TUI, after config load)
    let benchmark_timeout = if config.prover.benchmark_timeout_secs > 0 {
        Some(std::time::Duration::from_secs(
            config.prover.benchmark_timeout_secs,
        ))
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
    // One `sys_rand` key for every risc0 worker this miner spawns, loaded once: a measured journal is
    // only worth checking a binding against if the proof that follows, on whichever worker, seeds the
    // guest alike — and the measurements live in this process, as long as the key does.
    {
        let (key, err) = zkminer_prover_protocol::sys_rand::host_key(dirs::home_dir().as_deref());
        if let Some(e) = &err {
            tracing::warn!(
                "risc0 sys_rand key file unusable ({e}): using a key for this run only, so no \
                 journal-bound job is claimed (its journal could change when a lock is re-proved \
                 after a restart)"
            );
        }
        zkminer_prover::worker::set_risc0_sys_rand_key(key, err.is_some());
    }
    // Watch-only proves nothing, and only measures what this build serves: no worker for another
    // backend (SP1's has host-wide startup effects: it installs its bundled `sp1-gpu-server` and
    // reaps orphaned servers' sockets, beside whatever miner runs on this host).
    if watch_only() {
        pool.only_backends(served_backends());
    }
    // On a BLOCKING thread, like the hardware probe just below it and for the same reason.
    //
    // Per slot this blocks on `nvidia-smi` (up to VRAM_QUERY_TIMEOUT), then the serialised spawner
    // thread, then `cap_process_memory`'s `busctl` (up to CAP_TIMEOUT), then the Hello handshake —
    // tens of seconds in the worst case, serially, and the runtime only has four worker threads.
    // Doing that inline starved the executor before the TUI even existed.
    let (pool, connected): (WorkerPool, Vec<String>) = tokio::task::spawn_blocking(move || {
        let connected = pool.discover_and_spawn();
        (pool, connected)
    })
    .await
    .map_err(|e| anyhow::anyhow!("worker discovery task panicked: {e}"))?;
    if !connected.is_empty() {
        tracing::info!("Connected subprocess workers: {}", connected.join(", "));
    }
    init_worker_pool(pool);
    // SP1's one-time setup, in the background: SP1 jobs are not claimed until it is done (see the
    // pre-claim gate), and everything else proceeds meanwhile. Not when watching: it proves on the
    // GPU, and a watch-only run proves nothing.
    if !watch_only() {
        spawn_sp1_warmup();
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
            tracing::info!("Loaded cached benchmarks (zkOP/s: {:.0})", suite.zkops);
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

        s.runtime_settings.min_profit_threshold = config.prover.min_profit_threshold;
        s.runtime_settings.deadline_safety_margin = config.prover.deadline_safety_margin;
        s.runtime_settings.strategy = config.prover.strategy.clone();
        s.runtime_settings.electricity_cost_kwh = config.prover.electricity_cost_kwh;
        s.runtime_settings.system_power_watts = config.prover.system_power_watts;
        s.runtime_settings.token_price_usd = config.prover.token_price_usd;
        s.runtime_settings.gas_cost_usd = config.prover.gas_cost_usd;
        s.runtime_settings.risc0_job_po2_config = config.prover.risc0_job_po2.clone();
        // Default TRUE: every open-market job is journal-bound, and each is claimed only when the
        // journal its (program, input) measured satisfies its binding.
        s.runtime_settings.claim_predicate_jobs = config.chain.claim_predicate_jobs.unwrap_or(true);

        s.address = format!("{}", client.address);
        s.connected = true;
        s.chain_id = config.chain.chain_id;

        // Hydrate head + ETH/HEMI balances + stake + prover-stats in
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
                    // Surface the collateral picture at startup and warn if most of it is
                    // locked (e.g. tied up in past-deadline jobs) — the usual cause of a miner
                    // that connects fine but then silently claims nothing.
                    let avail = fmt_hemi(stake.available_collateral);
                    let locked = fmt_hemi(stake.locked_collateral);
                    let total = fmt_hemi(stake.total_staked);
                    tracing::info!(
                        "Collateral: {avail} HEMI available, {locked} locked, {total} staked"
                    );
                    if stake.total_staked > 0
                        && stake.available_collateral < stake.total_staked / 10
                    {
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
        s.setup_status.is_testnet =
            config.chain.chain_id == zkminer_chain::staking::TESTNET_CHAIN_ID;
        s.setup_status.min_staking_age_secs = config.chain.min_staking_age_secs.unwrap_or(0);
        s.setup_status
            .refresh_from_balances(eth, hemi, stake.as_ref());

        // Show setup wizard if not ready (first-run experience). Only when the
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
            s.add_log(
                LogLevel::Info,
                "Setup wizard started — complete steps to begin proving",
            );
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
    let backfill_client = client.clone();
    let event_handle = tokio::spawn(async move {
        // Events before `BackfillComplete` are the startup backfill: staged here, not ingested (see
        // `admit_backfilled_jobs`).
        let mut backfilling = true;
        let mut staged: Vec<TrackedJob> = Vec::new();
        let mut staged_cancelled: std::collections::HashSet<B256> = std::collections::HashSet::new();
        while let Some(event) = monitor_rx.recv().await {
            // History events touch only the local staging buffer: no state lock, O(1) per event
            // (caps are applied in amortized batches), so a long history cannot stall the brain.
            if backfilling {
                match &event {
                    MonitorEvent::JobSubmitted { proof_system_id, .. }
                        if resolve_backend(*proof_system_id).is_none() =>
                    {
                        continue;
                    }
                    MonitorEvent::JobCancelled { job_id, .. } => {
                        if staged_cancelled.len() < 4 * MAX_STAGED_BACKFILL {
                            staged_cancelled.insert(*job_id);
                        }
                        continue;
                    }
                    _ => {}
                }
            }
            let mut s = state_clone.write().await;
            match event {
                MonitorEvent::JobSubmitted {
                    job_id,
                    program_id,
                    proof_system_id,
                    caller,
                    min_price,
                    max_price,
                    fulfillment_timeout,
                    deposited_amount,
                    ..
                } => {
                    // STATIC ingest gate: a job whose proofSystemId doesn't map to
                    // a backend this build supports can never be claimed by this miner —
                    // don't let it occupy a candidate slot in the per-tick Multicall3
                    // forever. STATIC ONLY (resolve_backend is a pure keccak map): NEVER
                    // gate here on dynamic worker health / sim-mode — the monitor is
                    // forward-only with a one-shot backfill and no re-discovery, so a job
                    // dropped during a transient unhealthy-worker window would be
                    // permanently lost. The dynamic gate stays per-tick in the eval loop.
                    let tracked = TrackedJob {
                        info: zkminer_chain::jobs::JobInfo {
                            job_id,
                            program_id,
                            caller,
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
                    };
                    if resolve_backend(proof_system_id).is_none() {
                        tracing::debug!(
                            "ingest: ignoring job {} with unsupported proof system 0x{}",
                            short_id(job_id),
                            alloy::hex::encode(proof_system_id)
                        );
                        // Watch-only still reports it, as not served (live jobs only: the backfill
                        // is not status-checked, and its history would flood the inspector).
                        if !backfilling {
                            watch_enqueue(&tracked);
                        }
                        continue;
                    }
                    if backfilling {
                        // History: stage it (memory-bounded, caps amortized) for a status-checked
                        // admission.
                        drop(s);
                        staged.push(tracked);
                        if staged.len() >= 2 * MAX_STAGED_BACKFILL {
                            staged.retain(|j| !staged_cancelled.contains(&j.info.job_id));
                            enforce_per_caller_cap(&mut staged, MAX_STAGED_BACKFILL / 8);
                            retain_top_by_key(&mut staged, MAX_STAGED_BACKFILL, |j| j.current_price);
                        }
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
                    watch_enqueue(&tracked);
                    s.open_jobs.push(tracked);
                    // Bound the Open-candidate set. A submitter can post unboundedly
                    // many jobs and leave them Open; every brain tick reads them all via Multicall3
                    // over the throttled RPC, so an uncapped list is a slow-RPC-starvation DoS.
                    //
                    // Evict the LEAST VALUABLE jobs (lowest current_price), NOT the oldest. This
                    // monitor stream is forward-only with a one-shot backfill and no re-discovery (see
                    // the ingest gate above and the candidate-loop notes), so an evicted Open job is
                    // gone until some other event re-surfaces it — it does NOT "reappear via the
                    // monitor" on its own. Dropping by arrival age therefore let a decoy flood
                    // PERMANENTLY evict a legitimately high-value job that merely arrived early (an
                    // over-block). Dropping the cheapest instead means a submitter can only push a
                    // tracked job out by posting an even higher-priced one.
                    //
                    // But current_price is the submitter's own `min_price`, so a single hostile caller
                    // could flood >= MAX_OPEN_JOBS high-min_price jobs it can never let us claim
                    // (assigned to its own second address, or an unprovable/over-cap ELF) and
                    // PERMANENTLY evict every genuine job by advertised value alone. So enforce
                    // PER-CALLER FAIRNESS first: no single caller address may hold more than
                    // MAX_OPEN_JOBS_PER_CALLER of the set, so one address cannot crowd out other
                    // submitters' work. (A Sybil flood across many funded addresses still costs gas +
                    // a deposit per job per address and is the documented residual; a fully
                    // Sybil-proof fix needs on-chain re-discovery or stake-weighting.) The global cap
                    // then bounds the aggregate, still dropping the cheapest across whoever remains.
                    enforce_per_caller_cap(&mut s.open_jobs, MAX_OPEN_JOBS_PER_CALLER);
                    retain_top_by_key(&mut s.open_jobs, MAX_OPEN_JOBS, open_rank);
                }
                // Event-driven pruning: a job claimed (by ANYONE — including our
                // own claim, where this is an idempotent no-op) or cancelled is no longer
                // an open candidate. Pruning it here — straight from log data, zero extra
                // requests — removes it from the per-tick Multicall3 candidate set BEFORE
                // the next tick has to spend a chunk slot discovering the same thing.
                // GUARD: touch ONLY open_jobs. Never in_flight or the journal —
                // those are owned by the lifecycle/batch-reconcile paths, and a foreign
                // JobClaimed for a job WE hold would otherwise corrupt strand protection.
                MonitorEvent::JobClaimed { job_id, prover, .. } => {
                    forget_job_bound(job_id);
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
                MonitorEvent::BackfillComplete => {
                    backfilling = false;
                    let mut history = std::mem::take(&mut staged);
                    history.retain(|j| !staged_cancelled.contains(&j.info.job_id));
                    staged_cancelled.clear();
                    enforce_per_caller_cap(&mut history, MAX_STAGED_BACKFILL / 8);
                    retain_top_by_key(&mut history, MAX_STAGED_BACKFILL, |j| j.current_price);
                    if !history.is_empty() {
                        tokio::spawn(admit_backfilled_jobs(
                            backfill_client.clone(),
                            state_clone.clone(),
                            history,
                        ));
                    }
                }
                MonitorEvent::JobCancelled { job_id, .. } => {
                    forget_job_bound(job_id);
                    let before = s.open_jobs.len();
                    s.open_jobs.retain(|j| j.info.job_id != job_id);
                    if s.open_jobs.len() != before {
                        tracing::debug!(
                            "pruned cancelled job {} from candidates",
                            short_id(job_id)
                        );
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
        // Phase-offset the 15s state-refresh multicall by 7s so it does not
        // land in the same second as the monitor's 10s get_logs poll (their LCM collision
        // drops from every 30s to the 60s boundary). Fixed +7s startup delay only, zero
        // extra requests. Do NOT apply this offset to the monitor/brain loops.
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + std::time::Duration::from_secs(7),
            std::time::Duration::from_secs(15),
        );
        let meter = refresh_client.rpc_meter();
        let mut cycle: u64 = 0;
        // Circuit-breaker state: the wall-clock instant of the last get_refresh_batch
        // ATTEMPT (success OR failure). Seeded to now so the first cycle isn't force-refreshed.
        let mut last_refresh_attempt = tokio::time::Instant::now();
        loop {
            interval.tick().await;
            // Update the RPC request meter every cycle (and log it periodically so
            // headless runs can see request volume), independent of the balance refresh.
            let (rpc_total, rpc_min) = (meter.total(), meter.last_minute());
            cycle = cycle.wrapping_add(1);
            if cycle.is_multiple_of(4) {
                tracing::info!("rpc requests: {rpc_total} total, {rpc_min}/min");
            }
            {
                let mut s = state_refresh.write().await;
                s.rpc_total = rpc_total;
                s.rpc_last_minute = rpc_min;
            }
            // 429 CIRCUIT-BREAKER: while the endpoint is rate-limiting, SKIP the
            // Multicall3 refresh — it would just deepen the backlog, and its OWN 429 re-arms
            // the backoff meter every 15s, which would keep the brain's
            // claim-pause armed forever. The free meter update above still runs.
            // STALENESS CEILING: force a refresh ATTEMPT at least every REFRESH_STALENESS_CEILING
            // even during a storm (measured from the last ATTEMPT, so a sustained storm forces
            // ~1/ceiling, not 1/15s). NOTE: this bounds ATTEMPT cadence, NOT stake_info staleness
            // — a forced attempt that itself 429s updates nothing, so stake_info can stay frozen
            // for the whole storm. The idle-recovery gate is therefore made independently robust
            // to a stale stake_info (it scans when the read is stale),
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
                    // Stamp last_refresh ONLY when the stake sub-call
                    // actually returned — matching the startup path. `last_refresh` is the
                    // claim-freshness gate's proxy for "how fresh is s.stake_info", and
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
    let (_hw_monitor, hw_rx) =
        zkminer_tui::hardware::HwMonitor::spawn(hw_input, std::time::Duration::from_secs(2));
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

    // The journal is the AUTHORITATIVE record of what we hold on-chain: a breadcrumb is
    // written BEFORE every claim tx and removed only on fulfil or successful release, so it
    // brackets the on-chain lock exactly. `active_jobs` does NOT — a job is pushed there only
    // AFTER the claim mines and the post-claim status view returns, so during that window a
    // job holds collateral while being invisible to both shutdown stages. Constructed here
    // (rather than inside `miner_brain`) so the shutdown path can read it.

    // Miner brain: evaluates open jobs, claims, proves, and fulfills.
    let brain_client = client.clone();
    let brain_state = state.clone();
    // A watch-only run holds nothing, and the journal on disk belongs to the miner that may be
    // running beside it: start empty and never save (see `save_journal_or_warn`).
    let journal: SharedJournal = Arc::new(Mutex::new(if watch_only() {
        JobJournal::default()
    } else {
        JobJournal::load()
    }));
    let brain_journal = journal.clone();
    let proving_timeout = Duration::from_secs(config.prover.proving_timeout_secs.max(60));
    let cost_params = CostParams {
        electricity_cost_kwh: config.prover.electricity_cost_kwh,
        // The OVERHEAD only; `evaluate_job` adds the measured CPU and card.
        base_overhead_watts: config.prover.system_power_watts,
        hardware_cost_per_hour: 0.0,
        gas_cost_usd: config.prover.gas_cost_usd,
    };
    // `min_profit_threshold`, `deadline_safety_margin` and `token_price_usd` are NOT read here:
    // they are seeded into `runtime_settings` above and the brain re-reads them live each tick.
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
            // Handlers are installed IMMEDIATELY — NOT after the TUI exits.
            //
            // Awaiting `tui_done_rx` here would be wrong: it only fires AFTER
            // `run_tui` returns. So for the whole TUI session — and TUI is the DEFAULT mode
            // — SIGTERM would keep its default disposition and kill the process outright: no
            // pause, no drain, no ABANDON, no release_and_clean, no exit 75, no worker reap,
            // and every held job would ride to its 7200s lock deadline.
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
                // Break the TUI out of its event loop so `run()` reaches the ladder.
                // No-op in headless (nothing reads it there).
                {
                    let mut st = sig_state.write().await;
                    st.shutdown_requested = true;
                    st.paused = true;
                }
                n = n.saturating_add(1);
                match n {
                    // Wording must match what actually happens: with
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
                        // Reap workers first. SP1's `sp1-gpu-server` is a GRANDCHILD
                        // that does NOT die with us; it can keep ~11.5 GB of VRAM allocated
                        // after the parent exited.
                        //
                        // BOUNDED, because `shutdown_all` is not: its phase 4 takes a
                        // BLOCKING slot lock, while phases 2/3 skip any slot whose `pid` is
                        // momentarily 0 — the respawn/recycle window (dispatcher.rs, where
                        // the pid is zeroed before the handle is dropped and only restored
                        // after `ensure_alive`). Such a worker is never signalled, so the
                        // lock it holds is not released until its whole proof finishes (up
                        // to the 600s watchdog). The "Force exit" print therefore comes BEFORE
                        // this call, and the third signal must terminate regardless: reap
                        // off-thread and cap the wait (a normal reap takes ~2.2s).
                        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
                        std::thread::spawn(move || {
                            if let Some(pool) = zkminer_prover::engine::worker_pool() {
                                pool.close();
                            }
                            let _ = done_tx.send(());
                        });
                        if done_rx
                            .recv_timeout(std::time::Duration::from_secs(10))
                            .is_err()
                        {
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
        // Non-unix has no signal task; fall back to plain Ctrl-C so headless does not
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
    // brain_handle is NOT aborted here. The claim of "per-job lifecycles are
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
    // would not stall the drain.

    // 2. DRAIN — let in-flight proofs finish and fulfil.
    //
    //    The old sequence called `pool.shutdown_all()` HERE, before releasing. That kills
    //    the workers, so every in-flight proof was destroyed unconditionally — on the
    //    1-5 minute proofs this miner now runs that discarded up to five minutes of GPU
    //    work and the claim gas, even at 99% complete, and the job then had to be
    //    re-proved from scratch by the recovery path on the next start.
    let mut exit_code = 0i32;
    let supervised = SUPERVISED_STOP.load(std::sync::atomic::Ordering::SeqCst);
    let drain_budget = if supervised {
        SUPERVISED_DRAIN_TIMEOUT
    } else {
        DRAIN_TIMEOUT
    };
    if supervised {
        tracing::warn!(
            "supervised stop (SIGTERM): draining {}s then releasing — a supervisor will \
             SIGKILL before a full drain could finish",
            drain_budget.as_secs()
        );
    }
    let drain_deadline = std::time::Instant::now() + drain_budget;
    let mut abandoned = false;
    // Lifecycle-less entries the drain already released at the margin (see the loop below).
    // Lifecycle-less entries the drain handed to release_and_clean, and when. Re-armed: a lock that
    // was KEPT (a pause, a Disabled adapter, an unreadable state) can become releasable mid-drain.
    let mut drain_released: std::collections::HashMap<B256, std::time::Instant> =
        std::collections::HashMap::new();
    loop {
        if *sig_rx.borrow() >= 2 {
            tracing::warn!("drain interrupted by second signal — abandoning");
            abandoned = true;
            break;
        }
        // Union of what the UI thinks is in flight AND what the journal says we hold
        // on-chain. The journal alone is authoritative for "collateral is locked"; without
        // it the loop declares "drain complete" while a claim is mid-flight.
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
        let now_s = zkminer_chain::client::chain_now();
        // "Already past" decisions use the LOWER estimate, and only ABANDON can re-read the live
        // (pause-credited) deadline of an entry that merely LOOKS past.
        let now_floor = zkminer_chain::client::chain_now_floor();
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
                        } else if e.lock_deadline > now_floor {
                            true
                        } else {
                            // Past its RECORDED deadline — which goes stale during a pause. Not
                            // proof the lock is dead: send it through ABANDON's re-check.
                            stale_intent = true;
                            false
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
        // `Claiming` breadcrumb whose view reads prover == ZERO), and recovery — its GC — is off
        // during shutdown. Escalating unconditionally therefore aborted EVERY subsequent drain on
        // iteration 1, discarding in-flight proofs seconds from fulfilling. Its urgency is handled
        // separately: the margin cut below hands a lifecycle-less zero-deadline entry to
        // release_and_clean before even the contract's shortest window (MIN_JOB_WINDOW_SECS)
        // could close.
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
        // Never drain past the point where a held lock could still be released: `releaseJob` reverts
        // at D+G, and the drain budget itself is deadline-blind. A live lifecycle self-bounds at
        // `cutoff - DEADLINE_RELEASE_MARGIN_SECS`, but a journal entry with no lifecycle behind it (a
        // release that failed on RPC, a handed-back lock) has nothing to advance it: recovery is off
        // during shutdown, and waiting it out converts a releasable lock into a slash.
        // Only the entries that have reached the margin AND have no live lifecycle behind them need
        // action now — a live lifecycle self-releases at exactly this point, and a global abandon here
        // would release healthy siblings (a 5% penalty each) with proofs seconds from finishing.
        let near_margin: Vec<B256> = {
            let live: std::collections::HashSet<B256> = {
                let s = state.read().await;
                s.active_jobs.iter().map(|j| j.info.job_id).collect()
            };
            let j = journal.lock().unwrap_or_else(|e| e.into_inner());
            j.iter()
                .filter(|e| {
                    !live.contains(&e.job_id)
                        && drain_released
                            .get(&e.job_id)
                            .is_none_or(|t| t.elapsed() >= Duration::from_secs(60))
                })
                .filter(|e| {
                    if e.lock_deadline == 0 {
                        // Deadline never recorded (the lifecycle handed back before reading it). The
                        // shortest window the contract allows still bounds it: hand it to
                        // release_and_clean — which re-reads the view and backfills — before that
                        // window could close.
                        let age = now_s.saturating_sub(e.claimed_at.max(0) as u64);
                        return age.saturating_add(DEADLINE_RELEASE_MARGIN_SECS + 60) >= MIN_JOB_WINDOW_SECS;
                    }
                    // Past its RECORDED deadline too: the record goes stale during a pause, and only a
                    // re-read (release_and_clean) can tell a dead lock from a credited one.
                    now_s.saturating_add(DEADLINE_RELEASE_MARGIN_SECS) >= e.lock_deadline
                })
                .map(|e| e.job_id)
                .collect()
        };
        for jid in near_margin {
            tracing::warn!(
                "drain: {} has no live lifecycle and reached the release margin — releasing it now",
                short_id(jid)
            );
            drain_released.insert(jid, std::time::Instant::now());
            let (c, st, jr) = (client.clone(), state.clone(), journal.clone());
            tokio::spawn(async move {
                release_and_clean(&c, &st, &jr, jid).await;
            });
        }
        // `Submitting` jobs are excluded from the ABANDON release list, so the DRAIN is
        // the ONLY stage that can still free their collateral — by letting the fulfil land
        // (or give up, stashing its nonce so the lifecycle's own release can displace it).
        // `Submitting` is set BEFORE `fulfill_job`, whose pre-broadcast nonce reserve / fee
        // read / status view are all paced by the global RPC throttle, so a ZERO supervised
        // budget `process::exit`s the fulfil before it ever reaches the wire — the job ends
        // up neither fulfilled NOR released, and an operator-initiated stop is not restarted
        // by the exit code either. Grant a small grace, but ONLY when every outstanding
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
            outstanding
                .iter()
                .map(|j| short_id(*j))
                .collect::<Vec<_>>()
                .join(", ")
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
        // The LOWER chain-time estimate: an entry is only treated as already past its deadline once
        // it surely is.
        let now = zkminer_chain::client::chain_now_floor();
        // Source of truth is the JOURNAL: it covers the claim window that `active_jobs`
        // misses. `Submitting` jobs are deliberately EXCLUDED — they already have a
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
        // Past their RECORDED deadline — but that record can be stale (a lock kept through a pause
        // has an effective deadline moved out by the pause). Re-checked below, after the live ones.
        let mut past_recorded: Vec<B256> = Vec::new();
        for (deadline, jid) in doomed {
            // Re-read the live status per job: `submitting` was snapshotted BEFORE this
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
                // Past its RECORDED deadline: `releaseJob` reverts if that is still true, but the
                // record can be stale — a pause or a Disabled window credits the lock, moving the
                // effective deadline out. Defer it until every live release has its nonce;
                // `release_and_clean` then re-reads the view and either releases (still live) or
                // retains the breadcrumb and drains the stash (truly past).
                past_recorded.push(jid);
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
            // `release_and_clean`, not the raw client call: it re-checks the on-chain
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
        // The past-recorded-deadline entries, AFTER every live release took its nonce. No
        // pre-reserved nonce: most turn out truly past and send nothing, and a pre-reserved nonce they
        // then recycle would sit as a hole below the live releases.
        for jid in past_recorded {
            if client.has_abandoned_nonce(jid) && !stash_frontier_synced {
                // Learn the mined frontier before anything recycles a stash: a past-deadline fulfil
                // that mined as a revert left its nonce consumed with no receipt seen. Bounded and
                // once per burst (see the release ordering note above).
                stash_frontier_synced = true;
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(1_500),
                    client.resync_nonce(),
                )
                .await;
            }
            tracing::warn!(
                "job {} is past its recorded lock deadline — re-checking the live (pause-credited) \
                 deadline before giving it up",
                short_id(jid)
            );
            let (c, st, jr) = (client.clone(), state.clone(), journal.clone());
            releasing.push((
                jid,
                tokio::spawn(async move {
                    release_and_clean(&c, &st, &jr, jid).await;
                }),
            ));
        }
        let release_txs_attempted = releasing.len();
        // BOUND the join. Each `release_and_clean` is up to 5 attempts x (120s receipt +
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
                tracing::warn!(
                    "release of job {} did not confirm within budget",
                    short_id(jid)
                );
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
        // Use `nonce_gap_safe_to_fill()`, not a plain "anything executable at the mined
        // frontier => don't heal" test. That coarser test would exclude the case this whole
        // block exists for: the skipped release leaves a hole ABOVE the frontier (our own
        // broadcast release is executable AT it), so the probe would say "busy" and we would
        // never heal, and the queued releases would ride to their lock deadlines.
        // `nonce_gap_safe_to_fill` keeps that protection — it still refuses to displace an
        // executable tx at the frontier — while allowing a hole above it, where by
        // construction there is nothing to displace.
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
        // `pending` reports only the LOWEST hole, and `heal_nonce_gap` fills one. With
        // two or more skipped releases — routine when several jobs are doomed — plugging the
        // first leaves the next one blocking every release above it, and we exit immediately
        // with nothing alive to notice. The live watchdog walks holes one per ~2 min, which is
        // fine for a running process and useless here. Loop, bounded: each pass is a handful
        // of RPCs plus (for an above-frontier fill) no receipt wait, so this stays well inside
        // the shutdown budget.
        const MAX_SHUTDOWN_HEALS: usize = 3;
        // Bound in TIME as well as passes: a frontier-hole pass can still consume the
        // full 30s HEAL_RECEIPT_BUDGET, and the shutdown budget is already 45s join + reap
        // against a 90s supervisor kill. Overrunning costs the worker reap (SP1's gpu-server
        // holds ~11.5 GB) and the exit-75 verdict — worse than an unfilled hole, which
        // recovery re-drives on the next start.
        const HEAL_LOOP_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);
        let heal_deadline = std::time::Instant::now() + HEAL_LOOP_BUDGET;
        let mut heal_target = heal_target;
        let mut healed = 0usize;
        while healed < MAX_SHUTDOWN_HEALS {
            // Fill the nonce the GATE approved. `heal_nonce_gap()` re-derives from the
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

        // Leave a machine-readable verdict and a NON-ZERO exit when anything is still
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
    // BOUNDED, for the same reason as the hard-kill reap: `shutdown_all` phase 4 takes a
    // BLOCKING slot lock while phases 2/3 skip any slot whose `pid` is momentarily 0 (the
    // dispatcher's respawn/recycle window), so it can block for a whole proof (up to the 600s
    // watchdog). On a SUPERVISED stop there is no third signal to reach the bounded copy, and
    // the exit code below is gated behind this call — an unbounded reap means the
    // supervisor SIGKILLs us before EX_TEMPFAIL is ever delivered and the sp1-gpu-server
    // grandchild keeps its VRAM anyway. Off-thread so it also can't block a runtime worker.
    {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            if let Some(pool) = zkminer_prover::engine::worker_pool() {
                tracing::info!("shutting down worker pool");
                pool.close();
            }
            let _ = done_tx.send(());
        });
        if tokio::time::timeout(std::time::Duration::from_secs(10), done_rx)
            .await
            .is_err()
        {
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
fn synthetic_conservative_benchmark(
    cards: &[(String, String)],
) -> zkminer_prover::benchmark::BenchmarkSuite {
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
    // One conservative device row per proving GPU, so the suite is conservative about COST
    // as well as speed. Without it `device_benchmarks` is empty, and an empty device list is
    // indistinguishable from a CPU-only machine: the cost model would charge 0 W of GPU and
    // price every job as if the cards were switched off. This suite is the DEFAULT path on a
    // headless fresh install (`skip_benchmark_gate` defaults true) and after any driver bump
    // that invalidates the cache, so that was not a corner case.
    //
    // `FALLBACK_GPU_WATTS` is deliberately high rather than measured: an unmeasured card
    // should look expensive, not free.
    //
    // The cards arrive as a PARAMETER rather than being read from the worker pool here. Reading
    // them here took a slot mutex that `prove_on_slot` holds for the whole proof, on a function
    // the brain calls every tick — which stalled all claiming for minutes and idled the second
    // GPU. (The parameter also makes this function testable, the pool being a process-global;
    // no test uses it yet.)
    // Ids from `gpu_cards`, NOT from a card's position in a list. Minting `gpu{i}` positionally
    // coincides with the real id only when cards are enumerated from zero with none missing — filter to
    // the second card and the synthetic row says `gpu0` while `slots_disabled_by` says `gpu1`, so the
    // operator's per-device toggle and the dispatcher's filter name different things and the toggle is
    // decorative again.
    let device_benchmarks = cards
        .iter()
        .map(
            |(device_id, bus)| zkminer_prover::benchmark::DeviceBenchmark {
                program_stages: Vec::new(),
                device_id: device_id.clone(),
                device_label: format!("{} (unbenchmarked)", device_id.to_uppercase()),
                prover_backend: "risc0".to_string(),
                throughput: throughput_cps,
                power_watts: zkminer_prover::benchmark::FALLBACK_GPU_WATTS,
                optimal_po2: 21,
                memory_usage_bytes: 0,
                max_feasible_po2: 21,
                program_throughputs: std::collections::HashMap::new(),
                pci_bus_id: bus.clone(),
                po2_samples: Vec::new(),
                // Unmeasured by construction: nothing has been benchmarked. Admission control treats
                // that as "assume a conservative cost", not as "assume it is free".
                host_peak_bytes: None,
            },
        )
        .collect();

    BenchmarkSuite {
        results: vec![
            program("fibonacci", 500_000, 0.10, false),
            program("sha256-chain", 2_000_000, 0.20, true),
            program("ecdsa-verify", 5_000_000, 0.25, true),
            program("bigint-mul", 1_000_000, 0.10, false),
            program("memory-merkle", 3_000_000, 0.15, true),
            program("chacha-mix", 34_000_000, 0.20, false),
        ],
        device_benchmarks,
        zkops: throughput_cps,
        cpu_info: SYNTHETIC_SUITE_CPU.to_string(),
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

/// Jobs whose card is free again, reported by their lifecycle tasks (`CardRelease`) and drained by
/// the brain, which stops counting them against card capacity: a job being fulfilled holds
/// collateral, not a GPU. `CARD_FREED` wakes the brain for it, so the card's next job is admitted
/// now instead of on the next 5 s tick.
static CARDS_FREED: std::sync::Mutex<Vec<B256>> = std::sync::Mutex::new(Vec::new());
static CARD_FREED: std::sync::LazyLock<tokio::sync::Notify> =
    std::sync::LazyLock::new(tokio::sync::Notify::new);

/// Held by a job's lifecycle from its start until its proving is over: dropped there explicitly, or
/// on any earlier return (a failed claim, a refused job, failed proving), all of which leave the job
/// with no further need for a card. Reported once.
struct CardRelease(Option<B256>);
impl CardRelease {
    fn release(&mut self) {
        if let Some(jid) = self.0.take() {
            CARDS_FREED
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(jid);
            CARD_FREED.notify_one();
        }
    }
}
impl Drop for CardRelease {
    fn drop(&mut self) {
        self.release();
    }
}

/// The block each held job's lock is known at (`ClaimReceipt::block`: its claim's receipt, or the
/// read that found it already ours), for telling a reservation the on-chain collateral figure counts
/// from one it does not yet. Pruned to the jobs held each brain pass.
static LOCK_BLOCKS: std::sync::Mutex<Option<HashMap<B256, u64>>> = std::sync::Mutex::new(None);

fn note_lock_block(job_id: B256, block: u64) {
    LOCK_BLOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(job_id, block);
}

fn lock_blocks() -> HashMap<B256, u64> {
    LOCK_BLOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_default()
}

/// Keep only the lock blocks of jobs still held.
fn prune_lock_blocks(held: &HashMap<B256, u128>) {
    if let Some(m) = LOCK_BLOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
    {
        m.retain(|j, _| held.contains_key(j));
    }
}

/// Whether a stake read at `read_block` already counts a lock known at `lock_block`: only when both
/// are known and the lock is no later. Anything else is treated as not yet counted.
fn lock_counted_on_chain(read_block: Option<u64>, lock_block: Option<u64>) -> bool {
    matches!((read_block, lock_block), (Some(read), Some(lock)) if lock <= read)
}

/// The reservations of held jobs whose locks a stake read at `read_block` does not count yet.
fn uncounted_reservations(
    held: &HashMap<B256, u128>,
    lock_blocks: &HashMap<B256, u64>,
    read_block: Option<u64>,
) -> u128 {
    held.iter()
        .filter(|(jid, _)| !lock_counted_on_chain(read_block, lock_blocks.get(*jid).copied()))
        .fold(0u128, |sum, (_, reserved)| sum.saturating_add(*reserved))
}

/// What each card has proved jobs at, learned from the jobs themselves: cycles over duration for
/// each `(device id, backend)`, smoothed. Without a benchmark suite the planner had only the
/// synthetic placeholder's 1.0 M cycles/s for every card, against 1.0-3.0 M measured on this
/// host's four, so it modelled every card as busy up to 3x longer than it was.
static OBSERVED_THROUGHPUT: std::sync::Mutex<Option<HashMap<(String, String), f64>>> =
    std::sync::Mutex::new(None);

/// Weight of the newest proof in `OBSERVED_THROUGHPUT`'s moving average.
const OBSERVED_THROUGHPUT_WEIGHT: f64 = 0.3;

/// Record a finished proof's rate for its card (`slot` as `backend:tag:index`).
fn note_observed_throughput(slot: &str, cycles: u64, duration: Duration) {
    let Some((key, rate)) = observed_rate(slot, cycles, duration) else {
        return;
    };
    let mut seen = OBSERVED_THROUGHPUT
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let entry = seen
        .get_or_insert_with(HashMap::new)
        .entry(key)
        .or_insert(rate);
    *entry += OBSERVED_THROUGHPUT_WEIGHT * (rate - *entry);
}

/// `((device id, backend), cycles per second)` for one proof, or `None` for a slot that is not a
/// card or a proof with nothing to measure.
fn observed_rate(slot: &str, cycles: u64, duration: Duration) -> Option<((String, String), f64)> {
    let mut parts = slot.splitn(3, ':');
    let (backend, tag, index) = (parts.next()?, parts.next()?, parts.next()?);
    if !matches!(tag, "cuda" | "rocm" | "intel") || cycles == 0 || duration.is_zero() {
        return None;
    }
    let device = zkminer_prover::dispatcher::WorkerPool::gpu_device_id(tag, index);
    Some((
        (device, backend.to_string()),
        cycles as f64 / duration.as_secs_f64(),
    ))
}

/// The learned rates, for the planner.
fn observed_throughputs() -> HashMap<(String, String), f64> {
    OBSERVED_THROUGHPUT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_default()
}

/// Planner rows `(device, backend, cycles/s)` with every `observed` rate in place of what the rows
/// said for that device and backend, and added where they had nothing (SP1, which the synthetic
/// suite has no rows for).
fn with_observed(
    mut rows: Vec<(String, String, f64)>,
    observed: &HashMap<(String, String), f64>,
) -> Vec<(String, String, f64)> {
    rows.retain(|(device, backend, _)| !observed.contains_key(&(device.clone(), backend.clone())));
    let mut learned: Vec<(String, String, f64)> = observed
        .iter()
        .filter(|(_, rate)| rate.is_finite() && **rate > 0.0)
        .map(|((device, backend), rate)| (device.clone(), backend.clone(), *rate))
        .collect();
    learned.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    rows.extend(learned);
    rows
}

/// How many of the jobs held (`in_flight`) still need a card: those whose proving is not over
/// (`proved`). Counted, not subtracted, so an entry `proved` keeps for a job no longer held cannot
/// make it read low or wrap.
fn needing_card(
    in_flight: &HashMap<B256, u128>,
    proved: &std::collections::HashSet<B256>,
) -> usize {
    in_flight.keys().filter(|j| !proved.contains(*j)).count()
}

/// One candidate's position at the admission step, for `AdmissionTally::note`.
struct Candidate<'a> {
    /// The evaluator would claim it (profit, risk and deadline).
    recommended: bool,
    /// Its cycles are measured, which every claim requires.
    measurable: bool,
    planner_active: bool,
    /// Every job still needing a card is in the planner's model; the planner is used only then.
    model_complete: bool,
    /// The planner admitted it.
    planned: bool,
    /// Why the planner did not, when it was asked.
    rejection: Option<&'a zkminer_strategy::queue::Rejection>,
    /// Without the planner, there is a card for it now.
    bypass_room: bool,
}

/// How a brain pass's candidates fared at admission: claimed by the planner or without it, or why
/// not. Each candidate that reaches the step is counted once, under its first reason.
#[derive(Default, Debug, PartialEq, Eq)]
struct AdmissionTally {
    reached: usize,
    planned: usize,
    bypassed: usize,
    not_recommended: usize,
    not_measured: usize,
    /// Planner on, but a job needing a card is outside its model (claimed without it, or recovered),
    /// so it is not asked, and without it nothing may be claimed either.
    model_incomplete: usize,
    horizon_full: usize,
    deadline: usize,
    no_device: usize,
    /// Planner off, and every card has its job.
    no_room: usize,
}

impl AdmissionTally {
    fn note(&mut self, c: Candidate<'_>) {
        use zkminer_strategy::queue::Rejection;
        self.reached += 1;
        let count = if !c.recommended {
            &mut self.not_recommended
        } else if !c.measurable {
            &mut self.not_measured
        } else if c.planned {
            &mut self.planned
        } else if c.planner_active && !c.model_complete {
            &mut self.model_incomplete
        } else if c.planner_active {
            match c.rejection {
                Some(Rejection::HorizonFull) => &mut self.horizon_full,
                Some(Rejection::DeadlineInfeasible) => &mut self.deadline,
                Some(Rejection::NoUsableDevice) | None => &mut self.no_device,
            }
        } else if c.bypass_room {
            &mut self.bypassed
        } else {
            &mut self.no_room
        };
        *count += 1;
    }
}

impl std::fmt::Display for AdmissionTally {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at admission", self.reached)?;
        for (n, what) in [
            (self.planned, "planned"),
            (self.bypassed, "claimed without the planner"),
            (self.not_recommended, "not recommended"),
            (self.not_measured, "not measured"),
            (self.model_incomplete, "planner skipped (model incomplete)"),
            (self.horizon_full, "horizon full"),
            (self.deadline, "deadline infeasible"),
            (self.no_device, "no usable device"),
            (self.no_room, "no free card"),
        ] {
            if n > 0 {
                write!(f, ", {n} {what}")?;
            }
        }
        Ok(())
    }
}

/// `cpu_info` of the synthetic placeholder suite (`synthetic_conservative_benchmark`), which is how
/// a suite read back from the shared state is told apart from a measured one.
const SYNTHETIC_SUITE_CPU: &str = "(unbenchmarked placeholder)";

fn is_synthetic_suite(suite: &zkminer_prover::benchmark::BenchmarkSuite) -> bool {
    suite.cpu_info == SYNTHETIC_SUITE_CPU
}

/// `f64::min`-fold helper: an empty fold yields INFINITY, which downstream would read as
/// "infinitely fast" rather than "unknown". Collapse any non-finite result to a caller-chosen
/// sentinel so the unknown case stays explicit.
trait FiniteOr {
    fn pipe_finite_or(self, fallback: f64) -> f64;
}
impl FiniteOr for f64 {
    fn pipe_finite_or(self, fallback: f64) -> f64 {
        if self.is_finite() {
            self
        } else {
            fallback
        }
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
/// Seconds of a proof's watchdog budget that do not scale with its cycles. SP1's proof ends in a
/// Groth16 wrap that costs the same for any job, ~25-50 s on its own, and with hemilabs `sp1` from
/// v6.8.1 it can also wait for the host-wide final-wrap slot while another card's wrap holds it. A
/// small job sat at the 90 s floor, which those alone could use up.
fn fixed_proving_allowance_secs(backend: &str) -> u64 {
    if backend == zkminer_prover_protocol::BACKEND_SP1 {
        120
    } else {
        0
    }
}

/// Seconds of a risc0 proof's budget for executing its guest, from how long the measuring execute
/// took. A proof executes the guest again before proving it and replays each segment's execution in
/// its preflight: about twice the measurement, and half again for a busier host. A guest can make
/// execution slow out of all proportion to its cycles (a bigint2 ecall's verify arithmetic, its
/// nondet program), which sizing on cycles alone misses: its proof was killed by the watchdog, or
/// claimed into a window it could not fit. 0 without a measurement, and for other backends.
fn execute_allowance_secs(backend: &str, measured_execute_secs: Option<u64>) -> u64 {
    if backend == zkminer_prover_protocol::BACKEND_RISC0 {
        measured_execute_secs.unwrap_or(0).saturating_mul(3)
    } else {
        0
    }
}

/// A risc0 proving slot that proves jobs, and the segment size (po2) it measures and proves them at.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Risc0Card {
    slot: String,
    /// The benchmark device id (`gpu0`): its calibration row and its Settings override are keyed by it.
    device: String,
    po2: u8,
}

/// The risc0 job size the operator set for each card, by device id: the config's, overridden by the
/// Settings screen's while Advanced mode is on (its rows are shown only then).
fn risc0_job_po2_overrides(rs: &zkminer_tui::state::RuntimeSettings) -> HashMap<String, u8> {
    let mut sizes = rs.risc0_job_po2_config.clone();
    if rs.advanced_mode {
        for ((device, backend), po2) in &rs.po2_overrides {
            if backend == zkminer_prover_protocol::BACKEND_RISC0 {
                sizes.insert(device.clone(), *po2);
            }
        }
    }
    sizes
}

/// Each risc0 slot's job segment size, as `(slot, device, size)`, `None` for a card that proves no job
/// (see `benchmark::risc0_job_po2`). `slots` is `WorkerPool::risc0_slots`; `overrides` is
/// [`risc0_job_po2_overrides`].
fn risc0_slot_sizes(
    slots: &[(String, String, Option<u64>)],
    suite: Option<&zkminer_prover::benchmark::BenchmarkSuite>,
    overrides: &HashMap<String, u8>,
) -> Vec<(String, String, Option<u8>)> {
    let risc0 = zkminer_prover_protocol::BACKEND_RISC0;
    slots
        .iter()
        .map(|(slot, device, vram)| {
            let row = suite.and_then(|s| {
                s.device_benchmarks
                    .iter()
                    .find(|d| d.device_id == *device && d.prover_backend == risc0)
            });
            let over = overrides.get(device).copied();
            let po2 = zkminer_prover::benchmark::risc0_job_po2(over, row, *vram);
            (slot.clone(), device.clone(), po2)
        })
        .collect()
}

/// The risc0 cards that prove jobs: each slot with a size, unless the operator switched it (or risc0)
/// off.
fn risc0_job_cards(
    sizes: &[(String, String, Option<u8>)],
    disabled_slots: &[String],
    risc0_disabled: bool,
) -> Vec<Risc0Card> {
    if risc0_disabled {
        return Vec::new();
    }
    sizes
        .iter()
        .filter(|(slot, _, _)| !disabled_slots.contains(slot))
        .filter_map(|(slot, device, po2)| {
            po2.map(|po2| Risc0Card {
                slot: slot.clone(),
                device: device.clone(),
                po2,
            })
        })
        .collect()
}

/// The distinct sizes of `cards`, ascending. A risc0 job is measured at every one before it is claimed,
/// and claimed only if it measures clean at all of them with one journal, since any of these cards may
/// prove it and a guest can tell the size it runs at. One card size, as on most rigs: one measurement.
fn risc0_job_sizes(cards: &[Risc0Card]) -> Vec<u8> {
    let mut sizes: Vec<u8> = cards.iter().map(|c| c.po2).collect();
    sizes.sort_unstable();
    sizes.dedup();
    sizes
}

/// The risc0 cards as they stand now, from what the brain reads each tick, for a caller outside it
/// (the prove step, the watch-only inspector). Switching risc0 off stops new claims only: `for_claims`
/// false (a job already claimed) ignores it, as the dispatcher always has.
async fn current_risc0_cards(
    state: &zkminer_tui::state::SharedState,
    for_claims: bool,
) -> Vec<Risc0Card> {
    let Some(pool) = zkminer_prover::engine::worker_pool() else {
        return Vec::new();
    };
    let st = state.read().await;
    let rs = &st.runtime_settings;
    let sizes = risc0_slot_sizes(
        &pool.risc0_slots(),
        st.benchmark_results.as_ref(),
        &risc0_job_po2_overrides(rs),
    );
    if !for_claims {
        // A claimed job's dispatch applies its own snapshot of the disabled cards.
        return risc0_job_cards(&sizes, &[], false);
    }
    let disabled = pool.slots_disabled_by(&rs.disabled_devices, &rs.disabled_device_backends);
    let off = rs
        .disabled_backends
        .contains(zkminer_prover_protocol::BACKEND_RISC0);
    risc0_job_cards(&sizes, &disabled, off)
}

/// The slots a claimed risc0 job measured at `measured` (sizes) may be proven on, each with the size to
/// prove it at, and whether those sizes are ones it measured at. On each card, the largest measured
/// size that fits it: its own size or below, since a smaller segment needs less of the card (its size
/// can have moved since the claim: a restart, a re-benchmark, Settings). With none recorded (a lock from
/// an earlier build, or found on chain with no breadcrumb) the guess is `RISC0_DEFAULT_JOB_PO2`, which
/// every earlier build measured at, but not as a measured size. When no card holds a measured size,
/// each proves the job at its own size, unmeasured: a guest can behave otherwise there, but only a
/// hostile one would. That can cost the GPU time of its attempts as well as the release it would
/// otherwise have had at once, but releasing costs an honest job a certain penalty.
fn risc0_prove_sizes(cards: &[Risc0Card], measured: &[u8]) -> (HashMap<String, u8>, bool) {
    let guess = [zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2];
    let sizes = if measured.is_empty() {
        &guess[..]
    } else {
        measured
    };
    let fitted: HashMap<String, u8> = cards
        .iter()
        .filter_map(|c| {
            let fits = sizes.iter().copied().filter(|&m| m <= c.po2).max()?;
            Some((c.slot.clone(), fits))
        })
        .collect();
    if !fitted.is_empty() {
        return (fitted, !measured.is_empty());
    }
    (
        cards.iter().map(|c| (c.slot.clone(), c.po2)).collect(),
        false,
    )
}

/// The executes one more job measuring `adding` sizes may start, with `executing` executes of its
/// backend in flight against `budget` (the measure workers): as many as are free, at least one, or
/// none when every worker is busy. A job runs one execute per size it still lacks, side by side; one
/// that finds no free worker comes back `MeasureSlotsBusy` and its size is measured on a later tick, so
/// a job is admitted whenever any worker is free, never held back for all its sizes at once (which a
/// stream of jobs lacking one size each would make wait for ever).
fn measure_admits(executing: usize, adding: usize, budget: usize) -> usize {
    if executing >= budget {
        0
    } else {
        adding.clamp(1, budget - executing)
    }
}

/// The conservative sizing floor for a risc0 job on a rig whose smallest card size is the least of
/// `sizes`: `CONSERVATIVE_SIZING_CPS` describes the default size, and each step below it is charged
/// `RISC0_PO2_STEP_DOWN_FACTOR`, as for a measured row.
fn risc0_conservative_cps(sizes: &[u8]) -> f64 {
    let below = sizes.iter().min().map_or(0, |s| {
        zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2.saturating_sub(*s)
    });
    CONSERVATIVE_SIZING_CPS
        * zkminer_prover::benchmark::RISC0_PO2_STEP_DOWN_FACTOR.powi(i32::from(below))
}

/// The per-attempt proving watchdog for a measured job of `cycles`: four times its time at the slower
/// of 400k cycles/s and `planning_cps` (the slowest card the claim was sized on: a risc0 card at a
/// small size proves below 400k, and a watchdog sized above it would kill every attempt), plus the
/// `fixed` allowances, at least 90 s more than those and at most `cap`.
fn prove_watchdog(cycles: u64, planning_cps: Option<f64>, fixed: u64, cap: Duration) -> Duration {
    const CONSERVATIVE_CPS: u64 = 400_000;
    const TIMEOUT_MARGIN: u64 = 4;
    const MIN_PROVING_TIMEOUT_SECS: u64 = 90;
    let cap = cap.as_secs();
    let cps = planning_cps
        .filter(|c| c.is_finite() && *c >= 1.0)
        .map_or(CONSERVATIVE_CPS, |c| (c as u64).min(CONSERVATIVE_CPS));
    let est = (cycles / cps * TIMEOUT_MARGIN).saturating_add(fixed);
    Duration::from_secs(est.clamp((MIN_PROVING_TIMEOUT_SECS + fixed).min(cap), cap))
}

/// Whether a job may be admitted without look-ahead: fewer jobs in flight than `max_concurrent`, and
/// for a risc0 job fewer risc0 jobs (all in flight but `other_backend` ones) than `risc0_cards`. A job
/// is admitted to start now, one per card, and automatic concurrency counts every GPU, so a card with
/// no risc0 size would otherwise queue a second risc0 job behind the first's card.
fn risc0_bypass_room(
    in_flight: usize,
    other_backend: usize,
    max_concurrent: usize,
    risc0_job: bool,
    risc0_cards: usize,
) -> bool {
    in_flight < max_concurrent
        && (!risc0_job || in_flight.saturating_sub(other_backend) < risc0_cards)
}

/// A risc0 card that proves jobs but has no usable row in `rows` (its benchmark failed at po2 20, or
/// the suite predates it) is still one a job can land on: give it the conservative floor for its size
/// (`risc0_conservative_cps`), so it is never left out of the sizing. CPU slots are not planned.
fn fill_risc0_rows(rows: &mut Vec<(String, String, f64)>, cards: &[Risc0Card]) {
    let risc0 = zkminer_prover_protocol::BACKEND_RISC0;
    for card in cards.iter().filter(|c| c.device.starts_with("gpu")) {
        let usable = rows
            .iter()
            .any(|(d, b, t)| *d == card.device && b == risc0 && t.is_finite() && *t > 0.0);
        if !usable {
            rows.retain(|(d, b, _)| !(*d == card.device && b == risc0));
            rows.push((
                card.device.clone(),
                risc0.to_string(),
                risc0_conservative_cps(&[card.po2]),
            ));
        }
    }
}

/// How long a claimed risc0 job with no card to take it waits before looking again, with `budget` of
/// proving budget left: `NO_RISC0_CARD_WAIT`, but never into the release margin (the prove loop
/// abandons below `MIN_ATTEMPT_BUDGET_SECS`), and at least a second.
fn no_card_wait(budget: Option<Duration>) -> Duration {
    budget.map_or(NO_RISC0_CARD_WAIT, |b| {
        b.saturating_sub(Duration::from_secs(MIN_ATTEMPT_BUDGET_SECS))
            .clamp(Duration::from_secs(1), NO_RISC0_CARD_WAIT)
    })
}

/// The slots the operator has switched off (Settings: a device, or a backend on a device).
async fn operator_disabled_slots(state: &zkminer_tui::state::SharedState) -> Vec<String> {
    let st = state.read().await;
    zkminer_prover::engine::worker_pool()
        .map(|p| {
            p.slots_disabled_by(
                &st.runtime_settings.disabled_devices,
                &st.runtime_settings.disabled_device_backends,
            )
        })
        .unwrap_or_default()
}

/// Whether a job of `backend` may be planned on benchmark device `device`: any device for another
/// backend, only a card in `cards` for risc0.
fn risc0_job_device(backend: &str, cards: &[Risc0Card], device: &str) -> bool {
    backend != zkminer_prover_protocol::BACKEND_RISC0 || cards.iter().any(|c| c.device == device)
}

/// Warms SP1 and risc0 up in the background, each until it succeeds (see `WorkerPool::warm_up`), so
/// that their one-time setup happens before their first proof rather than inside it: SP1 installs
/// its Groth16 circuit artifacts and, where its server supports it, builds the stripped circuit;
/// risc0 installs its `risc0-groth16` component where it is missing (a host with only its GPU driver
/// has no rzup to install it with). A failure (a network error, the host short of memory just then)
/// is retried, more patiently each time.
fn spawn_sp1_warmup() {
    use zkminer_prover_protocol::{BACKEND_RISC0, BACKEND_SP1};
    let Some(pool) = zkminer_prover::engine::worker_pool() else {
        return;
    };
    for (backend, name) in [(BACKEND_SP1, "SP1"), (BACKEND_RISC0, "risc0")] {
        if !pool.has_slots(backend) || pool.backend_warmed(backend) {
            continue;
        }
        let spawned = std::thread::Builder::new()
            .name(format!("{backend}-warmup"))
            .spawn(move || {
                let mut delay = Duration::from_secs(60);
                loop {
                    match pool.warm_up(backend, zkminer_prover::dispatcher::WARMUP_TIMEOUT) {
                        Ok(summary) => {
                            tracing::info!("{name} is ready: {summary}");
                            return;
                        }
                        Err(e) => {
                            tracing::warn!(
                                "{name}'s one-time setup failed, so {name} jobs are not claimed \
                                 yet; retrying in {delay:?}: {e:#}"
                            );
                            std::thread::sleep(delay);
                            delay = (delay * 2).min(Duration::from_secs(15 * 60));
                        }
                    }
                }
            });
        if let Err(e) = spawned {
            tracing::error!(
                "could not start {name}'s warm-up ({e}); {name} jobs will not be claimed"
            );
        }
    }
}

async fn miner_brain(
    client: ChainClient,
    state: zkminer_tui::state::SharedState,
    proving_timeout: Duration,
    // Startup snapshot of the COST COMPOSITION only. The three figures the Settings screen
    // edits — `min_profit_threshold`, `deadline_safety_margin`, `token_price_usd`, plus the
    // three inside `CostParams` — are deliberately NOT parameters: the loop re-reads them
    // from `state` every tick so an edit takes effect, and a startup copy sitting here would
    // be the exact trap that made them decorative in production.
    cost_params: CostParams,
    skip_benchmark_gate: bool,
    recovery_lookback: u64,
    journal: SharedJournal,
    // Startup value, for the banner only. The loop reads the LIVE setting each tick so the
    // settings screen can change it — do not use this for decisions.
    initial_queue_horizon: Duration,
) {
    // Journal is owned by `run()` so the shutdown path can read it. Recovery
    // reconciles the on-disk journal AND scans the chain for locked positions the
    // journal never captured (crash before write, cleared journal, other machine),
    // so it always runs — not only when the journal is non-empty.
    {
        let n = journal
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entries
            .len();
        if n > 0 {
            tracing::info!("Loaded job journal with {n} claimed entries");
        }
    }
    // Concurrency: run one job per detected GPU (bounded by max_concurrent_proofs).
    // `in_flight` maps each in-progress job to the collateral it committed on-chain,
    // so concurrent claims don't over-commit before stake_info next refreshes;
    // finished tasks report their job_id back on `done_rx`. Recovered locks hold a slot too
    // (with no collateral: theirs is already in the on-chain figures).
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<B256>();
    let mut in_flight: HashMap<B256, u128> = HashMap::new();
    // The jobs in `in_flight` known to be of a backend other than risc0, so the rest can be held to
    // the risc0 cards (see `risc0_bypass_room`). Pruned to `in_flight` each tick; a job of unknown backend (a
    // recovered lock) counts as risc0, the safe direction.
    let mut other_backend_in_flight: std::collections::HashSet<B256> =
        std::collections::HashSet::new();
    // The jobs in `in_flight` that are SP1, held to what the host can stage (`sp1_concurrent_capacity`).
    let mut sp1_in_flight: std::collections::HashSet<B256> = std::collections::HashSet::new();
    // The jobs in `in_flight` whose card is free again (`CardRelease`): proved, or never going to
    // prove. They still hold collateral until fulfilled or released, but not a GPU, so card capacity
    // (`max_concurrent`, the claim ceiling, the planner's model) counts `in_flight` less these.
    let mut proved: std::collections::HashSet<B256> = std::collections::HashSet::new();
    // Each claimed job's measured cycles and backend, for placing it in the planner's model when the
    // planner did not admit it (see the repair below).
    let mut inflight_work: HashMap<B256, (u64, &'static str)> = HashMap::new();

    // The recovery room checks judge locks against chain time: read a header first, so the startup
    // pass does not fall back to the bare wall clock.
    client.refresh_chain_time().await;
    // CAPTURE whether startup recovery deferred under a
    // storm (do NOT discard it): seeding the loop's `recovery_deferred` from it arms the
    // sooner-retry floor for a STARTUP-time deferral too — otherwise a miner that restarts
    // mid-storm holding a deadline-imminent, None-view lock would wait the full ~5-min
    // periodic cadence and could be slashed.
    let startup_pass = if watch_only() {
        // Locks this address holds belong to the miner that took them: a watch-only run neither
        // drives nor releases them, and has no signer nonces to heal.
        tracing::info!("watch-only: lock recovery and the nonce watchdog are off");
        RecoveryPass {
            deferred: false,
            actions: Vec::new(),
            scan: None,
        }
    } else {
        recover_claimed_jobs(
            &client,
            &journal,
            recovery_lookback,
            &std::collections::HashSet::new(),
            None,
        )
        .await
    };
    let mut recovery_deferred = startup_pass.deferred;
    let mut recovery_scan = startup_pass.scan;
    spawn_recovery_actions(
        startup_pass.actions,
        &mut in_flight,
        &client,
        &state,
        &journal,
        &done_tx,
        proving_timeout,
    );

    // Per-proof-system adapter cache. Populated lazily; adapter parameters change
    // rarely, so a best-effort cache that never expires is acceptable. Repopulate
    // on miner restart.
    let mut adapter_cache: HashMap<alloy::primitives::B256, AdapterInfo> = HashMap::new();
    // Throttle for the "skipping all jobs — insufficient collateral" warning:
    // the brain re-evaluates every 5s, so warn at most once per COLLATERAL_WARN_EVERY.
    let mut last_collateral_warn: Option<std::time::Instant> = None;
    // 429-aware claiming: when the RPC is actively rate-limiting, pause
    // claiming NEW jobs (in-flight prove/fulfill keep going). Throttled warn.
    let rpc_meter = client.rpc_meter();
    let mut last_rpc_backoff_warn: Option<std::time::Instant> = None;
    // When the log last said that no card here proves risc0 jobs.
    let mut last_no_risc0_card_warn: Option<std::time::Instant> = None;
    // Escalating claim-pause. Repeated storm EPISODES widen the quiet period required
    // before claims resume (30→60→120s) so the miner doesn't jump back in the instant the
    // base window lapses and immediately re-trigger the storm. Decays after CLAIM_BACKOFF_DECAY
    // of quiet or on any successful claim.
    let mut claim_backoff_mult: u32 = 1; // effective window = RPC_BACKOFF_WINDOW * mult (cap 4)
    // Last router/Registry pause read (handoff §11) and when it was taken; polled at most every
    // PAUSE_POLL_EVERY so a pause stops NEW claims within ~30 s without an RPC per tick.
    let mut pause_seen: Option<(std::time::Instant, bool)> = None;
    // When the ETH funds gate last re-quoted fees for itself.
    let mut last_fee_quote: Option<std::time::Instant> = None;
    // Whether the clock-skew claim gate is closed (to log its opening and closing once), and when it
    // last re-read a header to confirm a large skew.
    let mut clock_skew_held = false;
    let mut last_skew_reread: Option<std::time::Instant> = None;
    // Where the rotating quarter of the per-tick candidate cut resumes.
    let mut candidate_rotation: usize = 0;
    let mut last_storm_seen: Option<std::time::Instant> = None;

    // Wait for benchmarks and initial state to settle.
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Periodic recovery cadence. Startup recovery runs exactly once, so a job that
    // becomes held-but-undriven LATER in the session (a release whose RPC failed, a lock handed
    // back on a pause or an unreadable state, a lagging-read drop) would strand to a keeper slash
    // with no restart. We re-run recovery on a timer — busy or not: the pass skips the jobs a live
    // task owns, and it spawns its re-drives rather than running them inline.
    // All of these cadences are WALL-CLOCK, not tick counts: a brain iteration can take far longer
    // than its 5-s tick (a large Open set, a slow RPC), and a lock waiting on a recovery pass must not
    // wait in proportion to that.
    const RECOVERY_EVERY: Duration = Duration::from_secs(300);
    // A handed-back lock (or a pause lift) asks for a pass sooner, but not more often than this.
    const RECOVERY_REQUEST_FLOOR: Duration = Duration::from_secs(30);
    // Full proof-system re-verification cadence (adapter swap / disable / un-disable).
    const PROOF_SYSTEM_RECHECK: Duration = Duration::from_secs(300);
                                          // When a recovery pass DEFERS work under a rate-limit storm, retry on this
                                          // much shorter floor instead of waiting the full idle cadence — so a None-view job with
                                          // an imminent deadline gets reconciled/released as soon as the storm eases, not up to
                                          // ~5 min later. Floored so it can't hammer a still-storming endpoint every tick.
    const RECOVERY_DEFERRED_RETRY: Duration = Duration::from_secs(30);
    let mut tick_count: u64 = 0;
    let mut pages_shown: std::collections::HashMap<String, std::time::Instant> =
        std::collections::HashMap::new();
    // Last host-memory pressure state reported to the ACTIVITY LOG, so the operator is told on each
    // transition rather than once per tick. `None` until the first classification, so the first
    // non-Ok state is always announced.
    let mut last_pressure_logged: Option<zkminer_prover::memory::PressureState> = None;
    // Whether the synthetic fallback suite has been published to the TUI yet. Once only: a real
    // benchmark must be free to replace it, and re-publishing every tick would clobber that.
    let mut synthetic_published = false;
    // `recovery_deferred` is seeded above from the startup pass. Count consecutive deferrals
    // to BACK OFF the retry floor (6→12→24→48 ticks) so a long-lived storm is not re-scanned
    // (find_locked_jobs getLogs + batch views run at the top of every pass, uncapped by the
    // per-job single-shot probe) every 30s — decaying toward, but never past, the periodic
    // cadence. Resets the instant a pass completes without deferring.
    let mut consecutive_defers: u32 = recovery_deferred as u32;
    let mut last_recovery_at = std::time::Instant::now();
    let mut last_wedge_probe_at = std::time::Instant::now();
    let mut last_reverify_at = std::time::Instant::now();
    let mut last_deployment_check_at = std::time::Instant::now();

    // Nonce-gap watchdog. A hole at the mined frontier (an evicted
    // external tx, or a below-`next` abort-gap no organic reserve refilled) leaves our
    // higher-nonce txs queued forever with NO error surfaced — a total signer wedge that
    // neither resync nor reserve can heal. Every WEDGE_CHECK_TICKS we probe for the gap;
    // only when the SAME gap PERSISTS across two probes (so a transient reserved-but-unsent
    // nonce isn't mistaken for a hole) do we fill it with a self-transfer.
    const WEDGE_CHECK_TICKS: u64 = 12; // log throttle (iterations)
    const WEDGE_PROBE_EVERY: Duration = Duration::from_secs(60);
    /// A nominated hole must survive at least this long in WALL CLOCK before it is filled.
    const WEDGE_MIN_PERSIST: std::time::Duration = std::time::Duration::from_secs(45);
    // (nonce, when it was FIRST seen) — see the WEDGE_MIN_PERSIST gate below.
    let mut last_gap: Option<(u64, std::time::Instant)> = None;
    // Per-device backlog, so look-ahead admission can ask "when would this job
    // actually START" instead of assuming now. Self-correcting: entries decay with the wall
    // clock and are dropped on completion, so a wrong estimate cannot accumulate.
    // (programId, keccak256(inputData)) -> MEASURED cycle count, from executing the guest.
    //
    // Keyed on the pair (program, input) because the cycle count is a deterministic
    // function of EXACTLY those two. Keying by programId alone under-sized an
    // input-varying flood — one cheap measurement of a program was reused for every later job of it,
    // including inputs that run billions of cycles. Keying by the descriptor hash alone
    // let a tag-varying flood dodge the cache, since the free-form `tag` is in the descriptor
    // hash but not the input. The pair defeats both: a new tag with the same input resolves to the
    // existing measurement (via `desc_input_hash` below), and a genuinely new input is measured on
    // its own merits. `UNMEASURABLE_CYCLES` is stored for a guest that tripped the execute cap,
    // negative-caching it as infeasible so it is never claimed and never re-measured.
    //
    // This exists because `expectedCycles` is submitter-declared, adversarial, and in practice
    // always zero, leaving a 34e6 constant ~8x below the measured median.
    // Measuring it ourselves is the only trustworthy source, and a job is NOT claimed until
    // we hold a measurement for its exact (program, input) — see `measurable` and the claim gate.
    // Shared so the background measurement task below can populate it while the brain runs.
    // One merged cache of [`Measured`] results: cycle count AND the execute's peak host RSS live in
    // ONE value per (backend, program, input) so they co-evict (finding C-8) — a surviving cycle count
    // always carries its own peak, closing the desync where an evicted peak let the H1 claim gate read
    // 0 ("unknown, do not gate") for a job whose execute would OOM beside the warm server. The peak is
    // read at the claim gate (finding H1) and threaded into the prove reservation (finding RH2); 0 /
    // absent = "unknown" (older worker, off-Linux, portable executor) = do not block.
    let measured_cycles: MeasuredCache =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    // descriptor hash -> keccak256(inputData). Lets a brain tick resolve a sighting's
    // input hash (and hence its measurement) WITHOUT re-fetching the descriptor for every candidate:
    // it is learned once, when the measurement task fetches the descriptor, and reused for every
    // later sighting of the same descriptor. A new tag is a new descriptor hash, so a miss here until
    // its (cheap, cached) descriptor fetch records it — never an under-size, because a miss blocks the
    // claim rather than falling back to the declared count.
    let desc_input_hash: DescInputCache =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    // Descriptor hashes already being measured, so N sightings of the same job spawn ONE measuring
    // task. Maps dh -> (backend_tag, executes admitted for it: see `measure_admits`) so the measure
    // budget below can be counted PER-BACKEND (one backend's in-flight measurement must not consume
    // the slot the other backend needs) in executes; dedup is still global by descriptor hash (a dh is
    // unique to one job).
    let measuring: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<alloy::primitives::B256, (u8, usize)>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    // (backend, program, input) triples with an execution IN FLIGHT. The `measuring` set
    // above dedups by DESCRIPTOR hash, but the measured cache keys by (backend, program, input): a
    // concurrent burst of the SAME input under many distinct tags is many distinct descriptor hashes,
    // which would all pass `measuring`, all see an empty cache, and all execute the identical heavy
    // input at once. This set collapses that to one execution per (backend, program, input).
    let measuring_inputs: std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashSet<(u8, alloy::primitives::B256, alloy::primitives::B256)>,
        >,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    // consecutive wall-clock measure-timeout strikes per (backend, program, input), so a
    // single transient timeout does not permanently blacklist a feasible job (see `measure_cycles`).
    let measure_strikes: MeasureStrikes =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    // (Over-cap fulfill-payload verdicts now live as the `over_cap` bit on each descriptor's DescInfo
    // resolver entry in `desc_input_hash`, so the verdict and the resolver evict together — see
    // `DescInfo` / `measure_cycles`.)
    // Journal length per (backend, program, input), cached when a measurement executes so a later
    // descriptor for the same pair (which reuses the cached cycle count without re-executing) can
    // still have its full fulfill payload checked and, if over the cap, flagged on its resolver entry.
    let measured_journal: JournalLenCache =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    // descriptor hash -> its payload length (inputData + the two extra-data fields), cached during
    // measurement so the claim gate can re-check a descriptor's full fulfill payload against the cap
    // even when that descriptor's own measure task returned before any journal existed (the
    // measuring_inputs race loser), which otherwise escaped both payload screens (see `DescPayloadCache`).
    let desc_payload: DescPayloadCache =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    // descriptor hash -> cooldown Instant for a job the submitter assigned to another prover, so a
    // flood of such jobs cannot re-consume the per-tick measure budget (see `AssignedElsewhere`).
    let assigned_elsewhere: AssignedElsewhere =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    if watch_only() {
        tokio::spawn(watch_inspector(
            client.clone(),
            state.clone(),
            // Caches of its own, the in-flight sets included: the brain measures only what it would
            // claim, on its own budget and schedule, and decides on its own measurements; sharing
            // any of them would make watch-only report claims, or delays, a miner would not have.
            // A guest the two both want runs twice.
            WatchCaches {
                measured: Default::default(),
                desc_input: Default::default(),
                measuring: Default::default(),
                measuring_inputs: Default::default(),
                measure_strikes: Default::default(),
                measured_journal: Default::default(),
                desc_payload: Default::default(),
                assigned_elsewhere: Default::default(),
            },
        ));
    }
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
    // The proving cards, read ONCE. Static after `init_worker_pool`, and reading them per tick
    // used to take a slot mutex that `prove_on_slot` holds for the whole proof.
    // `(device id, bus id)` per card, addressed the way the Settings toggles and `slots_disabled_by`
    // address them. Used to build the synthetic fallback suite so its ids are the real ones.
    let proving_cards: Vec<(String, String)> = zkminer_prover::engine::worker_pool()
        .map(|p| p.gpu_cards())
        .unwrap_or_default();

    // Headless-visible measure-pool health. A backend with a dedicated measure pool (sp1) can no
    // longer SIZE a not-yet-measured job — and so can no longer CLAIM one — if every pool worker is
    // dead and not revivable, yet `is_backend_healthy` stays green off the (still-alive) GPU prove
    // slot. (Already-measured jobs still claim and prove normally — they need no measure capacity;
    // only new/unmeasured jobs stall.) `worker_status` is a one-shot startup snapshot consumed only by
    // the TUI, so a runtime retirement is invisible to a HEADLESS operator (the primary deployment).
    // Emit a log on the live→down transition (and on recovery) so the outage reaches journald.
    // Per-backend last-known state so each tick only logs a CHANGE, never a per-tick spam. (Liveness,
    // not idleness: a BUSY or briefly-respawning pool is still live.)
    let mut measure_pool_down: std::collections::HashMap<&'static str, bool> =
        std::collections::HashMap::new();

    // When the last pass began: a pass a freed card triggers waits out the rest of
    // `MIN_EARLY_PASS_SPACING` after it, so a burst of finishing jobs cannot spin the brain.
    let mut last_pass = std::time::Instant::now();
    loop {
        // Every `interval` tick, or as soon as a job hands back its card. `tick_count` counts the
        // ticks only: the periodic work keyed on it keeps its 5 s cadence.
        let ticked = tokio::select! {
            _ = interval.tick() => true,
            _ = CARD_FREED.notified() => false,
        };
        if ticked {
            tick_count = tick_count.wrapping_add(1);
        } else if let Some(rest) = MIN_EARLY_PASS_SPACING.checked_sub(last_pass.elapsed()) {
            tokio::time::sleep(rest).await;
        }
        last_pass = std::time::Instant::now();
        // PAGE lines logged since the last tick (only collected in TUI mode, where the log file is
        // all the operator would otherwise see of them), each shown again at most every 10 minutes.
        for msg in take_pages() {
            let now = std::time::Instant::now();
            if pages_shown
                .get(&msg)
                .is_none_or(|t| now.duration_since(*t) >= Duration::from_secs(600))
            {
                if pages_shown.len() >= 256 {
                    pages_shown.clear();
                }
                pages_shown.insert(msg.clone(), now);
                state
                    .write()
                    .await
                    .add_log(LogLevel::Error, zkminer_chain::programs::sanitize_log(&msg));
            }
        }

        // Surface measure-pool unavailability to headless logs (see `measure_pool_down`).
        if let Some(pool) = zkminer_prover::engine::worker_pool() {
            for backend in ["sp1"] {
                if let Some(live) = pool.measure_pool_live(backend) {
                    let down = !live;
                    let was_down = measure_pool_down.get(backend).copied().unwrap_or(false);
                    if down && !was_down {
                        tracing::warn!(
                            "{backend} measure pool is DOWN — every measure worker is dead and not \
                             revivable; new/unmeasured {backend} jobs cannot be sized or claimed until \
                             it recovers (already-measured jobs still claim and prove normally). Check \
                             the measure-worker binary and logs.",
                        );
                    } else if !down && was_down {
                        tracing::info!("{backend} measure pool recovered — sizing/claiming resumes.");
                    }
                    measure_pool_down.insert(backend, down);
                }
            }
        }

        // Reap finished job tasks before re-evaluating the concurrency budget.
        while let Ok(jid) = done_rx.try_recv() {
            in_flight.remove(&jid);
            proved.remove(&jid);
            inflight_work.remove(&jid);
            queue_model.settle(&jid.0);
        }
        // And jobs done with their card: no longer a card's work, in the budget or in the model.
        for jid in std::mem::take(&mut *CARDS_FREED.lock().unwrap_or_else(|e| e.into_inner())) {
            if in_flight.contains_key(&jid) && proved.insert(jid) {
                queue_model.settle(&jid.0);
            }
        }
        // Only jobs still held. Every path that reaps one removes it here too, but an entry left
        // behind would read as one card fewer needed for as long as the miner ran: it did, from a
        // recovery pass's own reap, and the planner's model then never matched again.
        proved.retain(|j| in_flight.contains_key(j));
        inflight_work.retain(|j, _| in_flight.contains_key(j));
        prune_lock_blocks(&in_flight);
        {
            // Advance the backlog model by real elapsed time, not by tick count: the brain
            // loop awaits `recover_claimed_jobs` inline and can stall for minutes, and a
            // count-based decay would leave stale work blocking a device that is long idle.
            let now = std::time::Instant::now();
            queue_model.tick(now.duration_since(queue_last_tick));
            queue_last_tick = now;
        }

        // Nonce-gap watchdog (persistence-gated).
        // Not during shutdown. The ABANDON stage guards its own heal with
        // `frontier_has_executable_tx` precisely because a heal bids >= 4x base and would
        // replace our own still-mineable releaseJob with a 0-value self-transfer — stranding
        // exactly the nearest-deadline job it was trying to save. That guard was applied to
        // one of the two heal call sites; this is the other one, and the brain deliberately
        // keeps running through the drain, so it can fire mid-abandon. The abandon stage does
        // its own guarded heal, so skipping here loses nothing.
        if last_wedge_probe_at.elapsed() >= WEDGE_PROBE_EVERY
            && !SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst)
            && !watch_only()
        {
            last_wedge_probe_at = std::time::Instant::now();
            // Persist on ELAPSED TIME, not on two sightings.
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
            // finally mined -- the "nonce too low" send that would trigger a resync no
            // longer happens. Without this probe, a jam self-heals only if some
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
                        // Same hole, and it has genuinely persisted → fill THIS nonce.
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

        // Re-verify the served proof system periodically (handoff §11: an adapter can be disabled,
        // swapped by `executePendingReactivation`, or re-enabled during a run). Claims follow the
        // latest verdict; locks already held are driven either way.
        // The deployment on its own cadence (it is ~30 reads): every PROOF_SYSTEM_RECHECK while it
        // verifies, every DEPLOYMENT_RETRY while it doesn't. Not while stopping: the abandon releases
        // need the RPC budget more.
        let deployment_ok = DEPLOYMENT_VERIFIED.load(std::sync::atomic::Ordering::SeqCst);
        if !SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst)
            && last_deployment_check_at.elapsed()
                >= if deployment_ok {
                    PROOF_SYSTEM_RECHECK
                } else {
                    DEPLOYMENT_RETRY
                }
        {
            last_deployment_check_at = std::time::Instant::now();
            let msg = match reverify_deployment(&client).await {
                Ok(_) if !deployment_ok => Some((
                    LogLevel::Warn,
                    "deployment verified again — claiming can resume".to_string(),
                )),
                Err(e) if deployment_ok && !DEPLOYMENT_VERIFIED.load(std::sync::atomic::Ordering::SeqCst) => {
                    Some((
                        LogLevel::Error,
                        format!(
                            "PAGE: the deployment no longer verifies ({e:#}) — not claiming new jobs; \
                             held locks are still driven. Re-checked every {}s.",
                            DEPLOYMENT_RETRY.as_secs()
                        ),
                    ))
                }
                Err(e) => {
                    tracing::debug!("deployment re-check: {e:#}");
                    None
                }
                _ => None,
            };
            if let Some((level, msg)) = msg {
                // A PAGE reaches the dashboard through the log (`take_pages`); the rest directly.
                if level == LogLevel::Error {
                    tracing::error!("{msg}");
                } else {
                    tracing::warn!("{msg}");
                    state.write().await.add_log(level, msg);
                }
            }
        }
        if !SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst)
            && (last_reverify_at.elapsed() >= PROOF_SYSTEM_RECHECK
                || ((!risc0_adapter_verified() || !sp1_adapter_verified())
                    && last_reverify_at.elapsed() >= RECOVERY_REQUEST_FLOOR))
        {
            last_reverify_at = std::time::Instant::now();
            let was_sp1 = sp1_adapter_verified();
            match reverify_sp1(&client).await {
                Ok(adapter) if !was_sp1 => {
                    let msg = format!(
                        "sp1.groth16.v1 verified (adapter {adapter}) — SP1 jobs can be claimed"
                    );
                    tracing::warn!("{msg}");
                    state.write().await.add_log(LogLevel::Warn, msg);
                }
                Err(e) if was_sp1 && !sp1_adapter_verified() => tracing::error!(
                    "PAGE: sp1.groth16.v1 no longer verifies ({e:#}) — not claiming SP1 jobs; held \
                     locks are still driven"
                ),
                Err(e) => tracing::debug!("sp1.groth16.v1 re-check: {e:#}"),
                _ => {}
            }
            let was = risc0_adapter_verified();
            let msg = match reverify_risc0(&client).await {
                Ok(adapter) if !was => Some((
                    LogLevel::Warn,
                    format!("risczero.groth16.v1 verified again (adapter {adapter}) — claiming can resume"),
                )),
                Err(e) if was && !risc0_adapter_verified() => Some((
                    LogLevel::Error,
                    format!(
                        "PAGE: risczero.groth16.v1 no longer verifies ({e:#}) — not claiming risc0 jobs; \
                         held locks are still driven"
                    ),
                )),
                Err(e) => {
                    tracing::debug!("risczero.groth16.v1 re-check: {e:#}");
                    None
                }
                _ => None,
            };
            if let Some((level, msg)) = msg {
                // A PAGE reaches the dashboard through the log (`take_pages`); the rest directly.
                if level == LogLevel::Error {
                    tracing::error!("{msg}");
                } else {
                    tracing::warn!("{msg}");
                    state.write().await.add_log(level, msg);
                }
            }
        }

        // Periodic recovery — BUSY OR NOT. It skips every job a live lifecycle task owns
        // (`in_flight`), so it never double-drives one, and it SPAWNS its re-drives as slot-holding
        // tasks instead of awaiting them inline, so the brain keeps running. (It used to require an
        // idle miner, which a busy miner — or a submitter feeding it cheap jobs — never is: a lock
        // kept through a pause, or handed back on an unreadable state, then rode to a slash.)
        // find_locked_jobs re-discovers anything we still hold on-chain, so even a job dropped from
        // the journal by an earlier lagging read is re-driven here.
        // Run on the periodic cadence; SOONER when a lock was handed back or a pause lifted
        // (`RECOVERY_REQUESTED`), or when a previous pass deferred work.
        let since = last_recovery_at.elapsed();
        let due_periodic = since >= RECOVERY_EVERY;
        // Back-off floor: base << (consecutive_defers-1), capped at 8x (~4 min).
        let retry_floor =
            RECOVERY_DEFERRED_RETRY * (1u32 << consecutive_defers.saturating_sub(1).min(3));
        let due_deferred = recovery_deferred && since >= retry_floor;
        let due_requested = RECOVERY_REQUESTED.load(std::sync::atomic::Ordering::SeqCst)
            && since >= RECOVERY_REQUEST_FLOOR;
        if !watch_only() && (due_periodic || due_deferred || due_requested) {
            // Gate on ON-CHAIN LOCKED COLLATERAL, not the journal — but read its FRESHNESS
            // too. A 429 storm FREEZES stake_info: the refresh circuit-breaker
            // skips, and a forced ceiling attempt that itself 429s updates nothing — so a
            // `locked==0` from a STALE snapshot is NOT authoritative and must not veto a scan
            // (else a job locked just before the storm, whose stake_info still reads 0,
            // strands to a keeper slash). Scan when: a deferred-retry is pending (find_locked_jobs
            // is the authoritative chain scan, self-limited by the deferred-retry backoff) OR we KNOW we hold
            // collateral OR we CAN'T tell (stale read). Only a FRESH read of locked==0 skips.
            let (locked, stake_fresh) = {
                let s = state.read().await;
                let locked = s
                    .stake_info
                    .as_ref()
                    .map(|si| si.locked_collateral)
                    .unwrap_or(0);
                let fresh = s.last_refresh.is_some_and(|t| {
                    (chrono::Utc::now() - t)
                        .to_std()
                        .is_ok_and(|d| d < REFRESH_STALENESS_CEILING)
                });
                (locked, fresh)
            };
            // A breadcrumb no live task owns (a handed-back or kept lock, a failed release) is
            // reason enough to scan, whatever the stake snapshot says.
            let orphaned_breadcrumbs = {
                let j = journal.lock().unwrap_or_else(|p| p.into_inner());
                j.entries.keys().any(|k| !in_flight.contains_key(k))
            };
            if due_deferred || due_requested || orphaned_breadcrumbs || locked > 0 || !stake_fresh {
                tracing::debug!(
                    "recovery pass ({} in flight, {} locked{}, {tick_count} ticks{})",
                    in_flight.len(),
                    fmt_hemi(locked),
                    if stake_fresh {
                        ""
                    } else {
                        " [stale — scanning to be safe]"
                    },
                    if due_requested {
                        ", requested"
                    } else if due_deferred && !due_periodic {
                        ", deferred-retry"
                    } else {
                        ""
                    }
                );
                last_recovery_at = std::time::Instant::now();
                RECOVERY_REQUESTED.store(false, std::sync::atomic::Ordering::SeqCst);
                // Do not START a new recovery pass once shutdown has begun: the abandon path owns
                // the remaining breadcrumbs then.
                // Gate on SHUTTING_DOWN, not `paused`: `paused` is also the TUI's operator
                // pause toggle, and recovery is the ONLY thing that still releases a job whose
                // earlier release failed on RPC (its breadcrumb is retained but it is gone from
                // `active_jobs`). Keying this on `paused` let a routine operator pause silently
                // disable that rescue until the lock deadline passed.
                if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
                    tracing::info!("recovery skipped — shutting down");
                    recovery_deferred = false;
                } else {
                    // Reap first: a task that handed its lock back while this tick awaited RPCs must
                    // not count as live, or the pass skips the very job the request was for.
                    while let Ok(jid) = done_rx.try_recv() {
                        in_flight.remove(&jid);
                        proved.remove(&jid);
                        inflight_work.remove(&jid);
                        queue_model.settle(&jid.0);
                    }
                    let owned: std::collections::HashSet<B256> = in_flight.keys().copied().collect();
                    let pass = recover_claimed_jobs(
                        &client,
                        &journal,
                        recovery_lookback,
                        &owned,
                        recovery_scan.take(),
                    )
                    .await;
                    recovery_deferred = pass.deferred;
                    recovery_scan = pass.scan;
                    // Reap tasks that finished DURING the pass first, so a lock whose task just
                    // ended can be picked up again.
                    let mut rearm = false;
                    while let Ok(jid) = done_rx.try_recv() {
                        in_flight.remove(&jid);
                        proved.remove(&jid);
                        inflight_work.remove(&jid);
                        queue_model.settle(&jid.0);
                        // Ended during the pass, after `owned` was taken: the pass skipped it.
                        rearm |= journal_has(&journal, jid);
                    }
                    if rearm {
                        request_recovery();
                    }
                    spawn_recovery_actions(
                        pass.actions,
                        &mut in_flight,
                        &client,
                        &state,
                        &journal,
                        &done_tx,
                        proving_timeout,
                    );
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
                // an already-proven deferral.) The periodic clock restarts from here.
                recovery_deferred = false;
                consecutive_defers = 0;
                last_recovery_at = std::time::Instant::now();
            }
        }

        let (
            paused,
            open_jobs,
            max_concurrent,
            queue_horizon,
            benchmarks,
            stake_info,
            risc0_overrides,
        ) = {
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
                risc0_job_po2_overrides(&s.runtime_settings),
            )
        };

        // Each risc0 card's job size (see `risc0_job_po2`), published for the Settings screen before
        // anything below can skip the tick, so it never shows a stale or guessed size.
        let risc0_slot_sizes_now = zkminer_prover::engine::worker_pool()
            .map(|p| risc0_slot_sizes(&p.risc0_slots(), benchmarks.as_ref(), &risc0_overrides))
            .unwrap_or_default();
        {
            let shown: Vec<(String, Option<u8>)> = risc0_slot_sizes_now
                .iter()
                .map(|(_, device, po2)| (device.clone(), *po2))
                .collect();
            if state.read().await.risc0_job_po2s != shown {
                // Said whenever it changes, for an operator without the Settings screen, with any
                // configured size that names no card here (a typo, or a card id in upper case).
                let listed: Vec<String> = shown
                    .iter()
                    .map(|(device, po2)| match po2 {
                        Some(p) => format!("{device} po2 {p}"),
                        None => format!("{device} none"),
                    })
                    .collect();
                tracing::info!("risc0 job sizes: {}", listed.join(", "));
                let configured: Vec<String> = state
                    .read()
                    .await
                    .runtime_settings
                    .risc0_job_po2_config
                    .keys()
                    .filter(|d| !shown.iter().any(|(s, _)| s == *d))
                    .cloned()
                    .collect();
                if !shown.is_empty() && !configured.is_empty() {
                    tracing::warn!(
                        "prover.risc0_job_po2 sets a size for {configured:?}, which name no risc0 \
                         card here (the cards are {:?})",
                        shown.iter().map(|(d, _)| d).collect::<Vec<_>>()
                    );
                }
                state.write().await.risc0_job_po2s = shown;
            }
        }

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
        // version, and a mismatch discards it.
        //
        // The synthetic fallback DOES now carry one device row per detected card — added so the
        // cost model stops pricing an unbenchmarked GPU box at 0 W of GPU — but those rows carry
        // a FABRICATED throughput. They must not satisfy this gate: the planner would then model
        // a queue against a number nothing measured. Hence the explicit `measured` flag rather
        // than inspecting the rows.
        //
        // `.any(gpu)` and not `!is_empty()`: the suite on this rig has three cpu rows, which
        // the slot builder drops.
        // `measured` distinguishes a REAL suite from the synthetic fallback substituted further
        // down. Named explicitly because the planner's correctness depends on it and that
        // dependency was previously an accident of ordering: this gate happens to run before the
        // substitution, so it never saw the fabricated rows. Moving either one would have turned
        // the planner on against numbers nothing measured.
        // Read the operator's cost levers LIVE, like `max_concurrent_proofs` above. The startup
        // snapshot meant the Settings screen's "System Overhead", electricity price and gas
        // estimate were decorative in production — editable, saved, and never read again — while
        // mock mode honoured them. Only the three cost inputs; the composition itself is the
        // evaluator's.
        let (cost_params, min_profit_threshold, deadline_safety_margin, token_price_usd) = {
            let s = state.read().await;
            (
                CostParams {
                    electricity_cost_kwh: s.runtime_settings.electricity_cost_kwh,
                    base_overhead_watts: s.runtime_settings.system_power_watts,
                    gas_cost_usd: s.runtime_settings.gas_cost_usd,
                    ..cost_params.clone()
                },
                // The other three the Settings screen edits. All six were startup snapshots, so
                // every one of them was decorative in production while mock honoured them —
                // the same mock/production divergence that hid the original power bug. An
                // operator dropping "Min Profit Rate" from 10 to 2 saw the dashboard change and
                // the gate stay at 10 forever.
                s.runtime_settings.min_profit_threshold,
                s.runtime_settings.deadline_safety_margin,
                s.runtime_settings.token_price_usd,
            )
        };
        // Live, like the rest of them. See the claim gate below for why this one was load-bearing.
        let (disabled_backends, disabled_slots_by_backend) = {
            let st = state.read().await;
            let backends = st.runtime_settings.disabled_backends.clone();
            // Slot keys the per-DEVICE toggles switch off, so the claim gate can refuse a backend with
            // no card left. The dispatch site reads them again for its own hard filter; both have to,
            // because a toggle can change between the two.
            let slots = zkminer_prover::engine::worker_pool()
                .map(|p| {
                    p.slots_disabled_by(
                        &st.runtime_settings.disabled_devices,
                        &st.runtime_settings.disabled_device_backends,
                    )
                })
                .unwrap_or_default();
            (backends, slots)
        };

        // Publish the measured host-memory expectations so dispatch admission has real figures
        // rather than the conservative default. Cheap, and it tracks a re-benchmark.
        if let (Some(pool), Some(b)) = (zkminer_prover::engine::worker_pool(), benchmarks.as_ref())
        {
            pool.set_expected_host_peaks(b);
        }

        // THE BRAKE. Before deciding anything, ask how hard the host is struggling.
        //
        // PSI measures the symptom — time actually lost to reclaim — which is what "the host is
        // stalling" means, and it catches the slide before anything is killed. A free-memory
        // threshold cannot: this box reads 9 GB "free" with 26 GB available, and read 3 GB available
        // while perfectly healthy under a capped test load.
        // Sample ONCE. Re-reading inside the log arms could print figures that disagree with the
        // decision they are explaining, and `/proc` is not free.
        //
        // An unreadable `/proc` must not read as "healthy". `unwrap_or(u64::MAX)` for available
        // made a missing `/proc/meminfo` look like infinite headroom — the one failure mode where
        // fail-open means "keep piling on". Absent facts mean we cannot classify, so we keep the
        // last thing we could prove: PSI alone, which is the symptom and the stronger signal.
        let stall_pct = zkminer_prover::memory::memory_stall_percent();
        let mem_avail = zkminer_prover::memory::mem_available_bytes();
        let mem_total = zkminer_prover::memory::mem_total_bytes();
        let pressure = match (mem_avail, mem_total) {
            (Some(avail), Some(total)) => {
                zkminer_prover::memory::classify_pressure(stall_pct, avail, total)
            }
            // No absolute figures: classify on the stall alone. `classify_pressure` treats a
            // huge `available` as "the floor cannot be the reason", which is exactly the
            // PSI-only reading we want, and it is honest about what we actually measured.
            _ => zkminer_prover::memory::classify_pressure(stall_pct, u64::MAX, u64::MAX),
        };
        let avail_gib = mem_avail.unwrap_or(0) as f64 / (1024.0 * 1024.0 * 1024.0);
        // Tell the OPERATOR, not just the log file. Every memory message in this module was
        // `tracing`-only, and in TUI mode tracing goes to `~/.zkminer/logs/zkminer.log` with no
        // bridge to the activity log. A braked miner therefore showed "Active 0/2", jobs piling up
        // in Open, no badge and no line — indistinguishable from an idle market. The collateral gate
        // a few hundred lines below does both, and this is the same class of decision.
        //
        // Rate-limited, because the brake re-evaluates every tick and would otherwise own the panel.
        // The `tracing` line is also per-tick, which is tolerable in a file; `add_log` is not.
        let memory_state_changed = last_pressure_logged != Some(pressure);
        if memory_state_changed {
            last_pressure_logged = Some(pressure);
            if !matches!(pressure, zkminer_prover::memory::PressureState::Ok) {
                let reserved_gib = zkminer_prover::engine::worker_pool()
                    .map(|p| p.reserved_host_memory() as f64 / (1024.0 * 1024.0 * 1024.0))
                    .unwrap_or(0.0);
                let mut st = state.write().await;
                st.add_log(
                    if matches!(pressure, zkminer_prover::memory::PressureState::Critical) {
                        LogLevel::Error
                    } else {
                        LogLevel::Warn
                    },
                    format!(
                        "Not claiming: host RAM {} ({:.1} GiB free, {:.1} GiB held by proofs in \
                         flight, memory stall {:.1}%). In-flight proofs continue.",
                        if matches!(pressure, zkminer_prover::memory::PressureState::Critical) {
                            "CRITICAL"
                        } else {
                            "under pressure"
                        },
                        avail_gib,
                        reserved_gib,
                        stall_pct.unwrap_or(0.0),
                    ),
                );
            } else {
                let mut st = state.write().await;
                st.add_log(
                    LogLevel::Success,
                    format!("Host RAM recovered ({avail_gib:.1} GiB free); claiming again."),
                );
            }
        }
        match pressure {
            zkminer_prover::memory::PressureState::Ok => {}
            zkminer_prover::memory::PressureState::Brake => {
                // Stop ADMITTING; let what is running finish. Claiming here would be claiming work
                // we are about to be unable to prove.
                tracing::warn!(
                    "host memory under pressure (PSI full avg10 {:.1}%, {:.1} GiB available) \
                     — not claiming this tick; in-flight proofs continue",
                    stall_pct.unwrap_or(0.0),
                    avail_gib,
                );
                continue;
            }
            zkminer_prover::memory::PressureState::Critical => {
                // Beyond braking: the host is losing real time. We stop claiming, and that is ALL
                // we do — nothing in-flight is cancelled automatically. Releasing a claimed job
                // forfeits collateral, so that call is the operator's, and the log has to say so
                // plainly rather than imply the miner is shedding load on its own.
                tracing::error!(
                    "host memory CRITICAL (PSI full avg10 {:.1}%, {:.1} GiB available). Not \
                     claiming. Nothing in flight is being cancelled — a release forfeits \
                     collateral, so that is your call. If this persists the box cannot sustain \
                     this concurrency: lower max_concurrent_proofs or add RAM. Proofs in flight \
                     may be OOM-killed, which is reported as a host OOM rather than a prover \
                     fault.",
                    stall_pct.unwrap_or(0.0),
                    avail_gib,
                );
                continue;
            }
        }

        // A measured suite, or rates learned from this miner's own proofs. NOT the synthetic
        // placeholder, which the brain publishes to the shared state for the Settings screen and so
        // reads back here on every later tick; it counted as measured, and the planner ran on its
        // invented 1.0 M cycles/s for every card.
        let observed = observed_throughputs();
        let measured = benchmarks.as_ref().is_some_and(|b| !is_synthetic_suite(b));
        let planner_active = !queue_horizon.is_zero()
            && ((measured
                && benchmarks.as_ref().is_some_and(|b| {
                    b.device_benchmarks
                        .iter()
                        .any(|d| d.device_id.starts_with("gpu"))
                }))
                || !observed.is_empty());
        let claim_ceiling = if !planner_active {
            max_concurrent
        } else {
            // Enough headroom to hold the horizon's worth of work in reserve, bounded so a
            // mis-estimate cannot run away and lock unbounded collateral.
            max_concurrent.saturating_mul(3)
        };
        if needing_card(&in_flight, &proved) >= claim_ceiling {
            continue;
        }

        // Do not take on new collateral while the signer is JAMMED by an undisplaceable
        // nonce: nothing at or above it can mine, so a claim bonds collateral that no
        // fulfill and no release can free. A jam can let jobs age
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
            if tick_count.is_multiple_of(WEDGE_CHECK_TICKS) {
                tracing::warn!(
                    "signer jammed at nonce {:?} — not claiming new work until it clears; \
                     held jobs continue",
                    client.jammed_nonce()
                );
            }
            continue;
        }

        // Don't take on new jobs while the router or the Registry is PAUSED (handoff §11): every
        // claim reverts EnforcedPause/RegistryPaused, and the locks we hold keep their (credited)
        // deadlines. Held jobs continue — their fulfil loops hold sends until the lift. The same poll
        // refreshes the chain-vs-wall clock skew the deadline guards use.
        {
            let stale = pause_seen.is_none_or(|(t, _)| t.elapsed() >= PAUSE_POLL_EVERY);
            if stale {
                client.refresh_chain_time().await;
                match client.protocol_paused().await {
                    Ok(p) => {
                        if p != pause_seen.is_some_and(|(_, was)| was) {
                            if p {
                                tracing::warn!(
                                    "PAUSED: the router or Registry is paused — not claiming; held \
                                     locks are kept (their deadlines are credited)"
                                );
                            } else if pause_seen.is_some() {
                                tracing::info!("UNPAUSED: protocol pause lifted — claiming resumes");
                                // Locks kept through the pause are re-driven (or released) now.
                                request_recovery();
                            }
                        }
                        pause_seen = Some((std::time::Instant::now(), p));
                    }
                    Err(e) => tracing::debug!("pause read failed: {e:#}"),
                }
            }
            if pause_seen.is_some_and(|(_, p)| p) {
                continue;
            }
        }

        // Don't take on new jobs while this host's clock and the chain's disagree by more than
        // MAX_CLAIM_CLOCK_SKEW_SECS. Every deadline guard reads `chain_now()`, the later of the two,
        // so with the host clock ahead each fresh lock looks about to expire and is released at once:
        // the claim costs the release penalty and earns nothing. Behind, the "already past" checks run
        // late. Either way the host clock needs fixing (NTP) before it takes on collateral. With no
        // header read at all there is nothing to check against, so that holds too. Held locks keep
        // `chain_now()`: a large gap can't tell a host clock that is ahead (early release, 5%) from an
        // RPC that lags (trusting its header would release after D+G, a 100% slash), so they keep the
        // safe side. The header is refreshed with the pause poll above.
        {
            const SKEW_REREAD_EVERY: Duration = Duration::from_secs(10);
            let mut skew = zkminer_chain::client::chain_clock_skew_secs();
            // A large reading can be a stale header (a host suspend stops `Instant`): read a fresh one
            // before holding claims on it.
            if skew.is_none_or(|s| s.unsigned_abs() > MAX_CLAIM_CLOCK_SKEW_SECS)
                && last_skew_reread.is_none_or(|t| t.elapsed() >= SKEW_REREAD_EVERY)
            {
                last_skew_reread = Some(std::time::Instant::now());
                client.refresh_chain_time().await;
                skew = zkminer_chain::client::chain_clock_skew_secs();
            }
            // Reopen only well inside the limit, so a skew near it doesn't flap the gate.
            let limit = if clock_skew_held {
                MAX_CLAIM_CLOCK_SKEW_SECS - 60
            } else {
                MAX_CLAIM_CLOCK_SKEW_SECS
            };
            let hold = match skew {
                Some(s) if s.unsigned_abs() > limit => Some(format!(
                    "this host's clock is {}s {} the chain's (more than {}s): {}",
                    s.unsigned_abs(),
                    if s < 0 { "ahead of" } else { "behind" },
                    limit,
                    if s < 0 {
                        // Held locks stay timed by this clock: the safe side if it is the RPC that
                        // lags, at the cost of early releases if it is this host's clock that is off.
                        "the host clock is off (check NTP), or the RPC or chain has fallen behind; \
                         locks already held are still timed by this host's clock, so one may be \
                         released early, at the penalty"
                    } else {
                        "the host clock is off (check NTP)"
                    }
                )),
                Some(_) => None,
                None => {
                    Some("no block header has been read to check this host's clock against".into())
                }
            };
            match hold {
                Some(why) => {
                    // At once when the gate closes, then once a minute.
                    if !clock_skew_held || tick_count.is_multiple_of(WEDGE_CHECK_TICKS) {
                        let msg = format!(
                            "PAGE: CLOCK-SKEW — {why}; not claiming new work until they agree"
                        );
                        tracing::warn!("{msg}");
                    }
                    clock_skew_held = true;
                    continue;
                }
                None if clock_skew_held => {
                    let msg = "clock skew cleared — claiming resumes".to_string();
                    tracing::info!("{msg}");
                    state.write().await.add_log(LogLevel::Info, msg);
                    clock_skew_held = false;
                }
                None => {}
            }
        }

        // ETH funds gate (handoff §10; the reference daemons' funds check). A claim is admitted at
        // ~300k gas, but its fulfil carries a ~10M-gas limit the node admits only while the balance
        // covers `gas limit x maxFee` — about 33x the claim's. Without this a draining key keeps
        // claiming and proving jobs whose fulfils the node refuses, and each one ends in a release
        // penalty. Hold new claims while the balance cannot fund every held lock's fulfil plus this
        // claim, or while a recent send was refused for insufficient funds.
        {
            let eth = state.read().await.eth_balance;
            let need_at = |max_fee: u128| {
                let max_fee = max_fee.max(zkminer_chain::client::MIN_PRIORITY_FEE_WEI);
                (client.fulfill_gas_limit as u128)
                    .saturating_mul(max_fee)
                    .saturating_mul(in_flight.len() as u128 + 1)
                    .saturating_add(300_000u128.saturating_mul(max_fee))
            };
            let mut need = need_at(client.last_max_fee());
            // About to close on a quote from the last SEND, which nothing refreshes while the gate is
            // shut: re-quote first (rate-limited), or one stale fee could lock an idle miner out.
            if eth < need && last_fee_quote.is_none_or(|t| t.elapsed() >= PAUSE_POLL_EVERY) {
                last_fee_quote = Some(std::time::Instant::now());
                client.base_fees().await;
                need = need_at(client.last_max_fee());
            }
            let short = if client.funds_short() {
                if eth >= need {
                    client.clear_funds_short();
                    tracing::info!("FUNDS: balance {} wei covers a fulfil again — claiming resumes", eth);
                    false
                } else {
                    true
                }
            } else {
                eth > 0 && eth < need
            };
            if short {
                if tick_count.is_multiple_of(WEDGE_CHECK_TICKS) {
                    tracing::warn!(
                        "FUNDS-SHORT: ETH balance {eth} wei < {need} wei needed to fund {} held \
                         fulfil(s) plus one claim — not claiming new work; held jobs continue",
                        in_flight.len()
                    );
                }
                continue;
            }
        }

        // Don't take on new jobs while the endpoint is rate-limiting. We only
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
                    last_storm_seen.is_none_or(|t| now.duration_since(t) > RPC_BACKOFF_WINDOW);
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
                    .is_none_or(|t| now.duration_since(t) >= RPC_BACKOFF_WARN_EVERY);
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

        // Freshness precondition: never claim on stale collateral data. If the
        // refresh multicall hasn't succeeded recently (silent non-429 failure, or the just-
        // cleared post-storm tick before the forced refresh landed), skip this tick rather
        // than size a claim's collateral against a frozen stake_info. The refresh loop
        // updates last_refresh at least every REFRESH_STALENESS_CEILING even under a storm.
        {
            let stale = {
                let s = state.read().await;
                s.last_refresh.is_none_or(|t| {
                    (chrono::Utc::now() - t)
                        .to_std()
                        .map_or(true, |d| d > CLAIM_FRESHNESS_MAX)
                })
            };
            if stale {
                // Throttled WARN (not debug): if the endpoint is HEALTHY but the refresh keeps
                // failing (e.g. a Multicall3/staking-binding mismatch), claiming is paused with
                // no other symptom — this is the one operator-visible signal for that "idle
                // despite open jobs" mode. Reuses the backoff-warn throttle.
                let now = std::time::Instant::now();
                if last_rpc_backoff_warn
                    .is_none_or(|t| now.duration_since(t) >= RPC_BACKOFF_WARN_EVERY)
                {
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
            // Cards are passed in, not read from the worker pool here: that read took a slot
            // mutex held for the length of a proof, on the brain's per-tick path.
            None if skip_benchmark_gate => {
                let synthetic = synthetic_conservative_benchmark(&proving_cards);
                // PUBLISH it to the TUI, once. The Settings screen builds its device list and its
                // per-device proof-system grid from `state.benchmark_results`, so with this suite
                // living only as a local the shipped default configuration — `skip_benchmark_gate =
                // true`, no cache, nobody has pressed `[b]` — showed both cards as not-provable and
                // refused to toggle them. The operator had NO per-device control at all, while mock
                // mode seeded the field and showed the grid — a divergence where only the mock path
                // populated it. The figures are conservative placeholders and the
                // screen labels them "(unbenchmarked)"; what matters is that the cards are addressable.
                if !synthetic_published {
                    synthetic_published = true;
                    let mut st = state.write().await;
                    if st.benchmark_results.is_none() {
                        st.benchmark_results = Some(synthetic.clone());
                    }
                }
                synthetic
            }
            None => {
                // No benchmarks yet — evaluator can't make a safe decision.
                continue;
            }
        };

        // GPU rows of the benchmark suite, as (dispatcher-visible id, cycles/sec).
        // Keyed on the BENCHMARK device id (`gpu0`), not the dispatcher's (`risc0:cuda:0`):
        // the model only needs stable, distinct keys, and these are what carry a throughput.
        // A GPU with no benchmark row still appears, with 0.0, so the planner falls back to
        // the suite average rather than silently excluding it.
        // Kept at (device, BACKEND) granularity, which is what a `DeviceBenchmark` row IS.
        // Folding `max` over the backends on a card priced every job at the card's FASTEST
        // backend, on the stated reasoning that the fastest is "what the dispatcher would
        // pick". The dispatcher has no such freedom: a job names its proof system, and
        // `resolve_backend` turns that into the one backend that can serve it. So an SP1 job
        // on a card that also benchmarks risc0 was estimated at risc0's throughput —
        // optimistic by exactly the ratio between them, and optimism is the direction that
        // admits work whose deadline cannot be met, which forfeits the collateral.
        // Collapsed to the job's own backend at each use site instead.
        // The risc0 cards that prove jobs, each at its own segment size, and the sizes every risc0 job
        // is measured at before it is claimed (see `risc0_job_sizes`).
        let risc0_cards = risc0_job_cards(
            &risc0_slot_sizes_now,
            &disabled_slots_by_backend,
            disabled_backends.contains(zkminer_prover_protocol::BACKEND_RISC0),
        );
        let risc0_sizes = risc0_job_sizes(&risc0_cards);

        let device_backend_throughputs: Vec<(String, String, f64)> = {
            let mut v: Vec<(String, String, f64)> = Vec::new();
            for d in &benchmarks.device_benchmarks {
                if !d.device_id.starts_with("gpu") {
                    continue; // CPU rows are not proving slots here
                }
                // A risc0 row only for a card that proves risc0 jobs, at the rate of its job size.
                let throughput = if d.prover_backend == zkminer_prover_protocol::BACKEND_RISC0 {
                    match risc0_cards.iter().find(|c| c.device == d.device_id) {
                        Some(card) => zkminer_prover::benchmark::risc0_job_throughput(d, card.po2),
                        None => continue,
                    }
                } else {
                    d.throughput
                };
                v.push((d.device_id.clone(), d.prover_backend.clone(), throughput));
            }
            fill_risc0_rows(&mut v, &risc0_cards);
            // No measured suite: what the cards have actually proved at, where they have.
            if !measured {
                v = with_observed(v, &observed);
            }
            v
        };
        // The planner models only the jobs it placed, and is used only while that covers every job
        // still needing a card. A job it did not place (claimed while it was off, before any card's
        // rate was known, or recovered after a restart) therefore stopped ALL claims until every such
        // job had proved: the moment it switched on, the cards drained empty ("model 0/3"). Place them
        // as it would have, by measured cycles, or as a horizon of work when unknown.
        if planner_active {
            for jid in in_flight.keys() {
                if proved.contains(jid) || queue_model.contains(&jid.0) {
                    continue;
                }
                let (cycles, backend) = inflight_work
                    .get(jid)
                    .copied()
                    .unwrap_or((0, zkminer_prover_protocol::BACKEND_RISC0));
                let slots = queue_model.slots(&planner_throughputs_for_backend(
                    &device_backend_throughputs,
                    backend,
                ));
                if let Some((device, finishes_in)) =
                    zkminer_strategy::queue::place(&slots, cycles, queue_horizon)
                {
                    queue_model.commit(jid.0, &device, finishes_in);
                }
            }
        }

        // Available collateral for NEW claims this tick = on-chain available MINUS the reservations
        // of our claims that figure cannot include yet.
        //
        // getAvailableCollateral nets out EVERY lock mined by the block it was read at: our claims
        // that locked by then, and collateral stranded in past-deadline jobs that never sit in
        // `in_flight`. Subtracting every in-flight reservation on top of it (the old form)
        // double-counted each claim for as long as it was held, not only until the next refresh: on
        // 743111, where a job locks at least 100 HEMI, a 1,000 HEMI stake held about five jobs, not
        // ten. So a reservation is subtracted only while its lock is NOT counted on-chain: its claim
        // is still pending, mined after the block the stake was read at, or of a block we do not know
        // (`lock_counted_on_chain`). Each claim's lock block is the one its lifecycle proved the lock
        // at (`note_lock_block`), and the stake's is the refresh multicall's head (`read_block`), so
        // the two compare on one chain. Both unknown or out of order resolve to subtracting: the
        // failure mode left is a claim the chain reverts (gas), never collateral we do not have.
        //
        // (`total − max(on_chain_locked, Σ in_flight)`, tried earlier, was wrong for another reason:
        // a stranded lock is in `on_chain_locked` but not in `in_flight`, so max() dropped it.)
        let stake_read_block = stake_info.as_ref().and_then(|si| si.read_block);
        let lock_blocks = lock_blocks();
        let mut available_collateral = stake_info
            .as_ref()
            .map(|si| si.available_collateral)
            .unwrap_or(0)
            .saturating_sub(uncounted_reservations(
                &in_flight,
                &lock_blocks,
                stake_read_block,
            ))
            // Watch-only locks nothing, so take off what its would-be claims would have locked.
            .saturating_sub(watch_locked_collateral());

        // Highest-priced open jobs first; skip any already in flight. Cheap local verdicts are applied
        // BEFORE the status read, and the read is bounded to the top MAX_CANDIDATES_PER_TICK: the brain
        // reads views in 25-job chunks through the shared 4 req/s throttle, so an unbounded read of a
        // decoy-flooded Open set would make every iteration take minutes.
        let claim_predicate_now = state.read().await.runtime_settings.claim_predicate_jobs;
        let undecodable_now: Vec<B256> = open_jobs
            .iter()
            .map(|j| j.info.job_id)
            .filter(|jid| job_is_undecodable(*jid))
            .collect();
        if !undecodable_now.is_empty() {
            let mut s = state.write().await;
            s.open_jobs.retain(|j| !undecodable_now.contains(&j.info.job_id));
        }
        other_backend_in_flight.retain(|j| in_flight.contains_key(j));
        sp1_in_flight.retain(|j| in_flight.contains_key(j));
        let mut candidates: Vec<_> = open_jobs
            .iter()
            .filter(|j| !in_flight.contains_key(&j.info.job_id))
            .filter(|j| !undecodable_now.contains(&j.info.job_id))
            .filter(|j| !claim_backing_off(j.info.job_id))
            .filter(|j| claim_predicate_now || !job_is_bound(j.info.job_id))
            .filter(|j| !program_has_no_elf_source(j.info.program_id))
            .collect();
        candidates.sort_by_key(|j| std::cmp::Reverse(j.current_price));
        cut_candidates(&mut candidates, &mut candidate_rotation);

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
        prefetch_job_collateral_terms(&client, &candidate_ids).await;

        // Track whether we claimed anything this tick and, if not, the cheapest
        // job we had to skip purely for lack of available collateral — so an idle
        // miner tells the operator WHY (the per-job eval reason is DEBUG-only).
        let mut claimed_this_tick = false;
        // How this pass's candidates fared at admission, for the `queue:` debug summary below.
        let mut tally = AdmissionTally::default();
        // Collateral reserved by claims made THIS tick. `stake_info` is a
        // tick-start snapshot and is never re-read, so it does not reflect them; pairing it
        // with a post-claim `in_flight.len()` would count each claim twice.
        let mut reserved_this_tick: u128 = 0;
        // Backends already reported as not fitting THIS tick, so the warning is emitted once each
        // rather than once per candidate job.
        let mut memory_skips_this_tick: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        // Was ANY job affordable on collateral alone? NOT the same as
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
                    tracing::debug!(
                        "Skipping {}: no status in batch (revert/RPC miss)",
                        short_id(jid)
                    );
                    continue;
                }
            };
            // Drop from open_jobs if it's no longer an OPEN candidate: someone else claimed
            // it (prover != ZERO) OR it left the Open state entirely (status != 0 — e.g.
            // Cancelled, status 3, prover stays ZERO so the prover check alone never evicts
            // it and it would otherwise occupy a Multicall3 slot on every tick forever).
            if view.status != 0 || view.prover != alloy::primitives::Address::ZERO {
                forget_job_bound(jid);
                let mut s = state.write().await;
                s.open_jobs.retain(|j| j.info.job_id != jid);
                continue;
            }
            // `mut`: the candidate loop records this job's MEASURED cycle count on the snapshot below
            // (once resolved), so the prove path sizes its watchdog/VRAM/po2 on it, not on the
            // adversarial declared `expected_cycles`.
            let mut snapshot = JobStatusSnapshot::from_view(&view);
            // A competitive job with a live bid: zkminer doesn't bid, the view's price is the ceiling
            // frozen at the first bid (no direct claim gets it), and every claim reverts BiddingActive
            // until the round ends. Set it aside until then.
            if snapshot.current_bidder != alloy::primitives::Address::ZERO {
                let left = snapshot
                    .bid_deadline
                    .saturating_sub(zkminer_chain::client::chain_now_floor());
                tracing::debug!("Skipping {}: a bid is live for {left}s more", short_id(jid));
                note_job_retry_after(jid, Duration::from_secs(left.clamp(30, 3600)));
                continue;
            }
            // EVICT a descriptor whose fulfill payload a prior measurement found to be over the
            // on-chain cap: claiming+proving it would waste a full proof on a fulfill that is
            // guaranteed to OOG-revert, then release at a penalty. over_cap is keyed by THIS
            // descriptor hash, which is immutable on-chain for this job_id, so the job can never
            // become claimable — removing it from the Open set (rather than merely skipping) stops a
            // flood of high-min_price over-cap decoys from permanently occupying the value-ranked
            // retained slots and starving genuine work (a slimmer re-submission is a DIFFERENT
            // descriptor hash = a different job_id that re-ingests on its own).
            if desc_is_unfulfillable(&desc_input_hash, snapshot.descriptor_hash) {
                tracing::debug!(
                    "Evicting {}: its fulfill payload exceeds the on-chain cap (journal + descriptor \
                     + seal) — proving it would waste a proof on a guaranteed-revert fulfill",
                    short_id(jid)
                );
                state.write().await.open_jobs.retain(|j| j.info.job_id != jid);
                continue;
            }
            // EVICT a program whose served ELF can never satisfy its on-chain programId: a prior prove
            // derived the verifying key / image id and it did not match, so EVERY job for this program
            // fails AFTER the collateral-locking claim and releases at a penalty. SP1 cannot check this
            // before claiming (deriving the vkey needs the minutes-long setup), so it is only learned on
            // the TYPED prove-path worker error — recording it there caps the loss to the ONE claim wave
            // already in flight (this claim gate, the batch-claim task, and each per-job lifecycle task
            // all re-check the mark). The mismatch is program-wide, deterministic, and PERMANENT (the
            // worker error cannot be forged by guest text), so remove the job from the Open set rather
            // than merely skip it, so a flood of high-min_price mismatched decoys cannot permanently
            // occupy the value-ranked retained slots and starve genuine work. A legitimate program's
            // vkey always matches, so this never false-evicts real work.
            if program_vkey_mismatched_for(job.info.program_id, snapshot.proof_system_id) {
                tracing::debug!(
                    "Evicting {}: its programId cannot be satisfied by the served ELF under this \
                     backend (vkey/image-id mismatch seen on a prior prove) — any claim would waste a \
                     proof and release at a penalty",
                    short_id(jid)
                );
                state.write().await.open_jobs.retain(|j| j.info.job_id != jid);
                continue;
            }
            // EVICT a job whose submit tx can never be decoded into a JobDescriptor (an integrator
            // proxy / multicall wrapper, or calldata too short): without the descriptor we can run
            // neither the pre-claim predicate gate nor the prove/fulfill, so it is permanently
            // unclaimable. Keyed by the UNIQUE job_id — NOT the on-chain descriptorHash, which excludes
            // the submitter and is shared with honest jobs carrying the same descriptor — so this evicts
            // only the undecodable job itself, never an honest twin. Permanent (the submit tx is
            // immutable); a re-submission is a different job_id that re-ingests on its own.
            if job_is_undecodable(jid) {
                tracing::debug!(
                    "Evicting {}: its submit tx is undecodable (proxy/multicall wrapper or truncated \
                     calldata) — its descriptor can never be reconstructed to prove/fulfill it",
                    short_id(jid)
                );
                state.write().await.open_jobs.retain(|j| j.info.job_id != jid);
                continue;
            }
            // SKIP (not evict) an SP1 program observed with no registry elf_hash yet. The elf_hash is set
            // AFTER registration (registerProgram takes none), so its absence is TEMPORAL — a permanent
            // evict would drop a legit program whose hash appears later (the monitor is forward-only and
            // never re-ingests). The self-healing cooldown is consulted HERE, before any measure spawn,
            // so a flood of no-hash decoys never reaches the heavy descriptor scan in the measure path;
            // once the cooldown lapses the job is re-evaluated (and claimed if the hash has been set).
            if resolve_backend(snapshot.proof_system_id) == Some("sp1")
                && sp1_elf_hash_missing_recently(job.info.program_id)
            {
                tracing::trace!(
                    "Skipping {} this tick: its SP1 program has no registry elf_hash yet (re-check \
                     pending)",
                    short_id(jid)
                );
                continue;
            }
            // SKIP (not evict) a program whose NON-predicate pre-fulfill simulation reverted recently.
            // Unlike the vkey mismatch above, an eth_call revert is non-authoritative and may be
            // TRANSIENT (reorg / router pause / stale load-balanced RPC) on a legitimate program, so the
            // breaker is a self-healing cooldown: skip while it is live (throttling a genuinely-doomed
            // program's flood to ~one claim+prove per window) and KEEP the job in the Open set so it is
            // re-evaluated once the cooldown expires — evicting it would permanently drop honest work on
            // a transient blip (the monitor is forward-only and never re-ingests).
            if program_sim_reverted_recently(job.info.program_id, snapshot.proof_system_id) {
                tracing::debug!(
                    "Skipping {} this tick: its program's fulfill simulation reverted recently — \
                     throttling re-claim until the cooldown clears (may be a transient chain-state \
                     revert, so not evicted)",
                    short_id(jid)
                );
                continue;
            }
            // EVICT a job at MAX_REOPEN_COUNT (10) reopens: the router refuses every further claim
            // (`MaxReopenCountReached`), and anyone may `cancelStaleJob` it.
            if snapshot.reopen_count >= zkminer_chain::jobs::MAX_REOPEN_COUNT {
                zkminer_chain::jobs::forget_claim_high_water(jid);
                state.write().await.open_jobs.retain(|j| j.info.job_id != jid);
                continue;
            }
            // SKIP (not evict) a job whose last claim was refused for a TEMPORARY reason (a live price
            // below our high-water floor, a live bid, a pause, a free-stake shortfall): re-quote it after
            // a short back-off rather than every tick.
            if claim_backing_off(jid) {
                continue;
            }
            // A submitter whose job measured clean and then faulted after the claim, or the global
            // divergence breaker (see `note_post_claim_divergence`): no measure slot, no claim.
            if let Some(b) = resolve_backend(snapshot.proof_system_id) {
                if divergence_blocks_claim(job.info.caller, job.info.program_id, b) {
                    continue;
                }
            }
            // FULL/FIELDS-bound with bound-job claiming off: settled by its one descriptor fetch.
            if !claim_predicate_now && job_is_bound(jid) {
                continue;
            }
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
            if !DEPLOYMENT_VERIFIED.load(std::sync::atomic::Ordering::SeqCst) {
                // Whatever its proof system: the deployment it would be claimed on failed (or has not
                // passed) verification.
                tracing::debug!(
                    "Skipping {}: the deployment is not verified right now",
                    short_id(jid)
                );
                continue;
            }
            match resolve_backend(snapshot.proof_system_id) {
                None => {
                    tracing::debug!(
                        "Skipping {}: unsupported proof system {}",
                        short_id(jid),
                        snapshot.proof_system_id
                    );
                    continue;
                }
                Some("risc0") if !risc0_claimable() => {
                    // The proof system failed (or has not passed) verification: its adapter is
                    // disabled, swapped to unaudited code, or its SELECTOR differs from our seal
                    // prefix — every proof would revert after the collateral-locking claim.
                    tracing::debug!(
                        "Skipping {}: risczero.groth16.v1 is not verified claimable right now",
                        short_id(jid)
                    );
                    continue;
                }
                Some("sp1") if !sp1_claimable() => {
                    // The same for sp1.groth16.v1 (its VERIFIER_HASH must prefix our seals).
                    tracing::debug!(
                        "Skipping {}: sp1.groth16.v1 is not verified claimable right now",
                        short_id(jid)
                    );
                    continue;
                }
                Some(backend) => {
                    // Refuse a job whose window is too short to claim, prove, AND still
                    // release collateral before the deadline. A submitter can set a tiny
                    // fulfillmentTimeout (with small declared cycles so the duration estimate looks
                    // feasible) to bait a claim that then cannot be fulfilled in time → release
                    // penalty / slash. The floor is the irreducible overhead independent of proof
                    // size: release margin + one minimum attempt + the backend's fixed setup
                    // allowance + a buffer for the claim tx itself to mine. (Fresh-job loop only, so
                    // skipping is free — nothing is on-chain yet.)
                    // Planned against D, the fulfilment timeout. The release margin is NOT subtracted:
                    // it lives inside the 30-min PROVER_GRACE after D, which this window excludes.
                    let min_deadline_floor = MIN_ATTEMPT_BUDGET_SECS
                        + fixed_proving_allowance_secs(backend)
                        + DEADLINE_FULFILL_MARGIN_SECS;
                    if time_remaining < min_deadline_floor {
                        tracing::debug!(
                            "Skipping {}: deadline too short ({}s < {}s floor for {backend}) — \
                             claiming would risk a release penalty / slash",
                            short_id(jid),
                            time_remaining,
                            min_deadline_floor
                        );
                        continue;
                    }
                    // Snapshot the backend sources ONCE so `available` and `sim_mode`
                    // are computed from a single consistent view (a health flip between
                    // two separate calls could otherwise disagree).
                    let sources = zkminer_prover::engine::backend_sources();
                    let available = sources.iter().any(|(name, source)| {
                        *name == backend && !matches!(source, BackendSource::Simulated)
                    });
                    // `available` is false only when some real backend IS compiled
                    // in (so we're not in pure-sim mode) yet THIS backend is neither
                    // in-process nor served by a healthy worker.
                    // `all()` on an EMPTY list is true, which would read a host with no
                    // advertisable backend at all as demo mode and claim freely. A
                    // declined backend is now reported as nothing rather than Simulated,
                    // so the empty case is reachable: require a non-empty list.
                    //
                    // And a host where something DECLINED is not a demo host, however the rest of
                    // the list looks. A declined backend contributes no entry, so the remainder
                    // can be all-`Simulated` while a real worker has just said it cannot prove —
                    // and `sim_mode` would then wave through the very jobs it cannot serve.
                    // The operator switched this backend OFF. Honoured by mock mode and by
                    // nothing else: the dashboard struck the row out, mock stopped claiming, and
                    // production carried on. That made it a no-op exactly where it matters — it is
                    // the only lever an operator has for the backend that gets charged 18 GiB and
                    // the one documented to have been OOM-killed on this box.
                    if disabled_backends.contains(backend) {
                        tracing::debug!(
                            "Skipping {}: {backend} is disabled in settings",
                            short_id(jid)
                        );
                        continue;
                    }
                    // And a backend whose every DEVICE is switched off is just as unclaimable, even
                    // though the backend itself is enabled. `prove_min_vram` treats disabled slots as
                    // a hard filter and bails when they leave nothing — correctly — but by then the
                    // collateral is bonded, so the job can only be released at a penalty or stranded.
                    // An operator parking SP1 by unchecking both of its cards in the per-device grid,
                    // rather than by using the Proof Systems list, hit exactly this.
                    if !disabled_slots_by_backend.is_empty() {
                        if let Some(pool) = zkminer_prover::engine::worker_pool() {
                            if pool.every_slot_disabled(backend, &disabled_slots_by_backend) {
                                tracing::debug!(
                                    "Skipping {}: every {backend} device is disabled in settings",
                                    short_id(jid)
                                );
                                continue;
                            }
                        }
                    }

                    let sim_mode = !sources.is_empty()
                        && !zkminer_prover::engine::any_backend_declined()
                        && sources
                            .iter()
                            .all(|(_, source)| matches!(source, BackendSource::Simulated));

                    // Memory feasibility, beside the deadline and collateral gates and for the
                    // same reason: a job we cannot FIT is a guaranteed loss, not merely a crash
                    // risk. Claiming it means releasing at a penalty, or stranding the collateral
                    // if the deadline passes first.
                    //
                    // AFTER `sim_mode`, and skipped in it. A simulated proof allocates nothing, so
                    // charging it 18 GiB made the demo claim nothing at all on any box with under
                    // 21 GiB free, and report "the box cannot fit it right now" about a proof that
                    // never runs. The `available` gate below states the same no-op-in-demo rule for
                    // itself; this one sat above it and silently did not honour it.
                    // Not before the backend's one-time setup is done. SP1's first proof would
                    // otherwise download ~8 GB of circuit artifacts inside its 90 s watchdog, be
                    // killed mid-way, and leave an install that fails every later proof. See
                    // `spawn_sp1_warmup`.
                    if !sim_mode {
                        if let Some(pool) = zkminer_prover::engine::worker_pool() {
                            if !pool.backend_warmed(backend) {
                                if memory_skips_this_tick.insert(format!("{backend}:warmup")) {
                                    tracing::debug!(
                                        "Not claiming {backend} jobs until its one-time setup is \
                                         done"
                                    );
                                }
                                continue;
                            }
                        }
                    }
                    // No card here proves risc0 jobs: none has a size known to fit it (a card under
                    // 14 GiB needs calibrating, or a size set for it), or each one that has is
                    // switched off. The job could only be released. (With no risc0 card at all, the
                    // availability check below says so.)
                    if !sim_mode
                        && backend == "risc0"
                        && risc0_sizes.is_empty()
                        && !risc0_slot_sizes_now.is_empty()
                    {
                        let now = std::time::Instant::now();
                        if last_no_risc0_card_warn
                            .is_none_or(|t| now.duration_since(t) >= COLLATERAL_WARN_EVERY)
                        {
                            last_no_risc0_card_warn = Some(now);
                            let detail = "Not claiming risc0 jobs: no enabled card here has a risc0 \
                                          job size. A card with under 14 GiB of VRAM needs one: a \
                                          po2 under Settings → Advanced for this session, or \
                                          `prover.risc0_job_po2` in the config or, on an NVIDIA \
                                          card, `zkminer benchmark --calibrate`, each read when the \
                                          miner starts.";
                            tracing::warn!("{detail}");
                            state
                                .write()
                                .await
                                .add_log(LogLevel::Warn, detail.to_string());
                        }
                        continue;
                    }
                    if !sim_mode {
                        if let Some(pool) = zkminer_prover::engine::worker_pool() {
                            // Reserve for the largest size a card proves risc0 jobs at, so a job
                            // claimed here is one the PROVE gate can admit on any of them.
                            let want = if backend == "risc0" {
                                pool.expected_host_peak_at_po2(
                                    backend,
                                    risc0_sizes.iter().copied().max(),
                                )
                            } else {
                                pool.expected_host_peak(backend)
                            };
                            // `in_flight` — claims outstanding, spawned or not — and the real
                            // concurrency bound. NOT a per-tick accumulator: claimed jobs prove
                            // SEQUENTIALLY, so the memory a set of claims can demand at once is
                            // `min(outstanding + 1, max_concurrent)` peaks. See
                            // `backend_fits_for_claim`.
                            // An SP1 job the host could not stage beside those already waiting for
                            // a card would wait for memory holding collateral and a slot; one queued
                            // behind the running ones is enough to hide the next claim's latency.
                            if backend == zkminer_prover_protocol::BACKEND_SP1 {
                                let waiting = sp1_in_flight
                                    .iter()
                                    .filter(|j| !proved.contains(*j))
                                    .count();
                                let room = pool.sp1_concurrent_capacity().unwrap_or(usize::MAX);
                                if waiting > room.max(1) {
                                    continue;
                                }
                            }
                            if !pool.backend_fits_for_claim(
                                want,
                                backend,
                                needing_card(&in_flight, &proved),
                                max_concurrent,
                            ) {
                                // Rate-limited to once per backend per tick. On the market this
                                // repo documents — 298 open jobs declaring zero cycles — a
                                // memory-wedged miner emitted ~298 of these every 5s, about 60
                                // lines a second, which buries every other signal in the log.
                                if memory_skips_this_tick.insert(backend.to_string()) {
                                    let detail = format!(
                                        "Not claiming {backend} jobs: one proof needs ~{:.1} GiB \
                                         of host RAM, {} already outstanding, and this {:.1} GiB \
                                         box cannot run the resulting set ({:.1} GiB held by \
                                         proofs in flight). Claiming would mean releasing at a \
                                         penalty.",
                                        want as f64 / (1024.0 * 1024.0 * 1024.0),
                                        in_flight.len(),
                                        zkminer_prover::memory::mem_total_bytes().unwrap_or(0)
                                            as f64
                                            / (1024.0 * 1024.0 * 1024.0),
                                        pool.reserved_host_memory() as f64
                                            / (1024.0 * 1024.0 * 1024.0),
                                    );
                                    tracing::warn!("{detail}");
                                    // And on screen. Every memory message used to be
                                    // `tracing`-only, which in TUI mode is a log file the operator
                                    // is not reading — so the gate that actually fires on this box
                                    // produced nothing at all on the dashboard, while the job list
                                    // showed "Queued (waiting for GPU)" about idle cards.
                                    state.write().await.add_log(LogLevel::Warn, detail);
                                }
                                continue;
                            }
                        }
                    }
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
            // The submitter's `expectedCycles` is attacker-controlled: declaring a
            // tiny count behind an ELF that runs billions of cycles makes a job look cheap and
            // deadline-feasible, so the miner claims (locking collateral) then cannot finish, and
            // bleeds the release penalty. Defences:
            //   - measure the guest ourselves and key the result by (programId, keccak256(inputData)).
            //     The cycle count is a deterministic function of exactly (program, input): keying
            //     by programId alone under-sized an input-varying flood (one cheap input's measurement
            //     reused for a heavy one), and keying by descriptor_hash alone let a tag-varying flood
            //     dodge the cache (the free-form `tag` is in the hash but not the input). The pair
            //     resolves via `desc_input_hash`, so a repeat input — under any tag — is sized on its
            //     real measurement.
            //   - with a measurement, never size SMALLER than it: max(declared, measured).
            //   - with NO measurement (not yet measured for this exact input), floor the declaration at
            //     FALLBACK_ESTIMATED_CYCLES so a `declared = 1` can't shrink the estimate toward zero.
            //     This estimate is only for RANKING an unsized job; it cannot be CLAIMED until measured
            //     (see `measurable` and the claim gate), so the floor never gates real collateral.
            // The measured count is keyed by backend too, so resolve against THIS job's
            // backend — a measurement only sizes a job of the same proof system.
            let backend_opt = resolve_backend(snapshot.proof_system_id);
            // The feasibility estimate must be measured against the window the PROVE PATH actually
            // gets, not the full fulfillment window. Once claimed: the prove watchdog is budgeted at
            // (window − release margin), the fulfill tx needs its own margin AFTER the proof, and the
            // backend adds a fixed proving allowance (notably the ~120s SP1 Groth16 wrap) that the
            // pure cycles/throughput estimate omits. Subtract all three and feed this provable window
            // to the evaluator and the planner, so a job is admitted only if its estimate fits the time
            // it will truly have — closing the optimistic-full-window gap that led to admitted-then-
            // doomed claims (claim → watchdog kill → penalized release). The size-independent
            // `min_deadline_floor` gate above already guarantees time_remaining ≥ min_attempt
            // + fixed_allowance + fulfill, so this stays ≥ MIN_ATTEMPT_BUDGET_SECS (never 0) here,
            // before the measurement's execute allowance comes off it below.
            let prove_window = time_remaining.saturating_sub(
                DEADLINE_FULFILL_MARGIN_SECS
                    + backend_opt.map(fixed_proving_allowance_secs).unwrap_or(0),
            );
            // Resolve the measurement at every size the job is measured at (each risc0 card size; one
            // for SP1), with the cycles, the SP1 execute peak, the verified risc0 ELF keccak and the
            // journal all under ONE lock hold (finding C-8): a concurrent eviction between separate
            // reads could desync the peak to 0, un-gating the H1 check below, or drop the hash the
            // claim binds its ELF re-fetch to (`None`: the re-fetch falls back to the image-id check).
            let job_sizes = measure_sizes(backend_opt.unwrap_or(""), &risc0_sizes);
            let (measured_for_job, measured_peak_for_job) = match resolve_measured_at(
                &measured_cycles,
                &desc_input_hash,
                backend_opt.unwrap_or(""),
                &job_sizes,
                job.info.program_id,
                snapshot.descriptor_hash,
            ) {
                Some(r) => {
                    snapshot.verified_elf_hash = r.verified_elf_hash;
                    // The journal the lifecycle checks a bound job's binding against before the
                    // claim, from the same entries as the cycles.
                    snapshot.measured_journal = r.journal;
                    snapshot.measured_execute_secs = Some(r.execute_secs);
                    // The sizes it measured clean at: it is proven on a card at one of them.
                    if backend_opt == Some(zkminer_prover_protocol::BACKEND_RISC0) {
                        snapshot.measured_po2s = job_sizes.clone();
                    }
                    let sp1 = backend_opt == Some(zkminer_prover_protocol::BACKEND_SP1);
                    (Some(r.cycles), sp1.then_some(r.peak_host_bytes))
                }
                None => (None, None),
            };
            // Carry the measured count on the snapshot so the prove path (watchdog
            // timeout, min-VRAM) sizes on it instead of the adversarial declared field. Rides
            // through the batch tuple → spawn_lifecycle_task → process_job_lifecycle unchanged.
            snapshot.measured_cycles = measured_for_job;
            // The execute PEAK (same merged entry) for the RH2 prove reservation; carried on the snapshot.
            snapshot.measured_peak = measured_peak_for_job;
            // The proof executes the guest again, which its cycles do not size: out of the window,
            // into the watchdog gate and the planner's backlog below.
            let execute_allowance =
                execute_allowance_secs(backend_opt.unwrap_or(""), snapshot.measured_execute_secs);
            let prove_window = prove_window.saturating_sub(execute_allowance);

            // H1 provability gate (SP1 only). A guest measured feasible on the SERVER-LESS measure
            // worker can still OOM at PROVE time, where `run_proof` replays the same deterministic
            // execute on the prove worker that holds the warm ~17.6 GiB sp1-gpu-server — the host peak
            // is their SUM, which the serverless measure cap does not bound. Skip claiming this job
            // while that sum would not fit. TRANSIENT, not a negative-cache: provability depends on the
            // CURRENT server residency, so the job becomes claimable once the server goes idle/evicted
            // (or on a bigger host). `peak == 0` (older worker / off-Linux / portable executor, which
            // has no server-stacking) leaves it ungated — the prior behaviour.
            if backend_opt == Some("sp1") && measured_for_job.is_some() {
                // `worker_pool()` is None in sim mode, so the gate is naturally inert there.
                if let Some(pool) = zkminer_prover::engine::worker_pool() {
                    let peak = measured_peak_for_job.unwrap_or(0);
                    if !pool.sp1_execute_provable_beside_server(peak) {
                        // Once a tick for all of them, not per program: the id is the submitter's
                        // choice, so a program each would be one warning each, every tick.
                        if memory_skips_this_tick.insert("sp1:provable".to_string()) {
                            tracing::warn!(
                                "Not claiming SP1 job {}: its measured execute peak (~{:.1} GiB) plus \
                                 a warm sp1-gpu-server would exceed host RAM at prove time, so it is \
                                 not provable here. The gate assumes the server is warm at prove time \
                                 (it persists across proofs), so on this host this is effectively a \
                                 permanent decline for a job this heavy — a bigger host is required.",
                                short_id(job.info.program_id),
                                peak as f64 / (1024.0 * 1024.0 * 1024.0),
                            );
                        }
                        continue;
                    }
                }
            }

            // Per-device throughputs for THIS job's backend (the same rows the planner uses). Size the
            // live claim gate on the SLOWEST eligible card so admission is safe wherever dispatch lands
            // the job, and record the FASTEST eligible card as the preferred dispatch target so the job
            // runs on the card it was planned for when that card is free (graceful fallback otherwise).
            // When the look-ahead planner is active it is the finer, per-device admission gate and
            // overrides this preference with its own backlog-aware choice below — so the live gate stays
            // on the suite average there to avoid double-counting its conservatism into an over-refusal.
            // `throughputs_for_backend` also emits cross-backend FALLBACK rows (the global slowest)
            // for cards with no row for THIS backend — those exist only for the planner's
            // device-existence logic and CANNOT run this backend. Size and prefer over the GENUINE
            // per-device rows only: a card that cannot run the backend must neither drag the slowest
            // estimate down (over-refusing feasible work) nor be chosen as the preferred dispatch
            // target. Only when there is no genuine row at all do we fall back to the mixed-list value
            // (behavior there is unchanged; the empty-rows case is handled by the sizing rework).
            let backend_name = backend_opt.unwrap_or("");
            let genuine_throughputs: Vec<f64> = device_backend_throughputs
                .iter()
                .filter(|(_, b, t)| b.as_str() == backend_name && t.is_finite() && *t > 0.0)
                .map(|(_, _, t)| *t)
                .collect();
            let slowest_eligible = if genuine_throughputs.is_empty() {
                throughputs_for_backend(&device_backend_throughputs, backend_name)
                    .iter()
                    .filter(|(d, _)| risc0_job_device(backend_name, &risc0_cards, d))
                    .map(|(_, t)| *t)
                    .filter(|t| t.is_finite() && *t > 0.0)
                    .fold(f64::INFINITY, f64::min)
                    .pipe_finite_or(0.0)
            } else {
                genuine_throughputs.iter().copied().fold(f64::INFINITY, f64::min)
            };
            snapshot.preferred_device = device_backend_throughputs
                .iter()
                .filter(|(_, b, t)| b.as_str() == backend_name && t.is_finite() && *t > 0.0)
                .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(id, _, _)| id.clone());
            // The conservative floor, charged for a risc0 card at a size below the one rows describe.
            let conservative_cps = if backend_name == zkminer_prover_protocol::BACKEND_RISC0 {
                risc0_conservative_cps(&risc0_sizes)
            } else {
                CONSERVATIVE_SIZING_CPS
            };
            // Before its measurement only whether to measure the job rides on the evaluation (a claim
            // needs the measurement): size it on the fastest card, which may take it, so a slow card
            // (a small one at a small size) cannot keep every short-window job from being measured.
            // Measured, it is claimed only if the slowest card can finish it.
            let fastest_eligible = genuine_throughputs.iter().copied().fold(0.0, f64::max);
            let live_gate_throughput = if planner_active {
                0.0
            } else if measured_for_job.is_none() && fastest_eligible > 0.0 {
                fastest_eligible
            } else if slowest_eligible > 0.0 {
                slowest_eligible
            } else if benchmarks.is_simulated() {
                // Simulated suite: keep 0.0 so the evaluator's is_simulated()+throughput<=0 guard waves
                // the (instant, allocation-free) simulated proof through — don't break demo/test flows.
                0.0
            } else {
                // Real rig but no genuine per-device row for this backend (e.g. a cached suite
                // predating device_benchmarks): size on a conservative floor rather than letting the
                // evaluator fall back to its OPTIMISTIC suite average, which would re-open deadline
                // claim-bait. See `CONSERVATIVE_SIZING_CPS`.
                conservative_cps
            };
            // The slowest card's rate, for the prove watchdog: a card at a small size can be slower
            // than the watchdog's own floor.
            snapshot.planning_cps = if slowest_eligible > 0.0 {
                Some(slowest_eligible)
            } else {
                (!benchmarks.is_simulated()).then_some(conservative_cps)
            };
            let estimated_cycles = known_cycles.unwrap_or(FALLBACK_ESTIMATED_CYCLES);

            // Backstop the per-descriptor fulfill-payload screen at the claim gate, evaluated HERE —
            // right after resolve_measured — so the measured-cycle and journal-length caches are read
            // at one consistent point (past the adapter-query await above, and after the measure task's
            // journal-before-cycles insert order guarantees a resolved measurement implies a cached
            // journal). A sibling descriptor that LOST the measuring_inputs dedup race recorded its
            // resolver (so it became claimable) but returned before any journal existed, so neither
            // payload screen inside its measure task ran for it. Once the winner's measurement lands the
            // journal length is known; combined with THIS descriptor's cached payload the full payload
            // is re-checked here and the claim refused when it is over the cap — closing the window where
            // such a descriptor is claimed+proved into a guaranteed OOG-revert fulfill. Mark it so later
            // ticks short-circuit at the cheap desc_is_unfulfillable check. (Returns false — does not block — until
            // all three inputs are cached, so it never false-skips a job that could actually fulfill.)
            if let Some(backend) = backend_opt {
                if claim_payload_over_cap(
                    &desc_input_hash,
                    &measured_journal,
                    &desc_payload,
                    backend,
                    job.info.program_id,
                    snapshot.descriptor_hash,
                ) {
                    mark_desc_unfulfillable(&desc_input_hash, snapshot.descriptor_hash);
                    tracing::debug!(
                        "Skipping {}: its full fulfill payload (measured journal + descriptor + \
                         seal) exceeds the on-chain cap — proving it would waste a proof on a \
                         guaranteed-revert fulfill",
                        short_id(jid)
                    );
                    continue;
                }
            }

            let estimated_cycles = match (snapshot.expected_cycles, measured_for_job) {
                (0, Some(c)) => c,
                (0, None) => FALLBACK_ESTIMATED_CYCLES,
                (declared, Some(c)) => declared.max(c),
                (declared, None) => declared.max(FALLBACK_ESTIMATED_CYCLES),
            };

            // Required collateral: compute from the auction formula, with the job's OWN terms as
            // the router snapshotted them at submit (`getJobSnapshots`: the resolved collateralBps —
            // per-job override, else the adapter's then-default, else the global default — and the
            // then-MIN_COLLATERAL_AMOUNT). A submitter may set up to 500%, so the adapter's current
            // default is not an upper bound. Unreadable: skip this tick rather than guess.
            let (job_min_collateral, effective_bps) = match job_collateral_terms(jid) {
                Some((min, bps)) => (min, u64::try_from(bps).unwrap_or(u64::MAX)),
                None => {
                    tracing::debug!(
                        "Skipping {} this tick: its collateral terms are not read yet",
                        short_id(jid)
                    );
                    continue;
                }
            };
            // Collateral gate uses an UPPER BOUND on what the on-chain claim will lock,
            // NOT the current-price estimate. The claim locks
            // compute_collateral(settledPrice), where settledPrice is the auction price
            // AT EXECUTION — several seconds after this candidate snapshot (batch
            // assembly + tx mining), by which point the ascending auction has ramped the
            // price HIGHER than snapshot.current_price. Gating on the current price
            // UNDER-provisions: the miner batches N jobs believing they fit, then the tail
            // claim reverts on-chain for insufficient collateral. The failure mode: when
            // available collateral has fallen to only ~2.7 jobs' worth, every job can still
            // evaluate collateral-sufficient (its current-price estimate fits the stale
            // available), so the brain optimistically batches 3 and the 3rd sub-claim
            // reverts. max_price is the auction ceiling, so collateral
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
                job_min_collateral, // the job's snapshotted floor, not adapter.min_stake
            );

            let mut params = JobParams {
                current_price: snapshot.current_price,
                bonus_amount: snapshot.bonus_amount,
                speed_premium: snapshot.speed_premium,
                // The full premium: an upper bound, refined below for a job it would claim.
                premium_cap: None,
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
                // The provable window (full window − release/fulfill margins − fixed proving
                // allowance), NOT the full fulfillment window: the evaluator must size feasibility and
                // risk against the time the prove path actually gets. See `prove_window` above.
                time_remaining: prove_window,
                estimated_cycles,
                required_collateral,
                available_collateral,
                token_price_usd,
                fee_rate_bps: adapter_info.fee_rate_bps,
                // Slowest eligible card for this backend when the planner is off (safe for any
                // dispatch landing), the fastest while the job is unmeasured (only whether to measure
                // it rides on that); suite average when the planner is on (it is the finer gate). 0.0
                // falls back to the suite average inside the evaluator. See `live_gate_throughput`.
                throughput: live_gate_throughput,
                max_price: job.info.max_price.max(snapshot.current_price),
                // No specific card chosen yet (the dispatcher picks one at prove time), so
                // the cost model charges the suite's mean card — paired with the suite-average
                // throughput above. `evaluate_job` composes CPU + card + overhead; passing
                // `cost_params` through unmodified would charge the overhead term alone.
                device_watts: None,
            };
            let mut eval = evaluate_job(
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
            snapshot.estimated_prove_secs = Some(eval.estimated_proving_time_secs.max(0.0) as u64);
            // A verdict that holds while the job stays Open: its window is fixed until it is claimed,
            // and its cycles are measured (or declared at or above the floor, which binds the sizing
            // too). Set it aside rather than let it hold a slot of the per-tick cut every tick.
            if (!eval.deadline_feasible
                || eval.risk_level == zkminer_strategy::evaluator::RiskLevel::High)
                && !benchmarks.is_simulated()
                && (measured_for_job.is_some()
                    || snapshot.expected_cycles >= FALLBACK_ESTIMATED_CYCLES)
            {
                set_job_aside(jid, DETERMINISTIC_SKIP_TTL);
            }
            // Count + remember the cheapest job blocked SOLELY by collateral —
            // i.e. under-collateralized but otherwise on-time. Requiring
            // `deadline_feasible` avoids telling the operator to stake more for jobs
            // that would miss their deadline anyway (the evaluator reports the
            // collateral reason first, before checking the deadline).
            // Collateral alone was enough for this job, whatever else decided it.
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
            // Look-ahead admission. `evaluate_job` above answered "is this job worth
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
            // Never queue AHEAD on a job whose cycle count we do not know.
            //
            // In practice `expected_cycles` is always 0, so
            // `estimated_cycles` falls back to FALLBACK_ESTIMATED_CYCLES (34e6). That estimates
            // 14.9s on gpu0 against a real median of 123s — 8x under. The committed backlog
            // then decays to zero within a few brain ticks while the proof runs for another
            // ~100-290s, so `slots()` reports a busy card as idle, `HorizonFull` and
            // `DeadlineInfeasible` become unreachable, and the ONLY surviving bound is the
            // tripled ceiling. That is 3x depth gated by a start-now check — exactly the
            // shape that loses collateral.
            //
            // A declared cycle count is the planner's whole input. Without one, fall through
            // to the pre-feature idle-device rule rather than queue on a fiction.
            // A job is "sized" — and only then claimable — once we hold a MEASURED cycle
            // count for its exact (program, input). The submitter's declared `expected_cycles` is
            // adversarial and no longer makes a job claimable on its own; it only raises the estimate
            // once we ALSO have a measurement (max(declared, measured), above). For a backend we
            // cannot execute-measure, fall back to the declaration so the gate does not permanently
            // strand it — but both real backends (risc0 and sp1) measure, so in practice a claim
            // always waits for a real number. The planner shares this: it needs a real number too.
            // (`backend_opt` was resolved above, before the estimate, for the backend-keyed lookup.)
            let backend_measurable = matches!(backend_opt, Some("risc0") | Some("sp1"));
            // A claim requires a measurable backend. risc0 and sp1 both execute-size, so a claim
            // waits for a REAL cycle count. A NON-measurable backend (only OpenVM today, and it is
            // declined by default in `resolve_backend` unless ZKMINER_ENABLE_OPENVM=1) has no
            // pre-claim measurement, so sizing would otherwise fall back to the submitter-DECLARED
            // `expected_cycles` — an adversarial number. Refuse to make such a job claimable on that
            // declaration alone: a hostile OpenVM job must not be bonded blind (unbounded prove ->
            // deadline miss -> slash; and an in-process prove with no verified size -> host OOM) on a
            // count we never verified. It becomes claimable only once a real pre-claim measurement
            // path exists for that backend.
            let measurable = if backend_measurable {
                measured_for_job.is_some()
            } else {
                false
            };
            // A measured job whose proof cannot finish inside the per-attempt watchdog would be killed
            // on every attempt and released at a penalty, however long its window: the deadline gates
            // only compare to the window. Skip it (not evict: a raised `proving_timeout` heals it).
            if let Some(cycles) = measured_for_job {
                if slowest_eligible > 0.0 {
                    let est_secs = (cycles as f64 / slowest_eligible) * deadline_safety_margin
                        + backend_opt.map(fixed_proving_allowance_secs).unwrap_or(0) as f64
                        + execute_allowance as f64;
                    if est_secs >= proving_timeout.as_secs_f64() {
                        tracing::debug!(
                            "Skipping {}: measured {cycles} cycles need ~{est_secs:.0}s, over the {}s \
                             per-attempt proving timeout",
                            short_id(jid),
                            proving_timeout.as_secs()
                        );
                        // Deterministic for this (program, input) — an unmeasurable guest lands here
                        // too — so set the job aside rather than let it hold a slot of the per-tick
                        // candidate cut on every tick.
                        set_job_aside(jid, UNMEASURABLE_RETRY_TTL);
                        continue;
                    }
                }
            }

            // Not yet measured this exact (program, input)? Execute the guest in the
            // background to learn its TRUE cycle count, so a later sighting can be sized — and
            // CLAIMED — on a real number instead of the submitter's declaration. Deliberately does not
            // block this tick; the measurement improves every future decision about the same work, and
            // the market recycles a small set of (program, input) pairs.
            // Trigger for every measurable backend — risc0 AND sp1 now both execute-size
            // (the sp1 worker measures on a CPU executor). Deduped by DESCRIPTOR HASH: that is what we
            // hold before the descriptor is fetched, and the task resolves it to the input hash.
            // `measure_cycles` fetches the descriptor, records desc->input, short-circuits if this
            // input was already measured under another tag, else executes and caches by (backend,
            // program, input). A non-measurable backend is skipped — it relies on the declared floor
            // and cannot be claimed here anyway (its `measurable` is declared-only).
            //
            // Measure ONLY a job we would actually claim (`Recommendation::Claim` on the
            // current estimate). The measurement holds a GPU worker slot for up to MEASURE_TIMEOUT, so
            // without this gate a flood of distinct-input junk jobs — none of which we'd ever claim —
            // would consume every slot measuring and starve the proofs the measurement exists to
            // schedule. (Trade-off: a job that looks unprofitable/infeasible at the FALLBACK estimate
            // but is actually tiny won't be measured; that is a missed opportunity, not a safety loss,
            // and the fallback is ~the market median so it is rare.)
            let pid = job.info.program_id;
            let dh = snapshot.descriptor_hash;
            if backend_measurable
                && measured_for_job.is_none()
                && matches!(eval.recommendation, Recommendation::Claim)
                // Don't spend a measure slot on a program a prior prove already proved unclaimable
                // under this backend (its served ELF's vkey/image-id can never match its programId);
                // the claim gate skips it anyway.
                && !program_vkey_mismatched_for(pid, snapshot.proof_system_id)
                // Don't re-spawn a measure task (descriptor fetch + return) every tick for a job the
                // submitter exclusively assigned to ANOTHER prover; skip it for a cooldown so it cannot
                // monopolize the per-tick measure budget. Time-bounded, since exclusivity expires.
                && !assigned_elsewhere_recently(&assigned_elsewhere, jid)
            {
                let backend = backend_opt.unwrap_or("");
                // Dedup by descriptor hash so N sightings spawn ONE measuring task (an execute per size
                // it lacks); cleared below.
                const MAX_INFLIGHT_MEASUREMENTS: usize = 16;
                // Budget per-tick measurement spawns against the MEASURE POOL for a backend that has a
                // dedicated one — now BOTH sp1 AND risc0 (finding TR1 gave risc0 its own CPU-only
                // measure pool) — and against GPU prove-concurrency only for a backend with no dedicated
                // pool (openvm, in-process on its prove worker). Both pooled backends measure on a CPU
                // pool, never a GPU, so sizing their budget on GPU count was a category error: it
                // collapsed to 1 on a single-GPU rig (serializing the pool) and exceeded the pool on
                // >=3-GPU rigs (over-spawning into the "all slots busy" race). Pool-sized means
                // budget <= pool, counted in executes (see `measure_admits`): a job starts the
                // executes there are free workers for, and its other sizes are measured on a later
                // tick. A descriptor with no free worker simply waits.
                let measure_budget = match zkminer_prover::engine::worker_pool()
                    .and_then(|p| p.measure_worker_count(backend))
                {
                    Some(pool) => pool.min(MAX_INFLIGHT_MEASUREMENTS),
                    None => max_concurrent
                        .saturating_sub(in_flight.len())
                        .max(1)
                        .min(MAX_INFLIGHT_MEASUREMENTS),
                };
                // The executes it will run: one per size not measured yet (every size, while its
                // input is unknown).
                let to_measure = {
                    let input = desc_input_hash
                        .lock()
                        .ok()
                        .and_then(|m| m.get(&dh).map(|i| i.input_hash));
                    match (input, measured_cycles.lock()) {
                        (Some(ih), Ok(m)) => job_sizes
                            .iter()
                            .filter(|&&p| !m.contains_key(&(backend_tag(backend), p, pid, ih)))
                            .count(),
                        _ => job_sizes.len(),
                    }
                };
                let fresh = measuring
                    .lock()
                    .map(|mut m| {
                        // Budget PER-BACKEND: count only THIS backend's in-flight measurements, so one
                        // backend's long measurement (e.g. a ~115s SP1 decoy on its dedicated measure
                        // worker) cannot monopolize the slot the OTHER backend (risc0, now on its OWN
                        // dedicated measure pool) needs. Dedup stays global by descriptor hash.
                        let tag = backend_tag(backend_opt.unwrap_or(""));
                        let executing: usize =
                            m.values().filter(|(b, _)| *b == tag).map(|(_, n)| *n).sum();
                        let admitted = measure_admits(executing, to_measure, measure_budget);
                        if m.contains_key(&dh) || admitted == 0 {
                            None
                        } else {
                            m.insert(dh, (tag, admitted));
                            Some(admitted)
                        }
                    })
                    .unwrap_or(None);
                if let Some(admitted) = fresh {
                    let sizes2 = job_sizes.clone();
                    let (c2, st2, cache, resolver, inflight, inflight_inputs, strikes2, jcache2, pcache2, acache) = (
                        client.clone(),
                        state.clone(),
                        measured_cycles.clone(),
                        desc_input_hash.clone(),
                        measuring.clone(),
                        measuring_inputs.clone(),
                        measure_strikes.clone(),
                        measured_journal.clone(),
                        desc_payload.clone(),
                        assigned_elsewhere.clone(),
                    );
                    tokio::spawn(async move {
                        // measure_cycles does all caching: it records desc->input, negative-caches a
                        // too-heavy guest (sized infeasible so it is never claimed nor re-measured),
                        // caches a real measurement by (backend, program, input), and leaves a
                        // transient failure uncached so it retries. Classification is by
                        // the backend's precise cap error, never a loose substring like "cycle".
                        // `inflight_inputs` collapses a concurrent same-input/different-tag
                        // burst to ONE execution per (backend, program, input).
                        measure_cycles(
                            &c2,
                            &st2,
                            backend,
                            &sizes2,
                            admitted,
                            jid,
                            dh,
                            pid,
                            &cache,
                            &resolver,
                            &inflight_inputs,
                            &strikes2,
                            &jcache2,
                            &pcache2,
                            &acache,
                            true,
                        )
                        .await;
                        // Clear the per-descriptor in-flight marker so a transient failure can retry.
                        if let Ok(mut m) = inflight.lock() {
                            m.remove(&dh);
                        }
                    });
                }
            }
            #[cfg(target_os = "macos")]
            if resolve_backend(snapshot.proof_system_id) == Some("risc0") {
                let limits = zkminer_prover_protocol::macos::Risc0Limits::from_environment(
                    std::env::var("ZKMINER_RISC0_WRAP").as_deref() == Ok("native"),
                );
                let compatible = limits.and_then(|limits| {
                    limits.validate_claim(known_cycles.unwrap_or(0), None)?;
                    Ok(limits)
                });
                let limits = match compatible {
                    Ok(limits) => limits,
                    Err(error) => {
                        tracing::debug!("Skipping {} before claim: {error}", short_id(jid));
                        continue;
                    }
                };
                let settings = state.read().await;
                if settings.runtime_settings.po2_overrides.iter().any(|((_, b), &po2)|
                    b == "risc0" && (limits.validate_po2(Some(po2)).is_err() || po2 != limits.default_segment_po2)) {
                    tracing::warn!("Skipping {} before claim: macOS claim timing requires the default segment setting", short_id(jid));
                    continue;
                }
            }

            // A bypassed claim occupies a GPU without being committed to the model, so the
            // model then UNDER-reports that device and the planner would place a later job as
            // though the card were idle — void at depth 1, not just depth 2. Refuse to plan
            // against a model we know is incomplete rather than plan against a fiction.
            let model_complete = queue_model.outstanding() == needing_card(&in_flight, &proved);
            let mut plan_rejection = None;
            let admission = if planner_active
                && measurable
                && model_complete
                && matches!(eval.recommendation, Recommendation::Claim)
            {
                // Collapse to THIS job's backend. See `device_backend_throughputs`.
                let job_backend = resolve_backend(snapshot.proof_system_id).unwrap_or("");
                // GENUINE per-backend rows only when any exist — NOT the padded
                // `throughputs_for_backend` list. The padding credits every card with no row for
                // this backend at the global-slowest throughput, which the planner's slot model then
                // treats as a real, idle proving slot: on an asymmetric rig (a card the backend
                // cannot run, e.g. an arch its binary does not cover) that is a PHANTOM slot, and the
                // planner over-admits — it believes it has more devices than can serve the backend,
                // places bonded jobs against the phantom, and the surplus misses its lock deadline
                // (release penalty / slash). Only when NO card has a genuine row for the backend do
                // we fall back to the padded list, so a never-measured backend is sized
                // conservatively rather than refused forever. This mirrors the live claim gate's
                // `slowest_eligible`, keeping the two admission gates' device sets consistent.
                let mut device_throughputs =
                    planner_throughputs_for_backend(&device_backend_throughputs, job_backend);
                // A risc0 job only on a card that proves risc0 jobs (the padded fallback can name
                // others).
                device_throughputs.retain(|(d, _)| risc0_job_device(job_backend, &risc0_cards, d));
                let slots = queue_model.slots(&device_throughputs);
                match zkminer_strategy::queue::plan_admission(
                    &slots,
                    queue_horizon,
                    params.estimated_cycles,
                    // Same provable window as the live evaluator (release/fulfill margins + fixed
                    // proving allowance already subtracted); the planner had the identical
                    // full-window-optimism defect.
                    std::time::Duration::from_secs(prove_window),
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
                        plan_rejection = Some(reason.clone());
                        // HorizonFull is the healthy saturated state; log the others, which
                        // mean we are being offered work this rig cannot serve.
                        if !matches!(reason, zkminer_strategy::queue::Rejection::HorizonFull) {
                            tracing::debug!(
                                "queue: not admitting {} ({:?}, cycles={}, {}s left)",
                                short_id(jid),
                                reason,
                                params.estimated_cycles,
                                time_remaining,
                            );
                        }
                        None
                    }
                }
            } else {
                None
            };

            // When the planner is inactive the old gate is the whole gate: `claim_ceiling`
            // equals `max_concurrent` (and a risc0 job is held to its cards, `risc0_bypass_room`).
            // A BYPASSED claim never faced `plan_admission`, so it has not earned the
            // look-ahead headroom and must be held to the pre-feature cap.
            //
            // This interaction is subtle: `claim_ceiling` rides `planner_active`, which is
            // per-TICK, while `measurable` is per-JOB. When every job declares zero cycles,
            // turning the horizon on would give `claim_ceiling = max_concurrent * 3` with
            // `plan_admission` never called and `queue_model` permanently empty: 3x claim depth and ZERO
            // admission checking, strictly worse than the feature being off.
            // A claim requires `measurable` on EVERY path. `admission.is_some()` already
            // implies it (the planner block is gated on `measurable`); the bypass path — the whole
            // gate at the default `queue_horizon_secs = 0` — must require it too. The old bypass was
            // `!planner_active || !measurable`, which let an UNMEASURED job claim on the submitter's
            // declared/fallback estimate, exactly the under-sizing an input-varying flood exploited.
            // Now an unmeasured measurable-backend job is skipped this tick (its measurement was
            // triggered above) and becomes claimable next tick on the real size. `claim_ceiling` and
            // the `max_concurrent` cap are unchanged, but for `risc0_bypass_room` below.
            let queue_bypass = !planner_active;
            // Without look-ahead a job is admitted to start now, one per card: a risc0 job only while
            // fewer risc0 jobs are in flight than cards that prove risc0 jobs (automatic concurrency
            // counts every GPU, and one with no risc0 size would queue a second job behind the first's
            // card).
            let risc0_job = backend_opt == Some(zkminer_prover_protocol::BACKEND_RISC0);
            let bypass_room = risc0_bypass_room(
                needing_card(&in_flight, &proved),
                other_backend_in_flight
                    .iter()
                    .filter(|j| !proved.contains(*j))
                    .count(),
                max_concurrent,
                risc0_job,
                risc0_cards.len(),
            );
            let would_commit = admission.is_some() || (queue_bypass && measurable && bypass_room);
            tally.note(Candidate {
                recommended: matches!(eval.recommendation, Recommendation::Claim),
                measurable,
                planner_active,
                model_complete,
                planned: admission.is_some(),
                rejection: plan_rejection.as_ref(),
                bypass_room,
            });
            // The share of the speed premium a fulfil can still earn falls with every exit from a
            // lock (a release or slash, which count as reopens, and a pause's grace release, which
            // doesn't), and the job view doesn't carry it. Read it only for a job about to take a
            // slot, after every other gate — the evaluation above used the full premium, an upper
            // bound — and decide again on it. Unreadable: assume none is left.
            if would_commit
                && params.speed_premium > 0
                && matches!(eval.recommendation, Recommendation::Claim)
            {
                params.premium_cap = Some(client.get_premium_cap(jid).await.unwrap_or(0));
                eval = evaluate_job(
                    &benchmarks,
                    &cost_params,
                    &params,
                    min_profit_threshold,
                    deadline_safety_margin,
                );
            }
            if would_commit && matches!(eval.recommendation, Recommendation::Claim) {
                claimed_this_tick = true;
                // Reserve the slot + collateral NOW (like the single-claim path always
                // did): inserting into in_flight immediately makes the loop-top
                // `in_flight.contains_key` guard dedup a job that appears twice in
                // open_jobs, and keeps this tick's collateral math correct. Remove from
                // open_jobs so we don't re-pick it before the claim lands. The batch is
                // dispatched after the loop; a job that doesn't actually lock has its
                // slot freed (done_tx) by the dispatch.
                in_flight.insert(jid, required_collateral);
                if !risc0_job {
                    other_backend_in_flight.insert(jid);
                }
                if backend_opt == Some(zkminer_prover_protocol::BACKEND_SP1) {
                    sp1_in_flight.insert(jid);
                }
                inflight_work.insert(jid, (params.estimated_cycles, backend_opt.unwrap_or("")));
                // Commit the admission to the backlog model, paired with the
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
                    // Its execute allowance too, which the planner's cycle estimate leaves out (its
                    // window had it taken off): a later job queues behind all of it.
                    let finishes_in = a.finishes_in + Duration::from_secs(execute_allowance);
                    queue_model.commit(jid.0, &a.device_id, finishes_in);
                    // Prefer the planner's per-device, backlog-aware device over the fastest-eligible
                    // hint set above; dispatch tries it first, with the same graceful fallback.
                    snapshot.preferred_device = Some(a.device_id.clone());
                    // Queued behind others, the job is done when the planner says, not one proof
                    // from now: watch-only holds its would-be claim that long.
                    snapshot.estimated_prove_secs = Some(finishes_in.as_secs());
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
                if needing_card(&in_flight, &proved) >= claim_ceiling
                    || batch.len() >= MAX_CLAIM_BATCH
                {
                    break;
                }
            }
        }

        // What admission saw this pass: why work that was offered was or was not claimed, and how
        // busy the planner thinks each card is. Debug only (`zkminer -v`).
        if tracing::enabled!(tracing::Level::DEBUG) && (tally.reached > 0 || !open_jobs.is_empty())
        {
            let slots = queue_model
                .slots(&planner_throughputs_for_backend(
                    &device_backend_throughputs,
                    zkminer_prover_protocol::BACKEND_RISC0,
                ))
                .iter()
                .map(|s| {
                    format!(
                        "{} {:.0}s@{:.1}M",
                        s.device_id,
                        s.backlog.as_secs_f64(),
                        s.throughput / 1e6
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            tracing::debug!(
                "queue: pass {tick_count}{}: planner {}, model {}/{} needing a card ({} held, \
                 ceiling {claim_ceiling}), {} open; {}; risc0 cards: {slots}",
                if ticked { "" } else { " (card freed)" },
                if planner_active { "on" } else { "off" },
                queue_model.outstanding(),
                needing_card(&in_flight, &proved),
                in_flight.len(),
                open_jobs.len(),
                tally,
            );
        }

        // ── Dispatch the collected claim batch ───────────────────────────────────
        // Re-check `paused` HERE. The snapshot taken at the top of this tick is many
        // awaits old (the candidate status multicall + per-system adapter fetches), and since
        // the brain is no longer aborted when shutdown begins — so a signal landing
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
        // that no fulfill and no release can free -- a jam can let jobs age past their lock
        // deadline exactly this way, and past the
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
            // We passed the rate-limit pause + freshness gates and are claiming, so
            // the endpoint is healthy again → decay the escalated claim-pause window to base.
            claim_backoff_mult = 1;
            last_storm_seen = None;
            // ALWAYS single-claim, inside the lifecycle task. Batch claiming (claimJobBatch) was
            // REMOVED: it cannot run the per-job PRE-CLAIM gates the lifecycle runs before bonding
            // collateral (the predicate gate and the predicate-unsatisfiable breaker both need a
            // descriptor fetch), so a batch-claimed bait job bonded collateral and was then released at
            // the 5% penalty — at claim-rate, not prove-rate. On HemiProve v2 it is also unclassifiable:
            // every entry needs its own exact floors read at a mined block, and a failed entry is a bare
            // `false` with no reason.
            for (job, snapshot, _collateral) in batch.drain(..) {
                let jid = job.info.job_id;
                // Already reserved in in_flight during collection.
                tracing::info!(
                    "CLAIM {} (price {}, in_flight {}/{}, {} held in all)",
                    short_id(jid),
                    job.current_price,
                    needing_card(&in_flight, &proved),
                    max_concurrent,
                    in_flight.len(),
                );
                spawn_lifecycle_task(
                    jid,
                    job,
                    snapshot,
                    false,
                    &client,
                    &state,
                    &journal,
                    &done_tx,
                    proving_timeout,
                    None,
                );
            }
        }

        // We evaluated open jobs but claimed none, purely for lack of collateral
        // → warn (throttled). The per-job eval reason is DEBUG-only, so without this an
        // idle miner gives no clue why. Only fires when at least one job was skipped
        // specifically for collateral (early skips / lost races don't trigger it).
        // A plain `if !claimed_this_tick` only ever detected TOTAL starvation:
        // in PARTIAL starvation the miner still funds one claim, so the flag would be true on
        // essentially every tick and the warning would be suppressed. That can hide a
        // collateral shortfall for hours — the miner keeps one GPU busy while others sit idle
        // and HEMI sits unstaked in the wallet, with the skips visible only as DEBUG lines.
        //
        // The capacity test below fires on partial starvation too. It is computed from the
        // ON-CHAIN available figure, NOT the loop residual in scope here: `locked` already
        // includes live in-flight locks (measured: in_flight 2/2 -> locked = baseline + 2x),
        // and the brain deliberately subtracts them AGAIN as a documented fail-safe, so
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
                        .is_none_or(|t| now.duration_since(t) >= COLLATERAL_WARN_EVERY);
                    if due {
                        last_collateral_warn = Some(now);
                        let stake_cmd = zkminer_chain::staking::fmt_hemi_ceil(h.shortfall);
                        tracing::warn!(
                            "{}",
                            collateral_warning(
                                h.fundable,
                                h.wanted,
                                on_chain_avail,
                                per_claim,
                                h.shortfall,
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
        // its `available_collateral` is the brain's residual, while the dashboard's
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
                    .is_none_or(|t| now.duration_since(t) >= COLLATERAL_WARN_EVERY);
                if due {
                    last_collateral_warn = Some(now);
                    // Labelled "spendable now" rather than "available": this is the residual
                    // after the in-flight fail-safe subtraction, deliberately smaller than both the
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
    /// `reopenCount`: at `MAX_REOPEN_COUNT` the router refuses every further claim.
    reopen_count: u8,
    current_price: u128,
    bonus_amount: u128,
    speed_premium: u128,
    fulfillment_timeout: u64,
    lock_deadline: u64,
    time_remaining: u64,
    expected_cycles: u64,
    descriptor_hash: alloy::primitives::B256,
    proof_system_id: alloy::primitives::B256,
    /// The cycle count this job was actually MEASURED at for its (backend, program,
    /// input), when known. `expected_cycles` above is the SUBMITTER-DECLARED on-chain field and is
    /// adversarial; admission already sizes feasibility on `max(declared, measured)`, but the prove
    /// path (watchdog timeout, min-VRAM routing, po2) must use the same quantity or a tiny declared
    /// value collapses the watchdog to its floor and SIGKILLs a job that was admitted feasible on the
    /// larger measured count — a submitter-driven premature kill → release-penalty/slash. Populated by
    /// the candidate loop from `resolve_measured`; `None` on paths without a measurement (recovery,
    /// non-measurable backends), where the sizing falls back to the FALLBACK floor, never below it.
    measured_cycles: Option<u64>,
    /// This job's pre-claim measured EXECUTE peak host RSS (bytes) for its (backend, program, input),
    /// when known (SP1 only). Threaded into the prove reservation so the dispatcher charges the SP1
    /// execute spike — `server + execute` — to the host ledger and refuses a concurrent other-backend
    /// proof that would OOM during the execute window (finding RH2). `None` = unknown / not SP1.
    measured_peak: Option<u64>,
    /// Benchmark device id (e.g. "gpu1") of the card this job was sized/planned for at claim time,
    /// passed to the dispatcher as a PREFERENCE (tried first, graceful fallback). `None` on paths
    /// without a plan (recovery, non-measurable backends). See `prove_min_vram`'s `preferred_device`.
    preferred_device: Option<String>,
    /// keccak256 of the risc0 ELF whose image-id was verified when this (program, input) was measured,
    /// resolved from the measurement cache entry alongside `measured_cycles` (so it co-evicts with it).
    /// Threaded into `fetch_or_download_elf` on the claim-obtainability and prove fetches as the
    /// whole-ELF integrity hash for risc0 (which has no registry `elf_hash`), so a post-measure ELF
    /// swap is rejected at the re-fetch rather than reaching prove as a penalized release + permanent
    /// blacklist. `None` for SP1 (bound by `elf_hash`), recovery, and risc0 with no measured binding.
    verified_elf_hash: Option<alloy::primitives::B256>,
    /// The journal this (program, input) measured, with the keccak of that input, resolved from the
    /// same cache entry as `measured_cycles`. The lifecycle checks a journal-bound job's binding
    /// against it before claiming. `None` on recovery and wherever no whole journal was measured.
    measured_journal: MeasuredJournal,
    /// How long this (program, input)'s measuring execute took, in whole seconds, from the same
    /// cache entry as `measured_cycles`. The prove path's watchdog and the claim's window allow for
    /// it (see [`execute_allowance_secs`]). `None` without a measurement.
    measured_execute_secs: Option<u64>,
    /// The slowest rate (cycles/s) the claim gate sized this job's proof at, on the slowest card that may
    /// take it; the prove watchdog never assumes a faster one. `None` on recovery.
    planning_cps: Option<f64>,
    /// The segment sizes a risc0 job measured clean at (every card size here, when it was claimed):
    /// it is proven only on a card at one of them. Empty for other backends and on recovery, which
    /// reads them from the job's breadcrumb (see [`risc0_prove_sizes`]).
    measured_po2s: Vec<u8>,
    /// How long the claim gate estimated this job's proof to take, when it evaluated it. A
    /// watch-only "would claim" holds its slot and collateral this long, as a real one would.
    estimated_prove_secs: Option<u64>,
    /// A live bid's bidder on a competitive job (zero: none), and when its round ends.
    current_bidder: alloy::primitives::Address,
    bid_deadline: u64,
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
            reopen_count: v.reopenCount,
            current_price: v.currentAuctionPrice.to::<u128>(),
            bonus_amount: v.bonusAmount.to::<u128>(),
            speed_premium: v.speedPremium.to::<u128>(),
            fulfillment_timeout: time_remaining,
            lock_deadline: effective_cutoff(v),
            time_remaining,
            expected_cycles: v.expectedCycles,
            descriptor_hash: v.descriptorHash,
            proof_system_id: v.proofSystemId,
            // Set by the candidate loop once the measurement for this (backend, program, input) is
            // resolved; the view itself carries no measured count.
            measured_cycles: None,
            measured_peak: None,
            preferred_device: None,
            verified_elf_hash: None,
            measured_journal: None,
            measured_execute_secs: None,
            measured_po2s: Vec::new(),
            planning_cps: None,
            estimated_prove_secs: None,
            current_bidder: v.currentBidder,
            bid_deadline: u64::try_from(v.bidDeadline).unwrap_or(u64::MAX),
        }
    }
}

/// Bound on the watch-only per-job maps; past it they are cleared (reporting a job again is harmless).
const WATCH_MAP_CAP: usize = 4096;

/// Jobs a watch-only run reported it would claim.
static WATCH_WOULD_CLAIM: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Jobs as they enter the Open set, for the watch-only inspector. Queued at ingestion rather than
/// read from `open_jobs`, because the brain can evict a job (a failing binding, say) before the
/// inspector's next pass. Bounded: past the cap the oldest are dropped.
static WATCH_QUEUE: Mutex<std::collections::VecDeque<TrackedJob>> =
    Mutex::new(std::collections::VecDeque::new());

/// Queue a newly ingested job for the watch-only inspector (a no-op unless watching).
fn watch_enqueue(job: &TrackedJob) {
    if !watch_only() {
        return;
    }
    let mut q = WATCH_QUEUE.lock().unwrap_or_else(|p| p.into_inner());
    if q.len() >= WATCH_MAP_CAP {
        if let Some(old) = q.pop_front() {
            tracing::warn!(
                "watch-only: inspector backlog full — job {} will get no verdict",
                short_id(old.info.job_id)
            );
        }
    }
    q.push_back(job.clone());
}

/// Log a watch-only verdict for `job_id`, unless it is the verdict last logged for it (a job retried
/// after a back-off with the same outcome). Returns whether it was logged.
fn watch_report(job_id: B256, verdict: String) -> bool {
    static LAST: Mutex<Option<HashMap<B256, String>>> = Mutex::new(None);
    let mut g = LAST.lock().unwrap_or_else(|p| p.into_inner());
    let last = g.get_or_insert_with(HashMap::new);
    if last.get(&job_id) == Some(&verdict) {
        return false;
    }
    if last.len() >= WATCH_MAP_CAP {
        last.clear();
    }
    tracing::info!("WATCH {}: {verdict}", short_id(job_id));
    last.insert(job_id, verdict);
    true
}

/// The job's journal binding as the router reads it: NONE, FULL or FIELDS, plus a slot-0 marker.
fn describe_binding(d: &zkminer_contracts::bindings::JobDescriptor) -> String {
    use zkminer_chain::binding::{marker, JOURNAL_PREFIX_MARKER};
    let mut fields = d.journalFields;
    let m = marker(fields);
    if m.is_some() {
        fields.0[..4].fill(0);
    }
    let kind = if d.expectedJournalHash == B256::ZERO {
        "NONE"
    } else if fields == B256::ZERO {
        "FULL"
    } else {
        "FIELDS"
    };
    match m {
        Some(JOURNAL_PREFIX_MARKER) => format!("{kind} + journal-prefix"),
        Some(_) => format!("{kind} + SP1 proof-nonce"),
        None => kind.to_string(),
    }
}

/// Collateral watch-only's would-be claims would hold locked on-chain right now (see
/// `watch_claim_preview`).
static WATCH_LOCKED_COLLATERAL: std::sync::Mutex<u128> = std::sync::Mutex::new(0);

fn watch_locked_collateral() -> u128 {
    *WATCH_LOCKED_COLLATERAL
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn add_watch_locked_collateral(amount: u128, add: bool) {
    let mut g = WATCH_LOCKED_COLLATERAL
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    *g = if add {
        g.saturating_add(amount)
    } else {
        g.saturating_sub(amount)
    };
}

/// Watch-only stand-in for the claim: what `claim_job_idempotent` would meet for this job now, read
/// with the same pre-checks and quote and logged as the job's verdict. A job that would be claimed
/// leaves the Open set, as a claimed one does; a temporary refusal keeps it a candidate behind the
/// back-off a real refusal gets.
async fn watch_claim_preview(
    client: &ChainClient,
    state: &zkminer_tui::state::SharedState,
    job: &TrackedJob,
    snapshot: &JobStatusSnapshot,
) {
    use zkminer_chain::jobs::ClaimPreview;
    use zkminer_chain::revert::{ClaimClass, ClaimFailure};
    let job_id = job.info.job_id;
    let measured = snapshot.measured_cycles.map_or_else(
        || "unmeasured".to_string(),
        |c| format!("{c} cycles measured"),
    );
    let mut would_claim_price = None;
    let (verdict, would_claim, keep) = match client.preview_claim(job_id).await {
        Ok(ClaimPreview::Claimable(q)) => (
            format!(
                "WOULD CLAIM at {} HEMI (premium cap {} HEMI, quoted at block {}); {measured}",
                fmt_hemi(q.price_floor),
                fmt_hemi(q.premium_floor),
                q.block
            ),
            {
                would_claim_price = Some(q.price_floor);
                true
            },
            false,
        ),
        Ok(ClaimPreview::Held(p)) => (
            format!("would not claim: already held by {p}"),
            false,
            false,
        ),
        Err(e) => match e.downcast_ref::<ClaimFailure>() {
            Some(f) => {
                let keep = matches!(
                    f.class,
                    ClaimClass::Wait | ClaimClass::Paused | ClaimClass::StakeShort
                );
                if keep {
                    note_claim_retry_after(job_id, f.class);
                }
                (
                    format!(
                        "would not claim: the claim would be refused ({:?}): {}",
                        f.class, f.reason
                    ),
                    false,
                    keep,
                )
            }
            None => {
                note_transient_preclaim_failure(job_id);
                (
                    format!(
                        "no verdict yet: the claim quote is unreadable ({})",
                        zkminer_chain::programs::sanitize_log(&format!("{e:#}"))
                    ),
                    false,
                    true,
                )
            }
        },
    };
    if watch_report(job_id, verdict) && would_claim {
        WATCH_WOULD_CLAIM.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    if keep {
        requeue_open_job(state, job.clone()).await;
    } else {
        state
            .write()
            .await
            .open_jobs
            .retain(|j| j.info.job_id != job_id);
    }
    if would_claim {
        // A claimed job holds its slot and its collateral until it is fulfilled. Hold them here for
        // as long (the proof's estimate, and a claim and a fulfil to mine), so what follows is decided
        // with the capacity and stake a real claim would have left, up to the job's fulfilment window
        // (from its submit event: an Open job's view reads no window). The caller's slot guard frees
        // them on return.
        const CLAIM_AND_FULFIL_SECS: u64 = 30;
        let hold = Duration::from_secs(
            snapshot
                .estimated_prove_secs
                .unwrap_or(0)
                .saturating_add(CLAIM_AND_FULFIL_SECS)
                .min(job.info.fulfillment_timeout.max(CLAIM_AND_FULFIL_SECS)),
        );
        // A real lock takes this collateral out of `getAvailableCollateral` on top of the brain's
        // reservation; the chain doesn't here, so count it until the hold ends.
        let locked = match (would_claim_price, job_collateral_terms(job_id)) {
            (Some(price), Some((min, bps))) => zkminer_chain::auction::compute_collateral(
                price,
                u64::try_from(bps).unwrap_or(u64::MAX),
                min,
            ),
            _ => 0,
        };
        add_watch_locked_collateral(locked, true);
        let until = std::time::Instant::now() + hold;
        while std::time::Instant::now() < until
            && !SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst)
        {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        add_watch_locked_collateral(locked, false);
    }
}

/// The watch-only inspector's measurement caches, apart from the brain's.
struct WatchCaches {
    measured: MeasuredCache,
    desc_input: DescInputCache,
    measuring: Arc<Mutex<HashMap<B256, u8>>>,
    measuring_inputs: Arc<Mutex<std::collections::HashSet<(u8, B256, B256)>>>,
    measure_strikes: MeasureStrikes,
    measured_journal: JournalLenCache,
    desc_payload: DescPayloadCache,
    assigned_elsewhere: AssignedElsewhere,
}

/// A job the watch-only inspector has no verdict on yet.
struct Pending {
    job: TrackedJob,
    /// The first try (a job waits its turn behind slow inspections without using up its time).
    since: Option<std::time::Instant>,
    next_try: std::time::Instant,
    gap: Duration,
}

/// What the watch-only inspector concluded about one job.
enum Inspected {
    /// A final verdict, under a category for the periodic summary.
    Done(&'static str, String),
    /// Nothing conclusive yet (an RPC failure, a busy measure pool): try again on a later pass.
    Retry(String),
}

/// Watch-only: take every job that enters the Open set (`WATCH_QUEUE`) through the checks a claim
/// depends on, and report each once.
///
/// The brain measures only a job it would claim on this host, given its GPUs, benchmarks and stake,
/// so on a host that cannot prove, or as an address with no stake, it would check nothing. This
/// runs the same steps regardless: the job's view, its hash-verified descriptor, its journal binding,
/// a measurement (served backends only) with the binding checked against the measured journal, and
/// the claim quote for the watched address. What the brain itself would claim is reported at the
/// claim step (`watch_claim_preview`).
async fn watch_inspector(
    client: ChainClient,
    state: zkminer_tui::state::SharedState,
    caches: WatchCaches,
) {
    const PASS_EVERY: Duration = Duration::from_secs(5);
    const SUMMARY_EVERY: Duration = Duration::from_secs(600);
    // How long a job may stay inconclusive (waiting on a measurement the brain runs, a busy measure
    // pool, a slow source) before it is reported as such: a measurement's whole budget, and some.
    const GIVE_UP_AFTER: Duration =
        Duration::from_secs(MEASURE_TIMEOUT.as_secs() + 2 * MEASURE_FETCH_BUDGET.as_secs() + 60);
    const MAX_RETRY_GAP: Duration = Duration::from_secs(60);
    let started = std::time::Instant::now();
    let mut last_summary = started;
    let mut done: std::collections::HashSet<B256> = std::collections::HashSet::new();
    // Jobs taken off `WATCH_QUEUE` with no verdict yet: since when, the next try, and the gap to the
    // one after (doubling up to MAX_RETRY_GAP).
    let mut pending: Vec<Pending> = Vec::new();
    let mut tally: std::collections::BTreeMap<&'static str, u64> =
        std::collections::BTreeMap::new();
    loop {
        tokio::time::sleep(PASS_EVERY).await;
        {
            let mut q = WATCH_QUEUE.lock().unwrap_or_else(|p| p.into_inner());
            for job in q.drain(..) {
                let id = job.info.job_id;
                if !done.contains(&id) && !pending.iter().any(|p| p.job.info.job_id == id) {
                    let now = std::time::Instant::now();
                    pending.push(Pending {
                        job,
                        since: None,
                        next_try: now,
                        gap: PASS_EVERY,
                    });
                }
            }
        }
        if pending.len() > WATCH_MAP_CAP {
            for p in pending.drain(..pending.len() - WATCH_MAP_CAP) {
                tracing::warn!(
                    "watch-only: inspector backlog full — job {} will get no verdict",
                    short_id(p.job.info.job_id)
                );
            }
        }
        let mut still_pending = Vec::new();
        for mut p in std::mem::take(&mut pending) {
            if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            if std::time::Instant::now() < p.next_try {
                still_pending.push(p);
                continue;
            }
            let job_id = p.job.info.job_id;
            let since = *p.since.get_or_insert_with(std::time::Instant::now);
            let (category, verdict) = match watch_inspect(&client, &state, &p.job, &caches).await {
                Inspected::Done(category, verdict) => (category, verdict),
                Inspected::Retry(why) if since.elapsed() < GIVE_UP_AFTER => {
                    tracing::debug!("WATCH {}: no verdict yet ({why})", short_id(job_id));
                    p.next_try = std::time::Instant::now() + p.gap;
                    p.gap = (p.gap * 2).min(MAX_RETRY_GAP);
                    still_pending.push(p);
                    continue;
                }
                Inspected::Retry(why) => (
                    "inconclusive",
                    format!("no verdict after {}s: {why}", since.elapsed().as_secs()),
                ),
            };
            if done.len() >= WATCH_MAP_CAP {
                done.clear();
            }
            done.insert(job_id);
            *tally.entry(category).or_insert(0) += 1;
            watch_report(job_id, verdict);
        }
        pending = still_pending;
        if last_summary.elapsed() >= SUMMARY_EVERY {
            last_summary = std::time::Instant::now();
            let parts: Vec<String> = tally.iter().map(|(c, n)| format!("{c} {n}")).collect();
            tracing::info!(
                "WATCH summary after {} min: {} jobs inspected ({}); {} would be claimed by this host",
                started.elapsed().as_secs() / 60,
                tally.values().sum::<u64>(),
                parts.join(", "),
                WATCH_WOULD_CLAIM.load(std::sync::atomic::Ordering::Relaxed)
            );
        }
    }
}

/// One job through the watch-only inspection (see [`watch_inspector`]).
async fn watch_inspect(
    client: &ChainClient,
    state: &zkminer_tui::state::SharedState,
    job: &TrackedJob,
    c: &WatchCaches,
) -> Inspected {
    use zkminer_chain::jobs::ClaimPreview;
    use zkminer_chain::programs::sanitize_log;
    let job_id = job.info.job_id;
    let program_id = job.info.program_id;
    let view = match client.get_job_status_view(job_id).await {
        Ok(v) => v,
        Err(e) => return Inspected::Retry(format!("status view unreadable: {e:#}")),
    };
    if view.status != 0 || view.prover != alloy::primitives::Address::ZERO {
        return Inspected::Done(
            "no longer open",
            format!(
                "no longer open (status {}, prover {})",
                view.status, view.prover
            ),
        );
    }
    let system = zkminer_chain::auction::ProofSystem::from_id(view.proofSystemId).map_or_else(
        || format!("unknown proof system {}", view.proofSystemId),
        |p| p.label().to_string(),
    );
    let d = match tokio::time::timeout(
        MEASURE_FETCH_BUDGET,
        fetch_job_descriptor_checked(client, job_id, view.descriptorHash),
    )
    .await
    {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            let why = sanitize_log(&format!("{e:#}"));
            return if e
                .downcast_ref::<zkminer_chain::descriptor::UndecodableDescriptor>()
                .is_some()
            {
                Inspected::Done(
                    "descriptor undecodable",
                    format!("{system}: its descriptor is undecodable ({why})"),
                )
            } else {
                Inspected::Retry(format!("descriptor fetch failed: {why}"))
            };
        }
        Err(_) => return Inspected::Retry("descriptor fetch timed out".into()),
    };
    let head = format!(
        "{system}, {} binding, {} B input",
        describe_binding(&d),
        d.inputData.len()
    );
    let Some(backend) = resolve_backend(view.proofSystemId) else {
        return Inspected::Done("not served", format!("{head}: not served by this build"));
    };
    if zkminer_chain::binding::marker(d.journalFields).is_some() {
        return Inspected::Done(
            "binding unsupported",
            format!("{head}: its binding marker is not supported by this build"),
        );
    }
    if d.expectedJournalHash == B256::ZERO && d.assignedProver != client.address {
        return Inspected::Done(
            "reserved elsewhere",
            format!("{head}: reserved for prover {}", d.assignedProver),
        );
    }
    if d.assignedProver != alloy::primitives::Address::ZERO && d.assignedProver != client.address {
        match assigned_exclusivity_wait(client, job_id).await {
            Ok(None) => {}
            Ok(Some(_)) => {
                return Inspected::Done(
                    "assigned elsewhere",
                    format!(
                        "{head}: assigned to prover {}, and its exclusivity has not lapsed",
                        d.assignedProver
                    ),
                )
            }
            Err(e) => return Inspected::Retry(format!("job record unreadable: {e:#}")),
        }
    }
    if d.expectedJournalHash != B256::ZERO
        && !state.read().await.runtime_settings.claim_predicate_jobs
    {
        return Inspected::Done(
            "bound, opted out",
            format!("{head}: journal-bound, and claim_predicate_jobs is off"),
        );
    }
    let dh = view.descriptorHash;
    // At the size of every card here that proves risc0 jobs, as the brain measures it; on a host with
    // no risc0 card at all (watch-only reports whatever this host's GPUs), at the default size.
    let mut risc0_sizes = risc0_job_sizes(&current_risc0_cards(state, true).await);
    if risc0_sizes.is_empty()
        && zkminer_prover::engine::worker_pool().is_none_or(|p| p.risc0_slots().is_empty())
    {
        risc0_sizes.push(zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2);
    }
    let sizes = measure_sizes(backend, &risc0_sizes);
    if sizes.is_empty() {
        return Inspected::Done(
            "no card",
            format!(
                "{head}: no enabled card here proves risc0 jobs (one with under 14 GiB of VRAM needs \
                 a size: `prover.risc0_job_po2` in the config, or a calibration on an NVIDIA card)"
            ),
        );
    }
    let resolve =
        || resolve_measured_at(&c.measured, &c.desc_input, backend, &sizes, program_id, dh);
    if resolve().is_none() {
        if zkminer_prover::engine::worker_pool()
            .and_then(|p| p.measure_worker_count(backend))
            .is_none()
        {
            return Inspected::Done(
                "not measurable here",
                format!("{head}: this host has no {backend} measure worker"),
            );
        }
        // Its own in-flight set: one measuring task per descriptor at a time.
        let fresh = c
            .measuring
            .lock()
            .map(|mut m| match m.entry(dh) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(backend_tag(backend));
                    true
                }
                std::collections::hash_map::Entry::Occupied(_) => false,
            })
            .unwrap_or(false);
        if !fresh {
            return Inspected::Retry("being measured".into());
        }
        measure_cycles(
            client,
            state,
            backend,
            &sizes,
            sizes.len(),
            job_id,
            dh,
            program_id,
            &c.measured,
            &c.desc_input,
            &c.measuring_inputs,
            &c.measure_strikes,
            &c.measured_journal,
            &c.desc_payload,
            &c.assigned_elsewhere,
            false,
        )
        .await;
        if let Ok(mut m) = c.measuring.lock() {
            m.remove(&dh);
        }
    }
    // Checked before the measurement: an over-cap descriptor is refused without one.
    if desc_is_unfulfillable(&c.desc_input, dh) {
        return Inspected::Done(
            "payload over cap",
            format!("{head}: its fulfil payload would exceed the cap"),
        );
    }
    let Some(ResolvedMeasurement {
        cycles, journal, ..
    }) = resolve()
    else {
        return if job_is_undecodable(job_id) {
            Inspected::Done(
                "dropped at measure",
                format!("{head}: dropped while measuring (see the log above)"),
            )
        } else {
            Inspected::Retry("no measurement (see the log above)".into())
        };
    };
    if cycles >= UNMEASURABLE_CYCLES {
        return Inspected::Done(
            "unmeasurable",
            format!(
                "{head}: it cannot be measured (its ELF failed to fetch or execute, it hit the \
                 execute cap, its journal is over the cap, or its journal depends on the segment \
                 size; see the log above)"
            ),
        );
    }
    let at = if backend == zkminer_prover_protocol::BACKEND_RISC0 {
        let sizes: Vec<String> = sizes.iter().map(u8::to_string).collect();
        format!(", at po2 {}", sizes.join("/"))
    } else {
        String::new()
    };
    let measured = format!(
        "{cycles} cycles, {}{at}",
        journal.as_ref().map_or_else(
            || "journal not reported".to_string(),
            |(_, j)| format!("{} B journal", j.len())
        )
    );
    let bound = if d.expectedJournalHash == B256::ZERO {
        "no journal binding"
    } else {
        match measured_binding_verdict(&d, &journal, job_id, client.address) {
            Some(Ok(())) => "binding satisfied",
            Some(Err(why)) => {
                return Inspected::Done(
                    "binding fails",
                    format!("{head}: {measured}; the measured journal FAILS its binding ({why})"),
                )
            }
            None => {
                return Inspected::Done(
                    "no journal to check",
                    format!("{head}: {measured}; no whole journal to check the binding against"),
                )
            }
        }
    };
    match client.preview_claim(job_id).await {
        Ok(ClaimPreview::Claimable(q)) => Inspected::Done(
            "claim quote ok",
            format!(
                "{head}: {measured}, {bound}; claim quote {} HEMI (premium cap {} HEMI)",
                fmt_hemi(q.price_floor),
                fmt_hemi(q.premium_floor)
            ),
        ),
        Ok(ClaimPreview::Held(p)) => Inspected::Done(
            "no longer open",
            format!("{head}: {measured}, {bound}; now held by {p}"),
        ),
        Err(e) => match e.downcast_ref::<zkminer_chain::revert::ClaimFailure>() {
            Some(f) => Inspected::Done(
                "claim refused",
                format!(
                    "{head}: {measured}, {bound}; the claim would be refused ({:?}): {}",
                    f.class, f.reason
                ),
            ),
            None => Inspected::Retry(format!(
                "claim quote unreadable: {}",
                sanitize_log(&format!("{e:#}"))
            )),
        },
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
    prefetched_descriptor: Option<zkminer_contracts::bindings::JobDescriptor>,
) {
    let client = client.clone();
    let state = state.clone();
    let journal = journal.clone();
    let done_tx = done_tx.clone();
    tokio::spawn(async move {
        // Frees the concurrency slot on return OR panic.
        let _slot = SlotGuard(jid, done_tx);
        let outcome = process_job_lifecycle(
            &client,
            &state,
            &journal,
            job,
            snapshot,
            proving_timeout,
            already_locked,
            prefetched_descriptor,
        )
        .await;
        if let Err(e) = outcome {
            // A lock we hold that must NOT be released (a pause / disable hold, an unreadable post-
            // claim state): keep the breadcrumb, leave the stashed fulfil nonce for the re-drive or
            // a later release to resume, and ask recovery to pick it up.
            if let Some(h) = e.downcast_ref::<HandBack>() {
                tracing::warn!("KEEP: job {} {h}", short_id(jid));
                let mut s = state.write().await;
                s.active_jobs.retain(|j| j.info.job_id != jid);
                s.add_log(
                    zkminer_tui::state::LogLevel::Warn,
                    format!("Job {} kept: {}", short_id(jid), h.0),
                );
                request_recovery();
                return;
            }
            // The lifecycle error can carry a guest-controlled proof-failure
            // message (a worker Error.message surfaced as anyhow). Sanitize before it reaches the
            // operator's console/log or the TUI, so it cannot inject terminal escapes / forge lines.
            let emsg = zkminer_chain::programs::sanitize_log(&format!("{e:#}"));
            tracing::error!("Job {} lifecycle error: {emsg}", short_id(jid));
            {
                let mut s = state.write().await;
                s.add_log(
                    zkminer_tui::state::LogLevel::Error,
                    format!("Job {} failed: {emsg}", short_id(jid)),
                );
            }
            // Release the on-chain claim to unlock collateral and avoid slashing. If we
            // never claimed (pre-claim error), there's no journal entry and
            // release_and_clean is skipped.
            if journal_has(&journal, jid) {
                release_and_clean(&client, &state, &journal, jid).await;
            } else {
                // No breadcrumb → release is skipped. If a fulfill nonetheless
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
    // A descriptor the caller already fetched+verified (recovery does), to
    // skip the re-fetch at step 6. Always `None` for fresh jobs.
    prefetched_descriptor: Option<zkminer_contracts::bindings::JobDescriptor>,
) -> Result<()> {
    // This job's claim on a card, handed back once proving is over (below), or on any return before
    // that: either way the card's next job may be admitted while this one is fulfilled or released.
    let mut card = CardRelease(Some(job.info.job_id));
    use zkminer_tui::state::{LogLevel, MinerJobStatus};

    let job_id = job.info.job_id;
    let program_id = job.info.program_id;
    // The brain removed this job from `open_jobs` at dispatch; a TEMPORARY pre-claim refusal puts
    // it back (see `requeue_open_job`).
    let requeue_job = job.clone();
    // For the post-claim divergence breaker: who submitted it, and whether this claim rode a clean
    // pre-claim measurement of its (program, input) (recovery jobs carry none).
    let submitter = job.info.caller;
    let rode_measurement = !is_recovery && snapshot.measured_cycles.is_some();

    // Shutdown can begin between `spawn_lifecycle_task` and here. The brain's
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

    // A prior prove already proved this program's served ELF can never satisfy its on-chain
    // programId (SP1 vkey / risc0 image-id mismatch). The brain's claim gate skips such programs,
    // but a job can be evaluated as claimable at one tick and spawned into this task just as a
    // CONCURRENT sibling's prove marks the program — so re-check here, the last point before any
    // collateral is locked, and drop the fresh job (nothing is on-chain yet). This keeps a decoy
    // program's damage to the one claim wave already in flight when its first prove faulted, instead
    // of letting spawn-window stragglers lock still more collateral. Fresh jobs only: a recovery job
    // already holds its lock and MUST be driven to prove→release by the normal path (its prove faults
    // terminally and `release_and_clean` frees the collateral) — bailing here would strand it to a slash.
    if !is_recovery && program_vkey_mismatched_for(program_id, snapshot.proof_system_id) {
        tracing::debug!(
            "Dropping {} before claim: its program's served ELF cannot satisfy its programId under \
             this backend (vkey/image-id mismatch seen on a prior prove) — nothing locked",
            short_id(job_id)
        );
        let mut s = state.write().await;
        s.open_jobs.retain(|j| j.info.job_id != job_id);
        return Ok(());
    }
    // The same last-moment re-check for the divergence breaker and the proof system's verification
    // (either can flip while this task was being dispatched). Temporary, so the job is put back.
    if !is_recovery && claims_held_for(snapshot.proof_system_id, submitter, program_id) {
        tracing::debug!(
            "Not claiming {} now: the divergence breaker, or the deployment or proof-system check, \
             holds claims — nothing locked",
            short_id(job_id)
        );
        note_job_retry_after(job_id, Duration::from_secs(300));
        requeue_open_job(state, requeue_job.clone()).await;
        return Ok(());
    }

    // 0. Pre-claim binding gate (HemiProve v2, handoff §8). Every open-market job is FULL- or
    //    FIELDS-bound (`expectedJournalHash != 0`): a NONE job (both binding words 0) must name an
    //    `assignedProver`, and only that prover can ever lock it. A fulfil whose journal does not
    //    satisfy the binding reverts `JournalMismatch`, after the lock. Decide BEFORE locking
    //    collateral; recovery jobs are already locked and are never skipped here.
    // The descriptor verified here is kept for the prove and fulfil steps: it is immutable, and
    // re-fetching it after the lock could only add a way to fail on a lock we hold.
    let mut descriptor_in_hand = prefetched_descriptor;
    if !is_recovery {
        let claim_predicate = state.read().await.runtime_settings.claim_predicate_jobs;
        // Bounded, hash-VERIFIED fetch: the job holds an in_flight slot, so a black-holing source must
        // not wedge it, and the gate must act on the descriptor the router will hash at fulfil.
        let descriptor = with_deadline_budget(
            snapshot.lock_deadline,
            "binding descriptor fetch",
            job_id,
            fetch_job_descriptor_checked(client, job_id, snapshot.descriptor_hash),
        )
        .await;
        let skip = |why: String, drop: bool| async move {
            let mut s = state.write().await;
            if drop {
                s.open_jobs.retain(|j| j.info.job_id != job_id);
            }
            s.add_log(LogLevel::Info, format!("Skipping job {}: {why}", short_id(job_id)));
        };
        let d = match descriptor {
            Ok(d) => d,
            // FAIL CLOSED: a descriptor we cannot verify is one whose fulfil would revert
            // `InvalidDescriptorHash` — never claim it. A permanent verdict drops the job; a transient
            // one keeps it a candidate for a later tick.
            Err(e) => {
                let permanent = e
                    .downcast_ref::<zkminer_chain::descriptor::UndecodableDescriptor>()
                    .is_some();
                tracing::warn!(
                    "not claiming {}: descriptor unverifiable ({})",
                    short_id(job_id),
                    zkminer_chain::programs::sanitize_log(&format!("{e:#}"))
                );
                if permanent {
                    mark_job_undecodable(job_id);
                } else {
                    note_transient_preclaim_failure(job_id);
                    requeue_open_job(state, requeue_job.clone()).await;
                }
                skip("its descriptor cannot be verified".into(), permanent).await;
                return Ok(());
            }
        };
        // A binding MARKER in journalFields slot 0 (0xffffffff journal prefix `jobId ‖ prover`,
        // 0xfffffffe SP1 proof nonce) needs a guest input / patched prover this build does not have.
        let marker = u32::from_be_bytes(d.journalFields.0[..4].try_into().unwrap());
        if marker >= 0xffff_fffe {
            skip(format!("binding marker 0x{marker:08x} is not supported by this build"), true).await;
            return Ok(());
        }
        if d.expectedJournalHash == alloy_primitives::B256::ZERO {
            // NONE job: reserved for its assigned prover for the job's whole life.
            if d.assignedProver != client.address {
                skip("a NONE-bound job reserved for another prover".into(), true).await;
                return Ok(());
            }
        } else {
            if !claim_predicate {
                // FULL/FIELDS job and the operator opted out of journal-bound jobs (since the brain
                // dispatched it). Recorded and put back, as the measure path does, not dropped: the
                // setting is read live (though only the config sets it today).
                mark_job_bound(job_id);
                requeue_open_job(state, requeue_job.clone()).await;
                skip("journal-bound (claim_predicate_jobs=false)".into(), false).await;
                return Ok(());
            }
            // A recent real fulfil showed this exact binding unsatisfiable: claiming again bonds
            // collateral, burns a proof, and releases at a penalty for a guaranteed JournalMismatch.
            if predicate_unsatisfiable(&predicate_key(&d)) {
                skip(
                    "its journal binding was shown unsatisfiable by a recent fulfil".into(),
                    true,
                )
                .await;
                return Ok(());
            }
            // The local binding check: the router's own check, on the journal this (program, input)
            // measured, against the hash-verified descriptor the fulfil will carry. Only a journal
            // that satisfies it is worth locking collateral for.
            match measured_binding_verdict(&d, &snapshot.measured_journal, job_id, client.address) {
                Some(Ok(())) => {}
                Some(Err(why)) => {
                    mark_job_undecodable(job_id);
                    skip(
                        format!("its measured journal does not satisfy its binding ({why})"),
                        true,
                    )
                    .await;
                    return Ok(());
                }
                None => {
                    // No whole journal measured on exactly this input: not provably satisfiable.
                    note_transient_preclaim_failure(job_id);
                    requeue_open_job(state, requeue_job.clone()).await;
                    skip(
                        "no measured journal to check its binding against yet".into(),
                        false,
                    )
                    .await;
                    return Ok(());
                }
            }
        }
        descriptor_in_hand = Some(d);
    }

    // Re-check HERE, not only at the top of this fn. The guard above runs BEFORE the
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

    // Pin this program's cached ELF NOW — BEFORE the obtainability fetch warms it and before the
    // claim — and hold the guard through prove, so the on-disk LRU cannot evict the just-warmed bytes
    // during the fetch->claim->prove window. ElfCache::get is a bare read that does NOT refresh mtime,
    // so a cache-hit victim keeps its old measurement-time mtime and, unpinned, a concurrent decoy
    // measurement's put->prune (oldest-mtime-first) would evict it — turning the claim into a
    // prove-time fetch miss and a penalized release. Covers fresh (fetch+claim+prove) and recovery
    // (prove). Dropped automatically when this task ends (every path).
    let _elf_pin = zkminer_chain::programs::ElfPin::new(program_id);

    // Confirm the ELF is actually obtainable BEFORE committing collateral. A claim can
    // ride on a cached cycle MEASUREMENT (process-lifetime cache) whose ELF has since been evicted from
    // the much smaller on-disk LRU; the ELF is otherwise first (re)fetched only at prove time (step 7),
    // so a submitter who takes the storage URI offline after measurement turns the claim into a
    // post-claim release-penalty (or a slash if release cannot land). Fetching now makes a withheld ELF
    // a free PRE-claim skip instead. Common case: a disk-cache hit (cheap, no network — fetch_or_...
    // checks the cache first). Fresh jobs only: a recovery job is already locked and MUST be driven. We
    // do not thread the bytes to step 7 (it re-reads the now-warm cache); correctness over micro-opt.
    // The bytes fetched here are kept for the prove: nothing between the claim and the prove may read
    // the cache or the network again. A sibling job carrying a different ELF hash for the same program
    // can purge the on-disk entry (and the host can then withhold it), which would turn a healthy lock
    // into a release.
    let mut elf_in_hand: Option<Vec<u8>> = None;
    if !is_recovery {
        match tokio::time::timeout(
            MEASURE_FETCH_BUDGET,
            // Enforce the risc0 ELF binding co-resolved with this job's measurement: a swapped,
            // still-retrievable ELF fails the keccak here and becomes a free pre-claim skip.
            fetch_or_download_elf(
                client,
                state,
                program_id,
                snapshot.verified_elf_hash,
                resolve_backend(snapshot.proof_system_id) != Some("risc0"),
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("ELF fetch exceeded the pre-claim budget"))
        .and_then(|r| r)
        {
            Ok(elf) => {
                clear_preclaim_elf_failures(job_id);
                elf_in_hand = Some(elf)
            }
            Err(e) => {
                tracing::warn!(
                    "not claiming {}: its ELF is not obtainable now ({}) — skipping before locking \
                     collateral (the submitter may have withdrawn the stored program)",
                    short_id(job_id),
                    zkminer_chain::programs::sanitize_log(&format!("{e:#}"))
                );
                // Possibly transient (a storage outage): keep it a candidate behind an escalating
                // back-off, up to a limit — a withheld ELF must not re-take a claim slot forever.
                note_transient_preclaim_failure(job_id);
                if note_preclaim_elf_failure(job_id) < MAX_PRECLAIM_ELF_FAILURES {
                    requeue_open_job(state, requeue_job.clone()).await;
                }
                return Ok(());
            }
        }
    }

    // Re-check shutdown AFTER the ELF-obtainability fetch above. That fetch is an await of up to
    // MEASURE_FETCH_BUDGET (a submitter can stall the ELF host), and the earlier
    // `!is_recovery && SHUTTING_DOWN` gate ran BEFORE it — so without this a signal landing during the
    // fetch would let the drain union (which sees neither `active_jobs` nor the not-yet-written claim
    // breadcrumb below) report "drain complete"/exit 0 while this task goes on to write the breadcrumb
    // and broadcast a fresh claim, locking brand-new collateral on an exiting process. Nothing is
    // on-chain yet, so dropping is free. `is_recovery` jobs are already locked and must still be driven.
    if !is_recovery && SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
        tracing::warn!(
            "shutdown began during the pre-claim ELF fetch for {} — dropping, nothing locked",
            short_id(job_id)
        );
        let mut s = state.write().await;
        s.open_jobs.retain(|j| j.info.job_id != job_id);
        return Ok(());
    }
    // The same holds as step 0, again: the descriptor and ELF fetches since can take minutes, and a
    // re-check in the meantime may have closed a gate.
    if !is_recovery && claims_held_for(snapshot.proof_system_id, submitter, program_id) {
        tracing::debug!(
            "Not claiming {} now: a claim gate closed during its pre-claim fetches — nothing locked",
            short_id(job_id)
        );
        note_job_retry_after(job_id, Duration::from_secs(300));
        requeue_open_job(state, requeue_job.clone()).await;
        return Ok(());
    }

    // Watch-only: every check above ran as it would before a real claim. Report what the claim would
    // meet instead of sending it; no breadcrumb is written.
    if watch_only() {
        watch_claim_preview(client, state, &requeue_job, &snapshot).await;
        return Ok(());
    }

    // 1. Record claim intent BEFORE sending the claim tx, so a crash mid-claim
    //    still leaves breadcrumbs for recovery. A recovered lock already has its breadcrumb (with a
    //    proven deadline and state); overwriting it with a fresh `Claiming` intent would regress it.
    // A breadcrumb that already exists for a FRESH dispatch is an earlier claim of ours whose outcome
    // was never confirmed (the tx may still be pooled, or mined unseen). Nothing this invocation learns
    // covers that tx, so this invocation must never be the one that drops the breadcrumb.
    let prior_claim = !is_recovery && journal_has(journal, job_id);
    if !is_recovery {
        let submit_tx = client.submit_tx_for(job_id);
        journal_update(journal, |j| {
            j.record_claim_intent(job_id, snapshot.lock_deadline, submit_tx);
            // A restart proves it on a card at a size it measured clean at.
            j.note_measured_po2s(job_id, &snapshot.measured_po2s);
        });
        let mut s = state.write().await;
        s.add_log(
            LogLevel::Info,
            format!("Claiming job {}...", short_id(job_id)),
        );
    }

    // The two shutdown gates above are both `!is_recovery`, but the batch reconcile
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

    // A program proven unclaimable since this task was dispatched (served ELF vkey/image-id can never
    // match its programId) must not get a FRESH claim broadcast for it. The `!is_recovery` pre-claim
    // gate above already drops fresh jobs, but the batch-reconcile UNKNOWN class and crash recovery
    // dispatch with is_recovery=true (ownership unproven), and `claim_job_idempotent` below broadcasts
    // a fresh claim whenever the job still reads open. Confirm ownership: if we already hold it, fall
    // through and drive it to prove->release (never stranded); if we do NOT hold it, leave it (the
    // breadcrumb stays for the abandon path) rather than locking new collateral on a dead-end program.
    if is_recovery && program_vkey_mismatched_for(program_id, snapshot.proof_system_id) {
        let held = matches!(
            client.get_job_status_view(job_id).await,
            Ok(v) if v.prover == client.address
        );
        if !held {
            tracing::warn!(
                "not re-claiming {}: its program was proved unclaimable (vkey/image-id mismatch) and                  we do not hold it — leaving it for the abandon path",
                short_id(job_id)
            );
            let mut s = state.write().await;
            s.open_jobs.retain(|j| j.info.job_id != job_id);
            return Ok(());
        }
    }

    // 2. Claim (idempotent): exact floors quoted at a mined block, sent ALONE, and confirmed by
    //    re-reading `jobs(jobId).prover` at a block at or after the receipt's. `lock_block` is that
    //    block: every later read deciding whether to PUBLISH a proof is pinned at or after it.
    //    A RECOVERED lock is never re-claimed: recovery proved it ours moments ago, and a re-claim's
    //    refusal (`JobNotOpen` — the job is Locked, by us) must never be read as "nothing locked".
    //    Its pin is a block where an ownership read shows it ours.
    let lock_block: u64 = if is_recovery {
        let mut read = client.read_job_record(job_id, None).await;
        for _ in 0..2 {
            if read.is_ok() {
                break;
            }
            tokio::time::sleep(DEADLINE_READ_RETRY_DELAY).await;
            read = client.read_job_record(job_id, None).await;
        }
        match read {
            Ok((rec, at))
                if rec.prover == client.address
                    && rec.status == zkminer_chain::jobs::JOB_STATUS_LOCKED =>
            {
                at
            }
            // Unreadable, or a (possibly lagging) read disagreeing with recovery's view: never a
            // release reason. Recovery re-reads it on its next pass and decides from that.
            Ok((rec, at)) => {
                return Err(HandBack(format!(
                    "jobs() at block {at} shows status {} prover {} for a lock recovery saw as ours",
                    rec.status, rec.prover
                ))
                .into())
            }
            Err(e) => return Err(HandBack(format!("ownership re-read failed: {e:#}")).into()),
        }
    } else {
        match client
            .claim_job_idempotent(job_id, snapshot.current_price)
            .await
        {
            Ok(ClaimOutcome::Claimed(r)) => r.block,
            Ok(ClaimOutcome::LostRace) if prior_claim => {
                return Err(HandBack("another prover reads as holding a job an earlier claim of ours may hold".into()).into());
            }
            Ok(ClaimOutcome::LostRace) => {
                journal_update(journal, |j| j.remove(job_id));
                let mut s = state.write().await;
                s.open_jobs.retain(|j| j.info.job_id != job_id);
                s.add_log(
                    LogLevel::Info,
                    format!("Job {} was claimed by someone else", short_id(job_id)),
                );
                return Ok(());
            }
            Err(e) if e.downcast_ref::<zkminer_chain::revert::ClaimNotSent>().is_some() => {
                // Nothing was broadcast (a quote read, a nonce reservation): temporary. A one-off RPC
                // failure must not lose a job the forward-only monitor will never show us again.
                tracing::warn!("{}: {e:#} — retrying later", short_id(job_id));
                note_transient_preclaim_failure(job_id);
                requeue_open_job(state, requeue_job.clone()).await;
                if prior_claim {
                    return Err(HandBack("claim not sent; an earlier claim is unresolved".into()).into());
                }
                journal_update(journal, |j| j.remove(job_id));
                return Ok(());
            }
            Err(e) => {
                // A TYPED refusal that is authoritative that NOTHING of ours is locked —
                // `claim_job_idempotent` re-read ownership at or after the refusal's block before
                // leaving `definitely_not_locked` set: there is no collateral to release, so drop the
                // claim-intent breadcrumb and act on the class (handoff §9).
                if let Some(f) = e.downcast_ref::<zkminer_chain::revert::ClaimFailure>() {
                    if f.definitely_not_locked {
                        use zkminer_chain::revert::ClaimClass;
                        // Authoritative for THIS invocation's txs; an earlier unresolved claim keeps
                        // its breadcrumb (recovery decides it from chain state).
                        if !prior_claim {
                            journal_update(journal, |j| j.remove(job_id));
                        }
                        // Temporary conditions keep the job a candidate (re-quoted after a back-off,
                        // never below our high-water floor); permanent ones drop it.
                        let keep = matches!(
                            f.class,
                            ClaimClass::Wait | ClaimClass::Paused | ClaimClass::StakeShort
                        );
                        let tag = match f.class {
                            ClaimClass::StakeShort => "STAKE-SHORT",
                            ClaimClass::Paused => "PAUSED",
                            ClaimClass::Wait => "CLAIM-WAIT",
                            ClaimClass::Gone => "CLAIM-GONE",
                            ClaimClass::Unknown => "REFUSED",
                        };
                        tracing::warn!("{tag}: claim of {} refused — {}", short_id(job_id), f.reason);
                        if keep {
                            note_claim_retry_after(job_id, f.class);
                            // The brain removed it from `open_jobs` at dispatch: put it back, or the
                            // back-off above never gates anything and the job is lost.
                            requeue_open_job(state, requeue_job.clone()).await;
                        }
                        let mut s = state.write().await;
                        if !keep {
                            s.open_jobs.retain(|j| j.info.job_id != job_id);
                        }
                        s.add_log(
                            LogLevel::Info,
                            format!("Claim of {} refused ({tag}): {}", short_id(job_id), f.reason),
                        );
                        if prior_claim {
                            drop(s);
                            return Err(HandBack(format!("claim refused ({tag}); an earlier claim is unresolved")).into());
                        }
                        return Ok(());
                    }
                }
                // Ambiguous failure: the claimJob tx may have MINED (locking collateral) even though
                // we couldn't confirm it — e.g. an RPC 429 on every receipt/poll path. Keep the
                // claim-intent breadcrumb and hand it to recovery, which DRIVES the job if it turns
                // out to be ours (a release here would burn 5% of a healthy lock) and retains an Open
                // job's breadcrumb until it ages out. The job also stays a candidate behind a
                // back-off, in case the claim never landed; a later claim is idempotent.
                note_transient_preclaim_failure(job_id);
                journal_update(journal, |j| j.note_claim_unconfirmed(job_id));
                requeue_open_job(state, requeue_job.clone()).await;
                return Err(HandBack(format!("claim outcome unconfirmed: {e:#}")).into());
            }
        }
    };
    note_lock_block(job_id, lock_block);

    // 3. Read the view post-claim, PINNED at or after `lock_block` (a lagging replica would show the
    //    pre-claim state: lockDeadline 0, prover 0), to learn the authoritative effective deadline.
    //    The lock is PROVEN at this point, so a read that keeps failing is never a reason to release
    //    it (handoff §9: no release on an RPC error without revert data): hand it to recovery, which
    //    re-drives it from chain state.
    let mut view_read = client.get_job_status_view_at(job_id, lock_block).await;
    for _ in 0..DEADLINE_READ_RETRIES {
        match &view_read {
            Ok(v) if effective_cutoff(v) != 0 => break,
            _ => {}
        }
        tokio::time::sleep(DEADLINE_READ_RETRY_DELAY).await;
        view_read = client.get_job_status_view_at(job_id, lock_block).await;
    }
    let view = match view_read {
        Ok(v) if effective_cutoff(&v) != 0 => v,
        Ok(_) => {
            return Err(HandBack(format!(
                "lockDeadline still reads 0 at or after the lock block {lock_block}"
            ))
            .into())
        }
        Err(e) => return Err(HandBack(format!("post-claim view unreadable: {e:#}")).into()),
    };
    let mut lock_deadline = effective_cutoff(&view);
    if is_recovery {
        // Field-level: `mark_claimed` would regress a recovered Proving/Fulfilling entry's state.
        journal_update(journal, |j| {
            if let Some(e) = j.entries.get_mut(&job_id) {
                e.lock_deadline = lock_deadline;
            }
            j.note_lock_seen(job_id, Some(lock_block), view.reopenCount);
        });
    } else {
        journal_update(journal, |j| {
            j.mark_claimed(job_id, None, lock_deadline);
            j.note_lock_seen(job_id, Some(lock_block), view.reopenCount);
        });
    }

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
        s.add_log(
            LogLevel::Success,
            format!("Job {} claimed", short_id(job_id)),
        );
    }

    // 4. Resolve backend from proof system id.
    let proof_system_id = view.proofSystemId;
    let backend = resolve_backend(proof_system_id).ok_or_else(|| {
        anyhow::anyhow!(
            "Unsupported proof system: 0x{}",
            alloy::hex::encode(proof_system_id)
        )
    })?;

    // 5. Deadline gate — bail out early if we can't hope to fulfill.
    // Release responsibility is on the caller (miner_brain / recover_claimed_jobs). While the job's
    // clock is stopped (a hold, the resume grace after a lift) the room is not shrinking, and the view
    // understates it: not a reason to give up the lock.
    if let Err(e) = ensure_deadline_room(lock_deadline, DEADLINE_FULFILL_MARGIN_SECS) {
        if client.job_clock_stopped(proof_system_id).await {
            return Err(HandBack(format!("{e:#} while the job's clock is stopped")).into());
        }
        return Err(e);
    }

    // 6. Fetch the JobDescriptor (needed for fulfillJob and for inputData).
    // Deadline-bounded: a stalled RPC/storage endpoint must not hang past the point
    // where releaseJob can still land (see with_deadline_budget).
    // Recovery already fetched+verified the descriptor — reuse it instead of
    // re-fetching (3-4 RPC saved per recovered job). The verify_descriptor_hash below
    // stays UNCONDITIONAL either way, re-checking against THIS view's fresh
    // descriptorHash at zero RPC cost.
    let descriptor = match descriptor_in_hand {
        Some(d) => d,
        None => {
            let fetched = with_deadline_budget(lock_deadline, "descriptor reconstruction", job_id, async {
                fetch_job_descriptor_checked(client, job_id, view.descriptorHash)
                    .await
                    .context("descriptor reconstruction failed")
            })
            .await;
            match fetched {
                Ok(d) => d,
                // A permanent verdict cannot be fulfilled: release. Anything else on a lock we hold
                // is an RPC failure, never a release reason (handoff §9).
                Err(e)
                    if e.downcast_ref::<zkminer_chain::descriptor::UndecodableDescriptor>()
                        .is_some() =>
                {
                    return Err(e)
                }
                Err(e) => return Err(HandBack(format!("{e:#}")).into()),
            }
        }
    };
    verify_descriptor_hash(&descriptor, view.descriptorHash)
        .map_err(|e| anyhow::anyhow!("descriptor hash mismatch: {e:#}"))?;
    // programId in descriptor must match what the JobSubmitted event told us.
    if descriptor.programId != program_id {
        return Err(anyhow::anyhow!(
            "descriptor.programId {} != event.programId {}",
            descriptor.programId,
            program_id,
        ));
    }

    // The submitter-controlled descriptor bytes (inputData + the two extra-data
    // fields) are re-encoded into the fulfillJob calldata under a fixed gas limit. Their size is known
    // NOW, before the expensive proof — so reject an over-budget descriptor here and release, rather
    // than burning a full Groth16 proof first. (The guest journal is only known post-prove and is
    // re-checked at the fulfill step.)
    {
        let descriptor_bytes = descriptor.inputData.len()
            + descriptor.callbackExtraData.len()
            + descriptor.extraVerifierData.len();
        // Leave generous headroom under the 128 KiB fulfill-payload cap for the journal + seal.
        const MAX_DESCRIPTOR_PAYLOAD_BYTES: usize = 96 * 1024;
        if descriptor_bytes > MAX_DESCRIPTOR_PAYLOAD_BYTES {
            return Err(anyhow::anyhow!(
                "descriptor payload for {} is {} bytes (> {} cap) — fulfill would OOG-revert; \
                 releasing before wasting a proof",
                short_id(job_id),
                descriptor_bytes,
                MAX_DESCRIPTOR_PAYLOAD_BYTES,
            ));
        }
    }

    // Surface predicate jobs (the default policy claims them). Fulfilling with a
    // proof whose public values don't reproduce the committed journal reverts
    // JournalMismatch (before any payment) and risks a slash on timeout.
    if descriptor.expectedJournalHash != alloy_primitives::B256::ZERO {
        tracing::info!(
            "Job {} is journal-bound: its proof's journal is checked against the binding before the \
             fulfil (a mismatch releases the lock instead of sending a fulfil that would revert)",
            short_id(job_id)
        );
    }

    // 7. Obtain the ELF binary (deadline-bounded — see with_deadline_budget).
    let elf = match elf_in_hand {
        Some(e) => e,
        None => {
            // Only a recovered lock gets here. A failed fetch may heal and the job can still settle:
            // hand it back; recovery's room check releases it if time runs out.
            let fetched = with_deadline_budget(
                lock_deadline,
                "ELF fetch",
                job_id,
                fetch_or_download_elf(
                    client,
                    state,
                    program_id,
                    snapshot.verified_elf_hash,
                    backend != "risc0",
                ),
            )
            .await;
            match fetched {
                Ok(e) => {
                    clear_preclaim_elf_failures(job_id);
                    e
                }
                // A few tries (recovery re-drives with a back-off between them), then release while
                // the window is still wide: an ELF the registrant has withdrawn will not come back,
                // and re-driving it for the lock's whole life would hold a slot and the RPC budget.
                Err(e) if note_preclaim_elf_failure(job_id) >= MAX_POSTLOCK_ELF_FAILURES => {
                    return Err(e.context("ELF unobtainable after repeated attempts"))
                }
                // Too little time left for a re-drive to start: recovery would only release it,
                // after a pass's worth of delay that comes out of the release ladder's margin.
                // Release it now.
                Err(e)
                    if deadline_proof_budget(lock_deadline).is_some_and(|b| {
                        b < Duration::from_secs(
                            MIN_ATTEMPT_BUDGET_SECS + DEADLINE_FULFILL_MARGIN_SECS,
                        )
                    }) =>
                {
                    return Err(e)
                }
                Err(e) => {
                    note_transient_preclaim_failure(job_id);
                    return Err(HandBack(format!("ELF fetch failed: {e:#}")).into());
                }
            }
        }
    };

    // 8. Deadline gate 2.
    ensure_deadline_room(lock_deadline, DEADLINE_FULFILL_MARGIN_SECS)?;

    // 9. Prove.
    {
        let mut s = state.write().await;
        s.add_log(
            LogLevel::Info,
            format!("Proving job {} with {}...", short_id(job_id), backend),
        );
    }
    journal_update(journal, |j| j.mark_proving(job_id));

    let pool = zkminer_prover::engine::worker_pool()
        .ok_or_else(|| anyhow::anyhow!("no worker pool available"))?;
    let input_bytes: Vec<u8> = descriptor.inputData.to_vec();

    // Pre-PROVE predicate breaker (closes the recovery bypass of the pre-claim gate at the
    // `!is_recovery` step-0 check). A recovered predicate job reaches here with is_recovery=true,
    // so it NEVER consulted the pre-claim `predicate_unsatisfiable` gate; without this check a
    // predicate-bait flood would pay a full Groth16 proof per decoy even after a sibling recorded the
    // tuple unsatisfiable. The collateral is already bonded on this path (the batch claim ran), but
    // releasing now — BEFORE the minutes-long prove — recovers it with the full deadline margin (a
    // pre-deadline release is the collateral rescue, not a slash) and skips the dominant GPU cost,
    // capping the flood's expensive work to ~one prove per cooldown window. Keyed by INPUT, so it
    // only skips the exact doomed tuple; a legitimate, satisfiable predicate job was never recorded
    // (it simulates clean) and so is never skipped here. Also closes the single-claim TOCTOU gap
    // where a sibling marks the tuple between the pre-claim gate and here.
    if descriptor.expectedJournalHash != alloy_primitives::B256::ZERO
        && predicate_unsatisfiable(&predicate_key(&descriptor))
    {
        return Err(anyhow::anyhow!(
            "job {}: its journal binding was shown unsatisfiable by a recent fulfil — releasing to \
             recover collateral instead of burning a proof on a guaranteed `JournalMismatch`",
            short_id(job_id)
        ));
    }

    // Size the watchdog / VRAM routing on the quantity admission used — the
    // MEASURED count — not the adversarial declared `expected_cycles`. See `prove_sizing_cycles`.
    let sizing_cycles: u64 = prove_sizing_cycles(snapshot.expected_cycles, snapshot.measured_cycles);

    // Proactive routing: a job that commits a large cycle count starts pinned to
    // a high-VRAM GPU (0 = uncommitted → no floor; the reactive path below still
    // catches an OOM on the first attempt).
    let mut min_vram: Option<u64> =
        (sizing_cycles >= LARGE_JOB_CYCLES).then_some(LARGE_JOB_MIN_VRAM_BYTES);
    // Slot keys of workers that wedged/timed out on this job, so a retry
    // is steered to a *different* GPU instead of being re-pinned to a flaky one.
    // The slots the operator switched off in Settings. Those toggles were honoured by mock mode and
    // by nothing else — the dashboard struck the row out while production kept proving on it.
    //
    // Passed SEPARATELY from `excluded`, not folded into it. `excluded` is a soft preference that the
    // dispatcher restores when pruning empties the candidate set, so that a wedged card can never
    // strand a job; routing the Settings toggles through it left them decorative exactly where it
    // matters most — on a single-GPU rig, disabling the only card restored it and proved on it anyway.
    // Read live; a risc0 job reads it again at every attempt (see the prove loop).
    let mut disabled_slots = operator_disabled_slots(state).await;
    if !disabled_slots.is_empty() {
        tracing::debug!(
            "operator-disabled slots for {}: {}",
            short_id(job_id),
            disabled_slots.join(", ")
        );
    }
    let mut excluded: Vec<String> = Vec::new();

    // Scale the proving-watchdog deadline to the job so a wedged GPU is
    // caught in minutes, not the full (large) configured timeout. Committed-cycle
    // jobs get a timeout proportional to their size; uncommitted jobs (cycles == 0,
    // can't estimate) fall back to the configured cap. Always <= proving_timeout. Uses a deliberately slow CPS floor + 4x margin so a legitimately
    // slow proof is never killed.
    // `sizing_cycles` = max(declared, measured) (or the FALLBACK floor), never the
    // raw declared field, so a small declaration cannot shrink this below the measured work.
    // Only a MEASURED job is tightened: a recovered lock carries no measurement, and a small
    // declared count (or the floor) would kill a long proof on every attempt.
    let effective_timeout = if sizing_cycles > 0 && snapshot.measured_cycles.is_some() {
        let fixed = fixed_proving_allowance_secs(backend)
            + execute_allowance_secs(backend, snapshot.measured_execute_secs);
        prove_watchdog(sizing_cycles, snapshot.planning_cps, fixed, proving_timeout)
    } else {
        proving_timeout
    };

    // Which worker slot actually produced the proof — captured on success so
    // the miner log ties a job to the physical GPU that proved it.
    let mut proved_on: Option<String> = None;
    let proof = {
        // Free host-RAM waits used by this job. Bounded separately from `attempt`, because a wait
        // deliberately refunds the attempt it would otherwise have spent.
        let mut memory_waits = 0u32;
        // Free VRAM waits, counted separately from `memory_waits`: the two shortages have different
        // remedies and different timescales, and sharing one budget would let a card occupied by a
        // desktop consume the waits a genuine host-RAM dip needs.
        let mut gpu_memory_waits = 0u32;
        let mut attempt = 0u32;
        // Set once the claim-time preferred card hits an ADMISSION (un-attempted host-RAM) refusal:
        // unlike a GPU shortage it does not exclude the card, so without dropping the preference the
        // dispatcher would re-pin the un-admittable cold preferred card every retry while the warm
        // sibling idles → abandon → penalized release. Dropping it reverts to warm-first fallback.
        let mut drop_preference = false;
        // Whether the log has said this job proves at a size it was not measured at, or that it is
        // waiting for a risc0 card.
        let mut warned_unmeasured = false;
        let mut warned_no_card = false;
        // Whether the last look found no card to take it (see the wait below).
        let mut waiting_for_card = false;
        loop {
            attempt += 1;
            // The EFFECTIVE deadline moves out while the protocol is paused or a Disabled window
            // lasts (and on a downtime extension): refresh it each attempt, so a proof is never cut
            // short — and its lock released — at a stale pre-pause cutoff.
            refresh_lock_deadline(client, journal, job_id, &mut lock_deadline).await;
            // Pre-deadline release margin: compute the absolute instant past
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
                    // While the job's clock is stopped (a hold, the resume grace after a lift) its
                    // window is not being consumed, so this budget is not shrinking: never abandon on
                    // it, and do not kill a proof at it. After a lift RESUME_GRACE (15 min) more is
                    // credited, which bounds how far past the budget a proof started now may run.
                    let clock = client.job_clock_state(proof_system_id).await.ok();
                    // The credit still coming bounds how far past the view's budget a proof may run: a
                    // full RESUME_GRACE after a hold lifts, only the REMAINING tail once a grace runs.
                    let coming = match clock {
                        Some(c) if c.hold.is_some() => Duration::from_secs(900),
                        Some(c) => Duration::from_secs(c.tail),
                        None => Duration::ZERO,
                    };
                    let held = clock.is_some_and(|c| c.hold.is_some());
                    if budget < Duration::from_secs(MIN_ATTEMPT_BUDGET_SECS)
                        && (held || budget + coming < Duration::from_secs(MIN_ATTEMPT_BUDGET_SECS))
                    {
                        // During a HOLD the lift will credit a full grace: wait for it. Otherwise the
                        // window is really closing (a running grace tail is already in `coming`).
                        if held && !SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
                            tokio::time::sleep(FULFIL_RETRY_WAIT).await;
                            attempt = attempt.saturating_sub(1);
                            continue;
                        }
                        // Not when it never ran because no card could take it: that says nothing about
                        // the guest.
                        if rode_measurement && !waiting_for_card {
                            note_post_claim_divergence(program_id, backend, submitter, "proving budget ran out");
                        }
                        return Err(anyhow::anyhow!(
                            "abandoning {} before deadline to recover collateral: only {}s of \
                             proving budget left (keeping {}s release margin)",
                            short_id(job_id),
                            budget.as_secs(),
                            DEADLINE_RELEASE_MARGIN_SECS,
                        ));
                    }
                    let budget = budget.max(effective_timeout.min(budget + coming));
                    Some(std::time::Instant::now() + budget)
                }
            };
            let elf_clone = elf.clone();
            let input_clone = input_bytes.clone();
            let backend_str = backend.to_string();
            // Bind the ELF to the job's programId so a worker refuses an ELF unrelated to the
            // registered program before spending a Groth16 proof on it. risc0 compares the guest
            // image id; SP1 compares the vkey hash; both ARE the on-chain programId for
            // their system. OpenVM ignores it (and is declined anyway). Never enforce against a
            // zero/unknown id (mock mode) — that would reject every legitimate job.
            let program_id_bytes: Option<[u8; 32]> = (program_id
                != alloy::primitives::B256::ZERO)
                .then(|| program_id.0);
            let mv = min_vram;
            let excl = excluded.clone();
            // A risc0 job proves only on a card at a size it measured clean at, at that card's size:
            // the guest can tell the size it runs at (see `RISC0_DEFAULT_JOB_PO2`). Read each attempt,
            // as the cards and their sizes are (Settings, a re-benchmark). A recovered lock reads its
            // sizes from its breadcrumb.
            let risc0_job = backend == zkminer_prover_protocol::BACKEND_RISC0;
            // A risc0 job re-reads the switched-off cards every attempt: with none left it waits
            // (below) rather than fail, so a card switched back on can take it. Other backends keep
            // the list they started with: their dispatch fails at once with every card switched off.
            if risc0_job {
                disabled_slots = operator_disabled_slots(state).await;
            }
            let job_sizes: Option<HashMap<String, u8>> = if risc0_job {
                let measured = if snapshot.measured_po2s.is_empty() {
                    journal
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .measured_po2s(job_id)
                } else {
                    snapshot.measured_po2s.clone()
                };
                // The cards this job may go to: not one switched off now (the dispatcher is held to the
                // same list), whatever their size.
                let mut cards = current_risc0_cards(state, false).await;
                cards.retain(|c| !disabled_slots.contains(&c.slot));
                let (sizes, measured_here) = risc0_prove_sizes(&cards, &measured);
                let recorded = if measured.is_empty() {
                    "no recorded sizes".to_string()
                } else {
                    format!("po2 {measured:?}")
                };
                if sizes.is_empty() {
                    // No enabled card here proves risc0 jobs now (switched off, or none has a size:
                    // Advanced mode turned off, a re-benchmark dropped a calibration). The job is not
                    // at fault, and the operator can fix it in place: wait, as for memory, while the
                    // window allows (the budget check above releases in time), never past it.
                    if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
                        return Err(HandBack(format!(
                            "no enabled risc0 card here has a job size ({recorded})"
                        ))
                        .into());
                    }
                    waiting_for_card = true;
                    if !warned_no_card {
                        warned_no_card = true;
                        let detail = format!(
                            "Job {} is waiting for a risc0 card: none enabled here has a job size \
                             ({recorded}). Switch one back on, or give one a po2 under Settings → \
                             Advanced; it is released before its deadline otherwise. (A size in \
                             the config, `prover.risc0_job_po2`, or a calibration applies only \
                             after a restart.)",
                            short_id(job_id)
                        );
                        tracing::warn!("{detail}");
                        state.write().await.add_log(LogLevel::Warn, detail);
                    }
                    attempt = attempt.saturating_sub(1);
                    tokio::time::sleep(no_card_wait(deadline_proof_budget(lock_deadline))).await;
                    continue;
                }
                waiting_for_card = false;
                warned_no_card = false;
                if !measured_here && !warned_unmeasured {
                    warned_unmeasured = true;
                    let default = zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2;
                    if measured.is_empty() && sizes.values().all(|&p| p == default) {
                        tracing::info!(
                            "{}: no recorded sizes (a lock from an earlier build, or found without \
                             its breadcrumb): proving it at po2 {default}, which earlier builds \
                             measured at",
                            short_id(job_id)
                        );
                    } else {
                        tracing::warn!(
                            "{}: no enabled risc0 card here holds a size it measured at \
                             ({recorded}); proving it at sizes it was not measured at instead of \
                             releasing it",
                            short_id(job_id)
                        );
                    }
                }
                Some(sizes)
            } else {
                None
            };
            // Cloned for the progress callback below, which runs on the blocking thread, and the
            // runtime it hands the state update to.
            let state_for_prove_progress = state.clone();
            let runtime_for_prove_progress = tokio::runtime::Handle::current();
            // Cloned per attempt: the closure below moves into `spawn_blocking`, and the retry loop
            // needs the list again next time round.
            let disabled_for_prove = disabled_slots.clone();
            // The card this job was planned for (benchmark id, e.g. "gpu1"), preferred at dispatch.
            let preferred_for_prove = if drop_preference {
                None
            } else {
                snapshot.preferred_device.clone()
            };
            // This job's pre-claim measured execute PEAK (SP1 only; 0 otherwise), for the dispatcher's
            // RH2 prove reservation — charges the `server + execute` spike so a concurrent other-backend
            // proof is not admitted into memory the SP1 execute window will consume. Copy, so captured
            // by value into the move closure.
            let execute_peak_for_prove = snapshot.measured_peak.unwrap_or(0);
            let (proof_result, used_slot) = match tokio::task::spawn_blocking(move || {
                let mut used = None;
                // Flip Queued -> Proving the moment the dispatcher actually starts
                // work. Until now `on_progress` was unused and the status was set to
                // `Proving { progress: 0.0 }` at CLAIM time, so a job waiting for a card was
                // indistinguishable from one running on it — which is exactly the thing
                // look-ahead queueing makes common. This runs on the proving thread, which a
                // label must never stall: see below for how the update gets there.
                let started_state = state_for_prove_progress.clone();
                let started_id = job_id;
                // Exactly ONE Progress message is sent per proof (at start), so unlike a
                // progress STREAM a single missed update strands the job in `Queued`, on no
                // card, for its whole run. So the update is handed to the runtime, which waits
                // for the lock there: it cannot be lost, and this thread never blocks on it.
                // Deliberately NOT `blocking_write()` here: if any async holder of this lock is
                // itself awaiting this proof, that would deadlock a real proof over a label. It
                // was a bounded `try_write` retry (40 x 5 ms) before, which a busy miner
                // outlasted: an RTX 4070 proved risc0 jobs back to back while its dashboard row
                // read "Idle", the jobs never attributed to it.
                let started_pool = pool;
                let started_runtime = runtime_for_prove_progress;
                let mark_started = move |_p: f64, slot_key: &str| {
                    // Which physical card took this job. Resolved through the pool
                    // rather than any index, so the dashboard can attribute the job
                    // to the right GPU row on a mixed-vendor box.
                    let bus = started_pool.bus_id_for_slot(slot_key);
                    let slot_key = slot_key.to_string();
                    let started_state = started_state.clone();
                    started_runtime.spawn(async move {
                        let mut st = started_state.write().await;
                        if let Some(j) = st
                            .active_jobs
                            .iter_mut()
                            .find(|j| j.info.job_id == started_id)
                        {
                            if matches!(j.status, zkminer_tui::state::MinerJobStatus::Queued) {
                                j.status = zkminer_tui::state::MinerJobStatus::Proving {
                                    progress: 0.0,
                                    elapsed_secs: 0,
                                };
                            }
                            // Overwrite UNCONDITIONALLY. `is_none()` made the attribution sticky, so after the GPU-OOM arm
                            // rerouted a job to a bigger card the dashboard kept naming the card it had failed on — and this
                            // is the only signal an operator has for which card a job is on. The callback carries the
                            // authoritative slot key for the attempt that is actually starting.
                            j.gpu_bus_id = bus;
                            // And WHICH SLOT. `prover_backend` was set only after a proof
                            // succeeded, so while work was running the dashboard showed the card
                            // but not the backend — and with two slots per card that is the one
                            // thing an operator checking their routing needs to see.
                            j.prover_backend = slot_key;
                        }
                    });
                };
                let size_on = |slot: &str| job_sizes.as_ref().and_then(|s| s.get(slot).copied());
                let r = pool.prove_min_vram(
                    &backend_str,
                    &elf_clone,
                    &input_clone,
                    None,
                    Some(effective_timeout),
                    Some(Box::new(mark_started)),
                    mv,
                    &excl,
                    &disabled_for_prove,
                    &mut used,
                    abort_at,
                    job_sizes
                        .is_some()
                        .then_some(&size_on as zkminer_prover::dispatcher::SlotPo2<'_>),
                    program_id_bytes,
                    preferred_for_prove.as_deref(),
                    execute_peak_for_prove,
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
                    // Matched on the TYPE, never on `msg`: that string embeds a worker's error
                    // verbatim, and a worker's error can carry text from the guest ELF of an
                    // on-chain job. Since this arm is terminal with zero retries, a substring match
                    // let a submitter end their own provable job and collect the release penalty.
                    // The substring predicate this replaced is gone, not kept.
                    if e.downcast_ref::<zkminer_prover_protocol::types::ProofDeadlineReached>()
                        .is_some()
                    {
                        // Unless the deadline itself moved out meanwhile (a pause began during this
                        // proof): then the kill was against a stale cutoff, and there is room to prove
                        // again. The refund is bounded — every one needs the deadline to have moved.
                        if refresh_lock_deadline(client, journal, job_id, &mut lock_deadline).await
                            && deadline_proof_budget(lock_deadline)
                                .is_some_and(|b| b >= Duration::from_secs(MIN_ATTEMPT_BUDGET_SECS))
                        {
                            tracing::warn!(
                                "{}: proof cut at a stale cutoff — the effective deadline moved out \
                                 (pause credit / extension); proving again",
                                short_id(job_id)
                            );
                            attempt = attempt.saturating_sub(1);
                            continue;
                        }
                        if rode_measurement {
                            note_post_claim_divergence(program_id, backend, submitter, "proof overran its deadline budget");
                        }
                        return Err(anyhow::anyhow!(
                            "proving stopped for {} (deadline): {msg}",
                            short_id(job_id)
                        ));
                    }
                    // Something holds this CARD's VRAM — a desktop session, a browser with hardware
                    // acceleration, somebody else's CUDA job, or our own worker of the other backend
                    // that could not be recycled for this proof yet. Neither the worker nor the job is
                    // at fault, and nothing ran, so this must not cost an attempt or mark the slot
                    // unhealthy.
                    //
                    // Unlike the host-RAM arm below, this one DOES exclude the slot, and that is the
                    // substantive difference between them: the host ledger is process-wide, so every
                    // other slot fails identically and excluding is pointless, whereas held VRAM is a
                    // property of one physical card. Excluding sends the retry to the other GPU,
                    // which is usually free. On a single-GPU box `prove_min_vram` restores the set it
                    // just emptied, so the retry lands on the same card — that is what the backoff and
                    // the wait cap are for, and why this cannot spin.
                    //
                    // EXCEPT when the obstacle was our own worker, which clears in seconds to a couple
                    // of minutes
                    // (`ours_in_the_way`: a sibling busy with a cycle measurement, memory of one just
                    // torn down). Excluding the card then — `excluded` lives for the whole job —
                    // reduced a two-card backend to its other card, whose single-key path waits on
                    // that card's guard behind whatever long proof it is running, up to the deadline.
                    //
                    // Matched on the TYPE for the same reason as every other arm here: `msg` embeds
                    // worker text that can carry a submitter's guest-ELF output, and an arm that
                    // refunds attempts is exactly what a forged error would want to reach.
                    if let Some(shortage) =
                        e.downcast_ref::<zkminer_prover_protocol::types::GpuMemoryShortage>()
                    {
                        if let Some(k) = used_slot.clone() {
                            if !shortage.ours_in_the_way && !excluded.contains(&k) {
                                excluded.push(k);
                            }
                        }
                        if gpu_memory_waits < MAX_GPU_MEMORY_WAITS {
                            gpu_memory_waits += 1;
                            attempt = attempt.saturating_sub(1);
                            tracing::warn!(
                                "{} is waiting for GPU memory, not failing: {shortage} Retrying in \
                                 {}s (wait {}/{}), {}; the deadline budget decides when to give up.",
                                short_id(job_id),
                                GPU_MEMORY_BACKOFF_SECS,
                                gpu_memory_waits,
                                MAX_GPU_MEMORY_WAITS,
                                if shortage.ours_in_the_way {
                                    "this card included"
                                } else {
                                    "preferring another card"
                                },
                            );
                            tokio::time::sleep(Duration::from_secs(GPU_MEMORY_BACKOFF_SECS)).await;
                            continue;
                        }
                        // Out of free waits. Still not the slot's fault, so it is not retired — but
                        // this one costs a real attempt and falls through to the ordinary budget.
                        tracing::warn!(
                            "{} ran out of free GPU-memory waits: {shortage}",
                            short_id(job_id),
                        );
                        if attempt < MAX_PROVE_ATTEMPTS {
                            continue;
                        }
                        return Err(anyhow::anyhow!(
                            "proving failed after {attempt} attempt(s): {msg}"
                        ));
                    }
                    // A HOST memory shortage is not this worker's fault and not this job's
                    // fault: the box is momentarily short of RAM. Classifying it as ill-health
                    // was a money-losing bug. The ledger is process-wide, so "retry on a
                    // different GPU" fails identically on every other slot, and the check is a
                    // `/proc/meminfo` read — so all three attempts burned inside a millisecond
                    // and the job was released at the RELEASE_PENALTY_FLOOR_BPS minimum. That is
                    // precisely the loss the admission gate exists to prevent, paid on every job
                    // the gate refused.
                    //
                    // Matched on the TYPE, never on `msg`. `msg` embeds a worker's error text
                    // verbatim, and that text can originate in the guest ELF of an on-chain job —
                    // so a `contains("HOST_MEMORY_SHORTAGE")` here would let any submitter buy
                    // their job unbounded free retries by panicking with the right string.
                    //
                    // So: wait for the host rather than blaming the slot. Do not exclude it (it
                    // is healthy), and do not spend an attempt (nothing was attempted). The
                    // termination guarantee is the deadline budget recomputed at the top of this
                    // loop: if memory never frees, `deadline_proof_budget` eventually falls below
                    // MIN_ATTEMPT_BUDGET_SECS and we abandon the job early enough to release the
                    // collateral without a penalty.
                    if let Some(shortage) =
                        e.downcast_ref::<zkminer_prover_protocol::types::HostMemoryShortage>()
                    {
                        // An admission refusal (nothing ran) means the slot just tried — most likely
                        // the cold claim-time preferred card — could not be admitted now. Unlike a GPU
                        // shortage this does NOT exclude the slot, so drop the device preference for the
                        // rest of this job and let the dispatcher's warm-first ordering pick the warm
                        // sibling instead of re-pinning the un-admittable card every retry. Only on an
                        // un-attempted (admission) refusal; an OOM mid-proof is a different event.
                        if !shortage.attempted {
                            drop_preference = true;
                        }
                        // Only an ADMISSION refusal is free. That costs a `/proc/meminfo` read, so
                        // nothing was attempted and waiting is the honest response. A worker
                        // OOM-killed MID-PROOF is a different event: minutes of real work ran and
                        // were lost, and refunding the attempt for it let a box that is simply too
                        // small run full proof attempts back to back until the lock deadline
                        // expired — MAX_PROVE_ATTEMPTS bypassed, the slot never excluded, the
                        // backend never retired, a concurrency slot held the whole time.
                        //
                        // Free waits are also capped independently of the deadline. Refunding an
                        // attempt means `MAX_PROVE_ATTEMPTS` no longer bounds anything by itself:
                        // an alternating health-fail / shortage sequence refunds each increment the
                        // health-fail spends, so without this cap the only bound was the deadline.
                        if !shortage.attempted && memory_waits < MAX_HOST_MEMORY_WAITS {
                            memory_waits += 1;
                            attempt = attempt.saturating_sub(1);
                            tracing::warn!(
                                "{} is waiting for host RAM, not failing: {msg}. Retrying the same \
                                 slot in {}s (wait {}/{}); the deadline budget decides when to give \
                                 up.",
                                short_id(job_id),
                                HOST_MEMORY_BACKOFF_SECS,
                                memory_waits,
                                MAX_HOST_MEMORY_WAITS,
                            );
                            // Until memory is given back, or the backoff at most: a release is a
                            // wake-up, not a promise, and one before this wait began is missed.
                            let _ = tokio::time::timeout(
                                Duration::from_secs(HOST_MEMORY_BACKOFF_SECS),
                                zkminer_prover::memory::MEMORY_RELEASED.notified(),
                            )
                            .await;
                            continue;
                        }
                        // Still not the slot's fault, so do not exclude it or call it unhealthy —
                        // but this one DOES cost an attempt, so fall through to the normal budget.
                        tracing::warn!(
                            "{} hit a host-RAM limit that cost a real attempt ({}): {msg}",
                            short_id(job_id),
                            if shortage.attempted {
                                "the proof was OOM-killed mid-run"
                            } else {
                                "out of free waits"
                            },
                        );
                        if attempt < MAX_PROVE_ATTEMPTS {
                            continue;
                        }
                        // A proof OOM-killed mid-run is a failure after a clean measurement like any
                        // other (a guest can balloon host memory on purpose). Only an admission refusal
                        // — nothing ran — is exempt.
                        if rode_measurement && shortage.attempted {
                            note_post_claim_divergence(program_id, backend, submitter, "proof OOM-killed mid-run");
                        }
                        return Err(anyhow::anyhow!(
                            "proving failed after {attempt} attempt(s): {msg}"
                        ));
                    }
                    // The WORKER's own classification where we have it, falling back to the text
                    // only for failures that never reached a worker (a spawn backoff, an EOF, a
                    // protocol desync) and therefore carry no guest-supplied text at all.
                    //
                    // The text forms were the last two guest-forgeable branches in this loop. `msg`
                    // embeds a worker's error verbatim and that error can come from the guest ELF of
                    // an on-chain job: panicking with "out of memory" steered the retry onto the
                    // largest card and set a VRAM floor, and panicking with "proof is invalid"
                    // suppressed the slot exclusion so the retry landed straight back on the card
                    // that had just failed. `ErrorKind` is set by the worker about itself.
                    let worker_err =
                        e.downcast_ref::<zkminer_prover_protocol::types::WorkerProofError>();
                    // A programId/vkey mismatch is PERMANENT for this program: the served ELF's
                    // verifying key / image id can never equal its on-chain programId, so no job for it
                    // can ever be proved. Record the program so the claim gate, measure gate, batch-claim
                    // task, and each per-job lifecycle task all skip every future job for it (capping the
                    // loss to the one claim wave already in flight when this prove faulted, not a penalty
                    // per job), and return terminally — more attempts on the same binding fail
                    // identically. Typed, so
                    // guest-controlled error text can never forge it.
                    if worker_err.map(|w| w.is_program_mismatch()).unwrap_or(false) {
                        // Key by the BACKEND that derived the mismatch: a risc0 image-id and an SP1
                        // vkey are different derivations, and proofSystemId is submitter-controlled, so
                        // marking programId alone would let an SP1-declared decoy carrying a legit risc0
                        // programId permanently over-block that program under risc0 (and vice versa).
                        mark_program_vkey_mismatch(program_id, backend);
                        if rode_measurement {
                            note_post_claim_divergence(program_id, backend, submitter, "image-id mismatch at prove");
                        }
                        return Err(anyhow::anyhow!(
                            "proving stopped for {} (served ELF's vkey/image-id does not match its \
                             programId — program is unprovable; skipping its future jobs): {msg}",
                            short_id(job_id)
                        ));
                    }
                    let invalid = match worker_err {
                        Some(w) => w.is_invalid(),
                        None => is_invalid_proof(&msg),
                    };
                    // A genuine GPU OOM means the job is too big for that card (retry on
                    // a bigger card). Everything else non-invalid is a worker-health /
                    // transient failure — wedge/EOF, a broken-pipe send failure, IPC
                    // stream corruption/protocol desync, or a respawn backoff. The
                    // dispatcher already killed/respawned the worker, so retry on a
                    // DIFFERENT card rather than abandoning a recoverable job (the old
                    // whitelist only retried wedge/EOF and dropped the rest).
                    let real_oom = match worker_err {
                        Some(w) => w.is_gpu_oom(),
                        None => zkminer_prover_protocol::types::is_gpu_oom(&msg),
                    };
                    let health_fail = !invalid && !real_oom;
                    if attempt < MAX_PROVE_ATTEMPTS {
                        // BOTH non-invalid classes steer OFF the card that just failed.
                        //
                        // Exclude the OOMing slot rather than setting a VRAM floor:
                        // `LARGE_JOB_MIN_VRAM_BYTES` exceeds every card on this hardware
                        // (30 GiB vs 16303 and 24564 MiB). A floor would empty the
                        // candidate set, `prove_min_vram` would restore the FULL key set, and
                        // the retry would land straight back on the card that had just OOMed
                        // -- which, with the other card already excluded, leaves one key
                        // and takes the single-key shortcut into an instant respawn-backoff
                        // bail.
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
                        // A VRAM OOM means the job did not fit THAT card, so ask for a
                        // strictly bigger one. A fixed floor cannot do that job:
                        // LARGE_JOB_MIN_VRAM_BYTES is 30 GiB and exceeds every card on
                        // this box (16303 and 24564 MiB), so it matches nothing and
                        // `prove_min_vram` just restores the full set. Measured here:
                        // bigint-mul groth16 OOMs on the 16 GiB 5080 and proves on the
                        // 24 GiB 4090 in 16s, so "> the card that just failed" routes it
                        // correctly on the first retry while a 30 GiB floor routes it
                        // nowhere. Falls back to the constant when the card's VRAM is
                        // unknown (non-CUDA, or nvidia-smi unavailable).
                        if real_oom {
                            // `used_slot`, NOT `proved_on`: the latter is assigned only on
                            // the success path, so reading it here always yields None and
                            // silently falls back to the inert constant.
                            min_vram = used_slot
                                .as_deref()
                                .and_then(|k| pool.vram_bytes_for_slot(k))
                                .map(|v| v.saturating_add(1))
                                .or(Some(LARGE_JOB_MIN_VRAM_BYTES));
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
                    // Every attempt failed on a job that measured clean. Class-agnostic on purpose: the
                    // worker's kind can follow guest-chosen text (see `note_post_claim_divergence`).
                    if rode_measurement {
                        note_post_claim_divergence(program_id, backend, submitter, "all prove attempts failed");
                    }
                    return Err(anyhow::anyhow!(
                        "proving failed after {attempt} attempt(s): {msg}"
                    ));
                }
            }
        }
    };

    card.release();
    if let Some(slot) = &proved_on {
        tracing::info!("Job {} proved on {}", short_id(job_id), slot);
        note_observed_throughput(slot, proof.cycles, proof.duration);
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

    // 10. (No separate deadline gate here: the fulfil loop below re-reads the effective cutoff every
    // round — so a proof that finished while the job's clock was stopped is not judged on the stale
    // pre-attempt cutoff — bounds each round by the remaining budget, and releases when it closes.)

    // A fulfillJob tx carries the full descriptor (incl. submitter-controlled
    // inputData) and the guest journal as publicValues, under a FIXED gas limit. A submitter who
    // sizes inputData and/or the journal large enough makes fulfill OOG-revert — wasting the proof
    // and the fulfill gas, and risking a slash if it recurs near the deadline. If the payload can't
    // plausibly fit the gas budget, skip the guaranteed-revert fulfill and release now to recover
    // collateral cheaply. ~16 gas/calldata-byte means the fulfill gas limit bounds total calldata;
    // the floor below leaves generous room for the fixed descriptor fields and on-chain execution.
    {
        // Sum ALL submitter-controlled calldata the fulfillJob tx carries: the guest journal
        // (publicValues), the seal, and every bytes field of the descriptor that is re-encoded
        // on-chain — inputData AND callbackExtraData AND extraVerifierData. Omitting
        // the latter two would leave the OOG-revert open: a submitter could move the bulk into them.
        let payload_bytes = proof.journal.len()
            + proof.seal.len()
            + descriptor.inputData.len()
            + descriptor.callbackExtraData.len()
            + descriptor.extraVerifierData.len();
        const MAX_FULFILL_PAYLOAD_BYTES: usize = 128 * 1024; // conservative vs the ~5M gas fulfill cap
        if payload_bytes > MAX_FULFILL_PAYLOAD_BYTES {
            // The pre-claim screens passed this job on its measured journal: a proof whose journal
            // pushes the payload over the cap means measure and prove diverged.
            if rode_measurement {
                note_post_claim_divergence(program_id, backend, submitter, "fulfil payload over the cap");
            }
            return Err(anyhow::anyhow!(
                "fulfill payload for {} is {} bytes (> {} cap) — would OOG-revert under the fulfill \
                 gas limit; releasing to recover collateral instead of burning gas",
                short_id(job_id),
                payload_bytes,
                MAX_FULFILL_PAYLOAD_BYTES,
            ));
        }
    }

    // RISC Zero groth16 seals must be selector-prefixed for on-chain verification;
    // the worker returns the bare 256-byte proof, so prepend the 4-byte selector.
    let seal_bytes: Vec<u8> = if backend == "risc0" {
        let selector = risc0_seal_selector();
        let mut s = Vec::with_capacity(selector.len() + proof.seal.len());
        s.extend_from_slice(&selector);
        s.extend_from_slice(&proof.seal);
        s
    } else {
        proof.seal.clone()
    };

    // An SP1 seal goes on chain as the worker returned it: one of another length or circuit would
    // revert VerifierCallFailed after the fulfil's gas, so release instead of publishing it.
    if backend == zkminer_prover_protocol::BACKEND_SP1
        && (seal_bytes.len() != SP1_GROTH16_SEAL_LEN || seal_bytes[..4] != sp1_seal_prefix())
    {
        return Err(anyhow::anyhow!(
            "SP1 seal for {} is {} bytes prefixed 0x{} — not a circuit v6.1.0 Groth16 seal ({} bytes \
             prefixed 0x{}); releasing instead of publishing it",
            short_id(job_id),
            seal_bytes.len(),
            alloy::hex::encode(&seal_bytes[..seal_bytes.len().min(4)]),
            SP1_GROTH16_SEAL_LEN,
            alloy::hex::encode(sp1_seal_prefix())
        ));
    }

    // A journal over MAX_JOURNAL_BYTES reverts `JournalTooLarge` — refuse BEFORE publishing the seal.
    if proof.journal.len() > zkminer_chain::jobs::MAX_JOURNAL_BYTES {
        // Pre-claim screens refuse a measured journal over the cap, so this one diverged.
        if rode_measurement {
            note_post_claim_divergence(program_id, backend, submitter, "journal over MAX_JOURNAL_BYTES");
        }
        return Err(anyhow::anyhow!(
            "journal for {} is {} bytes (> {} MAX_JOURNAL_BYTES) — the fulfil would revert \
             JournalTooLarge; releasing instead of publishing the proof",
            short_id(job_id),
            proof.journal.len(),
            zkminer_chain::jobs::MAX_JOURNAL_BYTES
        ));
    }

    // The router checks the journal binding before the verifier; check it here first, so a proof whose
    // journal cannot settle this job is released without publishing its seal or paying for the revert.
    // A claim is made only on a measured journal that satisfies the binding, so a mismatch here means
    // the proof's journal diverged from the measurement.
    if let Err(why) = zkminer_chain::binding::check_journal_binding(
        &descriptor,
        &proof.journal,
        job_id,
        client.address,
    ) {
        if rode_measurement {
            note_post_claim_divergence(program_id, backend, submitter, "journal fails the binding");
        }
        // What the fulfil's `JournalMismatch` would have recorded (a prefix mismatch is about this
        // job and prover, not the binding its siblings share).
        if matches!(why, zkminer_chain::binding::BindingMismatch::Journal { .. }) {
            mark_predicate_unsatisfiable(predicate_key(&descriptor));
        }
        return Err(anyhow::anyhow!(
            "the journal of {}'s proof does not satisfy the job's binding ({why}) — the fulfil would \
             revert; releasing instead of publishing the proof",
            short_id(job_id)
        ));
    }

    // Fields the failure classes act on, captured before the loop (the descriptor is cloned per try).
    let fulfill_key = predicate_key(&descriptor);
    let fulfill_is_bound = descriptor.expectedJournalHash != alloy_primitives::B256::ZERO;
    let fulfill_program_id = descriptor.programId;
    let fulfill_proof_system = descriptor.proofSystemId;
    // A submitter-controlled per-job lever must not let a decoy carrying a LEGIT program's public
    // programId throttle that program, so a `VerifierCallFailed` throttles the (program, proof system)
    // only for a lever-free descriptor. On v2 that is a CUSTOM_VERIFIER concern only: an adapter job's
    // callback is SOFT (it runs after verification and cannot revert the fulfil) and the risc0 adapter
    // ignores `extraVerifierData`, so for adapter jobs no descriptor field can cause
    // `VerifierCallFailed` — exempting them would only let a submitter opt its decoy out of the breaker
    // by setting any callback.
    let fulfill_no_lever = descriptor.proofSystemId != zkminer_chain::auction::custom_verifier_id()
        || !descriptor_carries_revert_lever(&descriptor);

    // 11. Fulfil on-chain.
    journal_update(journal, |j| j.mark_fulfilling(job_id));
    {
        let mut s = state.write().await;
        if let Some(j) = s.active_jobs.iter_mut().find(|j| j.info.job_id == job_id) {
            j.status = MinerJobStatus::Submitting;
        }
        s.add_log(
            LogLevel::Info,
            format!("Submitting fulfillment for {}...", short_id(job_id)),
        );
    }
    // `Submitting` is the shutdown's proxy for "a fulfil is IN FLIGHT" (the drain excludes it from its
    // nearest-deadline cut and ABANDON refuses to release it). Clear it before ANY exit that hands the
    // job back to `release_and_clean`, so both stages see the job again.
    let clear_submitting = |why: &'static str| {
        let state = state.clone();
        async move {
            let mut s = state.write().await;
            if let Some(j) = s.active_jobs.iter_mut().find(|j| j.info.job_id == job_id) {
                j.status = MinerJobStatus::Skipped { reason: why.into() };
            }
        }
    };
    let public_values = Bytes::from(proof.journal.clone());
    let seal = Bytes::from(seal_bytes);
    // Retried BY CLASS until the job settles or its window closes (handoff §9). Each round re-reads
    // the EFFECTIVE cutoff (D_eff + PROVER_GRACE): a pause or a downtime extension moves it out, so a
    // lock kept through a pause is fulfilled after the lift instead of released for nothing.
    loop {
        let before = lock_deadline;
        if refresh_lock_deadline(client, journal, job_id, &mut lock_deadline).await {
            tracing::info!(
                "{}: effective deadline moved out by {}s (pause credit / downtime extension)",
                short_id(job_id),
                lock_deadline - before
            );
        }
        let fulfill_budget = match deadline_proof_budget(lock_deadline) {
            None => None,
            Some(b)
                if b < Duration::from_secs(MIN_ATTEMPT_BUDGET_SECS)
                    && clock_stopped_or_unknown(client, fulfill_proof_system, b).await =>
            {
                // The clock is stopped, so this budget is not shrinking and the view understates the
                // cutoff: `fulfill_job` holds during a pause and may land during the resume grace.
                // Never throw a finished proof away on it. (An UNREADABLE clock gets only the budget
                // that is really left.)
                if client.job_clock_stopped(fulfill_proof_system).await {
                    Some(Duration::from_secs(2 * MIN_ATTEMPT_BUDGET_SECS))
                } else {
                    Some(b)
                }
            }
            Some(b) if b < Duration::from_secs(MIN_ATTEMPT_BUDGET_SECS) => {
                clear_submitting("fulfil window closing — releasing").await;
                return Err(anyhow::anyhow!(
                    "fulfil window for {} closing ({}s before the release cutoff) — releasing to \
                     recover collateral",
                    short_id(job_id),
                    b.as_secs()
                ));
            }
            Some(b) => Some(b),
        };
        // The deadline budget is enforced INSIDE fulfill_job (never a `tokio::time::timeout` that
        // would drop it mid-flight and orphan its nonce); on give-up it STASHES its pending nonce, so
        // the next round re-publishes at that SAME nonce and a release displaces it there.
        let fulfil = client
            .fulfill_job(
                job_id,
                descriptor.clone(),
                public_values.clone(),
                seal.clone(),
                fulfill_budget,
                Some(lock_block),
            )
            .await;
        let e = match fulfil {
            Ok(()) => break,
            Err(e) => e,
        };
        use zkminer_chain::revert::{FulfilClass, FulfilFailure};
        let published_unconfirmed = e
            .downcast_ref::<FulfilFailure>()
            .is_some_and(|f| f.published && f.class == FulfilClass::Unknown);
        let (class, name, reason) = match e.downcast_ref::<FulfilFailure>() {
            Some(f) => (f.class, f.error_name.clone(), f.reason.clone()),
            None => (
                FulfilClass::Unknown,
                String::new(),
                zkminer_chain::programs::sanitize_log(&format!("{e:#}")),
            ),
        };
        match class {
            FulfilClass::ProofDefect => {
                // Our proof (or descriptor copy) cannot settle this job. A decoded JournalMismatch is a
                // pure function of the binding and our journal (it fires before the verifier and any
                // callback), so it throttles THIS binding for siblings; it cannot poison a binding that
                // differs in any component.
                if name == "JournalMismatch" && fulfill_is_bound {
                    mark_predicate_unsatisfiable(fulfill_key);
                }
                if name == "InvalidDescriptorHash" {
                    tracing::error!(
                        "PAGE: {} fulfil reverted InvalidDescriptorHash — zkminer's descriptor \
                         reconstruction disagrees with the router",
                        short_id(job_id)
                    );
                }
                clear_submitting("proof rejected — releasing").await;
                return Err(anyhow::anyhow!("fulfil rejected ({reason}) — releasing"));
            }
            FulfilClass::VerifierFailed => {
                // Release only if no governance cause (Registry paused / adapter Disabled) explains it,
                // read at one block. With a cause the lock is kept: time is credited.
                match client
                    .verifier_failure_has_governance_cause(fulfill_proof_system)
                    .await
                {
                    Ok(false) => {
                        if fulfill_no_lever {
                            mark_program_sim_reverted(fulfill_program_id, fulfill_proof_system);
                        }
                        clear_submitting("verifier rejected the proof — releasing").await;
                        return Err(anyhow::anyhow!(
                            "fulfil rejected by the verifier (VerifierCallFailed, no governance cause) \
                             — releasing"
                        ));
                    }
                    Ok(true) => tracing::warn!(
                        "KEEP: {} VerifierCallFailed while the Registry is paused or the adapter is \
                         Disabled — holding the lock (time is credited)",
                        short_id(job_id)
                    ),
                    Err(err) => tracing::warn!(
                        "KEEP: {} VerifierCallFailed and the governance re-read failed ({err:#}) — \
                         holding the lock and retrying",
                        short_id(job_id)
                    ),
                }
            }
            FulfilClass::Keep => tracing::warn!(
                "KEEP: {} fulfil held ({reason}) — keeping the lock; the clock is credited while the \
                 state lasts",
                short_id(job_id)
            ),
            FulfilClass::Stale => {
                // The lock is gone (another party's graceRelease, a slash, a reopen) or the job settled:
                // stop publishing. Nothing of ours is locked, so there is nothing to release.
                // `fulfill_job` only returns Stale once a `jobs()` read pinned at or after the lock
                // block agrees (a lagging preflight node's JobNotLocked is retried, not trusted).
                tracing::warn!("LOCK-LOST: {} — {reason}", short_id(job_id));
                journal_update(journal, |j| j.remove(job_id));
                // No release will ever run for this job, and release is the stash's only consumer.
                if let Some(n) = client.take_abandoned_nonce(job_id) {
                    client.abort_nonce(n);
                }
                let mut s = state.write().await;
                s.active_jobs.retain(|j| j.info.job_id != job_id);
                s.add_log(
                    LogLevel::Warn,
                    format!("Job {}: lock lost ({reason})", short_id(job_id)),
                );
                return Ok(());
            }
            FulfilClass::Late => {
                // Past D+G: never resend (a late fulfil only publishes the proof). A release would
                // revert too — `release_and_clean` sees the passed cutoff and leaves it to the slash.
                tracing::error!(
                    "PAGE: LOCK-LATE: {} — {reason}; the lock will be slashed",
                    short_id(job_id)
                );
                clear_submitting("past the fulfil window").await;
                return Err(anyhow::anyhow!("fulfil window passed for {}: {reason}", short_id(job_id)));
            }
            // An unclassifiable failure (no revert data, an RPC outage, an exhausted gas bump) is never
            // a release reason on its own: retry until the window closes (the budget check above
            // releases then — 5% beats a 100% slash).
            FulfilClass::Gas | FulfilClass::Unknown => tracing::warn!(
                "{}: fulfil not settled ({reason}) — retrying",
                short_id(job_id)
            ),
        }
        // Shutting down: a lock held by governance has nothing to wait for here, so leave it to the
        // next start (breadcrumb and stashed nonce kept, exit 75). Every other class keeps retrying —
        // the drain waits for a Submitting job, and an RPC-class failure is never a release reason: a
        // release now would out-bid and evict our own pending, valid fulfil.
        if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst)
            && matches!(class, FulfilClass::Keep | FulfilClass::VerifierFailed)
        {
            clear_submitting("shutdown during a held fulfil").await;
            return Err(HandBack(format!("shutdown while the fulfil is held: {reason}")).into());
        }
        // Never sleep past the release point: the release must start with its whole reserved ladder
        // (DEADLINE_RELEASE_MARGIN_SECS) still ahead of the window's close. When the next round
        // would have too little budget, go to the release now instead of after one more wait.
        match deadline_proof_budget(lock_deadline) {
            Some(b) if b <= FULFIL_RETRY_WAIT + Duration::from_secs(MIN_ATTEMPT_BUDGET_SECS) => {
                if refresh_lock_deadline(client, journal, job_id, &mut lock_deadline).await {
                    continue;
                }
                if clock_stopped_or_unknown(client, fulfill_proof_system, b).await {
                    tokio::time::sleep(FULFIL_RETRY_WAIT).await;
                    continue;
                }
                clear_submitting("fulfil window closing — releasing").await;
                return Err(anyhow::anyhow!(
                    "fulfil window for {} closing ({}s before the release cutoff) — releasing to \
                     recover collateral",
                    short_id(job_id),
                    b.as_secs()
                ));
            }
            // A published fulfil that is merely unconfirmed resumes its nonce at once: its fee climbs
            // per send, and an idle gap here only makes holding it out of blocks cheaper.
            _ if published_unconfirmed => tokio::time::sleep(Duration::from_secs(1)).await,
            _ => tokio::time::sleep(FULFIL_RETRY_WAIT).await,
        }
    }

    // 12. Success — drop from journal and move to completed_jobs.
    note_fulfil_success(program_id, backend);
    clear_preclaim_strikes(job_id);
    journal_update(journal, |j| j.remove(job_id));
    {
        let mut s = state.write().await;
        let completed = s
            .active_jobs
            .iter()
            .find(|j| j.info.job_id == job_id)
            .cloned();
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
        s.add_log(
            LogLevel::Success,
            format!("Job {} fulfilled on-chain", short_id(job_id)),
        );
    }

    Ok(())
}

/// Collapse per-(device, backend) benchmark rows to the per-device throughputs the queue
/// planner takes, for ONE backend — the one the job's proof system resolves to.
///
/// Every GPU present in `rows` is present in the result, so the planner distinguishes
/// "unmeasured under this backend" from "does not exist". A card with no row for `backend`
/// is credited with the slowest GPU throughput seen under ANY backend: pessimistic, which is
/// the only safe direction for an unknown device, but still non-zero. Zero would be read by
/// `plan_admission` as NoUsableDevice, and a backend with no rows at all — SP1 on a rig that
/// has only ever benchmarked risc0 — would then have every job of that proof system refused
/// forever rather than merely sized conservatively.
fn throughputs_for_backend(rows: &[(String, String, f64)], backend: &str) -> Vec<(String, f64)> {
    let slowest_any = rows
        .iter()
        .map(|(_, _, t)| *t)
        .filter(|t| t.is_finite() && *t > 0.0)
        .fold(f64::INFINITY, f64::min)
        .pipe_finite_or(0.0);
    let mut v: Vec<(String, f64)> = Vec::new();
    for (device, row_backend, t) in rows {
        if row_backend != backend {
            continue;
        }
        match v.iter_mut().find(|(id, _)| id == device) {
            // Same (device, backend) measured twice — keep the better figure. It is a real
            // observation of THIS backend, unlike the cross-backend max this replaced.
            Some((_, cur)) => *cur = cur.max(*t),
            None => v.push((device.clone(), *t)),
        }
    }
    for (device, _, _) in rows {
        if !v.iter().any(|(id, _)| id == device) {
            v.push((device.clone(), slowest_any));
        }
    }
    v
}

/// Device throughputs for the LOOK-AHEAD PLANNER's slot model, for one backend.
///
/// Unlike [`throughputs_for_backend`] — which pads every device with a pessimistic cross-backend
/// fallback so the planner can tell "unmeasured" from "absent" — this returns ONLY devices with a
/// genuine, finite, positive, measured row for `backend` WHENEVER ANY such row exists. A card with no
/// genuine row for this backend is either incapable of it (an arch its binary does not cover) or
/// merely unmeasured; either way it must not be modelled as an available proving slot. The planner's
/// slot model reads a padded card as a real idle GPU and will place bonded jobs against it, so on an
/// asymmetric rig the padding makes the planner believe it has more backend-capable devices than it
/// does and over-admit — stranding the surplus past its lock deadline (release penalty / slash).
///
/// Only when NO device has a genuine row for `backend` do we fall back to the padded list, so a
/// never-measured backend (e.g. SP1 on a rig that has only ever benchmarked risc0) is sized
/// conservatively rather than refused forever — the exact case [`throughputs_for_backend`]'s padding
/// exists for. The "genuine" test (finite and > 0, matching `backend`) is identical to the live claim
/// gate's `genuine_throughputs`, so both admission gates agree on which cards can serve the backend.
fn planner_throughputs_for_backend(
    rows: &[(String, String, f64)],
    backend: &str,
) -> Vec<(String, f64)> {
    let mut genuine: Vec<(String, f64)> = Vec::new();
    for (device, row_backend, t) in rows {
        if row_backend != backend || !t.is_finite() || *t <= 0.0 {
            continue;
        }
        match genuine.iter_mut().find(|(id, _)| id == device) {
            Some((_, cur)) => *cur = cur.max(*t),
            None => genuine.push((device.clone(), *t)),
        }
    }
    if genuine.is_empty() {
        throughputs_for_backend(rows, backend)
    } else {
        genuine
    }
}

fn resolve_backend(proof_system_id: alloy::primitives::B256) -> Option<&'static str> {
    use zkminer_chain::auction::ProofSystem;
    match ProofSystem::from_id(proof_system_id)? {
        // The one system this build can prove AND verify end-to-end against the deployed verifier:
        // risc0 3.0.x Groth16 receipts encoded to the 260-byte seal (SELECTOR 0x73c457ba ‖ proof).
        // Checked at startup against the live adapter's native verifier.
        ProofSystem::Risc0Groth16 => Some("risc0"),
        // SP1 6.8.1 (hemilabs/sp1 #19) Groth16 proofs of circuit v6.1.0, the circuit the 743111 SP1
        // verifiers accept; checked at startup against the live adapter's native verifier.
        ProofSystem::Sp1Groth16 => Some("sp1"),
        // NOT SERVED: `sp1.plonk.v1` needs a PLONK prove mode, which the worker does not have (gnark's
        // CPU PLONK prover takes ~3.5 minutes and ~49 GB of RAM a proof on this class of host).
        ProofSystem::Sp1Plonk => None,
        // Not registered on 743111 at launch, and the OpenVM worker cannot prove (every Prove
        // returns an error) yet reports SIMULATED throughput, so the evaluator would find its jobs
        // attractive and claim what it cannot fulfil. Opt in with ZKMINER_ENABLE_OPENVM=1 only once
        // real Halo2 proving lands.
        ProofSystem::OpenVmHalo2 => {
            (std::env::var("ZKMINER_ENABLE_OPENVM").ok().as_deref() == Some("1")).then_some("openvm")
        }
    }
}

/// The backends `resolve_backend` serves in this build.
fn served_backends() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = zkminer_chain::auction::ProofSystem::ALL
        .iter()
        .filter_map(|p| resolve_backend(p.id()))
        .collect();
    out.dedup();
    out
}

/// The lifecycle's working deadline for a Locked job — the instant BOTH v2 windows close:
/// `getJobStatusView().lockDeadline` (EFFECTIVE: pause-credited, extended for downtime) +
/// `PROVER_GRACE` (30 min). A fulfil is accepted while job-local time is at or before it and a
/// release only strictly before it (handoff §4), so every deadline guard here (prove budget, fulfil
/// budget, release margin, recovery, shutdown ordering) targets this value. Never the RAW
/// `jobs().lockDeadline` / `JobClaimed.lockDeadline`, which ignore pauses. 0 = unknown / not Locked.
fn effective_cutoff(view: &zkminer_contracts::bindings::JobStatusView) -> u64 {
    match view.lockDeadline.to::<u64>() {
        0 => 0,
        d => d.saturating_add(zkminer_chain::auction::PROVER_GRACE_SECS),
    }
}

/// For the fulfil loop's "window closing" exits: true while the job's clock is stopped (a hold, a
/// resume grace) — or while its state is UNREADABLE and some budget is still left. An exit throws the
/// finished proof away (release_and_clean would just KEEP the lock during a pause), so one failed read
/// must not cause it; the budget reaching zero still does.
async fn clock_stopped_or_unknown(client: &ChainClient, proof_system_id: B256, budget: Duration) -> bool {
    for i in 0..2 {
        match client.job_clock_state(proof_system_id).await {
            Ok(c) => return c.hold.is_some() || c.tail > 0,
            Err(_) if i == 0 => tokio::time::sleep(Duration::from_secs(2)).await,
            Err(_) => {}
        }
    }
    !budget.is_zero()
}

/// Re-read a lock's EFFECTIVE cutoff and, if it moved out (pause credit, a Disabled window, a
/// downtime extension), raise `lock_deadline` and the journal breadcrumb to it. True if it moved.
async fn refresh_lock_deadline(
    client: &ChainClient,
    journal: &SharedJournal,
    job_id: B256,
    lock_deadline: &mut u64,
) -> bool {
    let Ok(v) = client.get_job_status_view(job_id).await else {
        return false;
    };
    if v.prover != client.address {
        return false;
    }
    let c = effective_cutoff(&v);
    if c <= *lock_deadline {
        return false;
    }
    *lock_deadline = c;
    journal_update(journal, |j| {
        if let Some(e) = j.entries.get_mut(&job_id) {
            e.lock_deadline = c;
        }
    });
    true
}

/// How often the brain re-reads the router/Registry pause state before claiming.
const PAUSE_POLL_EVERY: Duration = Duration::from_secs(30);

/// Wait between fulfil rounds while a lock is KEPT through a temporary protocol state (pause, disabled
/// adapter, pending settlement) or an unclassifiable failure.
const FULFIL_RETRY_WAIT: Duration = Duration::from_secs(30);

/// Remaining time we may spend proving a job before we must stop and release it,
/// keeping [`DEADLINE_RELEASE_MARGIN_SECS`] of room before `lock_deadline` so a
/// `releaseJob` still lands (it reverts at/after the deadline, stranding the
/// collateral until a slash). Returns `None` when the deadline is unknown (0) —
/// no clamp is applied. `Some(0)` means no budget is left at all.
fn deadline_proof_budget(lock_deadline: u64) -> Option<Duration> {
    if lock_deadline == 0 {
        return None;
    }
    let now = zkminer_chain::client::chain_now();
    Some(Duration::from_secs(lock_deadline.saturating_sub(
        now.saturating_add(DEADLINE_RELEASE_MARGIN_SECS),
    )))
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
    let now = zkminer_chain::client::chain_now();
    if now.saturating_add(margin_secs) >= lock_deadline {
        anyhow::bail!(
            "deadline too close: now={}, lock_deadline={}, margin={}s",
            now,
            lock_deadline,
            margin_secs,
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
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
async fn measure_cycles(
    client: &ChainClient,
    state: &zkminer_tui::state::SharedState,
    backend: &str,
    // The sizes to measure at (see `measure_sizes`): every risc0 card size, each its own execute.
    sizes: &[u8],
    // How many of the sizes still to measure to execute now (the measure budget admitted them); the
    // rest are measured on later ticks.
    max_executes: usize,
    job_id: alloy::primitives::B256,
    descriptor_hash: alloy::primitives::B256,
    program_id: alloy::primitives::B256,
    measured: &MeasuredCache,
    desc_input: &DescInputCache,
    measuring_inputs: &std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashSet<(u8, alloy::primitives::B256, alloy::primitives::B256)>,
        >,
    >,
    measure_strikes: &MeasureStrikes,
    measured_journal: &JournalLenCache,
    desc_payload: &DescPayloadCache,
    assigned_elsewhere: &AssignedElsewhere,
    // Whether this measurement's outcome paces the brain's claims: transient-failure back-offs,
    // their clearing on success, and the program cooldowns. The watch-only inspector measures
    // every job and retries on its own schedule, so its measurements must not (a real miner would
    // not have been held back by them).
    paces_claims: bool,
) {
    // Cheap availability probe FIRST, for THIS backend. The fetches below can hit the chain, and
    // under load most measurement attempts are skipped for a busy worker — doing the RPC work only to
    // throw it away wastes a throttled connection the proving path needs. A busy worker is a TRANSIENT
    // condition: cache nothing and return so a later tick retries. risc0 and sp1 both
    // measure (sp1 on a CPU executor); a non-measurable backend is never triggered.
    // Accept a DOWN-but-revivable worker here too: `execute_cycles` can respawn one for a
    // (VRAM-cheap) measurement, and gating that out would reintroduce the claim↔measure deadlock for a
    // backend whose only worker was recycled. A BUSY worker is still skipped (the probe excludes it).
    match zkminer_prover::engine::worker_pool() {
        Some(pool) if pool.has_idle_or_revivable_worker(backend) => {}
        _ => return,
    }

    // Already known permanently undecodable (proxy/multicall submit tx): skip WITHOUT re-running the
    // up-to-500k-block descriptor scan. The candidate loop evicts these, but guard here too so a race
    // in the window before the eviction propagates cannot re-trigger the scan.
    if job_is_undecodable(job_id) {
        return;
    }

    // SP1 requires a program-wide registry `elf_hash` to guarantee measure-ELF == prove-ELF: SP1 has no
    // cheap programId->bytes binding (its vkey needs the minutes-long `setup`), so the ONLY guarantee is
    // that `download_elf` enforces `elf_hash` as its `expected_hash` against EVERY served URI, on BOTH
    // the measure and the prove fetch. A per-URI `content_hash` does NOT suffice — download_elf serves
    // the first reachable URI and checks only that one (skipping a zero hash), so a zero-hash sibling URL
    // is served unverified and two URIs pinned to different hashes let a submitter serve cheap-at-measure
    // / heavy-at-prove: the measure-cheap/prove-heavy SLASH. risc0 is EXEMPT (its image-id binds the
    // whole ELF to programId at measure AND prove). This requirement is PROGRAM-wide (independent of
    // inputData), so check it HERE — before the (potentially 500k-block) descriptor scan — and decline a
    // no-hash program without that scan. The absence is temporal (see SP1_ELF_HASH_RECHECK_TTL), so it is
    // a self-healing cooldown, not a permanent mark.
    if backend == "sp1" {
        if sp1_elf_hash_missing_recently(program_id) {
            return;
        }
        match client.get_program_info(program_id).await {
            Ok(info) if info.elf_hash.is_none() => {
                tracing::warn!(
                    "measure {} (sp1): registry carries no program-wide elf_hash yet — refusing to \
                     size; re-checking after {}s",
                    short_id(program_id),
                    SP1_ELF_HASH_RECHECK_TTL.as_secs()
                );
                if paces_claims {
                    mark_sp1_elf_hash_missing(program_id);
                }
                return;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::debug!(
                    "measure {} (sp1): program-info fetch failed (transient): {e:#}",
                    short_id(program_id)
                );
                return;
            }
        }
    }

    // Locally cached after the first sighting of a descriptor, so a repeat costs no chain traffic.
    // A fetch failure is transient (RPC / storage): cache nothing, retry later.
    // Bound the pre-claim descriptor fetch by wall-clock time. Unlike the prove path
    // (wrapped in `with_deadline_budget`), this fetch had NO overall bound, so a submitter whose
    // storage/descriptor source stalls could pin this measure-budget slot indefinitely — and because a
    // claim now REQUIRES a measurement, a frozen measure budget halts all claiming. The
    // error embeds submitter-controlled text (URI), so sanitize before logging.
    let descriptor = match tokio::time::timeout(
        MEASURE_FETCH_BUDGET,
        fetch_job_descriptor_checked(client, job_id, descriptor_hash),
    )
    .await
    {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            if e.downcast_ref::<zkminer_chain::descriptor::UndecodableDescriptor>()
                .is_some()
            {
                // PERMANENT, deterministic: the authoritative submit tx's selector is not a known entry
                // point (a proxy/multicall wrapper) or its calldata is too short — the descriptor can
                // NEVER be reconstructed, and the submit tx is immutable. Negative-cache it by UNIQUE
                // JOB ID (NOT descriptorHash, which excludes the submitter and is shared with honest jobs
                // carrying the same descriptor) so the candidate loop and this path skip it instead of
                // re-running the up-to-500k-block descriptor scan every tick, WITHOUT false-evicting an
                // honest twin job. `desc_input`/`descriptor_hash` are deliberately NOT touched here.
                tracing::warn!(
                    "measure {}: descriptor is permanently undecodable ({}) — marking this job unclaimable \
                     so it is not re-scanned every tick",
                    short_id(program_id),
                    zkminer_chain::programs::sanitize_log(&format!("{e:#}"))
                );
                mark_job_undecodable(job_id);
                return;
            }
            // Transient — but per-job escalating back-off, so a job whose descriptor keeps failing to
            // fetch (a decoy, or an outage) cannot hold this measure slot on every tick.
            if paces_claims {
                note_transient_preclaim_failure(job_id);
            }
            tracing::debug!(
                "measure {}: descriptor fetch failed (transient, backing off): {}",
                short_id(program_id),
                zkminer_chain::programs::sanitize_log(&format!("{e:#}"))
            );
            return;
        }
        Err(_elapsed) => {
            if paces_claims {
                note_transient_preclaim_failure(job_id);
            }
            tracing::debug!(
                "measure {}: descriptor fetch exceeded the {}s measure-fetch budget — skipping \
                 (transient, backing off); a later tick retries",
                short_id(program_id),
                MEASURE_FETCH_BUDGET.as_secs()
            );
            return;
        }
    };
    // (Pre-claim strikes are cleared only once this job's measurement OUTCOME is final — below — never
    // on a descriptor success alone: a job that fetches fine and then fails later in this path, every
    // time, must keep escalating its back-off.)
    // The v2 binding gate, decided BEFORE executing the guest (it mirrors the lifecycle's pre-claim
    // gate): a job this build can never claim must not spend a measure slot, and must not stay a
    // candidate that wins the price-ordered measure budget on every tick.
    {
        let marker = u32::from_be_bytes(descriptor.journalFields.0[..4].try_into().unwrap());
        if marker >= 0xffff_fffe {
            // A binding marker (journal prefix / SP1 proof nonce) this build cannot satisfy: permanent
            // for this job (its descriptor is immutable), keyed by the unique jobId.
            mark_job_undecodable(job_id);
            return;
        }
        if descriptor.expectedJournalHash == alloy::primitives::B256::ZERO {
            if descriptor.assignedProver != client.address {
                // A NONE job is reserved for its assigned prover for its WHOLE life (the contract keeps
                // `assignedOnly` across release and slash): it can never become ours. Permanent, keyed
                // by jobId, so the candidate loop evicts it.
                tracing::debug!(
                    "measure {}: NONE-bound job {} is reserved for {} — evicting",
                    short_id(program_id),
                    short_id(job_id),
                    descriptor.assignedProver
                );
                mark_job_undecodable(job_id);
                return;
            }
        } else if !state.read().await.runtime_settings.claim_predicate_jobs {
            // FULL/FIELDS-bound and the operator does not claim bound jobs: do not size it. Recorded
            // per jobId, not evicted (the setting is read live, though only the config sets it today).
            mark_job_bound(job_id);
            return;
        }
    }
    // The submitter-controlled descriptor payload (inputData + the two extra-data
    // fields) is re-encoded into the fulfillJob calldata under a fixed gas limit. Its size is known
    // here, PRE-CLAIM — so a descriptor that would OOG-revert fulfill is skipped now (never measured →
    // never claimable for a measurable backend) instead of after the collateral-locking claim, which
    // would force a penalized release. Not negative-cached: the cap mixes fields outside the
    // (program, input) cache key, and the per-tick re-check is cheap (no execution).
    const MAX_DESCRIPTOR_PAYLOAD_BYTES: usize = 96 * 1024;
    let descriptor_payload =
        descriptor.inputData.len() + descriptor.callbackExtraData.len() + descriptor.extraVerifierData.len();
    if descriptor_payload > MAX_DESCRIPTOR_PAYLOAD_BYTES {
        // This descriptor's payload alone would OOG-revert fulfill. Flag it unclaimable (the over-cap
        // bit on its resolver entry, keyed by descriptor hash so it never mis-skips a sibling) so the
        // claim gate short-circuits it on
        // every later tick instead of re-fetching its descriptor and re-occupying a measure-budget
        // slot here forever. Deterministic for this descriptor; the over-cap payload cannot shrink.
        tracing::warn!(
            "measure {}: descriptor payload is {} bytes (> {} cap) — would OOG-revert fulfill; \
             marking unclaimable so it is not re-fetched or re-measured every tick",
            short_id(program_id),
            descriptor_payload,
            MAX_DESCRIPTOR_PAYLOAD_BYTES
        );
        mark_desc_unfulfillable(desc_input, descriptor_hash);
        return;
    }
    // Skip a job the submitter assigned exclusively to a DIFFERENT prover while that exclusivity
    // lasts: the candidate filter gates only on status/prover and JobStatusView does not expose
    // `assignedProver`, so without this we would measure it (burning a measure-budget slot) and quote a
    // claim the contract refuses. The descriptor carries the assignment, `jobs()` the window. Once the
    // window has lapsed (or the job has none), it is anyone's and is measured as usual.
    {
        let assigned = descriptor.assignedProver;
        if assigned != alloy::primitives::Address::ZERO && assigned != client.address {
            // An unreadable record waits the minimum, then reads again.
            let wait = assigned_exclusivity_wait(client, job_id)
                .await
                .unwrap_or(Some(ASSIGNED_ELSEWHERE_TTL));
            if let Some(wait) = wait {
                // Set the job aside (so it leaves the per-tick candidate cut instead of holding a
                // slot every tick) until the window ends.
                tracing::debug!(
                    "measure {}: job assigned to another prover ({}) — skipping for {}s (we cannot \
                     claim it until its exclusivity lapses)",
                    short_id(program_id),
                    assigned,
                    wait.as_secs()
                );
                mark_assigned_elsewhere(assigned_elsewhere, job_id, wait);
                if paces_claims {
                    set_job_aside(job_id, wait);
                }
                return;
            }
        }
    }
    let input: Vec<u8> = descriptor.inputData.to_vec();
    // The cycle count is a function of (backend, size, program, keccak256(input)); the descriptor hash
    // resolves to that input hash. Record the resolver FIRST so a later sighting of this descriptor
    // (e.g. under a different tag, which this task may already have short-circuited) can find the
    // measurement.
    let input_hash = alloy::primitives::keccak256(&input);
    insert_desc_input(desc_input, descriptor_hash, input_hash);
    // Cache THIS descriptor's payload length alongside the resolver, BEFORE the short-circuit and the
    // measuring_inputs dedup CAS below. A descriptor that loses that race returns without running either
    // payload screen, yet it is now claimable (its resolver is recorded); the claim gate re-runs the
    // full-payload check from this cached length plus the winner's journal length (see
    // `claim_payload_over_cap`), so the race loser can no longer slip an over-cap descriptor through.
    insert_desc_payload(desc_payload, descriptor_hash, descriptor_payload as u64);
    let input_key = (backend_tag(backend), program_id, input_hash);
    // The sizes this (backend, program, input) is not measured at yet. A size measured already is
    // reused with NO execution — e.g. the same input flooded under many distinct tags, or the pair
    // measured before a card of another size was added — so only the resolver above needed updating.
    let missing: Vec<u8> = match measured.lock() {
        Ok(m) => sizes
            .iter()
            .copied()
            .filter(|&p| !m.contains_key(&(input_key.0, p, program_id, input_hash)))
            .collect(),
        Err(_) => return,
    };

    // Short-circuit: measured at every size already, so this descriptor hash now points at the known
    // measurements.
    if missing.is_empty() {
        // The journal is a function of (program, input), shared by every descriptor for this pair, so
        // THIS descriptor's full fulfill payload must still be checked even though we skip execution:
        // its callbackExtraData/extraVerifierData differ from the descriptor that was executed. Using
        // the journal length cached when that measurement ran, mark this descriptor unclaimable if its
        // payload is over the cap — otherwise a sibling descriptor with padded extra-data escapes the
        // check entirely and is claimed+proved into a guaranteed-revert fulfill. (If no journal length
        // was cached — an older measurement, or one that failed before producing a journal — skip the
        // check; it is re-done when the pair is next executed.)
        if let Some(journal_len) = get_journal_len(measured_journal, backend, program_id, input_hash) {
            if fulfill_payload_over_cap(
                journal_len,
                descriptor.inputData.len(),
                descriptor.callbackExtraData.len(),
                descriptor.extraVerifierData.len(),
            ) {
                tracing::warn!(
                    "measure {}: a sibling descriptor's fulfill payload (cached journal {} + its \
                     descriptor + seal) exceeds the cap — marking it unclaimable",
                    short_id(program_id),
                    journal_len
                );
                mark_desc_unfulfillable(desc_input, descriptor_hash);
            }
        }
        // The journal is shared by every descriptor for this pair, but the binding is THIS
        // descriptor's: check it against the cached journal so an unsatisfiable sibling is dropped
        // here rather than dispatched.
        let cached_journal: MeasuredJournal = resolve_measured_at(
            measured,
            desc_input,
            backend,
            sizes,
            program_id,
            descriptor_hash,
        )
        .and_then(|r| r.journal);
        drop_if_measured_binding_fails(&descriptor, &cached_journal, job_id, client.address);
        tracing::debug!(
            "measure {}: (backend, program, input) already measured — resolver updated, no execution",
            short_id(program_id)
        );
        if paces_claims {
            clear_preclaim_strikes(job_id);
        }
        return;
    }

    // (The SP1 program-wide `elf_hash` requirement is enforced EARLIER — before the descriptor scan
    // above — via the self-healing SP1_ELF_HASH_MISSING cooldown, so a no-hash program is declined
    // without paying the scan. See that block near the top of this function.)

    // Claim the (backend, program, input) as in-flight BEFORE the expensive fetch +
    // execute. A concurrent burst of the same input under different tags passes the descriptor-hash
    // dedup as distinct descriptors; without this they would all execute the identical heavy input at
    // once. The first task here wins and executes; the rest return (the resolver is already recorded,
    // so they will resolve to the winner's measurement). Released via the guard below on every path.
    let claimed_input = measuring_inputs
        .lock()
        .map(|mut s| s.insert(input_key))
        .unwrap_or(false);
    if !claimed_input {
        tracing::debug!(
            "measure {}: an execution of this exact (backend, program, input) is already in flight",
            short_id(program_id)
        );
        // The winner decides for this descriptor too (its resolver is recorded): no need to take a
        // measure slot again until it has.
        if paces_claims {
            note_job_retry_after(job_id, Duration::from_secs(15));
        }
        return;
    }
    // RAII release so an early return / panic cannot leak the in-flight marker (which would wedge all
    // future measurements of this input).
    struct InputGuard<'a> {
        set: &'a std::sync::Mutex<
            std::collections::HashSet<(u8, alloy::primitives::B256, alloy::primitives::B256)>,
        >,
        key: (u8, alloy::primitives::B256, alloy::primitives::B256),
    }
    impl Drop for InputGuard<'_> {
        fn drop(&mut self) {
            if let Ok(mut s) = self.set.lock() {
                s.remove(&self.key);
            }
        }
    }
    let _input_guard = InputGuard {
        set: measuring_inputs,
        key: input_key,
    };

    // A fetch failure says nothing about one size over another: it strikes every size still to be
    // measured, and strikes them all out together. Returns the highest count.
    let strike_missing = || {
        missing
            .iter()
            .map(|&p| bump_measure_strikes(measure_strikes, backend, p, program_id, input_hash))
            .max()
            .unwrap_or(0)
    };
    let strike_out_missing = || {
        for &p in &missing {
            insert_measured(
                measured,
                backend,
                p,
                program_id,
                input_hash,
                UNMEASURABLE_CYCLES,
            );
            clear_measure_strikes(measure_strikes, backend, p, program_id, input_hash);
        }
    };

    // Bound the pre-claim ELF fetch by wall-clock time, like the descriptor fetch above.
    // `download_elf` also caps the number of URIs tried;
    // together they stop a submitter URI list from pinning this measure-budget slot for minutes.
    // Sanitize the (URI-bearing) error before logging.
    let elf = match tokio::time::timeout(
        MEASURE_FETCH_BUDGET,
        // Measure path (bootstrap): no co-stored hash yet — the risc0 worker's image-id check inside
        // execute_cycles below is the binding, and it is what first produces the hash we store.
        fetch_or_download_elf(client, state, program_id, None, backend != "risc0"),
    )
    .await
    {
        Ok(Ok(e)) => e,
        Ok(Err(e))
            if e.downcast_ref::<zkminer_chain::programs::NoStorageUris>().is_some()
                || e.downcast_ref::<RegistryUnavailable>().is_some() =>
        {
            // Not registered yet, or registered with no URIs yet: says nothing about the program's
            // future. A back-off, never a strike toward a permanent UNMEASURABLE verdict.
            if paces_claims {
                note_transient_preclaim_failure(job_id);
            }
            if paces_claims
                && e.downcast_ref::<zkminer_chain::programs::NoStorageUris>()
                    .is_some()
            {
                mark_program_no_elf_source(program_id);
            }
            tracing::debug!(
                "measure {}: no ELF source now ({e:#}) — backing off",
                short_id(program_id)
            );
            return;
        }
        Ok(Err(e)) => {
            // An ELF fetch failure is usually transient (RPC/storage), but a submitter can make it
            // PERMANENT and free by serving a stalling or withheld ELF: without a bound this re-fetches
            // every tick forever, starving the measure budget and all claiming. Strike-count it per
            // (program, input) exactly like the execute-failure path below — a genuinely transient
            // failure clears on the next success, while a repeatable one is negative-cached
            // UNMEASURABLE after MEASURE_TIMEOUT_STRIKES so it stops being re-selected. (Trade-off,
            // identical to the execute path: a sustained >3-tick outage of a LEGITIMATE program also
            // retires it until restart; the on-disk ELF cache means a once-fetched program never hits
            // this, so it bites only a never-yet-cached program whose host is down during measurement.)
            let strikes = strike_missing();
            if strikes >= MEASURE_TIMEOUT_STRIKES {
                tracing::warn!(
                    "measure {} ({backend}): ELF fetch failed #{strikes} (>= {}) — marking infeasible \
                     so it is not re-fetched or re-measured every tick: {}",
                    short_id(program_id),
                    MEASURE_TIMEOUT_STRIKES,
                    zkminer_chain::programs::sanitize_log(&format!("{e:#}"))
                );
                // PERMANENT: an ELF-fetch failure is submitter-REACHABLE — a hostile submitter serves a
                // failing/withheld ELF deterministically — so a retry TTL would let it re-trigger a
                // fresh fetch (a scarce measure-budget slot) every TTL for each of up to 100k distinct
                // (program, input) pairs, a perpetual sizing DoS. Keep it permanent, as at HEAD. The
                // genuinely-transient case (a legitimate program whose storage blips during its
                // never-yet-cached measurement) is narrow — the on-disk ELF cache means a once-fetched
                // program never hits this — and is the accepted trade-off the strike bound already made.
                strike_out_missing();
            } else {
                tracing::debug!(
                    "measure {}: ELF fetch failed #{strikes} (< {}, may be transient): {}",
                    short_id(program_id),
                    MEASURE_TIMEOUT_STRIKES,
                    zkminer_chain::programs::sanitize_log(&format!("{e:#}"))
                );
            }
            return;
        }
        Err(_elapsed) => {
            // A wall-clock timeout on the fetch (a slow or stalling ELF host) gets the same bounded
            // treatment, so a submitter cannot pin a measure-budget slot for MEASURE_FETCH_BUDGET every
            // tick indefinitely.
            let strikes = strike_missing();
            if strikes >= MEASURE_TIMEOUT_STRIKES {
                tracing::warn!(
                    "measure {} ({backend}): ELF fetch exceeded the {}s budget #{strikes} (>= {}) — \
                     marking infeasible so it is not re-fetched every tick",
                    short_id(program_id),
                    MEASURE_FETCH_BUDGET.as_secs(),
                    MEASURE_TIMEOUT_STRIKES
                );
                // PERMANENT: an ELF-fetch wall-clock timeout is likewise submitter-REACHABLE (a
                // deliberately stalling ELF host), so a retry TTL would reopen the same per-pair
                // re-fetch DoS. Keep it permanent, as at HEAD (see the fetch-failure arm above).
                strike_out_missing();
            } else {
                tracing::debug!(
                    "measure {}: ELF fetch exceeded the {}s budget #{strikes} (< {}) — a later tick \
                     retries (may be transient)",
                    short_id(program_id),
                    MEASURE_FETCH_BUDGET.as_secs(),
                    MEASURE_TIMEOUT_STRIKES
                );
            }
            return;
        }
    };

    let pool = match zkminer_prover::engine::worker_pool() {
        Some(p) => p,
        None => return,
    };

    // Bind the sizing ELF to the programId so the pre-claim measurement path cannot be driven with an
    // ELF unrelated to the registered program. Never against a zero id. risc0's worker checks the image
    // id at execute, which binds the bytes to the programId. SP1's Execute arm does NOT check the vkey
    // (deriving it needs the minutes-long `setup`, which would blow the measure watchdog), so for SP1
    // this `program_id_bytes` is advisory and the load-bearing guarantee is the host-side `elf_hash`
    // gate above.
    let program_id_bytes: Option<[u8; 32]> =
        (program_id != alloy::primitives::B256::ZERO).then(|| program_id.0);

    // Captured before `input` is shared with the blocking closures; the journal-size screen below
    // needs it.
    let input_len = input.len();
    // risc0 binds the ELF bytes to the programId by image-id, which the worker checks INSIDE
    // `execute_cycles` (it refuses to size a mismatched ELF). So a successful risc0 execute proves
    // these exact bytes ARE the registered program: capture their keccak (on the blocking thread,
    // only for risc0, only on success) so the later claim/prove re-fetch can enforce
    // measure-ELF == prove-ELF for risc0 the way the registry `elf_hash` does for SP1 — closing the
    // post-measure ELF-swap slash/blacklist window. The keccak is stored IN the measurement entry
    // (`Measured::verified_elf_hash`), so it co-evicts with the cycle count a claim rides on. SP1 does
    // NOT get this: its Execute arm does not derive the vkey, so keccak(elf) here is not a verified
    // binding; SP1 is bound by the mandatory registry `elf_hash` gate above instead.
    let capture_risc0_keccak = backend == "risc0";
    let elf = std::sync::Arc::new(elf);
    let input = std::sync::Arc::new(input);
    // One execute per missing size, side by side (the brain admitted as many as had free workers; the
    // rest race for one): blocking, since the worker protocol is synchronous, and each bounded by the
    // watchdog inside `execute_cycles`. A size that finds no free measure worker comes back
    // `MeasureSlotsBusy` and is measured on a later tick.
    let runs: Vec<_> = missing
        .iter()
        .take(max_executes.max(1))
        .map(|&po2| {
            let (backend_owned, elf, input) = (backend.to_string(), elf.clone(), input.clone());
            let size = (backend == zkminer_prover_protocol::BACKEND_RISC0).then_some(po2);
            let run = tokio::task::spawn_blocking(move || {
                let out = pool.execute_cycles(
                    &backend_owned,
                    &elf,
                    &input,
                    Some(MEASURE_TIMEOUT),
                    program_id_bytes,
                    size,
                );
                let elf_keccak = (capture_risc0_keccak && out.is_ok())
                    .then(|| alloy::primitives::keccak256(&elf[..]));
                (out, elf_keccak)
            });
            (po2, run)
        })
        .collect();
    let mut elf_cached = false;
    for (po2, run) in runs {
        let res = run.await;
        // risc0 bytes reach the on-disk cache only once the worker has image-id-verified them: an
        // unverified download (a squatted id, a mirror's error page) cached here would be served to
        // every later measurement of the program, across restarts.
        // Once per program: every cached entry is verified, so an existing one is these bytes'
        // program already (rewriting it per measured input would amplify disk writes).
        if !elf_cached && matches!(res, Ok((Ok(_), Some(_)))) {
            elf_cached = true;
            let elf = elf.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let cache = zkminer_chain::programs::ElfCache::new();
                if !cache.contains(&program_id) {
                    if let Err(e) = cache.put(&program_id, &elf) {
                        tracing::warn!("Failed to cache ELF: {e:#}");
                    }
                }
            })
            .await;
        }
        match res {
            Ok((Ok(measurement), elf_keccak)) => {
                let zkminer_prover::dispatcher::ExecuteMeasurement {
                    cycles,
                    journal_len,
                    journal,
                    peak_host_bytes,
                    duration_secs,
                } = measurement;
                if paces_claims {
                    clear_preclaim_strikes(job_id);
                }
                // The guest committed `journal_len` bytes. fulfillJob re-encodes the journal
                // AND the input (plus the rest of the descriptor) into its calldata under a fixed gas
                // limit. Both the journal and the input are a deterministic function of (program, input)
                // at this size — exactly this cache key — so if journal + input ALONE already exceed
                // the fulfill payload cap, fulfill is guaranteed to OOG-revert regardless of the rest of
                // the descriptor, and no proof of this job can EVER be fulfilled. Negative-cache it so
                // the job is never CLAIMED and never re-measured, instead of committing collateral and
                // a full Groth16 proof only to discover the over-cap journal post-prove and release at a
                // penalty. Keyed purely by (program, input), so it never mis-blacklists a sibling
                // descriptor. A worker that does not report the journal length reports journal_len ==
                // 0, which never trips this (screen simply disabled for it).
                if journal_len as usize + input_len > MAX_FULFILL_PAYLOAD_BYTES
                    || journal_len as usize > zkminer_chain::jobs::MAX_JOURNAL_BYTES
                {
                    // journal + input ALONE exceed the cap, or the journal alone exceeds the router's
                    // MAX_JOURNAL_BYTES (32,768; `JournalTooLarge` on every fulfil path): fulfill can
                    // never succeed regardless of the rest of the descriptor, and both terms are a
                    // function of (program, input) — exactly this cache key — so negative-cache the
                    // pair as infeasible (never claimed, never re-measured). A worker that does not
                    // report a journal length sends 0, disabling this.
                    tracing::warn!(
                        "measure {} ({backend}): journal {} bytes (cap {}) + input {} bytes (fulfil \
                         payload cap {}) — the fulfil would revert; marking infeasible so it is never \
                         claimed or re-measured",
                        short_id(program_id),
                        journal_len,
                        zkminer_chain::jobs::MAX_JOURNAL_BYTES,
                        input_len,
                        MAX_FULFILL_PAYLOAD_BYTES
                    );
                    insert_measured(
                        measured,
                        backend,
                        po2,
                        program_id,
                        input_hash,
                        UNMEASURABLE_CYCLES,
                    );
                    clear_measure_strikes(measure_strikes, backend, po2, program_id, input_hash);
                } else {
                    tracing::info!(
                        "measured {cycles} cycles for program {} ({backend}{}) by execution — its \
                         jobs with this input are sized on it once every size is measured",
                        short_id(program_id),
                        if po2 == NO_PO2 {
                            String::new()
                        } else {
                            format!(", po2 {po2}")
                        }
                    );
                    // Cache the journal length FIRST, then the cycle count. Consumers key off the
                    // cycle count (resolve_measured_at / the measure-task short-circuit) and then read
                    // the journal; inserting the journal before the cycle count makes "cycle count
                    // visible" imply "journal visible" (program order + the per-map mutex
                    // release/acquire), so no reader can observe a measurement whose journal length is
                    // not yet cached. This closes the one-tick window in which the claim-gate payload
                    // backstop (claim_payload_over_cap) saw the cycle count but a None journal and
                    // waved an over-cap descriptor through. A LATER descriptor for this same (program,
                    // input) reuses this cycle count and short-circuits without re-executing, yet still
                    // has its own full fulfill payload checked against the cap from this cached journal
                    // length (see the short-circuit above).
                    insert_journal_len(
                        measured_journal,
                        backend,
                        program_id,
                        input_hash,
                        journal_len,
                    );
                    // Cache the cycle count AND the execute's peak host footprint as ONE merged entry
                    // (finding C-8), so they co-evict: the claim gate reads the peak to check it fits
                    // beside the warm sp1-gpu-server at prove time (finding H1) and the prove
                    // reservation folds it in (finding RH2), and a surviving cycle count always carries
                    // its peak rather than desyncing to a 0 that would silently un-gate. 0 peak = older
                    // worker / off-Linux / portable executor = "unknown, do not gate".
                    // Store the keccak of the bytes the risc0 worker just image-id-verified IN the
                    // measurement entry, so it co-evicts with the cycle count (never dropped while the
                    // measurement a claim rides survives). A later claim's ELF re-fetch binds to it,
                    // catching a post-measure ELF swap as a clean pre-claim skip rather than a
                    // prove-time penalized release + permanent blacklist. `elf_keccak` is `Some` only
                    // for a real risc0 measurement; SP1 and the infeasible branches pass `None`.
                    let measured_journal: MeasuredJournal =
                        journal.map(|j| (input_hash, std::sync::Arc::from(j)));
                    insert_measurement(
                        measured,
                        backend,
                        po2,
                        program_id,
                        input_hash,
                        cycles,
                        peak_host_bytes,
                        elf_keccak,
                        measured_journal.as_ref().map(|(_, j)| j.clone()),
                        duration_secs.max(0.0).ceil() as u64,
                    );
                    clear_measure_strikes(measure_strikes, backend, po2, program_id, input_hash);
                    // A guest whose journal depends on the size it runs at is not claimed (see
                    // `resolve_measured_at`): say so once, here.
                    if let Some((_, j)) = measured_journal.as_ref() {
                        let differs = measured.lock().is_ok_and(|m| {
                            sizes.iter().filter(|&&q| q != po2).any(|&q| {
                                m.get(&(input_key.0, q, program_id, input_hash))
                                    .and_then(|e| e.journal.as_ref())
                                    .is_some_and(|other| other[..] != j[..])
                            })
                        });
                        if differs {
                            tracing::warn!(
                                "measure {} ({backend}): its journal at po2 {po2} differs from another \
                                 size's — a guest that commits by the size it runs at is not claimed",
                                short_id(program_id)
                            );
                        }
                    }
                    drop_if_measured_binding_fails(
                        &descriptor,
                        &measured_journal,
                        job_id,
                        client.address,
                    );
                    // journal + input fit, but the full fulfill payload also carries THIS descriptor's
                    // callbackExtraData + extraVerifierData + the proof seal — fields outside the
                    // (program, input) key, so their contribution cannot be folded into the input-keyed
                    // negative-cache above without risking a cross-descriptor skip. Mark THIS descriptor
                    // (only) unclaimable when its full payload is over the cap; the minimal seal
                    // estimate makes this fire only when fulfill is certain to OOG-revert, never a false
                    // skip. The measurement stays cached, so a slimmer descriptor for the same input is
                    // unaffected.
                    if fulfill_payload_over_cap(
                        journal_len,
                        descriptor.inputData.len(),
                        descriptor.callbackExtraData.len(),
                        descriptor.extraVerifierData.len(),
                    ) {
                        tracing::warn!(
                            "measure {} ({backend}): fulfill payload (journal {} + this descriptor + \
                             seal) exceeds the {}-byte cap — marking this descriptor unclaimable (other \
                             descriptors for this input are unaffected)",
                            short_id(program_id),
                            journal_len,
                            MAX_FULFILL_PAYLOAD_BYTES
                        );
                        mark_desc_unfulfillable(desc_input, descriptor_hash);
                    }
                }
            }
            Ok((Err(e), _)) => {
                // A host-RAM admission refusal from the measure path (the shared ledger would be
                // over-committed) is TRANSIENT — nothing ran, the program is fine — so never strike or
                // negative-cache it; skip and let a later tick retry once memory frees. Must precede
                // the strike logic below, which would otherwise treat it as a repeatable execute
                // failure and eventually negative-cache a perfectly measurable program. (A
                // measure-worker death to a HOST OOM is NOT surfaced as HostMemoryShortage from the
                // measure path — see the dispatcher note on finding C deferred to D-B — so it flows
                // through the generic strike path below, exactly as at HEAD.)
                if e.downcast_ref::<zkminer_prover_protocol::types::HostMemoryShortage>()
                    .is_some()
                {
                    tracing::debug!(
                        "measure {}: deferred — host RAM is committed, not sizing now (transient)",
                        short_id(program_id)
                    );
                    continue;
                }
                // Pure scheduling contention (every measure/worker slot busy or down-and-not-
                // revivable): nothing ran, so it is TRANSIENT — never strike or negative-cache it;
                // retry next tick.
                if e.downcast_ref::<zkminer_prover_protocol::types::MeasureSlotsBusy>()
                    .is_some()
                {
                    tracing::debug!(
                        "measure {}: all measure slots busy, not sizing now (transient)",
                        short_id(program_id)
                    );
                    continue;
                }
                // A committed proof reclaimed this measurement's resources (dispatcher preemption,
                // residual A). Nothing about the (program, input) failed — it was healthy and yielded
                // to a bonded job on the marginal box. TRANSIENT, exactly like `MeasureSlotsBusy`: no
                // strike, no negative-cache, no TTL — re-measure next tick once the proof has freed the
                // resources. A hostile guest cannot reach this branch: only the dispatcher's preemption
                // path constructs `MeasurePreempted`, never a worker error carrying guest text.
                if is_measure_preempted(&e) {
                    tracing::debug!(
                        "measure {}: preempted by a claimed proof, not sizing now (transient)",
                        short_id(program_id)
                    );
                    continue;
                }
                let msg = format!("{e:#}");
                // The message embeds guest/worker-controlled text; sanitize before logging
                // (classification still matches the RAW text — the precise cap phrase, not the
                // sanitized one). Two dispositions:
                //
                //  - A CLEAN CAP TRIP is the executor itself reporting it passed the cycle cap:
                //    reliable and deterministic for the (program, input), so negative-cache it
                //    PERMANENTLY on the FIRST sighting (sized infeasible -> never claimed nor
                //    re-measured). risc0 emits "Session limit exceeded"; sp1's cap trip is canonicalized
                //    to "exceeded cycle limit".
                //
                //  - EVERY OTHER failure — a wall-clock watchdog timeout, a guest panic, a
                //    risc0 image-id / SP1 vkey mismatch, any deterministic bad-program error — is
                //    strike-counted per (backend, size, program, input) and negative-cached UNMEASURABLE
                //    after MEASURE_TIMEOUT_STRIKES CONSECUTIVE failures. Without this bound, every
                //    non-wall-clock failure would be left uncached and re-measured every tick FOREVER: a
                //    submitter controls (ELF, input), so a DETERMINISTIC non-cap failure (e.g. an
                //    image-id mismatch, which needs no clever guest) would re-fire the measurement
                //    endlessly — a free, perpetual CPU/sizing DoS that also starves the measure budget.
                //    A genuinely transient failure (a one-off RPC/worker hiccup, or a guest that misses
                //    the 120s budget only under transient host load) clears on the next success
                //    (`clear_measure_strikes` on the Ok path), so the bound only ever retires a
                //    REPEATABLE failure. Matching only the precise cap phrase, never a loose substring
                //    like "cycle", still avoids false-blacklisting.
                let msg_log = zkminer_chain::programs::sanitize_log(&msg);
                let lower = msg.to_lowercase();
                let clean_cap_trip = lower.contains("session limit")
                    || lower.contains("exceeded cycle limit")
                    || lower.contains("exceededcyclelimit");
                // A TYPED, dispatcher-generated signal — NOT a substring of the (guest-controlled)
                // message (finding RH-round2/4). Only the dispatcher's watchdog path constructs
                // `MeasureWallClockTimeout`, so a guest cannot forge the phrase in its panic text to
                // win the lenient retry TTL below. (A cap trip is matched by string, but that only
                // ever grants the SAFE permanent verdict, so forging it is self-defeating.)
                let wall_clock_timeout = is_measure_wall_clock_timeout(&e);
                if clean_cap_trip {
                    tracing::warn!(
                        "measure {} ({backend}): program exceeds the execute cycle cap — marking \
                         infeasible so it is not claimed or re-measured",
                        short_id(program_id)
                    );
                    insert_measured(
                        measured,
                        backend,
                        po2,
                        program_id,
                        input_hash,
                        UNMEASURABLE_CYCLES,
                    );
                    clear_measure_strikes(measure_strikes, backend, po2, program_id, input_hash);
                } else {
                    let kind = if wall_clock_timeout {
                        "wall-clock measure timeout"
                    } else {
                        "execute failure"
                    };
                    let strikes =
                        bump_measure_strikes(measure_strikes, backend, po2, program_id, input_hash);
                    if strikes >= MEASURE_TIMEOUT_STRIKES {
                        tracing::warn!(
                            "measure {} ({backend}): {kind} #{strikes} (>= {}) — cannot be sized across \
                             repeated attempts; marking infeasible so it is not claimed or re-measured: \
                             {}",
                            short_id(program_id),
                            MEASURE_TIMEOUT_STRIKES,
                            msg_log
                        );
                        // TTL **only** for a WALL-CLOCK TIMEOUT: the watchdog SIGKILLed the guest for
                        // not finishing in 120s, which a FEASIBLE guest can hit purely under transient
                        // host load (SP1's CPU executor runs alongside live proofs), so blacklisting it
                        // forever loses a provable job. A non-wall-clock "execute failure" — a guest
                        // panic/trap, a risc0 image-id or SP1 vkey mismatch — is DETERMINISTIC and
                        // submitter-REACHABLE: giving it a retry TTL lets a hostile submitter re-trigger
                        // a fresh ~full-budget execute every TTL for each of up to 100k distinct
                        // (program, input) pairs, a perpetual CPU/sizing DoS (the exact thing the
                        // permanent negative-cache exists to stop). So the deterministic case stays
                        // PERMANENT, as at HEAD. (Residual, accepted: a guest crafted to
                        // deterministically time out at ~120s is re-measured once per TTL, bounded by
                        // the 2-slot measure budget — far weaker than the one-shot-then-permanent flood,
                        // and indistinguishable from a feasible-but-slow guest, which is the case the
                        // TTL is for.)
                        if wall_clock_timeout {
                            insert_unmeasurable(measured, backend, po2, program_id, input_hash);
                        } else {
                            insert_measured(
                                measured,
                                backend,
                                po2,
                                program_id,
                                input_hash,
                                UNMEASURABLE_CYCLES,
                            );
                        }
                        clear_measure_strikes(
                            measure_strikes,
                            backend,
                            po2,
                            program_id,
                            input_hash,
                        );
                    } else {
                        tracing::debug!(
                            "measure {} ({backend}): {kind} #{strikes} (< {}) — leaving uncached so a \
                             later tick retries (may be transient): {}",
                            short_id(program_id),
                            MEASURE_TIMEOUT_STRIKES,
                            msg_log
                        );
                    }
                }
            }
            Err(join) => {
                tracing::debug!(
                    "measure {}: measurement task panicked (transient): {join}",
                    short_id(program_id)
                );
            }
        }
    }
}

async fn fetch_or_download_elf(
    client: &ChainClient,
    state: &zkminer_tui::state::SharedState,
    program_id: alloy::primitives::B256,
    // The risc0 whole-ELF integrity hash to enforce when the registry carries no `elf_hash` (risc0).
    // For a CLAIM/PROVE fetch this is `snapshot.verified_elf_hash` — the keccak captured and co-stored
    // with the measurement this claim rides on — so a post-measure ELF swap is rejected here instead of
    // reaching prove. `None` on the measure (bootstrap: image-id is the binding) and batch-obtainability
    // paths, and for SP1 (bound by the registry `elf_hash`, which takes precedence below).
    expected_risc0_hash: Option<alloy::primitives::B256>,
    // Enforce the registry `elf_hash`. False for risc0: the registrant can rewrite it at any time, and
    // the image id already binds the bytes to the programId, so it can only purge good bytes.
    honor_registry_hash: bool,
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
            // Cache I/O (a read of up to MAX_ELF_BYTES plus a keccak over it) runs on a blocking
            // thread so a large-ELF flood cannot stall the async runtime's worker threads. Verify
            // the cached bytes against the risc0 verified-keccak when we have one even here (registry
            // down), so a swapped ELF that was somehow cached is still rejected; `None` otherwise
            // (SP1 relies on `elf_hash`, which needs the now-unavailable registry).
            let risc0_hash = expected_risc0_hash;
            let cache_read = cache.clone();
            let cached = tokio::task::spawn_blocking(move || cache_read.get(&program_id, risc0_hash))
                .await
                .ok()
                .flatten();
            if let Some(elf) = cached {
                tracing::warn!(
                    "ProgramRegistry unavailable ({e:#}); using cached ELF for {} ({} bytes)",
                    program_id,
                    elf.len(),
                );
                return Ok(elf);
            }
            return Err(RegistryUnavailable(format!(
                "ProgramRegistry query failed and no cached ELF for {program_id}: {e:#}"
            ))
            .into());
        }
    };
    // The registry marks a program Active / Deprecated / Revoked. A non-Active status
    // (Active is the zero/default variant) means the program author pulled it; proving it wastes GPU
    // + gas. We WARN by default rather than hard-refuse because the exact enum ordering is not
    // encoded in the JSON ABI and a wrong guess would refuse legitimate Active programs. Set
    // ZKMINER_REFUSE_NONACTIVE_PROGRAMS=1 to refuse non-Active programs outright on a deployment
    // whose status mapping you have confirmed.
    if info.status != 0 {
        if std::env::var("ZKMINER_REFUSE_NONACTIVE_PROGRAMS")
            .ok()
            .as_deref()
            == Some("1")
        {
            return Err(anyhow::anyhow!(
                "program {} has non-Active registry status {} — refusing (ZKMINER_REFUSE_NONACTIVE_PROGRAMS=1)",
                program_id,
                info.status
            ));
        }
        tracing::warn!(
            "program {} has non-Active registry status {} (Deprecated/Revoked) — proving anyway; \
             set ZKMINER_REFUSE_NONACTIVE_PROGRAMS=1 to decline",
            program_id,
            info.status
        );
    }
    // Verify a cached/downloaded ELF against the SAME quantity the download enforces when it writes
    // the cache. For SP1 that is the program-wide registry `elf_hash` (mandatory; measure refuses an
    // SP1 program without it). elf_hash and the per-URI content_hash are independent, both
    // submitter-controlled, so verifying the read against a per-URI content_hash that differs from
    // elf_hash would make every cache read mismatch and re-download on every measure/claim/prove — a
    // decoy content_hash would defeat the cache for free. Do NOT fall back to a per-URI content_hash
    // when elf_hash is absent, since download_elf did not enforce that hash on the whole cached file
    // either (only on the one URI it served, when that URI's hash was non-zero), so a decoy on a
    // different URI would again force a re-download.
    //
    // `elf_hash` is absent only for a risc0 program. There we fall back to `expected_risc0_hash` — the
    // keccak captured when the measure worker image-id-verified this program's ELF, co-stored with the
    // measurement this claim rides on and threaded in via the snapshot. It binds measure-ELF ==
    // prove-ELF, so a post-measure swap is rejected HERE (cache purge + a download that fails every
    // mismatching URI -> a clean fetch failure) rather than reaching prove as a penalized release +
    // permanent blacklist. It is `None` on the measure/batch paths and when no real measurement binding
    // exists — there the risc0 image-id check at execute/prove is the binding, as before this fix (a
    // wrong cached ELF simply fails there, it cannot forge).
    //
    // When BOTH exist (a risc0 claim/prove with a measurement binding), the verified measurement keccak
    // WINS: the registrant can rewrite the registry `elfHash` at any time (`setBuildInfo`), so letting
    // it take precedence would let a post-measure swap to a different ELF pass this check — the cached,
    // verified bytes purged, the swapped ones downloaded and accepted — and fault at prove as a
    // penalized release. For risc0 the registry hash adds nothing the image id does not already bind.
    let integrity_hash = if honor_registry_hash {
        expected_risc0_hash.or(info.elf_hash)
    } else {
        expected_risc0_hash
    };
    let expected_cache_hash = integrity_hash;
    let cache_read = cache.clone();
    let cached = tokio::task::spawn_blocking(move || cache_read.get(&program_id, expected_cache_hash))
        .await
        .ok()
        .flatten();
    if let Some(elf) = cached {
        tracing::info!("Using cached ELF for {} ({} bytes)", program_id, elf.len());
        return Ok(elf);
    }
    {
        let mut s = state.write().await;
        s.add_log(
            LogLevel::Info,
            format!(
                "Downloading ELF '{}' ({} URIs)",
                zkminer_chain::programs::sanitize_log(&info.name),
                info.storage_uris.len()
            ),
        );
    }
    let elf = zkminer_chain::programs::download_elf(&info.storage_uris, integrity_hash)
        .await
        .context("ELF download failed")?;
    // Cache only bytes bound to a known hash. Unverified risc0 bytes (the measure bootstrap, a
    // recovery re-fetch) are cached by the measure path once the worker has image-id-verified them.
    if integrity_hash.is_none() && !honor_registry_hash {
        return Ok(elf);
    }
    // Write the cache on a blocking thread (a disk write of up to MAX_ELF_BYTES plus a prune that
    // stats every cache file); the ELF is moved in and handed back out so it is not copied.
    let elf = tokio::task::spawn_blocking(move || {
        if let Err(e) = cache.put(&program_id, &elf) {
            tracing::warn!("Failed to cache ELF: {e:#}");
        }
        elf
    })
    .await
    .map_err(|e| anyhow::anyhow!("ELF cache-write task failed: {e}"))?;
    Ok(elf)
}

/// The ProgramRegistry could not be read (and no cached ELF stood in): an RPC failure, which says
/// nothing about the program — a back-off, never a measure strike.
#[derive(Debug)]
struct RegistryUnavailable(String);

impl std::fmt::Display for RegistryUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for RegistryUnavailable {}

/// What a read pinned at or after the block where we last saw our lock says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockOwnership {
    /// Provably gone: the reopen count has risen since we saw it, or the pinned read shows someone
    /// else (or no one).
    Gone,
    /// The pinned read shows it ours and Locked: a read saying otherwise lags.
    Ours,
    /// Nothing to pin to, or the pinned read failed.
    Unknown,
}

/// Judge our lock on `job_id` given a read that shows it not ours with `reopen_count`. An unpinned
/// read alone may come from a replica still behind our claim, showing the job's previous holder or
/// none; the journal's `lock_reopens` (every way a lock ends bumps the count, but the prover's own
/// pause release, which zkminer never sends) and `lock_block` settle it when they can.
async fn lock_ownership(
    client: &ChainClient,
    journal: &SharedJournal,
    job_id: B256,
    reopen_count: u8,
) -> LockOwnership {
    const JOB_STATUS_LOCKED: u8 = 1;
    let (lock_block, lock_reopens) = {
        let j = journal.lock().unwrap_or_else(|p| p.into_inner());
        j.entries
            .get(&job_id)
            .map_or((0, None), |e| (e.lock_block, e.lock_reopens))
    };
    if lock_reopens.is_some_and(|r| reopen_count > r) {
        return LockOwnership::Gone;
    }
    if lock_block == 0 {
        return LockOwnership::Unknown;
    }
    match client.read_job_record(job_id, Some(lock_block)).await {
        // A record with no caller is a job this router doesn't know (the contracts never delete
        // one): the config names another stack, not proof that our lock ended.
        Ok((rec, _)) if rec.caller == alloy::primitives::Address::ZERO => LockOwnership::Unknown,
        Ok((rec, _)) if rec.prover != client.address => LockOwnership::Gone,
        Ok((rec, _)) if rec.status == JOB_STATUS_LOCKED => LockOwnership::Ours,
        _ => LockOwnership::Unknown,
    }
}

/// The journal's evidence of where we last saw our lock on `job_id` (see `release_job_with_nonce`).
fn lock_seen(journal: &SharedJournal, job_id: B256) -> zkminer_chain::jobs::LockSeen {
    let j = journal.lock().unwrap_or_else(|p| p.into_inner());
    j.entries
        .get(&job_id)
        .map_or_else(Default::default, |e| zkminer_chain::jobs::LockSeen {
            block: (e.lock_block != 0).then_some(e.lock_block),
            reopens: e.lock_reopens,
        })
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
    use zkminer_chain::jobs::GovernanceHold;
    // Read the view first: the governance-hold decision needs the job's proof system.
    let mut view_read = client.get_job_status_view(job_id).await;
    if view_read.is_err() {
        tokio::time::sleep(DEADLINE_READ_RETRY_DELAY).await;
        view_read = client.get_job_status_view(job_id).await;
    }
    let proof_system = view_read
        .as_ref()
        .map(|v| v.proofSystemId)
        .unwrap_or_default();
    let mut hold = client.governance_hold(proof_system).await;
    if hold.is_err() {
        tokio::time::sleep(DEADLINE_READ_RETRY_DELAY).await;
        hold = client.governance_hold(proof_system).await;
    }
    // A state we could not read is UNKNOWN, not "no hold": `releaseJob` has no pause gate, so sending
    // it during a pause we failed to see burns the penalty for nothing, and a Disabled adapter has a
    // free exit (handoff §9: never release on an RPC error). Keep the lock — unless it is inside the
    // release margin, where a release is the only alternative left to a 100% slash.
    // An unreadable view also hides the job's proof system, and with it a Disabled adapter (whose exit is
    // free): resolve it from the router's per-job record instead.
    if view_read.is_err() && hold.is_ok() {
        if let Ok(ps) = client.job_proof_system(job_id).await {
            if ps != B256::ZERO {
                hold = client.governance_hold(ps).await;
            }
        }
    }
    if hold.is_err() || view_read.is_err() {
        // The live (credited) cutoff when the view was read; the journal's only when it was not.
        let cutoff = match &view_read {
            Ok(v) => effective_cutoff(v),
            Err(_) => {
                let j = journal.lock().unwrap_or_else(|p| p.into_inner());
                j.entries.get(&job_id).map(|e| e.lock_deadline).unwrap_or(0)
            }
        };
        let near_cutoff = cutoff != 0
            && zkminer_chain::client::chain_now().saturating_add(DEADLINE_RELEASE_MARGIN_SECS) >= cutoff;
        if !near_cutoff {
            tracing::warn!(
                "KEEP: {} not released — its governance or lock state is unreadable; recovery retries",
                short_id(job_id)
            );
            if let Some(n) = pre_nonce {
                client.abort_nonce(n);
            }
            request_recovery();
            state
                .write()
                .await
                .active_jobs
                .retain(|j| j.info.job_id != job_id);
            return;
        }
    }
    // A pause is NEVER a reason to release (handoff §9, §11): while the router or Registry is paused
    // every lock's effective deadline moves out by the pause's length (and a penalty-free
    // `gracePauseRelease` opens after 15 min), yet `releaseJob` has NO pause gate — a release sent now
    // would land and burn the release penalty for nothing. Keep the lock: retain the breadcrumb (the
    // only record that collateral is locked), refresh its deadline to the credited one (every shutdown
    // decision keys off it), and leave the job to the recovery pass, which re-drives or releases it
    // after the lift. (An unreadable hold state was handled above: kept, unless near the cutoff.)
    if matches!(hold, Ok(Some(GovernanceHold::Paused))) {
        tracing::warn!(
            "KEEP: {} not released — the router or Registry is paused (the deadline is credited); \
             recovery re-drives it after the lift",
            short_id(job_id)
        );
        if let Ok(v) = &view_read {
            let d = effective_cutoff(v);
            if v.prover == client.address && d != 0 {
                journal_update(journal, |j| {
                    if let Some(e) = j.entries.get_mut(&job_id) {
                        e.lock_deadline = d;
                    }
                });
            }
        }
        note_pause_kept(job_id);
        if let Some(n) = pre_nonce {
            client.abort_nonce(n);
        }
        state
            .write()
            .await
            .active_jobs
            .retain(|j| j.info.job_id != job_id);
        return;
    }
    // The job's adapter is DISABLED: a live lock cannot be slashed (its clock is frozen) and
    // `graceRelease` frees the collateral WITHOUT the release penalty `releaseJob` would burn. Exit
    // through it; if it does not confirm, keep the breadcrumb (nothing is at risk while Disabled) and
    // let recovery retry.
    let mut pre_nonce = pre_nonce;
    if let Ok(Some(GovernanceHold::AdapterDisabled)) = &hold {
        const JOB_STATUS_LOCKED: u8 = 1;
        // Keyed on the hold alone: an unreadable view must not route a Disabled-adapter lock to the
        // penalized releaseJob. graceRelease answers Ok(false) itself when the job is not our lock.
        let ours = view_read
            .as_ref()
            .map_or(true, |v| v.prover == client.address && v.status == JOB_STATUS_LOCKED);
        if ours {
            if let Some(n) = pre_nonce.take() {
                client.abort_nonce(n);
            }
            match client.grace_release_job(job_id).await {
                // Refused (the lock was already late when the window opened, is not ours, or the
                // adapter is no longer Disabled): retrying only burns gas — take the normal path below,
                // which releases a live lock or retains a past-deadline one. With no readable view that
                // path cannot tell which, so keep the lock and let recovery re-read it.
                Ok(false) if view_read.is_err() => {
                    request_recovery();
                    state
                        .write()
                        .await
                        .active_jobs
                        .retain(|j| j.info.job_id != job_id);
                    return;
                }
                Ok(false) => {}
                Ok(true) => {
                    journal_update(journal, |j| j.remove(job_id));
                    if let Some(n) = client.take_abandoned_nonce(job_id) {
                        client.abort_nonce(n);
                    }
                    let mut s = state.write().await;
                    s.active_jobs.retain(|j| j.info.job_id != job_id);
                    s.add_log(
                        LogLevel::Warn,
                        format!(
                            "Job {} grace-released (its adapter is Disabled — no penalty)",
                            short_id(job_id)
                        ),
                    );
                    return;
                }
                Err(e) => {
                    tracing::warn!(
                        "graceRelease of {} failed ({e:#}) — keeping the lock (a live lock cannot be \
                         slashed while its adapter is Disabled); recovery retries",
                        short_id(job_id)
                    );
                    request_recovery();
                    state
                        .write()
                        .await
                        .active_jobs
                        .retain(|j| j.info.job_id != job_id);
                    return;
                }
            }
        }
    }
    // The breadcrumb may be ambiguous — a claim whose tx we never confirmed (it may
    // have reverted / never landed, or it may have mined and locked collateral).
    // Check on-chain ownership first so we don't fire a guaranteed-to-revert
    // releaseJob (wasted gas + extra RPC pressure during a 429 storm) on a job we
    // never actually locked. If the check itself fails (RPC), fall through and
    // attempt the release anyway — recovering collateral we might hold outweighs a
    // wasted tx, and a failed release is retained for startup recovery.
    if let Ok(view) = view_read {
        // JobStatus::Locked == 1. releaseJob reverts (JobNotLocked) on anything else,
        // so skip a guaranteed-revert tx when the job isn't ours OR is no longer Locked
        // — the latter catches the race where a fulfill we started actually landed just
        // as we gave up waiting (status now Fulfilled, but prover still == us).
        const JOB_STATUS_LOCKED: u8 = 1;
        // A read showing the job not ours is checked against the journal's evidence: when a read
        // pinned at our lock block shows the lock ours and Locked, this one lags, and the release
        // must still go out.
        let ownership = if view.prover != client.address {
            Some(lock_ownership(client, journal, job_id, view.reopenCount).await)
        } else {
            // Ours: the count it reads now is the floor a later "gone" must rise above.
            journal_update(journal, |j| {
                j.note_lock_seen(job_id, None, view.reopenCount)
            });
            None
        };
        let pinned_ours = ownership == Some(LockOwnership::Ours);
        let not_ours = view.prover != client.address && !pinned_ours;
        let not_locked = view.status != JOB_STATUS_LOCKED && !pinned_ours;
        if not_ours || not_locked {
            // `prover == ZERO` (the job still reads OPEN) does NOT prove our claim never
            // landed: the claimJob(Batch) tx may still be pending, or this node may simply be
            // behind the claim block — the same lag `DEADLINE_READ_RETRIES` exists for, and
            // the reason a post-claim read treats ZERO as UNKNOWN rather than not-ours. A
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
                            || e.lock_deadline > zkminer_chain::client::chain_now_floor(),
                    ),
                    None => (false, false),
                }
            };
            // Another prover on this unpinned read is no better evidence than ZERO: a replica
            // behind our claim still shows the job's previous holder. A risen reopen count, or a read
            // pinned at or after our lock block, settles it.
            let gone = ownership == Some(LockOwnership::Gone);
            if not_ours && !gone && (unconfirmed_claim || deadline_live) {
                // Not provably gone: recovery reads it again soon, rather than at its periodic
                // cadence — a live lock near its margin can't wait that long.
                request_recovery();
                tracing::warn!(
                    "Job {} reads prover {} but our lock is not provably gone — retaining \
                     breadcrumb (claim tx may still be pending, or this read is from a lagging \
                     node; recovery reconciles it)",
                    short_id(job_id),
                    view.prover
                );
                // This arm SKIPS release_job too, and release_job is the only consumer
                // of the abandoned-fulfill stash, so it must drain the stash itself like the
                // sibling arms below. A leaked stash nonce carries NO abort record
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
            // This path SKIPS release_job (the only stash consumer). If a fulfill
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
                format!(
                    "Job {} {} — dropped stale claim breadcrumb",
                    short_id(job_id),
                    why
                ),
            );
            return;
        }
        // releaseJob also reverts ("At or past deadline") once we're at/past
        // lock_deadline. Don't pay gas for that guaranteed revert on every call/
        // restart — retain the breadcrumb; when a keeper slashes the job, prover/status
        // flip and the not-ours/not-locked drop above purges it. (This is the already-
        // stranded case; only a slash frees the collateral now.) Judged with the LOWER chain-time
        // estimate: skipping a release that could still land rides the lock to a 100% slash.
        let now = zkminer_chain::client::chain_now_floor();
        let lock_deadline = effective_cutoff(&view);
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
            tracing::error!(
                "PAGE: LOCK-LATE: {} is past its deadline ({} >= {}) — releaseJob would revert; \
                 retaining breadcrumb (collateral stranded until a keeper slash)",
                short_id(job_id),
                now,
                lock_deadline,
            );
            // Past-deadline SKIPS release_job — drain the fulfill stash so a stashed
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
                format!(
                    "Job {} past deadline — cannot release (stranded until slash)",
                    short_id(job_id)
                ),
            );
            return;
        }
    }

    let seen = lock_seen(journal, job_id);
    let mut release = client.release_job_with_nonce(job_id, pre_nonce, seen).await;
    // Inside the release margin there may be no time for a recovery pass: retry in place while the
    // window is open. A ladder can burn out in seconds on a burst of refused sends. A typed revert is
    // an answer from the chain (past the window, lock gone), so it stops.
    let mut in_place = 0;
    while let Err(e) = &release {
        let recorded = {
            let j = journal.lock().unwrap_or_else(|p| p.into_inner());
            j.entries.get(&job_id).map(|e| e.lock_deadline).unwrap_or(0)
        };
        let near_cutoff = recorded != 0
            && zkminer_chain::client::chain_now().saturating_add(DEADLINE_RELEASE_MARGIN_SECS) >= recorded
            && zkminer_chain::client::chain_now_floor() < recorded;
        if in_place >= 3
            || !near_cutoff
            || e.downcast_ref::<zkminer_chain::revert::FulfilFailure>().is_some()
        {
            break;
        }
        in_place += 1;
        tracing::warn!(
            "release of {} failed inside its margin ({e:#}) — retrying ({in_place}/3)",
            short_id(job_id)
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
        release = client.release_job_with_nonce(job_id, None, seen).await;
    }
    let release_ok = match release {
        Ok(()) => {
            journal_update(journal, |j| j.remove(job_id));
            true
        }
        Err(e) => {
            // Keep the journal entry and ask for a recovery pass soon (not only at the next periodic
            // one, which could land after the window closes).
            tracing::error!(
                "release_job({}) RPC failed: {e:#} — journal entry retained for recovery",
                job_id,
            );
            request_recovery();
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
            format!(
                "Release failed for {} — retained in journal, recovery retries",
                short_id(job_id)
            ),
        );
    }
}

/// Save the journal, logging a warning on error. All transitional state writes
/// go through this helper so that disk-full / permission errors are visible
/// rather than silently swallowed.
fn save_journal_or_warn(journal: &JobJournal) {
    // Never from a watch-only run: the file is the running miner's record of its locks.
    if watch_only() {
        return;
    }
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

/// What a recovery pass decided for one lock we hold. The BRAIN executes these as spawned tasks
/// holding an `in_flight` slot (never inline in the pass), so a recovered lock proves in parallel
/// with the others, one held fulfil (a pause, an unmined tx) cannot block the rest of the pass or the
/// brain loop, and the next pass never double-drives a job a task already owns.
#[allow(clippy::large_enum_variant)] // short-lived, a handful per pass
enum RecoveryAction {
    /// Re-drive prove → fulfil from the lock we hold.
    Drive {
        job: TrackedJob,
        snapshot: JobStatusSnapshot,
        descriptor: zkminer_contracts::bindings::JobDescriptor,
    },
    /// Too little room left (or a permanent defect): release it (or keep it, if a governance hold
    /// says so — `release_and_clean` decides).
    Release(B256),
}

/// The outcome of one [`recover_claimed_jobs`] pass.
struct RecoveryPass {
    /// The pass was cut short (a rate-limit storm, a failed chain scan, a transient descriptor
    /// failure): retry SOONER than the periodic cadence.
    deferred: bool,
    actions: Vec<(B256, RecoveryAction)>,
    /// The incremental locked-job scan state to hand to the next pass.
    scan: Option<RecoveryScan>,
}

/// Incremental discovery of locks we hold. Only the startup pass scans the whole lookback window;
/// later passes scan the blocks since `cursor` and re-read only `known` (ids last seen locked to us,
/// or whose claim may still be pending) plus the journal — so a pass costs O(locks held), not
/// O(every job claimed in the window).
struct RecoveryScan {
    cursor: u64,
    known: std::collections::HashSet<B256>,
}

/// Blocks each incremental recovery scan re-reads behind its cursor (see `recover_claimed_jobs`).
const RECOVERY_SCAN_OVERLAP: u64 = 64;

/// Reconcile every lock we might hold — the journal's breadcrumbs plus every job the chain says we
/// locked within `lookback_blocks` — against live chain state.
///
/// For each job we hold: if there is room, return a `Drive` action (the brain spawns its lifecycle);
/// if not, a `Release` action. Jobs that are no longer ours are dropped from the journal here. Jobs in
/// `skip` (owned by a live lifecycle task) are not touched at all. While the protocol is paused, a
/// lock already KEPT through this pause after its lifecycle failed is left alone until the lift.
async fn recover_claimed_jobs(
    client: &ChainClient,
    journal: &SharedJournal,
    lookback_blocks: u64,
    skip: &std::collections::HashSet<B256>,
    scan: Option<RecoveryScan>,
) -> RecoveryPass {
    // Reconcile everything the journal is tracking, PLUS any job this miner has
    // locked on-chain that the journal doesn't know about (crash before the
    // journal write, a cleared journal, or a claim from a previous machine).
    let (mut job_ids, journal_submit_txs): (Vec<B256>, Vec<(B256, B256)>) = {
        let j = journal.lock().unwrap_or_else(|p| p.into_inner());
        (
            j.entries.keys().cloned().collect(),
            j.iter().filter_map(|e| e.submit_tx.map(|t| (e.job_id, t))).collect(),
        )
    };
    // A held lock's submit tx, persisted with its breadcrumb: its descriptor then rebuilds with one
    // tx read after a restart, not a long log scan an RPC may refuse.
    for (jid, tx) in journal_submit_txs {
        if client.submit_tx_for(jid).is_none() {
            client.note_submit_tx(jid, tx);
        }
    }
    let mut scan_failed = false;
    let mut next_scan = scan;
    let scanned = match client.head_block_cached().await {
        Ok(head) => match &next_scan {
            None => client
                .find_locked_jobs_in(head.saturating_sub(lookback_blocks), head)
                .await
                .map(|(ids, to)| (ids, to, true)),
            // Overlapping the last RECOVERY_SCAN_OVERLAP blocks: the cursor moves to the head we
            // asked for, and a lagging replica can answer for less without an error.
            Some(sc) if head > sc.cursor => client
                .find_locked_jobs_in((sc.cursor + 1).saturating_sub(RECOVERY_SCAN_OVERLAP), head)
                .await
                .map(|(ids, to)| (ids, to, false)),
            Some(sc) => Ok((Vec::new(), sc.cursor, false)),
        },
        Err(e) => Err(e),
    };
    match scanned {
        Ok((onchain, to, full)) => {
            let sc = next_scan.get_or_insert_with(|| RecoveryScan {
                cursor: to,
                known: Default::default(),
            });
            if full {
                sc.known.clear();
            }
            sc.cursor = to;
            sc.known.extend(onchain);
        }
        // A window that could not be scanned may hide a lock we must settle or release before D+G:
        // drive the journal's jobs now, but report the pass DEFERRED so the brain re-scans soon
        // (with its back-off) instead of waiting for the next periodic pass. The cursor stays put.
        Err(e) => {
            tracing::warn!("recover: on-chain locked-job scan failed: {e:#}");
            scan_failed = true;
        }
    }
    if let Some(sc) = &next_scan {
        let mut discovered = 0usize;
        for jid in &sc.known {
            if !job_ids.contains(jid) {
                job_ids.push(*jid);
                discovered += 1;
            }
        }
        if discovered > 0 {
            tracing::debug!("recover: {discovered} on-chain claimed job(s) not in the journal");
        }
    }
    // Ids found settled / not ours this pass: dropped from `known` at the end.
    let mut settled: Vec<B256> = Vec::new();
    // A live lifecycle task owns these: it is the only writer of their breadcrumbs.
    job_ids.retain(|jid| !skip.contains(jid));
    if !job_ids.is_empty() {
        tracing::info!(
            "recover: reconciling {} claimed/locked job(s)",
            job_ids.len()
        );
    }
    // One pause read per pass (a failed read counts as not paused: the per-job paths re-check).
    let paused = matches!(client.protocol_paused().await, Ok(true));

    // Fetch EVERY candidate's view in ONE (chunked) batch and FILTER to jobs we
    // currently hold Locked, up front. Terminal/not-ours jobs are dropped from the journal here
    // using the batch views. The pass no longer awaits any lifecycle inline, so these views stay
    // fresh for every room decision below (an inline re-drive held through a pause used to make
    // them stale by the whole pause, and later locks were released despite their pause credit).
    let views_map: std::collections::HashMap<B256, zkminer_contracts::bindings::JobStatusView> =
        client
            .get_job_status_views_batch(&job_ids)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(jid, v)| v.map(|view| (jid, view)))
            .collect();

    const JOB_STATUS_LOCKED: u8 = 1;
    // Breadcrumbs whose claim tx could still be LIVE. `prover == ZERO` (the job reads
    // OPEN) is UNKNOWN, never "not ours": a claim still pending and a lagging post-mine read
    // are indistinguishable from it — the rule `release_and_clean` already applies. Dropping such
    // an entry is irreversible. Bound it by the same age the drain uses, so a claim that genuinely
    // lost is still GC'd once it ages out. Judged with the LOWER chain-time estimate: a breadcrumb
    // is only declared dead once it surely is.
    let live_claim_intent: std::collections::HashSet<B256> = {
        let now_s = zkminer_chain::client::chain_now_floor();
        let j = journal.lock().unwrap_or_else(|p| p.into_inner());
        j.iter()
            .filter(|e| {
                // An entry past `Claiming` has POSITIVELY OBSERVED the lock (`mark_claimed` only runs
                // after a view returned a nonzero lockDeadline), so retain it while its recorded
                // deadline is live even when it is older than the claim-intent age bound.
                now_s.saturating_sub(e.claimed_at.max(0) as u64) <= CLAIM_INTENT_MAX_AGE_SECS
                    || e.lock_deadline > now_s
            })
            .map(|e| e.job_id)
            .collect()
    };
    // Live breadcrumbs this unpinned batch shows not ours whose lock is provably gone (a risen
    // reopen count, or a read pinned at or after our lock block): without that it is only a
    // lagging read.
    let mut lock_gone: std::collections::HashSet<B256> = std::collections::HashSet::new();
    for jid in &job_ids {
        if let Some(v) = views_map.get(jid) {
            if v.prover != client.address
                && live_claim_intent.contains(jid)
                && lock_ownership(client, journal, *jid, v.reopenCount).await == LockOwnership::Gone
            {
                lock_gone.insert(*jid);
            }
        }
    }
    let before = job_ids.len();
    let mut open_intent = false;
    job_ids.retain(|jid| match views_map.get(jid) {
        // Ours AND still Locked → re-drive. Persist a breadcrumb NOW for anything
        // `find_locked_jobs` discovered that the journal lacks: the drain union, the abandon list
        // and the EX_TEMPFAIL gate ALL read only `active_jobs ∪ journal`. This view has just
        // PROVEN the collateral is ours and locked.
        Some(v) if v.prover == client.address && v.status == JOB_STATUS_LOCKED => {
            let d = effective_cutoff(v);
            if !journal_has(journal, *jid) {
                tracing::warn!(
                    "recover: {} is locked to us with no journal entry — recording breadcrumb \
                     so the shutdown drain/abandon can see it",
                    jid
                );
                journal_update(journal, |j| j.mark_claimed(*jid, None, d));
            } else if d != 0 {
                // Backfill the authoritative (pause-credited) deadline onto an EXISTING breadcrumb
                // too: every shutdown decision keys off it. Field-level write, not `mark_claimed`:
                // that would regress a Proving/Fulfilling entry's state back to Claimed.
                journal_update(journal, |j| {
                    if let Some(e) = j.entries.get_mut(jid) {
                        e.lock_deadline = d;
                    }
                });
            }
            journal_update(journal, |j| j.note_lock_seen(*jid, None, v.reopenCount));
            true
        }
        // Reads OPEN (prover == ZERO), or held by ANOTHER prover, while our claim could still be in
        // flight or our recorded lock is live → UNKNOWN, not "not ours". This read is unpinned: a
        // replica below our claim block still shows the job's previous state. Another prover is
        // proof only when a read pinned at or after our lock block shows it too (`foreign_confirmed`:
        // a lock does pass on, by our release, a grace release anyone may send while the adapter is
        // Disabled, or a slash). KEEP the breadcrumb but do not re-drive it this pass.
        Some(v)
            if v.prover != client.address
                && live_claim_intent.contains(jid)
                && !lock_gone.contains(jid) =>
        {
            tracing::warn!(
                "recover: {} reads {} but our claim may still be pending or the read lags — \
                 retaining breadcrumb",
                jid,
                if v.prover == alloy::primitives::Address::ZERO {
                    "OPEN".to_string()
                } else {
                    format!("held by {}", v.prover)
                }
            );
            // Look again soon, not at the periodic cadence: if that claim lands, the lock needs a
            // driver well before a short job's window closes.
            open_intent = true;
            false
        }
        // Present but settled / held by another prover → drop the stale breadcrumb.
        Some(_) => {
            settled.push(*jid);
            journal_update(journal, |j| j.remove(*jid));
            take_pause_kept(*jid);
            // Dropping the breadcrumb means no `release_job` will ever run for this job again,
            // and that is the ONLY consumer of the abandoned-nonce stash. Leaking one leaves a
            // hole with no local trace that wedges the whole signer.
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
                let d = effective_cutoff(v);
                if d == 0 {
                    u64::MAX
                } else {
                    d
                }
            })
            .unwrap_or(u64::MAX)
    });

    // `deferred` = the pass left work for a sooner retry. `storm_probed` = we already spent our
    // ONE single-shot re-read this pass, so subsequent unreadable jobs defer without fanning out.
    let mut deferred = false;
    let mut storm_probed = false;
    let mut actions: Vec<(B256, RecoveryAction)> = Vec::new();
    for jid in job_ids {
        // Shutdown can begin MID-PASS. Break, don't continue: the remaining ids keep their journal
        // breadcrumbs and are released nearest-deadline-first by the abandon path.
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
                let rate_limited = client
                    .rpc_meter()
                    .rate_limited_within(std::time::Duration::from_secs(5));
                // Under a storm, spend ONE bounded single-shot probe on the first unreadable job,
                // then defer the rest (they keep their breadcrumbs and are retried sooner).
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
                            tracing::warn!(
                                "recover: storm probe of {} failed ({e:#}) — deferring, will retry sooner",
                                jid
                            );
                            deferred = true;
                            break;
                        }
                        tracing::warn!("recover: view for {} failed: {e:#}", jid);
                        deferred = true;
                        continue;
                    }
                }
            }
        };
        if view.prover != client.address {
            // ZERO = the job reads OPEN = UNKNOWN, not "not ours", and so is another prover on this
            // unpinned read (see the batch arm above) unless a read pinned at our lock block agrees
            // — keep the breadcrumb while our claim could still be live; a later pass GCs it once it
            // ages out.
            if live_claim_intent.contains(&jid)
                && lock_ownership(client, journal, jid, view.reopenCount).await
                    != LockOwnership::Gone
            {
                tracing::warn!(
                    "recover: {} reads prover {} but our claim may still be pending or the read \
                     lags — retaining breadcrumb",
                    jid,
                    view.prover
                );
                open_intent = true;
                continue;
            }
            tracing::info!("recover: {} no longer ours (prover={})", jid, view.prover);
            settled.push(jid);
            journal_update(journal, |j| j.remove(jid));
            take_pause_kept(jid);
            if let Some(n) = client.take_abandoned_nonce(jid) {
                client.abort_nonce(n);
            }
            continue;
        }
        // Terminal status check (Open=0, Locked=1, Fulfilled=2, Released=3, Cancelled=4): only a
        // Locked job can be fulfilled or released.
        if view.status != 1 {
            tracing::info!(
                "recover: {} has non-Locked status {} — dropping stale journal entry",
                jid,
                view.status,
            );
            settled.push(jid);
            journal_update(journal, |j| j.remove(jid));
            take_pause_kept(jid);
            if let Some(n) = client.take_abandoned_nonce(jid) {
                client.abort_nonce(n);
            }
            continue;
        }
        let lock_deadline = effective_cutoff(&view);
        // Ownership is PROVEN by the read above. An id that reached the loop via the `None => true`
        // arm may have NO journal entry: write one so the shutdown paths can see the lock.
        if !journal_has(journal, jid) {
            tracing::warn!(
                "recover: {} is locked to us with no journal entry — recording breadcrumb so \
                 the shutdown drain/abandon can see it",
                jid
            );
            journal_update(journal, |j| j.mark_claimed(jid, None, lock_deadline));
        }
        journal_update(journal, |j| j.note_lock_seen(jid, None, view.reopenCount));
        // A lock KEPT through this pause after its lifecycle failed: re-driving it now would repeat
        // the failure (the fulfil cannot land until the lift) and releasing would burn the penalty
        // for nothing (handoff §11). Its clock is credited; leave it until the lift.
        if paused && is_pause_kept(jid) {
            tracing::debug!("recover: {} kept through the pause — re-driven after the lift", short_id(jid));
            continue;
        }
        if !paused {
            take_pause_kept(jid);
        }
        let now = zkminer_chain::client::chain_now();
        // Drive any lock with room for a re-drive to start at all: the release margin, one minimum
        // attempt and the fulfil margin. The lifecycle's own deadline budget then releases it in time
        // if the proof can't finish, and the release penalty is flat, so releasing earlier than that
        // (it used to take the whole proving timeout) saves nothing and gives up locks that would
        // have been fulfilled.
        let drive_floor =
            DEADLINE_RELEASE_MARGIN_SECS + MIN_ATTEMPT_BUDGET_SECS + DEADLINE_FULFILL_MARGIN_SECS;
        let recovery_margin = drive_floor;
        // Too little room for a re-drive to start: release now, with the whole ladder ahead. (A lock
        // inside a resume grace has its job-local clock frozen, but the lifecycle's pre-prove fetches
        // are budgeted on the view's room alone, so driving it would only release it there instead.)
        if lock_deadline > 0 && now + recovery_margin >= lock_deadline {
            tracing::warn!(
                "recover: {} past deadline room (now={} deadline={} margin={}s) — releasing",
                jid,
                now,
                lock_deadline,
                recovery_margin,
            );
            actions.push((jid, RecoveryAction::Release(jid)));
            continue;
        }

        // Reconstruct a TrackedJob from the view.
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

        // We need program_id to fetch the ELF — derive from the descriptor (checked fetch, handed
        // to the lifecycle so it is fetched ONCE per recovered job). Only a PERMANENT decode verdict
        // releases: a transient fetch failure on a lock we hold is never a release reason (handoff
        // §9) — keep the breadcrumb and retry sooner.
        let descriptor = match fetch_job_descriptor_checked(client, jid, view.descriptorHash).await
        {
            Ok(d) => d,
            Err(e)
                if e
                    .downcast_ref::<zkminer_chain::descriptor::UndecodableDescriptor>()
                    .is_some() =>
            {
                tracing::error!(
                    "recover: descriptor for {} can never be reconstructed ({e:#}) — releasing",
                    jid
                );
                actions.push((jid, RecoveryAction::Release(jid)));
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    "recover: descriptor fetch for {} failed ({e:#}) — keeping the lock, retrying sooner",
                    jid
                );
                deferred = true;
                continue;
            }
        };
        if let Err(e) = verify_descriptor_hash(&descriptor, view.descriptorHash) {
            tracing::error!(
                "recover: descriptor hash verify failed for {}: {e:#} — releasing",
                jid
            );
            actions.push((jid, RecoveryAction::Release(jid)));
            continue;
        }

        let mut tracked = TrackedJob {
            info: job_info,
            status: zkminer_tui::state::MinerJobStatus::Proving {
                progress: 0.0,
                elapsed_secs: 0,
            },
            current_price: view.currentAuctionPrice.to::<u128>(),
            gpu_bus_id: None,
            prover_backend: String::new(),
            estimated_cycles: view.expectedCycles,
        };
        tracked.info.program_id = descriptor.programId;

        // A program proven unclaimable this session (vkey/image-id mismatch) would re-drive into the
        // identical guaranteed fault: release it directly. The mark is process-wide and reset on
        // restart, so the FIRST job of a mismatched program still re-drives once to establish it.
        if program_vkey_mismatched_for(tracked.info.program_id, snapshot.proof_system_id) {
            tracing::warn!(
                "recover: {} belongs to a program already proved unclaimable this session under its \
                 backend (vkey/image-id mismatch) — releasing instead of re-driving a guaranteed-fail \
                 prove",
                jid
            );
            actions.push((jid, RecoveryAction::Release(jid)));
            continue;
        }
        tracing::info!("recover: re-driving fulfill path for {}", jid);
        actions.push((
            jid,
            RecoveryAction::Drive {
                job: tracked,
                snapshot,
                descriptor,
            },
        ));
    }
    if let Some(sc) = next_scan.as_mut() {
        for jid in &settled {
            sc.known.remove(jid);
        }
    }
    RecoveryPass {
        deferred: deferred || scan_failed || open_intent,
        actions,
        scan: next_scan,
    }
}

/// Execute a recovery pass's actions as spawned tasks, each holding an `in_flight` slot (no
/// collateral: the lock is already reflected in the on-chain stake figures). Shutdown can begin
/// between the pass and here; a lock left undriven keeps its breadcrumb for the abandon path.
#[allow(clippy::too_many_arguments)]
fn spawn_recovery_actions(
    pass_actions: Vec<(B256, RecoveryAction)>,
    in_flight: &mut HashMap<B256, u128>,
    client: &ChainClient,
    state: &zkminer_tui::state::SharedState,
    journal: &SharedJournal,
    done_tx: &mpsc::UnboundedSender<B256>,
    proving_timeout: Duration,
) {
    for (jid, action) in pass_actions {
        if in_flight.contains_key(&jid) || SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
            continue;
        }
        in_flight.insert(jid, 0);
        match action {
            RecoveryAction::Drive {
                job,
                snapshot,
                descriptor,
            } => spawn_lifecycle_task(
                jid,
                job,
                snapshot,
                true,
                client,
                state,
                journal,
                done_tx,
                proving_timeout,
                Some(descriptor),
            ),
            RecoveryAction::Release(jid) => {
                let (c, st, jr, done) = (client.clone(), state.clone(), journal.clone(), done_tx.clone());
                tokio::spawn(async move {
                    let _slot = SlotGuard(jid, done);
                    release_and_clean(&c, &st, &jr, jid).await;
                });
            }
        }
    }
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
    use alloy::primitives::B256;

    /// The terminal-vs-retryable classification is by TYPE, and guest text cannot forge it.
    ///
    /// This replaced a `msg.contains("deadline cutoff") || msg.contains("job deadline reached")`
    /// test applied to a string that embeds a worker's error verbatim — text that can come from the
    /// guest ELF of a submitter's job. Since the terminal arm releases immediately with zero
    /// retries, a guest panicking with the right words ended its own provable job and collected the
    /// release penalty. The forgery assertion below is the one that matters; the positive case only
    /// proves the plumbing is connected.
    #[test]
    fn the_deadline_class_is_typed_and_unforgeable() {
        use zkminer_prover_protocol::types::ProofDeadlineReached;

        let real: anyhow::Error = anyhow::Error::new(ProofDeadlineReached {
            detail: "proof on risc0:cuda:1 stopped: job deadline reached mid-proof".to_string(),
        });
        assert!(real.downcast_ref::<ProofDeadlineReached>().is_some());

        // Survives wrapping, which a substring match in a `{e:#}` chain also would, but a
        // `.context()` that REPLACED the message would not.
        let wrapped = real.context("while proving job 0xabc");
        assert!(
            wrapped.downcast_ref::<ProofDeadlineReached>().is_some(),
            "the class must survive a context layer"
        );

        // A guest ELF panicking with the exact wording must NOT be terminal.
        let forged = anyhow::anyhow!(
            "Proof error from risc0:cuda:0: guest panicked: 'job deadline reached mid-proof, \
             deadline cutoff'"
        );
        assert!(
            forged.downcast_ref::<ProofDeadlineReached>().is_none(),
            "submitter-controlled text must not be able to make a job terminal"
        );
    }

    /// And the two routing branches, which a guest could previously steer.
    ///
    /// `out of memory` in a guest panic sent the retry to the largest card and set a VRAM floor;
    /// `proof is invalid` suppressed the exclusion so the retry landed back on the card that had just
    /// failed. Both are now read from the worker's own `ErrorKind`, which no guest can set.
    #[test]
    fn the_routing_branches_read_the_workers_own_verdict() {
        use zkminer_prover_protocol::types::{ErrorKind, WorkerProofError};

        let oom: anyhow::Error = anyhow::Error::new(WorkerProofError {
            kind: ErrorKind::ResourceExhausted,
            slot_key: "risc0:cuda:0".to_string(),
            message: "cudaMalloc failed".to_string(),
        });
        let w = oom.downcast_ref::<WorkerProofError>().expect("typed");
        assert!(w.is_gpu_oom());
        assert!(!w.is_invalid());

        // A guest claiming to be out of memory, reported by the worker as a plain proof failure.
        let forged: anyhow::Error = anyhow::Error::new(WorkerProofError {
            kind: ErrorKind::ProofFailed,
            slot_key: "risc0:cuda:0".to_string(),
            message: "guest panicked: out of memory, cudaMalloc, bad_alloc".to_string(),
        });
        let f = forged.downcast_ref::<WorkerProofError>().expect("typed");
        assert!(
            !f.is_gpu_oom(),
            "guest text must not route this job onto the biggest card"
        );
        assert!(
            !f.is_invalid(),
            "nor must it suppress the exclusion of the slot that just failed"
        );
        // The old text predicate WOULD have been fooled, which is why this matters.
        assert!(zkminer_prover_protocol::types::is_gpu_oom(&f.message));
    }

    /// The same property for the host-memory class, where a forgery buys the opposite prize:
    /// unbounded free retries that never consume an attempt.
    #[test]
    fn the_host_memory_class_is_typed_and_unforgeable() {
        use zkminer_prover_protocol::types::HostMemoryShortage;

        let real: anyhow::Error = anyhow::Error::new(HostMemoryShortage {
            attempted: false,
            slot_key: "sp1:cuda:0".to_string(),
            needed: 18 << 30,
            reserved: 0,
            available: 4 << 30,
        });
        assert!(real.downcast_ref::<HostMemoryShortage>().is_some());

        let forged = anyhow::anyhow!(
            "Proof error from sp1:cuda:0: guest panicked: 'HOST_MEMORY_SHORTAGE host RAM is short'"
        );
        assert!(
            forged.downcast_ref::<HostMemoryShortage>().is_none(),
            "a guest must not be able to buy itself unlimited retries"
        );
    }

    /// The same property for the GPU-memory class. This arm refunds its attempt AND excludes a slot,
    /// so a forgery buys both free retries and the power to steer a job off a healthy card.
    #[test]
    fn the_gpu_memory_class_is_typed_and_unforgeable() {
        use zkminer_prover_protocol::types::GpuMemoryShortage;

        let real: anyhow::Error = anyhow::Error::new(GpuMemoryShortage {
            slot_key: "sp1:cuda:0".to_string(),
            foreign_bytes: 2 << 30,
            sibling_bytes: 0,
            available_bytes: 14 << 30,
            needed_bytes: Some(16_000_000_000),
            ours_in_the_way: false,
            total_bytes: 16 << 30,
        });
        assert!(real.downcast_ref::<GpuMemoryShortage>().is_some());

        let forged = anyhow::anyhow!(
            "Proof error from sp1:cuda:0: guest panicked: 'GPU memory shortage: another process \
             holds this card'"
        );
        assert!(
            forged.downcast_ref::<GpuMemoryShortage>().is_none(),
            "a guest must not be able to refund its own attempts or exclude a healthy card"
        );
        // Nor may it be mistaken for either neighbouring class, which carry different policies:
        // host RAM does not exclude the slot, and a deadline is terminal.
        assert!(real
            .downcast_ref::<zkminer_prover_protocol::types::HostMemoryShortage>()
            .is_none());
        assert!(real
            .downcast_ref::<zkminer_prover_protocol::types::ProofDeadlineReached>()
            .is_none());
    }

    /// The transient failures that a bare `contains("deadline")` would have swallowed must stay
    /// retryable — the backoff string in particular once caused jobs to be dropped that should have
    /// retried. With the classification typed, none of them can reach the terminal arm at all.
    #[test]
    fn transient_failures_are_not_deadline_terminal() {
        use zkminer_prover_protocol::types::ProofDeadlineReached;
        for m in [
            "Backoff: waiting 4.52991749s before respawning /home/user/.zkminer/provers/zkminer-prove-risc0-cuda",
            "Worker risc0:cuda:0 process died (EOF)",
            "allocation failed on evaluated: 1728053248 bytes",
            "failed to run groth16 prove operation: cudaGetLastError() failed: \"out of memory\"",
        ] {
            let e = anyhow::anyhow!("{m}");
            assert!(
                e.downcast_ref::<ProofDeadlineReached>().is_none(),
                "should be retryable: {m}"
            );
        }
    }

    /// The VRAM floor the OOM arm sets exceeds EVERY card on
    /// this hardware (16303 MiB / 24564 MiB), so using it INSTEAD of excluding the failed
    /// slot would empty the candidate set, `prove_min_vram` would restore the full set, and the
    /// retry would land back on the card that had just OOMed. The floor is a preference
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
    fn a_job_is_priced_at_its_own_backend_not_the_cards_fastest() {
        // gpu0 runs both; sp1 is the slower of the two on it. The bug this guards was a
        // `max` fold over backends, which handed an sp1 job risc0's 3.0M.
        let rows = vec![
            ("gpu0".to_string(), "risc0".to_string(), 3_000_000.0),
            ("gpu0".to_string(), "sp1".to_string(), 1_000_000.0),
        ];
        let sp1 = throughputs_for_backend(&rows, "sp1");
        assert_eq!(sp1, vec![("gpu0".to_string(), 1_000_000.0)]);
        let risc0 = throughputs_for_backend(&rows, "risc0");
        assert_eq!(risc0, vec![("gpu0".to_string(), 3_000_000.0)]);
    }

    #[test]
    fn a_card_unmeasured_under_this_backend_is_present_and_pessimistic() {
        // gpu1 has no sp1 row. It must still appear — absent would read as "no such card" —
        // and at the slowest figure we hold, never at gpu0's faster sp1 number.
        let rows = vec![
            ("gpu0".to_string(), "sp1".to_string(), 2_000_000.0),
            ("gpu1".to_string(), "risc0".to_string(), 900_000.0),
        ];
        let got = throughputs_for_backend(&rows, "sp1");
        assert_eq!(got.len(), 2, "every card must be represented: {got:?}");
        let gpu1 = got.iter().find(|(d, _)| d == "gpu1").expect("gpu1 present");
        assert_eq!(
            gpu1.1, 900_000.0,
            "unmeasured card must take the slowest row"
        );
    }

    #[test]
    fn a_backend_with_no_rows_anywhere_is_still_claimable() {
        // The never-claim trap: all-zero throughputs make `plan_admission` answer
        // NoUsableDevice for every job of this proof system, forever.
        let rows = vec![
            ("gpu0".to_string(), "risc0".to_string(), 3_000_000.0),
            ("gpu1".to_string(), "risc0".to_string(), 1_500_000.0),
        ];
        let got = throughputs_for_backend(&rows, "sp1");
        assert_eq!(got.len(), 2);
        assert!(
            got.iter().all(|(_, t)| *t == 1_500_000.0),
            "unknown backend must fall back to the slowest known GPU, got {got:?}"
        );
    }

    #[test]
    fn an_unresolvable_proof_system_does_not_price_at_the_fastest_card() {
        // `resolve_backend(..).unwrap_or("")` at the call site: the empty backend must match
        // no row, and so must land on the pessimistic path rather than on a real measurement.
        let rows = vec![("gpu0".to_string(), "risc0".to_string(), 3_000_000.0)];
        let got = throughputs_for_backend(&rows, "");
        assert_eq!(got, vec![("gpu0".to_string(), 3_000_000.0)]);
    }

    #[test]
    fn no_rows_at_all_yields_no_slots_rather_than_infinity() {
        // An empty `min` fold is INFINITY, which would read as infinitely fast.
        let got = throughputs_for_backend(&[], "sp1");
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn planner_excludes_a_phantom_card_when_a_genuine_row_exists() {
        // THE F2 CASE. gpu0 runs sp1; gpu1 has only a risc0 row (it cannot run sp1). The padded
        // `throughputs_for_backend` would hand the planner BOTH cards for sp1 — gpu1 as a phantom
        // idle slot at the global-slowest figure — and the planner would place bonded sp1 jobs
        // against a card that can never prove them, over-admitting into a deadline-miss slash. The
        // planner list must carry gpu0 ONLY.
        let rows = vec![
            ("gpu0".to_string(), "sp1".to_string(), 2_000_000.0),
            ("gpu1".to_string(), "risc0".to_string(), 900_000.0),
        ];
        // Confirm the padded list (what the planner used to get) DOES include the phantom...
        assert_eq!(
            throughputs_for_backend(&rows, "sp1").len(),
            2,
            "padded list credits the phantom card (the bug)"
        );
        // ...and the planner list does NOT.
        let got = planner_throughputs_for_backend(&rows, "sp1");
        assert_eq!(
            got,
            vec![("gpu0".to_string(), 2_000_000.0)],
            "planner must model only cards with a genuine sp1 row: {got:?}"
        );
    }

    #[test]
    fn planner_keeps_every_genuine_card_on_a_symmetric_rig() {
        // Both cards have a real sp1 row: both are usable slots, at their own measured figures.
        let rows = vec![
            ("gpu0".to_string(), "sp1".to_string(), 2_000_000.0),
            ("gpu1".to_string(), "sp1".to_string(), 1_400_000.0),
        ];
        let mut got = planner_throughputs_for_backend(&rows, "sp1");
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            got,
            vec![
                ("gpu0".to_string(), 2_000_000.0),
                ("gpu1".to_string(), 1_400_000.0),
            ]
        );
    }

    #[test]
    fn planner_falls_back_to_padded_list_when_no_genuine_row() {
        // No card has an sp1 row at all: fall back to the padded list so a never-measured backend is
        // sized conservatively rather than refused forever (NoUsableDevice for every sp1 job). This
        // matches `throughputs_for_backend`, and the conservative-sizing floor keeps each estimate
        // pessimistic.
        let rows = vec![
            ("gpu0".to_string(), "risc0".to_string(), 3_000_000.0),
            ("gpu1".to_string(), "risc0".to_string(), 1_500_000.0),
        ];
        let got = planner_throughputs_for_backend(&rows, "sp1");
        assert_eq!(got, throughputs_for_backend(&rows, "sp1"));
        assert_eq!(got.len(), 2, "both cards present on the forever-refused fallback");
    }

    #[test]
    fn planner_drops_a_zero_or_nonfinite_genuine_row() {
        // A card with an sp1 row of 0.0 (or NaN) is not a usable slot: `plan_admission` cannot
        // estimate on it. With a sibling genuine row present it is dropped outright — NOT padded,
        // since `genuine` is non-empty — so it can neither be a phantom slot nor drag the fallback in.
        let rows = vec![
            ("gpu0".to_string(), "sp1".to_string(), 2_000_000.0),
            ("gpu1".to_string(), "sp1".to_string(), 0.0),
            ("gpu2".to_string(), "sp1".to_string(), f64::NAN),
        ];
        let got = planner_throughputs_for_backend(&rows, "sp1");
        assert_eq!(
            got,
            vec![("gpu0".to_string(), 2_000_000.0)],
            "only the finite, positive genuine row survives: {got:?}"
        );
    }

    #[test]
    fn planner_with_no_rows_at_all_is_empty() {
        // Empty in -> empty out (-> NoUsableDevice -> not claimed this tick), same as the padded fn.
        assert!(planner_throughputs_for_backend(&[], "sp1").is_empty());
    }


    #[test]
    fn resolve_backend_maps_known_proof_systems() {
        use zkminer_chain::auction::{
            openvm_halo2_v1_id, risc_zero_groth16_v1_id, sp1_groth16_v1_id, sp1_plonk_v1_id,
        };
        assert_eq!(resolve_backend(risc_zero_groth16_v1_id()), Some("risc0"));
        // SP1 Groth16 is served (circuit v6.1.0); PLONK is not.
        assert_eq!(resolve_backend(sp1_groth16_v1_id()), Some("sp1"));
        assert_eq!(resolve_backend(sp1_plonk_v1_id()), None);
        // OpenVM is declined by default (its worker cannot prove).
        if std::env::var("ZKMINER_ENABLE_OPENVM").ok().as_deref() != Some("1") {
            assert_eq!(resolve_backend(openvm_halo2_v1_id()), None);
        }
        // The RETIRED ids (refused at submit on v2) never resolve.
        for retired in ["risczero.v1", "sp1.v1", "openvm.v1"] {
            assert_eq!(resolve_backend(alloy::primitives::keccak256(retired)), None);
        }
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

    /// Pins the arguments in place: a positional call can rotate its last two args and tell
    /// the operator to stake 1 HEMI when they are 4.25 short.
    #[test]
    fn names_the_shortfall_as_the_stake_amount_not_the_gpu_count() {
        // Scenario: 145.75 available, 150.00 per claim, 1 of 2 slots fundable.
        let msg = collateral_warning(
            1,
            2,
            145_750_000_000_000_000_000,
            150 * ONE_HEMI_WEI,
            4_250_000_000_000_000_000,
        );
        assert!(msg.contains("Fix: run `zkminer stake 4.25`"), "got: {msg}");
        assert!(
            msg.contains("1 GPU(s) will sit idle"),
            "GPU count must be a count: {msg}"
        );
        assert!(
            msg.contains("Only 1 of 2 GPU slot(s) fundable"),
            "got: {msg}"
        );
        assert!(msg.contains("145.75 HEMI available"), "got: {msg}");
        assert!(msg.contains("locks up to 150.00 HEMI"), "got: {msg}");
        // The broken strings, asserted absent so they can never come back.
        assert!(
            !msg.contains("stake 1`"),
            "remediation is the GPU count again: {msg}"
        );
        assert!(
            !msg.contains("4.25 GPU"),
            "shortfall leaked into the GPU count: {msg}"
        );
    }

    /// At ~50 HEMI per_claim a remediation scaled to GPU count instead of per_claim undershoots by ~35x.
    #[test]
    fn remediation_scales_with_per_claim_not_with_gpu_count() {
        let msg = collateral_warning(0, 2, 0, 50 * ONE_HEMI_WEI, 50 * ONE_HEMI_WEI);
        assert!(msg.contains("zkminer stake 50.00"), "got: {msg}");
        assert!(msg.contains("2 GPU(s) will sit idle"), "got: {msg}");
    }

    /// Whatever the warning prints must be enough when typed back in.
    #[test]
    fn the_printed_remediation_always_covers_the_shortfall() {
        for shortfall in [
            1u128,
            ONE_HEMI_WEI - 1,
            4_250_000_000_000_000_001,
            149_999_999_999_999_999_999,
            333_333_333_333_333_333,
        ] {
            let printed = fmt_hemi_ceil(shortfall);
            assert!(collateral_warning(1, 2, 0, 150 * ONE_HEMI_WEI, shortfall)
                .contains(&format!("zkminer stake {printed}")));
            let cents: u128 = printed.replace('.', "").parse().unwrap();
            assert!(
                cents * (ONE_HEMI_WEI / 100) >= shortfall,
                "printed {printed} is short of {shortfall} wei"
            );
        }
    }
}

#[cfg(test)]
mod r2_sizing_tests {
    //! The measurement cache is keyed by (programId, keccak256(inputData)) and resolved
    //! through a descriptor-hash -> input-hash map. These tests pin the invariants the claim gate
    //! relies on: a job is sized only once BOTH the resolver and the measurement exist (so an
    //! unmeasured job is never claimable), a repeat input under a new tag reuses the measurement, and
    //! a different input of the same program is sized independently.
    use super::*;
    use alloy::primitives::{keccak256, B256};

    /// The size a risc0 measurement in these tests is taken at.
    const R0: u8 = zkminer_prover_protocol::RISC0_DEFAULT_JOB_PO2;

    fn fresh() -> (MeasuredCache, DescInputCache) {
        (
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        )
    }

    #[test]
    fn unsized_until_both_resolver_and_measurement_present() {
        let (measured, desc_input) = fresh();
        let prog = B256::repeat_byte(0xAA);
        let desc = B256::repeat_byte(0x11);
        let input = b"the-input".to_vec();
        let ih = keccak256(&input);

        // Nothing known yet -> not sized -> NOT claimable.
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc),
            None
        );

        // Resolver alone (descriptor fetched, not yet executed) is still not sized: the claim must
        // wait for the real cycle count, never fall back to the declared value.
        insert_desc_input(&desc_input, desc, ih);
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc),
            None
        );

        // Measurement present for a DIFFERENT input does not size this descriptor.
        insert_measured(&measured, "risc0", R0, prog, keccak256(b"other-input"), 999);
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc),
            None
        );

        // Both present for THIS input -> sized.
        insert_measured(&measured, "risc0", R0, prog, ih, 42_000);
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc),
            Some(42_000)
        );
    }

    #[test]
    fn same_input_under_new_tag_reuses_measurement() {
        let (measured, desc_input) = fresh();
        let prog = B256::repeat_byte(0xBB);
        let input = b"shared-input".to_vec();
        let ih = keccak256(&input);
        // Two distinct descriptor hashes (two tags), same input.
        let desc_a = B256::repeat_byte(0x01);
        let desc_b = B256::repeat_byte(0x02);

        insert_desc_input(&desc_input, desc_a, ih);
        insert_measured(&measured, "risc0", R0, prog, ih, 7_777);
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc_a),
            Some(7_777)
        );

        // A new tag is a miss until its descriptor fetch records the resolver entry — then it resolves
        // to the SAME measurement with no new execution. This is the tag-flood defence.
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc_b),
            None
        );
        insert_desc_input(&desc_input, desc_b, ih);
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc_b),
            Some(7_777)
        );
    }

    #[test]
    fn different_inputs_of_same_program_are_sized_independently() {
        let (measured, desc_input) = fresh();
        let prog = B256::repeat_byte(0xCC);
        let (in_cheap, in_heavy) = (b"cheap".to_vec(), b"heavy".to_vec());
        let (desc_cheap, desc_heavy) = (B256::repeat_byte(0x03), B256::repeat_byte(0x04));

        insert_desc_input(&desc_input, desc_cheap, keccak256(&in_cheap));
        insert_desc_input(&desc_input, desc_heavy, keccak256(&in_heavy));
        insert_measured(&measured, "risc0", R0, prog, keccak256(&in_cheap), 10_000);

        // The cheap input is sized; the heavy input — the input-flood vector — is still UNSIZED and so
        // cannot be claimed on the cheap measurement. This is the exact under-sizing the per-input key closes.
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc_cheap),
            Some(10_000)
        );
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc_heavy),
            None
        );

        // Measure the heavy input as too-heavy (negative cache) -> now sized infeasible.
        insert_measured(
            &measured,
            "risc0",
            R0,
            prog,
            keccak256(&in_heavy),
            UNMEASURABLE_CYCLES,
        );
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc_heavy),
            Some(UNMEASURABLE_CYCLES)
        );
    }

    #[test]
    fn bounded_insert_evicts_and_caps() {
        let mut m: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
        for i in 0..5u32 {
            bounded_insert(&mut m, i, i * 10, 3);
        }
        // Never exceeds the cap.
        assert!(m.len() <= 3);
        // Re-inserting an existing key does not evict (present-key path).
        let before = m.len();
        if let Some((&k, _)) = m.iter().next() {
            bounded_insert(&mut m, k, 123, 3);
            assert_eq!(m.len(), before);
            assert_eq!(m.get(&k), Some(&123));
        }
    }

    // F3: the Open-candidate cap must keep the HIGHEST-value jobs, so a decoy flood cannot evict a
    // legitimately high-value job that merely arrived early.
    #[test]
    fn retain_top_by_key_keeps_the_highest_value_not_the_oldest() {
        // (arrival-id, value). The high-value job (99) arrived FIRST; the rest are cheap decoys.
        let mut v: Vec<(u8, u128)> = vec![(0, 99), (1, 1), (2, 2), (3, 3), (4, 4)];
        retain_top_by_key(&mut v, 3, |&(_, price)| price);
        assert_eq!(v.len(), 3);
        let mut kept: Vec<u128> = v.iter().map(|&(_, p)| p).collect();
        kept.sort_unstable();
        assert_eq!(kept, vec![3, 4, 99], "must retain the 3 highest values");
        assert!(
            v.iter().any(|&(id, _)| id == 0),
            "the high-value job that arrived first must survive the flood"
        );
    }

    #[test]
    fn retain_top_by_key_is_a_noop_within_cap() {
        let mut v: Vec<u128> = vec![5, 1, 9];
        retain_top_by_key(&mut v, 3, |&p| p);
        assert_eq!(v.len(), 3);
        retain_top_by_key(&mut v, 10, |&p| p);
        assert_eq!(v.len(), 3, "cap above len leaves the vec untouched");
    }

    #[test]
    fn measurement_is_isolated_per_backend() {
        // programId, inputData AND proofSystemId are all submitter-chosen, so a cheap
        // risc0 measurement of (P, I) must NOT size an SP1 job carrying the same (P, I) — the SP1
        // worker cannot prove a risc0 ELF (→ release penalty). The backend-qualified key isolates them.
        let (measured, desc_input) = fresh();
        let prog = B256::repeat_byte(0xDD);
        let input = b"shared-input".to_vec();
        let ih = keccak256(&input);
        let desc = B256::repeat_byte(0x05);
        insert_desc_input(&desc_input, desc, ih);

        // Measure it for risc0 only.
        insert_measured(&measured, "risc0", R0, prog, ih, 12_345);
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc),
            Some(12_345)
        );
        // An SP1 job with the SAME programId+input is still UNSIZED (not claimable on risc0's number).
        assert_eq!(
            resolve_measured(&measured, &desc_input, "sp1", &[NO_PO2], prog, desc),
            None
        );
        // Measuring it for SP1 is independent and does not disturb the risc0 entry.
        insert_measured(&measured, "sp1", NO_PO2, prog, ih, 67_890);
        assert_eq!(
            resolve_measured(&measured, &desc_input, "sp1", &[NO_PO2], prog, desc),
            Some(67_890)
        );
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc),
            Some(12_345)
        );
        // The backend tag isolates them even at one size: a risc0 entry at the size SP1's carry does
        // not size an SP1 job.
        let other = keccak256(b"other-input");
        let desc2 = B256::repeat_byte(0x06);
        insert_desc_input(&desc_input, desc2, other);
        insert_measured(&measured, "risc0", NO_PO2, prog, other, 1);
        assert_eq!(
            resolve_measured(&measured, &desc_input, "sp1", &[NO_PO2], prog, desc2),
            None
        );
    }

    #[test]
    fn estimate_never_shrinks_below_measurement() {
        // Mirrors the match in the brain loop: a measurement is a hard floor on the estimate, and an
        // unsized job falls back to the fallback floor (which cannot be claimed, only ranked).
        let est = |declared: u64, measured: Option<u64>| match (declared, measured) {
            (0, Some(c)) => c,
            (0, None) => FALLBACK_ESTIMATED_CYCLES,
            (d, Some(c)) => d.max(c),
            (d, None) => d.max(FALLBACK_ESTIMATED_CYCLES),
        };
        // A tiny declaration cannot shrink a large measurement.
        assert_eq!(est(1, Some(500_000_000)), 500_000_000);
        // A large declaration is honoured over a small measurement (bond-backed, never smaller).
        assert_eq!(est(900_000_000, Some(10_000)), 900_000_000);
        // Unsized: floored, never zero.
        assert_eq!(est(1, None), FALLBACK_ESTIMATED_CYCLES);
        assert_eq!(est(0, None), FALLBACK_ESTIMATED_CYCLES);
    }

    #[test]
    fn wall_clock_timeout_strikes_bound_before_permanent_blacklist() {
        // A wall-clock measure-timeout must NOT permanently blacklist on the first one:
        // it takes MEASURE_TIMEOUT_STRIKES consecutive strikes, and a success (or a clean cap trip)
        // clears the tally so a feasible job that timed out under transient load self-heals.
        let strikes: MeasureStrikes =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let prog = B256::repeat_byte(0xCC);
        let ih = keccak256(b"heavy-input");

        // Each strike returns the running count; the threshold is reached only on the Kth.
        for n in 1..MEASURE_TIMEOUT_STRIKES {
            assert_eq!(bump_measure_strikes(&strikes, "sp1", NO_PO2, prog, ih), n);
            assert!(n < MEASURE_TIMEOUT_STRIKES, "below threshold -> still retryable, not blacklisted");
        }
        assert_eq!(
            bump_measure_strikes(&strikes, "sp1", NO_PO2, prog, ih),
            MEASURE_TIMEOUT_STRIKES,
            "the Kth consecutive wall-clock timeout reaches the blacklist threshold"
        );

        // A success / clean cap trip clears the tally: the count restarts from 1.
        clear_measure_strikes(&strikes, "sp1", NO_PO2, prog, ih);
        assert_eq!(
            bump_measure_strikes(&strikes, "sp1", NO_PO2, prog, ih),
            1,
            "clearing resets the tally so a later transient timeout starts over, never pre-escalated"
        );

        // Strikes are isolated per (backend, size, program, input): a different backend is
        // independent, at its sizes and at the same size alike, and so is another size.
        assert_eq!(bump_measure_strikes(&strikes, "risc0", R0, prog, ih), 1);
        assert_eq!(bump_measure_strikes(&strikes, "risc0", NO_PO2, prog, ih), 1);
        assert_eq!(bump_measure_strikes(&strikes, "risc0", R0 - 1, prog, ih), 1);
    }

    #[test]
    fn prove_sizing_never_sizes_below_the_measured_count() {
        // The prove-path watchdog/VRAM/po2 must size on max(declared, measured), so a
        // submitter who declares a tiny `expectedCycles` cannot shrink the budget below the MEASURED
        // work (which is what admission claimed the job on) and get a feasible proof SIGKILLed.
        const FB: u64 = FALLBACK_ESTIMATED_CYCLES;

        // A tiny declared value can never pull the sizing below the measurement.
        assert_eq!(prove_sizing_cycles(1, Some(200_000_000)), 200_000_000);
        assert_eq!(prove_sizing_cycles(0, Some(200_000_000)), 200_000_000);
        // A declared value LARGER than the measurement raises the sizing (harmless: a larger watchdog
        // only detects a wedge later, bounded by the cap).
        assert_eq!(prove_sizing_cycles(500_000_000, Some(200_000_000)), 500_000_000);

        // With no measurement (recovery / non-measurable backend) the declared value is still
        // adversarial: a nonzero one is floored at FALLBACK, never trusted small...
        assert_eq!(prove_sizing_cycles(1, None), FB);
        assert_eq!(prove_sizing_cycles(FB + 7, None), FB + 7);
        // ...and a zero declaration returns 0 so the caller keeps the old full-timeout fallback.
        assert_eq!(prove_sizing_cycles(0, None), 0);

        // The exploit shape: declared = 1 (floors the raw formula to the 90s watchdog), measured huge.
        // Sizing on `declared` would give a 90s kill; sizing on the measured count is correct.
        let measured = 1_900_000_000; // ~just under the execute cap, a real multi-minute proof
        assert_eq!(prove_sizing_cycles(1, Some(measured)), measured);
        assert!(
            prove_sizing_cycles(1, Some(measured)) > 1,
            "the declared=1 must NOT be the sizing value when a real measurement exists"
        );
    }

    #[test]
    fn unfulfillable_descriptor_skip_is_per_descriptor_and_bounded() {
        // A descriptor whose fulfill payload is over the cap must be skippable WITHOUT blacklisting a
        // sibling descriptor that happens to share the same program+input (the overflow comes from the
        // descriptor's extra-data, which is outside the measurement cache key).
        let desc_input: DescInputCache =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let fat = B256::repeat_byte(0x11);
        let slim = B256::repeat_byte(0x22);
        assert!(!desc_is_unfulfillable(&desc_input, fat));
        mark_desc_unfulfillable(&desc_input, fat);
        assert!(desc_is_unfulfillable(&desc_input, fat), "the over-cap descriptor is flagged");
        assert!(
            !desc_is_unfulfillable(&desc_input, slim),
            "a different descriptor (e.g. a slim one for the same input) is NOT flagged"
        );
        // The verdict rides the SAME entry as the resolver, so it co-evicts with claimability:
        // learning the input hash afterwards preserves the over-cap bit, and the over-cap bit can
        // never outlive the resolver that makes the descriptor claimable.
        insert_desc_input(&desc_input, fat, keccak256(b"some-input"));
        assert!(
            desc_is_unfulfillable(&desc_input, fat),
            "recording the resolver must not clear the over-cap verdict"
        );
        // Idempotent and bounded: re-marking the same descriptor keeps exactly one entry.
        mark_desc_unfulfillable(&desc_input, fat);
        assert_eq!(desc_input.lock().unwrap().len(), 1);
    }

    #[test]
    fn fulfill_payload_over_cap_is_conservative_and_descriptor_sensitive() {
        let cap = MAX_FULFILL_PAYLOAD_BYTES;
        // Clearly under the cap: a big (but MAX_JOURNAL_BYTES-legal) journal with a tiny descriptor
        // still fits, so it must NOT be flagged (no false skip of a job that could fulfill).
        assert!(!fulfill_payload_over_cap(30 * 1024, 1024, 0, 0));
        // The gap the fix closes: the SAME 30 KiB journal (same program+input) with ~100 KiB of
        // descriptor extra-data tips the full payload over the cap, so THIS descriptor is flagged
        // even though the journal+input alone fit.
        assert!(fulfill_payload_over_cap(30 * 1024, 1024, 100 * 1024, 0));
        // A journal that alone exceeds the whole cap is always over, with or without a descriptor.
        assert!(fulfill_payload_over_cap(cap as u64 + 1, 0, 0, 0));
        // Exactly at the cap with the minimal seal is NOT over (strictly-greater comparison, so the
        // minimal-seal estimate can never false-fire on a payload that just fits).
        assert!(!fulfill_payload_over_cap(30 * 1024, cap - 30 * 1024 - MIN_SEAL_BYTES, 0, 0));
    }

    #[test]
    fn journal_len_cache_round_trips_per_backend_program_input() {
        let jc: JournalLenCache =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let prog = B256::repeat_byte(0x33);
        let ih = keccak256(b"some-input");
        assert_eq!(get_journal_len(&jc, "sp1", prog, ih), None);
        insert_journal_len(&jc, "sp1", prog, ih, 70_000);
        assert_eq!(get_journal_len(&jc, "sp1", prog, ih), Some(70_000));
        // Keyed by backend too: a different backend for the same program+input is independent, so a
        // sibling check on one backend never reads the other's journal length.
        assert_eq!(get_journal_len(&jc, "risc0", prog, ih), None);
    }

    #[test]
    fn program_vkey_mismatch_is_keyed_by_program_and_backend() {
        // A (programId, backend) recorded as vkey/image-id-mismatched is permanently unclaimable UNDER
        // THAT BACKEND; an unrelated program is unaffected. Distinct ids keep it independent of any
        // other test touching the process-wide set.
        let bad = B256::repeat_byte(0xab);
        let good = B256::repeat_byte(0xcd);
        assert!(!program_vkey_mismatched(bad, "sp1"));
        mark_program_vkey_mismatch(bad, "sp1");
        assert!(program_vkey_mismatched(bad, "sp1"), "the mismatched (program, backend) is skipped");
        assert!(!program_vkey_mismatched(good, "sp1"), "an unrelated program is not skipped");
        // CRITICAL: a mismatch derived under SP1 must NOT block the SAME programId under risc0 — a
        // submitter-declared proofSystemId cannot be allowed to cross-contaminate a legit program's
        // real backend. This is the defect the (programId, backend) key closes.
        assert!(
            !program_vkey_mismatched(bad, "risc0"),
            "a mismatch under one backend must not block the same programId under another"
        );
        // Idempotent: re-marking the same (program, backend) does not change membership.
        mark_program_vkey_mismatch(bad, "sp1");
        assert!(program_vkey_mismatched(bad, "sp1"));
    }

    #[test]
    fn undecodable_job_cache_is_keyed_by_job_id_not_descriptor_hash() {
        // A job whose submit tx is undecodable (proxy/multicall wrapper) is negative-cached by its
        // UNIQUE job_id, NOT by the on-chain descriptorHash — which excludes the submitter and is shared
        // with honest jobs carrying a byte-identical descriptor. Keying by descriptorHash let a proxy-
        // wrapped decoy permanently evict an honest twin job (the r9 regression this closes). Distinct
        // ids keep this independent of other tests touching the process-wide set.
        let decoy_job = B256::repeat_byte(0x71);
        let honest_twin_job = B256::repeat_byte(0x72); // SAME descriptor, DIFFERENT job_id
        assert!(!job_is_undecodable(decoy_job));
        mark_job_undecodable(decoy_job);
        assert!(job_is_undecodable(decoy_job), "the undecodable job itself is skipped");
        assert!(
            !job_is_undecodable(honest_twin_job),
            "an honest job with a different job_id (even an identical descriptor) is NOT evicted"
        );
    }

    #[test]
    fn sp1_elf_hash_missing_is_a_self_healing_program_keyed_cooldown() {
        // An SP1 program observed with no registry elf_hash is skipped on a PROGRAM-keyed cooldown (the
        // requirement is program-wide, independent of inputData) and an unrelated program is unaffected.
        // The cooldown self-heals when it lapses — asserted by injecting an already-expired deadline,
        // which must read as not-recently (so the program is re-checked and can be claimed once its hash
        // is set). Distinct ids keep this independent of other tests touching the process-wide map.
        let no_hash = B256::repeat_byte(0x81);
        let other = B256::repeat_byte(0x82);
        assert!(!sp1_elf_hash_missing_recently(no_hash));
        mark_sp1_elf_hash_missing(no_hash);
        assert!(sp1_elf_hash_missing_recently(no_hash), "a no-elf_hash SP1 program is on cooldown");
        assert!(!sp1_elf_hash_missing_recently(other), "an unrelated program is not affected");
        // Self-heal: an expired deadline reads as not-recently (re-check, do not permanently over-block).
        if let Ok(mut m) = sp1_elf_hash_missing_map().lock() {
            m.insert(no_hash, std::time::Instant::now() - Duration::from_secs(1));
        }
        assert!(
            !sp1_elf_hash_missing_recently(no_hash),
            "once the cooldown lapses the program is re-checked, not permanently blocked"
        );
    }

    #[test]
    fn predicate_unsatisfiable_is_keyed_by_the_whole_binding() {
        // A binding a real fulfil showed unsatisfiable (decoded `JournalMismatch`) is skipped for its
        // EXACT binding only. Every component of the key must isolate a decoy from the honest job that
        // shares the rest of its PUBLIC tuple — distinct ids keep this independent of other tests.
        use zkminer_contracts::bindings::JobDescriptor;
        let base = JobDescriptor {
            programId: B256::repeat_byte(0x11),
            proofSystemId: zkminer_chain::auction::sp1_groth16_v1_id(),
            callbackContract: alloy::primitives::Address::ZERO,
            assignedProver: alloy::primitives::Address::ZERO,
            tag: B256::ZERO,
            inputData: alloy::primitives::Bytes::from_static(b"attacker-decoy-input"),
            callbackExtraData: alloy::primitives::Bytes::new(),
            extraVerifierData: alloy::primitives::Bytes::new(),
            expectedJournalHash: B256::repeat_byte(0x22),
            journalFields: B256::ZERO,
        };
        let decoy = predicate_key(&base);
        assert!(!predicate_unsatisfiable(&decoy));
        mark_predicate_unsatisfiable(decoy);
        assert!(predicate_unsatisfiable(&decoy), "the exact baited binding is skipped");
        // The honest job differing in ANY binding component is NOT skipped:
        let mut honest_input = base.clone();
        honest_input.inputData = alloy::primitives::Bytes::from_static(b"honest-input");
        let mut other_id = base.clone(); // same vkey under the OTHER SP1 wrapper (FULL hash differs)
        other_id.proofSystemId = zkminer_chain::auction::sp1_plonk_v1_id();
        let mut other_fields = base.clone(); // FIELDS ranges / a marker change what is checked
        other_fields.journalFields = B256::repeat_byte(0x01);
        let mut other_ejh = base.clone();
        other_ejh.expectedJournalHash = B256::repeat_byte(0x33);
        let mut other_prog = base.clone();
        other_prog.programId = B256::repeat_byte(0x44);
        for (what, d) in [
            ("input", &honest_input),
            ("proofSystemId", &other_id),
            ("journalFields", &other_fields),
            ("expectedJournalHash", &other_ejh),
            ("programId", &other_prog),
        ] {
            assert!(
                !predicate_unsatisfiable(&predicate_key(d)),
                "a binding differing only in {what} must not be skipped"
            );
        }
        // Idempotent.
        mark_predicate_unsatisfiable(decoy);
        assert!(predicate_unsatisfiable(&decoy));
    }

    #[test]
    fn sim_revert_cooldown_throttles_but_does_not_permanently_poison() {
        // A NON-predicate sim revert throttles the program via a self-healing cooldown — distinct
        // from the PERMANENT, authoritative vkey-mismatch breaker — so a transient revert (reorg /
        // router pause / stale load-balanced RPC) on a legitimate program never over-blocks it
        // forever. Distinct ids keep this independent of other tests.
        let bad = B256::repeat_byte(0x55);
        let good = B256::repeat_byte(0x66);
        let g16 = zkminer_chain::auction::sp1_groth16_v1_id();
        let plonk = zkminer_chain::auction::sp1_plonk_v1_id();
        assert!(!program_sim_reverted_recently(bad, g16));
        mark_program_sim_reverted(bad, g16);
        assert!(
            program_sim_reverted_recently(bad, g16),
            "a freshly-reverted (program, proof system) is throttled within the cooldown window"
        );
        assert!(
            !program_sim_reverted_recently(good, g16),
            "an unrelated program is not throttled"
        );
        assert!(
            !program_sim_reverted_recently(bad, plonk),
            "the same vkey under the OTHER SP1 wrapper is not throttled (a different seal)"
        );
        // The sim-revert cooldown must NOT be the permanent vkey-mismatch breaker: throttling a
        // program here leaves `program_vkey_mismatched` (the evict-forever path) untouched, so a
        // transient sim revert can never permanently evict honest work.
        assert!(
            !program_vkey_mismatched(bad, "risc0") && !program_vkey_mismatched(bad, "sp1"),
            "a sim-revert cooldown must not feed the permanent vkey-mismatch eviction set"
        );
    }

    #[test]
    fn revert_lever_gate_distinguishes_submitter_levers_from_a_vanilla_descriptor() {
        use zkminer_contracts::bindings::JobDescriptor;
        // Build a descriptor with the three submitter-controlled revert levers set to the given values
        // and everything else neutral.
        let mk = |cb: alloy::primitives::Address, verifier: &[u8], cb_data: &[u8]| JobDescriptor {
            programId: B256::repeat_byte(0x11),
            proofSystemId: B256::ZERO,
            callbackContract: cb,
            assignedProver: alloy::primitives::Address::ZERO,
            tag: B256::ZERO,
            inputData: alloy::primitives::Bytes::new(),
            callbackExtraData: alloy::primitives::Bytes::copy_from_slice(cb_data),
            extraVerifierData: alloy::primitives::Bytes::copy_from_slice(verifier),
            journalFields: B256::ZERO,
            expectedJournalHash: B256::ZERO,
        };
        // A vanilla descriptor (no callback, no extra-verifier/callback data) has NO submitter lever,
        // so a fulfill revert on it is attributable to the program/predicate binding and IS recorded.
        assert!(
            !descriptor_carries_revert_lever(&mk(alloy::primitives::Address::ZERO, b"", b"")),
            "a vanilla descriptor carries no revert lever"
        );
        // ANY of the three submitter-controlled levers present means a revert could be forged on a
        // per-job cause, so the gate must refuse to attribute it to the program/tuple (no poison).
        assert!(
            descriptor_carries_revert_lever(&mk(alloy::primitives::Address::repeat_byte(0xcc), b"", b"")),
            "a callback contract is a lever"
        );
        assert!(
            descriptor_carries_revert_lever(&mk(alloy::primitives::Address::ZERO, b"x", b"")),
            "extraVerifierData is a lever"
        );
        assert!(
            descriptor_carries_revert_lever(&mk(alloy::primitives::Address::ZERO, b"", b"x")),
            "callbackExtraData is a lever"
        );
    }

    #[test]
    fn per_caller_cap_bounds_one_address_without_evicting_others() {
        // Build an Open set where one hostile caller holds far more than the cap and a second,
        // honest caller holds a few LOWER-priced jobs. The per-caller cap must drop only the hostile
        // caller's cheapest jobs down to the cap and leave every other caller's jobs intact — so a
        // single address cannot crowd the honest submitter out of the value-ranked global retain.
        fn mk(caller: u8, jid: u8, price: u128) -> TrackedJob {
            TrackedJob {
                info: zkminer_chain::jobs::JobInfo {
                    job_id: B256::repeat_byte(jid),
                    caller: alloy::primitives::Address::repeat_byte(caller),
                    ..Default::default()
                },
                status: zkminer_tui::state::MinerJobStatus::Open,
                current_price: price,
                gpu_bus_id: None,
                prover_backend: String::new(),
                estimated_cycles: 0,
            }
        }
        let cap = 3usize;
        let mut v = Vec::new();
        // Hostile caller 0xAA: 6 jobs, prices 100..=105 (all HIGHER than the honest caller's).
        for i in 0..6u8 {
            v.push(mk(0xAA, i, 100 + i as u128));
        }
        // Honest caller 0xBB: 2 jobs, low prices.
        v.push(mk(0xBB, 100, 5));
        v.push(mk(0xBB, 101, 6));
        enforce_per_caller_cap(&mut v, cap);
        let hostile = v.iter().filter(|j| j.info.caller == alloy::primitives::Address::repeat_byte(0xAA)).count();
        let honest = v.iter().filter(|j| j.info.caller == alloy::primitives::Address::repeat_byte(0xBB)).count();
        assert_eq!(hostile, cap, "the hostile caller is capped to `cap` jobs");
        assert_eq!(honest, 2, "the honest caller keeps all of its jobs");
        // The jobs the hostile caller keeps are its HIGHEST-priced (103,104,105 -> jids 3,4,5).
        let kept: std::collections::HashSet<u8> = v
            .iter()
            .filter(|j| j.info.caller == alloy::primitives::Address::repeat_byte(0xAA))
            .map(|j| j.info.job_id.0[0])
            .collect();
        assert_eq!(kept, std::collections::HashSet::from([3, 4, 5]));
    }

    #[test]
    fn per_caller_cap_is_a_noop_when_all_within_cap() {
        fn mk(caller: u8, jid: u8) -> TrackedJob {
            TrackedJob {
                info: zkminer_chain::jobs::JobInfo {
                    job_id: B256::repeat_byte(jid),
                    caller: alloy::primitives::Address::repeat_byte(caller),
                    ..Default::default()
                },
                status: zkminer_tui::state::MinerJobStatus::Open,
                current_price: 1,
                gpu_bus_id: None,
                prover_backend: String::new(),
                estimated_cycles: 0,
            }
        }
        let mut v = vec![mk(1, 1), mk(1, 2), mk(2, 3)];
        enforce_per_caller_cap(&mut v, 4);
        assert_eq!(v.len(), 3, "nothing dropped when every caller is within cap");
    }

    #[test]
    fn per_caller_cap_breaks_price_ties_toward_newer_jobs() {
        // A busy submitter's history and its live jobs share a price: the OLD entries (likelier settled)
        // go first, so the live ones are kept.
        fn mk(jid: u8) -> TrackedJob {
            TrackedJob {
                info: zkminer_chain::jobs::JobInfo {
                    job_id: B256::repeat_byte(jid),
                    caller: alloy::primitives::Address::repeat_byte(7),
                    ..Default::default()
                },
                status: zkminer_tui::state::MinerJobStatus::Open,
                current_price: 10,
                gpu_bus_id: None,
                prover_backend: String::new(),
                estimated_cycles: 0,
            }
        }
        let mut v: Vec<TrackedJob> = (1..=5).map(mk).collect();
        enforce_per_caller_cap(&mut v, 2);
        let kept: Vec<u8> = v.iter().map(|j| j.info.job_id.0[0]).collect();
        assert_eq!(kept, vec![4, 5], "the two newest of equal price are kept");
    }

    #[test]
    fn a_journal_over_max_journal_bytes_is_over_the_fulfil_cap() {
        // The router refuses any journal over 32,768 bytes, far below the calldata cap: the pre-claim
        // screens must refuse it on its own.
        let max = zkminer_chain::jobs::MAX_JOURNAL_BYTES as u64;
        assert!(!fulfill_payload_over_cap(max, 10, 0, 0));
        assert!(fulfill_payload_over_cap(max + 1, 10, 0, 0));
    }

    #[test]
    fn transient_preclaim_failures_back_off_and_escalate() {
        let jid = B256::repeat_byte(0xC1);
        assert!(!claim_backing_off(jid));
        note_transient_preclaim_failure(jid);
        assert!(claim_backing_off(jid), "a transient failure backs the job off");
        // Escalation: the stored strike count grows (30 s, 60 s, ... capped at 15 min).
        assert_eq!(note_transient_preclaim_failure(jid), 2);
        let k = PRECLAIM_STRIKES
            .get()
            .and_then(|m| m.lock().ok().and_then(|m| m.get(&jid).copied()));
        assert_eq!(k, Some(2));
        clear_preclaim_strikes(jid);
        let k = PRECLAIM_STRIKES
            .get()
            .and_then(|m| m.lock().ok().and_then(|m| m.get(&jid).copied()));
        assert_eq!(k, None);
    }

    #[test]
    fn post_claim_failures_mark_with_a_ttl_and_the_global_hold_spares_proven_programs() {
        let addr = alloy::primitives::Address::repeat_byte;
        let prog = B256::repeat_byte;
        // An honest program proven before the attack.
        note_fulfil_success(prog(0xD0), "risc0");
        assert!(!divergence_blocks_claim(addr(0xD1), prog(0xD1), "risc0"));
        note_post_claim_divergence(prog(0xD1), "risc0", addr(0xD1), "test");
        assert!(divergence_blocks_claim(addr(0xD1), prog(0xEE), "risc0"), "the submitter is marked");
        assert!(
            !divergence_blocks_claim(addr(0xEE), prog(0xD1), "risc0"),
            "one submitter's failure does not block a public program for everyone"
        );
        assert!(
            !program_vkey_mismatched(prog(0xD1), "risc0"),
            "a failure must not write the permanent mismatch verdict (recovery releases on that)"
        );
        // One wave of the same program, from the same submitter, is not a Sybil spread.
        note_post_claim_divergence(prog(0xD1), "risc0", addr(0xD1), "test");
        note_post_claim_divergence(prog(0xD1), "risc0", addr(0xD1), "test");
        assert!(!divergence_blocks_claim(addr(0xEE), prog(0xEE), "risc0"), "distinct programs count");
        assert!(!divergence_blocks_claim(addr(0xEE), prog(0xD1), "risc0"));
        // A second submitter failing on it marks the program itself.
        note_post_claim_divergence(prog(0xD1), "risc0", addr(0xD2), "test");
        assert!(
            divergence_blocks_claim(addr(0xEE), prog(0xD1), "risc0"),
            "and now its program"
        );
        // Fresh programs and addresses trip the hold — for unproven programs only.
        note_post_claim_divergence(prog(0xD3), "risc0", addr(0xD3), "test");
        note_post_claim_divergence(prog(0xD4), "risc0", addr(0xD4), "test");
        assert!(divergence_blocks_claim(addr(0xEE), prog(0xEE), "risc0"), "unproven work is held");
        assert!(!divergence_blocks_claim(addr(0xEE), prog(0xD0), "risc0"), "proven work keeps flowing");
        // A success cannot launder a program while it is marked.
        note_fulfil_success(prog(0xD1), "risc0");
        assert!(divergence_blocks_claim(addr(0xEE), prog(0xD1), "risc0"));
        // One submitter's failure didn't mark D3, so a later success proves it again.
        note_fulfil_success(prog(0xD3), "risc0");
        assert!(!divergence_blocks_claim(addr(0xEE), prog(0xD3), "risc0"));
    }

    #[test]
    fn bound_jobs_rank_last_and_are_forgotten_with_the_job() {
        let jid = B256::repeat_byte(0xB1);
        let job = TrackedJob {
            info: zkminer_chain::jobs::JobInfo {
                job_id: jid,
                ..Default::default()
            },
            status: zkminer_tui::state::MinerJobStatus::Open,
            current_price: 1_000,
            gpu_bus_id: None,
            prover_backend: String::new(),
            estimated_cycles: 0,
        };
        assert_eq!(open_rank(&job), 1_000);
        mark_job_bound(jid);
        assert!(job_is_bound(jid));
        assert_eq!(open_rank(&job), 0, "a bound job can never outrank a claimable one");
        forget_job_bound(jid);
        assert!(!job_is_bound(jid));
        assert_eq!(open_rank(&job), 1_000);
    }

    #[test]
    fn only_a_lasting_set_aside_ranks_a_job_last() {
        let job = |b| TrackedJob {
            info: zkminer_chain::jobs::JobInfo {
                job_id: B256::repeat_byte(b),
                ..Default::default()
            },
            status: zkminer_tui::state::MinerJobStatus::Open,
            current_price: 1_000,
            gpu_bus_id: None,
            prover_backend: String::new(),
            estimated_cycles: 0,
        };
        // A temporary refusal backs a job off, and it is then put back: it keeps its price, or a full
        // Open set would evict exactly the job just requeued.
        let backing_off = job(0xB2);
        note_job_retry_after(backing_off.info.job_id, Duration::from_secs(60));
        assert!(claim_backing_off(backing_off.info.job_id));
        assert_eq!(open_rank(&backing_off), 1_000);
        // A lasting verdict (assigned elsewhere, too slow) ranks it last, and backs it off too.
        let aside = job(0xB3);
        set_job_aside(aside.info.job_id, Duration::from_secs(60));
        assert!(claim_backing_off(aside.info.job_id));
        assert_eq!(open_rank(&aside), 0);
        let expired = job(0xB4);
        set_job_aside(expired.info.job_id, Duration::ZERO);
        assert_eq!(open_rank(&expired), 1_000, "only while it lasts");
    }

    #[test]
    fn the_candidate_cut_keeps_the_top_by_price_and_rotates_the_rest() {
        let mut rotation = 0;
        let mut seen = std::collections::HashSet::new();
        let ticks = 300usize.div_ceil(64) + 1;
        for _ in 0..ticks {
            let mut c: Vec<u32> = (0..300u32).rev().collect(); // sorted by "price", highest first
            cut_candidates(&mut c, &mut rotation);
            assert_eq!(c.len(), MAX_CANDIDATES_PER_TICK);
            assert!(
                c[..192].iter().copied().eq((108..300u32).rev()),
                "the top 192 by price"
            );
            let distinct: std::collections::HashSet<_> = c.iter().collect();
            assert_eq!(distinct.len(), c.len(), "no duplicates");
            seen.extend(c[192..].iter().copied());
        }
        assert_eq!(
            seen.len(),
            108,
            "every job below the price slots is visited"
        );
        let mut short: Vec<u32> = (0..10).collect();
        cut_candidates(&mut short, &mut rotation);
        assert_eq!(
            short,
            (0..10).collect::<Vec<_>>(),
            "under the cap: untouched"
        );
    }

    #[test]
    fn exclusivity_holds_only_inside_its_window() {
        let min = ASSIGNED_ELSEWHERE_TTL;
        let max = ASSIGNED_ELSEWHERE_MAX_WAIT;
        assert_eq!(
            exclusivity_wait(1_000, 0, 1_000),
            None,
            "no window: anyone may claim"
        );
        assert_eq!(exclusivity_wait(1_000, 0, 0), None);
        // The contract holds it while jobNow < rampUpStart + exclusivityDuration.
        assert_eq!(
            exclusivity_wait(1_000, 600, 1_600),
            None,
            "lapsed at the end"
        );
        assert_eq!(exclusivity_wait(1_000, 600, 5_000), None);
        assert_eq!(
            exclusivity_wait(1_000, 600, 1_599),
            Some(min),
            "never shorter than the minimum"
        );
        assert_eq!(
            exclusivity_wait(1_000, 600, 1_400),
            Some(Duration::from_secs(200))
        );
        assert_eq!(
            exclusivity_wait(1_000, 86_400, 1_000),
            Some(max),
            "read again within the hour"
        );
        assert_eq!(exclusivity_wait(u64::MAX, 600, 0), Some(max), "no overflow");
    }

    #[test]
    fn a_program_without_an_elf_source_cools_down_as_a_whole() {
        let p = B256::repeat_byte(0xA7);
        assert!(!program_has_no_elf_source(p));
        mark_program_no_elf_source(p);
        assert!(program_has_no_elf_source(p));
        assert!(!program_has_no_elf_source(B256::repeat_byte(0xA8)));
    }

    #[test]
    fn elf_failures_count_separately_from_other_preclaim_strikes() {
        let jid = B256::repeat_byte(0xC7);
        for _ in 0..5 {
            note_claim_retry_after(jid, zkminer_chain::revert::ClaimClass::StakeShort);
        }
        assert_eq!(note_preclaim_elf_failure(jid), 1, "earlier refusals do not count as ELF failures");
        clear_preclaim_elf_failures(jid);
        assert_eq!(note_preclaim_elf_failure(jid), 1);
    }

    #[test]
    fn pause_kept_locks_are_tracked_until_taken() {
        let jid = B256::repeat_byte(0xE1);
        assert!(!is_pause_kept(jid));
        note_pause_kept(jid);
        assert!(is_pause_kept(jid));
        assert!(take_pause_kept(jid));
        assert!(!is_pause_kept(jid));
        assert!(!take_pause_kept(jid));
    }

    #[test]
    fn claim_payload_over_cap_catches_the_race_loser_and_needs_all_three_inputs() {
        // Reproduces the measuring_inputs race loser: its own (early-returning) measure task cached its
        // resolver and payload, and the winner cached the journal length for the shared (program,
        // input). The claim gate must then catch an over-cap full payload — and must NOT fire until all
        // three inputs are present, so it never false-skips a job that could still fulfill.
        let desc_input: DescInputCache =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let jc: JournalLenCache =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let pc: DescPayloadCache =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let prog = B256::repeat_byte(0x44);
        let desc = B256::repeat_byte(0x55);
        let ih = keccak256(b"shared-input");

        // Nothing cached yet -> never blocks.
        assert!(!claim_payload_over_cap(&desc_input, &jc, &pc, "sp1", prog, desc));
        // Resolver only -> cannot decide, does not block.
        insert_desc_input(&desc_input, desc, ih);
        assert!(!claim_payload_over_cap(&desc_input, &jc, &pc, "sp1", prog, desc));
        // + a journal length that alone fits under the cap, but THIS descriptor's payload is not yet
        // cached -> still does not block.
        insert_journal_len(&jc, "sp1", prog, ih, 30 * 1024);
        assert!(!claim_payload_over_cap(&desc_input, &jc, &pc, "sp1", prog, desc));
        // + a FAT descriptor payload that tips the full payload (journal + payload + seal) over the cap
        // -> now the claim is refused (the race-loser case).
        insert_desc_payload(&pc, desc, 100 * 1024);
        assert!(claim_payload_over_cap(&desc_input, &jc, &pc, "sp1", prog, desc));
        // A slim descriptor for the SAME (program, input) is independent and NOT blocked.
        let slim = B256::repeat_byte(0x66);
        insert_desc_input(&desc_input, slim, ih);
        insert_desc_payload(&pc, slim, 1024);
        assert!(!claim_payload_over_cap(&desc_input, &jc, &pc, "sp1", prog, slim));
        // Journal is backend-keyed: the same descriptor under a DIFFERENT backend (no journal there)
        // does not block.
        assert!(!claim_payload_over_cap(&desc_input, &jc, &pc, "risc0", prog, desc));
    }

    // Finding C-8: the cycle count and the execute peak live in ONE merged entry, so they resolve
    // together and can never desync (which would let an evicted peak un-gate the H1 claim check).
    #[test]
    fn peak_resolves_from_the_same_merged_entry_as_cycles() {
        let (measured, desc_input) = fresh();
        let prog = B256::repeat_byte(0xC1);
        let desc = B256::repeat_byte(0xC2);
        let ih = keccak256(b"peak-input");
        insert_desc_input(&desc_input, desc, ih);

        // A real measurement stores cycles AND peak in one value.
        const PEAK: u64 = 9 * 1024 * 1024 * 1024;
        insert_measurement(
            &measured, "sp1", NO_PO2, prog, ih, 5_000, PEAK, None, None, 0,
        );
        assert_eq!(
            resolve_measured(&measured, &desc_input, "sp1", &[NO_PO2], prog, desc),
            Some(5_000)
        );
        assert_eq!(
            resolve_measured_peak(&measured, &desc_input, "sp1", &[NO_PO2], prog, desc),
            Some(PEAK)
        );

        // A later cycle-only write (e.g. a deterministic UNMEASURABLE verdict) replaces the SAME entry,
        // so the peak follows the cycles rather than being stranded at the old value.
        insert_measured(&measured, "sp1", NO_PO2, prog, ih, UNMEASURABLE_CYCLES);
        assert_eq!(
            resolve_measured(&measured, &desc_input, "sp1", &[NO_PO2], prog, desc),
            Some(UNMEASURABLE_CYCLES)
        );
        assert_eq!(
            resolve_measured_peak(&measured, &desc_input, "sp1", &[NO_PO2], prog, desc),
            Some(0)
        );
    }

    // F1: the verified risc0 ELF keccak is co-stored with the measurement, so a claim that resolves a
    // measurement ALWAYS gets its hash under one lock hold — it can never be evicted independently (the
    // residual the independent-map design had).
    #[test]
    fn verified_elf_hash_co_resolves_with_the_measurement() {
        let (measured, desc_input) = fresh();
        let prog = B256::repeat_byte(0xE1);
        let desc = B256::repeat_byte(0xE2);
        let ih = keccak256(b"risc0-input");
        insert_desc_input(&desc_input, desc, ih);

        let elf_keccak = keccak256(b"the-verified-risc0-elf-bytes");
        insert_measurement(
            &measured,
            "risc0",
            R0,
            prog,
            ih,
            42_000,
            0,
            Some(elf_keccak),
            None,
            0,
        );

        // The hash rides out of the SAME resolve that makes the job claimable.
        assert_eq!(
            resolve_measured_with_hash(&measured, &desc_input, "risc0", &[R0], prog, desc),
            Some((42_000, Some(elf_keccak), None, 0)),
            "a claim resolving this measurement must receive its verified ELF hash"
        );
        // And the plain cycle resolve is unchanged.
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc),
            Some(42_000)
        );
    }

    #[test]
    fn verified_elf_hash_is_none_for_sp1_and_for_infeasible_verdicts() {
        let (measured, desc_input) = fresh();
        let prog = B256::repeat_byte(0xE3);
        let desc = B256::repeat_byte(0xE4);
        let ih = keccak256(b"sp1-input");
        insert_desc_input(&desc_input, desc, ih);

        // SP1 carries no co-stored hash (it is bound by the registry elf_hash instead).
        insert_measurement(&measured, "sp1", NO_PO2, prog, ih, 5_000, 7, None, None, 0);
        assert_eq!(
            resolve_measured_with_hash(&measured, &desc_input, "sp1", &[NO_PO2], prog, desc),
            Some((5_000, None, None, 0))
        );

        // A deterministic infeasible verdict (and the cycle-only insert path) carries no hash.
        let desc2 = B256::repeat_byte(0xE5);
        let ih2 = keccak256(b"infeasible-input");
        insert_desc_input(&desc_input, desc2, ih2);
        insert_measured(&measured, "risc0", R0, prog, ih2, UNMEASURABLE_CYCLES);
        assert_eq!(
            resolve_measured_with_hash(&measured, &desc_input, "risc0", &[R0], prog, desc2),
            Some((UNMEASURABLE_CYCLES, None, None, 0))
        );
    }

    // A later cycle-only write to the SAME (program, input) replaces the whole entry, so a stale hash
    // can never outlive the measurement it belonged to.
    #[test]
    fn a_cycle_only_rewrite_clears_a_previously_stored_hash() {
        let (measured, desc_input) = fresh();
        let prog = B256::repeat_byte(0xE6);
        let desc = B256::repeat_byte(0xE7);
        let ih = keccak256(b"rewrite-input");
        insert_desc_input(&desc_input, desc, ih);

        insert_measurement(
            &measured,
            "risc0",
            R0,
            prog,
            ih,
            10_000,
            0,
            Some(keccak256(b"old")),
            None,
            0,
        );
        // A subsequent cycle-only write (e.g. an UNMEASURABLE verdict) replaces the merged entry.
        insert_measured(&measured, "risc0", R0, prog, ih, UNMEASURABLE_CYCLES);
        assert_eq!(
            resolve_measured_with_hash(&measured, &desc_input, "risc0", &[R0], prog, desc),
            Some((UNMEASURABLE_CYCLES, None, None, 0)),
            "the hash must follow the entry, not be stranded"
        );
    }

    // The journal a bound job's binding is checked against resolves with the cycle count it was
    // measured with, keyed to the input it was executed on.
    #[test]
    fn the_measured_journal_resolves_with_its_cycles_and_input() {
        let (measured, desc_input) = fresh();
        let prog = B256::repeat_byte(0xF1);
        let desc = B256::repeat_byte(0xF2);
        let ih = keccak256(b"journal-input");
        insert_desc_input(&desc_input, desc, ih);
        let journal: std::sync::Arc<[u8]> = std::sync::Arc::from(&b"the journal"[..]);
        insert_measurement(
            &measured,
            "risc0",
            R0,
            prog,
            ih,
            9_000,
            0,
            None,
            Some(journal.clone()),
            7,
        );
        assert_eq!(
            resolve_measured_with_hash(&measured, &desc_input, "risc0", &[R0], prog, desc),
            Some((9_000, None, Some((ih, journal.clone())), 7))
        );
        insert_measurement(
            &measured,
            "sp1",
            NO_PO2,
            prog,
            ih,
            8_000,
            5,
            None,
            Some(journal.clone()),
            0,
        );
        assert_eq!(
            resolve_measured_full(&measured, &desc_input, "sp1", &[NO_PO2], prog, desc),
            Some((8_000, 5, Some((ih, journal)), 0))
        );
        // An infeasible verdict replaces the entry, journal and all.
        insert_measured(&measured, "risc0", R0, prog, ih, UNMEASURABLE_CYCLES);
        assert_eq!(
            resolve_measured_with_hash(&measured, &desc_input, "risc0", &[R0], prog, desc),
            Some((UNMEASURABLE_CYCLES, None, None, 0))
        );
    }

    // A risc0 proof executes its guest again: its budget allows three times the measurement for it,
    // whatever the guest's cycles say. Other backends, and a job with no measurement, get none.
    #[test]
    fn the_execute_allowance_is_three_measurements_for_risc0_only() {
        assert_eq!(execute_allowance_secs("risc0", Some(40)), 120);
        assert_eq!(execute_allowance_secs("risc0", None), 0);
        assert_eq!(execute_allowance_secs("sp1", Some(40)), 0);
        assert_eq!(execute_allowance_secs("risc0", Some(u64::MAX)), u64::MAX);
    }

    // Journals of up to 32 KiB in 100k entries would hold ~3 GiB: the cache evicts other entries past
    // its byte bound, largest journals first, never the one just inserted, and never an entry that
    // frees nothing (an empty journal or an infeasible verdict).
    #[test]
    fn the_measured_cache_bounds_its_journal_bytes() {
        let (measured, _) = fresh();
        let prog = B256::repeat_byte(0xF3);
        let small: std::sync::Arc<[u8]> = std::sync::Arc::from(&[1u8; 8][..]);
        let empty: std::sync::Arc<[u8]> = std::sync::Arc::from(&[][..]);
        let kept: Vec<B256> = (0..30u8).map(|i| keccak256([0xAA, i])).collect();
        for (i, ih) in kept.iter().enumerate() {
            match i % 3 {
                0 => insert_measurement(
                    &measured,
                    "risc0",
                    R0,
                    prog,
                    *ih,
                    1,
                    0,
                    None,
                    Some(small.clone()),
                    0,
                ),
                1 => insert_measurement(
                    &measured,
                    "risc0",
                    R0,
                    prog,
                    *ih,
                    1,
                    0,
                    None,
                    Some(empty.clone()),
                    0,
                ),
                _ => insert_measured(&measured, "risc0", R0, prog, *ih, UNMEASURABLE_CYCLES),
            }
        }
        let journal: std::sync::Arc<[u8]> = vec![7u8; 32 * 1024].into();
        let n = MEASURED_JOURNAL_BYTES_CAP / journal.len() + 50;
        let mut last = B256::ZERO;
        for i in 0..n {
            last = keccak256((i as u64).to_be_bytes());
            insert_measurement(
                &measured,
                "risc0",
                R0,
                prog,
                last,
                1,
                0,
                None,
                Some(journal.clone()),
                0,
            );
        }
        let m = measured.lock().unwrap();
        let total: usize = m
            .values()
            .filter_map(|v| v.journal.as_ref())
            .map(|j| j.len())
            .sum();
        assert!(total <= MEASURED_JOURNAL_BYTES_CAP, "{total} bytes held");
        assert!(m.len() < n, "entries past the bound were evicted");
        assert!(
            m.contains_key(&(backend_tag("risc0"), R0, prog, last)),
            "the newest entry stays"
        );
        for ih in &kept {
            assert!(
                m.contains_key(&(backend_tag("risc0"), R0, prog, *ih)),
                "the flood evicts its own large journals, not small, empty or infeasible entries"
            );
        }
    }

    // A real measurement that came back without its journal sizes jobs for a while, then expires so
    // its journal-bound jobs are re-measured instead of waiting on it forever.
    #[test]
    fn a_measurement_without_a_journal_expires() {
        let (measured, desc_input) = fresh();
        let prog = B256::repeat_byte(0xF4);
        let desc = B256::repeat_byte(0xF5);
        let ih = keccak256(b"no-journal");
        insert_desc_input(&desc_input, desc, ih);
        insert_measurement(&measured, "risc0", R0, prog, ih, 4_000, 0, None, None, 0);
        let key = (backend_tag("risc0"), R0, prog, ih);
        let until = measured.lock().unwrap()[&key]
            .retry_after
            .expect("journal-less entries expire");
        assert!(until > std::time::Instant::now());
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc),
            Some(4_000)
        );
        measured.lock().unwrap().get_mut(&key).unwrap().retry_after =
            Some(std::time::Instant::now() - Duration::from_secs(1));
        assert_eq!(
            resolve_measured(&measured, &desc_input, "risc0", &[R0], prog, desc),
            None
        );
        assert!(
            !measured.lock().unwrap().contains_key(&key),
            "dropped, so the pair is re-measured"
        );

        // With its journal it never expires.
        insert_measurement(
            &measured,
            "risc0",
            R0,
            prog,
            ih,
            4_000,
            0,
            None,
            Some(std::sync::Arc::from(&b"j"[..])),
            0,
        );
        assert!(measured.lock().unwrap()[&key].retry_after.is_none());
    }

    fn bound_descriptor(
        expected: B256,
        fields: B256,
        input: &[u8],
    ) -> zkminer_contracts::bindings::JobDescriptor {
        zkminer_contracts::bindings::JobDescriptor {
            programId: B256::repeat_byte(0xA1),
            proofSystemId: zkminer_chain::auction::risc_zero_groth16_v1_id(),
            callbackContract: alloy::primitives::Address::ZERO,
            assignedProver: alloy::primitives::Address::ZERO,
            tag: B256::ZERO,
            inputData: input.to_vec().into(),
            callbackExtraData: Default::default(),
            extraVerifierData: Default::default(),
            expectedJournalHash: expected,
            journalFields: fields,
        }
    }

    #[test]
    fn the_preclaim_verdict_needs_a_journal_measured_on_this_input() {
        use zkminer_chain::binding::{full_hash, BindingMismatch};
        let job = B256::repeat_byte(0x10);
        let me = alloy::primitives::Address::repeat_byte(0x20);
        let input = b"the input";
        let journal: std::sync::Arc<[u8]> = std::sync::Arc::from(&b"the output"[..]);
        let expected = full_hash(
            zkminer_chain::auction::risc_zero_groth16_v1_id(),
            B256::repeat_byte(0xA1),
            &journal,
        );
        let d = bound_descriptor(expected, B256::ZERO, input);
        let measured: MeasuredJournal = Some((keccak256(input), journal.clone()));
        assert_eq!(
            measured_binding_verdict(&d, &measured, job, me),
            Some(Ok(()))
        );

        // Another expected hash: the fulfil would revert, so the verdict is a mismatch.
        let other = bound_descriptor(B256::repeat_byte(0xEE), B256::ZERO, input);
        assert!(matches!(
            measured_binding_verdict(&other, &measured, job, me),
            Some(Err(BindingMismatch::Journal { .. }))
        ));
        // A journal measured on another input, or none at all, decides nothing.
        let elsewhere: MeasuredJournal = Some((keccak256(b"another input"), journal));
        assert_eq!(measured_binding_verdict(&d, &elsewhere, job, me), None);
        assert_eq!(measured_binding_verdict(&d, &None, job, me), None);
    }

    #[test]
    fn a_failing_measured_binding_drops_the_job_and_only_then() {
        let me = alloy::primitives::Address::repeat_byte(0x21);
        let input = b"in";
        let measured: MeasuredJournal = Some((keccak256(input), std::sync::Arc::from(&b"out"[..])));

        let bad = B256::repeat_byte(0x31);
        drop_if_measured_binding_fails(
            &bound_descriptor(B256::repeat_byte(0xEE), B256::ZERO, input),
            &measured,
            bad,
            me,
        );
        assert!(job_is_undecodable(bad));

        // A NONE job (nothing to check), an unknown verdict, and a satisfied binding stay claimable.
        let none = B256::repeat_byte(0x32);
        drop_if_measured_binding_fails(
            &bound_descriptor(B256::ZERO, B256::ZERO, input),
            &measured,
            none,
            me,
        );
        assert!(!job_is_undecodable(none));
        let unknown = B256::repeat_byte(0x33);
        drop_if_measured_binding_fails(
            &bound_descriptor(B256::repeat_byte(0xEE), B256::ZERO, input),
            &None,
            unknown,
            me,
        );
        assert!(!job_is_undecodable(unknown));
        let good = B256::repeat_byte(0x34);
        let mut fields = B256::ZERO;
        fields.0[..4].copy_from_slice(&3u32.to_be_bytes()); // FIELDS slot 0: offset 0, length 3, "out"
        let d = bound_descriptor(keccak256(b"out"), fields, input);
        drop_if_measured_binding_fails(&d, &measured, good, me);
        assert!(!job_is_undecodable(good));
    }

    #[test]
    fn watch_only_names_each_binding_as_the_router_reads_it() {
        let hash = B256::repeat_byte(0xEE);
        let with_marker = |m: u32, rest: u8| {
            let mut f = B256::ZERO;
            f.0[..4].copy_from_slice(&m.to_be_bytes());
            f.0[4] = rest;
            f
        };
        assert_eq!(
            describe_binding(&bound_descriptor(B256::ZERO, B256::ZERO, b"")),
            "NONE"
        );
        assert_eq!(
            describe_binding(&bound_descriptor(hash, B256::ZERO, b"")),
            "FULL"
        );
        assert_eq!(
            describe_binding(&bound_descriptor(hash, with_marker(3, 0), b"")),
            "FIELDS"
        );
        // A marker is cleared before the mode is chosen: with nothing else it is FULL.
        assert_eq!(
            describe_binding(&bound_descriptor(hash, with_marker(0xffff_ffff, 0), b"")),
            "FULL + journal-prefix"
        );
        assert_eq!(
            describe_binding(&bound_descriptor(hash, with_marker(0xffff_fffe, 7), b"")),
            "FIELDS + SP1 proof-nonce"
        );
    }

    #[test]
    fn watch_only_logs_a_job_again_only_when_its_verdict_changes() {
        let job = B256::repeat_byte(0x41);
        assert!(watch_report(job, "refused (StakeShort)".into()));
        assert!(!watch_report(job, "refused (StakeShort)".into()));
        assert!(watch_report(job, "WOULD CLAIM".into()));
        assert!(watch_report(
            B256::repeat_byte(0x42),
            "refused (StakeShort)".into()
        ));
    }

    // UNMEASURABLE TTL: a wall-clock-timeout verdict is dropped and re-measured after its TTL; every
    // deterministic / submitter-reachable one (cap trip / mismatch / over-cap / guest panic / ELF
    // fetch) is permanent.
    #[test]
    fn a_nondeterministic_unmeasurable_expires_a_deterministic_one_is_permanent() {
        let (measured, desc_input) = fresh();
        let prog = B256::repeat_byte(0xD1);

        // EXPIRING, already past its retry instant: dropped on resolve so a later tick re-measures.
        let expiring_desc = B256::repeat_byte(0xD2);
        let expiring_in = keccak256(b"expiring");
        insert_desc_input(&desc_input, expiring_desc, expiring_in);
        measured.lock().unwrap().insert(
            (backend_tag("sp1"), NO_PO2, prog, expiring_in),
            Measured {
                cycles: UNMEASURABLE_CYCLES,
                peak_host_bytes: 0,
                retry_after: Some(std::time::Instant::now() - Duration::from_secs(1)),
                verified_elf_hash: None,
                journal: None,
                execute_secs: 0,
            },
        );
        assert_eq!(
            resolve_measured(
                &measured,
                &desc_input,
                "sp1",
                &[NO_PO2],
                prog,
                expiring_desc
            ),
            None
        );
        assert!(!measured.lock().unwrap().contains_key(&(
            backend_tag("sp1"),
            NO_PO2,
            prog,
            expiring_in
        )));

        // A not-yet-expired non-deterministic verdict still blacklists (so a flood is still bounded).
        let live_desc = B256::repeat_byte(0xD3);
        let live_in = keccak256(b"live");
        insert_desc_input(&desc_input, live_desc, live_in);
        insert_unmeasurable(&measured, "sp1", NO_PO2, prog, live_in);
        assert_eq!(
            resolve_measured(&measured, &desc_input, "sp1", &[NO_PO2], prog, live_desc),
            Some(UNMEASURABLE_CYCLES)
        );

        // DETERMINISTIC: a permanent sentinel (retry_after == None) never expires.
        let perm_desc = B256::repeat_byte(0xD4);
        let perm_in = keccak256(b"perm");
        insert_desc_input(&desc_input, perm_desc, perm_in);
        insert_measured(&measured, "sp1", NO_PO2, prog, perm_in, UNMEASURABLE_CYCLES);
        assert_eq!(
            resolve_measured(&measured, &desc_input, "sp1", &[NO_PO2], prog, perm_desc),
            Some(UNMEASURABLE_CYCLES)
        );
    }

    // Finding RH-round2/4: the wall-clock-timeout discriminant (which grants the lenient retry TTL)
    // must be the TYPED, dispatcher-only signal — a hostile guest must not be able to forge it by
    // putting the phrase "wall-clock watchdog" in its panic message.
    #[test]
    fn wall_clock_timeout_is_classified_by_type_not_message() {
        // A genuine, dispatcher-generated typed timeout is recognised.
        let real: anyhow::Error = anyhow::Error::new(
            zkminer_prover_protocol::types::MeasureWallClockTimeout {
                slot_key: "sp1:measure:0".to_string(),
            },
        );
        assert!(is_measure_wall_clock_timeout(&real));
        // A guest-forged error whose message merely CONTAINS the phrase is NOT — it is a different
        // error type, so it stays on the permanent-blacklist path.
        let forged = anyhow::anyhow!("cycle measurement failed: Guest panicked: wall-clock watchdog");
        assert!(!is_measure_wall_clock_timeout(&forged));
    }

    /// A preempted measurement (residual A) is classified by its TYPE, is DISTINCT from a wall-clock
    /// timeout (no retry TTL, just plain transient), and cannot be forged from guest text.
    #[test]
    fn preemption_is_classified_by_type_and_is_not_a_timeout() {
        let real: anyhow::Error =
            anyhow::Error::new(zkminer_prover_protocol::types::MeasurePreempted {
                slot_key: "sp1:measure:0".to_string(),
            });
        assert!(is_measure_preempted(&real));
        // Distinct from a wall-clock timeout — a preemption must NOT take the lenient-TTL path.
        assert!(!is_measure_wall_clock_timeout(&real));
        // A guest-forged message does not win the transient treatment.
        let forged = anyhow::anyhow!("cycle measurement failed: Guest panicked: preempted (transient)");
        assert!(!is_measure_preempted(&forged));
    }

    /// A measured entry: `cycles`, a journal, the verified ELF keccak and the execute's seconds.
    fn entry(cycles: u64, journal: Option<&[u8]>, hash: Option<B256>, secs: u64) -> Measured {
        Measured {
            cycles,
            peak_host_bytes: cycles / 1000,
            retry_after: None,
            verified_elf_hash: hash,
            journal: journal.map(std::sync::Arc::from),
            execute_secs: secs,
        }
    }

    #[test]
    fn a_job_is_sized_on_its_measurement_at_every_card_size() {
        let (measured, desc_input) = fresh();
        let (prog, ih, desc) = (
            B256::repeat_byte(0x31),
            keccak256(b"in"),
            B256::repeat_byte(0x32),
        );
        insert_desc_input(&desc_input, desc, ih);
        let at =
            |sizes: &[u8]| resolve_measured_at(&measured, &desc_input, "risc0", sizes, prog, desc);
        let hash = Some(B256::repeat_byte(0x33));
        insert_measured_value(
            &measured,
            "risc0",
            20,
            prog,
            ih,
            entry(40_000, Some(b"j"), hash, 3),
        );
        assert_eq!(at(&[20]).map(|r| r.cycles), Some(40_000));
        // Not measured at 19 yet: not sized, so not claimable.
        assert_eq!(at(&[19, 20]), None);
        assert_eq!(at(&[]), None);
        insert_measured_value(
            &measured,
            "risc0",
            19,
            prog,
            ih,
            entry(45_000, Some(b"j"), hash, 5),
        );
        // The most cycles, the slowest execute, the highest peak; the one journal and ELF.
        let r = at(&[19, 20]).unwrap();
        assert_eq!(
            (r.cycles, r.execute_secs, r.peak_host_bytes),
            (45_000, 5, 45)
        );
        assert_eq!(r.verified_elf_hash, hash);
        assert_eq!(
            r.journal.map(|(i, j)| (i, j.to_vec())),
            Some((ih, b"j".to_vec()))
        );
        // An SP1 measurement of the same pair is another key.
        assert_eq!(
            resolve_measured_at(&measured, &desc_input, "sp1", &[NO_PO2], prog, desc),
            None
        );
    }

    #[test]
    fn a_verdict_or_a_size_dependent_journal_at_any_size_is_the_jobs() {
        let (measured, desc_input) = fresh();
        let prog = B256::repeat_byte(0x41);
        let pair = |n: u8| {
            let (ih, desc) = (keccak256([n]), B256::repeat_byte(n));
            insert_desc_input(&desc_input, desc, ih);
            (ih, desc)
        };
        let at = |desc, sizes: &[u8]| {
            resolve_measured_at(&measured, &desc_input, "risc0", sizes, prog, desc)
        };
        let unmeasurable = Some(ResolvedMeasurement::unmeasurable());

        // A journal that depends on the size the guest runs at, even with a size still to measure.
        let (ih, desc) = pair(1);
        insert_measured_value(
            &measured,
            "risc0",
            20,
            prog,
            ih,
            entry(9, Some(b"a"), None, 1),
        );
        insert_measured_value(
            &measured,
            "risc0",
            19,
            prog,
            ih,
            entry(9, Some(b"b"), None, 1),
        );
        assert_eq!(at(desc, &[19, 20]), unmeasurable);
        assert_eq!(at(desc, &[18, 19, 20]), unmeasurable);
        assert_eq!(
            at(desc, &[20]).map(|r| r.cycles),
            Some(9),
            "one size alone is fine"
        );

        // A verdict at one size, with the other not measured yet: settled, nothing more to measure.
        let (ih, desc) = pair(2);
        insert_measured(&measured, "risc0", 19, prog, ih, UNMEASURABLE_CYCLES);
        assert_eq!(at(desc, &[19, 20]), unmeasurable);

        // No journal at one size: sized, with no journal to check a binding against.
        let (ih, desc) = pair(3);
        insert_measured_value(
            &measured,
            "risc0",
            20,
            prog,
            ih,
            entry(9, Some(b"j"), None, 1),
        );
        insert_measured_value(&measured, "risc0", 19, prog, ih, entry(9, None, None, 1));
        let r = at(desc, &[19, 20]).unwrap();
        assert_eq!((r.cycles, r.journal), (9, None));

        // Different verified ELF bytes at two sizes: either binds the claim's re-fetch.
        let (ih, desc) = pair(4);
        let (h1, h2) = (Some(B256::repeat_byte(1)), Some(B256::repeat_byte(2)));
        insert_measured_value(
            &measured,
            "risc0",
            20,
            prog,
            ih,
            entry(9, Some(b"j"), h1, 1),
        );
        insert_measured_value(
            &measured,
            "risc0",
            19,
            prog,
            ih,
            entry(9, Some(b"j"), h2, 1),
        );
        let bound = at(desc, &[19, 20]).unwrap().verified_elf_hash;
        assert!(bound == h1 || bound == h2, "{bound:?}");
        assert_eq!(at(desc, &[20]).unwrap().verified_elf_hash, h1);
    }

    #[test]
    fn an_expired_verdict_at_one_size_is_measured_again() {
        let (measured, desc_input) = fresh();
        let (prog, ih, desc) = (
            B256::repeat_byte(0x51),
            keccak256(b"x"),
            B256::repeat_byte(0x52),
        );
        insert_desc_input(&desc_input, desc, ih);
        insert_measured_value(
            &measured,
            "risc0",
            20,
            prog,
            ih,
            entry(9, Some(b"j"), None, 1),
        );
        let mut expired = entry(UNMEASURABLE_CYCLES, None, None, 0);
        expired.retry_after = Some(std::time::Instant::now());
        insert_measured_value(&measured, "risc0", 19, prog, ih, expired);
        assert_eq!(
            resolve_measured_at(&measured, &desc_input, "risc0", &[19, 20], prog, desc),
            None
        );
        let m = measured.lock().unwrap();
        assert!(!m.contains_key(&(backend_tag("risc0"), 19, prog, ih)));
        assert!(m.contains_key(&(backend_tag("risc0"), 20, prog, ih)));
    }

    fn risc0_row(
        device: &str,
        calibrated: &[u8],
        optimal: u8,
    ) -> zkminer_prover::benchmark::DeviceBenchmark {
        zkminer_prover::benchmark::DeviceBenchmark {
            device_id: device.to_string(),
            device_label: String::new(),
            prover_backend: "risc0".to_string(),
            throughput: 1_000_000.0,
            power_watts: 300.0,
            optimal_po2: optimal,
            memory_usage_bytes: 1,
            max_feasible_po2: calibrated.iter().copied().max().unwrap_or(24),
            program_throughputs: HashMap::new(),
            po2_samples: calibrated
                .iter()
                .map(|&po2| zkminer_prover::benchmark::Po2Sample {
                    po2,
                    total_cycles: 62_000_000,
                    segment_count: 4,
                    duration_secs: 60.0,
                    throughput: 1_000_000.0,
                })
                .collect(),
            program_stages: Vec::new(),
            pci_bus_id: String::new(),
            host_peak_bytes: None,
        }
    }

    #[test]
    fn each_card_measures_and_proves_risc0_jobs_at_its_own_size() {
        const GIB: u64 = 1 << 30;
        let slot =
            |i: usize, vram: Option<u64>| (format!("risc0:cuda:{i}"), format!("gpu{i}"), vram);
        let slots = vec![
            slot(0, Some(24 * GIB)), // uncalibrated: the default size
            slot(1, Some(12 * GIB)), // uncalibrated, too small for it: none
            slot(2, Some(12 * GIB)), // calibrated: its measured best
            slot(3, None),           // VRAM unknown: the default size
            slot(4, Some(8 * GIB)),  // a size set in Settings
            slot(5, Some(24 * GIB)), // a heuristic row, no samples: the default size
        ];
        let suite = zkminer_prover::benchmark::BenchmarkSuite {
            device_benchmarks: vec![risc0_row("gpu2", &[18, 19], 19), risc0_row("gpu5", &[], 23)],
            ..Default::default()
        };
        let overrides = HashMap::from([("gpu4".to_string(), 18u8)]);
        let sizes = risc0_slot_sizes(&slots, Some(&suite), &overrides);
        assert_eq!(
            sizes
                .iter()
                .map(|(_, d, p)| (d.as_str(), *p))
                .collect::<Vec<_>>(),
            vec![
                ("gpu0", Some(20)),
                ("gpu1", None),
                ("gpu2", Some(19)),
                ("gpu3", Some(20)),
                ("gpu4", Some(18)),
                ("gpu5", Some(20)),
            ]
        );
        let cards = risc0_job_cards(&sizes, &["risc0:cuda:3".to_string()], false);
        assert_eq!(
            cards.iter().map(|c| c.slot.as_str()).collect::<Vec<_>>(),
            vec![
                "risc0:cuda:0",
                "risc0:cuda:2",
                "risc0:cuda:4",
                "risc0:cuda:5"
            ]
        );
        assert_eq!(risc0_job_sizes(&cards), vec![18, 19, 20]);
        assert!(
            risc0_job_cards(&sizes, &[], true).is_empty(),
            "risc0 switched off"
        );
        // Planned only on those cards; other backends anywhere.
        assert!(risc0_job_device("risc0", &cards, "gpu2"));
        assert!(!risc0_job_device("risc0", &cards, "gpu1"));
        assert!(risc0_job_device("sp1", &cards, "gpu1"));
        assert_eq!(measure_sizes("risc0", &[19, 20]), vec![19, 20]);
        assert_eq!(measure_sizes("sp1", &[19, 20]), vec![NO_PO2]);
    }

    #[test]
    fn a_job_proves_at_a_size_it_measured_at_on_each_card_that_holds_one() {
        let card = |slot: &str, po2| Risc0Card {
            slot: slot.to_string(),
            device: String::new(),
            po2,
        };
        let sorted = |cards: &[Risc0Card], measured: &[u8]| {
            let (sizes, measured_here) = risc0_prove_sizes(cards, measured);
            let mut v: Vec<(String, u8)> = sizes.into_iter().collect();
            v.sort();
            (v, measured_here)
        };
        let cards = vec![card("a", 18), card("b", 20), card("c", 21)];
        // Each card at the largest measured size it holds: its own, or below it.
        assert_eq!(
            sorted(&cards, &[18, 20]),
            (
                vec![
                    ("a".to_string(), 18),
                    ("b".to_string(), 20),
                    ("c".to_string(), 20)
                ],
                true
            )
        );
        // A card too small for every measured size takes no part...
        assert_eq!(
            sorted(&cards, &[19, 21]),
            (vec![("b".to_string(), 19), ("c".to_string(), 21)], true)
        );
        // ...and when every card is (a restart or a re-benchmark moved them since the claim), each
        // proves it at its own size rather than releasing it.
        assert_eq!(
            sorted(&[card("a", 18), card("b", 19)], &[20]),
            (vec![("a".to_string(), 18), ("b".to_string(), 19)], false)
        );
        // No recorded sizes (a lock from an earlier build, or found with no breadcrumb): the
        // default size every earlier build measured at, on the cards that hold it, as a guess...
        assert_eq!(
            sorted(&cards, &[]),
            (vec![("b".to_string(), 20), ("c".to_string(), 20)], false)
        );
        // ...and on a rig with none, each card at its own size.
        assert_eq!(
            sorted(&[card("a", 18)], &[]),
            (vec![("a".to_string(), 18)], false)
        );
        // No card at all: nothing (the caller keeps the lock for later).
        assert_eq!(sorted(&[], &[20]), (vec![], false));
    }

    #[test]
    fn a_cards_size_is_the_configs_or_this_sessions_in_advanced_mode() {
        let mut rs = zkminer_tui::state::RuntimeSettings {
            risc0_job_po2_config: HashMap::from([
                ("gpu0".to_string(), 19),
                ("gpu1".to_string(), 18),
            ]),
            po2_overrides: HashMap::from([
                (("gpu1".to_string(), "risc0".to_string()), 17),
                (("gpu2".to_string(), "risc0".to_string()), 21),
                (("gpu2".to_string(), "sp1".to_string()), 16),
            ]),
            ..Default::default()
        };
        // Advanced mode off: the session's rows are hidden, and so not applied.
        let mut got: Vec<_> = risc0_job_po2_overrides(&rs).into_iter().collect();
        got.sort();
        assert_eq!(
            got,
            vec![("gpu0".to_string(), 19), ("gpu1".to_string(), 18)]
        );
        rs.advanced_mode = true;
        let mut got: Vec<_> = risc0_job_po2_overrides(&rs).into_iter().collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("gpu0".to_string(), 19),
                ("gpu1".to_string(), 17),
                ("gpu2".to_string(), 21),
            ]
        );
    }

    #[test]
    fn the_conservative_rate_is_halved_per_step_below_the_default_size() {
        assert_eq!(risc0_conservative_cps(&[20, 21]), CONSERVATIVE_SIZING_CPS);
        assert_eq!(
            risc0_conservative_cps(&[18, 20]),
            CONSERVATIVE_SIZING_CPS * 0.25
        );
        assert_eq!(risc0_conservative_cps(&[]), CONSERVATIVE_SIZING_CPS);
    }

    #[test]
    fn a_pairs_other_sizes_are_never_evicted_to_make_room_for_one() {
        let (measured, _) = fresh();
        let prog = B256::repeat_byte(0x61);
        let big = vec![0u8; 32 * 1024];
        let fill = |n: usize| {
            for i in 0..n {
                let ih = keccak256(i.to_le_bytes());
                insert_measured_value(
                    &measured,
                    "risc0",
                    R0,
                    prog,
                    ih,
                    entry(9, Some(&big[..]), None, 1),
                );
            }
        };
        // At the journal byte cap, a pair measured at one size, then at another with the largest
        // journal: the cap evicts other pairs, never the first size of this one.
        fill(MEASURED_JOURNAL_BYTES_CAP / big.len());
        let ih = keccak256(b"victim");
        let largest = vec![0u8; 32 * 1024 + 1];
        insert_measured_value(
            &measured,
            "risc0",
            19,
            prog,
            ih,
            entry(9, Some(&largest[..]), None, 1),
        );
        insert_measured_value(
            &measured,
            "risc0",
            20,
            prog,
            ih,
            entry(9, Some(&largest[..]), None, 1),
        );
        let m = measured.lock().unwrap();
        assert!(m.contains_key(&(backend_tag("risc0"), 19, prog, ih)));
        assert!(m.contains_key(&(backend_tag("risc0"), 20, prog, ih)));
        let total: usize = m
            .values()
            .filter_map(|v| v.journal.as_ref())
            .map(|j| j.len())
            .sum();
        assert!(total <= MEASURED_JOURNAL_BYTES_CAP);
    }

    #[test]
    fn the_watchdog_never_assumes_a_card_faster_than_the_slowest_it_was_sized_on() {
        let cap = Duration::from_secs(3600);
        // 40M cycles at the 400k floor: 100 s, four times over.
        assert_eq!(prove_watchdog(40_000_000, None, 0, cap).as_secs(), 400);
        assert_eq!(prove_watchdog(40_000_000, Some(2e6), 0, cap).as_secs(), 400);
        // A card at a small size, at 100k: four times its 400 s.
        assert_eq!(
            prove_watchdog(40_000_000, Some(1e5), 0, cap).as_secs(),
            1600
        );
        // Bounded by the cap, and never under 90 s plus the allowances.
        assert_eq!(prove_watchdog(40_000_000, Some(1e4), 0, cap), cap);
        assert_eq!(prove_watchdog(1_000, Some(1e5), 30, cap).as_secs(), 120);
        assert_eq!(
            prove_watchdog(40_000_000, Some(f64::NAN), 0, cap).as_secs(),
            400
        );
    }

    #[test]
    fn the_journal_length_kept_is_the_longest_at_any_size() {
        let cache: JournalLenCache = Default::default();
        let (prog, ih) = (B256::repeat_byte(0x71), keccak256(b"j"));
        insert_journal_len(&cache, "risc0", prog, ih, 100);
        insert_journal_len(&cache, "risc0", prog, ih, 40);
        assert_eq!(get_journal_len(&cache, "risc0", prog, ih), Some(100));
        insert_journal_len(&cache, "risc0", prog, ih, 300);
        assert_eq!(get_journal_len(&cache, "risc0", prog, ih), Some(300));
    }

    /// A proof's rate is filed under the planner's id for its card, for its backend.
    #[test]
    fn a_proof_teaches_the_planner_its_cards_rate() {
        let secs = Duration::from_secs;
        assert_eq!(
            observed_rate("risc0:cuda:1", 42_000_000, secs(14)),
            Some((("gpu1".to_string(), "risc0".to_string()), 3_000_000.0))
        );
        assert_eq!(
            observed_rate("sp1:rocm:0", 20_000_000, secs(40)).map(|(k, _)| k),
            Some(("gpu-rocm0".to_string(), "sp1".to_string()))
        );
        assert_eq!(
            observed_rate("risc0:intel:0", 1, secs(1)).map(|(k, _)| k.0),
            Some("gpu-intel0".to_string())
        );
        assert_eq!(observed_rate("risc0:cpu", 1_000, secs(1)), None);
        assert_eq!(observed_rate("risc0:cuda:0", 1_000, Duration::ZERO), None);
        assert_eq!(observed_rate("risc0:cuda:0", 0, secs(1)), None);

        // Smoothed: the first proof sets it, a later one moves it part of the way.
        note_observed_throughput("openvm:cuda:7", 10_000_000, secs(10));
        let key = ("gpu7".to_string(), "openvm".to_string());
        assert_eq!(observed_throughputs()[&key], 1_000_000.0);
        note_observed_throughput("openvm:cuda:7", 20_000_000, secs(10));
        let expected = 1_000_000.0 + OBSERVED_THROUGHPUT_WEIGHT * 1_000_000.0;
        assert!((observed_throughputs()[&key] - expected).abs() < 1e-6);
    }

    /// Learned rates replace what the rows said for that card and backend, keep the rest, and add a
    /// backend the rows lacked.
    #[test]
    fn learned_rates_replace_the_placeholder_rows() {
        let rows = vec![
            ("gpu0".to_string(), "risc0".to_string(), 1e6),
            ("gpu1".to_string(), "risc0".to_string(), 1e6),
        ];
        let observed: HashMap<(String, String), f64> = [
            (("gpu0".to_string(), "risc0".to_string()), 3e6),
            (("gpu0".to_string(), "sp1".to_string()), 1.5e6),
            (("gpu1".to_string(), "sp1".to_string()), f64::NAN),
        ]
        .into_iter()
        .collect();
        let mut got = with_observed(rows, &observed);
        got.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        assert_eq!(
            got,
            vec![
                ("gpu0".to_string(), "risc0".to_string(), 3e6),
                ("gpu0".to_string(), "sp1".to_string(), 1.5e6),
                ("gpu1".to_string(), "risc0".to_string(), 1e6),
            ]
        );
    }

    /// The placeholder suite is recognisable once it has been read back from the shared state, and a
    /// suite from a benchmark run is not mistaken for it.
    #[test]
    fn the_synthetic_suite_is_never_taken_for_a_measured_one() {
        let cards = vec![("gpu0".to_string(), "0000:06:10.0".to_string())];
        assert!(is_synthetic_suite(&synthetic_conservative_benchmark(
            &cards
        )));
        let mut measured = zkminer_prover::benchmark::BenchmarkSuite::default();
        measured.cpu_info = "AMD Ryzen Threadripper 3970X 32-Core Processor".to_string();
        assert!(!is_synthetic_suite(&measured));
    }

    /// Each candidate lands under its first reason, and the summary names only what happened.
    #[test]
    fn the_admission_tally_names_why_work_was_not_claimed() {
        use zkminer_strategy::queue::Rejection;
        let base = Candidate {
            recommended: true,
            measurable: true,
            planner_active: true,
            model_complete: true,
            planned: false,
            rejection: None,
            bypass_room: false,
        };
        let mut t = AdmissionTally::default();
        t.note(Candidate {
            planned: true,
            ..base
        });
        t.note(Candidate {
            model_complete: false,
            ..base
        });
        t.note(Candidate {
            rejection: Some(&Rejection::HorizonFull),
            ..base
        });
        t.note(Candidate {
            rejection: Some(&Rejection::DeadlineInfeasible),
            ..base
        });
        t.note(Candidate {
            recommended: false,
            planned: true,
            ..base
        });
        t.note(Candidate {
            planner_active: false,
            bypass_room: true,
            ..base
        });
        t.note(Candidate {
            planner_active: false,
            ..base
        });
        assert_eq!(
            t,
            AdmissionTally {
                reached: 7,
                planned: 1,
                bypassed: 1,
                not_recommended: 1,
                model_incomplete: 1,
                horizon_full: 1,
                deadline: 1,
                no_room: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            t.to_string(),
            "7 at admission, 1 planned, 1 claimed without the planner, 1 not recommended, \
             1 planner skipped (model incomplete), 1 horizon full, 1 deadline infeasible, \
             1 no free card"
        );
    }

    /// A reservation is subtracted from the on-chain available figure only while that figure cannot
    /// count its lock: claim pending, locked after the read, or either block unknown.
    #[test]
    fn a_lock_already_counted_on_chain_is_not_subtracted_again() {
        assert!(lock_counted_on_chain(Some(100), Some(100)));
        assert!(lock_counted_on_chain(Some(100), Some(99)));
        assert!(!lock_counted_on_chain(Some(100), Some(101)));
        assert!(!lock_counted_on_chain(None, Some(1)));
        assert!(!lock_counted_on_chain(Some(100), None));

        const HEMI: u128 = 1_000_000_000_000_000_000;
        let (a, b, c, d) = (
            B256::repeat_byte(0xa1),
            B256::repeat_byte(0xa2),
            B256::repeat_byte(0xa3),
            B256::repeat_byte(0xa4),
        );
        // a locked before the read, b after it, c's claim still pending, d recovered (0 reserved).
        let held: HashMap<B256, u128> = [(a, 100 * HEMI), (b, 100 * HEMI), (c, 100 * HEMI), (d, 0)]
            .into_iter()
            .collect();
        let locks: HashMap<B256, u64> = [(a, 90), (b, 110), (d, 50)].into_iter().collect();
        assert_eq!(uncounted_reservations(&held, &locks, Some(100)), 200 * HEMI);
        // A stake read of unknown block counts nothing as on-chain: every reservation subtracted,
        // the old form exactly.
        assert_eq!(uncounted_reservations(&held, &locks, None), 300 * HEMI);
        // On a 1,000 HEMI stake with five held jobs locked by the read, the old form left 0 HEMI
        // (500 counted on-chain, 500 again here); this leaves the 500 that are free.
        let five: HashMap<B256, u128> = (0..5u8)
            .map(|i| (B256::repeat_byte(i), 100 * HEMI))
            .collect();
        let locked: HashMap<B256, u64> = five.keys().map(|j| (*j, 10)).collect();
        let on_chain_available = 500 * HEMI;
        assert_eq!(
            on_chain_available - uncounted_reservations(&five, &locked, Some(20)),
            500 * HEMI
        );
    }

    /// A job no longer held never counts as needing a card, nor makes the count wrap.
    #[test]
    fn only_held_jobs_count_as_needing_a_card() {
        let (a, b, c) = (
            B256::repeat_byte(1),
            B256::repeat_byte(2),
            B256::repeat_byte(3),
        );
        let in_flight: HashMap<B256, u128> = [(a, 0), (b, 0)].into_iter().collect();
        let proved: std::collections::HashSet<B256> = [b, c].into_iter().collect();
        assert_eq!(needing_card(&in_flight, &proved), 1);
        assert_eq!(needing_card(&HashMap::new(), &proved), 0);
    }

    /// A job hands its card back exactly once, whether released explicitly or by dropping.
    #[test]
    fn a_card_is_handed_back_once() {
        let jid = B256::repeat_byte(0xc4);
        {
            let mut card = CardRelease(Some(jid));
            card.release();
        }
        let freed = CARDS_FREED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(freed.iter().filter(|j| **j == jid).count(), 1);
        CARDS_FREED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|j| *j != jid);
    }

    #[test]
    fn a_risc0_job_is_held_to_the_risc0_cards_without_look_ahead() {
        // Two GPUs, one with no risc0 size: one risc0 job at a time...
        assert!(risc0_bypass_room(0, 0, 2, true, 1));
        assert!(!risc0_bypass_room(1, 0, 2, true, 1));
        // ...but an SP1 job in flight on the other card takes no risc0 room.
        assert!(risc0_bypass_room(1, 1, 2, true, 1));
        assert!(
            !risc0_bypass_room(2, 1, 2, true, 1),
            "the total cap still holds"
        );
        // Another backend's job is held to the total alone.
        assert!(risc0_bypass_room(1, 0, 2, false, 1));
        assert!(
            !risc0_bypass_room(0, 0, 2, true, 0),
            "no risc0 card, no risc0 job"
        );
    }

    #[test]
    fn a_risc0_card_with_no_usable_row_is_planned_at_the_conservative_rate() {
        let card = |device: &str, po2| Risc0Card {
            slot: format!("risc0:cuda:{device}"),
            device: device.to_string(),
            po2,
        };
        let mut rows = vec![
            ("gpu0".to_string(), "risc0".to_string(), 1.5e6),
            ("gpu1".to_string(), "risc0".to_string(), 0.0),
            ("gpu1".to_string(), "sp1".to_string(), 9e5),
        ];
        fill_risc0_rows(
            &mut rows,
            &[
                card("gpu0", 20),
                card("gpu1", 18),
                card("gpu2", 20),
                card("cpu", 20),
            ],
        );
        rows.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        assert_eq!(
            rows,
            vec![
                ("gpu0".to_string(), "risc0".to_string(), 1.5e6),
                (
                    "gpu1".to_string(),
                    "risc0".to_string(),
                    CONSERVATIVE_SIZING_CPS * 0.25
                ),
                ("gpu1".to_string(), "sp1".to_string(), 9e5),
                (
                    "gpu2".to_string(),
                    "risc0".to_string(),
                    CONSERVATIVE_SIZING_CPS
                ),
            ]
        );
    }

    #[test]
    fn a_job_waits_for_a_card_but_never_into_its_release_margin() {
        assert_eq!(no_card_wait(None), NO_RISC0_CARD_WAIT);
        assert_eq!(
            no_card_wait(Some(Duration::from_secs(600))),
            NO_RISC0_CARD_WAIT
        );
        assert_eq!(
            no_card_wait(Some(Duration::from_secs(MIN_ATTEMPT_BUDGET_SECS + 20))),
            Duration::from_secs(20)
        );
        assert_eq!(no_card_wait(Some(Duration::ZERO)), Duration::from_secs(1));
    }

    #[test]
    fn a_job_measures_whenever_a_measure_worker_is_free() {
        // One size: as many jobs as measure workers.
        assert_eq!(measure_admits(0, 1, 2), 1);
        assert_eq!(measure_admits(1, 1, 2), 1);
        assert_eq!(measure_admits(2, 1, 2), 0);
        // Two sizes on two workers: both at once when both are free...
        assert_eq!(measure_admits(0, 2, 2), 2);
        // ...one when one is (the other size on a later tick), never held back for both.
        assert_eq!(measure_admits(1, 2, 2), 1);
        // More sizes than workers.
        assert_eq!(measure_admits(0, 3, 2), 2);
        assert_eq!(measure_admits(3, 1, 2), 0);
    }
}
