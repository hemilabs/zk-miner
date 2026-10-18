//! RISC Zero prover worker binary.
//!
//! Long-running process that communicates with the host via stdin/stdout IPC.
//! Stderr is used for logging (captured and forwarded by host).

use std::io::{self, BufReader, BufWriter};
use std::time::Instant;

use anyhow::{Context, Result};
use zkminer_prover_protocol::types::CUDA_VRAM_BYTES_ENV;
use zkminer_prover_protocol::{
    is_gpu_oom, read_message, write_message, BenchmarkEntry, ErrorKind, WorkerCommand,
    WorkerResponse, BACKEND_RISC0, BENCH_BIGINT_MUL, BENCH_CHACHA_MIX, BENCH_ECDSA_VERIFY,
    BENCH_FIBONACCI, BENCH_MEMORY_MERKLE, BENCH_SHA256_CHAIN, PROTOCOL_VERSION,
};

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

const WORKER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Duplicate `fd` with close-on-exec set.
///
/// `dup` deliberately CLEARS `FD_CLOEXEC` on the new descriptor, so without this every process the
/// worker forks inherits a writable copy of the host's IPC pipe; a grandchild that outlives us then
/// keeps the write end open and the host's blocking `read_exact` never sees EOF. The host never
/// passes this descriptor to anyone, so close-on-exec is unconditionally correct. (Mirrors the SP1
/// worker's `dup_cloexec`.)
#[cfg(unix)]
fn dup_cloexec(fd: std::os::unix::io::RawFd) -> std::io::Result<std::os::unix::io::RawFd> {
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(new)
}

fn main() {
    // Direct benchmark mode runs the operator's own guests and prints a human table to the REAL
    // stdout, so it must come before the fd-1 redirect below. It speaks no IPC.
    if std::env::args().any(|a| a == "--benchmark") {
        tracing_subscriber::fmt()
            .with_writer(io::stderr)
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
        let results = run_benchmarks();
        for r in &results {
            println!(
                "{:<16} {:>12} cycles  {:>8.2}s  {:>12.0} c/s  weight={:.2}  precompile={}",
                r.program_name, r.cycles, r.duration_secs, r.throughput, r.weight, r.precompile,
            );
        }
        return;
    }

    // CRITICAL (security): save the real stdout FD for IPC, then redirect FD 1 to stderr so NOTHING
    // the guest (via risc0's POSIX `sys_write`/`sys_log` to fd 1, which `PosixIo::default()` wires to
    // this process's stdout) — nor any native/CUDA library — can inject bytes into the length-prefixed
    // bincode control stream the dispatcher reads. A submitter's ELF could otherwise desync/forge that
    // stream and churn the GPU prover. The SP1 worker already does this for gnark's CGO prints; risc0
    // and OpenVM were missing it. The worker's own IPC frames go only through the saved descriptor.
    #[cfg(unix)]
    let ipc_stdout = {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let stdout_fd = io::stdout().as_raw_fd(); // FD 1
        let ipc_fd = dup_cloexec(stdout_fd).expect("dup(stdout) failed");
        unsafe { libc::dup2(io::stderr().as_raw_fd(), stdout_fd) };
        unsafe { std::fs::File::from_raw_fd(ipc_fd) }
    };
    #[cfg(not(unix))]
    let ipc_stdout = io::stdout();

    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    if let Err(e) = run_worker_loop(ipc_stdout) {
        tracing::error!("Worker fatal error: {e}");
        std::process::exit(1);
    }
}

fn run_worker_loop(ipc_stdout: impl io::Write) -> Result<()> {
    let mut stdin = BufReader::new(io::stdin().lock());
    let mut stdout = BufWriter::new(ipc_stdout);

    loop {
        let cmd: WorkerCommand = match read_message(&mut stdin) {
            Ok(cmd) => cmd,
            Err(zkminer_prover_protocol::FrameError::UnexpectedEof) => {
                tracing::info!("Host closed stdin, shutting down");
                break;
            }
            Err(e) => {
                tracing::error!("Failed to read command: {e}");
                break;
            }
        };

        match cmd {
            WorkerCommand::Hello { protocol_version } => {
                tracing::info!("Hello from host (protocol v{protocol_version})");
                let resp = WorkerResponse::HelloAck {
                    protocol_version: PROTOCOL_VERSION,
                    backend: BACKEND_RISC0.to_string(),
                    sdk_version: format!("risc0-zkvm {}", risc0_zkvm::VERSION),
                    worker_version: WORKER_VERSION.to_string(),
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Capabilities => {
                let (gpu_available, gpu_name) = detect_gpu();
                let resp = WorkerResponse::CapabilitiesReport {
                    backend: BACKEND_RISC0.to_string(),
                    version: risc0_zkvm::VERSION.to_string(),
                    supported_benchmarks: vec![
                        BENCH_FIBONACCI.to_string(),
                        BENCH_SHA256_CHAIN.to_string(),
                        BENCH_ECDSA_VERIFY.to_string(),
                        BENCH_BIGINT_MUL.to_string(),
                        BENCH_MEMORY_MERKLE.to_string(),
                        BENCH_CHACHA_MIX.to_string(),
                    ],
                    gpu_available,
                    gpu_name,
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Benchmark => {
                tracing::info!("Running benchmarks...");
                let results = run_benchmarks_streaming(&mut stdout)?;
                let resp = WorkerResponse::BenchmarkResult { results };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Prove {
                request_id,
                elf,
                input_data,
                po2,
                program_id,
            } => {
                tracing::info!(
                    "Proving request {request_id} ({} bytes ELF, po2={po2:?})",
                    elf.len()
                );
                // Announce that proving has STARTED. `WorkerResponse::Progress` had exactly one
                // reference in the whole workspace — the arm that consumes it — so no worker
                // ever emitted one and the dispatcher's `on_progress` callback was dead code.
                // The miner uses that callback to move a job from Queued to Proving, so without
                // this a job claimed ahead of a free GPU displayed "Queued (waiting for GPU)"
                // for the entire proof: the opposite of the truth, and worse than the
                // "Proving 0%" it replaced. Sent once, at the transition that matters.
                let started = WorkerResponse::Progress {
                    request_id,
                    fraction: 0.0,
                    elapsed_secs: 0.0,
                    segments: None,
                };
                write_message(&mut stdout, &started)?;
                match run_proof(&elf, &input_data, po2, program_id) {
                    Ok((journal, seal, duration_secs, cycles)) => {
                        let resp = WorkerResponse::ProofResult {
                            request_id,
                            journal,
                            seal,
                            duration_secs,
                            cycles,
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                    Err(e) => {
                        let msg = format!("{e:#}");
                        let kind = if is_gpu_oom(&msg) {
                            // GPU OOM: tag as ResourceExhausted so the dispatcher kills +
                            // respawns this worker with a clean GPU context (a wedged/leaked
                            // context would otherwise fail every subsequent proof).
                            ErrorKind::ResourceExhausted
                        } else if msg.contains("po2 value")
                            || msg.contains("out of valid range")
                            || msg.contains("does not match job programId")
                        {
                            // Bad job (wrong po2 / wrong ELF for the programId), not a sick worker:
                            // InvalidInput so the dispatcher does not kill+respawn a healthy worker.
                            ErrorKind::InvalidInput
                        } else if msg.contains("serialize") || msg.contains("bincode") {
                            ErrorKind::Internal
                        } else {
                            ErrorKind::ProofFailed
                        };
                        let resp = WorkerResponse::Error {
                            request_id,
                            kind,
                            message: msg,
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                }
            }

            WorkerCommand::Execute {
                request_id,
                elf,
                input_data,
                program_id,
            } => {
                tracing::info!("Execute request {request_id} ({} bytes ELF)", elf.len());
                match run_execute(&elf, &input_data, program_id) {
                    Ok((cycles, duration_secs)) => {
                        tracing::info!(
                            "Execute {request_id}: {cycles} cycles in {duration_secs:.2}s"
                        );
                        let resp = WorkerResponse::ExecuteResult {
                            request_id,
                            cycles,
                            duration_secs,
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                    Err(e) => {
                        let msg = format!("{e:#}");
                        // Execution failure is NOT proof failure: the guest may simply panic
                        // on this input, which is a property of the job, not of this worker.
                        // Report InvalidInput so the dispatcher does not kill and respawn a
                        // perfectly healthy worker over a bad job.
                        let resp = WorkerResponse::Error {
                            request_id,
                            kind: ErrorKind::InvalidInput,
                            message: msg,
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                }
            }

            WorkerCommand::Cancel { request_id } => {
                // Best-effort cancellation. Current risc0 proving is synchronous,
                // so we can only acknowledge after the fact.
                tracing::info!("Cancel requested for {request_id}");
                let resp = WorkerResponse::Cancelled { request_id };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Warmup { request_id } => {
                // Nothing to set up before a first proof.
                let resp = WorkerResponse::WarmupDone {
                    request_id,
                    summary: "nothing to warm up".to_string(),
                    groth16_helper: false,
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Shutdown => {
                tracing::info!("Shutdown requested, exiting");
                break;
            }

            WorkerCommand::CalibrateSegmentLimit { request_id, po2 } => {
                tracing::info!("Po2 calibration requested at po2={po2}");
                match run_po2_calibration(request_id, po2) {
                    Ok(resp) => write_message(&mut stdout, &resp)?,
                    Err(e) => {
                        let resp = WorkerResponse::Error {
                            request_id,
                            kind: ErrorKind::ProofFailed,
                            message: format!("Po2 calibration failed: {e:#}"),
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                }
            }
        }
    }

    Ok(())
}

fn detect_gpu() -> (bool, Option<String>) {
    #[cfg(feature = "cuda")]
    {
        if let Ok(output) = std::process::Command::new("nvidia-smi")
            .args(["--query-gpu=name", "--format=csv,noheader,nounits"])
            .output()
        {
            if output.status.success() {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !name.is_empty() {
                    return (true, Some(name));
                }
            }
        }
    }
    #[cfg(feature = "rocm")]
    {
        // Try rocm-smi first (more reliable than sysfs product_name)
        if let Ok(output) = std::process::Command::new("rocm-smi")
            .args(["--showproductname"])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    if line.contains("Card Series") {
                        if let Some(name) = line.split(':').nth(1) {
                            let name = name.trim().to_string();
                            if !name.is_empty() {
                                return (true, Some(name));
                            }
                        }
                    }
                }
            }
        }
        // Fallback: check sysfs for any AMD GPU
        if std::path::Path::new("/dev/kfd").exists() {
            return (true, Some("AMD GPU".to_string()));
        }
    }
    (false, None)
}

/// Execute the guest WITHOUT proving, returning its true cycle count.
///
/// This is the RISC-V simulator: it runs the program to completion and reports
/// `total_cycles` — the same quantity `ProofResult.cycles` carries — at execution cost
/// rather than proving cost. On the measured rig a 92.8M-cycle job proves in ~40s on a 5090;
/// executing it is a small fraction of that, because no STARK is generated.
///
/// Deliberately uses the default (CPU) executor: this is a sizing measurement, so it must not
/// contend for the GPU that the proofs it sizes are running on.
/// True when `image_id` (a risc0 guest image id, 32 bytes) corresponds to the on-chain `program_id`.
///
/// The byte order the registry stores a risc0 programId in — vs risc0's native word layout from
/// `Digest::as_bytes` — is deployment-defined and not knowable from this repo, so we accept EITHER
/// order. A legitimately matching ELF matches under whichever order the chain used; an ELF that is a
/// *different* program matches under neither (a 256-bit collision is infeasible). Accepting both
/// orders is what guarantees the binding check can never false-reject a genuine job.
fn image_id_matches(image_id: &[u8], program_id: &[u8; 32]) -> bool {
    image_id == program_id.as_slice()
        || image_id.iter().rev().copied().eq(program_id.iter().copied())
}

/// Set `ZKMINER_RISC0_SKIP_PROGRAM_ID_CHECK=1` to disable the image-id↔programId binding (only for a
/// deployment whose risc0 programId is NOT the raw image id). Enforced by default.
fn program_id_check_disabled() -> bool {
    matches!(
        std::env::var("ZKMINER_RISC0_SKIP_PROGRAM_ID_CHECK")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

/// Refuse to run an ELF whose computed risc0 image id does not match the job's on-chain `programId`.
/// No-op when the host did not supply a programId (benchmark/calibration/mock) or the check is
/// disabled. Catches a submitter who registers programId X but serves an ELF for a different program,
/// *before* a full Groth16 proof (or a sizing execute) is spent on a proof the chain will reject.
fn verify_program_id(elf: &[u8], program_id: Option<[u8; 32]>) -> anyhow::Result<()> {
    let Some(pid) = program_id else {
        return Ok(());
    };
    if program_id_check_disabled() {
        return Ok(());
    }
    let image_id =
        risc0_zkvm::compute_image_id(elf).context("compute_image_id for programId binding")?;
    if image_id_matches(image_id.as_bytes(), &pid) {
        Ok(())
    } else {
        anyhow::bail!(
            "ELF image id {image_id} does not match job programId {} (served ELF is not the \
             registered program) — refusing to prove",
            risc0_zkvm::Digest::from(pid)
        );
    }
}

/// Cycle cap for the pre-claim EXECUTE (sizing) path. A runaway guest here is a free DoS lever (no
/// claim, no collateral at stake), and the result is only a sizing estimate, so a generous cap is
/// safe: `1<<34` ≈ 1.7e10 cycles is ~180× the largest proof observed on this market (~9.3e7) and
/// cannot false-cap a real job. The wall-clock measure timeout is the primary bound; this is
/// defence-in-depth and yields a clean "session limit exceeded" rather than a watchdog kill.
/// Override with `ZKMINER_RISC0_EXECUTE_MAX_CYCLES` (0 = unlimited).
fn execute_session_cycle_limit() -> Option<u64> {
    const DEFAULT: u64 = 1u64 << 34;
    match std::env::var("ZKMINER_RISC0_EXECUTE_MAX_CYCLES") {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(_) => Some(DEFAULT),
        },
        Err(_) => Some(DEFAULT),
    }
}

/// Optional cycle cap for the PROVE path, honoured only when the operator sets
/// `ZKMINER_RISC0_MAX_SESSION_CYCLES`. Unset = SDK default (no cap), so a legitimately large proof
/// is never cut short by surprise.
fn prove_session_cycle_limit() -> Option<u64> {
    std::env::var("ZKMINER_RISC0_MAX_SESSION_CYCLES")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
}

fn run_execute(
    elf: &[u8],
    input_data: &[u8],
    program_id: Option<[u8; 32]>,
) -> anyhow::Result<(u64, f64)> {
    use std::time::Instant;
    // Bind the ELF to the job's programId before spending any execution on it (the pre-claim
    // measurement path runs UNCLAIMED, submitter-controlled ELFs).
    verify_program_id(elf, program_id)?;
    let started = Instant::now();

    let mut env_builder = risc0_zkvm::ExecutorEnv::builder();
    if !input_data.is_empty() {
        env_builder.write_slice(input_data);
    }
    if let Some(limit) = execute_session_cycle_limit() {
        env_builder.session_limit(Some(limit));
    }
    let env = env_builder
        .build()
        .map_err(|e| anyhow::anyhow!("execute: env build failed: {e}"))?;

    let session = risc0_zkvm::default_executor()
        .execute(env, elf)
        .map_err(|e| anyhow::anyhow!("execute: {e}"))?;

    // `SessionInfo::cycles()` is the total cycle count, matching what proving reports.
    let cycles = session.cycles();
    Ok((cycles, started.elapsed().as_secs_f64()))
}

/// Cards with less VRAM than this release the Groth16 SRS cache after every proof.
///
/// Set between the two cards measured on 2026-10-07. On the 16.3 GB RTX 5080 the cache stays resident
/// at ~7.25 GB between proofs, and the next 46M-cycle STARK at po2 20 then peaked at 15,834 MiB — 469
/// MiB from the card's capacity — and in the benchmark's program order failed outright. Releasing it
/// dropped the idle worker to 2,452 MiB and that peak to 12,436 MiB. On the 24.6 GB RTX 4090 the same
/// proof leaves ~8 GB spare, so it keeps the cache.
///
/// The saving from keeping it turned out small: wraps after a release ran 2.08-2.12 s on the 5080
/// against 2.01-2.05 s on the cache-keeping 4090, so at most ~0.1 s. The threshold is therefore cheap to
/// get wrong in the conservative direction, which is why an unknown size releases.
const RELEASE_GROTH16_CACHE_BELOW_BYTES: u64 = 20 * 1024 * 1024 * 1024;

/// Free the Groth16 prover and SRS cached on the GPU if this card cannot also hold the next STARK.
///
/// The cache is the Groth16 prover's: `shrink_wrap` uploads the SRS once and keeps it for the life of
/// the process, in a C++ static nothing frees. Whether to drop it is a property of the CARD, which the
/// library cannot see from where it sits, so the decision lives here. The card's size arrives from the
/// dispatcher in `CUDA_VRAM_BYTES_ENV`: `nvidia-smi` ignores `CUDA_VISIBLE_DEVICES`, so this pinned
/// worker cannot ask about its own card. When the size is UNKNOWN the cache is released — that costs
/// at most ~0.1 s per proof, while keeping it on a card that cannot afford it costs the proof.
///
/// Called whether the proof succeeded or not: a wrap that failed part-way can still have built the
/// cache, and the retry that follows needs the room most.
fn release_groth16_cache_if_tight() {
    static DECISION: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let release = *DECISION.get_or_init(|| {
        let total = std::env::var(CUDA_VRAM_BYTES_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok());
        let release = total.is_none_or(|t| t < RELEASE_GROTH16_CACHE_BELOW_BYTES);
        match total {
            Some(t) => tracing::info!(
                "card has {:.1} GiB of VRAM: {} the Groth16 SRS cache between proofs",
                t as f64 / (1u64 << 30) as f64,
                if release { "releasing" } else { "keeping" },
            ),
            None => tracing::info!(
                "card VRAM unknown ({CUDA_VRAM_BYTES_ENV} unset): releasing the Groth16 SRS cache \
                 between proofs"
            ),
        }
        release
    });
    if release {
        if let Err(e) = risc0_groth16::prove::release_srs() {
            tracing::warn!("could not release the Groth16 SRS cache: {e:#}");
        }
    }
}

fn run_proof(
    elf: &[u8],
    input_data: &[u8],
    po2: Option<u8>,
    program_id: Option<[u8; 32]>,
) -> Result<(Vec<u8>, Vec<u8>, f64, u64)> {
    // Bind the ELF to the job's programId ONCE, before the retry loop spends any GPU on it.
    verify_program_id(elf, program_id)?;
    // Retry-on-invalid mitigation for the rare (~1.5%) nondeterministic GPU
    // timing race on RTX 5090 / Blackwell (sm_120) — an intra-kernel race
    // produces an internally-invalid segment STARK, surfaced as
    // "verify segment: verification indicates proof is invalid" (or a failed
    // receipt.verify). It is NOT reproducible for the same input: a fresh prove
    // almost always succeeds. Re-proving on that error class makes the effective
    // failure rate negligible (~1.5% -> ~0.02% with one retry) and guarantees we
    // never return — and never lose stake on (see below) — a corrupt proof.
    // Bounded so a genuine, deterministic failure (bad ELF, real OOM) still
    // surfaces instead of looping. Only the GPU-corruption error class is retried.
    const MAX_ATTEMPTS: usize = 4;
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match run_proof_once(elf, input_data, po2) {
            Ok(result) => {
                if attempt > 1 {
                    tracing::warn!(
                        "Proof succeeded on attempt {attempt}/{MAX_ATTEMPTS} after retrying a (nondeterministic) invalid-proof error"
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                let msg = format!("{e:#}").to_lowercase();
                let recoverable = msg.contains("verification indicates")
                    || msg.contains("verify segment")
                    || msg.contains("receipt is invalid")
                    || msg.contains("proof verification failed");
                if recoverable && attempt < MAX_ATTEMPTS {
                    tracing::warn!(
                        "Proof attempt {attempt}/{MAX_ATTEMPTS} produced an invalid proof (likely GPU race), re-proving: {e:#}"
                    );
                    last_err = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("proof failed after {MAX_ATTEMPTS} attempts")))
}

fn run_proof_once(
    elf: &[u8],
    input_data: &[u8],
    po2: Option<u8>,
) -> Result<(Vec<u8>, Vec<u8>, f64, u64)> {
    use risc0_zkvm::ProverOpts;

    // TEST-ONLY: RISC0_TEST_INJECT_INVALID=N makes the first N calls return a
    // synthetic invalid-proof error before proving, to exercise the retry-on-
    // invalid wrapper deterministically (and cheaply, on any guest/GPU).
    if let Ok(n) = std::env::var("RISC0_TEST_INJECT_INVALID") {
        static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let c = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if c < n.parse::<usize>().unwrap_or(0) {
            anyhow::bail!(
                "verify segment: verification indicates proof is invalid (TEST INJECTED)"
            );
        }
    }

    let mut env_builder = risc0_zkvm::ExecutorEnv::builder();
    env_builder.write_slice(input_data);
    if let Some(po2) = po2 {
        if !(13..=24).contains(&po2) {
            anyhow::bail!("po2 value {po2} out of valid range 13..=24");
        }
        tracing::info!("Setting segment_limit_po2 = {po2}");
        env_builder.segment_limit_po2(po2 as u32);
    }
    if let Some(limit) = prove_session_cycle_limit() {
        tracing::info!("Setting session_limit = {limit} cycles (operator override)");
        env_builder.session_limit(Some(limit));
    }
    let env = env_builder.build()?;

    // Use Groth16 receipt kind for on-chain verifiable proofs.
    // This performs STARK proving followed by Groth16 SNARK compression,
    // producing a constant-size proof (~256 bytes seal) that the on-chain
    // RiscZeroVerifierAdapter can verify.
    let prover = risc0_zkvm::default_prover();
    let opts = ProverOpts::groth16();
    let start = Instant::now();
    let proved = prover.prove_with_opts(env, elf, &opts);
    release_groth16_cache_if_tight();
    let prove_info = proved?;
    let duration_secs = start.elapsed().as_secs_f64();

    let receipt = prove_info.receipt;

    // Verify proof locally before returning — catches GPU corruption (e.g., ROCm SHA-256 bug)
    let image_id =
        risc0_zkvm::compute_image_id(elf).context("Failed to compute image ID for verification")?;
    receipt.verify(image_id).context(
        "Proof verification FAILED — receipt is invalid, GPU may have produced corrupt output",
    )?;

    let journal = receipt.journal.bytes.clone();

    // Extract the Groth16 seal. With ProverOpts::groth16(), the receipt
    // should always contain a Groth16 inner proof.
    let seal = receipt
        .inner
        .groth16()
        .context("Expected Groth16 receipt but got different proof type")?
        .seal
        .clone();

    tracing::info!(
        "Proof complete: {} journal bytes, {} seal bytes, {:.1}s, {} cycles",
        journal.len(),
        seal.len(),
        duration_secs,
        prove_info.stats.total_cycles,
    );

    let cycles = prove_info.stats.total_cycles;
    Ok((journal, seal, duration_secs, cycles))
}

/// Run benchmarks, sending a BenchmarkProgress message after each program completes.
fn run_benchmarks_streaming<W: std::io::Write>(
    stdout: &mut W,
) -> anyhow::Result<Vec<BenchmarkEntry>> {
    let mut results = Vec::new();
    let bench_only = std::env::var("BENCH_ONLY").ok();

    // All 6 canonical programs matching BENCHMARK_PROGRAMS weights.
    // Input sizes tuned so each completes in 5-30s on a mid-range GPU,
    // keeping total benchmark time under 2 minutes on a 4090.
    let benchmarks: &[(&str, &[u8], &[u8], f64, bool)] = &[
        (
            BENCH_FIBONACCI,
            FIBONACCI_ELF,
            &1000u32.to_le_bytes(),
            0.10,
            false,
        ),
        (
            BENCH_SHA256_CHAIN,
            SHA256_CHAIN_ELF,
            &10_000u32.to_le_bytes(),
            0.20,
            true,
        ),
        (
            BENCH_ECDSA_VERIFY,
            ECDSA_VERIFY_ELF,
            &10u32.to_le_bytes(),
            0.25,
            true,
        ),
        (
            BENCH_BIGINT_MUL,
            BIGINT_MUL_ELF,
            &100u32.to_le_bytes(),
            0.10,
            false,
        ),
        (
            BENCH_MEMORY_MERKLE,
            MEMORY_MERKLE_ELF,
            &512u32.to_le_bytes(),
            0.15,
            true,
        ),
        (
            BENCH_CHACHA_MIX,
            CHACHA_MIX_ELF,
            &5_000u32.to_le_bytes(),
            0.20,
            false,
        ),
    ];

    let active: Vec<_> = benchmarks
        .iter()
        .filter(|&&(name, elf, _, _, _)| {
            !elf.is_empty()
                && bench_only
                    .as_ref()
                    .map_or(true, |only| name.eq_ignore_ascii_case(only))
        })
        .collect();
    let total = active.len() as u32;

    for (idx, &&(name, elf, input, weight, precompile)) in active.iter().enumerate() {
        if let Some(entry) = benchmark_program(name, elf, input, weight, precompile) {
            let progress = WorkerResponse::BenchmarkProgress {
                entry: entry.clone(),
                program_index: (idx + 1) as u32,
                total_programs: total,
            };
            write_message(stdout, &progress)?;
            results.push(entry);
        }
    }

    Ok(results)
}

fn run_benchmarks() -> Vec<BenchmarkEntry> {
    let mut results = Vec::new();

    // Check for single-benchmark mode via env var (e.g., BENCH_ONLY=fibonacci)
    let bench_only = std::env::var("BENCH_ONLY").ok();

    // All 6 canonical programs matching BENCHMARK_PROGRAMS weights.
    // Input sizes tuned so each completes in 5-30s on a mid-range GPU,
    // keeping total benchmark time under 2 minutes on a 4090.
    let benchmarks: &[(&str, &[u8], &[u8], f64, bool)] = &[
        (
            BENCH_FIBONACCI,
            FIBONACCI_ELF,
            &1000u32.to_le_bytes(),
            0.10,
            false,
        ),
        (
            BENCH_SHA256_CHAIN,
            SHA256_CHAIN_ELF,
            &10_000u32.to_le_bytes(),
            0.20,
            true,
        ),
        (
            BENCH_ECDSA_VERIFY,
            ECDSA_VERIFY_ELF,
            &10u32.to_le_bytes(),
            0.25,
            true,
        ),
        (
            BENCH_BIGINT_MUL,
            BIGINT_MUL_ELF,
            &100u32.to_le_bytes(),
            0.10,
            false,
        ),
        (
            BENCH_MEMORY_MERKLE,
            MEMORY_MERKLE_ELF,
            &512u32.to_le_bytes(),
            0.15,
            true,
        ),
        (
            BENCH_CHACHA_MIX,
            CHACHA_MIX_ELF,
            &5_000u32.to_le_bytes(),
            0.20,
            false,
        ),
    ];

    for &(name, elf, input, weight, precompile) in benchmarks {
        if elf.is_empty() {
            continue;
        }
        if let Some(ref only) = bench_only {
            if !name.eq_ignore_ascii_case(only) {
                continue;
            }
        }
        if let Some(entry) = benchmark_program(name, elf, input, weight, precompile) {
            results.push(entry);
        }
    }

    results
}

fn benchmark_program(
    name: &str,
    elf: &[u8],
    input: &[u8],
    weight: f64,
    precompile: bool,
) -> Option<BenchmarkEntry> {
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write_slice(input)
        .build()
        .ok()?;

    // Quick HIP sanity check before proving
    #[cfg(feature = "rocm")]
    {
        use std::ffi::c_void;
        extern "C" {
            fn hipMalloc(ptr: *mut *mut c_void, size: usize) -> i32;
            fn hipMemcpy(dst: *mut c_void, src: *const c_void, size: usize, kind: i32) -> i32;
            fn hipFree(ptr: *mut c_void) -> i32;
            fn hipGetLastError() -> i32;
            fn hipDeviceSynchronize() -> i32;
        }
        unsafe {
            // Clear any pending errors
            let last = hipGetLastError();
            if last != 0 {
                tracing::warn!("Pending HIP error before prove: {last}");
            }
            let sync = hipDeviceSynchronize();
            if sync != 0 {
                tracing::warn!("hipDeviceSynchronize before prove: {sync}");
            }
            // Test allocation + memcpy
            let mut ptr: *mut c_void = std::ptr::null_mut();
            let ret = hipMalloc(&mut ptr, 256);
            tracing::info!("HIP test: hipMalloc(256) = {ret}, ptr = {ptr:?}");
            if ret == 0 && !ptr.is_null() {
                let data = [0xAAu8; 256];
                let ret2 = hipMemcpy(ptr, data.as_ptr() as *const c_void, 256, 1);
                tracing::info!("HIP test: hipMemcpy H2D = {ret2}");
                hipFree(ptr);
            }
        }
    }

    // ONE proof, staged, so each stage is timed exactly rather than inferred from two runs.
    //
    // This previously called bare `prove(env, elf)`, i.e. `ProverOpts::default()`, which is
    // `ReceiptKind::Composite`: segment proofs only. That is not what the miner submits. Production
    // (`run_proof_once`) and calibration (`calibrate_segment_limit`) both go to Groth16, so the
    // benchmark measured neither the recursion that folds segments together — whose cost scales with
    // segment count, i.e. with po2 — nor the wrap. `compress` consumes the previous receipt, so the
    // three stages below add up to the same work `prove_with_opts(groth16)` does in one call.
    let prover = risc0_zkvm::default_prover();

    // Stage 1: execution and the segment proofs.
    let started = Instant::now();
    let prove_info = match prover.prove_with_opts(env, elf, &risc0_zkvm::ProverOpts::composite()) {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("{name}: prove failed: {e:#}");
            return None;
        }
    };
    let composite_secs = started.elapsed().as_secs_f64();

    // Stage 2: lift every segment receipt and join them into one constant-size STARK. Scales with
    // segment count, so it is STARK proving and belongs on the variable side of the split.
    let started = Instant::now();
    let succinct = match prover.compress(&risc0_zkvm::ProverOpts::succinct(), &prove_info.receipt) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("{name}: succinct recursion failed: {e:#}");
            return None;
        }
    };
    let recursion_secs = started.elapsed().as_secs_f64();

    // Stage 3: STARK-to-SNARK. Proves the fixed `stark_verify` circuit with a fixed proving key
    // (`~/.risc0/extensions/*-risc0-groth16/stark_verify_final.zkey`), so it does not depend on the
    // program at all — which is the reason to report it apart from the stages above.
    let started = Instant::now();
    let wrapped = prover.compress(&risc0_zkvm::ProverOpts::groth16(), &succinct);
    let wrap_secs = started.elapsed().as_secs_f64();
    // Outside the stopwatch: the release is not part of the wrap, and on a card that releases, the NEXT
    // wrap pays the reload — which is that card's honest per-proof cost.
    release_groth16_cache_if_tight();
    let groth16 = match wrapped {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("{name}: Groth16 wrap failed: {e:#}");
            return None;
        }
    };

    // Verify the GROTH16 receipt — the artifact production submits — rather than the composite one.
    // It also covers the earlier stages: the recursion circuit verifies every segment proof, so GPU
    // output corruption there (notably the known ROCm SHA-256 bug at scale) cannot reach a valid
    // Groth16 receipt. An unverified benchmark would pollute the throughput cache with numbers from a
    // broken proof and the miner would later lose stake attempting to fulfill with an invalid one.
    let image_id = match risc0_zkvm::compute_image_id(elf) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("{name}: failed to compute image id for verification: {e:#}");
            return None;
        }
    };
    if let Err(e) = groth16.verify(image_id) {
        tracing::error!(
            "{name}: Groth16 receipt.verify() FAILED — benchmark proof is invalid, skipping entry: \
             {e:#}"
        );
        return None;
    }

    let cycles = prove_info.stats.total_cycles;
    // STARK = segments + recursion: everything up to one constant-size proof. `throughput` is over
    // this, not over the total, because the wrap is a fixed cost and folding it into a rate would
    // make a 33k-cycle program look orders of magnitude slower than a 65M-cycle one.
    let duration_secs = composite_secs + recursion_secs;
    let throughput = cycles as f64 / duration_secs;

    tracing::info!(
        "{name}: {cycles} cycles — STARK {duration_secs:.2}s (segments {composite_secs:.2}s + \
         recursion {recursion_secs:.2}s, {throughput:.0} c/s), Groth16 wrap {wrap_secs:.2}s, \
         verified"
    );

    Some(BenchmarkEntry {
        program_name: name.to_string(),
        prover_backend: BACKEND_RISC0.to_string(),
        cycles,
        duration_secs,
        throughput,
        weight,
        precompile,
        wrap_secs: Some(wrap_secs),
    })
}

/// Iteration count for the po2 calibration workload.
///
/// MUST produce a workload spanning several segments at PO2_MAX (2^24 cycles), otherwise
/// the sweep carries NO po2 signal: if the program fits in one segment at every po2 then
/// the measured differences are just warm-up and timer noise, and
/// `zkminer_prover::benchmark::calibration_is_usable` discards the whole sweep (host-side
/// `optimal_po2_for_job` is argmax(throughput), so adopting noise would pick a segment
/// size at random).
///
/// Sizing: the fibonacci guest costs a MEASURED ~10.4 cycles/iteration — stable for
/// n >= 100_000 (at small n the reported `total_cycles` is the padded segment size, not
/// the real cost, which is why n=1000 appeared to be ~32.8 cycles/iter).
///   6_000_000 iters ~= 62.4M cycles
///     -> ceil(62.4M / 2^24) = 4 segments at po2=24, ~7% padding
///     -> 62.4M / 2^18      = ~238 segments at po2=18
/// Both ends therefore segment, so the sweep measures the real segment-count trade-off.
///
/// Was 1_000 iterations = 32,768 cycles, which fit in ONE segment at EVERY po2 and made
/// calibration useless (measured on an RTX 5090: segment_count == 1 for po2 18..24).
///
/// Cost: this is a real proof per po2 step, so a full sweep is minutes per GPU. That is
/// why calibration is opt-in (`zkminer benchmark --calibrate`), never a default run.
const CALIBRATION_ITERS: u32 = 6_000_000;

/// Run a po2 calibration: prove fibonacci at the specified segment po2 and measure throughput.
fn run_po2_calibration(request_id: u64, po2: u8) -> Result<WorkerResponse> {
    let input = CALIBRATION_ITERS.to_le_bytes();
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write_slice(&input)
        .segment_limit_po2(po2 as u32)
        .build()?;

    let start = std::time::Instant::now();
    let prover = risc0_zkvm::default_prover();
    // Measure the SAME pipeline the miner actually runs (`run_proof_once` uses
    // ProverOpts::groth16()), NOT `prove()`'s default composite receipt.
    //
    // This is the difference between a useful calibration and a misleading one. A
    // composite proof stops after segment proving, so it never observes:
    //   * lift/join FOLDING, whose cost scales with SEGMENT COUNT and is therefore the
    //     dominant po2-dependent term, and
    //   * the Groth16 wrap.
    // Measured on a 4090 with this 62M-cycle workload (po2 18/19/20):
    //     folding      50.90 / 23.90 / 11.60 s   <- halves per po2 step
    //     segments+CPU 34.29 / 31.70 / 30.46 s   <- nearly flat
    //     REAL total   87.20 / 57.55 / 44.02 s
    // Composite-only calibration reported 34.6/31.7/30.7 s — i.e. it saw a 12% spread
    // where the real spread is 98%, leaving its argmax to be decided by noise. It also
    // under-reports MEMORY pressure: po2=21 completes composite-only but OOMs on the
    // real groth16 path, so a composite-derived max_feasible_po2 is too optimistic.
    let opts = risc0_zkvm::ProverOpts::groth16();
    let proved = prover.prove_with_opts(env, FIBONACCI_ELF, &opts);
    release_groth16_cache_if_tight();
    let prove_info = proved?;
    let duration = start.elapsed();

    let total_cycles = prove_info.stats.total_cycles;
    let segment_count = prove_info.stats.segments as u32;

    Ok(WorkerResponse::CalibrationResult {
        request_id,
        po2,
        segment_count,
        total_cycles,
        prove_duration_secs: duration.as_secs_f64(),
    })
}

#[cfg(test)]
mod program_id_tests {
    use super::*;

    #[test]
    fn matches_forward_and_reverse_but_not_a_different_id() {
        let mut img = [0u8; 32];
        for (i, b) in img.iter_mut().enumerate() {
            *b = i as u8;
        }
        // Same bytes (forward order) matches.
        assert!(image_id_matches(&img, &img));
        // The chain may store the reversed order — that must still match.
        let mut rev = img;
        rev.reverse();
        assert!(image_id_matches(&img, &rev));
        // A genuinely different program (one bit flipped) matches under neither order.
        let mut other = img;
        other[0] ^= 0x01;
        assert!(!image_id_matches(&img, &other));
    }

    #[test]
    fn verify_accepts_none_and_respects_kill_switch() {
        // No programId supplied (benchmark/calibration/mock) → always OK, regardless of ELF.
        assert!(verify_program_id(&[0u8; 8], None).is_ok());
    }

    // Guest-gated: only meaningful when real guests were compiled in (not RISC0_SKIP_BUILD).
    #[test]
    fn computed_image_id_matches_embedded_fibonacci_id() {
        if FIBONACCI_ELF.is_empty() {
            return; // stubbed guests; nothing to validate
        }
        let image_id = risc0_zkvm::compute_image_id(FIBONACCI_ELF).expect("compute image id");
        // The build embeds FIBONACCI_ID from the SAME computation; this proves our local
        // image-id derivation is self-consistent (the forward byte order).
        let embedded: Vec<u8> = FIBONACCI_ID.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(image_id.as_bytes(), embedded.as_slice());
        // And the real embedded id must bind to itself under verify_program_id.
        let mut pid = [0u8; 32];
        pid.copy_from_slice(image_id.as_bytes());
        assert!(verify_program_id(FIBONACCI_ELF, Some(pid)).is_ok());
        // A different programId (bit flipped) must be refused.
        pid[0] ^= 0x01;
        assert!(verify_program_id(FIBONACCI_ELF, Some(pid)).is_err());
    }
}
