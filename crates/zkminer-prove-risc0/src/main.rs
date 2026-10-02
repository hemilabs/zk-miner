//! RISC Zero prover worker binary.
//!
//! Long-running process that communicates with the host via stdin/stdout IPC.
//! Stderr is used for logging (captured and forwarded by host).

use std::io::{self, BufReader, BufWriter};
use std::time::Instant;

use anyhow::{Context, Result};
use zkminer_prover_protocol::{
    is_gpu_oom, read_message, write_message, BenchmarkEntry, ErrorKind, WorkerCommand,
    WorkerResponse, BACKEND_RISC0, BENCH_BIGINT_MUL, BENCH_CHACHA_MIX, BENCH_ECDSA_VERIFY,
    BENCH_FIBONACCI, BENCH_MEMORY_MERKLE, BENCH_SHA256_CHAIN, PROTOCOL_VERSION,
};

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

const WORKER_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Direct benchmark mode: run benchmarks and print results to stdout
    if std::env::args().any(|a| a == "--benchmark") {
        let results = run_benchmarks();
        for r in &results {
            println!(
                "{:<16} {:>12} cycles  {:>8.2}s  {:>12.0} c/s  weight={:.2}  precompile={}",
                r.program_name, r.cycles, r.duration_secs, r.throughput, r.weight, r.precompile,
            );
        }
        return;
    }

    if let Err(e) = run_worker_loop() {
        tracing::error!("Worker fatal error: {e}");
        std::process::exit(1);
    }
}

fn run_worker_loop() -> Result<()> {
    let mut stdin = BufReader::new(io::stdin().lock());
    let mut stdout = BufWriter::new(io::stdout().lock());

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
            } => {
                tracing::info!("Proving request {request_id} ({} bytes ELF, po2={po2:?})", elf.len());
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
                match run_proof(&elf, &input_data, po2) {
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
                        } else if msg.contains("po2 value") || msg.contains("out of valid range") {
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
            } => {
                tracing::info!("Execute request {request_id} ({} bytes ELF)", elf.len());
                match run_execute(&elf, &input_data) {
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
fn run_execute(elf: &[u8], input_data: &[u8]) -> anyhow::Result<(u64, f64)> {
    use std::time::Instant;
    let started = Instant::now();

    let mut env_builder = risc0_zkvm::ExecutorEnv::builder();
    if !input_data.is_empty() {
        env_builder.write_slice(input_data);
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

fn run_proof(elf: &[u8], input_data: &[u8], po2: Option<u8>) -> Result<(Vec<u8>, Vec<u8>, f64, u64)> {
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
            anyhow::bail!("verify segment: verification indicates proof is invalid (TEST INJECTED)");
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
    let env = env_builder.build()?;

    // Use Groth16 receipt kind for on-chain verifiable proofs.
    // This performs STARK proving followed by Groth16 SNARK compression,
    // producing a constant-size proof (~256 bytes seal) that the on-chain
    // RiscZeroVerifierAdapter can verify.
    let prover = risc0_zkvm::default_prover();
    let opts = ProverOpts::groth16();
    let start = Instant::now();
    let prove_info = prover.prove_with_opts(env, elf, &opts)?;
    let duration_secs = start.elapsed().as_secs_f64();

    let receipt = prove_info.receipt;

    // Verify proof locally before returning — catches GPU corruption (e.g., ROCm SHA-256 bug)
    let image_id = risc0_zkvm::compute_image_id(elf)
        .context("Failed to compute image ID for verification")?;
    receipt.verify(image_id)
        .context("Proof verification FAILED — receipt is invalid, GPU may have produced corrupt output")?;

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
        (BENCH_FIBONACCI, FIBONACCI_ELF, &1000u32.to_le_bytes(), 0.10, false),
        (BENCH_SHA256_CHAIN, SHA256_CHAIN_ELF, &10_000u32.to_le_bytes(), 0.20, true),
        (BENCH_ECDSA_VERIFY, ECDSA_VERIFY_ELF, &10u32.to_le_bytes(), 0.25, true),
        (BENCH_BIGINT_MUL, BIGINT_MUL_ELF, &100u32.to_le_bytes(), 0.10, false),
        (BENCH_MEMORY_MERKLE, MEMORY_MERKLE_ELF, &512u32.to_le_bytes(), 0.15, true),
        (BENCH_CHACHA_MIX, CHACHA_MIX_ELF, &5_000u32.to_le_bytes(), 0.20, false),
    ];

    let active: Vec<_> = benchmarks.iter()
        .filter(|&&(name, elf, _, _, _)| {
            !elf.is_empty() && bench_only.as_ref().map_or(true, |only| name.eq_ignore_ascii_case(only))
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
        (BENCH_FIBONACCI, FIBONACCI_ELF, &1000u32.to_le_bytes(), 0.10, false),
        (BENCH_SHA256_CHAIN, SHA256_CHAIN_ELF, &10_000u32.to_le_bytes(), 0.20, true),
        (BENCH_ECDSA_VERIFY, ECDSA_VERIFY_ELF, &10u32.to_le_bytes(), 0.25, true),
        (BENCH_BIGINT_MUL, BIGINT_MUL_ELF, &100u32.to_le_bytes(), 0.10, false),
        (BENCH_MEMORY_MERKLE, MEMORY_MERKLE_ELF, &512u32.to_le_bytes(), 0.15, true),
        (BENCH_CHACHA_MIX, CHACHA_MIX_ELF, &5_000u32.to_le_bytes(), 0.20, false),
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

    let start = Instant::now();
    let prover = risc0_zkvm::default_prover();
    let prove_info = match prover.prove(env, elf) {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("{name}: prove failed: {e:#}");
            return None;
        }
    };
    let duration_secs = start.elapsed().as_secs_f64();

    // Verify the receipt locally — catches GPU output corruption (notably the
    // known ROCm SHA-256 bug at scale). An unverified benchmark would pollute
    // the throughput cache with numbers from a broken proof and the miner
    // would later lose stake attempting to fulfill with an invalid proof.
    let image_id = match risc0_zkvm::compute_image_id(elf) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("{name}: failed to compute image id for verification: {e:#}");
            return None;
        }
    };
    if let Err(e) = prove_info.receipt.verify(image_id) {
        tracing::error!(
            "{name}: receipt.verify() FAILED — benchmark proof is invalid, skipping entry: {e:#}"
        );
        return None;
    }

    let cycles = prove_info.stats.total_cycles;
    let throughput = cycles as f64 / duration_secs;

    tracing::info!("{name}: {cycles} cycles in {duration_secs:.2}s ({throughput:.0} c/s, verified)");

    Some(BenchmarkEntry {
        program_name: name.to_string(),
        prover_backend: BACKEND_RISC0.to_string(),
        cycles,
        duration_secs,
        throughput,
        weight,
        precompile,
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
    let prove_info = prover.prove_with_opts(env, FIBONACCI_ELF, &opts)?;
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
