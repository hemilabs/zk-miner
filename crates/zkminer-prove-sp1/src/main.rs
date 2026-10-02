//! SP1 prover worker binary.
//!
//! Long-running process that communicates with the host via stdin/stdout IPC.

use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter};
use std::time::Instant;

use anyhow::Result;

/// The concrete proving-key type produced by the blocking CUDA prover's `setup`.
/// Named via the associated type so we don't need a direct `sp1-cuda` dependency.
type CudaPk = <sp1_sdk::blocking::CudaProver as sp1_sdk::blocking::Prover>::ProvingKey;

/// Hash an ELF into a stable cache key (the proving key depends only on the program).
fn elf_hash(elf: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    elf.hash(&mut h);
    h.finish()
}
use zkminer_prover_protocol::{
    is_gpu_oom, read_message, write_message, BenchmarkEntry, ErrorKind, WorkerCommand,
    WorkerResponse, BACKEND_SP1, BENCH_BIGINT_MUL, BENCH_CHACHA_MIX, BENCH_ECDSA_VERIFY,
    BENCH_FIBONACCI, BENCH_MEMORY_MERKLE, BENCH_SHA256_CHAIN, PROTOCOL_VERSION,
};

const WORKER_VERSION: &str = env!("CARGO_PKG_VERSION");

// SP1 ELFs are embedded via include_bytes! using env vars set by sp1_build::build_program.
const FIBONACCI_SP1_GUEST_ELF: &[u8] = include_bytes!(env!("SP1_ELF_fibonacci-sp1-guest"));
const SHA256_CHAIN_SP1_GUEST_ELF: &[u8] = include_bytes!(env!("SP1_ELF_sha256-chain-sp1-guest"));
const ECDSA_VERIFY_SP1_GUEST_ELF: &[u8] = include_bytes!(env!("SP1_ELF_ecdsa-verify-sp1-guest"));
const BIGINT_MUL_SP1_GUEST_ELF: &[u8] = include_bytes!(env!("SP1_ELF_bigint-mul-sp1-guest"));
const MEMORY_MERKLE_SP1_GUEST_ELF: &[u8] = include_bytes!(env!("SP1_ELF_memory-merkle-sp1-guest"));
const CHACHA_MIX_SP1_GUEST_ELF: &[u8] = include_bytes!(env!("SP1_ELF_chacha-mix-sp1-guest"));

fn main() {
    // CRITICAL: Save the real stdout FD for IPC before anything can pollute it.
    // The SP1 SDK's gnark CGO library (Go code) may print to stdout (FD 1),
    // which would corrupt the bincode IPC stream. We dup stdout for IPC,
    // then redirect FD 1 to stderr so any stray prints go to the log.
    #[cfg(unix)]
    let ipc_stdout = {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let stdout_fd = io::stdout().as_raw_fd(); // FD 1
        let ipc_fd = unsafe { libc::dup(stdout_fd) }; // duplicate FD 1
        assert!(ipc_fd >= 0, "dup(stdout) failed");
        // Redirect FD 1 to stderr (FD 2) so stray prints go to log
        unsafe { libc::dup2(io::stderr().as_raw_fd(), stdout_fd) };
        unsafe { std::fs::File::from_raw_fd(ipc_fd) }
    };
    #[cfg(not(unix))]
    let ipc_stdout = io::stdout();

    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Direct benchmark mode: run benchmarks and print results to stderr (stdout is redirected)
    if std::env::args().any(|a| a == "--benchmark") {
        let prover = sp1_sdk::blocking::ProverClient::builder().cuda().build();
        let results = run_benchmarks(&prover);
        for r in &results {
            eprintln!(
                "{:<16} {:>12} cycles  {:>8.2}s  {:>12.0} c/s  weight={:.2}  precompile={}",
                r.program_name, r.cycles, r.duration_secs, r.throughput, r.weight, r.precompile,
            );
        }
        return;
    }

    if let Err(e) = run_worker_loop(ipc_stdout) {
        tracing::error!("Worker fatal error: {e}");
        std::process::exit(1);
    }
}

fn run_worker_loop(ipc_stdout: impl io::Write) -> Result<()> {
    let mut stdin = BufReader::new(io::stdin().lock());
    let mut stdout = BufWriter::new(ipc_stdout);

    // Lazy-init the CUDA prover on first Prove/Benchmark command, not at startup.
    // CudaProver initialization is expensive (spawns sp1-gpu-server, CUDA context)
    // and would block the handshake response if done before the message loop.
    let mut prover: Option<sp1_sdk::blocking::CudaProver> = None;
    // Cache one proving key per unique ELF. The key depends only on the program, so
    // reusing it across proofs of the same ELF avoids a costly setup() every call AND
    // stops leaking a fresh GPU-resident key per proof (the old code mem::forget'd the
    // key each time). VRAM is now bounded to O(unique ELFs) instead of O(proofs).
    let mut pk_cache: HashMap<u64, CudaPk> = HashMap::new();
    macro_rules! get_prover {
        ($p:expr) => {
            $p.get_or_insert_with(|| {
                tracing::info!("Initializing SP1 CUDA prover...");
                sp1_sdk::blocking::ProverClient::builder().cuda().build()
            })
        };
    }

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
                    backend: BACKEND_SP1.to_string(),
                    sdk_version: format!("sp1-sdk {}", sp1_sdk::SP1_CIRCUIT_VERSION),
                    worker_version: WORKER_VERSION.to_string(),
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Capabilities => {
                let (gpu_available, gpu_name) = detect_gpu();
                let resp = WorkerResponse::CapabilitiesReport {
                    backend: BACKEND_SP1.to_string(),
                    version: sp1_sdk::SP1_CIRCUIT_VERSION.to_string(),
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
                let results = run_benchmarks(get_prover!(prover));
                let resp = WorkerResponse::BenchmarkResult { results };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Prove {
                request_id,
                elf,
                input_data,
                po2: _, // SP1 does not use segment sizing
            } => {
                tracing::info!("Proving request {request_id} ({} bytes ELF)", elf.len());
                // Announce proof START so the miner can move the job from Queued to Proving.
                // Without this the job displays "Queued (waiting for GPU)" for the whole proof.
                let started = WorkerResponse::Progress {
                    request_id,
                    fraction: 0.0,
                    elapsed_secs: 0.0,
                    segments: None,
                };
                write_message(&mut stdout, &started)?;
                match run_proof(get_prover!(prover), &mut pk_cache, &elf, &input_data) {
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
                            // respawns this worker (and its gpu-server) with clean VRAM.
                            ErrorKind::ResourceExhausted
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

            WorkerCommand::Cancel { request_id } => {
                tracing::info!("Cancel requested for {request_id}");
                let resp = WorkerResponse::Cancelled { request_id };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::CalibrateSegmentLimit { request_id, .. } => {
                tracing::warn!("CalibrateSegmentLimit not supported by SP1");
                let resp = WorkerResponse::Error {
                    request_id,
                    kind: ErrorKind::Internal,
                    message: "SP1 does not support segment limit calibration".to_string(),
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Execute { request_id, .. } => {
                // Cycle measurement is implemented for risc0 only: it is the backend whose
                // executor reports the same `total_cycles` the prover does, so the number is
                // directly comparable to what proving will report. Decline explicitly rather
                // than returning a fabricated count — a wrong cycle count would size the
                // deadline check and the look-ahead queue, and silently claiming work we
                // cannot finish loses collateral outright.
                let resp = WorkerResponse::Error {
                    request_id,
                    kind: ErrorKind::InvalidInput,
                    message: "cycle measurement not supported by the sp1 backend".to_string(),
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Shutdown => {
                tracing::info!("Shutdown requested, exiting");
                break;
            }
        }
    }

    // Cleanly release GPU resources before exit. Dropping the CudaProver / proving
    // keys performs async teardown of the sp1-gpu-server, which needs a tokio runtime
    // context — without one the drops panic and the gpu-server is only reaped by the
    // parent's process-group kill (and NOT at all on a clean graceful shutdown, where
    // it would otherwise orphan and leak ~18.6 GB of VRAM). Drop them inside a runtime.
    if prover.is_some() || !pk_cache.is_empty() {
        match tokio::runtime::Runtime::new() {
            Ok(rt) => rt.block_on(async move {
                drop(pk_cache);
                drop(prover);
            }),
            Err(e) => {
                // Couldn't build a runtime — forget rather than panic in Drop; the
                // dispatcher's process-group kill will reap the gpu-server.
                tracing::warn!("No tokio runtime for GPU teardown ({e}); leaking to parent kill");
                std::mem::forget(pk_cache);
                std::mem::forget(prover);
            }
        }
    }

    Ok(())
}

fn detect_gpu() -> (bool, Option<String>) {
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
    (false, None)
}

fn run_proof(
    prover: &sp1_sdk::blocking::CudaProver,
    pk_cache: &mut HashMap<u64, CudaPk>,
    elf: &[u8],
    input_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, f64, u64)> {
    use sp1_sdk::blocking::{Elf, ProveRequest, Prover, SP1Stdin};

    let mut stdin = SP1Stdin::new();
    // NOTE: this pushes the ENTIRE input as ONE SP1 input element (SP1Stdin.buffer
    // is a Vec<Vec<u8>> and the read syscall consumes one element per read). Guests
    // must therefore read the whole blob once (io::read_vec) and parse fields from
    // it — NOT call io::read::<u32>() per field, since the 2nd such read would find
    // no element and halt (empty journal). See guests/sp1/*/src/main.rs.
    stdin.write_slice(input_data);

    // Execute first to get cycle count
    let (_, report) = prover.execute(Elf::from(elf), stdin.clone()).run()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let cycles = report.total_instruction_count();

    // Get-or-create the proving key for this ELF. The key depends only on the
    // program (not the input), so it's cached and reused across proofs — no per-proof
    // setup() and no per-proof GPU-key leak. See `pk_cache` in run_worker_loop.
    let key = elf_hash(elf);
    if !pk_cache.contains_key(&key) {
        let pk = prover.setup(Elf::from(elf)).map_err(|e| anyhow::anyhow!("{e}"))?;
        pk_cache.insert(key, pk);
    }
    let pk = pk_cache.get(&key).expect("pk was just inserted");

    // Generate Groth16 proof for on-chain verification.
    // The SP1 on-chain verifier expects: vkey_hash[0..4] || encoded_groth16_proof
    let start = Instant::now();
    let proof = prover
        .prove(pk, stdin)
        .groth16()
        .run()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let duration_secs = start.elapsed().as_secs_f64();

    // Verify proof locally before returning — catches GPU output corruption.
    if let Err(e) = prover.verify(&proof, pk.verifying_key(), None) {
        return Err(anyhow::anyhow!("Proof verification FAILED — SP1 proof is invalid: {e}"));
    }

    let journal = proof.public_values.to_vec();
    // Use bytes() which produces the on-chain format: vkey_hash[..4] || proof_bytes
    let seal = proof.bytes();

    Ok((journal, seal, duration_secs, cycles))
}

fn run_benchmarks(prover: &sp1_sdk::blocking::CudaProver) -> Vec<BenchmarkEntry> {
    let mut results = Vec::new();

    let benchmarks: &[(&str, &[u8], &[u8], f64, bool)] = &[
        (BENCH_FIBONACCI, FIBONACCI_SP1_GUEST_ELF, &1000u32.to_le_bytes(), 0.10, false),
        (BENCH_SHA256_CHAIN, SHA256_CHAIN_SP1_GUEST_ELF, &50_000u32.to_le_bytes(), 0.20, true),
        (BENCH_ECDSA_VERIFY, ECDSA_VERIFY_SP1_GUEST_ELF, &10u32.to_le_bytes(), 0.25, true),
        (BENCH_BIGINT_MUL, BIGINT_MUL_SP1_GUEST_ELF, &100u32.to_le_bytes(), 0.10, false),
        (BENCH_MEMORY_MERKLE, MEMORY_MERKLE_SP1_GUEST_ELF, &1024u32.to_le_bytes(), 0.15, true),
        (BENCH_CHACHA_MIX, CHACHA_MIX_SP1_GUEST_ELF, &20_000u32.to_le_bytes(), 0.20, false),
    ];

    for &(name, elf, input, weight, precompile) in benchmarks {
        if elf.is_empty() {
            continue;
        }
        if let Some(entry) = benchmark_program(prover, name, elf, input, weight, precompile) {
            results.push(entry);
        }
    }

    results
}

fn benchmark_program(
    prover: &impl sp1_sdk::blocking::Prover,
    name: &str,
    elf: &[u8],
    input: &[u8],
    weight: f64,
    precompile: bool,
) -> Option<BenchmarkEntry> {
    use sp1_sdk::blocking::{Elf, ProveRequest, SP1Stdin};
    // The blocking Prover's `type ProvingKey: ProvingKey` is bound by this trait;
    // it must be in scope for `pk.verifying_key()` on the generic associated type.
    use sp1_sdk::ProvingKey;

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(input);

    // Execute to get real cycle count
    let (_, report) = prover.execute(Elf::from(elf), stdin.clone()).run().ok()?;
    let cycles = report.total_instruction_count();

    let start = Instant::now();
    let pk = prover.setup(Elf::from(elf)).ok()?;
    let proof = match prover.prove(&pk, stdin).run() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("{name}: prove failed: {e}");
            std::mem::forget(pk);
            return None;
        }
    };
    let duration_secs = start.elapsed().as_secs_f64();

    // Verify the proof locally — catches GPU output corruption before polluting
    // the benchmark cache with invalid throughput numbers.
    if let Err(e) = prover.verify(&proof, pk.verifying_key(), None) {
        tracing::error!(
            "{name}: proof verification FAILED — benchmark proof is invalid, skipping entry: {e}"
        );
        std::mem::forget(pk);
        return None;
    }

    // Leak the proving key to avoid drop panic (SP1 CUDA PK drops require tokio runtime context)
    std::mem::forget(pk);

    let throughput = cycles as f64 / duration_secs;

    tracing::info!("{name}: {cycles} cycles in {duration_secs:.2}s ({throughput:.0} c/s, verified)");

    Some(BenchmarkEntry {
        program_name: name.to_string(),
        prover_backend: BACKEND_SP1.to_string(),
        cycles,
        duration_secs,
        throughput,
        weight,
        precompile,
    })
}

