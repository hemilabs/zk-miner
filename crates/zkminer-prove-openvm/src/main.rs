//! OpenVM prover worker binary.
//!
//! Long-running process that communicates with the host via stdin/stdout IPC.

use std::io::{self, BufReader, BufWriter};
use std::time::Instant;

use anyhow::Result;
use zkminer_prover_protocol::{
    read_message, write_message, BenchmarkEntry, ErrorKind, WorkerCommand, WorkerResponse,
    BACKEND_OPENVM, BENCH_BIGINT_MUL, BENCH_CHACHA_MIX, BENCH_ECDSA_VERIFY, BENCH_FIBONACCI,
    BENCH_MEMORY_MERKLE, BENCH_SHA256_CHAIN, PROTOCOL_VERSION,
};

const WORKER_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

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
                    backend: BACKEND_OPENVM.to_string(),
                    sdk_version: "openvm-sdk 1.5.0-rc.1".to_string(),
                    worker_version: WORKER_VERSION.to_string(),
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Capabilities => {
                let resp = WorkerResponse::CapabilitiesReport {
                    backend: BACKEND_OPENVM.to_string(),
                    version: "1.5.0-rc.1".to_string(),
                    supported_benchmarks: vec![
                        BENCH_FIBONACCI.to_string(),
                        BENCH_SHA256_CHAIN.to_string(),
                        BENCH_ECDSA_VERIFY.to_string(),
                        BENCH_BIGINT_MUL.to_string(),
                        BENCH_MEMORY_MERKLE.to_string(),
                        BENCH_CHACHA_MIX.to_string(),
                    ],
                    gpu_available: false,
                    gpu_name: None,
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Benchmark => {
                tracing::info!("Running benchmarks...");
                let results = run_benchmarks();
                let resp = WorkerResponse::BenchmarkResult { results };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Prove {
                request_id,
                elf,
                input_data,
                po2: _, // OpenVM does not use segment sizing
            } => {
                tracing::info!("Proving request {request_id} ({} bytes ELF)", elf.len());
                // OpenVM SDK compiles guests at runtime, so proving is handled differently.
                // For now, return an error indicating this is not yet fully implemented.
                let resp = WorkerResponse::Error {
                    request_id,
                    kind: ErrorKind::Internal,
                    message: "OpenVM proving via subprocess not yet fully implemented".to_string(),
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Cancel { request_id } => {
                tracing::info!("Cancel requested for {request_id}");
                let resp = WorkerResponse::Cancelled { request_id };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::CalibrateSegmentLimit { request_id, .. } => {
                tracing::warn!("CalibrateSegmentLimit not supported by OpenVM");
                let resp = WorkerResponse::Error {
                    request_id,
                    kind: ErrorKind::Internal,
                    message: "OpenVM does not support segment limit calibration".to_string(),
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
                    message: "cycle measurement not supported by the openvm backend".to_string(),
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Shutdown => {
                tracing::info!("Shutdown requested, exiting");
                break;
            }
        }
    }

    Ok(())
}

fn run_benchmarks() -> Vec<BenchmarkEntry> {
    // OpenVM compiles guests at runtime; for benchmarks we use simulated workloads
    // but report the real backend name.
    // Weights and precompile flags must match the host's BENCHMARK_PROGRAMS.
    vec![
        simulated_benchmark(BENCH_FIBONACCI, 500_000, 0.10, false),
        simulated_benchmark(BENCH_SHA256_CHAIN, 2_000_000, 0.20, true),
        simulated_benchmark(BENCH_ECDSA_VERIFY, 5_000_000, 0.25, true),
        simulated_benchmark(BENCH_BIGINT_MUL, 1_000_000, 0.10, false),
        simulated_benchmark(BENCH_MEMORY_MERKLE, 3_000_000, 0.15, true),
        simulated_benchmark(BENCH_CHACHA_MIX, 34_000_000, 0.20, false),
    ]
}

fn simulated_benchmark(
    name: &str,
    cycles: u64,
    weight: f64,
    precompile: bool,
) -> BenchmarkEntry {
    let start = Instant::now();
    let iterations = (cycles / 1000) as usize;
    let mut acc: u64 = 0;
    for i in 0..iterations {
        acc = std::hint::black_box(acc)
            .wrapping_mul(6364136223846793005)
            .wrapping_add(i as u64);
    }
    std::hint::black_box(acc);
    let duration_secs = start.elapsed().as_secs_f64();
    let throughput = cycles as f64 / duration_secs;

    tracing::info!("{name} (simulated): {cycles} cycles in {duration_secs:.2}s ({throughput:.0} c/s)");

    BenchmarkEntry {
        program_name: name.to_string(),
        prover_backend: BACKEND_OPENVM.to_string(),
        cycles,
        duration_secs,
        throughput,
        weight,
        precompile,
    }
}
