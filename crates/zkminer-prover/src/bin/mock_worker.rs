//! Mock worker binary for integration tests.
//!
//! Speaks the worker IPC protocol (Hello/HelloAck handshake, Benchmark, Prove,
//! CalibrateSegmentLimit)
//! and can be configured via environment variables:
//!
//! - `MOCK_HANG_ON`: `"benchmark"`, `"prove"`, or `"both"` — hangs (sleeps forever)
//!   on the specified command type. Unset or empty = respond normally.
//! - `MOCK_CRASH_ON`: `"benchmark"`, `"prove"`, or `"both"` — exits immediately
//!   with code 1 on the specified command type, simulating a worker crash.
//! - `MOCK_BACKEND`: backend name for the HelloAck response. Default: `"mock"`.

use std::io::{self, BufReader, BufWriter};
use std::time::Duration;

use zkminer_prover_protocol::{
    read_message, write_message, FrameError, WorkerCommand, WorkerResponse, PROTOCOL_VERSION,
};

fn main() {
    let hang_on = std::env::var("MOCK_HANG_ON").unwrap_or_default();
    let crash_on = std::env::var("MOCK_CRASH_ON").unwrap_or_default();
    let backend = std::env::var("MOCK_BACKEND").unwrap_or_else(|_| "mock".to_string());

    let mut stdin = BufReader::new(io::stdin().lock());
    let mut stdout = BufWriter::new(io::stdout().lock());

    loop {
        let cmd: WorkerCommand = match read_message(&mut stdin) {
            Ok(cmd) => cmd,
            Err(FrameError::UnexpectedEof) => break,
            Err(_) => break,
        };

        match cmd {
            WorkerCommand::Hello { protocol_version: _ } => {
                let resp = WorkerResponse::HelloAck {
                    protocol_version: PROTOCOL_VERSION,
                    backend: backend.clone(),
                    sdk_version: "mock 0.1.0".to_string(),
                    worker_version: "0.1.0".to_string(),
                };
                write_message(&mut stdout, &resp).unwrap();
            }

            WorkerCommand::Capabilities => {
                let resp = WorkerResponse::CapabilitiesReport {
                    backend: backend.clone(),
                    version: "0.1.0".to_string(),
                    supported_benchmarks: vec![],
                    gpu_available: false,
                    gpu_name: None,
                };
                write_message(&mut stdout, &resp).unwrap();
            }

            WorkerCommand::Benchmark => {
                if crash_on == "benchmark" || crash_on == "both" {
                    std::process::exit(1);
                }
                if hang_on == "benchmark" || hang_on == "both" {
                    // Hang forever — the watchdog will SIGKILL us
                    loop {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
                let resp = WorkerResponse::BenchmarkResult { results: vec![] };
                write_message(&mut stdout, &resp).unwrap();
            }

            WorkerCommand::Prove {
                request_id,
                elf: _,
                input_data: _,
                po2: _,
            } => {
                if crash_on == "prove" || crash_on == "both" {
                    std::process::exit(1);
                }
                if hang_on == "prove" || hang_on == "both" {
                    loop {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
                let resp = WorkerResponse::ProofResult {
                    request_id,
                    journal: vec![],
                    seal: vec![],
                    duration_secs: 0.01,
                    cycles: 1000,
                };
                write_message(&mut stdout, &resp).unwrap();
            }

            WorkerCommand::Cancel { request_id } => {
                let resp = WorkerResponse::Cancelled { request_id };
                write_message(&mut stdout, &resp).unwrap();
            }

            WorkerCommand::CalibrateSegmentLimit { request_id, po2 } => {
                let resp = WorkerResponse::CalibrationResult {
                    request_id,
                    po2,
                    segment_count: 1,
                    total_cycles: 1000,
                    prove_duration_secs: 0.01,
                };
                write_message(&mut stdout, &resp).unwrap();
            }

            WorkerCommand::Shutdown => break,
        }
    }
}
