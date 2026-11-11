//! The Metal worker over its IPC protocol, as the dispatcher drives it: Hello, Capabilities, Warmup
//! (pipelines + one verified Groth16 proof), one Prove, Shutdown. Needs an Apple Silicon Mac and the
//! `risc0-groth16` component (Warmup installs it), so it is ignored by default:
//!
//!   cargo test --release -p zkminer-prove-risc0 --features metal --test metal_worker -- --ignored --nocapture
#![cfg(feature = "metal")]

use std::io::{BufReader, BufWriter, Write};
use std::process::{Command, Stdio};
use std::time::Instant;

use zkminer_prover_protocol::{read_message, write_message, WorkerCommand, WorkerResponse};

#[test]
#[ignore = "proves on the Apple GPU; run with --ignored"]
fn the_metal_worker_warms_up_and_proves_over_ipc() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zkminer-prove-risc0-metal"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the worker");
    let mut to = BufWriter::new(child.stdin.take().unwrap());
    let mut from = BufReader::new(child.stdout.take().unwrap());
    let mut ask = |cmd: &WorkerCommand| -> WorkerResponse {
        write_message(&mut to, cmd).unwrap();
        to.flush().unwrap();
        loop {
            match read_message(&mut from).unwrap() {
                WorkerResponse::Progress { .. } => continue,
                other => return other,
            }
        }
    };

    match ask(&WorkerCommand::Capabilities) {
        WorkerResponse::CapabilitiesReport {
            gpu_available,
            gpu_name,
            ..
        } => {
            assert!(gpu_available);
            assert!(gpu_name.unwrap().starts_with("Apple"));
        }
        other => panic!("unexpected {other:?}"),
    }

    let t = Instant::now();
    match ask(&WorkerCommand::Warmup { request_id: 1 }) {
        WorkerResponse::WarmupDone { summary, .. } => {
            eprintln!("warm-up ({:.1} s): {summary}", t.elapsed().as_secs_f64());
            assert!(summary.contains("built the Metal pipelines"), "{summary}");
            assert!(summary.contains("verified a Groth16 proof"), "{summary}");
        }
        other => panic!("unexpected {other:?}"),
    }

    let dir = tempfile::tempdir().unwrap();
    let guest = dir.path().join("fibonacci.elf");
    let out = Command::new(env!("CARGO_BIN_EXE_zkminer-prove-risc0-metal"))
        .arg("--export-guest")
        .arg("fibonacci")
        .arg(&guest)
        .output()
        .unwrap();
    assert!(out.status.success());
    let t = Instant::now();
    match ask(&WorkerCommand::Prove {
        request_id: 2,
        elf: std::fs::read(&guest).unwrap(),
        input_data: 1000u32.to_le_bytes().to_vec(),
        po2: None,
        program_id: None,
    }) {
        WorkerResponse::ProofResult { seal, cycles, .. } => {
            eprintln!(
                "proof: {cycles} cycles, {} seal bytes, {:.1} s",
                seal.len(),
                t.elapsed().as_secs_f64()
            );
            assert!(!seal.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }

    write_message(&mut to, &WorkerCommand::Shutdown).unwrap();
    to.flush().unwrap();
    assert!(child.wait().unwrap().success());
}
