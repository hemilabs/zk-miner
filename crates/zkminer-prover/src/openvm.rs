//! OpenVM prover backend.

use crate::benchmark::BenchmarkResult;
use crate::engine::{ProofOutput, ProvingEngine};
use anyhow::Result;
use std::time::Instant;

/// OpenVM proving engine.
pub struct OpenVmProver;

impl ProvingEngine for OpenVmProver {
    fn prove(&self, elf: &[u8], input_data: &[u8], _po2: Option<u8>) -> Result<ProofOutput> {
        let start = Instant::now();

        let sdk = openvm_sdk::Sdk::new();
        let elf_data = openvm_sdk::fs::ElfData::from_bytes(elf.to_vec());
        let stdin = openvm_sdk::StdIn::from_bytes(input_data);

        let proof = sdk
            .prove(&elf_data, stdin)
            .map_err(|e| anyhow::anyhow!("OpenVM proving failed: {e}"))?;

        let duration = start.elapsed();

        Ok(ProofOutput {
            journal: proof.public_values().to_vec(),
            seal: bincode::serialize(&proof)
                .map_err(|e| anyhow::anyhow!("Failed to serialize proof: {e}"))?,
            duration,
            cycles: proof.cycles(),
        })
    }
}

/// Run a fibonacci benchmark using the real OpenVM prover.
///
/// Note: OpenVM guest compilation is handled externally. The ELF must be
/// pre-compiled and provided. For benchmarks, we compile it on the fly
/// using the SDK.
pub fn benchmark_fibonacci(n: u32) -> BenchmarkResult {
    tracing::info!("OpenVM benchmark: fibonacci({n})");
    let start = Instant::now();

    let sdk = openvm_sdk::Sdk::new();

    // Build the guest program from source
    let guest_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("guests/openvm/fibonacci");

    let elf = sdk
        .build(openvm_sdk::fs::BuildArgs::new(guest_dir))
        .expect("OpenVM guest build failed");

    let stdin = openvm_sdk::StdIn::from_bytes(&n.to_le_bytes());
    let proof = sdk
        .prove(&elf, stdin)
        .expect("OpenVM fibonacci proving failed");

    let duration = start.elapsed();
    let cycles = proof.cycles();
    let throughput = cycles as f64 / duration.as_secs_f64();

    tracing::info!(
        "  openvm fibonacci({n}): {cycles} cycles in {duration:?} ({throughput:.0} c/s)"
    );

    BenchmarkResult {
        program_name: format!("fibonacci({n})"),
        prover_backend: "openvm".to_string(),
        cycles,
        duration,
        throughput,
        weight: 0.0,
        precompile: false,
    }
}
