//! SP1 prover backend.

use crate::benchmark::BenchmarkResult;
use crate::engine::{ProofOutput, ProvingEngine};
use anyhow::Result;
use sp1_sdk::blocking::Prover;
use std::time::Instant;

/// The compiled SP1 fibonacci ELF (built by sp1-build in build.rs).
pub const FIBONACCI_ELF: sp1_sdk::Elf = sp1_sdk::include_elf!("fibonacci-sp1-guest");

/// The compiled SP1 sha256-chain ELF (built by sp1-build in build.rs).
pub const SHA256_CHAIN_ELF: sp1_sdk::Elf = sp1_sdk::include_elf!("sha256-chain-sp1-guest");

/// SP1 proving engine using the blocking CPU prover.
pub struct Sp1Prover {
    client: sp1_sdk::blocking::CpuProver,
}

impl Sp1Prover {
    pub fn new() -> Self {
        Self {
            client: sp1_sdk::blocking::CpuProver::new(),
        }
    }
}

impl ProvingEngine for Sp1Prover {
    fn prove(&self, elf: &[u8], input_data: &[u8], _po2: Option<u8>) -> Result<ProofOutput> {
        use sp1_sdk::blocking::ProveRequest;

        let start = Instant::now();

        let elf: sp1_sdk::Elf = elf.into();
        let mut stdin = sp1_sdk::SP1Stdin::new();
        stdin.write_slice(input_data);

        let pk = self
            .client
            .setup(elf)
            .map_err(|e| anyhow::anyhow!("SP1 setup failed: {e}"))?;
        // Use Groth16 mode for on-chain verifiable proofs.
        let proof = self
            .client
            .prove(&pk, stdin)
            .groth16()
            .run()
            .map_err(|e| anyhow::anyhow!("SP1 proving failed: {e}"))?;

        let duration = start.elapsed();

        Ok(ProofOutput {
            journal: proof.public_values.to_vec(),
            // bytes() returns the on-chain format: vkey_hash[..4] || encoded_proof
            seal: proof.bytes(),
            duration,
            cycles: 0,
        })
    }
}

/// Run a sha256-chain benchmark using the real SP1 prover.
pub fn benchmark_sha256_chain(n: u32) -> BenchmarkResult {
    use sp1_sdk::blocking::ProveRequest;

    tracing::info!("SP1 benchmark: sha256-chain({n})");

    let client = sp1_sdk::blocking::CpuProver::new();

    let mut stdin = sp1_sdk::SP1Stdin::new();
    stdin.write(&n);

    // Execute to get cycle count
    let (_pv, report) = client
        .execute(SHA256_CHAIN_ELF.clone(), stdin.clone())
        .run()
        .expect("SP1 sha256-chain execution failed");
    let cycles = report.total_instruction_count();

    // Prove to measure total time
    let start = Instant::now();
    let pk = client
        .setup(SHA256_CHAIN_ELF.clone())
        .expect("SP1 setup failed");
    let _proof = client
        .prove(&pk, stdin)
        .run()
        .expect("SP1 sha256-chain proving failed");
    let duration = start.elapsed();

    let throughput = cycles as f64 / duration.as_secs_f64();

    tracing::info!(
        "  sp1 sha256-chain({n}): {cycles} cycles in {duration:?} ({throughput:.0} c/s)"
    );

    BenchmarkResult {
        program_name: format!("sha256-chain({n})"),
        prover_backend: "sp1".to_string(),
        cycles,
        duration,
        throughput,
        weight: 0.0,
        precompile: true,
    }
}

/// Run a fibonacci benchmark using the real SP1 prover.
pub fn benchmark_fibonacci(n: u32) -> BenchmarkResult {
    use sp1_sdk::blocking::ProveRequest;

    tracing::info!("SP1 benchmark: fibonacci({n})");

    let client = sp1_sdk::blocking::CpuProver::new();

    let mut stdin = sp1_sdk::SP1Stdin::new();
    stdin.write(&n);

    // Execute to get cycle count
    let (_pv, report) = client
        .execute(FIBONACCI_ELF.clone(), stdin.clone())
        .run()
        .expect("SP1 fibonacci execution failed");
    let cycles = report.total_instruction_count();

    // Prove to measure total time
    let start = Instant::now();
    let pk = client
        .setup(FIBONACCI_ELF.clone())
        .expect("SP1 setup failed");
    let _proof = client
        .prove(&pk, stdin)
        .run()
        .expect("SP1 fibonacci proving failed");
    let duration = start.elapsed();

    let throughput = cycles as f64 / duration.as_secs_f64();

    tracing::info!("  sp1 fibonacci({n}): {cycles} cycles in {duration:?} ({throughput:.0} c/s)");

    BenchmarkResult {
        program_name: format!("fibonacci({n})"),
        prover_backend: "sp1".to_string(),
        cycles,
        duration,
        throughput,
        weight: 0.0,
        precompile: false,
    }
}
