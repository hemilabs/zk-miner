//! The benchmark suite: which programs a GPU is measured on, with what input and weight.
//!
//! The miner owns it. It sends the programs to a worker in `WorkerCommand::Benchmark`, and the
//! worker proves its own build of each named guest with the input given, so changing the suite (a
//! program dropped, an input resized, a weight moved) needs a new miner, not new workers. A program
//! no worker build has yet is the one change that still needs the workers rebuilt.

use crate::types::{
    BenchmarkProgramSpec, BACKEND_SP1, BENCH_BIGINT_MUL, BENCH_CHACHA_MIX, BENCH_ECDSA_VERIFY,
    BENCH_MEMORY_MERKLE, BENCH_SHA256_CHAIN, BENCH_WARMUP, BENCH_ZKOP_MIX,
};

/// A program of the suite.
#[derive(Debug, Clone)]
pub struct BenchmarkProgram {
    pub name: &'static str,
    pub description: &'static str,
    /// Uses zkVM precompile acceleration (SHA-256, ECDSA).
    pub precompile: bool,
    /// Representative cycle count for this workload, for the simulated (CPU) benchmark.
    pub simulated_cycles: u64,
    /// Weight among these programs (all weights sum to 1.0).
    pub weight: f64,
    /// The guest's `u32` input on RISC Zero, and on every zkVM without its own below. Sized so each
    /// proof takes 5-30 s on a mid-range GPU.
    pub input: u32,
    /// The input on SP1, whose guests run the same work in fewer cycles.
    pub sp1_input: u32,
}

/// The 5 canonical benchmark programs, in the order they run.
///
/// Weight distribution:
///   40% pure compute (chacha-mix 0.20, bigint-mul 0.20)
///   45% precompile   (sha256-chain 0.20, ecdsa-verify 0.25)
///   15% mixed        (memory-merkle 0.15)
pub const BENCHMARK_PROGRAMS: [BenchmarkProgram; 5] = [
    BenchmarkProgram {
        name: BENCH_SHA256_CHAIN,
        description: "Sequential SHA-256 hashing (precompile-accelerated)",
        precompile: true,
        simulated_cycles: 2_000_000,
        weight: 0.20,
        input: 10_000,
        sp1_input: 50_000,
    },
    BenchmarkProgram {
        name: BENCH_ECDSA_VERIFY,
        description: "Elliptic curve signature verification (precompile-accelerated)",
        precompile: true,
        simulated_cycles: 5_000_000,
        weight: 0.25,
        input: 10,
        sp1_input: 10,
    },
    BenchmarkProgram {
        name: BENCH_BIGINT_MUL,
        description: "4096-bit integer schoolbook multiplication",
        precompile: false,
        simulated_cycles: 1_000_000,
        weight: 0.20,
        input: 100,
        sp1_input: 100,
    },
    BenchmarkProgram {
        name: BENCH_MEMORY_MERKLE,
        description: "Build 1024-leaf Merkle tree with repeated hashing",
        precompile: true, // Uses sha2 crate which triggers SHA-256 precompile
        simulated_cycles: 3_000_000,
        weight: 0.15,
        input: 512,
        sp1_input: 1024,
    },
    BenchmarkProgram {
        name: BENCH_CHACHA_MIX,
        description: "Pure ARX computation (Add-Rotate-XOR), no precompiles",
        precompile: false,
        simulated_cycles: 34_000_000,
        weight: 0.20,
        input: 5_000,
        sp1_input: 20_000,
    },
];

impl BenchmarkProgram {
    /// This program's input on `backend`.
    pub fn input_for(&self, backend: &str) -> u32 {
        if backend == BACKEND_SP1 {
            self.sp1_input
        } else {
            self.input
        }
    }
}

/// The suite as one `Benchmark` request for a `backend` worker.
///
/// The Groth16 wrap is fixed (one circuit, one key), so one measurement stands for every program.
/// SP1 can only time it by proving a program a second time, so it is asked for on the LAST program,
/// by which point the first proof's GPU warm-up has been paid and cannot land in one of the two runs
/// and not the other. Every other zkVM stages its proof and times the wrap exactly, at no extra
/// proof, so it is asked for on every program.
pub fn benchmark_suite(backend: &str) -> Vec<BenchmarkProgramSpec> {
    let last = BENCHMARK_PROGRAMS.len() - 1;
    BENCHMARK_PROGRAMS
        .iter()
        .enumerate()
        .map(|(i, p)| BenchmarkProgramSpec {
            name: p.name.to_string(),
            input: p.input_for(backend).to_le_bytes().to_vec(),
            weight: p.weight,
            precompile: p.precompile,
            measure_wrap: backend != BACKEND_SP1 || i == last,
        })
        .collect()
}

/// The proof a `backend` worker runs before the suite, whose result is thrown away.
///
/// A worker's first proof pays one-off costs: kernels loaded, memory pools grown, and on RISC Zero
/// the Groth16 prover's first use. Measured on an RTX 5090, RISC Zero's first suite program ran at
/// 3.0M c/s with a 4.7 s wrap, against 5.1M c/s and 0.37 s for every later one. A small fibonacci
/// proof, through the wrap where the suite times it on every program, takes those costs instead.
/// SP1 times its wrap only on the last program, by when that is warm anyway.
pub fn warmup_spec(backend: &str) -> BenchmarkProgramSpec {
    BenchmarkProgramSpec {
        name: BENCH_WARMUP.to_string(),
        input: 1000u32.to_le_bytes().to_vec(),
        weight: 0.0,
        precompile: false,
        measure_wrap: backend != BACKEND_SP1,
    }
}

/// One `zkop-mix` proof at `iterations`, for the zkOP/s score (see `measure_zkop_mix`). It has no
/// weight among the programs and its wrap is not measured.
pub fn zkop_mix_spec(iterations: u32) -> BenchmarkProgramSpec {
    BenchmarkProgramSpec {
        name: BENCH_ZKOP_MIX.to_string(),
        input: iterations.to_le_bytes().to_vec(),
        weight: 0.0,
        precompile: false,
        measure_wrap: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BACKEND_OPENVM, BACKEND_RISC0, ZKOP_MIX_ITERATIONS};

    #[test]
    fn weights_sum_to_one() {
        let sum: f64 = BENCHMARK_PROGRAMS.iter().map(|p| p.weight).sum();
        assert!((sum - 1.0).abs() < 1e-9, "weights sum to {sum}");
    }

    #[test]
    fn each_zkvm_gets_its_own_inputs() {
        let input = |backend: &str, name: &str| {
            let spec = benchmark_suite(backend)
                .into_iter()
                .find(|s| s.name == name)
                .unwrap();
            u32::from_le_bytes(spec.input.try_into().unwrap())
        };
        assert_eq!(input(BACKEND_RISC0, BENCH_SHA256_CHAIN), 10_000);
        assert_eq!(input(BACKEND_SP1, BENCH_SHA256_CHAIN), 50_000);
        assert_eq!(input(BACKEND_OPENVM, BENCH_CHACHA_MIX), 5_000);
        assert_eq!(input(BACKEND_SP1, BENCH_CHACHA_MIX), 20_000);
    }

    #[test]
    fn sp1_times_the_wrap_once_and_on_the_last_program() {
        let sp1 = benchmark_suite(BACKEND_SP1);
        let wrapped: Vec<_> = sp1
            .iter()
            .filter(|s| s.measure_wrap)
            .map(|s| &s.name)
            .collect();
        assert_eq!(wrapped, [BENCH_CHACHA_MIX]);
        assert!(benchmark_suite(BACKEND_RISC0)
            .iter()
            .all(|s| s.measure_wrap));
    }

    #[test]
    fn the_warm_up_is_no_suite_program_and_wraps_where_the_suite_does() {
        assert!(BENCHMARK_PROGRAMS.iter().all(|p| p.name != BENCH_WARMUP));
        assert!(warmup_spec(BACKEND_RISC0).measure_wrap);
        assert!(!warmup_spec(BACKEND_SP1).measure_wrap);
        assert_eq!(warmup_spec(BACKEND_SP1).weight, 0.0);
    }

    #[test]
    fn the_scoring_proof_is_unweighted_and_unwrapped() {
        let spec = zkop_mix_spec(ZKOP_MIX_ITERATIONS);
        assert_eq!(spec.name, BENCH_ZKOP_MIX);
        assert_eq!(spec.input, ZKOP_MIX_ITERATIONS.to_le_bytes());
        assert_eq!(spec.weight, 0.0);
        assert!(!spec.measure_wrap);
    }
}
