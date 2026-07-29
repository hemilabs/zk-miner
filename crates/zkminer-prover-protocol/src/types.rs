use serde::{Deserialize, Serialize};

/// Protocol version for the worker IPC wire format.
pub const PROTOCOL_VERSION: u32 = 3;

/// Maximum frame size: 256 MB (accommodates large risc0 composite receipts).
pub const MAX_FRAME_SIZE: u32 = 256 * 1024 * 1024;

// Canonical backend names — workers MUST use these exact strings.
pub const BACKEND_RISC0: &str = "risc0";
pub const BACKEND_SP1: &str = "sp1";
pub const BACKEND_OPENVM: &str = "openvm";

// Canonical benchmark program names — must match BENCHMARK_PROGRAMS in benchmark.rs.
pub const BENCH_FIBONACCI: &str = "fibonacci";
pub const BENCH_SHA256_CHAIN: &str = "sha256-chain";
pub const BENCH_ECDSA_VERIFY: &str = "ecdsa-verify";
pub const BENCH_BIGINT_MUL: &str = "bigint-mul";
pub const BENCH_MEMORY_MERKLE: &str = "memory-merkle";
pub const BENCH_CHACHA_MIX: &str = "chacha-mix";

/// Commands sent from host to worker via stdin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkerCommand {
    /// Initial handshake. Worker must respond with HelloAck.
    Hello { protocol_version: u32 },
    /// Request worker capabilities.
    Capabilities,
    /// Run the full benchmark suite. Worker runs all programs it supports.
    Benchmark,
    /// Generate a proof for the given ELF and input data.
    Prove {
        request_id: u64,
        elf: Vec<u8>,
        input_data: Vec<u8>,
        /// Segment limit as log2 of rows. None = use SDK default.
        /// Only meaningful for risc0; other backends accept but ignore.
        po2: Option<u8>,
    },
    /// Cancel an in-flight proof. Worker should abort and send Cancelled or Error.
    Cancel { request_id: u64 },
    /// Graceful shutdown. Worker should exit after sending no further responses.
    Shutdown,
    /// Run a po2 calibration proof. The worker uses its built-in calibration
    /// program (chacha-mix with small input) at the specified segment limit
    /// and reports segment count + timing.
    CalibrateSegmentLimit {
        request_id: u64,
        po2: u8,
    },
}

/// Responses sent from worker to host via stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkerResponse {
    /// Response to Hello.
    HelloAck {
        protocol_version: u32,
        backend: String,
        /// SDK version string, e.g. "risc0-zkvm 3.0.5"
        sdk_version: String,
        /// Worker binary version from Cargo.toml
        worker_version: String,
    },
    /// Response to Capabilities.
    CapabilitiesReport {
        backend: String,
        version: String,
        supported_benchmarks: Vec<String>,
        gpu_available: bool,
        gpu_name: Option<String>,
    },
    /// Response to Benchmark.
    BenchmarkResult {
        results: Vec<BenchmarkEntry>,
    },
    /// Progressive benchmark result: sent after each program completes.
    /// Worker sends one of these per program, then a final BenchmarkResult.
    BenchmarkProgress {
        entry: BenchmarkEntry,
        /// 1-based index of this program in the suite.
        program_index: u32,
        /// Total number of programs in the suite.
        total_programs: u32,
    },
    /// Successful proof result.
    ProofResult {
        request_id: u64,
        journal: Vec<u8>,
        seal: Vec<u8>,
        /// Proving duration in seconds (f64 to avoid Duration serialization issues).
        duration_secs: f64,
        cycles: u64,
    },
    /// Progress update during proving.
    Progress {
        request_id: u64,
        /// Fraction complete (0.0 to 1.0).
        fraction: f64,
        elapsed_secs: f64,
        /// (completed_segments, total_segments) if known.
        segments: Option<(u32, u32)>,
    },
    /// Acknowledgement of a Cancel command.
    Cancelled { request_id: u64 },
    /// Error during proving or other operation.
    Error {
        request_id: u64,
        kind: ErrorKind,
        message: String,
    },
    /// Result of a CalibrateSegmentLimit run.
    CalibrationResult {
        request_id: u64,
        po2: u8,
        segment_count: u32,
        total_cycles: u64,
        prove_duration_secs: f64,
    },
}

/// Classification of worker errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorKind {
    /// Proof generation failed (e.g. guest panicked).
    ProofFailed,
    /// Invalid input data or ELF.
    InvalidInput,
    /// Ran out of memory or other system resources.
    ResourceExhausted,
    /// Protocol violation (unexpected message, version mismatch).
    ProtocolError,
    /// Catch-all for internal errors.
    Internal,
}

/// True if a worker error message indicates a GPU out-of-memory / device
/// allocation failure (CUDA or HIP/ROCm). Workers use this to tag such errors as
/// [`ErrorKind::ResourceExhausted`] so the dispatcher kills + respawns the worker
/// with a clean GPU context instead of reusing a wedged one. Match is
/// case-insensitive and covers the phrasings seen from the risc0/sp1 GPU stacks
/// (e.g. "witness generation failure: std::bad_alloc: cudaErrorMemoryAllocation:
/// out of memory").
pub fn is_gpu_oom(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("out of memory")
        || m.contains("bad_alloc")
        || m.contains("cudaerrormemoryallocation")
        || m.contains("cuda_error_out_of_memory")
        || m.contains("hiperroroutofmemory")
        || m.contains("hip_error_out_of_memory")
        || m.contains("cudamalloc")
        || m.contains("hsa_status_error_out_of_resources")
}

/// A single benchmark measurement from a worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkEntry {
    /// Must be one of the BENCH_* constants.
    pub program_name: String,
    /// Must be one of the BACKEND_* constants.
    pub prover_backend: String,
    pub cycles: u64,
    /// Duration in seconds (f64 to avoid Duration serialization issues).
    pub duration_secs: f64,
    /// Cycles per second throughput.
    pub throughput: f64,
    /// Weight in the zkOP/s blend.
    pub weight: f64,
    /// Whether this program uses zkVM precompile acceleration.
    pub precompile: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_oom_classification() {
        // Real strings observed from the risc0/sp1 CUDA+HIP stacks.
        assert!(is_gpu_oom(
            "witness generation failure: std::bad_alloc: cudaErrorMemoryAllocation: out of memory"
        ));
        assert!(is_gpu_oom("CUDA_ERROR_OUT_OF_MEMORY"));
        assert!(is_gpu_oom("hipErrorOutOfMemory"));
        assert!(is_gpu_oom("cudaMalloc failed"));
        // Non-OOM proof failures must NOT be misclassified as ResourceExhausted.
        assert!(!is_gpu_oom("Proof verification FAILED — SP1 proof is invalid"));
        assert!(!is_gpu_oom("guest panicked at 'index out of bounds'"));
        assert!(!is_gpu_oom("po2 value 25 out of valid range 13..=24"));
    }

    #[test]
    fn command_round_trip() {
        let cmd = WorkerCommand::Prove {
            request_id: 42,
            elf: vec![1, 2, 3],
            input_data: vec![4, 5, 6],
            po2: Some(20),
        };
        let bytes = bincode::serialize(&cmd).unwrap();
        let decoded: WorkerCommand = bincode::deserialize(&bytes).unwrap();
        match decoded {
            WorkerCommand::Prove {
                request_id,
                elf,
                input_data,
                po2,
            } => {
                assert_eq!(request_id, 42);
                assert_eq!(elf, vec![1, 2, 3]);
                assert_eq!(input_data, vec![4, 5, 6]);
                assert_eq!(po2, Some(20));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn response_round_trip() {
        let resp = WorkerResponse::ProofResult {
            request_id: 1,
            journal: vec![0xAB],
            seal: vec![0xCD],
            duration_secs: 12.5,
            cycles: 1_000_000,
        };
        let bytes = bincode::serialize(&resp).unwrap();
        let decoded: WorkerResponse = bincode::deserialize(&bytes).unwrap();
        match decoded {
            WorkerResponse::ProofResult {
                request_id,
                duration_secs,
                cycles,
                ..
            } => {
                assert_eq!(request_id, 1);
                assert!((duration_secs - 12.5).abs() < f64::EPSILON);
                assert_eq!(cycles, 1_000_000);
            }
            _ => panic!("wrong variant"),
        }
    }
}
