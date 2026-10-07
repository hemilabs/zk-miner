use serde::{Deserialize, Serialize};

/// Protocol version for the worker IPC wire format.
///
/// 4: `BenchmarkEntry` gained `wrap_secs`. The codec is bincode, which is POSITIONAL — an extra field
/// cannot be defaulted, so a v3 worker's entries do not decode as v4 and would fail mid-benchmark.
/// Bumping the version makes `handshake` reject a stale worker at spawn with a clear message instead.
pub const PROTOCOL_VERSION: u32 = 4;

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
    /// EXECUTE the guest without proving, to measure its true cycle count.
    ///
    /// Every scheduling decision in the miner — deadline feasibility, the look-ahead queue,
    /// the proving timeout — is sized from `expectedCycles` on the job descriptor, which is
    /// SUBMITTER-DECLARED and, on the observed market, always zero (298/298 jobs), leaving a
    /// hardcoded 34e6 fallback that is ~8x too small against a 123s median. Executing is the
    /// only way to learn the real number before committing collateral, and it costs execution
    /// time rather than proving time — orders of magnitude cheaper than the proof it sizes.
    Execute {
        request_id: u64,
        elf: Vec<u8>,
        input_data: Vec<u8>,
    },
    /// Cancel an in-flight proof. Worker should abort and send Cancelled or Error.
    Cancel { request_id: u64 },
    /// Graceful shutdown. Worker should exit after sending no further responses.
    Shutdown,
    /// Run a po2 calibration proof. The worker uses its built-in calibration
    /// program (chacha-mix with small input) at the specified segment limit
    /// and reports segment count + timing.
    CalibrateSegmentLimit { request_id: u64, po2: u8 },
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
    BenchmarkResult { results: Vec<BenchmarkEntry> },
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
    /// Result of an `Execute`: the guest's true cycle count, with no proof produced.
    ExecuteResult {
        request_id: u64,
        /// Total cycles reported by the executor — the same quantity `ProofResult.cycles`
        /// carries, obtained without proving.
        cycles: u64,
        /// How long the execution itself took, so the caller can bound future ones.
        duration_secs: f64,
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
/// Bytes of HOST memory a worker is allowed to use, as the dispatcher sees it.
///
/// A worker cannot work this out for itself: the ceiling is the host's RAM minus the slice reserved
/// for everything else, and only the dispatcher knows the latter. Passed so a backend that can scale
/// its own memory appetite has something to scale against. See `SP1_VRAM_BYTES_ENV` for the device
/// side of the same idea.
pub const HOST_MEM_BUDGET_ENV: &str = "ZKMINER_HOST_MEM_BUDGET_BYTES";

/// Total VRAM of the card a worker has been assigned, in bytes.
///
/// Also not something the worker can discover reliably: `nvidia-smi` ignores `CUDA_VISIBLE_DEVICES`,
/// so a worker querying "my card" would get every card's figure. The dispatcher already holds the
/// per-slot number it uses for VRAM-based routing, so it is the authority.
pub const CUDA_VRAM_BYTES_ENV: &str = "ZKMINER_CUDA_VRAM_BYTES";

/// VRAM on this worker's card that was FREE TO US when the worker was spawned, in bytes.
///
/// Separate from [`CUDA_VRAM_BYTES_ENV`], which carries the card's capacity, because a backend that
/// sizes itself from capacity on a card it does not have to itself will commit to more memory than
/// exists. SP1 does exactly that — its `local_gpu_opts` reads `cuda_memory_info().1`, the total,
/// discarding the free figure returned alongside it — so the dispatcher measures what is free and
/// hands it over, and the worker sizes against this instead.
///
/// Absent means "unknown"; a worker must then fall back to the capacity figure, which is the
/// behaviour that predates this variable.
pub const CUDA_VRAM_AVAILABLE_BYTES_ENV: &str = "ZKMINER_CUDA_VRAM_AVAILABLE_BYTES";

/// MiB, as `nvidia-smi` reports it.
const MIB: u64 = 1024 * 1024;

/// Measured `(element threshold, peak VRAM)` for SP1, largest first.
///
/// Both figures measured on this box on 2026-10-05 with a 1,912,954,963-cycle `sha256-chain` proof
/// through to a compact Groth16 seal: 17,766 MiB of a 24,564 MiB RTX 4090 at the 268M threshold, and
/// 15,092 MiB of a 16,303 MiB RTX 5080 at 134M.
///
/// `402_653_184` — the fork's own default — is deliberately ABSENT. Nothing here has measured its peak
/// VRAM, and this table is used to decide what will fit. Its omission makes a roomy card slightly
/// conservative (it is capped to 268M rather than left at 402M) and never unsafe, which is the same
/// trade the worker's `sp1_element_threshold_for` already makes for host memory: only ever a value
/// measured to complete a proof.
const SP1_MEASURED_TIERS: &[(u64, u64)] =
    &[(268_435_456, 17_766 * MIB), (134_217_728, 15_092 * MIB)];

/// Headroom required on top of a measured peak before that configuration is considered to fit.
///
/// A CUDA context alone costs ~400 MiB here (measured: a process allocating 2,048 MiB showed as 2,444
/// MiB), and the peaks above come from one program — another workload of the same shard shape can sit
/// a little above them.
const SP1_VRAM_MARGIN: u64 = 512 * MIB;

/// The SP1 shard element threshold for a card with `available` bytes of VRAM free to us, or `None`
/// when that is below what even the smallest measured configuration needs.
///
/// Why not SP1's own tier arithmetic, which is what this first did: `local_gpu_opts` computes
/// `gpu_memory_gb = ceil(total / 1 GiB) + 4` and takes the larger tier above 20. That formula carries
/// 4 GiB of implicit slack that only holds for a card whose capacity it is given. Fed an AVAILABLE
/// figure it selects the 268M tier from 16.4 GiB upward, while that tier's measured peak is 17.4 GiB —
/// so between roughly 16.4 and 17.8 GiB free it would choose a configuration that does not fit and
/// fail part-way through a claimed job. The same latent gap exists in the fork for a real 17 GiB card;
/// it has never shown because the cards that exist are 16 and 24.
///
/// So: pick the largest configuration whose MEASURED peak fits, with margin. The result is only ever
/// used to LOWER the threshold, via `SP1_GPU_ELEMENT_THRESHOLD`, which the fork treats as a cap on its
/// own tier choice. That direction matters for soundness as well as memory: the shape allow-list is
/// enumerated against the compile-time `PADDED_ELEMENT_THRESHOLD`, so a threshold below the constant
/// yields shapes the circuit already accepts while one above it does not.
pub fn sp1_element_threshold_for_available_vram(available: u64) -> Option<u64> {
    SP1_MEASURED_TIERS
        .iter()
        .find(|(_, peak)| peak.saturating_add(SP1_VRAM_MARGIN) <= available)
        .map(|(threshold, _)| *threshold)
}

/// How much VRAM must be free before SP1 can be given work at all: what its smallest measured
/// configuration needs, plus margin.
///
/// Derived from [`SP1_MEASURED_TIERS`] rather than written down separately, so this and
/// [`sp1_element_threshold_for_available_vram`] cannot disagree about whether a card is usable. Two
/// independent constants did disagree in the first draft — the floor admitted a card by ~350 MiB that
/// the tier function then had no configuration for, which would have refused the work one layer later
/// after the worker was already spawned.
pub fn sp1_min_available_vram_bytes() -> u64 {
    SP1_MEASURED_TIERS
        .last()
        .map(|(_, peak)| peak.saturating_add(SP1_VRAM_MARGIN))
        .unwrap_or(u64::MAX)
}

/// Environment variable naming the CUDA device a worker should drive.
///
/// A CONTRACT between the dispatcher and a worker that must not be given `CUDA_VISIBLE_DEVICES`,
/// which is why it lives here rather than on either side of it.
///
/// SP1 is the case. Its SDK sets `CUDA_VISIBLE_DEVICES` on the `sp1-gpu-server` child ITSELF, from
/// the id passed to `CudaProver::new_with_id`, and reaches that child over a per-device socket
/// `/tmp/sp1-cuda-<id>.sock`. `Command::env` overrides, and the id never comes from the worker's
/// environment — so setting `CUDA_VISIBLE_DEVICES` on the worker cannot reach the server and cannot
/// choose its card. The only thing that selects a device is the id handed to the SDK, and the only way
/// to get it there is to tell the worker.
///
/// It also has to be DISTINCT per worker. Two SP1 workers that both default to device 0 both start a
/// server for device 0, and the second unlinks and rebinds the shared socket — so both clients end up
/// on one server, on one card, double-booking its VRAM. That, not the pin, is what killed the earlier
/// attempt at per-card SP1 slots.
///
/// Absent means "let the SDK choose", which is device 0.
pub const CUDA_DEVICE_ID_ENV: &str = "ZKMINER_CUDA_DEVICE_ID";

/// Marker in a spawn error meaning the worker SPOKE the protocol and deliberately
/// DECLINED: it can run, but it cannot prove on this host (e.g. an SP1 worker whose
/// `sp1-gpu-server` needs a CUDA runtime the host lacks).
///
/// This is categorically different from a transient spawn failure. A dead-but-eligible
/// slot is intentionally still "healthy" so a crashed worker respawns and claiming does
/// not stall -- but a decline will never succeed on retry, so advertising the backend
/// makes the miner claim jobs it must then release at a penalty. Callers match on this
/// to tell the two apart.
pub const WORKER_DECLINED: &str = "worker declined: cannot prove on this host";
/// The host has too little RAM free to start this proof right now.
///
/// A TYPED error, not a string marker. It used to be a `&str` embedded in an `anyhow` message and
/// matched with `contains`, which was wrong in both directions. The message the retry loop
/// classifies also carries a worker's `WorkerResponse::Error` text verbatim, and that text can come
/// from the guest ELF named by an on-chain job — so any submitter could have put this literal in a
/// guest panic and bought their job unbounded free retries. Conversely a `.context()` added anywhere
/// in the chain could have hidden it. A type cannot be forged by a message and cannot be lost by
/// wrapping: `anyhow::Error::downcast_ref` either finds it or it does not.
///
/// Callers must not treat this as worker ill-health. Doing so excluded a perfectly healthy slot,
/// burned every retry attempt inside a millisecond — the ledger is process-wide, so "retry on a
/// different GPU" fails identically — and then released the job at the penalty floor, which is
/// precisely the loss the memory gate exists to prevent. Wait for the host instead.
#[derive(Debug, Clone)]
pub struct HostMemoryShortage {
    /// Did a proof actually RUN before this was reported?
    ///
    /// `false` for an admission refusal, which costs a `/proc/meminfo` read: nothing was attempted,
    /// so the caller may wait and retry without spending an attempt.
    ///
    /// `true` for a worker OOM-killed mid-proof, where minutes of real work were done and then lost.
    /// Routing both through the "nothing was attempted" arm let a box that is simply too small run
    /// full proof attempts back to back until the lock deadline expired — `MAX_PROVE_ATTEMPTS`
    /// bypassed, the slot never excluded, the backend never retired, the concurrency slot held
    /// throughout — where before it failed three times and moved on.
    pub attempted: bool,
    /// Which slot was refused, e.g. `risc0:cuda:0`.
    pub slot_key: String,
    /// Bytes the proof was expected to need.
    pub needed: u64,
    /// Bytes already reserved by proofs in flight.
    pub reserved: u64,
    /// `MemAvailable` at the moment of the refusal.
    pub available: u64,
}

impl std::fmt::Display for HostMemoryShortage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
        write!(
            f,
            "host RAM is short for {}: needs ~{:.1} GiB, {:.1} GiB already reserved by proofs in \
             flight, {:.1} GiB available",
            self.slot_key,
            self.needed as f64 / GIB,
            self.reserved as f64 / GIB,
            self.available as f64 / GIB,
        )
    }
}

impl std::error::Error for HostMemoryShortage {}

/// Not enough of this card's VRAM is free for this backend to be given work on it.
///
/// Distinct from `HostMemoryShortage` (that is system RAM) and from a GPU OOM (that is the proof
/// having already failed). This one is an ADMISSION refusal: nothing ran, so it costs no attempt,
/// and the condition is usually transient — a desktop session, a browser with hardware acceleration,
/// someone else's CUDA job — so the honest response is to try the other card and then wait.
///
/// Typed for the same reason as `HostMemoryShortage`: the caller must not mistake it for worker
/// ill-health, and `msg` embeds worker text that can originate in a submitter's guest ELF, so any
/// substring test would let a job buy itself free retries.
#[derive(Debug, Clone)]
pub struct GpuMemoryShortage {
    /// Which slot was refused, e.g. `sp1:cuda:0`.
    pub slot_key: String,
    /// VRAM held on that card by processes that are not ours, in bytes.
    pub foreign_bytes: u64,
    /// `total - foreign`: what was actually free to us, in bytes.
    pub available_bytes: u64,
    /// What this backend needs free before it may be given work, in bytes.
    pub needed_bytes: u64,
    /// Total VRAM of the card, in bytes, for the operator's benefit in the log line.
    pub total_bytes: u64,
}

impl std::fmt::Display for GpuMemoryShortage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const MIB: f64 = 1024.0 * 1024.0;
        write!(
            f,
            "{} has only {:.0} MiB of its {:.0} MiB VRAM free -- {:.0} MiB is held by another \
             process -- and {} needs {:.0} MiB. It sizes its proof from the card's TOTAL VRAM, so \
             it would commit to more than is free and fail part-way. Close whatever is using the \
             card, or drive the display from another GPU.",
            self.slot_key,
            self.available_bytes as f64 / MIB,
            self.total_bytes as f64 / MIB,
            self.foreign_bytes as f64 / MIB,
            self.slot_key.split(':').next().unwrap_or("this backend"),
            self.needed_bytes as f64 / MIB,
        )
    }
}

impl std::error::Error for GpuMemoryShortage {}

/// The job's own deadline ran out: no retry on any GPU can beat it.
///
/// Typed for the same reason as `HostMemoryShortage`, and here the stakes are higher. The caller
/// treats this class as TERMINAL — zero retries, release immediately — and it used to be recognised
/// by `msg.contains("deadline cutoff") || msg.contains("job deadline reached")` against a string that
/// embeds a worker's `WorkerResponse::Error` text verbatim. That text can originate in the guest ELF
/// of a submitter's job, so a guest that panicked with the right words made its own provable job
/// terminal on the first attempt and collected the release penalty. The substring test was already a
/// tightening of a bare `contains("deadline")`; a type ends the class of bug.
#[derive(Debug, Clone)]
pub struct ProofDeadlineReached {
    /// Human-readable detail: which slot, how much budget was left, and at which stage.
    pub detail: String,
}

impl std::fmt::Display for ProofDeadlineReached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail)
    }
}

impl std::error::Error for ProofDeadlineReached {}

/// A proof failed and the WORKER said why, in its own `ErrorKind` field.
///
/// Typed for the reason `HostMemoryShortage` and `ProofDeadlineReached` are: the retry loop used to
/// decide "GPU out of memory, route to a bigger card" and "invalid proof, do not exclude this slot"
/// by searching a string that embeds the worker's message verbatim — and that message can carry text
/// from the guest ELF of an on-chain job. A guest panicking with `out of memory` steered its own
/// retry onto the largest card and set a VRAM floor; one panicking with `proof is invalid` suppressed
/// the slot exclusion so the retry landed back on the same card. The `kind` comes from the worker's
/// own classification of its own failure, which no guest can set.
#[derive(Debug, Clone)]
pub struct WorkerProofError {
    /// The worker's own classification.
    pub kind: ErrorKind,
    /// Which slot, e.g. `risc0:cuda:0`.
    pub slot_key: String,
    /// The worker's message. DIAGNOSTIC ONLY — may contain guest-controlled text, so nothing may
    /// branch on it.
    pub message: String,
}

impl WorkerProofError {
    /// Did the GPU run out of memory, so a bigger card might succeed?
    pub fn is_gpu_oom(&self) -> bool {
        matches!(self.kind, ErrorKind::ResourceExhausted)
    }

    /// Was the input or the proof itself rejected, so another card would fail the same way?
    pub fn is_invalid(&self) -> bool {
        matches!(self.kind, ErrorKind::InvalidInput)
    }
}

impl std::fmt::Display for WorkerProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "worker {} proof error ({:?}): {}",
            self.slot_key, self.kind, self.message
        )
    }
}

impl std::error::Error for WorkerProofError {}

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
    /// STARK proving time in seconds: execution, the core/segment proofs, and the recursion that
    /// folds them into ONE constant-size STARK (risc0's succinct receipt, SP1's compressed proof).
    ///
    /// Deliberately EXCLUDES two things. The Groth16 wrap, reported separately in `wrap_secs`,
    /// because it is a fixed cost — it proves a fixed circuit with a fixed, version-pinned proving
    /// key — while everything here scales with cycles. And per-program proving-key setup, which the
    /// SP1 worker caches per ELF in production and so pays once per program rather than per proof.
    ///
    /// This is the figure `throughput` divides by. Before protocol v4 it was core proving alone
    /// (risc0's composite receipt, SP1's Core mode) and, for SP1, included key setup.
    pub duration_secs: f64,
    /// Cycles per second over `duration_secs`: the STARK proving rate.
    pub throughput: f64,
    /// Weight in the zkOP/s blend.
    pub weight: f64,
    /// Whether this program uses zkVM precompile acceleration.
    pub precompile: bool,
    /// Seconds to turn the constant-size STARK into the Groth16 proof that is submitted on chain,
    /// or `None` when it was not measured for this program.
    ///
    /// risc0 measures it on every program, exactly, by staging one proof: composite, then `compress`
    /// to succinct, then `compress` to Groth16. SP1 cannot be staged from the client — the CUDA
    /// server runs the whole pipeline as one request — so it measures by DIFFERENCE, proving one
    /// program a second time in Groth16 mode and subtracting the compressed run, and does it once
    /// per slot: the wrap is fixed, and a second full proof per program would multiply the suite's
    /// run time against a per-slot benchmark timeout.
    pub wrap_secs: Option<f64>,
}

#[cfg(test)]
mod tests {
    /// The tier must never select a configuration whose MEASURED peak does not fit, and never exceed
    /// the fork's default, which it is only allowed to cap.
    #[test]
    fn the_sp1_tier_only_picks_a_configuration_that_fits() {
        use super::{sp1_element_threshold_for_available_vram as tier, MIB};
        const GIB: u64 = 1024 * 1024 * 1024;
        const FULL_DEFAULT: u64 = 402_653_184;

        // An empty 4090 has room for the 268M configuration (17,766 MiB + margin).
        assert_eq!(tier(24 * GIB), Some(268_435_456));
        // 16 GiB free steps down to 134M, whose 15,092 MiB peak fits.
        assert_eq!(tier(16 * GIB), Some(134_217_728));

        // THE REGRESSION THIS GUARDS. SP1's own rule — `ceil(gib) + 4 > 20` — takes the 268M tier from
        // 16.4 GiB upward, but that tier peaks at 17,766 MiB. Everything in that band must step down,
        // or we commit to a configuration that cannot fit and fail part-way through a claimed job.
        for mib in [16_500u64, 17_000, 17_500, 18_000, 18_277] {
            assert_eq!(
                tier(mib * MIB),
                Some(134_217_728),
                "{mib} MiB free must take the 134M tier: 268M peaks at 17,766 MiB and will not fit"
            );
        }
        // Just above the 268M peak plus margin, it may step back up.
        assert_eq!(tier(18_278 * MIB), Some(268_435_456));

        // Below the smallest measured configuration there is nothing to offer.
        assert_eq!(tier(8 * GIB), None);
        assert_eq!(tier(0), None);

        // Monotonic, and never above the default it may only cap.
        let mut prev = 0u64;
        for mib in (0..=49_152u64).step_by(128) {
            if let Some(t) = tier(mib * MIB) {
                assert!(t >= prev, "tier fell as free VRAM grew, at {mib} MiB");
                assert!(t <= FULL_DEFAULT, "{t} exceeds the default {FULL_DEFAULT}");
                prev = t;
            }
        }
    }

    /// The floor and the tier table must agree about whether a card is usable at all. Two independent
    /// constants did not: the floor admitted a card by ~350 MiB that the tier function had no
    /// configuration for, so the work would have been refused a layer later, after a worker spawn.
    #[test]
    fn the_floor_is_exactly_what_the_smallest_configuration_needs() {
        let floor = super::sp1_min_available_vram_bytes();
        assert!(
            super::sp1_element_threshold_for_available_vram(floor).is_some(),
            "a card that exactly clears the floor must have a configuration available"
        );
        assert!(
            super::sp1_element_threshold_for_available_vram(floor - 1).is_none(),
            "one byte below the floor there must be nothing on offer, or the two disagree"
        );
    }

    /// These messages are operator-facing and go to a one-line log sink, so a wrapped literal must be
    /// continued with `\` rather than left to carry its own indentation. `cargo fmt` collapses the
    /// literal onto one physical line and the leading spaces survive into the output, which is how
    /// this shipped the first time: "more than              the 512 MiB".
    #[test]
    fn shortage_messages_render_as_one_clean_line() {
        let msgs = [
            super::GpuMemoryShortage {
                slot_key: "sp1:cuda:1".to_string(),
                foreign_bytes: 2444 * 1024 * 1024,
                available_bytes: 22120 * 1024 * 1024,
                needed_bytes: 16_000_000_000,
                total_bytes: 24564 * 1024 * 1024,
            }
            .to_string(),
            super::HostMemoryShortage {
                attempted: false,
                slot_key: "sp1:cuda:0".to_string(),
                needed: 18 << 30,
                reserved: 0,
                available: 4 << 30,
            }
            .to_string(),
        ];
        for m in msgs {
            assert!(!m.contains('\n'), "embedded newline in {m:?}");
            assert!(
                !m.contains("  "),
                "run of spaces from an uncontinued literal in {m:?}"
            );
        }
    }

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
        assert!(!is_gpu_oom(
            "Proof verification FAILED — SP1 proof is invalid"
        ));
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
