use serde::{Deserialize, Serialize};

/// Protocol version for the worker IPC wire format.
///
/// 4: `BenchmarkEntry` gained `wrap_secs`. The codec is bincode, which is POSITIONAL — an extra field
/// cannot be defaulted, so a v3 worker's entries do not decode as v4 and would fail mid-benchmark.
/// Bumping the version makes `handshake` reject a stale worker at spawn with a clear message instead.
/// 6: `ExecuteResult` gained `peak_host_bytes` (and, retroactively, relies on `journal_len`). Same
/// bincode-positional reason: a trailing field a v5 worker omits makes a v6 reader underrun the frame,
/// so `#[serde(default)]` does NOT give cross-version back-compat on the wire — it only lets a
/// SAME-version co-built binary that happens not to set the field decode as 0. The bump makes the
/// handshake reject a mismatched (old) worker at spawn rather than fail cryptically at first Execute.
/// 7: `ExecuteResult` gained `journal`, the bytes the host checks a job's journal binding against
/// before claiming it.
/// 8: no new field, a new meaning: risc0 `ExecuteResult.cycles` is the padded proving total (plus
/// the keccak proofs), the `sys_rand` seed hashes the image id and the key comes from the miner. A
/// v7 risc0 worker would measure in other units and seed guests differently from a v8 one proving
/// the same job, so the handshake refuses it.
/// 9: no new field, a new meaning: a risc0 worker measures and proves a job at `RISC0_SEGMENT_PO2`,
/// refuses a job proof at any other, and executes with risc0's refusals of guests no proof of which
/// can verify. A v8 worker would measure such a guest clean, and a v9 one refuses the po2 a v8 host
/// may send.
/// 10: `Execute` gained `po2`: the host measures a risc0 job at the segment size of each card that
/// may prove it, and a job proof runs at its card's size, within [`RISC0_JOB_PO2_MIN`]..=
/// [`RISC0_JOB_PO2_MAX`]. A v9 worker would measure every job at 20 whatever the host asked.
/// 11: `ProgramId` / `ProgramIdResult`: the program id a chain binds a proof of an ELF to (the risc0
/// image id, the SP1 verifying-key hash), derived without executing it. A v10 worker cannot decode the
/// command, so the handshake refuses it.
pub const PROTOCOL_VERSION: u32 = 11;

/// The segment size (po2) a risc0 worker executes or proves a job at when the host names none.
///
/// A guest can tell the size it runs at: every split leaves the pc it suspended at in memory the guest
/// can read (its own kernel, or a copy through the sha ecall). So a measurement at one size says
/// nothing about a proof at another, where one that measured clean could exit, or commit, otherwise.
/// The host therefore measures a job at the size of every card that may prove it, and a card proves it
/// at its own size; neither side leaves the size to the SDK (which picks 21 on a 32 GB card).
pub const RISC0_DEFAULT_JOB_PO2: u8 = 20;

/// The smallest segment size a risc0 job is measured or proven at. Below 16 the executor's segments
/// hold little but their own overhead: at 15 a segment must split 25,000 cycles early to leave room
/// for the longest instruction (a bigint2 ecall), leaving ~11% of it for the guest, and at 14 an
/// instruction over 2,000 cycles past ~14,400 fails the execution outright. A job measured there would
/// size every job far heavier than its other cards prove it, or refuse honest ones.
pub const RISC0_JOB_PO2_MIN: u8 = 16;

/// The largest segment size a risc0 job is measured or proven at: risc0's `DEFAULT_MAX_PO2`. The
/// Groth16 prover refuses a larger segment ("segment po2 exceeds max on ProverOpts") although the
/// executor runs it, so a job measured above it would fail every proof after its claim.
pub const RISC0_JOB_PO2_MAX: u8 = 22;

/// The longest journal an `ExecuteResult` carries. The router refuses a longer one on every fulfil
/// path (`MAX_JOURNAL_BYTES`, `JournalTooLarge`), so a longer journal is reported by its length alone.
pub const EXECUTE_JOURNAL_MAX_BYTES: usize = 32 * 1024;

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
        /// Segment limit as log2 of rows. None = [`RISC0_DEFAULT_JOB_PO2`].
        /// Only meaningful for risc0; other backends accept but ignore.
        po2: Option<u8>,
        /// The job's on-chain `programId` (32 bytes), if the host knows it. For risc0 this is the
        /// guest image id, so the worker refuses to prove an ELF whose computed image id does not
        /// match (a submitter who serves bytes unrelated to the registered program can otherwise
        /// burn a full Groth16 proof + fulfill gas on a proof the on-chain verifier will reject).
        /// SP1/OpenVM ignore it (for SP1 `programId` is a vkey, not the ELF image). `None` keeps
        /// the pre-existing behaviour (benchmark/calibration paths, mock worker).
        #[serde(default)]
        program_id: Option<[u8; 32]>,
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
        /// The job's on-chain `programId` (32 bytes), if known. Same meaning as on `Prove`: the
        /// risc0 worker refuses to EXECUTE (size) an ELF whose image id does not match, so a
        /// submitter cannot drive the zero-cost pre-claim measurement path with an ELF unrelated
        /// to the program they registered. `None` preserves the prior behaviour.
        #[serde(default)]
        program_id: Option<[u8; 32]>,
        /// The segment size to execute at (risc0; other backends ignore it), which must be the size
        /// the proof will run at. `None` = [`RISC0_DEFAULT_JOB_PO2`].
        #[serde(default)]
        po2: Option<u8>,
    },
    /// Cancel an in-flight proof. Worker should abort and send Cancelled or Error.
    Cancel { request_id: u64 },
    /// Graceful shutdown. Worker should exit after sending no further responses.
    Shutdown,
    /// Run a po2 calibration proof. The worker uses its built-in calibration
    /// program (chacha-mix with small input) at the specified segment limit
    /// and reports segment count + timing.
    CalibrateSegmentLimit { request_id: u64, po2: u8 },
    /// Do the one-time setup a backend needs before its first proof, outside any proof's
    /// watchdog: for SP1, installing the Groth16 circuit artifacts (~8 GB downloaded) and, where
    /// its `sp1-gpu-server` supports it, building the stripped circuit its Groth16 helper reads.
    /// Answered with `WarmupDone`, or `Error`. A backend with nothing to set up answers at once.
    Warmup { request_id: u64 },
    /// Derive the program id the chain binds a proof of `elf` to, without executing it: the risc0
    /// image id (`compute_image_id`, milliseconds), or the SP1 verifying-key hash (`vk.bytes32()`,
    /// SP1's `setup` on the CPU, minutes). For a caller that must know a served ELF IS a job's program
    /// before it trusts a measurement of it: SP1's `Execute` does not check that (see its `program_id`).
    /// Answered with `ProgramIdResult`, or `Error` (`InvalidInput` for an ELF the SDK refuses).
    /// Appended last, so every earlier variant keeps its bincode index.
    ProgramId { request_id: u64, elf: Vec<u8> },
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
        /// carries, obtained without proving (risc0: each segment padded to its power of two, not
        /// the guest's user cycles).
        cycles: u64,
        /// How long the execution itself took, so the caller can bound future ones.
        duration_secs: f64,
        /// Length in bytes of the guest journal (risc0) / public values (SP1) this
        /// execution produced. The guest commits it deterministically from (ELF, input) — the same
        /// bytes the later proof would carry as `ProofResult.journal` — so the host can pre-screen a
        /// program whose journal alone would OOG-revert fulfillJob and refuse to CLAIM it, instead of
        /// discovering it only after wasting a full proof. `#[serde(default)]` keeps an older worker
        /// (which omits the field) interoperable: it decodes as 0, i.e. "unknown, do not screen".
        #[serde(default)]
        journal_len: u64,
        /// Peak RESIDENT host memory (bytes) this measurement's executor child reached — anon plus the
        /// /dev/shm-mapped guest image. The measure worker is server-less, so this is the execute
        /// phase's footprint IN ISOLATION; the host reserves it PLUS the warm `sp1-gpu-server`'s
        /// resident when deciding whether a claimed job is provable-without-OOM (the prove-time
        /// execute stacks on the resident server). A v6 worker always sets it: the measured peak on
        /// native x86-64 Linux, else 0 ("unknown" — the portable executor has no such child), and the
        /// host treats 0 as do-not-gate. `#[serde(default)]` is only a same-version safety net; it does
        /// NOT give wire back-compat to a v5 worker (bincode is positional) — the `PROTOCOL_VERSION`
        /// bump to 6 rejects a mismatched worker at the handshake instead.
        #[serde(default)]
        peak_host_bytes: u64,
        /// The journal itself (the same bytes as `journal_len` counts), so the host can check the
        /// job's `expectedJournalHash` / `journalFields` binding before claiming. `None` when the
        /// journal is longer than [`EXECUTE_JOURNAL_MAX_BYTES`] (no fulfil could carry it) or the
        /// worker cannot vouch that a proof would commit the same bytes; the host then claims no
        /// journal-bound job on this measurement. `Some(vec![])` is a guest that committed nothing.
        #[serde(default)]
        journal: Option<Vec<u8>>,
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
    /// Response to Warmup.
    WarmupDone {
        request_id: u64,
        /// What was done, for the log.
        summary: String,
        /// Whether this worker's Groth16 runs in a helper process outside the worker's own
        /// (`sp1-gpu-server --sp1-groth16-cpu-helper`), whose memory a peak read from the live
        /// processes alone would miss once it has exited.
        groth16_helper: bool,
    },
    /// Response to `ProgramId`.
    ProgramIdResult {
        request_id: u64,
        /// risc0: the image id (`Digest::as_bytes`, the order the deployed adapter verifies against).
        /// SP1: the verifying-key hash as `vk.bytes32()` writes it. The on-chain order of an SP1
        /// programId is deployment-defined, so a caller compares it in either order, as the SP1
        /// worker's prove-path gate does.
        program_id: [u8; 32],
        /// How long the derivation took.
        duration_secs: f64,
    },
}

/// Classification of worker errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorKind {
    /// Proof generation failed (e.g. guest panicked).
    ProofFailed,
    /// Invalid input data or ELF.
    InvalidInput,
    /// The served ELF's verifying key / image id cannot match the job's on-chain `programId`, so NO
    /// job for this program can ever produce an accepted proof. Distinct from `InvalidInput` (which is
    /// per-job) because it is PERMANENT per program: the host negative-caches the program on it so it
    /// stops claiming every future job the program submits, capping the loss to the one claim wave
    /// already in flight when its first prove faults instead of one release penalty per job. SP1 cannot
    /// check this before claiming (deriving the vkey needs the
    /// minutes-long `setup`), so it is only proven on the prove path and reported with this kind.
    ProgramMismatch,
    /// Ran out of memory or other system resources.
    ResourceExhausted,
    /// Protocol violation (unexpected message, version mismatch).
    ProtocolError,
    /// Catch-all for internal errors.
    Internal,
}
/// The exit code of a worker whose proving server is gone, or whose connection to it is unusable.
///
/// The SP1 SDK keeps one connection to the `sp1-gpu-server` it starts and never reconnects, so a
/// worker that loses it can prove nothing more, and it exits for the dispatcher to replace it. Its
/// server may have been killed by the host running out of memory, which the worker cannot tell, so
/// the dispatcher reads this code as it reads a worker's own SIGKILL (see
/// `WorkerHandle::died_of_host_oom`). 75 is `EX_TEMPFAIL`: another worker may well succeed.
pub const WORKER_EXIT_SERVER_LOST: i32 = 75;

/// Bytes of HOST memory a worker is allowed to use, as the dispatcher sees it.
///
/// A worker cannot work this out for itself: the ceiling is the host's RAM minus the slice reserved
/// for everything else, and only the dispatcher knows the latter. Passed so a backend that can scale
/// its own memory appetite has something to scale against. See `CUDA_VRAM_BYTES_ENV` and
/// `CUDA_VRAM_AVAILABLE_BYTES_ENV` for the device side of the same idea.
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
/// Both figures measured on this box with a 1,912,954,963-cycle `sha256-chain` proof
/// through to a compact Groth16 seal: 17,766 MiB of a 24,564 MiB RTX 4090 at the 268M threshold, and
/// 15,092 MiB of a 16,303 MiB RTX 5080 at 134M.
///
/// `402_653_184` — the fork's own default — is deliberately ABSENT. Nothing here has measured its peak
/// VRAM, and this table is used to decide what will fit. Its omission makes a roomy card slightly
/// conservative (it is capped to 268M rather than left at 402M) and never unsafe, which is the same
/// trade `sp1_element_threshold_for_host_scale` already makes for host memory: only ever a value
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

/// The variable through which SP1's element threshold is set. An operator who sets it by hand
/// overrides the worker's own bounds below — the worker leaves it alone, and the dispatcher must then
/// size room for the operator's value rather than for one it computed. The server's own tier from the
/// card's total (`sp1_fork_threshold_for_total_vram`) still caps it.
pub const SP1_ELEMENT_THRESHOLD_ENV: &str = "SP1_GPU_ELEMENT_THRESHOLD";

/// Set to disable the SP1 worker's host-memory tuning, for bisecting a proving failure against stock
/// SDK behaviour.
pub const SP1_NO_AUTOTUNE_ENV: &str = "ZKMINER_SP1_NO_AUTOTUNE";

/// Set to `1` to run an SP1 worker in MEASURE-ONLY mode: it answers Hello without the GPU usability
/// probe (cycle sizing is pure CPU emulation, so GPU usability is irrelevant) and HARD-REFUSES every
/// `Prove`/`Benchmark` so it can never build the `CudaProver` / fork `sp1-gpu-server`. The dispatcher
/// runs one such server-less worker as the dedicated cycle-measurement slot, so a measure wall-clock
/// watchdog SIGKILL (which group-kills the worker) can never tear down a proving worker's warm server.
pub const SP1_MEASURE_ONLY_ENV: &str = "ZKMINER_SP1_MEASURE_ONLY";

/// Set to `0` to stop the SP1 worker installing the `sp1-gpu-server` shipped beside it over
/// `~/.sp1/bin/sp1-gpu-server`. Shared because the dispatcher has to know which of the two servers
/// a worker will run, to check that the card can run its GPU code.
pub const SP1_SERVER_INSTALL_ENV: &str = "ZKMINER_SP1_SERVER_INSTALL";

/// Host budget the STOCK SP1 defaults are assumed to need.
///
/// A lower bound turned into a working figure. The defaults were measured dying at 25.0 GiB against
/// a 25.1 GiB ceiling on this box — so they need MORE than 25.1 GiB, but the kill tells us only where
/// it stopped, not where it would have peaked. Setting the reference AT the observed kill point would
/// make this box scale by 1.00 and change nothing, i.e. fail again. 32 GiB is the next plausible tier
/// for a prover whose own device tiers are 24/40/78 GB, and it makes a 28 GiB host scale to ~0.78 — a
/// real reduction that can then be measured. Refine it when a run on a larger host records the true
/// peak.
pub const SP1_REFERENCE_BUDGET_BYTES: u64 = 32 * 1024 * 1024 * 1024;

/// The smallest factor the host tuning scales SP1's defaults by.
pub const SP1_MIN_SCALE: f64 = 0.25;

/// Element thresholds MEASURED to complete a proof within a host-memory budget, descending. See
/// `sp1_element_threshold_for_host_scale`.
const SP1_HOST_MEASURED_THRESHOLDS: &[u64] = &[268_435_456, 134_217_728];

/// The fork's own default element threshold, which every computed figure may only cap.
const SP1_FORK_DEFAULT_THRESHOLD: u64 = 402_653_184;

/// The factor SP1's defaults are scaled by for a worker with `host_budget` bytes of host memory, in
/// `[SP1_MIN_SCALE, 1.0]`. `1.0` — change nothing — when the budget is unknown or tuning is disabled.
///
/// Shared so the dispatcher can work out the tier a worker WILL use without asking it: the worker
/// applies this to itself at startup, and the dispatcher needs the same answer to decide how much
/// room to make for it on a card.
///
/// DIRECTION IS ONE-WAY. Clamped to at most 1.0, so this only ever reduces the defaults: scaling them
/// UP on a bigger machine might be correct, but nothing has measured it, and a guess in that
/// direction risks the host freeze this exists to prevent.
pub fn sp1_memory_scale(host_budget: Option<u64>, no_autotune: bool) -> f64 {
    if no_autotune {
        return 1.0;
    }
    match host_budget {
        // Unknown budget: change nothing. An absent reading is not evidence of a small machine, and
        // the stock defaults are the only configuration with any track record.
        None => 1.0,
        Some(b) => (b as f64 / SP1_REFERENCE_BUDGET_BYTES as f64).clamp(SP1_MIN_SCALE, 1.0),
    }
}

/// The element threshold a host-memory `scale` allows, or `None` for no host-derived limit.
///
/// THE lever for SP1 host memory, and the only one measured to work: the threshold sizes the
/// per-worker pinned HOST buffer (`num_workers x threshold x 4 bytes`). Measured on this 28 GiB box
/// with the RTX 4090, one Groth16 proof each: the default 402,653,184 was OOM-killed in the wrap at
/// 25.0 GiB (and still was with the trace ring halved); 268,435,456 passed in 55.0 s; 134,217,728 in
/// 58.0 s.
///
/// Only ever a value MEASURED to complete a proof: the computed figure is snapped DOWN to the nearest
/// known-good step rather than used directly, and below the smallest step the smallest is still used
/// rather than inventing one.
pub fn sp1_element_threshold_for_host_scale(scale: f64) -> Option<u64> {
    if scale >= 1.0 {
        return None;
    }
    let want = SP1_FORK_DEFAULT_THRESHOLD as f64 * scale;
    SP1_HOST_MEASURED_THRESHOLDS
        .iter()
        .copied()
        .find(|t| (*t as f64) <= want)
        .or_else(|| SP1_HOST_MEASURED_THRESHOLDS.last().copied())
}

/// The element threshold an SP1 worker caps itself to, from the two independent bounds — the HOST's
/// budget via `scale`, and the CARD's free VRAM — the smaller winning. `None` when neither bounds it.
///
/// A free-VRAM figure below every measured tier still bounds it, to the SMALLEST tier. It used to
/// bound nothing, which handed the choice back to the fork's own rule — the LARGEST configuration on a
/// 24 GB card, 402,653,184, for exactly the card with the least room. Nothing measured fits there, but
/// the smallest configuration is the one most likely to; and the dispatcher — which refuses such a card
/// unless the operator lowered or disabled its floor — then predicts the same tier it would run at.
///
/// This is only the worker's half. The server takes the minimum of this and its own tier from the
/// card's TOTAL (`sp1_fork_threshold_for_total_vram`), so the threshold actually used is that minimum.
/// Ignores the operator's `SP1_ELEMENT_THRESHOLD_ENV`, which callers check first: when it is set the
/// worker applies none of this.
pub fn sp1_element_threshold_cap(scale: f64, available_vram: Option<u64>) -> Option<u64> {
    let from_host = sp1_element_threshold_for_host_scale(scale);
    let from_vram = available_vram.map(|a| {
        sp1_element_threshold_for_available_vram(a).unwrap_or_else(sp1_smallest_measured_threshold)
    });
    [from_host, from_vram].into_iter().flatten().min()
}

/// The smallest SP1 element threshold with a measured VRAM peak.
pub fn sp1_smallest_measured_threshold() -> u64 {
    SP1_MEASURED_TIERS
        .last()
        .map(|(t, _)| *t)
        .unwrap_or(SP1_FORK_DEFAULT_THRESHOLD)
}

/// The element threshold `sp1-gpu-server` picks for itself from the card's TOTAL VRAM, before any cap.
///
/// Mirrors `local_gpu_opts` in the fork (`sp1-gpu/crates/prover_components/src/builder.rs`): it computes
/// `gpu_memory_gb = ceil(total / 1 GiB) + 4`, takes `ELEMENT_THRESHOLD - (1 << 28)` = 134,217,728 when
/// that is at most 20 and the full `ELEMENT_THRESHOLD` = 402,653,184 above it, and then uses the
/// minimum of that and `SP1_GPU_ELEMENT_THRESHOLD` if the variable parses. So the 16,303 MiB RTX 5080
/// (16 + 4 = 20) runs at most 134M whatever it is told, and the 24,564 MiB RTX 4090 (24 + 4 = 28) at
/// most 402M.
///
/// The dispatcher needs it to predict a worker's tier exactly: without it, an operator's 268M on a
/// 5080 read as needing 18,278 MiB — more than the card has — so the gate never made room for a
/// worker that actually runs at 134M and needs 15,604.
pub fn sp1_fork_threshold_for_total_vram(total: u64) -> u64 {
    const GIB: u64 = 1024 * 1024 * 1024;
    let gpu_memory_gb = total.div_ceil(GIB) + 4;
    if gpu_memory_gb <= 20 {
        SP1_FORK_DEFAULT_THRESHOLD - (1 << 28)
    } else {
        SP1_FORK_DEFAULT_THRESHOLD
    }
}

/// How much VRAM an SP1 worker sized at `threshold` needs free on its card: that configuration's
/// measured peak plus [`SP1_VRAM_MARGIN`]. `None` for a threshold this table has not measured.
///
/// The inverse of [`sp1_element_threshold_for_available_vram`], from the same table, so the two cannot
/// disagree: `sp1_element_threshold_for_available_vram(sp1_vram_required_for_threshold(t))` is `t`.
/// The dispatcher uses it to decide how much room an SP1 proof needs made for it on a card our other
/// workers share.
pub fn sp1_vram_required_for_threshold(threshold: u64) -> Option<u64> {
    SP1_MEASURED_TIERS
        .iter()
        .find(|(t, _)| *t == threshold)
        .map(|(_, peak)| peak.saturating_add(SP1_VRAM_MARGIN))
}

/// How much VRAM must be free before SP1 can be given work at all: what its smallest measured
/// configuration needs, plus margin.
///
/// Derived from [`SP1_MEASURED_TIERS`] rather than written down separately, so this and
/// [`sp1_element_threshold_for_available_vram`] cannot disagree about whether a card is usable. Two
/// independent constants could disagree — a floor that admitted a card by ~350 MiB the tier function
/// then had no configuration for would refuse the work one layer later, after the worker was already
/// spawned.
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

/// Every worker/measure slot for a backend was BUSY (or down-and-not-revivable) when a cycle
/// measurement tried to run, so nothing was attempted.
///
/// Typed for the same reason as `HostMemoryShortage`: the caller (the measure path) must not mistake
/// pure scheduling contention for a bad program. It is TRANSIENT — no guest executed, so the
/// (program, input) must not be struck or negative-cached; the next tick retries when a slot frees.
#[derive(Debug, Clone)]
pub struct MeasureSlotsBusy {
    /// The backend whose measure/worker slots were all busy, e.g. `sp1`.
    pub backend: String,
    /// How many candidate slots were checked and found busy/unrevivable.
    pub slots: usize,
}

impl std::fmt::Display for MeasureSlotsBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "all {} '{}' measure/worker slot(s) busy, or down and not revivable; skipping cycle \
             measurement (transient)",
            self.slots, self.backend,
        )
    }
}

impl std::error::Error for MeasureSlotsBusy {}

/// The measure worker chosen for a sizing request (`Execute`, `ProgramId`) was already dead when the
/// request was SENT to it: the pipe was closed while the worker sat idle (an OOM kill or an operator's
/// kill between requests). Nothing ran, so nothing about the (program, input) is known; the dispatcher
/// has cleared the slot, so the next request revives it.
///
/// Typed so a caller can tell this from a worker that died DURING a request (which may be the
/// guest's doing, and stays an untyped error): `zkminer simulate` reports it `unavailable`, not a
/// strike-counted failure. Only the dispatcher's send-failure arms construct it, never from worker
/// text.
#[derive(Debug, Clone)]
pub struct MeasureWorkerGone {
    /// The slot whose worker was gone, e.g. `risc0:measure:0`.
    pub slot_key: String,
    /// The send error (the OS's text, e.g. "Broken pipe").
    pub message: String,
}

impl std::fmt::Display for MeasureWorkerGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "measure worker {} was gone when the request was sent ({}); nothing ran (transient)",
            self.slot_key, self.message
        )
    }
}

impl std::error::Error for MeasureWorkerGone {}

/// A worker answered a `ProgramId` request with `InvalidInput`: its SDK refused to derive a program
/// id from these bytes (risc0: not an ELF it can compute an image id for; SP1: `setup` failed on it).
/// Typed so a caller can tell the worker's verdict on the ELF from everything else that can fail
/// around it (no worker, a dead or OOM-killed one, an internal error) — those say nothing about the
/// program. The message carries SDK text derived from the ELF: never match on it.
#[derive(Debug, Clone)]
pub struct ProgramIdRefused {
    pub message: String,
}

impl std::fmt::Display for ProgramIdRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the worker refused to derive a program id: {}", self.message)
    }
}

impl std::error::Error for ProgramIdRefused {}

/// A cycle measurement's wall-clock watchdog SIGKILLed the worker because the guest did not finish
/// within the measure budget.
///
/// Typed on purpose (finding RH-round2/4): the measure path treats a genuine wall-clock timeout as
/// POSSIBLY transient (a feasible guest can miss the budget under transient host load) and gives it a
/// retry TTL rather than a permanent blacklist. That leniency MUST be driven by a dispatcher-generated
/// signal — the watchdog's `intentional_kill` — NOT by substring-matching the error text, because a
/// `WorkerResponse::Error` message carries guest-controlled bytes: a guest could panic with the phrase
/// "wall-clock watchdog" and forge the TTL, re-opening the perpetual re-measurement DoS the permanent
/// negative-cache exists to stop. Only the dispatcher's watchdog path constructs this error, so a
/// `downcast_ref` to it is an unforgeable "this was a real timeout" signal. Everything else — a guest
/// panic/trap, an image-id/vkey mismatch, a cap trip — stays permanent.
#[derive(Debug, Clone)]
pub struct MeasureWallClockTimeout {
    /// The slot whose worker the watchdog killed, e.g. `sp1:measure:0`.
    pub slot_key: String,
}

impl std::fmt::Display for MeasureWallClockTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cycle measurement timed out on {}: the guest did not finish within the measure budget \
             (wall-clock watchdog) — may be transient host load",
            self.slot_key,
        )
    }
}

impl std::error::Error for MeasureWallClockTimeout {}

/// A committed (claimed) proof reclaimed this in-flight pre-claim MEASUREMENT's resources by killing
/// its throwaway measure worker (dispatcher `preempt_measures_for_host` / `preempt_measures_for_shm`).
///
/// Typed, and TRANSIENT, for the same reason as `MeasureSlotsBusy`: nothing about the (program, input)
/// failed — the measurement was healthy and simply YIELDED to a bonded job on the marginal box where a
/// ~12 GiB measure and an ~18 GiB prove cannot co-fit (host-RAM and, on x86_64, `/dev/shm`). A
/// measurement is speculative work with no collateral; a claimed proof is bonded and on a deadline, so
/// giving the proof priority is the correct resolution of that contention (finding RH-round3 residual
/// A — the "give the committed prove priority over the speculative measure" proper fix). The caller
/// MUST treat it exactly like `MeasureSlotsBusy`: NO strike, NO negative-cache, NO retry TTL — just
/// re-measure on a later tick once the proof has freed the resources.
///
/// Dispatcher-only and unforgeable: only the preemption path constructs it, never a
/// `WorkerResponse::Error` carrying guest-controlled text, so a `downcast_ref` to it cannot be forged
/// by a hostile guest to win the lenient transient treatment.
#[derive(Debug, Clone)]
pub struct MeasurePreempted {
    /// The measure slot whose worker a claimed proof killed to reclaim its resources, e.g.
    /// `sp1:measure:0`.
    pub slot_key: String,
}

impl std::fmt::Display for MeasurePreempted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cycle measurement on {} was preempted to free resources for a claimed proof (transient) \
             — it will be re-measured on a later tick",
            self.slot_key,
        )
    }
}

impl std::error::Error for MeasurePreempted {}

/// Not enough of this card's VRAM is free for this backend to be given work on it.
///
/// Distinct from `HostMemoryShortage` (that is system RAM) and from a GPU OOM (that is the proof
/// having already failed). This one is an ADMISSION refusal: nothing ran, so it costs no attempt,
/// and the condition is usually transient — a desktop session, a browser with hardware acceleration,
/// someone else's CUDA job, or one of this miner's own workers of the other backend that could not be
/// recycled to make room yet — so the honest response is to try the other card and then wait; or,
/// when the obstacle is ours (`ours_in_the_way`), to come back to this card shortly.
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
    /// VRAM still held on that card by this miner's OTHER processes, in bytes: another backend's
    /// worker that was busy, memory of one recycled moments ago that had not come back yet, one still
    /// starting up, a worker pinned to another card holding a context on this one, or one not worth
    /// recycling because doing so would not have made room.
    ///
    /// Separate from `foreign_bytes` because the operator's remedy differs. Foreign VRAM is a
    /// desktop or someone else's job, which only they can close; this is ours.
    pub sibling_bytes: u64,
    /// What was actually free to this slot, in bytes: the card's total less its driver-reserved
    /// memory, `foreign_bytes` and `sibling_bytes`.
    pub available_bytes: u64,
    /// What this backend needs free before it may be given work, in bytes — or `None` when that is not
    /// known: a backend whose requirement nothing has measured, refused because our own worker still
    /// stood in the way.
    pub needed_bytes: Option<u64>,
    /// The obstacle is OURS and transient: another of this miner's workers on the card could not be
    /// recycled yet (its slot was busy), or the memory of one just torn down had not come back. The
    /// retry should come back to THIS card shortly rather than exclude it — it is often the only card
    /// that can take the job, and excluding it parked the job behind a long proof on the other card.
    pub ours_in_the_way: bool,
    /// Total VRAM of the card, in bytes, for the operator's benefit in the log line.
    pub total_bytes: u64,
}

/// Foreign VRAM below this is driver bookkeeping, not an occupant: an idle card with nothing running
/// reads 1-2 MiB used. Telling the operator to close something over that would send them looking for
/// a process that does not exist.
const NOTABLE_FOREIGN_BYTES: u64 = 64 * MIB;

impl std::fmt::Display for GpuMemoryShortage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const MIB: f64 = 1024.0 * 1024.0;
        let mib = |b: u64| (b as f64 / MIB).round() as u64;
        let backend = self.slot_key.split(':').next().unwrap_or("this backend");
        let foreign = self.foreign_bytes >= NOTABLE_FOREIGN_BYTES;
        // Whatever the other figures do not account for is the driver's own reservation (or, rarely,
        // memory that came and went between readings).
        let reserved = self
            .total_bytes
            .saturating_sub(self.available_bytes)
            .saturating_sub(self.foreign_bytes)
            .saturating_sub(self.sibling_bytes);
        let mut held = Vec::new();
        if foreign {
            held.push(format!(
                "{} MiB is held by another process",
                mib(self.foreign_bytes)
            ));
        }
        if self.sibling_bytes > 0 {
            held.push(format!(
                "{} MiB is still held by this miner's other workers on the card",
                mib(self.sibling_bytes)
            ));
        }
        if held.is_empty() && reserved >= NOTABLE_FOREIGN_BYTES {
            held.push(format!("{} MiB is reserved by the driver", mib(reserved)));
        }
        write!(
            f,
            "{} has only {} MiB of its {} MiB VRAM free",
            self.slot_key,
            mib(self.available_bytes),
            mib(self.total_bytes),
        )?;
        let and = if held.is_empty() {
            " and".to_string()
        } else {
            format!(" -- {} -- and", held.join(" and "))
        };
        match self.needed_bytes {
            Some(needed) => write!(f, "{and} {backend} needs {} MiB.", mib(needed))?,
            None => write!(
                f,
                "{and} {backend} needs that memory freed before it can start."
            )?,
        }
        if self.needed_bytes.is_some() && !self.ours_in_the_way {
            write!(
                f,
                " It is not started below that, so it cannot run out of device memory part-way \
                 through a claimed job."
            )?;
        }
        // Each cause gets its own remedy: ours clears by itself; a foreign occupant only if closed.
        if self.ours_in_the_way && self.sibling_bytes > 0 {
            write!(f, " The memory of ours is temporary.")?;
        }
        if foreign {
            write!(
                f,
                " Close whatever is using the card, or drive the display from another GPU."
            )?;
        }
        Ok(())
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

    /// Did the served ELF's verifying key / image id fail to match the job's `programId`? Then no job
    /// for this program can ever be proved: the caller should stop claiming the program, not retry.
    pub fn is_program_mismatch(&self) -> bool {
        matches!(self.kind, ErrorKind::ProgramMismatch)
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
/// allocation failure (CUDA, HIP/ROCm or Level Zero/SYCL). Workers use this to tag such errors as
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
        // Level Zero and SYCL's Unified Runtime: ZE_RESULT_ERROR_OUT_OF_DEVICE_MEMORY,
        // UR_RESULT_ERROR_OUT_OF_DEVICE_MEMORY ("Native API returns: 39"), and SYCL's own wording.
        || m.contains("out_of_device_memory")
        || m.contains("out of device memory")
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

    /// What a tier needs and what tier a figure buys must be exact inverses, at every tier. The
    /// dispatcher evicts our other workers from a card until an SP1 proof has `required(t)` free; if
    /// that figure bought a SMALLER tier than `t`, the worker would be recycled down a tier on a card
    /// we had just emptied for it, and if it bought a larger one the worker would be sized past what
    /// the dispatcher made room for.
    #[test]
    fn the_requirement_buys_exactly_its_own_tier() {
        use super::{
            sp1_element_threshold_for_available_vram as tier,
            sp1_vram_required_for_threshold as required, SP1_MEASURED_TIERS,
        };
        for (t, _) in SP1_MEASURED_TIERS {
            let need = required(*t).expect("every measured tier has a requirement");
            assert_eq!(
                tier(need),
                Some(*t),
                "{need} bytes must buy exactly tier {t}"
            );
            assert_ne!(
                tier(need - 1),
                Some(*t),
                "one byte short of {need} must not buy tier {t}"
            );
        }
        // The smallest tier's requirement IS the floor: the two are one rule, not two constants.
        let smallest = SP1_MEASURED_TIERS.last().unwrap().0;
        assert_eq!(
            required(smallest),
            Some(super::sp1_min_available_vram_bytes())
        );
        // An unmeasured configuration has no requirement — never a guess.
        assert_eq!(required(402_653_184), None);
        assert_eq!(required(0), None);
    }

    /// The host-memory half of SP1's sizing, which the worker applies to itself and the dispatcher
    /// predicts with these same functions.
    #[test]
    fn the_host_scale_only_ever_lowers_and_snaps_to_measured_steps() {
        use super::{
            sp1_element_threshold_cap as cap, sp1_element_threshold_for_host_scale as host,
            sp1_memory_scale as scale,
        };
        const GIB: u64 = 1024 * 1024 * 1024;
        // Unknown budget, or tuning off: change nothing.
        assert_eq!(scale(None, false), 1.0);
        assert_eq!(scale(Some(4 * GIB), true), 1.0);
        // Never above 1.0, never below the floor.
        assert_eq!(scale(Some(64 * GIB), false), 1.0);
        assert_eq!(scale(Some(GIB), false), super::SP1_MIN_SCALE);
        // This box: ~25.1 GiB of budget scales to ~0.78 and snaps DOWN to 268M.
        assert_eq!(host(scale(Some(25 * GIB), false)), Some(268_435_456));
        // A smaller host snaps to 134M, and below the smallest step still gets the smallest.
        assert_eq!(host(scale(Some(20 * GIB), false)), Some(134_217_728));
        assert_eq!(host(super::SP1_MIN_SCALE), Some(134_217_728));
        assert_eq!(host(1.0), None);
        // The two bounds combine as the smaller; neither present means the fork decides.
        assert_eq!(cap(1.0, Some(24 * GIB)), Some(268_435_456));
        assert_eq!(cap(0.6, Some(24 * GIB)), Some(134_217_728));
        assert_eq!(cap(0.8, Some(16 * GIB)), Some(134_217_728));
        // Too little free for any measured tier still bounds it — to the smallest, never to nothing,
        // which would hand a 24 GB card back to the fork's 402M.
        assert_eq!(cap(1.0, Some(8 * GIB)), Some(134_217_728));
        assert_eq!(cap(1.0, None), None);
    }

    /// These messages are operator-facing and go to a one-line log sink, so a wrapped literal must be
    /// continued with `\` rather than left to carry its own indentation. `cargo fmt` collapses the
    /// literal onto one physical line and the leading spaces survive into the output, e.g.
    /// "more than              the 512 MiB".
    #[test]
    fn shortage_messages_render_as_one_clean_line() {
        const MIB: u64 = 1024 * 1024;
        let gpu = |slot: &str,
                   foreign: u64,
                   sibling: u64,
                   available: u64,
                   needed: Option<u64>,
                   total: u64,
                   ours: bool| {
            super::GpuMemoryShortage {
                slot_key: slot.to_string(),
                foreign_bytes: foreign * MIB,
                sibling_bytes: sibling * MIB,
                available_bytes: available * MIB,
                needed_bytes: needed.map(|n| n * MIB),
                ours_in_the_way: ours,
                total_bytes: total * MIB,
            }
            .to_string()
        };
        let msgs = [
            // 0: a desktop on the 4090 (24,564 less 455 reserved and 2,444 held).
            gpu("sp1:cuda:1", 2444, 0, 21665, Some(18278), 24564, false),
            // 1: our risc0 worker on the 5080 was busy (2 MiB of driver bookkeeping is not "foreign").
            gpu("sp1:cuda:0", 2, 1806, 14072, Some(15604), 16303, true),
            // 2: both a desktop and a busy sibling.
            gpu("sp1:cuda:1", 2444, 7134, 14531, Some(15604), 24564, true),
            // 3: risc0, whose requirement is unmeasured, behind an idle SP1 arena.
            gpu("risc0:cuda:0", 2, 15124, 754, None, 16303, true),
            // 4: nothing but the driver's reservation short of an operator-raised floor.
            gpu("sp1:cuda:0", 2, 0, 15878, Some(16000), 16303, false),
            super::HostMemoryShortage {
                attempted: false,
                slot_key: "sp1:cuda:0".to_string(),
                needed: 18 << 30,
                reserved: 0,
                available: 4 << 30,
            }
            .to_string(),
        ];
        let has = |i: usize, what: &str| msgs[i].contains(what);
        // A foreign occupant is named, with the advice to remove it; nothing of ours is invented.
        assert!(has(0, "2444 MiB is held by another process"), "{}", msgs[0]);
        assert!(has(0, "Close whatever"), "{}", msgs[0]);
        assert!(!has(0, "other workers"), "{}", msgs[0]);
        // Our own worker in the way: named, said to be temporary, and the operator is NOT told to
        // close anything — nor told that the 2 MiB of bookkeeping is another process.
        assert!(
            has(1, "-- 1806 MiB is still held by this miner's other workers"),
            "{}",
            msgs[1]
        );
        assert!(has(1, "of ours is temporary"), "{}", msgs[1]);
        assert!(!has(1, "Close whatever"), "{}", msgs[1]);
        assert!(!has(1, "another process"), "{}", msgs[1]);
        // Both at once, joined; each cause with its own remedy.
        assert!(
            has(
                2,
                "is held by another process and 7134 MiB is still held by"
            ),
            "{}",
            msgs[2]
        );
        assert!(
            has(2, "of ours is temporary") && has(2, "Close whatever"),
            "{}",
            msgs[2]
        );
        // An unmeasured requirement is not invented.
        assert!(has(3, "needs that memory freed"), "{}", msgs[3]);
        assert!(!has(3, "risc0 needs 1"), "{}", msgs[3]);
        assert!(!has(3, "not started below"), "{}", msgs[3]);
        // The reservation alone is named rather than left as a dangling clause.
        assert!(
            has(
                4,
                "-- 423 MiB is reserved by the driver -- and sp1 needs 16000 MiB."
            ),
            "{}",
            msgs[4]
        );
        assert!(!has(4, "Close whatever"), "{}", msgs[4]);
        for m in msgs {
            assert!(!m.contains('\n'), "embedded newline in {m:?}");
            assert!(
                !m.contains("  "),
                "run of spaces from an uncontinued literal in {m:?}"
            );
            assert!(!m.contains("-- --") && !m.contains("free --  and"), "{m:?}");
        }
    }

    /// The server's own tier from the card's TOTAL, as `local_gpu_opts` computes it.
    #[test]
    fn the_fork_tier_follows_the_cards_total() {
        use super::sp1_fork_threshold_for_total_vram as fork;
        const MIB: u64 = 1024 * 1024;
        assert_eq!(
            fork(16_303 * MIB),
            134_217_728,
            "RTX 5080: ceil(15.92) + 4 = 20"
        );
        assert_eq!(
            fork(24_564 * MIB),
            402_653_184,
            "RTX 4090: ceil(23.99) + 4 = 28"
        );
        assert_eq!(
            fork(16 * 1024 * MIB),
            134_217_728,
            "exactly 16 GiB: 16 + 4 = 20"
        );
        assert_eq!(
            fork(16 * 1024 * MIB + 1),
            402_653_184,
            "a byte over: 17 + 4 = 21"
        );
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
        assert!(is_gpu_oom(
            "Native API failed. Native API returns: 39 (UR_RESULT_ERROR_OUT_OF_DEVICE_MEMORY)"
        ));
        assert!(is_gpu_oom(
            "zeMemAllocDevice: ZE_RESULT_ERROR_OUT_OF_DEVICE_MEMORY"
        ));
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
            program_id: Some([7u8; 32]),
        };
        let bytes = bincode::serialize(&cmd).unwrap();
        let decoded: WorkerCommand = bincode::deserialize(&bytes).unwrap();
        match decoded {
            WorkerCommand::Prove {
                request_id,
                elf,
                input_data,
                po2,
                program_id,
            } => {
                assert_eq!(request_id, 42);
                assert_eq!(elf, vec![1, 2, 3]);
                assert_eq!(input_data, vec![4, 5, 6]);
                assert_eq!(po2, Some(20));
                assert_eq!(program_id, Some([7u8; 32]));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn execute_carries_the_segment_size_to_measure_at() {
        for po2 in [None, Some(RISC0_JOB_PO2_MIN), Some(19)] {
            let cmd = WorkerCommand::Execute {
                request_id: 7,
                elf: vec![1],
                input_data: vec![2],
                program_id: Some([3u8; 32]),
                po2,
            };
            let bytes = bincode::serialize(&cmd).unwrap();
            match bincode::deserialize::<WorkerCommand>(&bytes).unwrap() {
                WorkerCommand::Execute {
                    po2: got,
                    program_id,
                    ..
                } => {
                    assert_eq!(got, po2);
                    assert_eq!(program_id, Some([3u8; 32]));
                }
                _ => panic!("wrong variant"),
            }
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

    /// `MeasurePreempted` is a real `std::error::Error`, names its slot, says "transient", and is a
    /// DISTINCT type from the other transient/timeout measure errors — so the measure path can
    /// downcast it specifically and treat it like `MeasureSlotsBusy` (no strike, no TTL).
    #[test]
    fn measure_preempted_is_a_typed_transient() {
        let e = MeasurePreempted {
            slot_key: "sp1:measure:0".to_string(),
        };
        let msg = e.to_string();
        assert!(msg.contains("sp1:measure:0"), "names the slot: {msg}");
        assert!(msg.contains("transient"), "flagged transient: {msg}");

        // Boxed as a trait object, it downcasts to itself and NOT to the sibling measure errors — the
        // unforgeable-type property the measure path relies on.
        let boxed: Box<dyn std::error::Error> = Box::new(MeasurePreempted {
            slot_key: "sp1:measure:1".to_string(),
        });
        assert!(boxed.downcast_ref::<MeasurePreempted>().is_some());
        assert!(boxed.downcast_ref::<MeasureSlotsBusy>().is_none());
        assert!(boxed.downcast_ref::<MeasureWallClockTimeout>().is_none());
    }
}
