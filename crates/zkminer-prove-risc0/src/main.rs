//! RISC Zero prover worker binary.
//!
//! Long-running process that communicates with the host via stdin/stdout IPC.
//! Stderr is used for logging (captured and forwarded by host).

use std::io::{self, BufReader, BufWriter};
#[cfg(not(feature = "macos"))]
use std::time::Instant;

#[cfg(all(feature = "macos", not(all(target_os = "macos", target_arch = "aarch64"))))]
compile_error!("the macos worker requires aarch64-apple-darwin");
#[cfg(all(feature = "macos", any(feature = "cuda", feature = "rocm", feature = "intel")))]
compile_error!("macos mode cannot be combined with CUDA, ROCm or Intel");
#[cfg(feature = "macos")]
mod macos;
#[cfg(feature = "macos-metal")]
compile_error!("macos-metal is retired; use macos-rv32im-metal with RISC0_SEGMENT_HAL=metal");
#[cfg(not(feature = "macos"))]
mod groth16_component;

use anyhow::{Context, Result};
#[cfg(not(feature = "macos"))]
use risc0_zkvm::Prover as _;
#[cfg(not(feature = "macos"))]
use zkminer_prover_protocol::types::CUDA_VRAM_BYTES_ENV;
#[cfg(not(feature = "macos"))]
use zkminer_prover_protocol::{BENCH_BIGINT_MUL, BENCH_CHACHA_MIX, BENCH_ECDSA_VERIFY, BENCH_MEMORY_MERKLE};
use zkminer_prover_protocol::{
    is_gpu_oom, read_message, write_message, BenchmarkEntry, ErrorKind, WorkerCommand,
    WorkerResponse, BACKEND_RISC0, BENCH_FIBONACCI, BENCH_SHA256_CHAIN, EXECUTE_JOURNAL_MAX_BYTES,
    PROTOCOL_VERSION, RISC0_DEFAULT_JOB_PO2, RISC0_JOB_PO2_MAX, RISC0_JOB_PO2_MIN,
};

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

const WORKER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Duplicate `fd` with close-on-exec set.
///
/// `dup` deliberately CLEARS `FD_CLOEXEC` on the new descriptor, so without this every process the
/// worker forks inherits a writable copy of the host's IPC pipe; a grandchild that outlives us then
/// keeps the write end open and the host's blocking `read_exact` never sees EOF. The host never
/// passes this descriptor to anyone, so close-on-exec is unconditionally correct. (Mirrors the SP1
/// worker's `dup_cloexec`.)
#[cfg(unix)]
fn dup_cloexec(fd: std::os::unix::io::RawFd) -> std::io::Result<std::os::unix::io::RawFd> {
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(new)
}

/// The release's Intel worker ships Intel's Level Zero driver beside it (`zkminer-intel/lib`, from
/// `Dockerfile.build`'s intel-gpu-runtime). The Level Zero loader (shipped there too) would also open
/// any other driver it finds on the host by its usual names, such as a distribution's
/// `libze_intel_gpu_legacy1.so.1`, which adds its devices to the ones `ZE_AFFINITY_MASK` indexes;
/// `ZE_ENABLE_ALT_DRIVERS` makes the shipped driver the only one. An operator's own setting wins.
#[cfg(feature = "intel")]
fn use_shipped_level_zero_driver() {
    if std::env::var_os("ZE_ENABLE_ALT_DRIVERS").is_some() {
        return;
    }
    let Some(driver) = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join("zkminer-intel/lib/libze_intel_gpu.so.1")))
        .filter(|driver| driver.is_file())
    else {
        return;
    };
    // Before anything starts a thread or initialises Level Zero.
    std::env::set_var("ZE_ENABLE_ALT_DRIVERS", driver);
}

fn main() {
    #[cfg(feature = "intel")]
    use_shipped_level_zero_driver();

    #[cfg(feature = "macos-recursion-metal")]
    if std::env::args().nth(1).as_deref() == Some("--macos-recursion-probe") {
        match macos::recursion_device_probe() {
            Ok(value) => { println!("{value}"); return; }
            Err(error) => { eprintln!("recursion Metal probe failed: {error:#}"); std::process::exit(1); }
        }
    }
    #[cfg(feature = "macos")]
    if std::env::args().nth(1).as_deref() == Some("--macos-metal-probe") {
        eprintln!("The fold-only Metal probe is retired; use RISC0_SEGMENT_HAL=metal on a macos-rv32im-metal worker");
        std::process::exit(2);
    }

    // Direct benchmark mode runs the operator's own guests and prints a human table to the REAL
    // stdout, so it must come before the fd-1 redirect below. It speaks no IPC.
    if std::env::args().any(|a| a == "--benchmark") {
        tracing_subscriber::fmt()
            .with_writer(io::stderr)
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
        let results = run_benchmarks();
        for r in &results {
            println!(
                "{:<16} {:>12} cycles  {:>8.2}s  {:>12.0} c/s  weight={:.2}  precompile={}",
                r.program_name, r.cycles, r.duration_secs, r.throughput, r.weight, r.precompile,
            );
        }
        return;
    }

    // `--export-guest <name> <path>`: write one of the embedded guests to `path` and print its image
    // id, which is the `programId` of a job for it. For harnesses that submit jobs this worker can
    // serve (crates/zkminer-cli/tests/localnet.rs). Speaks no IPC.
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--export-guest") {
        let (Some(name), Some(path)) = (args.get(i + 1), args.get(i + 2)) else {
            eprintln!("usage: --export-guest fibonacci <path>");
            std::process::exit(2);
        };
        let elf = match name.as_str() {
            "fibonacci" => FIBONACCI_ELF,
            other => {
                eprintln!("unknown guest {other:?} (known: fibonacci)");
                std::process::exit(2);
            }
        };
        let image_id = risc0_zkvm::compute_image_id(elf).expect("compute_image_id");
        if let Err(e) = std::fs::write(path, elf) {
            eprintln!("write {path}: {e}");
            std::process::exit(1);
        }
        let hex: String = image_id
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        println!("0x{hex}");
        return;
    }

    // CRITICAL: save the real stdout FD for IPC, then redirect FD 1 to stderr so NOTHING
    // the guest (via risc0's POSIX `sys_write`/`sys_log` to fd 1, which `PosixIo::default()` wires to
    // this process's stdout) — nor any native/CUDA library — can inject bytes into the length-prefixed
    // bincode control stream the dispatcher reads. A submitter's ELF could otherwise desync or forge
    // that stream and churn the GPU prover. The SP1 worker does the same for gnark's CGO prints. The
    // worker's own IPC frames go only through the saved descriptor.
    #[cfg(unix)]
    let mut ipc_stdout = {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let stdout_fd = io::stdout().as_raw_fd(); // FD 1
        let ipc_fd = dup_cloexec(stdout_fd).expect("dup(stdout) failed");
        unsafe { libc::dup2(io::stderr().as_raw_fd(), stdout_fd) };
        unsafe { std::fs::File::from_raw_fd(ipc_fd) }
    };
    #[cfg(not(unix))]
    let mut ipc_stdout = io::stdout();

    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Load (or create) the `sys_rand` key now, outside any job: a failure inside a job's panic
    // containment would be blamed on that job's program.
    sys_rand_key();

    #[cfg(feature = "macos")]
    if let Err(error) = macos::preflight() {
        tracing::error!("macOS worker unavailable: {error:#}");
        let _ = write_message(&mut ipc_stdout, &WorkerResponse::Error {
            request_id: 0, kind: ErrorKind::ProofFailed,
            message: format!("macOS worker unavailable: {error:#}"),
        });
        std::process::exit(1);
    }

    if let Err(e) = run_worker_loop(ipc_stdout) {
        tracing::error!("Worker fatal error: {e}");
        std::process::exit(1);
    }
}

fn run_worker_loop(ipc_stdout: impl io::Write) -> Result<()> {
    let mut stdin = BufReader::new(io::stdin().lock());
    let mut stdout = BufWriter::new(ipc_stdout);

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
                #[cfg(feature = "macos")]
                if protocol_version != PROTOCOL_VERSION {
                    write_message(&mut stdout, &WorkerResponse::Error {
                        request_id: 0, kind: ErrorKind::ProtocolError,
                        message: format!("expected protocol {PROTOCOL_VERSION}, received {protocol_version}"),
                    })?;
                    break;
                }
                tracing::info!("Hello from host (protocol v{protocol_version})");
                let resp = WorkerResponse::HelloAck {
                    protocol_version: PROTOCOL_VERSION,
                    backend: BACKEND_RISC0.to_string(),
                    sdk_version: format!("risc0-zkvm {}", risc0_zkvm::VERSION),
                    worker_version: WORKER_VERSION.to_string(),
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Capabilities => {
                let (gpu_available, gpu_name) = detect_gpu();
                #[cfg(feature = "macos")]
                let supported_benchmarks = vec![BENCH_FIBONACCI.to_string(), BENCH_SHA256_CHAIN.to_string()];
                #[cfg(not(feature = "macos"))]
                let supported_benchmarks = vec![BENCH_FIBONACCI.to_string(), BENCH_SHA256_CHAIN.to_string(),
                    BENCH_ECDSA_VERIFY.to_string(), BENCH_BIGINT_MUL.to_string(), BENCH_MEMORY_MERKLE.to_string(), BENCH_CHACHA_MIX.to_string()];
                let resp = WorkerResponse::CapabilitiesReport {
                    backend: BACKEND_RISC0.to_string(),
                    version: risc0_zkvm::VERSION.to_string(),
                    supported_benchmarks,
                    gpu_available,
                    gpu_name,
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Benchmark => {
                tracing::info!("Running benchmarks...");
                let results = run_benchmarks_streaming(&mut stdout)?;
                let resp = WorkerResponse::BenchmarkResult { results };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Prove {
                request_id,
                elf,
                input_data,
                po2,
                program_id,
            } => {
                tracing::info!(
                    "Proving request {request_id} ({} bytes ELF, po2={po2:?})",
                    elf.len()
                );
                // Announce that proving has STARTED. `WorkerResponse::Progress` had exactly one
                // reference in the whole workspace — the arm that consumes it — so no worker
                // ever emitted one and the dispatcher's `on_progress` callback was dead code.
                // The miner uses that callback to move a job from Queued to Proving, so without
                // this a job claimed ahead of a free GPU displayed "Queued (waiting for GPU)"
                // for the entire proof: the opposite of the truth, and worse than the
                // "Proving 0%" it replaced. Sent once, at the transition that matters.
                let started = WorkerResponse::Progress {
                    request_id,
                    fraction: 0.0,
                    elapsed_secs: 0.0,
                    segments: None,
                };
                write_message(&mut stdout, &started)?;
                // A crafted ELF that EXECUTES cleanly (so it measures feasible and gets
                // CLAIMED) can still panic in risc0's prove-only path (image-id/proving on an
                // adversarial-but-executable program). Without containment the worker dies on a CLAIMED
                // job, the dispatcher charges a healthy slot, the retry loop re-dispatches the same job
                // to every GPU crashing each, and the program is never classed bad — so it is cheaply
                // repeatable and drives a release-penalty/slash. Contain it here and answer with an
                // error (typed by what panicked, below) instead of dying.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    #[cfg(feature = "macos")]
                    {
                        verify_program_id(&elf, program_id)?;
                        if program_id.is_some() { job_segment_po2(po2)?; }
                        macos::prove(request_id, &elf, &input_data, po2)
                    }
                    #[cfg(not(feature = "macos"))]
                    { run_proof(&elf, &input_data, po2, program_id) }
                }));
                match outcome {
                    Ok(Ok((journal, seal, duration_secs, cycles))) => {
                        let resp = WorkerResponse::ProofResult {
                            request_id,
                            journal,
                            seal,
                            duration_secs,
                            cycles,
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                    Err(panic) => {
                        // A prove-path panic is usually OURS: risc0's CUDA HAL panics on a failed
                        // allocation or GPU call (`.unwrap()` / `panic!` in hal/cuda.rs). It does not
                        // say the job is bad, so it must never be typed InvalidInput. OOM routes to a
                        // bigger card; anything else is a sick worker to replace.
                        let detail = panic
                            .downcast_ref::<String>()
                            .map(String::as_str)
                            .or_else(|| panic.downcast_ref::<&str>().copied())
                            .unwrap_or("");
                        let kind = if is_gpu_oom(detail) || detail.contains("allocation failed") {
                            ErrorKind::ResourceExhausted
                        } else {
                            ErrorKind::Internal
                        };
                        let resp = WorkerResponse::Error {
                            request_id,
                            kind,
                            message: format!("risc0 prover panicked: {detail}"),
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                    Ok(Err(e)) => {
                        let msg = format!("{e:#}");
                        let lower = msg.to_ascii_lowercase();
                        // A guest-execution fault must be classified BEFORE is_gpu_oom. risc0 wraps a
                        // guest panic as "Guest panicked: <msg>" — a host-generated prefix followed by
                        // the guest's OWN text. Feeding that whole string to is_gpu_oom let a guest
                        // panic with "out of memory" and steer ITSELF onto a worker kill+respawn and a
                        // bigger-card retry — the self-classification the typed `kind` was meant to
                        // prevent. A guest that faults in the prove-only path is a BAD JOB, not a sick
                        // worker: classify InvalidInput and never let its text reach is_gpu_oom.
                        // (Session-/cycle-limit are too-heavy bad jobs; their text is host-generated.)
                        // "Unknown syscall: <name>" quotes a GUEST-chosen string (and has no panic
                        // prefix), so it is matched here, before any classifier reads the text.
                        let kind = if lower.contains("guest panicked")
                            || lower.starts_with("unknown syscall")
                            || lower.contains(": unknown syscall")
                            || lower.contains("session limit")
                            || lower.contains("exceeded cycle")
                            || lower.contains("non-zero exit code")
                        {
                            ErrorKind::InvalidInput
                        } else if msg.contains("does not match job programId") {
                            // The served ELF's image id is not this job's programId — permanent for the
                            // program. Report ProgramMismatch so the host stops claiming its jobs.
                            ErrorKind::ProgramMismatch
                        } else if is_gpu_oom(&msg) {
                            // GPU OOM — host/driver text (guest faults are handled above): tag
                            // ResourceExhausted so the dispatcher kills + respawns this worker with a
                            // clean GPU context (a wedged/leaked context would fail every later proof).
                            ErrorKind::ResourceExhausted
                        } else if msg.contains("po2 value") || msg.contains("out of valid range") {
                            // Bad job (wrong po2), not a sick worker: InvalidInput so the dispatcher
                            // does not kill+respawn a healthy worker.
                            ErrorKind::InvalidInput
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

            WorkerCommand::Execute {
                request_id,
                elf,
                input_data,
                program_id,
                po2,
            } => {
                tracing::info!(
                    "Execute request {request_id} ({} bytes ELF, po2={po2:?})",
                    elf.len()
                );
                // The ELF bytes are fully attacker-controlled and reach risc0's ELF
                // parser / image-id computation / executor UNCLAIMED on this pre-claim measurement
                // path. Those SDK calls CAN PANIC on a malformed registered ELF rather than returning
                // Err (the SP1 worker's Execute arm documents and guards the identical hazard). An
                // unguarded panic unwinds out of this loop and kills the worker PROCESS; the dispatcher
                // then sees a bare EOF (non-intentional), scores a HEALTHY slot as failed, and the host
                // never classes the program as bad — so the crash repeats on every respawn, a free
                // sustained liveness DoS. Contain it here: a caught panic is a property of the job
                // (InvalidInput), exactly like an execution Err.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_execute(&elf, &input_data, program_id, po2)
                }));
                match outcome {
                    Ok(Ok((cycles, journal, duration_secs))) => {
                        tracing::info!(
                            "Execute {request_id}: {cycles} cycles in {duration_secs:.2}s"
                        );
                        let journal_len = journal.len() as u64;
                        let resp = WorkerResponse::ExecuteResult {
                            request_id,
                            cycles,
                            duration_secs,
                            journal_len,
                            // The host checks the job's journal binding against these bytes. One no
                            // fulfil could carry is reported by its length alone, and so is one a
                            // proof on another worker may not reproduce (a process-only seed key).
                            journal: (journal.len() <= EXECUTE_JOURNAL_MAX_BYTES
                                && sys_rand_key_is_shared())
                            .then_some(journal),
                            // risc0 is bounded by its own in-process RSS self-guard + the ledger charge
                            // (finding H4), not by the SP1-only prove-stacking claim gate (H1), so it
                            // reports no peak: 0 = "unknown", which leaves `sp1_execute_provable_beside_
                            // server` ungated for risc0 (it is only consulted for SP1 anyway).
                            peak_host_bytes: 0,
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                    Ok(Err(e)) => {
                        let msg = format!("{e:#}");
                        // Execution failure is NOT proof failure: the guest may simply panic
                        // on this input, which is a property of the job, not of this worker.
                        // Report InvalidInput so the dispatcher does not kill and respawn a
                        // perfectly healthy worker over a bad job.
                        let resp = WorkerResponse::Error {
                            request_id,
                            kind: ErrorKind::InvalidInput,
                            message: msg,
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                    Err(_panic) => {
                        // risc0 panicked parsing/executing this attacker ELF. Same
                        // disposition as an execution Err — a bad program, not a sick worker — so the
                        // slot stays healthy and the host can negative-cache the program.
                        let resp = WorkerResponse::Error {
                            request_id,
                            kind: ErrorKind::InvalidInput,
                            message: "risc0 executor panicked while sizing this ELF (malformed or hostile program)"
                                .to_string(),
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                }
            }

            WorkerCommand::Cancel { request_id } => {
                // Best-effort cancellation. Current risc0 proving is synchronous,
                // so we can only acknowledge after the fact.
                tracing::info!("Cancel requested for {request_id}");
                let resp = WorkerResponse::Cancelled { request_id };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Warmup { request_id } => {
                #[cfg(feature = "macos")]
                let resp = WorkerResponse::WarmupDone {
                    request_id, summary: macos::warmup_summary(), groth16_helper: true,
                };
                #[cfg(not(feature = "macos"))]
                let resp = match warm_up() {
                    Ok(summary) => WorkerResponse::WarmupDone {
                        request_id,
                        summary,
                        groth16_helper: false,
                    },
                    Err(e) => WorkerResponse::Error {
                        request_id,
                        kind: ErrorKind::Internal,
                        message: format!("warm-up failed: {e:#}"),
                    },
                };
                write_message(&mut stdout, &resp)?;
            }

            WorkerCommand::Shutdown => {
                tracing::info!("Shutdown requested, exiting");
                break;
            }

            WorkerCommand::CalibrateSegmentLimit { request_id, po2 } => {
                tracing::info!("Po2 calibration requested at po2={po2}");
                match run_po2_calibration(request_id, po2) {
                    Ok(resp) => write_message(&mut stdout, &resp)?,
                    Err(e) => {
                        let resp = WorkerResponse::Error {
                            request_id,
                            kind: ErrorKind::ProofFailed,
                            message: format!("Po2 calibration failed: {e:#}"),
                        };
                        write_message(&mut stdout, &resp)?;
                    }
                }
            }
        }
    }

    Ok(())
}

fn detect_gpu() -> (bool, Option<String>) {
    #[cfg(feature = "macos")]
    return macos::capabilities();
    #[cfg(feature = "cuda")]
    {
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
    }
    #[cfg(feature = "rocm")]
    {
        // Try rocm-smi first (more reliable than sysfs product_name)
        if let Ok(output) = std::process::Command::new("rocm-smi")
            .args(["--showproductname"])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    if line.contains("Card Series") {
                        if let Some(name) = line.split(':').nth(1) {
                            let name = name.trim().to_string();
                            if !name.is_empty() {
                                return (true, Some(name));
                            }
                        }
                    }
                }
            }
        }
        // Fallback: check sysfs for any AMD GPU
        if std::path::Path::new("/dev/kfd").exists() {
            return (true, Some("AMD GPU".to_string()));
        }
    }
    #[cfg(feature = "intel")]
    {
        // The host pins this worker to one card through ZE_AFFINITY_MASK, which sysfs does not see;
        // name the card only when the box has exactly one Intel GPU, so the name is never another
        // card's. The host names its slots from its own discovery either way.
        let names: Vec<String> = std::fs::read_dir("/sys/class/drm")
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with("card") && !n.contains('-')
            })
            .filter_map(|e| {
                let dev = e.path().join("device");
                let vendor = std::fs::read_to_string(dev.join("vendor")).ok()?;
                (vendor.trim().eq_ignore_ascii_case("0x8086") && dev.join("tile0").is_dir()).then(
                    || {
                        std::fs::read_to_string(dev.join("label"))
                            .ok()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty())
                            .unwrap_or_else(|| "Intel GPU".to_string())
                    },
                )
            })
            .collect();
        match names.as_slice() {
            [] => {}
            [one] => return (true, Some(one.clone())),
            _ => return (true, Some("Intel GPU".to_string())),
        }
    }
    (false, None)
}

/// Execute the guest WITHOUT proving, returning its true cycle count.
///
/// This is the RISC-V simulator: it runs the program to completion and reports
/// `total_cycles` — the same quantity `ProofResult.cycles` carries — at execution cost
/// rather than proving cost. On the measured rig a 92.8M-cycle job proves in ~40s on a 5090;
/// executing it is a small fraction of that, because no STARK is generated.
///
/// Deliberately uses the default (CPU) executor: this is a sizing measurement, so it must not
/// contend for the GPU that the proofs it sizes are running on.
/// True when `image_id` (a risc0 guest image id, 32 bytes) corresponds to the on-chain `program_id`.
///
/// NATIVE byte order only (`Digest::as_bytes`). The deployed HemiProve v2 risc0 adapter passes the
/// job's programId VERBATIM as the image id to the risc0-ethereum verifier
/// (`verify(seal, programId, sha256(journal))`, RiscZeroGroth16VerifierAdapter), and zkminer pins that
/// adapter's code at startup — so only the native order can ever verify. Accepting the byte-reversed
/// order too (as the v1 binding did) let a submitter register `reverse(imageId)` and have us claim,
/// prove and publish a proof the adapter must reject (`VerifierCallFailed`), releasing at a penalty.
fn image_id_matches(image_id: &[u8], program_id: &[u8; 32]) -> bool {
    image_id == program_id.as_slice()
}

/// Set `ZKMINER_RISC0_SKIP_PROGRAM_ID_CHECK=1` to disable the image-id↔programId binding (only for a
/// deployment whose risc0 programId is NOT the raw image id). Enforced by default.
fn program_id_check_disabled() -> bool {
    matches!(
        std::env::var("ZKMINER_RISC0_SKIP_PROGRAM_ID_CHECK")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

/// Refuse to run an ELF whose computed risc0 image id does not match the job's on-chain `programId`,
/// and return that image id (the guest's `sys_rand` seed is derived from it). The match is skipped
/// when the host did not supply a programId (benchmark/calibration/mock) or the check is disabled.
/// Catches a submitter who registers programId X but serves an ELF for a different program,
/// *before* a full Groth16 proof (or a sizing execute) is spent on a proof the chain will reject.
fn verify_program_id(elf: &[u8], program_id: Option<[u8; 32]>) -> anyhow::Result<[u8; 32]> {
    let image_id =
        risc0_zkvm::compute_image_id(elf).context("compute_image_id for programId binding")?;
    let image_bytes: [u8; 32] = image_id
        .as_bytes()
        .try_into()
        .expect("a digest is 32 bytes");
    let Some(pid) = program_id else {
        return Ok(image_bytes);
    };
    if program_id_check_disabled() || image_id_matches(image_id.as_bytes(), &pid) {
        Ok(image_bytes)
    } else {
        anyhow::bail!(
            "ELF image id {image_id} does not match job programId {} (served ELF is not the \
             registered program) — refusing to prove",
            risc0_zkvm::Digest::from(pid)
        );
    }
}

/// Cycle cap for the pre-claim EXECUTE (sizing) path. A runaway guest here is a free DoS lever (no
/// claim, no collateral at stake), and the result is only a sizing estimate. The cap is set BELOW the
/// cycles a non-terminating guest could reach inside the host's ~120 s measure watchdog, so a runaway
/// trips risc0's clean "Session limit exceeded" error — which the host classifies as "too heavy" and
/// negative-caches — rather than the watchdog SIGKILL (indistinguishable from a transient crash). 2e9
/// is still ~21× the largest proof observed on this market (~9.3e7), so it cannot false-cap a real
/// job. Override with `ZKMINER_RISC0_EXECUTE_MAX_CYCLES` (0 = unlimited).
#[cfg(not(feature = "macos"))]
fn execute_session_cycle_limit() -> Option<u64> {
    const DEFAULT: u64 = 2_000_000_000;
    match std::env::var("ZKMINER_RISC0_EXECUTE_MAX_CYCLES") {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(_) => Some(DEFAULT),
        },
        Err(_) => Some(DEFAULT),
    }
}

/// Optional cycle cap for the PROVE path, honoured only when the operator sets
/// `ZKMINER_RISC0_MAX_SESSION_CYCLES`. Unset = SDK default (no cap), so a legitimately large proof
/// is never cut short by surprise.
#[cfg(not(feature = "macos"))]
fn prove_session_cycle_limit() -> Option<u64> {
    std::env::var("ZKMINER_RISC0_MAX_SESSION_CYCLES")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
}

/// Host-RAM ceiling (bytes) for the IN-PROCESS pre-claim execute. risc0's `default_executor().execute()`
/// runs the submitter-controlled guest in THIS process with only a cycle cap — no RSS bound — so a
/// crafted guest can balloon host memory and, on a box co-hosting a warm SP1 server, OOM-kill it
/// (finding H4). The dispatcher charges this execute `RISC0_EXECUTE_PEAK_BYTES` (8 GiB, == this
/// ceiling) to the shared ledger so it is admitted only when it fits; this ceiling is the matching
/// ENFORCEMENT (charge == enforced cap) — if the execute's resident set crosses it, the worker aborts
/// itself, converting an uncontained host-OOM into a bounded slot failure (dispatcher respawns; the
/// job strike-negative-caches). On a dedicated risc0 MEASURE worker (finding TR1) that abort kills only
/// the throwaway measure process, never the warm prover. The dispatcher sets this env to
/// `RISC0_EXECUTE_PEAK_BYTES` on measure workers; override it (0 = unlimited) to raise the ceiling,
/// but then size the host reserve up, since the ledger charge stays at 8 GiB.
fn execute_max_rss_bytes() -> Option<u64> {
    const DEFAULT: u64 = 8 * 1024 * 1024 * 1024;
    match std::env::var("ZKMINER_RISC0_EXECUTE_MAX_RSS_BYTES") {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(_) => Some(DEFAULT),
        },
        Err(_) => Some(DEFAULT),
    }
}

/// This process's current resident set (VmRSS) in bytes, from `/proc/self/status`. `None` off-Linux or
/// on a read error (→ the self-guard simply does not fire, same as having no bound).
#[cfg(target_os = "linux")]
fn self_vmrss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|kb| kb.saturating_mul(1024));
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn self_vmrss_bytes() -> Option<u64> {
    None
}

/// Run `f` while a background thread watches this process's resident set; if it crosses
/// `limit_bytes`, abort the worker to contain the in-process execute balloon (finding H4). Returns
/// `f`'s result on the normal path. `limit_bytes == None` → no guard.
fn with_rss_self_guard<T>(limit_bytes: Option<u64>, f: impl FnOnce() -> T) -> T {
    let Some(limit) = limit_bytes else {
        return f();
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let stop = Arc::new(AtomicBool::new(false));
    let handle = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Some(rss) = self_vmrss_bytes() {
                    if rss > limit {
                        tracing::error!(
                            "risc0 execute resident set {} MiB exceeded the {} MiB self-guard — \
                             aborting the worker to contain the in-process balloon before it OOMs the \
                             host (ZKMINER_RISC0_EXECUTE_MAX_RSS_BYTES)",
                            rss / (1024 * 1024),
                            limit / (1024 * 1024)
                        );
                        std::process::exit(101);
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
    };
    // Stop + join via Drop so a PANIC out of `f` (the executor is `catch_unwind`-wrapped at the call
    // site) still tears the guard thread down, rather than leaking one looping thread per panicking
    // submission.
    struct Guard {
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }
    let mut guard = Guard {
        stop,
        handle: Some(handle),
    };
    let out = f();
    guard.stop.store(true, Ordering::Relaxed);
    if let Some(h) = guard.handle.take() {
        let _ = h.join();
    }
    out
}

/// The seed for the guest's `sys_rand` on one (program, input).
///
/// Unseeded, risc0 answers `sys_rand` with fresh host entropy on every execution, so a guest can
/// branch on its random bytes: measure clean before the claim and fail the proof after it, which
/// costs us the release penalty. The pre-claim measurement and every proving attempt use this seed
/// instead, so they run the guest identically, even in different workers. It is keyed with this
/// host's secret key, so the bytes stay unpredictable to everyone else, as the guest's randomness
/// should be: risc0 also draws the entropy that keeps a receipt's post-state digest from revealing
/// private inputs from it. It hashes the program's IMAGE ID, not its ELF bytes: two ELFs with one
/// image id (one stripped, say) are the same program, and a lock re-driven after a restart may fetch
/// the other one.
fn sys_rand_seed(key: &[u8; 32], image_id: &[u8; 32], input_data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"zkminer/risc0/sys_rand/v2");
    mac.update(image_id);
    mac.update(&Sha256::digest(input_data));
    mac.finalize().into_bytes().into()
}

/// This host's `sys_rand` key, loaded once per process: the one the miner passed in
/// [`SYS_RAND_KEY_ENV`] (it hands the same key to every risc0 worker it spawns), else
/// `~/.zkminer/risc0-sys-rand.key` (created there on first use) for a worker started on its own.
///
/// If neither can be used, the worker keys its seeds for this process alone: its measurements and
/// proofs still agree with each other, but a job measured by another worker can diverge again, so its
/// measurements then report no journal (see [`sys_rand_key_is_shared`]).
fn sys_rand_key() -> [u8; 32] {
    sys_rand_key_state().0
}

/// Whether the seed key is the host's lasting key (its file's, read here or passed by the miner)
/// rather than one for this process or this miner run alone.
fn sys_rand_key_is_shared() -> bool {
    sys_rand_key_state().1
}

fn sys_rand_key_state() -> &'static ([u8; 32], bool) {
    use zkminer_prover_protocol::sys_rand;
    static KEY: std::sync::OnceLock<([u8; 32], bool)> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        if let Ok(v) = std::env::var(sys_rand::SYS_RAND_KEY_ENV) {
            // Out of this process's environment once read, so nothing it starts (nvidia-smi,
            // rocm-smi, docker) inherits it. `main` reads the key before any other thread exists.
            std::env::remove_var(sys_rand::SYS_RAND_KEY_ENV);
            let ephemeral =
                std::env::var(sys_rand::SYS_RAND_KEY_EPHEMERAL_ENV).is_ok_and(|v| v == "1");
            match sys_rand::decode_key(v.trim()) {
                // A key for the miner's run alone keeps this run's workers in step, but a lock
                // re-proved after a restart would not be: report no journal, as for a
                // process-only key.
                Some(key) => return (key, !ephemeral),
                None => tracing::warn!(
                    "{} is not 64 hex digits — ignoring it",
                    sys_rand::SYS_RAND_KEY_ENV
                ),
            }
        }
        let loaded = match dirs::home_dir() {
            Some(home) => sys_rand::load_or_create_key(&sys_rand::key_path(&home))
                .map_err(anyhow::Error::from),
            None => Err(anyhow::anyhow!("no home directory")),
        };
        match loaded {
            Ok(key) => (key, true),
            Err(e) => {
                tracing::warn!(
                    "sys_rand key unavailable ({e:#}): seeding with a key for this process only, so \
                     a job measured here may be proved by another worker with other randomness; \
                     measurements report no journal, and no journal-bound job is claimed on them"
                );
                let mut key = [0u8; 32];
                getrandom::fill(&mut key).expect("no OS randomness for the sys_rand key");
                (key, false)
            }
        }
    })
}

/// What one keccak proof request at the default keccak po2 (17) is charged in a measurement (see
/// `run_execute`): about a 2^20 segment's proving time on the cards this runs on. A larger keccak
/// po2 (RISC0_KECCAK_PO2, up to 18) doubles it per step; a smaller one still pays for the lift and
/// the join, so never less.
const KECCAK_REQUEST_CYCLES: u64 = 1 << 20;

/// The keccak proof requests a measured guest made, checked as the prover will check them.
#[derive(Default)]
struct KeccakAudit {
    /// Each request's claim, as the guest's keccak root commits to it.
    requests: Vec<risc0_zkvm::Assumption>,
    /// What the requests are charged (see [`KECCAK_REQUEST_CYCLES`]).
    cycles: u64,
}

impl risc0_zkvm::CoprocessorCallback for KeccakAudit {
    fn prove_keccak(&mut self, request: risc0_zkvm::ProveKeccakRequest) -> anyhow::Result<()> {
        use risc0_circuit_keccak::{compute_keccak_digest, KECCAK_CONTROL_ROOT};
        // The prover proves the request's input and refuses a claim digest that isn't its output
        // ("keccak claim digest mismatch"); the executor takes the guest's word for it. Ask now.
        let input: Vec<u8> = request
            .input
            .iter()
            .flat_map(|state| state.iter().flat_map(|w| w.to_ne_bytes()))
            .collect();
        anyhow::ensure!(
            request.control_root == KECCAK_CONTROL_ROOT
                && request.claim_digest == compute_keccak_digest(&input),
            "a keccak proof request does not match its input — every proof would fail"
        );
        self.requests.push(risc0_zkvm::Assumption {
            claim: request.claim_digest,
            control_root: KECCAK_CONTROL_ROOT,
        });
        self.cycles = self
            .cycles
            .saturating_add(KECCAK_REQUEST_CYCLES << request.po2.saturating_sub(17).min(8));
        Ok(())
    }
}

impl KeccakAudit {
    /// The root assumption a guest's keccak batcher verifies over these requests: risc0's
    /// Merkle-mountain accumulator of them, a lone request standing for itself (`mmr.rs`).
    fn root(&self) -> Option<risc0_zkvm::Assumption> {
        use risc0_zkvm::sha::Digestible;
        let merge = |a: &risc0_zkvm::Assumption, b: &risc0_zkvm::Assumption| {
            let (x, y) = (a.digest(), b.digest());
            let (left, right) = if x <= y { (x, y) } else { (y, x) };
            risc0_zkvm::Assumption {
                claim: risc0_zkvm::UnionClaim { left, right }.digest(),
                control_root: risc0_zkvm::ALLOWED_CONTROL_ROOT,
            }
        };
        let mut peaks: Vec<(risc0_zkvm::Assumption, u32)> = Vec::new();
        for request in &self.requests {
            let mut add = (request.clone(), 0);
            while let Some(top) = peaks.last() {
                if top.1 != add.1 {
                    break;
                }
                let (top, height) = peaks.pop().expect("just seen");
                add = (merge(&add.0, &top), height + 1);
            }
            peaks.push(add);
        }
        let mut peaks = peaks.into_iter().map(|(a, _)| a);
        let first = peaks.next()?;
        Some(peaks.fold(first, |acc, peak| merge(&acc, &peak)))
    }
}

/// The segment size a job is executed or proven at: the host's, or [`RISC0_DEFAULT_JOB_PO2`]. One
/// outside [`RISC0_JOB_PO2_MIN`]..=[`RISC0_JOB_PO2_MAX`] is refused (an InvalidInput, by its "po2
/// value" text): the host measures and proves a job at sizes in that range only.
fn job_segment_po2(po2: Option<u8>) -> anyhow::Result<u8> {
    #[cfg(feature = "macos")]
    {
        // The local Mac worker also accepts po2 14/15 for bounded diagnostic
        // proofs. `macos::bound_env` checks the selected mode's exact limits.
        let default = if cfg!(feature = "macos-native-wrap") {
            zkminer_prover_protocol::macos::DEFAULT_NATIVE_SEGMENT_PO2
        } else {
            18
        };
        return Ok(po2.unwrap_or(default));
    }
    #[cfg(not(feature = "macos"))]
    {
    let po2 = po2.unwrap_or(RISC0_DEFAULT_JOB_PO2);
    if !(RISC0_JOB_PO2_MIN..=RISC0_JOB_PO2_MAX).contains(&po2) {
        anyhow::bail!(
            "po2 value {po2} is outside the job range {RISC0_JOB_PO2_MIN}..={RISC0_JOB_PO2_MAX}"
        );
    }
    Ok(po2)
    }
}

fn run_execute(
    elf: &[u8],
    input_data: &[u8],
    program_id: Option<[u8; 32]>,
    po2: Option<u8>,
) -> anyhow::Result<(u64, Vec<u8>, f64)> {
    use std::time::Instant;
    let po2 = job_segment_po2(po2)?;
    // Bind the ELF to the job's programId before spending any execution on it (the pre-claim
    // measurement path runs UNCLAIMED, submitter-controlled ELFs).
    let image_id = verify_program_id(elf, program_id)?;
    let started = Instant::now();

    let mut env_builder = risc0_zkvm::ExecutorEnv::builder();
    #[cfg(feature = "macos")]
    macos::bound_env(&mut env_builder, Some(po2))?;
    if !input_data.is_empty() {
        env_builder.write_slice(input_data);
    }
    env_builder.random_seed(sys_rand_seed(&sys_rand_key(), &image_id, input_data));
    // At the size the job will be proven at, on the card the host asked for: the guest can tell (see
    // `RISC0_DEFAULT_JOB_PO2`).
    env_builder.segment_limit_po2(po2 as u32);
    #[cfg(not(feature = "macos"))]
    if let Some(limit) = execute_session_cycle_limit() {
        env_builder.session_limit(Some(limit));
    }
    // Here only, never on a prove: a callback takes the keccak requests the prover must prove.
    let keccak = std::rc::Rc::new(std::cell::RefCell::new(KeccakAudit::default()));
    env_builder.coprocessor_callback_ref(keccak.clone());
    let env = env_builder
        .build()
        .map_err(|e| anyhow::anyhow!("execute: env build failed: {e}"))?;

    // In-process RSS self-guard (finding H4): contain a ballooning guest before it OOMs the host.
    let session = with_rss_self_guard(execute_max_rss_bytes(), || {
        // The in-process executor, never one chosen by RISC0_EXECUTOR (an external r0vm).
        risc0_zkvm::local_executor().execute(env, elf)
    })
    .map_err(|e| anyhow::anyhow!("execute: {e}"))?;
    #[cfg(feature = "macos")]
    macos::check_guest_cycles(session.cycles())?;

    // A guest that does not halt with exit code 0 can NEVER produce a receipt that
    // `receipt.verify(image_id)` accepts (verify builds the expected claim as Halted(0)), so this
    // (program, input) is permanently unprovable and unfulfillable. Reject it HERE, on the pre-claim
    // measure path, so the host strike-negative-caches it per (program, input) and never claims it —
    // instead of sizing it feasible, locking collateral on a claim, then force-releasing at a penalty
    // when the proof is rejected post-prove. Deterministic for (ELF, input); a legitimate job halts 0.
    match session.exit_code {
        risc0_zkvm::ExitCode::Halted(0) => {}
        other => {
            anyhow::bail!(
                "execute: guest did not halt successfully (exit {other:?}) — a non-zero exit code can \
                 never produce an accepted proof for this program+input"
            );
        }
    }

    // A guest that halts with no output (a zero output digest: `sys_halt` skipped `env::finalize`)
    // executes cleanly and proves, but its receipt never verifies — a claim without an output is not
    // what `receipt.verify(image_id)` or the chain accept. An honest guest always has one, if empty.
    // (One that halts with a non-zero digest other than its output's, the pinned executor refuses
    // itself, as it does a bigint2 witness its verify program rejects.)
    let output = session
        .receipt_claim
        .as_ref()
        .and_then(|c| c.output.as_value().ok())
        .and_then(|o| o.as_ref())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "execute: the guest halted without an output — no proof of this program+input can \
                 verify"
            )
        })?;
    // Everything the proof would assume must be something it also proves: the guest's keccak root.
    // Anything else (an `env::verify_assumption2` of an arbitrary claim) executes cleanly here and
    // fails every proof ("no receipt available for unresolved assumption").
    let keccak = keccak.borrow();
    let root = keccak.root();
    let assumptions = output
        .assumptions
        .as_value()
        .map_err(|_| anyhow::anyhow!("execute: the session's assumptions are pruned"))?;
    for a in &assumptions.0 {
        if a.as_value().ok() != root.as_ref() {
            anyhow::bail!(
                "execute: the guest assumes a claim no proof here resolves — every proof of this \
                 program+input would fail"
            );
        }
    }

    // What proving costs, and reports as `total_cycles`: every segment padded to its power of two.
    // `SessionInfo::cycles()` counts user cycles only — no paging, no padding — and a guest that
    // pages heavily (each page-in costs hundreds of cycles) can make a proof 100x what it shows.
    // Measured at `po2`, the size the job proves at on its card. Each keccak request is a further
    // proof of its own (a 2^17-row keccak STARK, its lift and a join), priced here as a 2^20 segment.
    let cycles: u64 = session.segments.iter().map(|s| 1u64 << s.po2).sum::<u64>() + keccak.cycles;
    // The journal the guest committed here is byte-identical to the one the later proof
    // would carry at this segment size (both are a deterministic function of (ELF, input) at the size
    // both run at, which a guest can tell — `sys_rand` included, via the shared seed — and the image-id
    // check makes measure-ELF == prove-ELF). The host checks the job's journal binding against it,
    // and screens a journal that would blow the fulfillJob payload cap, before committing
    // collateral and a full proof to it.
    Ok((
        cycles,
        session.journal.bytes,
        started.elapsed().as_secs_f64(),
    ))
}

/// Cards with less VRAM than this release the Groth16 SRS cache after every proof.
///
/// Set between the two cards that were measured. On the 16.3 GB RTX 5080 the cache stays resident
/// at ~7.25 GB between proofs, and the next 46M-cycle STARK at po2 20 then peaked at 15,834 MiB — 469
/// MiB from the card's capacity — and in the benchmark's program order failed outright. Releasing it
/// dropped the idle worker to 2,452 MiB and that peak to 12,436 MiB. On the 24.6 GB RTX 4090 the same
/// proof leaves ~8 GB spare, so it keeps the cache.
///
/// The saving from keeping it turned out small: wraps after a release ran 2.08-2.12 s on the 5080
/// against 2.01-2.05 s on the cache-keeping 4090, so at most ~0.1 s. The threshold is therefore cheap to
/// get wrong in the conservative direction, which is why an unknown size releases.
#[cfg(not(feature = "macos"))]
const RELEASE_GROTH16_CACHE_BELOW_BYTES: u64 = 20 * 1024 * 1024 * 1024;

/// Free the Groth16 prover and SRS cached on the GPU if this card cannot also hold the next STARK.
///
/// The cache is the Groth16 prover's: `shrink_wrap` uploads the SRS once and keeps it for the life of
/// the process, in a C++ static nothing frees. Whether to drop it is a property of the CARD, which the
/// library cannot see from where it sits, so the decision lives here. The card's size arrives from the
/// dispatcher in `CUDA_VRAM_BYTES_ENV`: `nvidia-smi` ignores `CUDA_VISIBLE_DEVICES`, so this pinned
/// worker cannot ask about its own card. When the size is UNKNOWN the cache is released — that costs
/// at most ~0.1 s per proof, while keeping it on a card that cannot afford it costs the proof.
///
/// Called whether the proof succeeded or not: a wrap that failed part-way can still have built the
/// cache, and the retry that follows needs the room most.
#[cfg(not(feature = "macos"))]
fn release_groth16_cache_if_tight() {
    static DECISION: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let release = *DECISION.get_or_init(|| {
        let total = std::env::var(CUDA_VRAM_BYTES_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok());
        let release = total.is_none_or(|t| t < RELEASE_GROTH16_CACHE_BELOW_BYTES);
        match total {
            Some(t) => tracing::info!(
                "card has {:.1} GiB of VRAM: {} the Groth16 SRS cache between proofs",
                t as f64 / (1u64 << 30) as f64,
                if release { "releasing" } else { "keeping" },
            ),
            None => tracing::info!(
                "card VRAM unknown ({CUDA_VRAM_BYTES_ENV} unset): releasing the Groth16 SRS cache \
                 between proofs"
            ),
        }
        release
    });
    if release {
        if let Err(e) = risc0_groth16::prove::release_srs() {
            tracing::warn!("could not release the Groth16 SRS cache: {e:#}");
        }
    }
}

/// The in-process prover, never one `RISC0_PROVER` names (an external r0vm, or a remote service,
/// which would also refuse our `sys_rand` seed). Every caller pairs it with options built with dev
/// mode off, whatever `RISC0_DEV_MODE` says: a dev-mode receipt is fake, and claiming on one ends in a
/// penalized release.
#[cfg(not(feature = "macos"))]
fn local_prover() -> risc0_zkvm::LocalProver {
    risc0_zkvm::LocalProver::new("local")
}

#[cfg(not(feature = "macos"))]
fn run_proof(
    elf: &[u8],
    input_data: &[u8],
    po2: Option<u8>,
    program_id: Option<[u8; 32]>,
) -> Result<(Vec<u8>, Vec<u8>, f64, u64)> {
    // Bind the ELF to the job's programId ONCE, before the retry loop spends any GPU on it.
    let image_id = verify_program_id(elf, program_id)?;
    // A job (bound to a programId) proves at a size the host measured it at, which is always in the
    // job range; other sizes are for benchmarks and calibration.
    if program_id.is_some() {
        job_segment_po2(po2)?;
    }
    // The seed the pre-claim measurement used, so every attempt runs the guest exactly as it did.
    let seed = sys_rand_seed(&sys_rand_key(), &image_id, input_data);
    // Retry-on-invalid mitigation for the rare (~1.5%) nondeterministic GPU
    // timing race on RTX 5090 / Blackwell (sm_120) — an intra-kernel race
    // produces an internally-invalid segment STARK, surfaced as
    // "verify segment: verification indicates proof is invalid" (or a failed
    // receipt.verify). It is NOT reproducible for the same input: a fresh prove
    // almost always succeeds. Re-proving on that error class makes the effective
    // failure rate negligible (~1.5% -> ~0.02% with one retry) and guarantees we
    // never return — and never lose stake on (see below) — a corrupt proof.
    // Bounded so a genuine, deterministic failure (bad ELF, real OOM) still
    // surfaces instead of looping. Only the GPU-corruption error class is retried.
    const MAX_ATTEMPTS: usize = 4;
    let mut last_err: Option<anyhow::Error> = None;
    // The segment the last invalid proof failed at. A race lands on a segment at random; the same
    // one failing twice is a witness the circuit rejects (a guest the measurement missed) or a fault
    // of this card's, and re-proving here would only spend it again. Reported as a failed proof, so
    // the host tries another card.
    let mut last_failed_segment: Option<u64> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match run_proof_once(elf, input_data, po2, seed) {
            Ok(result) => {
                if attempt > 1 {
                    tracing::warn!(
                        "Proof succeeded on attempt {attempt}/{MAX_ATTEMPTS} after retrying a (nondeterministic) invalid-proof error"
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                let msg = format!("{e:#}").to_lowercase();
                // A guest-execution fault carries guest-controlled text ("Guest panicked: <msg>"), so
                // it must never match the recoverable-retry predicate below — otherwise a guest could
                // panic with "receipt is invalid" and buy itself MAX_ATTEMPTS full re-proves of wasted
                // GPU. The genuine GPU-corruption signals this retry targets are host-generated (segment
                // verification / receipt.verify), never wrapped as a guest panic.
                let guest_fault = msg.contains("guest panicked")
                    || msg.contains("session limit")
                    || msg.contains("non-zero exit code")
                    // A seal that VERIFIES but proves another claim than the host built (a guest that
                    // halted with an output digest of its own): deterministic, not a GPU race.
                    || msg.contains("claim digest does not match");
                let recoverable = !guest_fault
                    && (msg.contains("verification indicates")
                        || msg.contains("verify segment")
                        || msg.contains("receipt is invalid")
                        || msg.contains("proof verification failed"));
                let segment = failed_segment(&msg);
                if recoverable && failed_twice(segment, last_failed_segment) {
                    let index = segment.unwrap_or_default();
                    return Err(e.context(format!(
                        "segment {index} failed to verify twice: deterministic, not a GPU race"
                    )));
                }
                last_failed_segment = segment;
                if recoverable && attempt < MAX_ATTEMPTS {
                    tracing::warn!(
                        "Proof attempt {attempt}/{MAX_ATTEMPTS} produced an invalid proof (likely GPU race), re-proving: {e:#}"
                    );
                    last_err = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("proof failed after {MAX_ATTEMPTS} attempts")))
}

/// The index of the segment whose seal did not verify, from the prover's (host-generated) context
/// "verify segment N" or "verify segment (last) N", in `msg` lowercased.
#[cfg(not(feature = "macos"))]
fn failed_segment(msg: &str) -> Option<u64> {
    let rest = msg.split("verify segment ").nth(1)?;
    let rest = rest.strip_prefix("(last) ").unwrap_or(rest);
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Whether an invalid proof failed at the segment the one before it did (both known).
#[cfg(not(feature = "macos"))]
fn failed_twice(segment: Option<u64>, last: Option<u64>) -> bool {
    segment.is_some() && segment == last
}

#[cfg(not(feature = "macos"))]
fn run_proof_once(
    elf: &[u8],
    input_data: &[u8],
    po2: Option<u8>,
    seed: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>, f64, u64)> {
    use risc0_zkvm::ProverOpts;

    // TEST-ONLY: RISC0_TEST_INJECT_INVALID=N makes the first N calls return a
    // synthetic invalid-proof error before proving, to exercise the retry-on-
    // invalid wrapper deterministically (and cheaply, on any guest/GPU).
    if let Ok(n) = std::env::var("RISC0_TEST_INJECT_INVALID") {
        static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let c = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if c < n.parse::<usize>().unwrap_or(0) {
            anyhow::bail!(
                "verify segment: verification indicates proof is invalid (TEST INJECTED)"
            );
        }
    }

    let mut env_builder = risc0_zkvm::ExecutorEnv::builder();
    env_builder.write_slice(input_data);
    env_builder.random_seed(seed);
    // Never left to the SDK, which picks 21 on a 32 GB card: a job is measured at the size the host
    // names here, and the guest can tell the size it runs at.
    let po2 = po2.unwrap_or(RISC0_DEFAULT_JOB_PO2);
    if !(13..=24).contains(&po2) {
        anyhow::bail!("po2 value {po2} out of valid range 13..=24");
    }
    tracing::info!("Setting segment_limit_po2 = {po2}");
    env_builder.segment_limit_po2(po2 as u32);
    if let Some(limit) = prove_session_cycle_limit() {
        tracing::info!("Setting session_limit = {limit} cycles (operator override)");
        env_builder.session_limit(Some(limit));
    }
    let env = env_builder.build()?;

    // Use Groth16 receipt kind for on-chain verifiable proofs.
    // This performs STARK proving followed by Groth16 SNARK compression,
    // producing a constant-size proof (~256 bytes seal) that the on-chain
    // RiscZeroVerifierAdapter can verify.
    let prover = local_prover();
    let opts = ProverOpts::groth16().with_dev_mode(false);
    let start = Instant::now();
    let proved = prover.prove_with_opts(env, elf, &opts);
    release_groth16_cache_if_tight();
    let prove_info = proved?;
    let duration_secs = start.elapsed().as_secs_f64();

    let receipt = prove_info.receipt;

    // Verify proof locally before returning — catches GPU corruption (e.g., ROCm SHA-256 bug)
    let image_id =
        risc0_zkvm::compute_image_id(elf).context("Failed to compute image ID for verification")?;

    // Defense in depth against a guest that halts with a non-zero exit code: `receipt.verify` below
    // builds the expected claim as Halted(0), so a non-zero exit deterministically fails verification
    // with a ClaimDigestMismatch that surfaces as "receipt is invalid" — which the retry wrapper in
    // `run_proof` would otherwise mistake for a (nondeterministic) GPU race and re-prove MAX_ATTEMPTS
    // times. Detect the non-zero exit explicitly and fail with a distinct, NON-recoverable error (it
    // does not match the invalid-proof retry phrases) so it is never retried. The pre-claim measure
    // gate already rejects such a program+input, so reaching here means a stale cached measurement or
    // a race — but we must still never burn repeated Groth16 proofs on a deterministic fault. If the
    // claim is pruned/unreadable this is a no-op and `receipt.verify` runs exactly as before.
    if let Ok(claim) = receipt.claim() {
        if let Ok(rc) = claim.as_value() {
            if !matches!(rc.exit_code, risc0_zkvm::ExitCode::Halted(0)) {
                anyhow::bail!(
                    "guest halted with a non-zero exit code ({:?}) — unprovable program+input, not a \
                     GPU race",
                    rc.exit_code
                );
            }
        }
    }

    receipt.verify(image_id).context(
        "Proof verification FAILED — receipt is invalid, GPU may have produced corrupt output",
    )?;

    let journal = receipt.journal.bytes.clone();

    // Extract the Groth16 seal. With ProverOpts::groth16(), the receipt
    // should always contain a Groth16 inner proof.
    let seal = receipt
        .inner
        .groth16()
        .context("Expected Groth16 receipt but got different proof type")?
        .seal
        .clone();

    tracing::info!(
        "Proof complete: {} journal bytes, {} seal bytes, {:.1}s, {} cycles",
        journal.len(),
        seal.len(),
        duration_secs,
        prove_info.stats.total_cycles,
    );

    let cycles = prove_info.stats.total_cycles;
    Ok((journal, seal, duration_secs, cycles))
}

/// Run benchmarks, sending a BenchmarkProgress message after each program completes.
fn run_benchmarks_streaming<W: std::io::Write>(
    stdout: &mut W,
) -> anyhow::Result<Vec<BenchmarkEntry>> {
    let mut results = Vec::new();
    let bench_only = std::env::var("BENCH_ONLY").ok();

    // All 6 canonical programs matching BENCHMARK_PROGRAMS weights.
    // Input sizes tuned so each completes in 5-30s on a mid-range GPU,
    // keeping total benchmark time under 2 minutes on a 4090.
    #[cfg(feature = "macos")]
    let benchmarks = macos::benchmarks();
    #[cfg(not(feature = "macos"))]
    let benchmarks: &[(&str, &[u8], &[u8], f64, bool)] = &[
        (
            BENCH_FIBONACCI,
            FIBONACCI_ELF,
            &1000u32.to_le_bytes(),
            0.10,
            false,
        ),
        (
            BENCH_SHA256_CHAIN,
            SHA256_CHAIN_ELF,
            &10_000u32.to_le_bytes(),
            0.20,
            true,
        ),
        (
            BENCH_ECDSA_VERIFY,
            ECDSA_VERIFY_ELF,
            &10u32.to_le_bytes(),
            0.25,
            true,
        ),
        (
            BENCH_BIGINT_MUL,
            BIGINT_MUL_ELF,
            &100u32.to_le_bytes(),
            0.10,
            false,
        ),
        (
            BENCH_MEMORY_MERKLE,
            MEMORY_MERKLE_ELF,
            &512u32.to_le_bytes(),
            0.15,
            true,
        ),
        (
            BENCH_CHACHA_MIX,
            CHACHA_MIX_ELF,
            &5_000u32.to_le_bytes(),
            0.20,
            false,
        ),
    ];

    let active: Vec<_> = benchmarks
        .iter()
        .filter(|&&(name, elf, _, _, _)| {
            !elf.is_empty()
                && bench_only
                    .as_ref()
                    .map_or(true, |only| name.eq_ignore_ascii_case(only))
        })
        .collect();
    let total = active.len() as u32;

    for (idx, &&(name, elf, input, weight, precompile)) in active.iter().enumerate() {
        if let Some(entry) = benchmark_program(name, elf, input, weight, precompile) {
            let progress = WorkerResponse::BenchmarkProgress {
                entry: entry.clone(),
                program_index: (idx + 1) as u32,
                total_programs: total,
            };
            write_message(stdout, &progress)?;
            results.push(entry);
        }
    }

    Ok(results)
}

fn run_benchmarks() -> Vec<BenchmarkEntry> {
    let mut results = Vec::new();

    // Check for single-benchmark mode via env var (e.g., BENCH_ONLY=fibonacci)
    let bench_only = std::env::var("BENCH_ONLY").ok();

    // All 6 canonical programs matching BENCHMARK_PROGRAMS weights.
    // Input sizes tuned so each completes in 5-30s on a mid-range GPU,
    // keeping total benchmark time under 2 minutes on a 4090.
    #[cfg(feature = "macos")]
    let benchmarks = macos::benchmarks();
    #[cfg(not(feature = "macos"))]
    let benchmarks: &[(&str, &[u8], &[u8], f64, bool)] = &[
        (
            BENCH_FIBONACCI,
            FIBONACCI_ELF,
            &1000u32.to_le_bytes(),
            0.10,
            false,
        ),
        (
            BENCH_SHA256_CHAIN,
            SHA256_CHAIN_ELF,
            &10_000u32.to_le_bytes(),
            0.20,
            true,
        ),
        (
            BENCH_ECDSA_VERIFY,
            ECDSA_VERIFY_ELF,
            &10u32.to_le_bytes(),
            0.25,
            true,
        ),
        (
            BENCH_BIGINT_MUL,
            BIGINT_MUL_ELF,
            &100u32.to_le_bytes(),
            0.10,
            false,
        ),
        (
            BENCH_MEMORY_MERKLE,
            MEMORY_MERKLE_ELF,
            &512u32.to_le_bytes(),
            0.15,
            true,
        ),
        (
            BENCH_CHACHA_MIX,
            CHACHA_MIX_ELF,
            &5_000u32.to_le_bytes(),
            0.20,
            false,
        ),
    ];

    for &(name, elf, input, weight, precompile) in benchmarks {
        if elf.is_empty() {
            continue;
        }
        if let Some(ref only) = bench_only {
            if !name.eq_ignore_ascii_case(only) {
                continue;
            }
        }
        if let Some(entry) = benchmark_program(name, elf, input, weight, precompile) {
            results.push(entry);
        }
    }

    results
}

#[cfg(feature = "macos")]
fn benchmark_program(
    name: &str, elf: &[u8], input: &[u8], weight: f64, precompile: bool,
) -> Option<BenchmarkEntry> {
    match macos::benchmark(name, elf, input, weight, precompile) {
        Ok(entry) => Some(entry),
        Err(error) => { tracing::error!("{name}: benchmark failed: {error:#}"); None }
    }
}

#[cfg(not(feature = "macos"))]
fn benchmark_program(
    name: &str,
    elf: &[u8],
    input: &[u8],
    weight: f64,
    precompile: bool,
) -> Option<BenchmarkEntry> {
    // At the size an uncalibrated card proves jobs at, so its throughput and host peak describe them.
    // (Its first stage is a composite proof, for which the SDK never picks a size of its own, so this
    // only says what the executor default already was.)
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write_slice(input)
        .segment_limit_po2(RISC0_DEFAULT_JOB_PO2 as u32)
        .build()
        .ok()?;

    // ONE proof, staged, so each stage is timed exactly rather than inferred from two runs.
    //
    // This previously called bare `prove(env, elf)`, i.e. `ProverOpts::default()`, which is
    // `ReceiptKind::Composite`: segment proofs only. That is not what the miner submits. Production
    // (`run_proof_once`) and calibration (`calibrate_segment_limit`) both go to Groth16, so the
    // benchmark measured neither the recursion that folds segments together — whose cost scales with
    // segment count, i.e. with po2 — nor the wrap. `compress` consumes the previous receipt, so the
    // three stages below add up to the same work `prove_with_opts(groth16)` does in one call.
    let prover = local_prover();

    // Stage 1: execution and the segment proofs.
    let started = Instant::now();
    let prove_info = match prover.prove_with_opts(
        env,
        elf,
        &risc0_zkvm::ProverOpts::composite().with_dev_mode(false),
    ) {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("{name}: prove failed: {e:#}");
            return None;
        }
    };
    let composite_secs = started.elapsed().as_secs_f64();

    // Stage 2: lift every segment receipt and join them into one constant-size STARK. Scales with
    // segment count, so it is STARK proving and belongs on the variable side of the split.
    let started = Instant::now();
    let succinct = match prover.compress(
        &risc0_zkvm::ProverOpts::succinct().with_dev_mode(false),
        &prove_info.receipt,
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("{name}: succinct recursion failed: {e:#}");
            return None;
        }
    };
    let recursion_secs = started.elapsed().as_secs_f64();

    // Stage 3: STARK-to-SNARK. Proves the fixed `stark_verify` circuit with a fixed proving key
    // (`~/.risc0/extensions/*-risc0-groth16/stark_verify_final.zkey`), so it does not depend on the
    // program at all — which is the reason to report it apart from the stages above.
    let started = Instant::now();
    let wrapped = prover.compress(
        &risc0_zkvm::ProverOpts::groth16().with_dev_mode(false),
        &succinct,
    );
    let wrap_secs = started.elapsed().as_secs_f64();
    // Outside the stopwatch: the release is not part of the wrap, and on a card that releases, the NEXT
    // wrap pays the reload — which is that card's honest per-proof cost.
    release_groth16_cache_if_tight();
    let groth16 = match wrapped {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("{name}: Groth16 wrap failed: {e:#}");
            return None;
        }
    };

    // Verify the GROTH16 receipt — the artifact production submits — rather than the composite one.
    // It also covers the earlier stages: the recursion circuit verifies every segment proof, so GPU
    // output corruption there (notably the known ROCm SHA-256 bug at scale) cannot reach a valid
    // Groth16 receipt. An unverified benchmark would pollute the throughput cache with numbers from a
    // broken proof and the miner would later lose stake attempting to fulfill with an invalid one.
    let image_id = match risc0_zkvm::compute_image_id(elf) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("{name}: failed to compute image id for verification: {e:#}");
            return None;
        }
    };
    if let Err(e) = groth16.verify(image_id) {
        tracing::error!(
            "{name}: Groth16 receipt.verify() FAILED — benchmark proof is invalid, skipping entry: \
             {e:#}"
        );
        return None;
    }

    let cycles = prove_info.stats.total_cycles;
    // STARK = segments + recursion: everything up to one constant-size proof. `throughput` is over
    // this, not over the total, because the wrap is a fixed cost and folding it into a rate would
    // make a 33k-cycle program look orders of magnitude slower than a 65M-cycle one.
    let duration_secs = composite_secs + recursion_secs;
    let throughput = cycles as f64 / duration_secs;

    tracing::info!(
        "{name}: {cycles} cycles — STARK {duration_secs:.2}s (segments {composite_secs:.2}s + \
         recursion {recursion_secs:.2}s, {throughput:.0} c/s), Groth16 wrap {wrap_secs:.2}s, \
         verified"
    );

    Some(BenchmarkEntry {
        program_name: name.to_string(),
        prover_backend: BACKEND_RISC0.to_string(),
        cycles,
        duration_secs,
        throughput,
        weight,
        precompile,
        wrap_secs: Some(wrap_secs),
    })
}

/// Iteration count for the po2 calibration workload.
///
/// MUST produce a workload spanning several segments at PO2_MAX (2^24 cycles), otherwise
/// the sweep carries NO po2 signal: if the program fits in one segment at every po2 then
/// the measured differences are just warm-up and timer noise, and
/// `zkminer_prover::benchmark::calibration_is_usable` refuses to pick the fastest size from it
/// (argmax(throughput) over noise would pick a card's job size at random).
///
/// Sizing: the fibonacci guest costs a MEASURED ~10.4 cycles/iteration — stable for
/// n >= 100_000 (at small n the reported `total_cycles` is the padded segment size, not
/// the real cost, which is why n=1000 appeared to be ~32.8 cycles/iter).
///   6_000_000 iters ~= 62.4M cycles
///     -> ceil(62.4M / 2^24) = 4 segments at po2=24, ~7% padding
///     -> 62.4M / 2^18      = ~238 segments at po2=18
/// Both ends therefore segment, so the sweep measures the real segment-count trade-off.
///
/// Was 1_000 iterations = 32,768 cycles, which fit in ONE segment at EVERY po2 and made
/// calibration useless (measured on an RTX 5090: segment_count == 1 for po2 18..24).
///
/// Cost: this is a real proof per po2 step, so a full sweep is minutes per GPU. That is
/// why calibration is opt-in (`zkminer benchmark --calibrate`), never a default run.
#[cfg(not(feature = "macos"))]
const CALIBRATION_ITERS: u32 = 6_000_000;

/// The one-time setup before a first proof (`WorkerCommand::Warmup`), which the miner runs before it
/// claims any risc0 job. Every backend: the `risc0-groth16` component every proof's Groth16 wrap
/// needs, installed if it is missing (`groth16_component`). On Intel, also the kernels: SYCL compiles
/// those shipped as SPIR-V (the zkp and Groth16 ones) for the device on first use, which took ~8
/// minutes on an Arc B580, longer than a benchmark's whole budget; the driver caches the result on
/// disk (`~/.cache/libsycl_cache`, `~/.cache/neo_compiler_cache`), so one small proof through the
/// full Groth16 pipeline compiles everything once for every later process. It is verified, so a
/// broken card fails here, not on a job.
#[cfg(all(feature = "intel", not(feature = "macos")))]
fn warm_up() -> Result<String> {
    let component = groth16_component::ensure_installed()?;
    let start = Instant::now();
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write_slice(&1000u32.to_le_bytes())
        .segment_limit_po2(RISC0_DEFAULT_JOB_PO2 as u32)
        .build()?;
    let opts = risc0_zkvm::ProverOpts::groth16().with_dev_mode(false);
    let proved = local_prover().prove_with_opts(env, FIBONACCI_ELF, &opts);
    release_groth16_cache_if_tight();
    proved?
        .receipt
        .verify(FIBONACCI_ID)
        .context("the warm-up proof does not verify")?;
    Ok(format!(
        "{component}; compiled and cached the Intel GPU kernels with a verified Groth16 proof in \
         {:.0} s",
        start.elapsed().as_secs_f64()
    ))
}

#[cfg(all(not(feature = "intel"), not(feature = "macos")))]
fn warm_up() -> Result<String> {
    groth16_component::ensure_installed()
}

/// Run a po2 calibration: prove fibonacci at the specified segment po2 and measure throughput.
#[cfg(feature = "macos")]
fn run_po2_calibration(_request_id: u64, _po2: u8) -> Result<WorkerResponse> {
    anyhow::bail!("CPU bootstrap calibration is unsupported; use bounded local workloads")
}

#[cfg(not(feature = "macos"))]
fn run_po2_calibration(request_id: u64, po2: u8) -> Result<WorkerResponse> {
    let input = CALIBRATION_ITERS.to_le_bytes();
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write_slice(&input)
        .segment_limit_po2(po2 as u32)
        .build()?;

    let start = std::time::Instant::now();
    let prover = local_prover();
    // Measure the SAME pipeline the miner actually runs (`run_proof_once` uses
    // ProverOpts::groth16()), NOT `prove()`'s default composite receipt.
    //
    // This is the difference between a useful calibration and a misleading one. A
    // composite proof stops after segment proving, so it never observes:
    //   * lift/join FOLDING, whose cost scales with SEGMENT COUNT and is therefore the
    //     dominant po2-dependent term, and
    //   * the Groth16 wrap.
    // Measured on a 4090 with this 62M-cycle workload (po2 18/19/20):
    //     folding      50.90 / 23.90 / 11.60 s   <- halves per po2 step
    //     segments+CPU 34.29 / 31.70 / 30.46 s   <- nearly flat
    //     REAL total   87.20 / 57.55 / 44.02 s
    // Composite-only calibration reported 34.6/31.7/30.7 s — i.e. it saw a 12% spread
    // where the real spread is 98%, leaving its argmax to be decided by noise. It also
    // under-reports MEMORY pressure: po2=21 completes composite-only but OOMs on the
    // real groth16 path, so a composite-derived max_feasible_po2 is too optimistic.
    let opts = risc0_zkvm::ProverOpts::groth16().with_dev_mode(false);
    let proved = prover.prove_with_opts(env, FIBONACCI_ELF, &opts);
    release_groth16_cache_if_tight();
    let prove_info = proved?;
    let duration = start.elapsed();

    let total_cycles = prove_info.stats.total_cycles;
    let segment_count = prove_info.stats.segments as u32;

    Ok(WorkerResponse::CalibrationResult {
        request_id,
        po2,
        segment_count,
        total_cycles,
        prove_duration_secs: duration.as_secs_f64(),
    })
}

#[cfg(test)]
mod program_id_tests {
    use super::*;

    #[test]
    fn matches_native_order_only_and_not_a_different_id() {
        let mut img = [0u8; 32];
        for (i, b) in img.iter_mut().enumerate() {
            *b = i as u8;
        }
        // Same bytes (native order) matches.
        assert!(image_id_matches(&img, &img));
        // The v2 adapter verifies against programId verbatim: the reversed order can never verify,
        // so it must NOT match (else a reversed registration is claimed, proved and rejected).
        let mut rev = img;
        rev.reverse();
        assert!(!image_id_matches(&img, &rev));
        // A genuinely different program (one bit flipped) matches under neither order.
        let mut other = img;
        other[0] ^= 0x01;
        assert!(!image_id_matches(&img, &other));
    }

    #[test]
    fn verify_computes_the_image_id_even_without_a_program_id() {
        // No programId supplied (benchmark/calibration/mock): nothing to match, but the image id is
        // still computed (it keys the `sys_rand` seed), so bytes that are no ELF are refused.
        assert!(verify_program_id(&[0u8; 8], None).is_err());
    }

    // Guest-gated: only meaningful when real guests were compiled in (not RISC0_SKIP_BUILD).
    #[test]
    fn computed_image_id_matches_embedded_fibonacci_id() {
        if FIBONACCI_ELF.is_empty() {
            return; // stubbed guests; nothing to validate
        }
        let image_id = risc0_zkvm::compute_image_id(FIBONACCI_ELF).expect("compute image id");
        // The build embeds FIBONACCI_ID from the SAME computation; this proves our local
        // image-id derivation is self-consistent (the forward byte order).
        let embedded: Vec<u8> = FIBONACCI_ID.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(image_id.as_bytes(), embedded.as_slice());
        // And the real embedded id must bind to itself under verify_program_id.
        let mut pid = [0u8; 32];
        pid.copy_from_slice(image_id.as_bytes());
        assert!(verify_program_id(FIBONACCI_ELF, Some(pid)).is_ok());
        // A different programId (bit flipped) must be refused.
        pid[0] ^= 0x01;
        assert!(verify_program_id(FIBONACCI_ELF, Some(pid)).is_err());
    }
}

#[cfg(test)]
mod keccak_audit_tests {
    use super::*;
    use risc0_zkvm::sha::Digestible;

    fn request(b: u8) -> risc0_zkvm::Assumption {
        risc0_zkvm::Assumption {
            claim: risc0_zkvm::Digest::from([b as u32; 8]),
            control_root: risc0_circuit_keccak::KECCAK_CONTROL_ROOT,
        }
    }

    fn union(a: &risc0_zkvm::Assumption, b: &risc0_zkvm::Assumption) -> risc0_zkvm::Assumption {
        let (x, y) = (a.digest(), b.digest());
        let (left, right) = if x <= y { (x, y) } else { (y, x) };
        risc0_zkvm::Assumption {
            claim: risc0_zkvm::UnionClaim { left, right }.digest(),
            control_root: risc0_zkvm::ALLOWED_CONTROL_ROOT,
        }
    }

    #[test]
    fn the_root_is_the_guest_batchers_mountain_range() {
        let audit = |n: u8| KeccakAudit {
            requests: (1..=n).map(request).collect(),
            cycles: 0,
        };
        assert_eq!(audit(0).root(), None, "no requests, nothing to assume");
        // A lone request stands for itself, under the keccak circuit's control root.
        assert_eq!(audit(1).root(), Some(request(1)));
        assert_eq!(audit(2).root(), Some(union(&request(1), &request(2))));
        // Three: a height-1 peak over the first two, then the third, folded front to back.
        let three = union(&union(&request(1), &request(2)), &request(3));
        assert_eq!(audit(3).root(), Some(three));
        // Four: one height-2 peak.
        let four = union(
            &union(&request(1), &request(2)),
            &union(&request(3), &request(4)),
        );
        assert_eq!(audit(4).root(), Some(four));
        // A union is unordered, so the root doesn't depend on the order within a pair.
        let swapped = KeccakAudit {
            requests: vec![request(2), request(1)],
            cycles: 0,
        };
        assert_eq!(swapped.root(), audit(2).root());
    }
}

#[cfg(test)]
mod sys_rand_tests {
    use super::*;

    #[test]
    fn seed_is_fixed_by_key_image_id_and_input() {
        let key = [1u8; 32];
        let image = [7u8; 32];
        let seed = sys_rand_seed(&key, &image, b"input");
        assert_eq!(sys_rand_seed(&key, &image, b"input"), seed);
        assert_ne!(sys_rand_seed(&[2u8; 32], &image, b"input"), seed);
        assert_ne!(sys_rand_seed(&key, &[8u8; 32], b"input"), seed);
        assert_ne!(sys_rand_seed(&key, &image, b"input2"), seed);
    }

    #[test]
    fn the_seed_follows_the_image_id_not_the_elf_bytes() {
        // The same program (one image id) must seed alike whichever of its ELFs was fetched.
        if FIBONACCI_ELF.is_empty() {
            return; // stubbed guests; nothing to validate
        }
        let image = verify_program_id(FIBONACCI_ELF, None).unwrap();
        assert_eq!(
            image,
            <[u8; 32]>::try_from(
                risc0_zkvm::compute_image_id(FIBONACCI_ELF)
                    .unwrap()
                    .as_bytes()
            )
            .unwrap()
        );
        assert_eq!(
            verify_program_id(FIBONACCI_ELF, Some(image)).unwrap(),
            image
        );
    }
}

#[cfg(all(test, not(feature = "macos")))]
mod retry_tests {
    use super::*;

    #[test]
    fn the_failed_segment_is_read_from_the_provers_context() {
        let msg = "verify segment 3: verification indicates proof is invalid";
        assert_eq!(failed_segment(msg), Some(3));
        let msg = "verify segment (last) 17: verification indicates proof is invalid";
        assert_eq!(failed_segment(msg), Some(17));
        // No index (the test injection, a receipt check): no segment to compare.
        let msg = "verify segment: verification indicates proof is invalid (test injected)";
        assert_eq!(failed_segment(msg), None);
        assert_eq!(failed_segment("receipt is invalid"), None);
    }

    #[test]
    fn only_the_same_segment_failing_again_stops_the_retries() {
        assert!(failed_twice(Some(3), Some(3)));
        assert!(!failed_twice(Some(3), Some(4)));
        assert!(!failed_twice(Some(3), None));
        assert!(
            !failed_twice(None, None),
            "an unindexed failure is never the same segment"
        );
    }

    #[test]
    fn a_job_runs_only_at_a_size_in_the_job_range() {
        assert_eq!(job_segment_po2(None).unwrap(), RISC0_DEFAULT_JOB_PO2);
        for p in [RISC0_JOB_PO2_MIN, 19, RISC0_JOB_PO2_MAX] {
            assert_eq!(job_segment_po2(Some(p)).unwrap(), p);
        }
        for p in [RISC0_JOB_PO2_MIN - 1, RISC0_JOB_PO2_MAX + 1] {
            let err = job_segment_po2(Some(p)).unwrap_err();
            assert!(
                format!("{err:#}").contains(&format!("po2 value {p} is outside")),
                "{err:#}"
            );
        }
        if FIBONACCI_ELF.is_empty() {
            return; // stubbed guests; nothing to validate
        }
        let image = verify_program_id(FIBONACCI_ELF, None).unwrap();
        let po2 = RISC0_JOB_PO2_MIN - 1;
        // Refused before any proving, executing or seeding: no GPU needed.
        let err = run_proof(FIBONACCI_ELF, &[], Some(po2), Some(image)).unwrap_err();
        assert!(format!("{err:#}").contains("po2 value"), "{err:#}");
        let err = run_execute(FIBONACCI_ELF, &[], Some(image), Some(po2)).unwrap_err();
        assert!(format!("{err:#}").contains("po2 value"), "{err:#}");
    }
}
